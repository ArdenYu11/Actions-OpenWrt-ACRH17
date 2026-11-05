#!/bin/sh

LP_DIR=${LP_DIR:-/var/run/l2tp-ipsec-client}
LP_LIB=${LP_LIB:-/usr/lib/l2tp-ipsec-client}
LP_CONFIG=${LP_CONFIG:-l2tpipsec}
LP_REQID=41717
LP_CONN=l2tpipsec
LP_IFACE=l2tp-vpn
LP_URI="unix://$LP_DIR/charon.vici"

lp_load() {
	. /lib/functions.sh
	config_load "$LP_CONFIG"
	config_get server main server
	config_get username main username
	config_get password main password
	config_get psk main psk
	config_get ike main ike aes256-sha256-modp2048
	config_get esp main esp aes256-sha1
	config_get local_id main local_id
	config_get remote_id main remote_id
	config_get mtu main mtu 1400
	config_get lcp_interval main lcp_interval 30
	config_get lcp_failure main lcp_failure 5
	config_get retry_interval main retry_interval 30
	config_get probe_ip main probe_ip
	config_get_bool reconnect main reconnect 1
	routes=""
	config_list_foreach main routes lp_add_route
}

lp_add_route() {
	routes="${routes:+$routes }$1"
}

lp_error() {
	LP_ERROR="$1"
	return 1
}

lp_number() {
	case "$1" in ''|*[!0-9]*) return 1 ;; esac
	[ "${#1}" -le 5 ] && [ "$1" -ge "$2" ] && [ "$1" -le "$3" ]
}

lp_ip4() {
	printf '%s\n' "$1" | awk -F. 'NF != 4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || length($i)>3 || $i+0>255) exit 1}'
}

lp_text() {
	# 拒绝控制字符，防止向配置文件注入额外指令。
	[ -n "$1" ] && [ "${#1}" -le "$2" ] || return 1
	[ "$(printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177')" = "$1" ]
}

lp_validate() {
	LP_ERROR=""
	case "$server" in ''|*[!a-zA-Z0-9.-]*|-*|.*|*.) lp_error '服务器地址必须是 IPv4 地址或域名。'; return 1 ;; esac
	[ "${#server}" -le 253 ] || { lp_error '服务器地址过长。'; return 1; }
	lp_text "$username" 128 || { lp_error '用户名不能为空，也不能包含控制字符。'; return 1; }
	lp_text "$password" 256 || { lp_error '密码不能为空，也不能包含控制字符。'; return 1; }
	lp_text "$psk" 256 || { lp_error '预共享密钥不能为空，也不能包含控制字符。'; return 1; }
	for value in "$local_id" "$remote_id"; do
		[ -z "$value" ] || lp_text "$value" 253 || { lp_error '身份标识包含无效字符。'; return 1; }
	done
	# 只公开随包安装的算法，不接受任意配置片段。
	case "$ike" in aes256-sha256-modp2048|aes128-sha256-modp2048|aes256-sha1-modp2048|aes128-sha1-modp2048) ;; *) lp_error '不支持此 IKE 算法组合。'; return 1 ;; esac
	case "$esp" in aes256-sha1|aes128-sha1|aes256-sha256|aes128-sha256) ;; *) lp_error '不支持此 ESP 算法组合。'; return 1 ;; esac
	lp_number "$mtu" 576 1460 || { lp_error 'MTU 必须介于 576 和 1460。'; return 1; }
	lp_number "$lcp_interval" 5 300 || { lp_error '保活间隔必须介于 5 和 300 秒。'; return 1; }
	lp_number "$lcp_failure" 1 20 || { lp_error '保活失败次数必须介于 1 和 20。'; return 1; }
	lp_number "$retry_interval" 10 300 || { lp_error '重连间隔必须介于 10 和 300 秒。'; return 1; }
	for route in $routes; do
		case "$route" in */*) ;; *) lp_error '内网路由必须使用 IPv4 CIDR 格式。'; return 1 ;; esac
		lp_ip4 "${route%/*}" && lp_number "${route##*/}" 1 32 || { lp_error '内网路由无效；暂不支持默认路由 0.0.0.0/0。'; return 1; }
	done
	[ -z "$probe_ip" ] || lp_ip4 "$probe_ip" || { lp_error '探测地址必须是 IPv4 地址。'; return 1; }
}

lp_quote() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

lp_state() {
	. /usr/share/libubox/jshn.sh
	json_init
	json_add_string phase "$1"
	json_add_string message "$2"
	json_add_string server "$server"
	json_add_string server_ip "${server_ip:-}"
	json_add_string interface "$LP_IFACE"
	json_add_int updated "$(date +%s)"
	json_dump > "$LP_DIR/status.new"
	mv "$LP_DIR/status.new" "$LP_DIR/status.json"
	lp_log "$2"
}

lp_log() {
	printf '%s %s\n' "$(date '+%H:%M:%S')" "$1" >> "$LP_DIR/events.log"
	if [ "$(wc -l < "$LP_DIR/events.log")" -gt 240 ]; then
		tail -n 160 "$LP_DIR/events.log" > "$LP_DIR/events.new"
		mv "$LP_DIR/events.new" "$LP_DIR/events.log"
	fi
}

lp_swan() {
	swanctl "$@" --uri "$LP_URI"
}

lp_render() {
	umask 077
	cat > "$LP_DIR/strongswan.conf" <<EOF
charon {
  load_modular = no
  load = random nonce openssl aes sha1 sha2 hmac kdf kernel-netlink socket-default vici
  install_routes = no
  plugins {
    vici { socket = $LP_URI }
  }
  filelog {
    managed {
      path = $LP_DIR/charon.log
      default = 0
      ike = 1
      cfg = 1
      flush_line = yes
    }
  }
}
EOF
	cat > "$LP_DIR/swanctl.conf" <<EOF
connections {
  $LP_CONN {
    version = 1
    remote_addrs = $server_ip
    proposals = $ike
    rekey_time = 0
    dpd_delay = 30s
    keyingtries = 1
    local {
      auth = psk
      id = "$(lp_quote "${local_id:-$local_ip}")"
    }
    remote {
      auth = psk
      id = "$(lp_quote "${remote_id:-%any}")"
    }
    children {
      $LP_CONN {
        mode = transport
        local_ts = dynamic[udp/1701]
        remote_ts = $server_ip/32[udp/1701]
        esp_proposals = $esp
        reqid = $LP_REQID
        priority = 100000
        start_action = none
        dpd_action = clear
        close_action = none
      }
    }
  }
}
secrets {
  ike-l2tpipsec {
    id = "$(lp_quote "${local_id:-$local_ip}")"
    secret = "$(lp_quote "$psk")"
  }
}
EOF
	cat > "$LP_DIR/ppp.options" <<EOF
noauth
hide-password
user "$(lp_quote "$username")"
password "$(lp_quote "$password")"
refuse-eap
refuse-chap
refuse-mschap
refuse-mschap-v2
noccp
noipdefault
nodefaultroute
ipcp-accept-local
ipcp-accept-remote
mtu $mtu
mru $mtu
lcp-echo-interval $lcp_interval
lcp-echo-failure $lcp_failure
ifname $LP_IFACE
ipparam l2tpipsec
ip-up-script $LP_LIB/ppp-up
ip-down-script $LP_LIB/ppp-down
EOF
	cat > "$LP_DIR/xl2tpd.conf" <<EOF
[global]
port = 1701
access control = yes
[lac $LP_CONN]
lns = $server_ip
pppoptfile = $LP_DIR/ppp.options
length bit = yes
autodial = no
redial = no
EOF
	printf '%s\n' $routes > "$LP_DIR/routes"
}

lp_has_ipsec() {
	local sas
	sas=$(lp_swan --list-sas 2>/dev/null) || return 1
	printf '%s\n' "$sas" | grep -q "${LP_CONN}: #.*ESTABLISHED" &&
	printf '%s\n' "$sas" | grep -q "${LP_CONN}: #.*INSTALLED"
}

lp_alive() {
	[ -n "$1" ] && kill -0 "$1" 2>/dev/null
}

lp_stop_pid() {
	lp_alive "$1" || return 0
	kill "$1" 2>/dev/null
	local tries=0
	while lp_alive "$1" && [ "$tries" -lt 20 ]; do
		sleep 0.1
		tries=$((tries + 1))
	done
	lp_alive "$1" && kill -9 "$1" 2>/dev/null
	return 0
}

lp_wait_command() {
	"$@" &
	command_pid=$!
	wait "$command_pid"
	local result=$?
	command_pid=""
	return "$result"
}

lp_sleep() {
	lp_wait_command sleep "$1"
}
