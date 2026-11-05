#!/bin/sh

LP_DIR=${LP_DIR:-/var/run/l2tp-ipsec-client}
LP_LIB=${LP_LIB:-/usr/lib/l2tp-ipsec-client}
LP_CONFIG=${LP_CONFIG:-l2tpipsec}
LP_REQID=41717
LP_CONN=l2tpipsec
LP_IFACE=l2tp-vpn
LP_URI="unix://$LP_DIR/charon.vici"
# xl2tpd-control 的结果管道固定建在这个目录，系统 xl2tpd 服务停用后没人创建它
LP_XL2TPD_RUN=${LP_XL2TPD_RUN:-/var/run/xl2tpd}
# PPP 认证阶段可能要在手机上确认登录，等待时间要留足
LP_PPP_TIMEOUT=90

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
	config_get retry_max_attempts main retry_max_attempts 0
	config_get probe_ip main probe_ip
	config_get routing_mode main routing_mode rules
	config_get vpn_dns main vpn_dns
	config_get_bool reconnect main reconnect 1
	routes=""
	config_list_foreach main routes lp_add_route
	domains=""; domain_prefixes=""; domain_suffixes=""
	config_list_foreach main domains lp_add_domain
	config_list_foreach main domain_prefixes lp_add_prefix
	config_list_foreach main domain_suffixes lp_add_suffix
}

lp_add_domain() { domains="${domains:+$domains }$1"; }
lp_add_prefix() { domain_prefixes="${domain_prefixes:+$domain_prefixes }$1"; }
lp_add_suffix() { domain_suffixes="${domain_suffixes:+$domain_suffixes }$1"; }

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
	case "$1" in ''|*[!0-9.]*) return 1 ;; esac
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
	lp_number "$retry_interval" 1 3600 || { lp_error '最大重连间隔必须介于 1 和 3600 秒。'; return 1; }
	lp_number "${retry_max_attempts:-0}" 0 10000 || { lp_error '最大重连次数必须介于 0 和 10000；0 表示不限次数。'; return 1; }
	case "${routing_mode:-rules}" in full|rules) ;; *) lp_error '路由模式无效。'; return 1 ;; esac
	local rule_count=0
	for value in ${domains:-} ${domain_prefixes:-} ${domain_suffixes:-}; do rule_count=$((rule_count + 1)); done
	[ "$rule_count" -le 512 ] || { lp_error '域名规则总数不能超过 512 条。'; return 1; }
	for route in $routes; do
		case "$route" in */*) ;; *) lp_error '内网路由必须使用 IPv4 CIDR 格式。'; return 1 ;; esac
		lp_ip4 "${route%/*}" && lp_number "${route##*/}" 1 32 || { lp_error '网段无效；全流量请选择全流量模式。'; return 1; }
	done
	for value in ${domains:-} ${domain_suffixes:-}; do
		lp_domain "$value" || { lp_error '域名或后缀无效，请填写不带协议、端口和通配符的域名。'; return 1; }
	done
	for value in ${domain_prefixes:-}; do
		lp_domain "${value%.}" || { lp_error '域名前缀无效，例如 api. 或 internal-。'; return 1; }
	done
	[ -z "${vpn_dns:-}" ] || lp_ip4 "$vpn_dns" || { lp_error 'VPN DNS 必须是 IPv4 地址。'; return 1; }
	[ -z "$probe_ip" ] || lp_probe_target "$probe_ip" || { lp_error '探测地址必须是 IPv4 地址或域名，不包含协议和端口。'; return 1; }
}

lp_domain() {
	case "$1" in ''|*[!a-zA-Z0-9_.-]*) return 1 ;; esac
	[ "${#1}" -le 253 ] && printf '%s\n' "$1" | LC_ALL=C awk -F. '
 {for(i=1;i<=NF;i++) if(length($i)<1 || length($i)>63 || $i !~ /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/) exit 1}'
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
	json_add_string routing_mode "${routing_mode:-rules}"
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
pap-max-authreq $((LP_PPP_TIMEOUT / 3))
noipdefault
nodefaultroute
usepeerdns
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
	printf '%s\n' "$server_ip" > "$LP_DIR/server-ip"
	printf '%s\n' $routes > "$LP_DIR/routes"
	printf '%s\n' "${routing_mode:-rules}" > "$LP_DIR/routing-mode"
	printf '%s\n' "${vpn_dns:-}" > "$LP_DIR/configured-dns"
	: > "$LP_DIR/domain-rules"
	if [ "${routing_mode:-rules}" = rules ]; then
		for value in ${domains:-}; do printf 'exact %s\n' "$value"; done >> "$LP_DIR/domain-rules"
		for value in ${domain_prefixes:-}; do printf 'prefix %s\n' "$value"; done >> "$LP_DIR/domain-rules"
		for value in ${domain_suffixes:-}; do printf 'suffix %s\n' "$value"; done >> "$LP_DIR/domain-rules"
	fi
}

lp_has_ipsec() {
	local output="$LP_DIR/sas.$$" result=1
	if lp_capture 5 "$output" lp_swan --list-sas; then
		grep -q "${LP_CONN}: #.*ESTABLISHED" "$output" &&
		grep -q "${LP_CONN}: #.*INSTALLED" "$output" && result=0
	fi
	rm -f "$output"
	return "$result"
}

# 带超时运行命令，输出写入文件。超时后不再等待：卡在内核不可中断状态的进程连 kill -9 都要等，
# 不能让工作进程跟着卡住。
lp_capture() {
	local limit="$1" output="$2" pid ticks=0
	shift 2
	"$@" > "$output" 2>/dev/null &
	pid=$!
	while kill -0 "$pid" 2>/dev/null; do
		if [ "$ticks" -ge $((limit * 10)) ]; then
			kill -9 "$pid" 2>/dev/null
			return 124
		fi
		sleep 0.1
		ticks=$((ticks + 1))
	done
	wait "$pid"
}

# 列出会和本插件抢端口的其他 IPsec/L2TP 进程，格式如「xl2tpd（PID 123）」。
lp_conflicts() {
	local name pid list=""
	for name in charon charon-systemd starter xl2tpd; do
		for pid in $(pidof "$name" 2>/dev/null); do
			list="${list:+${list}、}${name}（PID ${pid}）"
		done
	done
	printf '%s' "$list"
}

# 本连接的 pppd 是否还在。WAN 用 PPPoE 时也有 pppd，所以按命令行里的选项文件区分。
lp_pppd_running() {
	local pid
	for pid in $(pidof pppd 2>/dev/null); do
		tr '\000' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF "$LP_DIR/ppp.options" && return 0
	done
	return 1
}

# 只有当前连接的工作进程才能清理共享的运行目录和路由，避免残留的旧进程拆掉新连接。
lp_owns_session() {
	[ "$(cat "$LP_DIR/session" 2>/dev/null)" = "$$" ]
}

# 清理上次异常退出留下的东西：本插件的进程、路由规则、DNS 表、阻断策略和状态文件。
# 进程只按本插件的 pid 文件结束，并核对进程名，不会误杀其他服务。
lp_cleanup_leftovers() {
	local entry file comm pid old_ip
	for entry in ppp:pppd xl2tpd:xl2tpd charon:charon dns:domain-dns; do
		file="$LP_DIR/${entry%%:*}.pid"
		comm=${entry#*:}
		[ -f "$file" ] || continue
		read -r pid < "$file"
		case "$pid" in ''|*[!0-9]*) ;; *)
			[ "$(cat "/proc/$pid/comm" 2>/dev/null)" = "$comm" ] && lp_stop_pid "$pid"
		;; esac
		rm -f "$file"
	done
	"$LP_LIB/routing" purge >/dev/null 2>&1
	if [ -f "$LP_DIR/server-ip" ]; then
		read -r old_ip < "$LP_DIR/server-ip"
		if lp_ip4 "$old_ip"; then
			ip xfrm policy delete dir out src 0.0.0.0/0 dst "$old_ip/32" proto udp sport 1701 dport 1701 2>/dev/null
			ip -4 route del "$old_ip/32" metric 41717 2>/dev/null
		fi
	fi
	rm -f "$LP_DIR/ppp.up" "$LP_DIR/route.error" "$LP_DIR/l2tp-control" "$LP_DIR/charon.vici" \
		"$LP_DIR/swanctl.conf" "$LP_DIR/ppp.options" "$LP_DIR/peer-dns" "$LP_DIR"/sas.*
	return 0
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


lp_probe_target() {
 lp_ip4 "$1" && return 0
 case "$1" in ''|*[!0-9.]*) ;; *) return 1 ;; esac
 lp_domain "$1"
}

lp_probe() {
 LP_PROBE_REACH=unknown; LP_PROBE_ADDRESS=""
 [ -n "$probe_ip" ] || return 0
 lp_probe_target "$probe_ip" || { LP_PROBE_REACH=resolve_failed; return 0; }
 local addresses address routed=0
 if lp_ip4 "$probe_ip"; then addresses=$probe_ip
 else
  addresses=$(resolveip -4 -t 3 "$probe_ip" 2>/dev/null | head -n 3)
  [ -n "$addresses" ] || { LP_PROBE_REACH=resolve_failed; return 0; }
 fi
 LP_PROBE_REACH=no_route
 for address in $addresses; do
  lp_ip4 "$address" || continue
  [ -n "$LP_PROBE_ADDRESS" ] || LP_PROBE_ADDRESS=$address
  if ip -4 route get "$address" 2>/dev/null | grep -Eq 'dev l2tp-vpn( |$)'; then
   routed=1; LP_PROBE_ADDRESS=$address
   if ping -I l2tp-vpn -c 1 -W 1 "$address" >/dev/null 2>&1; then LP_PROBE_REACH=yes; return 0; fi
  fi
 done
 [ "$routed" = 0 ] || LP_PROBE_REACH=no
 [ -n "$LP_PROBE_ADDRESS" ] || LP_PROBE_REACH=resolve_failed
 return 0
}

lp_retry_reset() {
 retry_interval=$(printf '%s\n' "$retry_interval" | awk '{printf "%d", $1}')
 retry_max_attempts=$(printf '%s\n' "${retry_max_attempts:-0}" | awk '{printf "%d", $1}')
 retry_attempt=0; retry_delay=1; retry_previous=1; retry_wait=0
}

lp_retry_plan() {
 [ "${retry_max_attempts:-0}" = 0 ] || [ "$retry_attempt" -lt "$retry_max_attempts" ] || return 1
 retry_attempt=$((retry_attempt + 1)); retry_wait=$retry_delay
 if [ "$retry_delay" -ge "$retry_interval" ]; then
  retry_delay=1; retry_previous=1
 else
  local next=$((retry_previous + retry_delay))
  [ "$next" -le "$retry_interval" ] || next=$retry_interval
  retry_previous=$retry_delay; retry_delay=$next
 fi
 return 0
}
