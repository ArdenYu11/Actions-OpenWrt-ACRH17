# L2TP/IPsec 客户端插件

适用于使用新版 LuCI 和 firewall4 的 OpenWrt/LEDE，支持一条 IPv4 L2TP over IPsec 客户端连接：IKEv1、PSK、Transport、PPP PAP。后端使用 StrongSwan 的 VICI 接口和 xl2tpd，由 procd 管理连接工作进程。

## 集成编译

本仓库的 `diy-part2.sh` 会把两个包复制到 LEDE 的 `package/custom/`，`acrh17.config` 只需：

```ini
CONFIG_PACKAGE_luci-app-l2tp-ipsec-client=y
```

依赖自动带入 StrongSwan、OpenSSL 算法模块、VICI、xl2tpd、PPP、内核 IPsec/PPPoL2TP、firewall4/nft-xfrm/nft-nat、轻量 DNS 模块和路由工具。使用 OpenSSL 提供 DH，避开已记录的 gmpdh 加载问题。

在其他 OpenWrt/LEDE 构建目录中，将本目录的两个包复制到 `package/custom/`，再执行 `make menuconfig`，选择 LuCI → Applications → `luci-app-l2tp-ipsec-client`。

## 网页使用

刷机后进入 **VPN → L2TP/IPsec 客户端**：

1. 填写服务器、用户名、密码和 PSK。
2. 在「流量路由」选择「全流量」或「规则分流」。规则分流使用一个「已添加规则」列表，点击「添加规则」在弹窗选择指定网段或域名；域名再选择完整域名、前缀或后缀。列表支持编辑和删除，命中任一规则即走 VPN。
3. 使用全流量或域名规则时，VPN DNS 留空则使用 PPP 下发的地址；未下发时填写可经 VPN 访问的 IPv4 DNS 地址。
4. 可填写允许 Ping 的 IPv4 地址或域名作为内网探测地址。域名先解析为 IPv4，再检查路由和 Ping；规则分流时需要命中已添加的网段或域名规则。页面会区分域名解析失败、缺少 VPN 路由和 Ping 未响应。
5. 点击「保存并连接」，观察 IPsec、PPP 和探测结果。保存、应用、检查、启动任何一步失败，页面都会提示是哪一步、什么原因。

服务器要求在手机上确认登录（MFA）时，在页面显示「正在验证账号并连接 PPP」后 90 秒内确认即可；PPP 认证请求会在这段时间内持续重发。这种情况建议关闭「断线自动重连」和「开机自动连接」，否则每次重连或重启都会触发一次确认。

「保存设置」只保存参数，下次连接时生效。「开机自动连接」决定重启后是否连接。「断开连接」停止本次运行，开启自动连接时下次开机会再连接。

「断线自动重连」支持最大重连次数（默认 0，表示不限次数）和最大重连间隔（默认 30 秒，范围 1–3600 秒）。首次连接不计入重连次数，成功连接后次数和间隔重新开始；到达次数上限停止。关闭自动重连时，连接失败或中断后会在日志里写明「自动重连已关闭，连接已停止」。每次等待按 1、2、3、5、8……秒递增，触及最大间隔后从 1 秒循环。例如最大间隔 8 秒：`1、2、3、5、8、1、2……`；最大间隔 6 秒：`1、2、3、5、6、1、2……`。已有配置的 `retry_interval` 作为最大间隔使用。

默认 IKE `aes256-sha256-modp2048`、ESP `aes256-sha1`、MTU/MRU 1400、PPP 保活 30 秒/5 次。高级设置提供随包安装的算法组合和身份标识。

两种模式：

- **全流量**：IPv4 外网流量走 VPN，VPN 公网服务器及已有明确的本地路由仍走原接口。由于此连接只承载 IPv4，连接期间阻止 LAN 和路由器的 IPv6 外网流量，避免绕过 VPN。
- **规则分流**：指定网段与三类域名规则同时生效，任意命中走 VPN；其他流量走原有出口。直连网段优先保留，重叠的远端网段需要先解决地址冲突。

| 规则 | 示例 | 匹配范围 |
| --- | --- | --- |
| 指定网段 | `10.20.0.0/16` | 该 IPv4 网段内的地址 |
| 完整域名 | `api.example.com` | 仅这个域名 |
| 域名前缀 | `api.` / `internal-` | 域名开头为该文本 |
| 域名后缀 | `example.com` | 本域及全部子域；不包括 `badexample.com` |

域名匹配不区分大小写，不填写协议、端口、路径或通配符。后缀按域名标签边界匹配。总域名规则上限 512 条，动态 IPv4 地址上限 4096 个。

域名规则通过 DNS 解析结果学习 IPv4 路由。LAN 设备需要使用路由器 DNS；DoH/DoT、自定义外部 DNS、连接前已缓存的地址及直接用 IP 访问不会触发域名匹配。匹配域名不返回 AAAA、HTTPS/SVCB 地址提示和 ANY 结果，实际访问使用 IPv4。共享同一 IP 的其他域名也可能走 VPN。学到的地址在整个连接期间保留、断开时统一清理，所以 SSH 等长连接不会因为 DNS 有效期到了而中断；地址数达到上限时，只回收 DNS 有效期已过的地址。学到的地址同时记在运行目录的 `learned-routes` 里，连接期间路由被系统清掉时按它原地补回。

DNS 模块接收发往路由器的 LAN DNS 请求和发往 `127.0.0.1` / `::1` 的本机 DNS 请求；命中规则使用 VPN DNS，未命中转给原 DNS 服务，保留其 DHCP、本地域名和解析策略。不会修改 dnsmasq 的持久配置或关闭其重绑定保护。全流量的 DNS 全部使用 VPN DNS。若装有其他 DNS 接管或策略路由插件，需要在真机验证规则顺序。

LAN → VPN 已配置转发和地址伪装，远端主动访问 LAN 默认不允许。默认 LAN 网络名为 `lan`，额外 VLAN 需要另行配置转发和 DNS 接入。

## 配置与运行

- 持久配置：`/etc/config/l2tpipsec`，权限 600，凭据在刷机后填写。
- 临时运行文件：`/var/run/l2tp-ipsec-client/`，目录权限 700；断开后删除包含 PSK/密码的协议配置。
- 接口：`l2tp-vpn`，防火墙区域 `l2tpipsec` 直接按网卡名匹配。不建 netifd 逻辑接口：netifd 接管 pppd 建的网卡时会清空它的地址和路由。旧版本留下的 `network.l2tpipsec` 会在未连接时自动移除。
- 配置自愈：`/usr/lib/l2tp-ipsec-client/ensure-config` 在首次安装、开机和每次连接前检查防火墙区域、LAN 转发、nft 规则和 DNS 放行规则，缺什么补什么，不覆盖已有区域的策略选项，有改动才重新加载防火墙。用旧备份恢复配置后，下次连接会自动补回。改动在配置副本上做，只写回本插件的修改：其他操作用 `uci set` 暂存、尚未提交的改动不会被一起提交，仍留在暂存区。服务重新加载时会叠加这些暂存改动，所以需要补齐的配置（`firewall` 或 `network`）有别人的暂存改动时，本次不写回也不重载，连接日志写明原因；提交或放弃这些改动后，下次连接再补。写回时与 `uci commit` 一样对配置文件加排他锁，核对与替换之间其他提交进不来；原文件在检查期间被别人改过时放弃写回，下次再补。
- 日志：页面「连接日志」即 `/var/run/l2tp-ipsec-client/events.log`，并附带 IPsec 诊断和 `xl2tpd-control` 输出（`l2tp.log`）；xl2tpd、pppd 的详细日志用 `logread -e xl2tpd`、`logread -e pppd` 查看。
- 路由：独立表 `41717`，IPv4 规则优先级 `10100`–`10104`；占用时拒绝启动，不覆盖其他管理器。本插件加的规则逐条记在运行目录的 `routing-rules` 里，断开和下次连接前的残留清理都只按记录删除；没有记录的规则和表内路由无法确认归属，一律保留。
- DNS：双栈监听 `1053`，nftables 限制为 LAN/本机访问；使用表内专用路由访问 VPN DNS。
- 进程管理：`/etc/init.d/l2tp-ipsec-client start|stop`。
- 状态：`ubus call l2tp-ipsec-client status '{}'`。
- 诊断事件：`ubus call l2tp-ipsec-client logs '{}'`；不返回底层完整身份信息。
- 配置检查：`ubus call l2tp-ipsec-client validate '{}'`。

首次安装会停用没有连接配置的 swanctl/xl2tpd 默认服务。已有配置保留；检测到其他 charon、starter 或 xl2tpd 进程时，本插件提示是哪个进程、用什么命令停用，然后停止。第一版不支持与其他 IPsec/L2TP 管理实例同时运行。

工作进程先安装 UDP/1701 阻断策略，建立 IPsec CHILD_SA 后再启动 L2TP。断开时先停止 PPP/L2TP，再停止 IPsec，最后撤销保护策略及自身路由、DNS 进程和临时 nftables 表。

每次连接前会先清理上次异常退出留下的东西：按 pid 文件结束本插件的 pppd、xl2tpd、charon、DNS 模块，删除本插件专用的规则优先级 `10100`–`10104`、路由表 `41717`、nft 表 `l2tpipsec_dns`、阻断策略和状态文件，不需要重启路由器。每个连接有自己的会话标记，被新连接接替的旧工作进程只结束自己启动的进程，不会拆掉新连接。

连接期间每 5 秒检查一次：`l2tp-vpn` 的地址被系统清除时提示重新连接；路由被清除但地址还在时，原地恢复路由（最多 3 次），不断开 VPN，也不需要重新在手机上确认。

## 页面预览

```bash
python3 preview/build.py ~/Downloads/L2TP-IPsec-设置页预览.html
```

生成单文件 HTML，可双击打开。预览复用实际 LuCI 页面代码，模拟 LuCI 表单宿主和连接状态，所有输入只存在于当前页面内存。没有真实 VPN 拨号；正式页面外观随 LuCI 主题变化。

## 验证

```bash
python3 tests/test_backend.py
python3 tests/test_linux_integration.py
python3 tests/test_domain_dns.py
python3 tests/test_routing.py
python3 tests/test_ensure_config.py
python3 tests/test_retry_probe.py
node tests/test_ui_rules.js
node --check packages/luci-app-l2tp-ipsec-client/htdocs/luci-static/resources/view/l2tp-ipsec-client.js
```

固件编译和真机连接需要分别验收；页面预览或配置语法检查不能替代 RT-ACRH17 真机连通性验证。

## 许可

本目录新增的两个软件包使用 MIT 许可；依赖软件沿用各自许可。
