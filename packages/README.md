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
5. 点击「保存并连接」，观察 IPsec、PPP 和探测结果。

「保存设置」只保存参数，下次连接时生效。「开机自动连接」决定重启后是否连接。「断开连接」停止本次运行，开启自动连接时下次开机会再连接。

「断线自动重连」支持最大重连次数（默认 0，表示不限次数）和最大重连间隔（默认 30 秒，范围 1–3600 秒）。首次连接不计入重连次数，成功连接后次数和间隔重新开始；到达次数上限停止。每次等待按 1、2、3、5、8……秒递增，触及最大间隔后从 1 秒循环。例如最大间隔 8 秒：`1、2、3、5、8、1、2……`；最大间隔 6 秒：`1、2、3、5、6、1、2……`。已有配置的 `retry_interval` 作为最大间隔使用。

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

域名规则通过 DNS 解析结果学习 IPv4 路由。LAN 设备需要使用路由器 DNS；DoH/DoT、自定义外部 DNS、连接前已缓存的地址及直接用 IP 访问不会触发域名匹配。匹配域名不返回 AAAA、HTTPS/SVCB 地址提示和 ANY 结果，实际访问使用 IPv4。共享同一 IP 的其他域名也可能走 VPN；按 DNS TTL 清理地址，多个匹配域名共享地址时保留最长有效期。

DNS 模块接收发往路由器的 LAN DNS 请求和发往 `127.0.0.1` / `::1` 的本机 DNS 请求；命中规则使用 VPN DNS，未命中转给原 DNS 服务，保留其 DHCP、本地域名和解析策略。不会修改 dnsmasq 的持久配置或关闭其重绑定保护。全流量的 DNS 全部使用 VPN DNS。若装有其他 DNS 接管或策略路由插件，需要在真机验证规则顺序。

LAN → VPN 已配置转发和地址伪装，远端主动访问 LAN 默认不允许。默认 LAN 网络名为 `lan`，额外 VLAN 需要另行配置转发和 DNS 接入。

## 配置与运行

- 持久配置：`/etc/config/l2tpipsec`，权限 600，凭据在刷机后填写。
- 临时运行文件：`/var/run/l2tp-ipsec-client/`，目录权限 700；断开后删除包含 PSK/密码的协议配置。
- 接口：`l2tp-vpn`，防火墙区域与 netifd 逻辑接口：`l2tpipsec`。
- 路由：独立表 `41717`，IPv4 规则优先级 `10100`–`10104`；占用时拒绝启动，不覆盖其他管理器。
- DNS：双栈监听 `1053`，nftables 限制为 LAN/本机访问；使用表内专用路由访问 VPN DNS。
- 进程管理：`/etc/init.d/l2tp-ipsec-client start|stop`。
- 状态：`ubus call l2tp-ipsec-client status '{}'`。
- 诊断事件：`ubus call l2tp-ipsec-client logs '{}'`；不返回底层完整身份信息。
- 配置检查：`ubus call l2tp-ipsec-client validate '{}'`。

首次安装会停用没有连接配置的 swanctl/xl2tpd 默认服务。已有配置保留；检测到其他 charon、starter 或 xl2tpd 进程时，本插件提示冲突并停止。第一版不支持与其他 IPsec/L2TP 管理实例同时运行。

工作进程先安装 UDP/1701 阻断策略，建立 IPsec CHILD_SA 后再启动 L2TP。断开时先停止 PPP/L2TP，再停止 IPsec，最后撤销保护策略及自身路由、DNS 进程和临时 nftables 表。进程异常退出留下的保护策略会阻止裸发，需要重启路由器清理后重试。

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
python3 tests/test_retry_probe.py
node tests/test_ui_rules.js
node --check packages/luci-app-l2tp-ipsec-client/htdocs/luci-static/resources/view/l2tp-ipsec-client.js
```

固件编译和真机连接需要分别验收；页面预览或配置语法检查不能替代 RT-ACRH17 真机连通性验证。

## 许可

本目录新增的两个软件包使用 MIT 许可；依赖软件沿用各自许可。
