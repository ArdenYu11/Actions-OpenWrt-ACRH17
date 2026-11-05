# L2TP/IPsec 客户端插件

适用于使用新版 LuCI 和 firewall4 的 OpenWrt/LEDE，支持一条 IPv4 L2TP over IPsec 客户端连接：IKEv1、PSK、Transport、PPP PAP。后端使用 StrongSwan 的 VICI 接口和 xl2tpd，由 procd 管理连接工作进程。

## 集成编译

本仓库的 `diy-part2.sh` 会把两个包复制到 LEDE 的 `package/custom/`，`acrh17.config` 只需：

```ini
CONFIG_PACKAGE_luci-app-l2tp-ipsec-client=y
```

依赖自动带入 StrongSwan、OpenSSL 算法模块、VICI、xl2tpd、PPP、内核 IPsec/PPPoL2TP、firewall4/nft-xfrm 和路由工具。使用 OpenSSL 提供 DH，避开已记录的 gmpdh 加载问题。

在其他 OpenWrt/LEDE 构建目录中，将本目录的两个包复制到 `package/custom/`，再执行 `make menuconfig`，选择 LuCI → Applications → `luci-app-l2tp-ipsec-client`。

## 网页使用

刷机后进入 **VPN → L2TP/IPsec 客户端**：

1. 填写服务器、用户名、密码和 PSK。
2. 在「内网访问」填写需要经 VPN 访问的 IPv4 网段，例如 `10.20.0.0/16`。填写的是实际远端网段，不是 VPN 服务器公网地址。
3. 可填写允许 Ping 的内网 IP 作为探测地址。
4. 点击「保存并连接」，观察 IPsec、PPP 和探测结果。

「保存设置」只保存参数，下次连接时生效。「开机自动连接」决定重启后是否连接。「断开连接」停止本次运行，开启自动连接时下次开机会再连接。

默认 IKE `aes256-sha256-modp2048`、ESP `aes256-sha1`、MTU/MRU 1400、PPP 保活 30 秒/5 次。高级设置提供随包安装的算法组合和身份标识。

仅指定的网段走 VPN，暂不提供全局默认路由；不自动修改 DNS。远端域名访问需要在 OpenWrt 的 DHCP/DNS 中额外配置对应域的解析服务器。LAN → VPN 已配置转发和地址伪装，远端主动访问 LAN 默认不允许。

## 配置与运行

- 持久配置：`/etc/config/l2tpipsec`，权限 600，凭据在刷机后填写。
- 临时运行文件：`/var/run/l2tp-ipsec-client/`，目录权限 700；断开后删除包含 PSK/密码的协议配置。
- 接口：`l2tp-vpn`，防火墙区域与 netifd 逻辑接口：`l2tpipsec`。
- 进程管理：`/etc/init.d/l2tp-ipsec-client start|stop`。
- 状态：`ubus call l2tp-ipsec-client status '{}'`。
- 诊断事件：`ubus call l2tp-ipsec-client logs '{}'`；不返回底层完整身份信息。
- 配置检查：`ubus call l2tp-ipsec-client validate '{}'`。

首次安装会停用没有连接配置的 swanctl/xl2tpd 默认服务。已有配置保留；检测到其他 charon、starter 或 xl2tpd 进程时，本插件提示冲突并停止。第一版不支持与其他 IPsec/L2TP 管理实例同时运行。

工作进程先安装 UDP/1701 阻断策略，建立 IPsec CHILD_SA 后再启动 L2TP。断开时先停止 PPP/L2TP，再停止 IPsec，最后撤销保护策略及自身路由。进程异常退出留下的保护策略会阻止裸发，需要重启路由器清理后重试。

## 页面预览

```bash
python3 preview/build.py ~/Downloads/L2TP-IPsec-设置页预览.html
```

生成单文件 HTML，可双击打开。预览复用实际 LuCI 页面代码，模拟 LuCI 表单宿主和连接状态，所有输入只存在于当前页面内存。没有真实 VPN 拨号；正式页面外观随 LuCI 主题变化。

## 验证

```bash
python3 tests/test_backend.py
python3 tests/test_linux_integration.py
node --check packages/luci-app-l2tp-ipsec-client/htdocs/luci-static/resources/view/l2tp-ipsec-client.js
```

固件编译和真机连接需要分别验收；页面预览或配置语法检查不能替代 RT-ACRH17 真机连通性验证。

## 许可

本目录新增的两个软件包使用 MIT 许可；依赖软件沿用各自许可。
