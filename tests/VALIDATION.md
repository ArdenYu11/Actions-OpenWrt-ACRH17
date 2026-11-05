# 验证记录（2026-11-05）

## 1.2.0：统一规则列表、域名探测与重连策略

- 统一规则列表使用实际 LuCI 的自定义字段和 modal API，已有四类 UCI list 读取并汇总显示；保存时写回原字段，兼容旧配置。
- JavaScript 检查覆盖旧配置汇总/回写、编辑类型、删除、重复规则、容量限制及探测地址输入边界。
- 配置与边界测试 8 项、重连/探测测试 4 项、工作进程测试 6 项通过。重连验证覆盖 1/2/3/5/8 循环、非序列最大值、次数限制、成功后复位逻辑、前导零数值和手动停止。
- 域名探测覆盖解析失败、缺少 VPN 路由、Ping 未响应、多 IPv4 地址选择及原有 IP 探测。
- 浏览器验证弹窗添加网段和域名、编辑类型/内容、删除、模式切换保留列表、自动重连依赖字段保留及域名探测地址保存；下拉箭头保留右侧间距。
- 单文件 HTML 和列表/弹窗截图已更新。ShellCheck、Shell 和 JavaScript 语法检查通过。

完整固件编译、真实 VPN 下的域名探测和断线重连仍需真机验收。

## 1.1.0：全流量与网段/域名规则分流

- 配置及输入边界 7 项、路由管理 4 项、DNS UDP/TCP 与路由生命周期 8 项、工作进程生命周期 5 项通过，共 24 项。
- DNS 检查包含精确/前缀/后缀 OR 匹配、大小写、后缀边界、CNAME 和 TTL、无关 A 记录过滤、共享地址保留最长 TTL、AAAA/HTTPS/SVCB 抑制、异常包、路由失败返回 SERVFAIL、停止清理及慢 TCP 中断。
- C 模块使用 `-Wall -Wextra -Werror` 在本机和 Linux 编译通过；Linux 上 8 项 DNS 测试在 ASan/UBSan 下通过。
- Linux 独立网络命名空间中真实 `ip rule` / 路由表验证通过：静态网段与 DNS 动态地址走 VPN，未命中走 WAN，本地 LAN 和 VPN 公网服务器保持原出口，全流量切换与断开清理正确。
- 两模式 nftables 规则均通过 `nft -c`。真实 dnsmasq + DNS 模块 + nft 重定向联动通过：IPv4/IPv6 本机 DNS 进入代理，命中使用 VPN DNS，未命中透传原 dnsmasq，无 DNS 循环。
- 新 LuCI 页面的四类规则同时显示；全流量隐藏规则，切回规则分流保留值；可操作预览和规则页截图已更新。
- ShellCheck、JavaScript、JSON、YAML 和 shell 语法检查通过。

以上验证不涉及宿主实际 VPN 或路由。尚需完整固件交叉编译与 RT-ACRH17 真机的 procd、PPP DNS、firewall4/LAN DNS、其他 DNS/策略路由插件兼容及长期运行验收。

## 1.0.0：连接管理基础验证

已完成：

- 配置与输入边界测试 5 项：默认值、无效字段、凭据转义、权限、空路由。
- 工作进程测试 5 项：已有进程冲突、失败清理、重连等待中断、IPsec 等待中断、PPP 等待中断。本地和 Linux 隔离容器均通过。
- JavaScript、JSON、YAML、ShellCheck 和 Shell 语法检查通过。
- 在临时 LEDE 树执行 `make defconfig`，确认单个 LuCI 包配置自动选入后端、StrongSwan/VICI/OpenSSL、PPP/xl2tpd、firewall4/nft-xfrm、jshn 和路由工具，机型正确保留。
- Linux 隔离容器中 StrongSwan 5.9.14 成功加载 IKEv1/PSK/Transport 连接与带特殊字符的 PSK；PPP 2.5.2 接受生成的选项，xl2tpd 1.3.19 成功启动并响应控制请求。
- IPsec UDP/1701 阻断策略安装与删除通过。
- nftables 规则在独立网络空间中通过 `nft -c`：只接受匹配此实例 reqid 的解密 L2TP，并豁免外层 IPsec 的 WAN NAT。
- 浏览器预览检查必填校验、三个设置标签、连接状态顺序、失败提示和日志；演示凭据没有连接真实服务器。
- `diy-part2.sh` 在临时目录中正确复制两个软件包；安装文件布局和可执行权限通过检查。

验证时的源码版本：

| 源码 | 提交 |
| --- | --- |
| coolsnowwolf/lede | `74a59a5826862feacff9b9e9c93d28aec31aefd8` |
| coolsnowwolf/packages | `970d7296e646918746df95396eb12e3a344668a0` |
| coolsnowwolf/luci，openwrt-25.12 | `04bdb60fc11343d62916c530422a8971ffa73d42` |

尚未完成：

- 完整 RT-ACRH17 固件编译及软件包交叉编译。
- 真机上的 procd/rpcd/netifd/firewall4 联动与实际 VPN 连接。
- 真机上多台 LAN 设备访问远端内网、WAN 断线恢复、开机连接及长期运行。

本版本可以预览并进行固件编译验证，真机验收前不能宣称 VPN 已实际可用。
