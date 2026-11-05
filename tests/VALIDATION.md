# 验证记录（2026-11-05）

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
