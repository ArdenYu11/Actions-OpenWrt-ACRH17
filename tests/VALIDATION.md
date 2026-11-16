# 验证记录

## 真机验收清单

每次刷新固件后（尤其是用 `latest` 试新版 lede 时）按顺序做一遍，全部通过再更新 `lede.lock` / `feeds.lock`：

1. 保留配置升级，在网页点「保存并连接」，在手机上确认登录，状态变成「已连接」。
2. 电脑上 `dig` 内网域名得到内网地址，`curl` 能访问内网服务。
3. 重启路由器，不做任何手动操作，直接连接，结果同第 1、2 步。
4. 用旧备份恢复配置（会重启），连接后电脑仍能访问内网，`nft list ruleset | grep -c l2tp-vpn` 大于 0。
5. 连接中执行 `/etc/init.d/network restart`：要么 VPN 继续可用（电脑仍能访问内网），要么页面明确提示断开或需要重新连接，不能出现显示「已连接」却访问不了的情况。
6. 连接中执行 `kill -9 $(cat /var/run/l2tp-ipsec-client/worker.pid)`，再点「保存并连接」，能正常连上，不提示冲突。
7. 用 SSH 连上内网机器，保持 15 分钟以上不断开。
8. 故意填错密码或不在手机上确认，页面给出 PPP 失败的提示，日志里写明自动重连已关闭。

## 停止服务时看门狗的回收（2026-11-16）

上一版给 `lp_capture` 加了看门狗（到期 TERM 再补 KILL），但看门狗只是函数里的局部变量，停止服务时没有被谁管：

- 查询期间收到停止信号，`finish()` 会 `exit 0`，直接跳过 `lp_capture` 里 `wait` 之后的回收；
- `cleanup_attempt` 只结束 `command_pid`，不认识看门狗。

于是工作进程退出后，旧看门狗仍然活着，到期（3 或 5 秒）照旧向 `$pid` 发 TERM/KILL。`$pid` 那时已经被回收，PID 若被复用就会误伤别的进程。

修复：

- 看门狗记进全局 `command_watchdog`（和 `command_pid` 一个套路），`cleanup_attempt` 一开始就用 `KILL` 结束它。它剩下的 `sleep` 子进程没有任何后续动作，到期自己退出，不用管。
- 加 `lp_proc_start` / `lp_same_proc`：看门狗到点前先比对 `/proc/PID/stat` 的启动时间。进程已经没了、或者 PID 被复用（启动时间不同），就什么都不做。这一层是给「工作进程被 `kill -9`、清理根本没机会跑」准备的，那种情况谁也来不及回收。取不到启动时间（没有 `/proc`）时按「还是它」处理，保证超时本身仍然生效。
- 测试补到 11 项：`test_stop_kills_pending_watchdog` 直接抽取 worker 里**真实的** `cleanup_attempt` 跑停止流程（避免测试里养一份副本走偏），断言停止后看门狗已不在；另有 `lp_same_proc` 的比对逻辑测试（不依赖 `/proc`）和 Linux 上的真实解析测试。

对照验证：`test_stop_kills_pending_watchdog` 在上一版 `9425d9f` 上失败（`command_watchdog=none`，说明看门狗没被记录），修复后通过。`test_backend`、`test_retry_probe`、`test_domain_dns`、`test_routing`、`test_capture_timeout`、`test_ui_rules` 全过，`sh -n` 与 shellcheck（`-s dash -S warning`）无告警。

## 超时捕获的收尾：强制终止与测试补强（2026-11-16）

上一版 `lp_capture` 改用 `timeout` 之后留下两个问题，只查不修地复核后一并处理：

**清理阶段可能卡住。** `cleanup_attempt` 里的 `swanctl --terminate` 走 `lp_capture`，而 `finish()` 第一行是 `trap '' TERM INT`。`trap ''` 设的是「忽略」，忽略的处置会跨 fork/exec 被子进程继承（被捕获的才会在 exec 时恢复默认），所以 `timeout` 到点发的那一下 TERM 等于没发；`timeout` 不带 `-k` 时会一直等目标退出，`lp_capture` 的 `wait` 随之挂住，后面的 `lp_stop_pid charon`、`ppp-hook down`、`ip xfrm policy delete`、路由删除全都执行不到。只在停止服务/断开这条路径上触发；procd 约 15 秒后强杀，所以是「清理被中断」而不是永久卡死。

**测试只认 GNU 的返回值。** busybox 的 `timeout` 直接 `exec` 目标程序，由孙进程 `kill(parent, signo)`，源码里没有 124 这个返回值，程序被 TERM 结束后的 `$?` 是 143。测试硬断言 `rc=124`，Ubuntu CI 用 GNU timeout 所以通过，真机上跑必挂，也因此漏掉了上一条。

修复：

- `lp_capture` 不再调用 `timeout`，改为自己起一个看门狗：到期先 `TERM`，宽限 `LP_KILL_GRACE`（1 秒）后补 `KILL`。`SIGKILL` 不能被忽略，是最后一道保证；返回值由自己统一成 124，不再随 GNU/busybox 变化。
- 判断命令是否结束只用 `wait`，不再用 `kill -0` 轮询。busybox 的 ash 不回收后台子进程（`shell/ash.c` 的 `signal_handler` 对 SIGCHLD 只置 `got_sigchld`，只有 `wait` 才 `dowait`），已退出的命令会一直是僵尸，`kill -0` 照样成功——轮询会把正常结束的命令当成超时，正是 IPsec 被误判的另一种形态。
- `cleanup_attempt` 里把 `lp_capture 5` 收到 3 秒：内层 `--timeout 2` 已经限制住正常情况，而 procd 停止服务只等 15 秒，这里不能把预算吃光。
- `tests/test_capture_timeout.py` 补到 7 项：快速命令必须立刻返回且不能报超时、退出码原样透传、普通超时、命令忽略 TERM 仍能被结束、禁止小数 `sleep`、`lp_capture` 内禁止 `kill -0` 轮询和 `timeout` 依赖。

对照验证：用一个「只 `shift` 后 `exec`，什么都不杀」的 `timeout` 桩模拟 busybox 语义，把同一份新测试分别跑在修复前（`4a19da9`）和修复后——修复前「普通超时」「忽略 TERM」两项 25 秒内不返回（卡住），修复后 7 项全过。本机 `test_routing`、`test_domain_dns`、`test_backend`、`test_retry_probe`、`test_ui_rules` 均通过；`test_ensure_config` 的 `test_commit_released_lock_but_not_renamed_is_kept` 在修复前后的代码上都失败，是 macOS 上 uci 锁用例的既有差异，与本次改动无关。

## 真机故障修复：IPsec 建好却被判失败（2026-11-15）

现象：网页提示「IPsec 协商失败，请检查 PSK、身份标识和加密算法」，但 `charon.log` 里 IKE_SA 和 CHILD_SA 都已 `established`，紧接着 0 字节被本地删除（`sending DELETE`）。

原因：`lp_capture` 用 `sleep 0.1` 凑 5 秒预算（50 个 tick）。固件里的 busybox 没有编译小数延时（`CONFIG_FLOAT_DURATION=n`，`usleep` 也没开），每条 `sleep 0.1` 都直接报错退出，循环在几毫秒内跑完 50 次，把还在输出的 `swanctl --list-sas` 当成超时 `kill -9`，返回 124，`lp_has_ipsec` 于是判定 IPsec 没建立，`cleanup_attempt` 随即拆掉刚建好的隧道。这些 `sleep` 报错走 stderr，而 worker 的 stderr 指向 `/dev/null`，路由上看不到。

修复：

- `lp_capture` 优先用 busybox 默认开启的 `timeout`，没有它才按整秒轮询，不再依赖小数延时。（这条 `timeout` 的做法在下一轮被替换掉了，见上面「超时捕获的收尾」。）
- `lp_stop_pid`、`routing` 等 `dns.ready`、`rpcd` 的 `wait_stopped` 三处同样的小数延时，改成按截止时间等整秒。
- IPsec 失败时把 charon 日志里的最后一条错误带进状态提示，不再只有通用文案。
- 新增 `tests/test_capture_timeout.py`：用只接受整数、其余直接报错的 `sleep` 桩复现该问题，并禁止脚本里再出现小数 `sleep`。

本机复现对比：同一段 `lp_capture 5 ... /bin/sleep 1`，旧版打印 50 条 `sleep: invalid number '0.1'` 后返回 124，新版返回 0。

## PR 第四轮审核问题修复（2026-11-10）

针对基于 `29362b1` 的两项问题：

- 超过一分钟的活跃提交仍可能被覆盖：去掉临时文件的时间过滤。只要配置目录里有 `.<配置名>.uci-*`，就放弃写回，并在连接日志里写出路径。进行中的提交和异常退出的残留分不清（libuci 写完临时文件即关闭，也看不出有没有进程在用），取保守做法：残留文件需要人删除，删除前插件不写回该配置，另一份配置不受影响。
- 隔离重载失败后重新连接不会重试：重新加载失败时留下 `/var/run/l2tp-ipsec-client/firewall-reload-pending`。之后即使配置文件已没有差异，也按标记重试，成功后删除标记。重试时同样先检查暂存区，有别人的暂存改动就先不加载，免得冲掉他们手动重新加载过、尚未提交的设置。运行目录重启后清空，正好对应开机时防火墙按已提交配置完整加载。

本机两种 `sh` 下全部测试通过，防火墙配置自愈 15 项：新增「失败后按标记重试直到成功」「重试遇到暂存改动先等待」，「旧临时文件」改为「任何临时文件都放弃并写出路径」。这三项和「停在改名前的提交」在 `29362b1` 上失败。真实 libuci 复测：停在改名前的提交被保留；五分钟前的临时文件也会挡住写回，日志写出路径。

修复中发现 macOS 的 bash 3.2 在 UTF-8 环境下会把变量后紧跟的全角字符吞进变量名，新增那行提示改用 `${pending}`。固件的 busybox ash 和 dash 不受影响；其余脚本已检查，没有同样的写法。

## PR 第三轮审核问题修复（2026-11-10）

针对基于 `bd4fbb9` 的两项并发问题：

- 检查之后新暂存的设置仍会随重载生效：防火墙改在独立的挂载命名空间里重新加载（`unshare -m`，插件新增 `unshare` 依赖），命名空间里把空 tmpfs 挂到 `/tmp/.uci`，firewall4 只读到已提交的配置。已核对固定版本 firewall4（`18fc0ea`）的 init 脚本：`reload` 在当前进程调用 `fw4 reload`，在命名空间内执行。缺少 `unshare` 时不写回防火墙配置；隔离重载失败时在连接日志里写明。
- 文件锁不能防止覆盖并发提交：libuci（`66127cd`）的 `uci_file_commit` 先关闭配置文件释放锁，再把临时文件改名替换。写回在拿到锁后，再检查一分钟内的 `.<配置名>.uci-*` 临时文件：有就说明有提交已放锁、还没改名，放弃写回，下次再补；更早的临时文件是异常退出留下的，忽略。测试替身改为与 libuci 相同的「锁内写临时文件、放锁后改名」。

本机两种 `sh` 下全部测试通过，防火墙配置自愈 14 项（1 项需要 Linux 普通用户命名空间，CI 上执行）：新增「检查之后、重载之前另一会话暂存」「另一提交已放锁、停在改名前」「隔离重载失败」「异常退出留下的旧临时文件」，以及用真实 `unshare`、`mount` 的命名空间用例。前两项在 `bd4fbb9` 上失败。CI 新增一步放开 Ubuntu 24.04 对普通用户命名空间的 AppArmor 限制。

真实 libuci 复测：在本机编译的固件版本 uci 里，于「放锁之后、改名之前」加测试用的暂停点。另一会话提交 `DROP` 停在改名前，脚本最终核对之后放它改名：`bd4fbb9` 最终为 `REJECT`（`DROP` 被覆盖）；新版放弃写回，`DROP` 保留，改名完成后再跑，补齐插件区域，`DROP` 仍在。挂载命名空间无法在 macOS 上实测，由 CI 的 Linux 用例覆盖。

网络配置仍有的窗口：`network reload` 由常驻的 netifd 读取配置，无法用命名空间隔离；检查暂存区与 netifd 读取之间若有人恰好 `uci set network`，那条改动会随这次重新加载生效。只在一次性移除旧版 `network.l2tpipsec` 接口时触发。

## PR 复审问题修复（2026-11-10）

针对复审评论中基于 `970f48b` 的两项问题：

- 补齐配置后的重载提前应用其他暂存设置：firewall4、netifd 重新加载时会叠加 `/tmp/.uci` 里的暂存改动。`ensure-config` 改为：需要补齐的配置有别人的暂存改动（`uci changes <配置>` 非空）时，本次不写回也不重载，原因写进连接日志；只影响有暂存改动的那份配置。
- 比较原文件后再替换会覆盖并发提交：写回时与 `uci commit` 一样，对配置文件加 `flock` 排他锁，加锁后再用 inode 和内容核对原文件，核对与替换都在锁内；拿锁前文件已被替换时放弃。`flock` 由 busybox 默认提供。

本机两种 `sh` 下全部测试通过：防火墙配置自愈 9 项（新增「插件配置缺失且其他设置仍在暂存区」不写回、不重载，以及在最终核对之后发起提交的并发用例），工作进程 12 项（新增配置检查原因写进连接日志）。这些新用例在 `970f48b` 上失败。

真实 `uci`（`66127cd`）复测，重载入口记录重载时默认 uci 视图读到的值：
- `970f48b` 重载时读到暂存的 `ACCEPT`；新脚本不写回、不重载，放弃暂存改动后再跑，重载时读到的是 `REJECT` 和本插件区域。
- `970f48b` 在最终核对之后另一会话提交的 `DROP` 被旧副本覆盖回 `REJECT`；新脚本下另一会话等写回结束后再读取和提交，`DROP` 与本插件区域都保留。

此版仍留有检查之后、重载之前的窗口，以及 libuci 先放锁再改名带来的覆盖，见上方第三轮修复。

## PR 审核问题修复（2026-11-10）

针对 PR 评论中基于 `f1228c5` 的四项运行问题：

- 启动清理删除其他服务的路由配置：本插件加的规则逐条记在 `routing-rules`，断开和连接前的残留清理只按记录删除；没有归属标记时不清空表 `41717`。被其他服务占用时拒绝启动，并在页面写明占用的表和优先级。
- 路由恢复丢失已学习的域名路由：`domain-dns` 把学到的地址写入 `learned-routes`（先写临时文件再改名）。恢复改为 `routing repair`：DNS 进程不重启，按记录补回规则、网段、VPN DNS、域名地址路由和 nft 表；连接检查一次列出路由表，核对全部域名地址。
- 配置检查提交其他暂存的防火墙设置：`ensure-config` 在 `lp_` 开头的配置副本上修改，写回前核对原文件未被改动，只有本插件有改动时才写回并重载。`uci -t` 不能隔离，因为 libuci 始终读取 `/tmp/.uci`。
- IPsec 查询超时遗留进程：`lp_capture` 用 `exec` 让后台子进程直接成为外部命令，超时结束的就是 `swanctl` 本身；查询中途收到停止信号时由 `cleanup_attempt` 结束。断开时的 `swanctl --terminate` 也加了同样的超时。

本机（macOS）通过，`sh` 分别为 bash 3.2 和 dash 各跑一遍：配置与边界 9 项、重连/探测 4 项、DNS 模块 11 项（另用 ASan/UBSan 编译跑一遍）、路由管理 11 项、防火墙配置自愈 7 项、工作进程 11 项（1 项需要 Linux `/proc`，由 CI 执行）。复现这四项问题的新测试在 `f1228c5` 的代码上都失败。ShellCheck、JavaScript 语法检查、预览生成通过。

另用固件所用的 uci（`66127cd`）在本机编译出真实 `uci` 验证 `ensure-config`：旧脚本会把其他操作暂存的 `ACCEPT` 提交并重载防火墙；新脚本保留该暂存改动，配置完整时不写回、不重载，配置缺失时只写回本插件的段，旧接口迁移同样不影响其他暂存的网络改动，文件权限保持不变。

尚未完成：固件编译和 RT-ACRH17 真机验收（重点是连接中执行 `/etc/init.d/network restart` 后的原地恢复，以及恢复后已学习域名的访问）。

## 1.3.0：真机试用问题修复（2026-11-06）

修复 1.2.0 在 RT-ACRH17 上试用时发现的问题：

- 页面「保存并连接」出错时不提示：保存、应用、检查、启动每一步失败都弹出原因。
- 拨号失败：`xl2tpd-control` 的结果管道写死在 `/var/run/xl2tpd`，系统 xl2tpd 服务停用后没人创建，现由工作进程创建。
- 看不到 L2TP 日志：xl2tpd 加 `-l` 写系统日志，`xl2tpd-control` 输出进连接日志。
- 关闭自动重连时失败后静默退出：写明已停止。
- 冲突提示写明进程名、PID 和停用命令。
- 等手机确认登录的时间从 30 秒延长到 90 秒（PPP 等待和 PAP 重发次数），pppd 退出后提前结束等待。
- 恢复旧备份后防火墙区域丢失：新增 `ensure-config`，首次安装、开机、每次连接前补齐。
- netifd 接管 `l2tp-vpn` 时清空 VPN 地址和路由：不再建 netifd 接口，防火墙区域直接写网卡名；连接期间检查地址和路由，路由丢失时原地恢复。
- 异常退出的残留挡住下一次连接：连接前按 pid 文件和专用编号清理；会话标记防止旧工作进程拆掉新连接；查询 IPsec 状态加超时。
- 域名路由按 DNS TTL 删除导致长连接中断：改为整个连接期间保留，表满时只回收已过期地址。

本机（macOS）通过：配置与边界 8 项、重连/探测 4 项、DNS 模块 10 项、路由管理 7 项、防火墙配置自愈 4 项、工作进程 11 项（其中按进程名清理孤儿进程的 1 项需要 Linux `/proc`，由 CI 在 Linux 上执行）。ShellCheck、JavaScript 语法检查通过，预览已重新生成。

尚未完成：固件编译，以及真机上的恢复备份、强制结束工作进程后重连、网络服务重启后的路由恢复、长连接保持和手机确认登录验收。

## 1.2.0：统一规则列表、域名探测与重连策略（2026-11-05）

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
