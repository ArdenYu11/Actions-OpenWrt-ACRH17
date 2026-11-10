# RT-ACRH17 固件编译

用 GitHub Actions 基于 [coolsnowwolf/lede](https://github.com/coolsnowwolf/lede) 编译华硕 RT-ACRH17 固件。工作流结构参考 [P3TERX/Actions-OpenWrt](https://github.com/P3TERX/Actions-OpenWrt)。

## 编译

Actions → **Build RT-ACRH17 (lede)** → Run workflow。选择分支，并设置「编译成功后发布 Release」（默认关闭）。首次编译约 2–3 小时。

编译成功后，固件始终上传到这次运行页面底部的 Artifacts；只有开启发布选项，才会同时创建 Release。验证构建保持发布选项关闭，下载附件验收后再决定发布。

### 固定 lede 版本

默认按 `lede.lock`（lede 提交）和 `feeds.lock`（packages、luci 等 feeds 的提交）编译，每次编出来的源码都一样，不会被 lede 当天的更新影响。strongswan、xl2tpd、LuCI 都在 feeds 里，所以两个文件都要锁。

想试新版 lede 时：

1. Run workflow 时把「lede 源码版本」选成 `latest`，编译最新代码
2. 刷到路由器上，按 [tests/VALIDATION.md](tests/VALIDATION.md) 验证 VPN 等功能
3. 没问题的话，把这次产物里的 `lede.lock`、`feeds.lock` 拷到仓库根目录覆盖并提交，之后的默认编译就固定在这个版本

有问题就不用管，默认编译仍然用原来固定的版本。每次编译的产物里都带这两个文件，记录的是这次实际用到的版本。

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `acrh17.config` | 机型和软件包配置，需要的包追加 `CONFIG_PACKAGE_xxx=y` |
| `lede.lock`、`feeds.lock` | 默认编译固定使用的 lede 和 feeds 版本，见「固定 lede 版本」 |
| `diy-part1.sh` | 更新 feeds 前执行，增删 feeds 源 |
| `diy-part2.sh` | 安装 feeds 后执行，改默认 IP 等 |
| `files/` | 里面的文件原样放进固件根目录，例如 `files/etc/uci-defaults/` 下的脚本会在首次开机时执行 |

lede 里 RT-ACRH17 和 RT-AC42U 共用 `asus_rt-ac42u` 定义，所以固件文件名里是 `asus_rt-ac42u`。

已集成可独立维护的 L2TP/IPsec 客户端插件，在「VPN → L2TP/IPsec 客户端」统一填写服务器、账号密码和 PSK。通过一个编译配置项自动带入依赖，配置和预览方法见 [插件说明](packages/README.md)。

硬件是 IPQ4019 + 256 MB 内存 + 128 MB NAND，Docker、AdGuardHome 这类重型插件跑起来会很吃力，插件别贪多。

## 软件源与内核模块

lede 的内核是 6.18，但它把固件里的软件源写死成了官方 OpenWrt 24.10.5（内核 6.6）。网上没有任何源提供和本固件内核匹配的内核模块（`kmod-*`），所以：

- **需要内核模块的功能，都在 `acrh17.config` 里选上编进固件**，例如 `CONFIG_PACKAGE_kmod-tun=y`。依赖的模块会自动带进来
- 固件首次开机时会自动注释掉软件源里的 core 源（ipq40xx 目标包），免得装到不匹配的包，见 `files/etc/uci-defaults/zzzz-acrh17-distfeeds`
- 其余软件源还能用 opkg 装一些纯用户态的小工具，但依赖内核模块的包会因为缺依赖装不上，这类包同样要编进固件

## 刷机

> 刷机有变砖风险。下面的步骤整理自 OpenWrt 论坛里同型号用户的[实测帖](https://forum.openwrt.org/t/need-help-installing-openwrt-on-asus-rt-acrh17-rev-1-60-aka-rt-ac42u/155428)，不用拆机，但本仓库没有在真机上验证过。

整个过程分两段：先在原厂固件里写入官方 OpenWrt 的跳板镜像，从它启动一个只在内存里运行的临时系统；再在临时系统里刷入本仓库编译的正式固件。

### 准备

- 一根网线，电脑接路由器的**黄色 LAN 口**，全程不要用 Wi-Fi
- 原厂固件版本 **3.0.0.4.382_52517 或更新**。论坛反馈在 382_50470 上第 3 步的 `mtd-write` 不生效。原厂固件在华硕官网 RT-ACRH17 的支持页下载
- 下载两个文件，放到「下载」文件夹：
  - 官方 OpenWrt 跳板镜像：[openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb](https://downloads.openwrt.org/releases/25.12.6/targets/ipq40xx/generic/openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb)（约 8 MB）
  - 本仓库 Release 里以 `asus_rt-ac42u-squashfs-sysupgrade.bin` 结尾的文件。下文写作 `openwrt-ipq40xx-generic-asus_rt-ac42u-squashfs-sysupgrade.bin`，以实际文件名为准
- 下文命令里的 `admin` 换成你在原厂固件里设置的管理员账号

跳板不用本仓库编译的镜像：本仓库的固件带全套插件，体积大，没人验证过能写进原厂的 `linux` 分区并启动；官方跳板体积小，论坛有人实测成功。

### 第 1 步：在原厂固件里开启 SSH

1. （建议）先恢复出厂设置，再按向导完成初始设置
2. 后台「系统管理 → 系统」：「启用 SSH」选 LAN only，端口 22，「允许密码登录」选是，然后点应用

后台地址是 http://router.asus.com ，打不开就用路由器背面标的 IP。

### 第 2 步（强烈建议）：备份原厂闪存分区

以后想刷回原厂或者救砖，这份备份是唯一的原始数据，尤其是存放无线校准数据和 MAC 地址的 Factory 分区，丢了没处找。

```bash
mkdir -p ~/acrh17-backup && cd ~/acrh17-backup
ssh admin@router.asus.com cat /proc/mtd | tee proc_mtd.txt
for n in $(tail -n +2 proc_mtd.txt | cut -d: -f1); do ssh admin@router.asus.com "cat /dev/$n" > "$n.bin"; done
ls -lh
```

- 每读一个分区要输一次密码
- `proc_mtd.txt` 记录了 `mtdN.bin` 和分区名的对应关系
- 个别分区读不出来可以跳过，但 Bootloader、Factory 这几个小分区一定要备份成功
- 把整个 `~/acrh17-backup` 文件夹另存一份到别的地方

### 第 3 步：写入跳板镜像并重启

```bash
cd ~/Downloads
scp -O openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb admin@router.asus.com:/tmp/
ssh admin@router.asus.com
```

登录路由器后执行：

```
mtd-unlock -d linux
mtd-write -d linux -i /tmp/openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb
reboot -f
```

- `scp` 的 `-O` 不能省：原厂系统没有 sftp，新版 scp 默认走 sftp 会失败
- `mtd-unlock` 报错可以忽略
- `mtd-write` 正常要跑几秒。如果敲完立刻返回，说明没写进去（多半是原厂版本太旧），先升级原厂固件再从第 1 步来

### 第 4 步：上传正式固件

重启 1–2 分钟后，路由器运行的是临时 OpenWrt，地址 **192.168.1.1**，root **没有密码**（提示输入密码直接回车）。拔插一下网线，让电脑重新获取到 192.168.1.x 的地址。

```bash
cd ~/Downloads
ssh-keygen -R 192.168.1.1
scp -O openwrt-ipq40xx-generic-asus_rt-ac42u-squashfs-sysupgrade.bin root@192.168.1.1:/tmp/
```

### 第 5 步：删除原厂的 jffs2 卷，刷入正式固件

```bash
ssh root@192.168.1.1
```

登录后依次执行：

```
ubinfo -a | grep Name
ubirmvol /dev/ubi0 --name=jffs2
sysupgrade -n -v /tmp/openwrt-ipq40xx-generic-asus_rt-ac42u-squashfs-sysupgrade.bin
```

- 先确认第一条的输出里有 `jffs2`。这是原厂留下的数据卷，不删的话正式固件放不下
- `sysupgrade` 必须加 `-n`（不保留配置）：官方 OpenWrt 在这个机型上用 DSA，lede 用 swconfig，网络配置不通用
- 如果提示镜像不兼容，**不要加 `-F` 强刷**，先停下来查原因
- 刷写约 3 分钟，路由器会自动重启，期间不要断电

### 第 6 步：完成

打开 http://192.168.1.1 ，用户 `root`，密码 `password`。登录后先到「系统 → 管理权」改密码，再设置上网和无线。

### 常见问题

| 现象 | 处理 |
| --- | --- |
| scp 报 `subsystem request failed`，或者一直卡住 | 命令里漏了 `-O` |
| `mtd-write` 立刻返回，重启后还是原厂系统 | 原厂版本太旧，升级到 382_52517 或更新后重来 |
| ssh 报 `REMOTE HOST IDENTIFICATION HAS CHANGED` | 执行 `ssh-keygen -R 192.168.1.1`（或 `router.asus.com`）后重试 |
| 连不上 192.168.1.1 | 电脑有线网卡手动设成 192.168.1.10 / 255.255.255.0 |

### 以后升级

后台「系统 → 备份/升级 → 刷写新的固件」，上传新编译的 `squashfs-sysupgrade.bin`。

## 刷回原厂固件

> **先说结论**：RT-ACRH17 从 lede 或新版 OpenWrt 刷回原厂，目前没有公开验证过的不拆机方法。打算以后回原厂的，刷机前务必做好上面第 2 步的备份，并准备一根 3.3V 的 USB-TTL 串口线。

### 为什么麻烦

华硕的救援模式会把原厂固件写进名为 `linux` 的 UBI 卷。OpenWrt 把这个卷改成了刚好放下自己内核的大小，原厂固件写不进去，失败后又启动回 OpenWrt。串口日志里能看到 `size > volume size! Aborting!`，见 [openwrt/openwrt#9879](https://github.com/openwrt/openwrt/issues/9879)。

网上流传的 [RT-AC58U 回原厂方法](https://openwrt.org/toh/asus/rt-ac58u#returning_to_stock)（删 `linux2` 卷，执行 `sysupgrade -F /bin/busybox`，再用华硕恢复工具）只在 OpenWrt 21.02 上有效。RT-ACRH17 从 22.03 才开始被支持，没法先降级到 21.02 绕过去。同平台的 Lyra 上有人这样试过，结果既进不了救援模式也 SSH 不上，最后只能[拆机接串口](https://forum.openwrt.org/t/map-ac2200-upgrade-and-return-to-factory-default/138755)。**不建议不拆机硬试。**

### 拆机接串口的做法

思路：从串口让路由器在内存里启动一个临时系统，在里面删掉 OpenWrt 建的卷，复现 21.02 上那个方法成功时的状态，再用救援模式写入原厂固件。

这套做法根据同平台 RT-AC58U 和 Lyra 的经验整理，**在 RT-ACRH17 上没有公开的成功记录**，动手前建议先去 OpenWrt 论坛确认。好在全程不碰 bootloader，失败了也能用同样的串口方法重新刷回 OpenWrt。

1. **准备**
   - 3.3V 的 USB-TTL 串口线（**不能用 5V**）
   - 原厂固件 `.trx`（华硕官网下载）
   - 安装时用过的官方跳板镜像 `.itb`
   - 拆开底部 4 颗螺丝（会破坏保修贴），主板上标好了 GND、RXD、TXD。交叉接线：串口线的 TX 接 RXD，RX 接 TXD，GND 接 GND，VCC 不接
   - 电脑有线网卡手动设成 192.168.1.70 / 255.255.255.0，网线接路由器 LAN 口
2. **开启 Mac 自带的 TFTP 服务，放入跳板镜像**
   ```bash
   sudo cp ~/Downloads/openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb /private/tftpboot/
   sudo launchctl load -F /System/Library/LaunchDaemons/tftp.plist
   ```
3. **打开串口终端**（设备名用 `ls /dev/tty.usbserial*` 查）
   ```bash
   screen /dev/tty.usbserial-XXXX 115200
   ```
4. **从内存启动临时系统**：给路由器通电，出现启动菜单后 3 秒内按 `1`（Load System code to SDRAM via TFTP）。设备 IP 填 192.168.1.1，服务器 IP 填 192.168.1.70，文件名填跳板镜像的文件名
5. **删除 OpenWrt 建的卷**：临时系统启动后，在串口里回车出现 `root@OpenWrt` 提示符，执行
   ```
   ubinfo -a | grep Name
   ubirmvol /dev/ubi0 -N linux2
   ubirmvol /dev/ubi0 -N linux
   ubirmvol /dev/ubi0 -N rootfs
   ubirmvol /dev/ubi0 -N rootfs_data
   ```
   先对照第一条列出的卷名，列表里没有的跳过。**只删这四个，别动 Factory 等其他卷**
6. **进入救援模式**：拔电再通电。正常情况下 bootloader 找不到系统会自动进入救援模式，串口里会出现 `Enter Rescue Mode`、`tftpd start`。没有的话就拔电，按住 reset 键再通电，等串口出现这几行再松开
7. **写入原厂固件**，两种方式任选：
   - 华硕 Firmware Restoration 工具：Mac 在 App Store 搜 “Firmware Restoration”，Windows 在[华硕官网](https://www.asus.com/support/FAQ/1000814/)下载。选择原厂 `.trx`，点上传
   - 工具连不上时，用 Mac 自带的 tftp 直接上传（救援模式本质上就是一个 TFTP 服务器）：
     ```bash
     tftp 192.168.1.1
     ```
     进入 `tftp>` 提示符后依次输入 `binary`、`put RT-ACRH17_原厂固件.trx`、`quit`

   串口里出现写入完成并自动重启，等进入原厂系统即可
8. **收尾**：关闭 TFTP 服务，网卡改回自动获取
   ```bash
   sudo launchctl unload -F /System/Library/LaunchDaemons/tftp.plist
   ```

如果第 7 步之后又启动回了 OpenWrt，或者卡在某一步，把串口里的完整日志保存下来，去 OpenWrt 论坛求助。
