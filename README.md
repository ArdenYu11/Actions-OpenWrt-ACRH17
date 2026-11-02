# RT-ACRH17 固件编译

用 GitHub Actions 基于 [coolsnowwolf/lede](https://github.com/coolsnowwolf/lede) 编译华硕 RT-ACRH17 固件。工作流结构参考 [P3TERX/Actions-OpenWrt](https://github.com/P3TERX/Actions-OpenWrt)。

## 编译

Actions → **Build RT-ACRH17 (lede)** → Run workflow。首次编译约 2–3 小时。

编译完成后固件在两处：
- 这次运行页面底部的 Artifacts
- Releases（运行时勾选了“发布 Release”）

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `acrh17.config` | 机型和软件包配置，需要的包追加 `CONFIG_PACKAGE_xxx=y` |
| `diy-part1.sh` | 更新 feeds 前执行，增删 feeds 源 |
| `diy-part2.sh` | 安装 feeds 后执行，改默认 IP 等 |

lede 里 RT-ACRH17 和 RT-AC42U 共用 `asus_rt-ac42u` 定义，所以固件文件名里是 `asus_rt-ac42u`。

## 刷机

刷好后后台 http://192.168.1.1 ，用户 `root`，密码 `password`。

### 从原厂固件首次刷入（不用拆机）

用官方 OpenWrt 的 initramfs 镜像做跳板，再刷本仓库编译的 sysupgrade 镜像。方法来自 [OpenWrt 论坛实测](https://forum.openwrt.org/t/need-help-installing-openwrt-on-asus-rt-acrh17-rev-1-60-aka-rt-ac42u/155428)。

1. 原厂固件升级到 3.0.0.4.382_52517 或更新（旧版本上 `mtd-write` 不生效），在「系统管理 → 系统」里开启 SSH（LAN only，端口 22）
2. 下载官方跳板镜像 [openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb](https://downloads.openwrt.org/releases/25.12.6/targets/ipq40xx/generic/openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb)，和本仓库 Release 里的 `squashfs-sysupgrade.bin`
3. 写入跳板：
   ```bash
   scp -O openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb admin@router.asus.com:/tmp/
   ssh admin@router.asus.com
   mtd-write -d linux -i /tmp/openwrt-25.12.6-ipq40xx-generic-asus_rt-ac42u-initramfs-uImage.itb
   reboot -f
   ```
4. 重启后进入临时 OpenWrt（192.168.1.1，root 无密码），刷入正式固件：
   ```bash
   scp -O <本仓库的>-squashfs-sysupgrade.bin root@192.168.1.1:/tmp/
   ssh root@192.168.1.1
   ubirmvol /dev/ubi0 --name=jffs2
   sysupgrade -n -v /tmp/<本仓库的>-squashfs-sysupgrade.bin
   ```

`scp -O` 不能省：路由器上没有 sftp。`sysupgrade -n` 不保留配置：官方 OpenWrt 用 DSA，lede 这个平台用 swconfig，网络配置不兼容。

### 已经是本仓库的固件

后台「系统 → 备份/升级」刷 `squashfs-sysupgrade.bin`。

硬件是 IPQ4019 + 256 MB 内存 + 128 MB NAND，Docker、AdGuardHome 这类重型插件跑起来会很吃力，插件别贪多。
