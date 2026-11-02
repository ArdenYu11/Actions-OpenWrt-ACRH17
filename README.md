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

- 默认后台 http://192.168.1.1 ，用户 `root`，密码 `password`
- 从原厂固件首次刷入：用文件名含 `initramfs` 的镜像，具体步骤见 [OpenWrt Wiki](https://openwrt.org/toh/asus/rt-acrh17)
- 已经是 OpenWrt：直接用 `squashfs-sysupgrade.bin` 升级

硬件是 IPQ4019 + 256 MB 内存 + 128 MB NAND，Docker、AdGuardHome 这类重型插件跑起来会很吃力，插件别贪多。
