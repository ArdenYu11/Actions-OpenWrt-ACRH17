#!/bin/bash
# 在安装 feeds 之后、make defconfig 之前执行，当前目录是 lede 源码根目录。
# 用来改默认设置、替换软件包等。

# 示例：把默认管理地址从 192.168.1.1 改成 192.168.50.1
# sed -i 's/192.168.1.1/192.168.50.1/g' package/base-files/files/bin/config_generate
