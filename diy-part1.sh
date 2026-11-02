#!/bin/bash
# 在更新 feeds 之前执行，当前目录是 lede 源码根目录。
# 用来增删 feeds 源（lede 默认已启用 helloworld）。

# 示例：添加第三方 feed
# echo 'src-git 名称 https://github.com/用户/仓库.git' >> feeds.conf.default
