#!/bin/sh

sed -i "s/CONFIG_VERSION_NUMBER=\".*\"/CONFIG_VERSION_NUMBER=\"BY1032-`date +%Y%m%d%H%M-V2.1`\"/g" ./.config
touch ./package/base-files/files/etc/openwrt_release
