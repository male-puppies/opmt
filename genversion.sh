#!/bin/sh

sed -i "s/CONFIG_VERSION_NUMBER=\"[0-9].*\"/CONFIG_VERSION_NUMBER=\"`date +%Y%m%d`\"/g" ./.config
touch ./package/base-files/files/etc/openwrt_release
