#!/bin/sh

cp build_config/build.config .config

for i in build_config/*.conf; do
. $i
echo $board

DIST=$board
sed -i "s/option hostname.*$/option hostname $DIST/" ./package/base-files/files/etc/config/system
sed -i "s/\"actype\":\".*\"$/\"actype\":\"$DIST\"/" ./feeds/apop/myinit/root/etc/config/firmware.json
sed -i "s/CONFIG_VERSION_DIST=\".*\"/CONFIG_VERSION_DIST=\"$DIST\"/" ./.config
sed -i "s/CONFIG_VERSION_NUMBER=\".*\"/CONFIG_VERSION_NUMBER=\"v2.1-`date +%Y%m%d%H%M`\"/" ./.config
touch ./package/base-files/files/etc/openwrt_release

make

test $? -eq 0 || exit 1

DIST=`cat .config | grep CONFIG_VERSION_DIST | awk -F\" '{print $2}'`
VERSION=`cat .config | grep CONFIG_VERSION_NUMBER | awk -F\" '{print $2}'`

ls bin/ramips/*.bin | grep -v puppies | xargs rm >/dev/null 2>&1
mkdir -p bin/ramips/BY
echo mv bin/ramips/*$VERSION*puppies*bin bin/ramips/BY/$DIST-$VERSION
mv bin/ramips/*$VERSION*puppies*bin bin/ramips/BY/$DIST-$VERSION

done
