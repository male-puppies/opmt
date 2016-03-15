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
mkdir -p bin/ramips/AC
echo mv bin/ramips/*$VERSION*puppies*bin bin/ramips/AC/UploadBrush-bin.img
mv bin/ramips/*$VERSION*puppies*bin bin/ramips/AC/UploadBrush-bin.img

BINMD5=`md5sum bin/ramips/AC/UploadBrush-bin.img | awk '{print $1}'`
BINRANDOM=$bin_random
RANDMD5=`echo -n $BINRANDOM | md5sum | awk '{print $1}'`
echo -n ${BINMD5}${RANDMD5} | md5sum | awk '{print $1}' >  bin/ramips/AC/bin_random.txt
cd  bin/ramips/AC/
tar -zcf $DIST-$VERSION".tar.gz" UploadBrush-bin.img bin_random.txt
rm UploadBrush-bin.img bin_random.txt
mv $DIST-$VERSION".tar.gz" $DIST-$VERSION
cd -

done
