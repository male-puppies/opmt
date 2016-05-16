#!/bin/sh


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

ls bin/ar71xx/*.bin | grep -v '16M-squashfs-sysupgrade' | xargs rm >/dev/null 2>&1
mkdir -p bin/ar71xx/BY
echo mv bin/ar71xx/*16M-squashfs-sysupgrade*bin bin/ar71xx/BY/UploadBrush-bin.img
mv bin/ar71xx/*16M-squashfs-sysupgrade*bin bin/ar71xx/BY/UploadBrush-bin.img

BINMD5=`md5sum bin/ar71xx/BY/UploadBrush-bin.img | awk '{print $1}'`
BINRANDOM=${board}${bin_random}
RANDMD5=`echo -n $BINRANDOM | md5sum | awk '{print $1}'`
echo -n ${BINMD5}${RANDMD5} | md5sum | awk '{print $1}' >  bin/ar71xx/BY/bin_random.txt
cd  bin/ar71xx/BY/
tar -zcf $DIST-$VERSION".tar.gz" UploadBrush-bin.img bin_random.txt
rm UploadBrush-bin.img bin_random.txt
mv $DIST-$VERSION".tar.gz" $DIST-$VERSION
cd -

done
