#!/bin/sh
filename=`cat .config | grep CONFIG_VERSION_NUMBER | awk -F\" '{print $2}'`
test $? -eq 0 || exit 1

cd bin/ramips/
ls *.bin | grep -v puppies | xargs rm >/dev/null 2>&1 
echo mv *AC1032-201601271754-V2.1*bin $filename
mv *AC1032-201601271754-V2.1*bin $filename