#!/bin/sh 
./genversion.sh 
make -j1 V=s
./renamepackage.sh 