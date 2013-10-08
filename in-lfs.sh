#!/bin/bash

MODNAME="dm-gecko_mod"
NAME="gecko"
META_FILE="/tmp/foo-lfs"

if [ $# -ne 2 ]; then
	echo "Usage $0 <init-from-persistent-store (1=true | 0=false)> layout (linear | raid1 | raid0)"
	exit 1
fi

PERSIST=$1
LAYOUT=$2

DISK_LIST=""
if [ $LAYOUT == "raid1" ]; then
  DISK_LIST="g h"
elif [ $LAYOUT == "linear" ]; then
#  DISK_LIST="h"
  DISK_LIST="g h"
elif [ $LAYOUT == "raid0" ]; then
  DISK_LIST="f h"
else
    echo "Invalid layout $LAYOUT"
    exit 1
fi

sudo insmod "./${MODNAME}.ko"

devsize=0
DEVS=0
devlist=""

for i in $DISK_LIST; do
	devname="/dev/sd${i}"
	blockdevsize=`sudo blockdev --getsz $devname`
	devsize=`echo "$devsize + $blockdevsize" | bc`
	echo "$devname $blockdevsize $devsize"
	devlist="$devlist$devname "
	let DEVS="$DEVS+1"
done

if [ $LAYOUT == "raid1" ]; then
	echo "Halving the total size for $LAYOUT"
	devsize=`echo "$devsize / 2" | bc`
fi

echo 0 "$devsize" gecko "${PERSIST}" "${META_FILE}" "${LAYOUT}" "${DEVS}" \
	"${devlist}" | sudo dmsetup create "${NAME}"
