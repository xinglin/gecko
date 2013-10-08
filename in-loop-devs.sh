#!/bin/bash

MODNAME="dm-gecko_mod"
NAME="gecko"
META_FILE="/tmp/foo"

#DEVS="10"
DEVS="4"

if [ $# -ne 2 ]; then
	echo "Usage $0 <init-from-persistent-store (1=true | 0=false)> layout (linear | raid1)"
	exit 1
fi

PERSIST=$1
LAYOUT=$2

if [ $LAYOUT != "raid1" -a $LAYOUT != "linear"  ]; then
	echo "Invalid layout $LAYOUT"
	exit 1
fi

sudo insmod "./${MODNAME}.ko"

devsize=0
devlist=""
for ((i=0;i<"${DEVS}";i++)); do
	devname="/dev/loop${i}"
	blockdevsize=`sudo blockdev --getsz $devname`
	devsize=`echo "$devsize + $blockdevsize" | bc`
	echo "$devname $blockdevsize $devsize"
	devlist="$devlist$devname "
done

if [ $LAYOUT == "raid1" ]; then
	echo "Halving the total size for $LAYOUT"
	devsize=`echo "$devsize / 2" | bc`
fi

echo 0 "$devsize" gecko "${PERSIST}" "${META_FILE}" "${LAYOUT}" "${DEVS}" \
	"${devlist}" | sudo dmsetup create "${NAME}"

