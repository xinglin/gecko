#!/bin/bash

MODNAME="dm-gecko_mod"
NAME="gecko"
META_FILE="/tmp/foo"

if [ $# -ne 2 -a $# -ne 3 ]; then
	echo "Usage $0 <init-from-persistent-store (1=true | 0=false)> layout (linear | raid1 | raid0) [<number of stripes>]"
	exit 1
fi

PERSIST=$1
LAYOUT=$2

if [ $LAYOUT != "raid1" -a $LAYOUT != "linear" -a $LAYOUT != "raid0" ]; then
	echo "Invalid layout $LAYOUT"
	exit 1
fi

STRIPES=""
if [ $# -ne 2 -a $LAYOUT == "linear" ]; then
        echo "Invalid arguments: linear layout does not take # of stripes"
	exit 1
else
        STRIPES=$3
fi

sudo insmod "./${MODNAME}.ko"

devsize=0
DEVS=0
devlist=""
for i in c d e f g h; do
#for i in c d e f g; do
#for i in c d e f; do
#for i in c d e; do
#for i in h; do
#for i in g h; do
	devname="/dev/sd${i}"
	blockdevsize=`sudo blockdev --getsz $devname`
	devsize=`echo "$devsize + $blockdevsize" | bc`
	echo "$devname $blockdevsize $devsize"
	devlist="$devlist$devname "
	let DEVS="$DEVS+1"
done

if [ $LAYOUT == "raid1" ]; then
	echo "Dividing the total size for $LAYOUT by ${STRIPES}"
	devsize=`echo "$devsize / $STRIPES" | bc`
fi

echo 0 "$devsize" gecko "${PERSIST}" "${META_FILE}" "${LAYOUT}" "${STRIPES}" \
    "${DEVS}" "${devlist}" | sudo dmsetup create "${NAME}"
