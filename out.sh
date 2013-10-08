#!/bin/bash

NAME="gecko"

#get the final stats
echo "Final stats:"
sudo dmsetup table "${NAME}" && sudo dmsetup status "${NAME}"
sudo dmsetup remove "${NAME}"
sudo rmmod "./dm-${NAME}_mod.ko"
