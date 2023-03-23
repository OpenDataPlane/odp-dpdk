#!/bin/bash
set -e

CONFIG_OPT="--prefix=/opt/odp ${CONF}"

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

cd "$(dirname "$0")"/../..
./bootstrap
echo "./configure $CONFIG_OPT"
./configure $CONFIG_OPT

make clean

make -j $(nproc)

make install

make installcheck

umount /mnt/huge
