#!/bin/bash
set -e

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=${BUILD_ARCH:-x86_64-linux-gnu} \
	--prefix=/opt/odp \
	${CONF}

make clean

make -j $(nproc)

make install

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

make installcheck

umount /mnt/huge
