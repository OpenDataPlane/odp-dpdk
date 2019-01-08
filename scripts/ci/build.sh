#!/bin/bash
set -e

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--host=${TARGET_ARCH} --build=x86_64-linux-gnu \
	--prefix=/opt/odp \
	${CONF}

make -j $(nproc)

make install

pushd ${HOME}

# Fix build on CentOS
PKG_CONFIG="${TARGET_ARCH}-pkg-config"
if ! [ -x "$(command -v ${PKG_CONFIG})" ]; then
        PKG_CONFIG="pkg-config"
fi

CC="${CC:-${TARGET_ARCH}-gcc}"
${CC} ${CFLAGS} ${OLDPWD}/example/hello/odp_hello.c -o odp_hello_inst_dynamic \
	`PKG_CONFIG_PATH=/opt/odp/lib/pkgconfig ${PKG_CONFIG} --cflags --libs libodp-linux` \
	`${PKG_CONFIG} --cflags --libs libdpdk`

sysctl vm.nr_hugepages=1000
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

if [ -z "$TARGET_ARCH" ]
then
	LD_LIBRARY_PATH="/opt/odp/lib:$LD_LIBRARY_PATH" ./odp_hello_inst_dynamic
fi
popd

#dpdk wrapper script can umount hugepages itself
umount /mnt/huge || true
