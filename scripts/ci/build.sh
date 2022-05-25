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

pushd ${HOME}

# Fix build on CentOS
PKG_CONFIG="${TARGET_ARCH}-pkg-config"
if ! [ -x "$(command -v ${PKG_CONFIG})" ]; then
        PKG_CONFIG="pkg-config"
fi

# Default ODP library name
if [ -z "$ODP_LIB_NAME" ] ; then
ODP_LIB_NAME=libodp-dpdk
fi

# Additional warning checks
EXTRA_CHECKS="-Werror -Wall -Wextra -Wconversion -Wfloat-equal -Wpacked"
# Ignore clang warning about large atomic operations causing significant performance penalty
if [ "${CC#clang}" != "${CC}" ] ; then
	EXTRA_CHECKS="${EXTRA_CHECKS} -Wno-unknown-warning-option -Wno-atomic-alignment"
fi
# Ignore warnings from aarch64 DPDK internals
if [ "${TARGET_ARCH}" == "aarch64-linux-gnu" ] ; then
	EXTRA_CHECKS="${EXTRA_CHECKS} -Wno-conversion -Wno-packed"
fi

CC="${CC:-${TARGET_ARCH}-gcc}"
${CC} ${CFLAGS} ${EXTRA_CHECKS} ${OLDPWD}/example/sysinfo/odp_sysinfo.c -o odp_sysinfo_inst_dynamic \
	`PKG_CONFIG_PATH=/opt/odp/lib/pkgconfig:${PKG_CONFIG_PATH} ${PKG_CONFIG} --cflags --libs ${ODP_LIB_NAME}`

sysctl vm.nr_hugepages=1000
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

if [ -z "$TARGET_ARCH" ] || [ "$TARGET_ARCH" == "$BUILD_ARCH" ]
then
	LD_LIBRARY_PATH="/opt/odp/lib:$LD_LIBRARY_PATH" ./odp_sysinfo_inst_dynamic
fi
popd

#dpdk wrapper script can umount hugepages itself
umount /mnt/huge || true
