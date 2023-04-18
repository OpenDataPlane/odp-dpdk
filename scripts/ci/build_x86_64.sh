#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
	sed -i 's/ODP_CHECK_CFLAG(\[\-Wcast-align\])/#ODP_CHECK_CFLAG(\[\-Wcast-align\])/g' /odp/configure.ac
fi

# Required by CentOS and Rocky Linux to find DPDK install
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig/

exec "$(dirname "$0")"/build.sh
