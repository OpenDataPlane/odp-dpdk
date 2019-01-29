#!/bin/bash
set -e

export TARGET_ARCH=x86_64-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
	sed -i 's/ODP_CHECK_CFLAG(\[\-Wcast-align\])/#ODP_CHECK_CFLAG(\[\-Wcast-align\])/g' /odp/configure.ac
fi

exec "$(dirname "$0")"/build.sh
