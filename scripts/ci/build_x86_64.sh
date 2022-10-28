#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
	sed -i 's/ODP_CHECK_CFLAG(\[\-Wcast-align\])/#ODP_CHECK_CFLAG(\[\-Wcast-align\])/g' /odp/configure.ac
fi

exec "$(dirname "$0")"/build.sh
