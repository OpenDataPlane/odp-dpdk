#!/bin/bash
set -e

export TARGET_ARCH=x86_64-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

exec "$(dirname "$0")"/build.sh
make doxygen-doc 2>&1 |tee doxygen.log
fgrep -rq warning ./doxygen.log
if [ $? -eq 0 ]; then
	exit -1
else
	exit  0
fi

