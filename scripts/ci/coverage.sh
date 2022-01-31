#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	CFLAGS="-O0 -coverage $CFLAGS" CXXFLAGS="-O0 -coverage $CXXFLAGS" LDFLAGS="--coverage $LDFLAGS" \
	--enable-debug=full --enable-helper-linux
export CCACHE_DISABLE=1
make -j $(nproc)

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

ODP_SCHEDULER=basic    make check

# Run only validation tests for the sp scheduler
pushd ./test/validation/api/
ODP_SCHEDULER=sp       make check
popd

# Convert gcno files into gcov (required by Codecov)
find . -type f -name '*.gcno' -exec gcov -pb {} +

