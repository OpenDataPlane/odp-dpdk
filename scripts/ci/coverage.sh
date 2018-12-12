#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	CFLAGS="-O0 -coverage $CLFAGS" CXXFLAGS="-O0 -coverage $CXXFLAGS" LDFLAGS="--coverage $LDFLAGS" \
	--enable-debug=full --enable-helper-linux --disable-test-perf --disable-test-perf-proc
export CCACHE_DISABLE=1
make -j $(nproc)

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

ODP_SCHEDULER=basic    make check
ODP_SCHEDULER=sp       make check

bash <(curl -s https://codecov.io/bash) -X coveragepy
