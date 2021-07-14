#!/bin/bash
set -e

echo 1500 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

"`dirname "$0"`"/build_${ARCH}.sh

cd "$(dirname "$0")"/../..

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

# Run only validation tests
pushd ./test/validation/api/
make check
popd

#dpdk wrapper script can umount hugepages itself
umount /mnt/huge || true
