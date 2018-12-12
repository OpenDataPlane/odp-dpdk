#!/bin/bash
set -e

"`dirname "$0"`"/build_x86_64.sh

cd "$(dirname "$0")"/../..

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

sysctl vm.nr_hugepages=1000
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

make check

#dpdk wrapper script can umount hugepages itself
umount /mnt/huge || true
