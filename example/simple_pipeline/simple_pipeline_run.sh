#!/bin/bash
#
# Copyright (c) 2019, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

# Exit code expected by automake for skipped tests
TEST_SKIPPED=77

PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name udp64.pcap -print -quit`
echo "using PCAP_IN = ${PCAP_IN}"

if [ $(nproc --all) -lt 3 ]; then
  echo "Not enough CPU cores. Skipping test."
  exit $TEST_SKIPPED
fi

export ODP_PLATFORM_PARAMS="--no-pci \
--vdev net_pcap0,rx_pcap=${PCAP_IN},tx_pcap=/dev/null \
--vdev net_pcap1,rx_pcap=${PCAP_IN},tx_pcap=pcapout.pcap"

./odp_simple_pipeline${EXEEXT} -i 0,1 -e -t 2
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  exit 1
fi

if [ `stat -c %s pcapout.pcap` -ne `stat -c %s  ${PCAP_IN}` ]; then
  echo "File sizes disagree"
  exit 1
fi

rm -f pcapout.pcap

exit 0
