#!/bin/bash
#
# Copyright (c) 2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name udp64.pcap -print -quit`

export ODP_PLATFORM_PARAMS="--no-pci \
--vdev net_pcap0,rx_pcap=${PCAP_IN},tx_pcap=/dev/null"

echo "Packet dump test using PCAP_IN = ${PCAP_IN}"

./odp_packet_dump${EXEEXT} -i 0 -n 10 -o 0 -l 64
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  exit 1
fi

exit 0
