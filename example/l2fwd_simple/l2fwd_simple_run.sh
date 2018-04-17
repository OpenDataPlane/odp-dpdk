#!/bin/bash
#
# Copyright (c) 2016-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name udp64.pcap -print -quit`
echo "using PCAP_IN = ${PCAP_IN}"

export ODP_PLATFORM_PARAMS="--no-pci \
--vdev net_pcap0,rx_pcap=${PCAP_IN},tx_pcap=pcapout.pcap \
--vdev net_pcap1,rx_pcap=${PCAP_IN},tx_pcap=pcapout.pcap"

./odp_l2fwd_simple${EXEEXT} 0 1 \
	02:00:00:00:00:01 02:00:00:00:00:02 &

sleep 1
kill -s SIGINT $!
wait $!
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

./odp_l2fwd_simple${EXEEXT} null:0 null:1 \
	02:00:00:00:00:01 02:00:00:00:00:02 &

sleep 1
kill -s SIGINT $!
wait $!
STATUS=$?

if [ "$STATUS" -ne 255 ]; then
  echo "Error: status was: $STATUS, expected 255"
  exit 1
fi

exit 0
