#!/bin/bash
#
# Copyright (c) 2016-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

NUM_RX_PORT=3
RETVAL=0

PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name udp64.pcap -print -quit`
PCAP_EMPTY=`find . ${TEST_DIR} $(dirname $0) -name empty.pcap -print -quit`

echo "Switch test using PCAP_IN = ${PCAP_IN}"

RX_PORTS=""
RX_VDEVS=""
for i in `seq 1 $NUM_RX_PORT`;
do
	RX_PORTS="${RX_PORTS},${i}"
	RX_VDEVS="${RX_VDEVS} --vdev net_pcap${i},rx_pcap=${PCAP_EMPTY},tx_pcap=pcapout${i}.pcap"
done

export ODP_PLATFORM_PARAMS="--no-pci \
--vdev net_pcap0,rx_pcap=${PCAP_IN},tx_pcap=/dev/null ${RX_VDEVS}"

./odp_switch${EXEEXT} -i 0${RX_PORTS} -t 1
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  RETVAL=1
fi

for i in `seq 1 $NUM_RX_PORT`;
do
	if [ `stat -c %s pcapout${i}.pcap` -ne `stat -c %s ${PCAP_IN}` ]; then
		echo "Error: Output file $i size not matching"
		RETVAL=1
	fi
	rm -f pcapout${i}.pcap
done

exit $RETVAL
