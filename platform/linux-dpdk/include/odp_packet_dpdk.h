/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPDK_H_
#define ODP_PACKET_DPDK_H_

#include <odp/api/packet_io.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp_packet_internal.h>

#include <stdint.h>

/* Flags for pkt_dpdk_t.supported_ptypes */
#define PTYPE_VLAN      0x01
#define PTYPE_VLAN_QINQ 0x02
#define PTYPE_ARP       0x04
#define PTYPE_IPV4      0x08
#define PTYPE_IPV6      0x10
#define PTYPE_UDP       0x20
#define PTYPE_TCP       0x40

/** Packet parser using DPDK interface */
int _odp_dpdk_packet_parse_common(packet_parser_t *prs,
				  const uint8_t *ptr,
				  uint32_t pkt_len,
				  uint32_t seg_len,
				  struct rte_mbuf *mbuf,
				  int layer,
				  uint32_t supported_ptypes,
				  odp_pktin_config_opt_t pktin_cfg);

static inline int _odp_dpdk_packet_parse_layer(odp_packet_hdr_t *pkt_hdr,
					       struct rte_mbuf *mbuf,
					       odp_pktio_parser_layer_t layer,
					       uint32_t supported_ptypes,
					       odp_pktin_config_opt_t pktin_cfg)
{
	odp_packet_t pkt = packet_handle(pkt_hdr);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint32_t len = odp_packet_len(pkt);
	uint8_t *base = odp_packet_data(pkt);

	return _odp_dpdk_packet_parse_common(&pkt_hdr->p, base, len, seg_len,
					     mbuf, layer, supported_ptypes,
					     pktin_cfg);
}

#endif
