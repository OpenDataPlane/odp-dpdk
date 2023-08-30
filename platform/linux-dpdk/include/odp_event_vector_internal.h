/* Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP event vector descriptor - implementation internal
 */

#ifndef ODP_EVENT_VECTOR_INTERNAL_H_
#define ODP_EVENT_VECTOR_INTERNAL_H_

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp/api/packet.h>

#include <odp/api/plat/event_vector_inline_types.h>

#include <odp_event_internal.h>

#include <rte_config.h>

#include <stdint.h>

/**
 * Internal event vector header
 */
typedef struct ODP_ALIGNED_CACHE odp_event_vector_hdr_t {
	/* Underlying DPDK rte_mbuf */
	struct rte_mbuf mb;

	/* Common internal header */
	_odp_event_hdr_int_t event_hdr;

	/* User area pointer */
	void *uarea_addr;

	/* Event vector size */
	uint32_t size;

	/* Flags */
	_odp_event_vector_flags_t flags;

	/* Vector of packet handles */
	odp_packet_t packet[];

} odp_event_vector_hdr_t;

ODP_STATIC_ASSERT(sizeof(odp_event_vector_hdr_t) <= 3 * RTE_CACHE_LINE_SIZE,
		  "Additional cache line required for odp_event_vector_hdr_t");

/**
 * Return the vector header
 */
static inline odp_event_vector_hdr_t *_odp_packet_vector_hdr(odp_packet_vector_t pktv)
{
	return (odp_event_vector_hdr_t *)(uintptr_t)pktv;
}

/**
 * Return the event header
 */
static inline _odp_event_hdr_t *_odp_packet_vector_to_event_hdr(odp_packet_vector_t pktv)
{
	return (_odp_event_hdr_t *)(uintptr_t)_odp_packet_vector_hdr(pktv);
}

/**
 * Free packet vector and contained packets
 */
static inline void _odp_packet_vector_free_full(odp_packet_vector_t pktv)
{
	odp_event_vector_hdr_t *pktv_hdr = _odp_packet_vector_hdr(pktv);

	if (pktv_hdr->size)
		odp_packet_free_multi(pktv_hdr->packet, pktv_hdr->size);

	odp_packet_vector_free(pktv);
}

#endif /* ODP_EVENT_VECTOR_INTERNAL_H_ */
