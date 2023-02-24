/* Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP event descriptor - implementation internal
 */

#ifndef ODP_EVENT_INTERNAL_H_
#define ODP_EVENT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/event.h>
#include <odp/api/pool_types.h>

#include <stdint.h>

/* DPDK */
#include <rte_config.h>
#if defined(__clang__)
#undef RTE_TOOLCHAIN_GCC
#endif
#include <rte_mbuf.h>
/* ppc64 rte_memcpy.h (included through rte_mbuf.h) may define vector */
#if defined(__PPC64__) && defined(vector)
	#undef vector
#endif

/* Common header for all event types. */
typedef struct _odp_event_hdr_t {
	/* Underlying DPDK rte_mbuf */
	struct rte_mbuf mb;

	/* Pool handle */
	odp_pool_t pool;

	/* Buffer index in the pool */
	uint32_t  index;

	/* Pool type */
	int8_t    type;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* Event flow id */
	uint8_t   flow_id;

} _odp_event_hdr_t;

static inline odp_event_t _odp_event_from_hdr(_odp_event_hdr_t *hdr)
{
	return (odp_event_t)hdr;
}

static inline _odp_event_hdr_t *_odp_event_hdr(odp_event_t event)
{
	return (_odp_event_hdr_t *)(uintptr_t)event;
}

static inline odp_event_t _odp_event_from_mbuf(struct rte_mbuf *mbuf)
{
	return (odp_event_t)(uintptr_t)mbuf;
}

static inline struct rte_mbuf *_odp_event_to_mbuf(odp_event_t event)
{
	return (struct rte_mbuf *)(uintptr_t)event;
}

static inline void _odp_event_type_set(odp_event_t event, int ev)
{
	_odp_event_hdr(event)->event_type = ev;
}

static inline uint64_t *_odp_event_endmark_get_ptr(odp_event_t event)
{
	struct rte_mbuf *mbuf = _odp_event_to_mbuf(event);

	return (uint64_t *)((uint8_t *)mbuf->buf_addr + mbuf->buf_len);
}

#ifdef __cplusplus
}
#endif

#endif
