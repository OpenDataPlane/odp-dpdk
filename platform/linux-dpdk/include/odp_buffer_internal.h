/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP buffer descriptor - implementation internal
 */

#ifndef ODP_BUFFER_INTERNAL_H_
#define ODP_BUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp/api/byteorder.h>
#include <odp/api/debug.h>
#include <odp/api/event.h>
#include <odp/api/pool.h>
#include <odp/api/std_types.h>
#include <odp/api/thread.h>

#include <odp_config_internal.h>
#include <odp_event_internal.h>

#include <sys/types.h>
#include <stddef.h>

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

/* Type size limits number of flow IDs supported */
#define BUF_HDR_MAX_FLOW_ID 255

/* Internal buffer header */
typedef struct ODP_ALIGNED_CACHE odp_buffer_hdr_t {
	/* Underlying DPDK rte_mbuf */
	struct rte_mbuf mb;

	/* Common internal header */
	_odp_event_hdr_int_t event_hdr;

	/* User area pointer */
	void *uarea_addr;

} odp_buffer_hdr_t;

ODP_STATIC_ASSERT(sizeof(odp_buffer_hdr_t) <= 3 * RTE_CACHE_LINE_SIZE,
		  "Additional cache line required for odp_buffer_hdr_t");

static inline struct rte_mbuf *_odp_buf_to_mbuf(odp_buffer_t buf)
{
	return (struct rte_mbuf *)(uintptr_t)buf;
}

static inline odp_buffer_hdr_t *_odp_buf_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)(uintptr_t)buf;
}

#ifdef __cplusplus
}
#endif

#endif
