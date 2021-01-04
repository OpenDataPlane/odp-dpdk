/* Copyright (c) 2013-2018, Linaro Limited
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

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/byteorder.h>
#include <odp/api/thread.h>
#include <sys/types.h>
#include <odp/api/event.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_schedule_if.h>
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

ODP_STATIC_ASSERT(CONFIG_PACKET_SEG_LEN_MIN >= 256,
		  "ODP Segment size must be a minimum of 256 bytes");

ODP_STATIC_ASSERT(CONFIG_PACKET_MAX_SEGS < 256,
		  "Maximum of 255 segments supported");

/* Type size limits number of flow IDs supported */
#define BUF_HDR_MAX_FLOW_ID 255

struct odp_buffer_hdr_t {
	/* Underlying DPDK rte_mbuf */
	struct rte_mbuf mb;

	/* Buffer index in the pool */
	uint32_t  index;

	/* Total size of all allocated segs */
	uint32_t  totsize;

	/* Pool type */
	int8_t    type;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* Event flow id */
	uint8_t   flow_id;

	/* --- Mostly read only data --- */

	/* User pointer */
	const void *user_ptr;

	/* Pool pointer */
	void *pool_ptr;
};

/*
 * Buffer type
 *
 * @param buf      Buffer handle
 *
 * @return Buffer type
 */
int _odp_buffer_type(odp_buffer_t buf);

/*
 * Buffer type set
 *
 * @param buf      Buffer handle
 * @param type     New type value
 *
 */
void _odp_buffer_type_set(odp_buffer_t buf, int type);

static inline struct rte_mbuf *buf_to_mbuf(odp_buffer_t buf)
{
	return (struct rte_mbuf *)(uintptr_t)buf;
}

static inline odp_buffer_hdr_t *mbuf_to_buf_hdr(struct rte_mbuf *mbuf)
{
	return (odp_buffer_hdr_t *)(uintptr_t)mbuf;
}

static inline odp_buffer_t buf_from_buf_hdr(odp_buffer_hdr_t *hdr)
{
	return (odp_buffer_t)hdr;
}

static inline odp_buffer_hdr_t *buf_hdl_to_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)(uintptr_t)buf;
}

static inline odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf)
{
	return buf_hdl_to_hdr(buf)->event_type;
}

static inline void _odp_buffer_event_type_set(odp_buffer_t buf, int ev)
{
	buf_hdl_to_hdr(buf)->event_type = ev;
}

static inline uint32_t event_flow_id(odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr = (odp_buffer_hdr_t *)(uintptr_t)ev;

	return buf_hdr->flow_id;
}

static inline void event_flow_id_set(odp_event_t ev, uint32_t flow_id)
{
	odp_buffer_hdr_t *buf_hdr = (odp_buffer_hdr_t *)(uintptr_t)ev;

	buf_hdr->flow_id = flow_id;
}

#ifdef __cplusplus
}
#endif

#endif
