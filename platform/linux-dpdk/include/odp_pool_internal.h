/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP buffer pool - internal header
 */

#ifndef ODP_POOL_INTERNAL_H_
#define ODP_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/pool.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/std_types.h>
#include <odp/api/ticketlock.h>

#include <odp/api/plat/strong_types.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_event_internal.h>

#include <string.h>

/* for DPDK */
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
/* ppc64 rte_memcpy.h may overwrite bool with an incompatible type and define
 * vector */
#if defined(__PPC64__) && defined(bool)
	#undef bool
	#define bool _Bool
#endif
#if defined(__PPC64__) && defined(vector)
	#undef vector
#endif

/* Use ticketlock instead of spinlock */
#define POOL_USE_TICKETLOCK

/* Extra error checks */
/* #define POOL_ERROR_CHECK */

#ifdef POOL_USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#else
#include <odp/api/spinlock.h>
#endif

typedef struct ODP_ALIGNED_CACHE {
#ifdef POOL_USE_TICKETLOCK
	odp_ticketlock_t lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t lock ODP_ALIGNED_CACHE;
#endif
	uint32_t		pool_idx;

	/* Everything under this mark is memset() to zero on pool create */
	uint8_t			memset_mark;
	struct rte_mempool	*rte_mempool;
	uint32_t		seg_len; /* Initial packet segment length (excludes endmark) */
	uint32_t		ext_head_offset;
	uint32_t		num;
	uint32_t		num_populated;
	odp_pool_type_t		type_2;
	uint8_t			type;
	uint8_t			pool_ext;
	odp_pool_param_t	params;
	odp_pool_ext_param_t	ext_param;
	odp_shm_t		uarea_shm;
	uint64_t		uarea_shm_size;
	uint32_t		param_uarea_size;
	uint32_t		uarea_size;
	uint32_t		trailer_size; /* Endmark size */
	uint8_t			*uarea_base_addr;
	char			name[ODP_POOL_NAME_LEN];

} pool_t;

typedef struct pool_global_t {
	pool_t		pool[CONFIG_POOLS];
	odp_shm_t	shm;

	struct {
		uint32_t pkt_max_num;
	} config;

} pool_global_t;

extern pool_global_t *_odp_pool_glb;

static inline pool_t *_odp_pool_entry_from_idx(uint32_t pool_idx)
{
	return &_odp_pool_glb->pool[pool_idx];
}

static inline pool_t *_odp_pool_entry(odp_pool_t pool_hdl)
{
	return (pool_t *)(uintptr_t)pool_hdl;
}

static inline odp_pool_t _odp_pool_handle(pool_t *pool)
{
	return (odp_pool_t)(uintptr_t)pool;
}

static inline int _odp_event_alloc_multi(pool_t *pool, _odp_event_hdr_t *event_hdr[], int num)
{
	int i;
	struct rte_mempool *mp = pool->rte_mempool;

	if (odp_likely(rte_mempool_get_bulk(mp, (void **)event_hdr, num) == 0))
		return num;

	for (i = 0; i < num; i++) {
		struct rte_mbuf *mbuf;

		if (odp_unlikely(rte_mempool_get(mp, (void **)&mbuf) != 0))
			return i;

		event_hdr[i] = _odp_event_hdr(_odp_event_from_mbuf(mbuf));
	}

	return i;
}

static inline odp_event_t _odp_event_alloc(pool_t *pool)
{
	struct rte_mbuf *mbuf;
	struct rte_mempool *mp = pool->rte_mempool;

	if (odp_unlikely(rte_mempool_get(mp, (void **)&mbuf) != 0))
		return ODP_EVENT_INVALID;

	return _odp_event_from_mbuf(mbuf);
}

static inline void _odp_event_free_multi(_odp_event_hdr_t *event_hdr[], int num_free)
{
	struct rte_mbuf *mbuf_tbl[num_free];
	struct rte_mempool *mp_pending;
	unsigned int num_pending;

	mbuf_tbl[0] = &event_hdr[0]->mb;
	mp_pending = mbuf_tbl[0]->pool;
	num_pending = 1;

	for (int i = 1; i < num_free; i++) {
		struct rte_mbuf *mbuf = &event_hdr[i]->mb;

		if (mbuf->pool != mp_pending) {
			rte_mempool_put_bulk(mp_pending, (void **)mbuf_tbl, num_pending);
			mbuf_tbl[0] = mbuf;
			num_pending = 1;
			mp_pending = mbuf->pool;
		} else {
			mbuf_tbl[num_pending++] = mbuf;
		}
	}
	rte_mempool_put_bulk(mp_pending, (void **)mbuf_tbl, num_pending);
}

static inline void _odp_event_free(odp_event_t event)
{
	struct rte_mbuf *mbuf = _odp_event_to_mbuf(event);

	rte_mempool_put(mbuf->pool, mbuf);
}

int _odp_event_is_valid(odp_event_t event);

odp_pool_t _odp_pool_create(const char *name, const odp_pool_param_t *params,
			    odp_pool_type_t type_2);

#ifdef __cplusplus
}
#endif

#endif /* ODP_POOL_INTERNAL_H_ */
