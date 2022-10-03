/* Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_BUFFER_INLINES_H_
#define ODP_PLAT_BUFFER_INLINES_H_

#include <odp/api/event_types.h>
#include <odp/api/hints.h>
#include <odp/api/pool_types.h>

#include <odp/api/abi/buffer.h>

#include <odp/api/plat/event_inline_types.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#if defined(__PPC64__) && defined(bool)
	#undef bool
	#define bool _Bool
#endif
#if defined(__PPC64__) && defined(vector)
	#undef vector
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_event_inline_offset_t _odp_event_inline_offset;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_buffer_from_event __odp_buffer_from_event
	#define odp_buffer_to_event __odp_buffer_to_event
	#define odp_buffer_addr __odp_buffer_addr
	#define odp_buffer_size __odp_buffer_size
	#define odp_buffer_pool __odp_buffer_pool
	#define odp_buffer_free __odp_buffer_free
	#define odp_buffer_free_multi __odp_buffer_free_multi
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	return (odp_buffer_t)ev;
}

_ODP_INLINE odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

_ODP_INLINE void *odp_buffer_addr(odp_buffer_t buf)
{
	return _odp_event_hdr_field(buf, void *, base_data);
}

_ODP_INLINE uint32_t odp_buffer_size(odp_buffer_t buf)
{
	return _odp_event_hdr_field(buf, uint16_t, buf_len);
}

_ODP_INLINE odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	return (odp_pool_t)(uintptr_t)_odp_event_hdr_field(buf, void *, pool);
}

_ODP_INLINE void odp_buffer_free(odp_buffer_t buf)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)buf;

	rte_mempool_put(mbuf->pool, mbuf);
}

_ODP_INLINE void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	struct rte_mbuf *mbuf_tbl[num];
	struct rte_mempool *mp_pending;
	unsigned int num_pending;

	if (odp_unlikely(num <= 0))
		return;

	mbuf_tbl[0] = (struct rte_mbuf *)buf[0];
	mp_pending = mbuf_tbl[0]->pool;
	num_pending = 1;

	for (int i = 1; i < num; i++) {
		struct rte_mbuf *mbuf = (struct rte_mbuf *)buf[i];

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

/** @endcond */

#endif
