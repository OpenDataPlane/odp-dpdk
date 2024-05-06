/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Nokia
 */

#ifndef ODP_PLAT_BUFFER_INLINES_H_
#define ODP_PLAT_BUFFER_INLINES_H_

#include <odp/api/buffer_types.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/pool_types.h>

#include <odp/api/plat/buffer_inline_types.h>
#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/event_inline_types.h>
#include <odp/api/plat/event_validation_external.h>

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

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_buffer_from_event __odp_buffer_from_event
	#define odp_buffer_from_event_multi __odp_buffer_from_event_multi
	#define odp_buffer_to_event __odp_buffer_to_event
	#define odp_buffer_to_event_multi __odp_buffer_to_event_multi
	#define odp_buffer_addr __odp_buffer_addr
	#define odp_buffer_size __odp_buffer_size
	#define odp_buffer_pool __odp_buffer_pool
	#define odp_buffer_user_area __odp_buffer_user_area
	#define odp_buffer_free __odp_buffer_free
	#define odp_buffer_free_multi __odp_buffer_free_multi
	#define odp_buffer_is_valid __odp_buffer_is_valid
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_BUFFER);

	return (odp_buffer_t)ev;
}

_ODP_INLINE void odp_buffer_from_event_multi(odp_buffer_t buf[], const odp_event_t ev[], int num)
{
	for (int i = 0; i < num; i++)
		buf[i] = odp_buffer_from_event(ev[i]);
}

_ODP_INLINE odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

_ODP_INLINE void odp_buffer_to_event_multi(const odp_buffer_t buf[], odp_event_t ev[], int num)
{
	for (int i = 0; i < num; i++)
		ev[i] = odp_buffer_to_event(buf[i]);
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

_ODP_INLINE void *odp_buffer_user_area(odp_buffer_t buf)
{
	return _odp_buffer_get(buf, void *, uarea_addr);
}

_ODP_INLINE void odp_buffer_free(odp_buffer_t buf)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)buf;

	_odp_buffer_validate(buf, _ODP_EV_BUFFER_FREE);

	rte_mempool_put(mbuf->pool, mbuf);
}

_ODP_INLINE void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	struct rte_mbuf *mbuf_tbl[num];
	struct rte_mempool *mp_pending;
	unsigned int num_pending;

	if (odp_unlikely(num <= 0))
		return;

	_odp_buffer_validate_multi(buf, num, _ODP_EV_BUFFER_FREE_MULTI);

	mbuf_tbl[0] = (struct rte_mbuf *)buf[0];
	mp_pending = mbuf_tbl[0]->pool;
	num_pending = 1;

/*
 * num_pending is less than or equal to num, but GCC 13 is not able figure that out, so we have to
 * ignore array-bounds warnings in the rte_mempool_put_bulk() calls.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
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
#pragma GCC diagnostic pop
}

_ODP_INLINE int odp_buffer_is_valid(odp_buffer_t buf)
{
	if (odp_event_is_valid(odp_buffer_to_event(buf)) == 0)
		return 0;

	if (odp_event_type(odp_buffer_to_event(buf)) != ODP_EVENT_BUFFER)
		return 0;

	if (odp_unlikely(_odp_buffer_validate(buf, _ODP_EV_BUFFER_IS_VALID)))
		return 0;

	return 1;
}

/** @endcond */

#endif
