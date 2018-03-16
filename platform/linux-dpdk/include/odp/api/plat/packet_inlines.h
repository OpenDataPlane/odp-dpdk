/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet inline functions
 */

#ifndef _ODP_PLAT_PACKET_INLINES_H_
#define _ODP_PLAT_PACKET_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/abi/packet.h>
#include <odp/api/pool.h>
#include <odp/api/abi/packet_io.h>
#include <odp/api/hints.h>
#include <odp/api/time.h>
#include <odp/api/abi/buffer.h>

#include <odp/api/plat/packet_inline_types.h>
#include <odp/api/plat/pool_inline_types.h>
#include <odp/api/plat/pktio_inlines.h>

#include <string.h>
/* Required by rte_mbuf.h */
#include <sys/types.h>
#include <rte_mbuf.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_packet_inline_offset_t _odp_packet_inline;

extern const _odp_pool_inline_offset_t _odp_pool_inline;

static inline void *_odp_packet_offset(odp_packet_t pkt, uint32_t offset,
				       uint32_t *len, odp_packet_seg_t *seg)
{
	struct rte_mbuf *mb = &_odp_pkt_get(pkt, struct rte_mbuf, mb);

	if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
		goto err;

	do {
		if (mb->data_len > offset)
			break;
		offset -= mb->data_len;
		mb = mb->next;
	} while (mb);

	if (mb) {
		if (len)
			*len = mb->data_len - offset;
		if (seg)
			*seg = (odp_packet_seg_t)(uintptr_t)mb;
		return (void *)(rte_pktmbuf_mtod(mb, char *) + offset);
	}
err:
	if (len)
		*len = 0;
	if (seg)
		*seg = NULL;
	return NULL;
}

static inline void *_odp_packet_data(odp_packet_t pkt)
{
	uint8_t *buf_addr = (uint8_t *)_odp_pkt_get(pkt, void *, buf_addr);
	uint16_t data_off = _odp_pkt_get(pkt, uint16_t, data);

	return (void *)(buf_addr + data_off);
}

static inline uint32_t _odp_packet_seg_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, seg_len);
}

static inline uint32_t _odp_packet_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, pkt_len);
}

static inline uint32_t _odp_packet_headroom(odp_packet_t pkt)
{
	return rte_pktmbuf_headroom(&_odp_pkt_get(pkt, struct rte_mbuf, mb));
}

static inline uint32_t _odp_packet_tailroom(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &_odp_pkt_get(pkt, struct rte_mbuf, mb);

	return rte_pktmbuf_tailroom(rte_pktmbuf_lastseg(mb));
}

static inline odp_pool_t _odp_packet_pool(odp_packet_t pkt)
{
	void *pool = _odp_pkt_get(pkt, void *, pool);

	return _odp_pool_get(pool, odp_pool_t, pool_hdl);
}

static inline odp_pktio_t _odp_packet_input(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pktio_t, input);
}

static inline int _odp_packet_input_index(odp_packet_t pkt)
{
	odp_pktio_t pktio = _odp_packet_input(pkt);

	return _odp_pktio_index(pktio);
}

static inline int _odp_packet_num_segs(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, nb_segs);
}

static inline void *_odp_packet_user_ptr(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_ptr);
}

static inline void *_odp_packet_user_area(odp_packet_t pkt)
{
	return (void *)((char *)pkt + _odp_packet_inline.udata);
}

static inline uint32_t _odp_packet_user_area_size(odp_packet_t pkt)
{
	void *pool = _odp_pkt_get(pkt, void *, pool);

	return _odp_pool_get(pool, uint32_t, uarea_size);
}

static inline uint32_t _odp_packet_l2_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l2_offset);
}

static inline uint32_t _odp_packet_l3_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l3_offset);
}

static inline uint32_t _odp_packet_l4_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l4_offset);
}

static inline void *_odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	return _odp_packet_offset(pkt, _odp_pkt_get(pkt, uint16_t, l2_offset),
				  len, NULL);
}

static inline void *_odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	return _odp_packet_offset(pkt, _odp_pkt_get(pkt, uint16_t, l3_offset),
				  len, NULL);
}

static inline void *_odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	return _odp_packet_offset(pkt, _odp_pkt_get(pkt, uint16_t, l4_offset),
				  len, NULL);
}

static inline uint32_t _odp_packet_flow_hash(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, rss);
}

static inline void _odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	uint32_t *rss = &_odp_pkt_get(pkt, uint32_t, rss);
	uint64_t *ol_flags = &_odp_pkt_get(pkt, uint64_t, ol_flags);

	*rss = flow_hash;
	*ol_flags |= _odp_packet_inline.rss_flag;
}

static inline odp_time_t _odp_packet_ts(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_time_t, timestamp);
}

static inline void *_odp_packet_head(odp_packet_t pkt)
{
	return (uint8_t *)_odp_packet_data(pkt) - _odp_packet_headroom(pkt);
}

static inline int _odp_packet_is_segmented(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &_odp_pkt_get(pkt, struct rte_mbuf, mb);

	return !rte_pktmbuf_is_contiguous(mb);
}

static inline odp_packet_seg_t _odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)(uintptr_t)pkt;
}

static inline odp_packet_seg_t _odp_packet_last_seg(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &_odp_pkt_get(pkt, struct rte_mbuf, mb);

	return (odp_packet_seg_t)(uintptr_t)rte_pktmbuf_lastseg(mb);
}

static inline odp_packet_seg_t _odp_packet_next_seg(odp_packet_t pkt,
						    odp_packet_seg_t seg)
{
	struct rte_mbuf *mb = (struct rte_mbuf *)(uintptr_t)seg;
	(void)pkt;

	if (mb->next == NULL)
		return ODP_PACKET_SEG_INVALID;
	else
		return (odp_packet_seg_t)(uintptr_t)mb->next;
}

static inline void _odp_packet_prefetch(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	const char *addr = (char *)_odp_packet_data(pkt) + offset;
	size_t ofs;

	for (ofs = 0; ofs < len; ofs += RTE_CACHE_LINE_SIZE)
		rte_prefetch0(addr + ofs);
}

static inline int _odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
					  uint32_t len, void *dst)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	uint8_t *dstaddr = (uint8_t *)dst;

	if (offset + len > _odp_packet_len(pkt))
		return -1;

	while (len > 0) {
		mapaddr = _odp_packet_offset(pkt, offset, &seglen, NULL);
		cpylen = len > seglen ? seglen : len;
		memcpy(dstaddr, mapaddr, cpylen);
		offset  += cpylen;
		dstaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

static inline int _odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
					    uint32_t len, const void *src)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	const uint8_t *srcaddr = (const uint8_t *)src;

	if (offset + len > _odp_packet_len(pkt))
		return -1;

	while (len > 0) {
		mapaddr = _odp_packet_offset(pkt, offset, &seglen, NULL);
		cpylen = len > seglen ? seglen : len;
		memcpy(mapaddr, srcaddr, cpylen);
		offset  += cpylen;
		srcaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

static inline odp_packet_t _odp_packet_from_event(odp_event_t ev)
{
	if (odp_unlikely(ev == ODP_EVENT_INVALID))
		return ODP_PACKET_INVALID;

	return (odp_packet_t)ev;
}

static inline odp_event_t _odp_packet_to_event(odp_packet_t pkt)
{
	if (odp_unlikely(pkt == ODP_PACKET_INVALID))
		return ODP_EVENT_INVALID;

	return (odp_event_t)pkt;
}

static inline void _odp_packet_from_event_multi(odp_packet_t pkt[],
						const odp_event_t ev[],
						int num)
{
	int i;

	for (i = 0; i < num; i++)
		pkt[i] = _odp_packet_from_event(ev[i]);
}

static inline void _odp_packet_to_event_multi(const odp_packet_t pkt[],
					      odp_event_t ev[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		ev[i] = _odp_packet_to_event(pkt[i]);
}

#ifdef __cplusplus
}
#endif

/** @endcond */

#endif /* ODP_PLAT_PACKET_INLINES_H_ */
