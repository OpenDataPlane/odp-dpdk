/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp/api/byteorder.h>
#include <odp/api/hash.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/packet_flags.h>
#include <odp/api/packet_io.h>
#include <odp/api/proto_stats.h>
#include <odp/api/timer.h>

#include <odp/api/plat/byteorder_inlines.h>
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_io_inlines.h>

#include <odp_chksum_internal.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp_event_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_parse_internal.h>

#include <rte_version.h>

#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/sctp.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
	#define RTE_MBUF_F_RX_RSS_HASH PKT_RX_RSS_HASH
#endif

#include <odp/visibility_begin.h>

/* Fill in packet header field offsets for inline functions */

const _odp_packet_inline_offset_t _odp_packet_inline ODP_ALIGNED_CACHE = {
	.mb               = offsetof(odp_packet_hdr_t, event_hdr.mb),
	.pool             = offsetof(odp_packet_hdr_t, event_hdr.pool_ptr),
	.input            = offsetof(odp_packet_hdr_t, input),
	.user_ptr         = offsetof(odp_packet_hdr_t, user_ptr),
	.l2_offset        = offsetof(odp_packet_hdr_t, p.l2_offset),
	.l3_offset        = offsetof(odp_packet_hdr_t, p.l3_offset),
	.l4_offset        = offsetof(odp_packet_hdr_t, p.l4_offset),
	.timestamp        = offsetof(odp_packet_hdr_t, timestamp),
	.input_flags      = offsetof(odp_packet_hdr_t, p.input_flags),
	.flags            = offsetof(odp_packet_hdr_t, p.flags),
	.subtype          = offsetof(odp_packet_hdr_t, subtype),
	.buf_addr         = offsetof(odp_packet_hdr_t, event_hdr.mb.buf_addr),
	.data             = offsetof(odp_packet_hdr_t, event_hdr.mb.data_off),
	.pkt_len          = offsetof(odp_packet_hdr_t, event_hdr.mb.pkt_len),
	.seg_len          = offsetof(odp_packet_hdr_t, event_hdr.mb.data_len),
	.nb_segs          = offsetof(odp_packet_hdr_t, event_hdr.mb.nb_segs),
	.user_area        = offsetof(odp_packet_hdr_t, uarea_addr),
	.rss              = offsetof(odp_packet_hdr_t, event_hdr.mb.hash.rss),
	.ol_flags         = offsetof(odp_packet_hdr_t, event_hdr.mb.ol_flags),
	.rss_flag         = RTE_MBUF_F_RX_RSS_HASH
};

#include <odp/visibility_end.h>

/* Catch if DPDK mbuf members sizes have changed */
struct rte_mbuf _odp_dummy_mbuf;
ODP_STATIC_ASSERT(sizeof(_odp_dummy_mbuf.data_off) == sizeof(uint16_t),
		  "data_off should be uint16_t");
ODP_STATIC_ASSERT(sizeof(_odp_dummy_mbuf.pkt_len) == sizeof(uint32_t),
		  "pkt_len should be uint32_t");
ODP_STATIC_ASSERT(sizeof(_odp_dummy_mbuf.data_len) == sizeof(uint16_t),
		  "data_len should be uint16_t");
ODP_STATIC_ASSERT(sizeof(_odp_dummy_mbuf.nb_segs) == sizeof(uint16_t),
		  "nb_segs should be uint16_t");
ODP_STATIC_ASSERT(sizeof(_odp_dummy_mbuf.hash.rss) == sizeof(uint32_t),
		  "hash.rss should be uint32_t");
ODP_STATIC_ASSERT(sizeof(_odp_dummy_mbuf.ol_flags) == sizeof(uint64_t),
		  "ol_flags should be uint64_t");

/* Check that invalid values are the same. Some versions of Clang  and pedantic
 * build have trouble with the strong type casting, and complain that these
 * invalid values are not integral constants.
 *
 * Invalid values are required to be equal for _odp_buffer_is_valid() to work
 * properly. */
#ifndef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
ODP_STATIC_ASSERT(ODP_PACKET_INVALID == 0, "Packet invalid not 0");
ODP_STATIC_ASSERT(ODP_BUFFER_INVALID == 0, "Buffer invalid not 0");
ODP_STATIC_ASSERT(ODP_EVENT_INVALID  == 0, "Event invalid not 0");
ODP_STATIC_ASSERT(ODP_PACKET_VECTOR_INVALID == 0, "Packet vector invalid not 0");
ODP_STATIC_ASSERT(ODP_PACKET_TX_COMPL_INVALID == 0, "Packet TX completion invalid not 0");
ODP_STATIC_ASSERT(ODP_TIMEOUT_INVALID == 0, "Timeout invalid not 0");
#pragma GCC diagnostic pop
#endif

/* Calculate the number of segments */
static inline int num_segments(uint32_t len, uint32_t seg_len)
{
	int num = 1;

	if (odp_unlikely(len > seg_len)) {
		num = len / seg_len;

		if (odp_likely((num * seg_len) != len))
			num += 1;
	}

	return num;
}

static odp_packet_t packet_alloc(pool_t *pool, uint32_t len)
{
	odp_packet_t pkt;
	uintmax_t totsize = RTE_PKTMBUF_HEADROOM + len;
	odp_packet_hdr_t *pkt_hdr;
	uint16_t seg_len = pool->seg_len;
	int num_seg;

	num_seg = num_segments(totsize, seg_len);

	if (odp_likely(num_seg == 1)) {
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pool->rte_mempool);

		if (odp_unlikely(mbuf == NULL)) {
			_odp_errno = ENOMEM;
			return ODP_PACKET_INVALID;
		}
		pkt_hdr = (odp_packet_hdr_t *)mbuf;
		odp_prefetch((uint8_t *)mbuf + sizeof(struct rte_mbuf));
		odp_prefetch((uint8_t *)mbuf + sizeof(struct rte_mbuf) +
			     ODP_CACHE_LINE_SIZE);
	} else {
		struct rte_mbuf *mbufs[num_seg];
		struct rte_mbuf *head;
		int ret;
		int i;

		/* Check num_seg here so rte_pktmbuf_chain() always succeeds */
		if (odp_unlikely(num_seg > RTE_MBUF_MAX_NB_SEGS)) {
			_odp_errno = EOVERFLOW;
			return ODP_PACKET_INVALID;
		}

		ret = rte_pktmbuf_alloc_bulk(pool->rte_mempool, mbufs, num_seg);
		if (odp_unlikely(ret)) {
			/*
			 * rte_pktmbuf_alloc_bulk() fails when allocating the
			 * last buffers from the pool, if some of them, but not
			 * all, are in the cache.
			 *
			 * Try to allocate the buffers one by one.
			 */
			for (i = 0; i < num_seg; i++) {
				mbufs[i] = rte_pktmbuf_alloc(pool->rte_mempool);
				if (!mbufs[i]) {
					/*
					 * Failed to allocate the number of
					 * buffers that we wanted. Free the ones
					 * we managed to allocate, if any, and
					 * return error.
					 */
					while (i > 0)
						rte_pktmbuf_free(mbufs[--i]);

					_odp_errno = ENOMEM;
					return ODP_PACKET_INVALID;
				}
			}
		}

		head = mbufs[0];
		pkt_hdr = (odp_packet_hdr_t *)head;
		odp_prefetch((uint8_t *)head + sizeof(struct rte_mbuf));
		odp_prefetch((uint8_t *)head + sizeof(struct rte_mbuf) +
			     ODP_CACHE_LINE_SIZE);

		for (i = 1; i < num_seg; i++) {
			struct rte_mbuf *nextseg = mbufs[i];

			nextseg->data_off = 0;

			rte_pktmbuf_chain(head, nextseg);
		}
	}

	pkt_hdr->event_hdr.totsize = seg_len * num_seg;

	pkt = packet_handle(pkt_hdr);
	odp_packet_reset(pkt, len);

	return pkt;
}

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	if (odp_unlikely(pool->type != ODP_POOL_PACKET)) {
		_odp_errno = EINVAL;
		return ODP_PACKET_INVALID;
	}

	if (odp_unlikely(len == 0))
		return ODP_PACKET_INVALID;

	return packet_alloc(pool, len);
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			   odp_packet_t pkt[], int num)
{
	int i;
	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	if (odp_unlikely(pool->type != ODP_POOL_PACKET)) {
		_odp_errno = EINVAL;
		return -1;
	}

	if (odp_unlikely(len == 0))
		return -1;

	for (i = 0; i < num; i++) {
		pkt[i] = packet_alloc(pool, len);
		if (odp_unlikely(pkt[i] == ODP_PACKET_INVALID))
			return (i == 0 && _odp_errno != ENOMEM) ? -1 : i;
	}
	return i;
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = packet_hdr(pkt);
	struct rte_mbuf *ms, *mb = &pkt_hdr->event_hdr.mb;
	uint8_t nb_segs = 0;
	int32_t lenleft = len;

	if (odp_unlikely(len == 0))
		return -1;

	if (RTE_PKTMBUF_HEADROOM + len > odp_packet_buf_len(pkt)) {
		ODP_DBG("Not enought head room for that packet %d/%d\n",
			RTE_PKTMBUF_HEADROOM + len,
			odp_packet_buf_len(pkt));
		return -1;
	}

	pkt_hdr->p.input_flags.all  = 0;
	pkt_hdr->p.flags.all_flags  = 0;

	pkt_hdr->p.l2_offset = 0;
	pkt_hdr->p.l3_offset = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->p.l4_offset = ODP_PACKET_OFFSET_INVALID;

	pkt_hdr->input = ODP_PKTIO_INVALID;
	pkt_hdr->subtype = ODP_EVENT_PACKET_BASIC;

	mb->port = 0xff;
	mb->pkt_len = len;
	mb->data_off = RTE_PKTMBUF_HEADROOM;
	mb->vlan_tci = 0;
	nb_segs = 1;

	if (RTE_PKTMBUF_HEADROOM + lenleft <= mb->buf_len) {
		mb->data_len = lenleft;
	} else {
		mb->data_len = mb->buf_len - RTE_PKTMBUF_HEADROOM;
		lenleft -= mb->data_len;
		ms = mb->next;
		while (lenleft > 0) {
			nb_segs++;
			ms->data_len = lenleft <= ms->buf_len ?
				lenleft : ms->buf_len;
			lenleft -= ms->buf_len;
			ms = ms->next;
		}
	}

	mb->nb_segs = nb_segs;
	return 0;
}

int odp_event_filter_packet(const odp_event_t event[],
			    odp_packet_t packet[],
			    odp_event_t remain[], int num)
{
	int i;
	int num_pkt = 0;
	int num_rem = 0;

	for (i = 0; i < num; i++) {
		if (odp_event_type(event[i]) == ODP_EVENT_PACKET) {
			packet[num_pkt] = odp_packet_from_event(event[i]);
			num_pkt++;
		} else {
			remain[num_rem] = event[i];
			num_rem++;
		}
	}

	return num_pkt;
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	return packet_hdr(pkt)->event_hdr.totsize;
}

void *odp_packet_tail(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(packet_hdr(pkt)->event_hdr.mb);

	mb = rte_pktmbuf_lastseg(mb);
	return (void *)(rte_pktmbuf_mtod(mb, char *) + mb->data_len);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = &(packet_hdr(pkt)->event_hdr.mb);

	return (void *)rte_pktmbuf_prepend(mb, len);
}

static void _copy_head_metadata(struct rte_mbuf *newhead,
				struct rte_mbuf *oldhead)
{
	rte_mbuf_refcnt_set(newhead, rte_mbuf_refcnt_read(oldhead));

	_odp_packet_copy_md((odp_packet_hdr_t *)newhead, (odp_packet_hdr_t *)oldhead, 0);
}

int odp_packet_extend_head(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			   uint32_t *seg_len)
{
	struct rte_mbuf *mb = &(packet_hdr(*pkt)->event_hdr.mb);
	int addheadsize = len - rte_pktmbuf_headroom(mb);

	if (addheadsize > 0) {
		struct rte_mbuf *newhead, *t;
		uint32_t totsize_change;
		int i;

		newhead = rte_pktmbuf_alloc(mb->pool);
		if (newhead == NULL)
			return -1;

		newhead->data_len = addheadsize % newhead->buf_len;
		newhead->pkt_len = addheadsize;
		newhead->data_off = newhead->buf_len - newhead->data_len;
		newhead->nb_segs = addheadsize / newhead->buf_len + 1;
		t = newhead;

		for (i = 0; i < newhead->nb_segs - 1; --i) {
			t->next = rte_pktmbuf_alloc(mb->pool);

			if (t->next == NULL) {
				rte_pktmbuf_free(newhead);
				return -1;
			}
			/* The intermediate segments are fully used */
			t->data_len = t->buf_len;
			t->data_off = 0;
		}
		totsize_change = newhead->nb_segs * newhead->buf_len;
		if (rte_pktmbuf_chain(newhead, mb)) {
			rte_pktmbuf_free(newhead);
			return -1;
		}
		/* Expand the original head segment*/
		newhead->pkt_len += rte_pktmbuf_headroom(mb);
		mb->data_len += rte_pktmbuf_headroom(mb);
		mb->data_off = 0;
		_copy_head_metadata(newhead, mb);
		mb = newhead;
		*pkt = (odp_packet_t)newhead;
		packet_hdr(*pkt)->event_hdr.totsize += totsize_change;
	} else {
		rte_pktmbuf_prepend(mb, len);
	}

	if (data_ptr)
		*data_ptr = odp_packet_data(*pkt);
	if (seg_len)
		*seg_len = mb->data_len;

	return 0;
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = pkt_to_mbuf(pkt);

	if (odp_unlikely(len >= mb->data_len))
		return NULL;

	return (void *)rte_pktmbuf_adj(mb, len);
}

int odp_packet_trunc_head(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			  uint32_t *seg_len)
{
	struct rte_mbuf *mb = pkt_to_mbuf(*pkt);

	if (odp_unlikely(len >= odp_packet_len(*pkt)))
		return -1;

	if (len > mb->data_len) {
		struct rte_mbuf *newhead = mb, *prev = NULL;
		uint32_t left = len;
		uint32_t totsize_change = 0;

		while (newhead->next != NULL) {
			if (newhead->data_len > left)
				break;
			left -= newhead->data_len;
			totsize_change += newhead->buf_len;
			prev = newhead;
			newhead = newhead->next;
			--mb->nb_segs;
		}
		newhead->data_off += left;
		newhead->nb_segs = mb->nb_segs;
		newhead->pkt_len = mb->pkt_len - len;
		newhead->data_len -= left;
		_copy_head_metadata(newhead, mb);
		prev->next = NULL;
		rte_pktmbuf_free(mb);
		mb = newhead;
		*pkt = (odp_packet_t)newhead;
		packet_hdr(*pkt)->event_hdr.totsize -= totsize_change;
	} else {
		rte_pktmbuf_adj(mb, len);
	}

	if (data_ptr)
		*data_ptr = odp_packet_data(*pkt);
	if (seg_len)
		*seg_len = mb->data_len;

	return 0;
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = &(packet_hdr(pkt)->event_hdr.mb);

	return (void *)rte_pktmbuf_append(mb, len);
}

int odp_packet_extend_tail(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			   uint32_t *seg_len)
{
	struct rte_mbuf *mb = &(packet_hdr(*pkt)->event_hdr.mb);
	int newtailsize = len - odp_packet_tailroom(*pkt);
	uint32_t old_pkt_len = odp_packet_len(*pkt);

	if (data_ptr)
		*data_ptr = odp_packet_tail(*pkt);

	if (newtailsize > 0) {
		struct rte_mbuf *newtail = rte_pktmbuf_alloc(mb->pool);
		struct rte_mbuf *t;
		struct rte_mbuf *m_last = rte_pktmbuf_lastseg(mb);
		int i;

		if (newtail == NULL)
			return -1;
		newtail->data_off = 0;
		newtail->pkt_len = newtailsize;
		if (newtailsize > newtail->buf_len)
			newtail->data_len = newtail->buf_len;
		else
			newtail->data_len = newtailsize;
		newtail->nb_segs = newtailsize / newtail->buf_len + 1;
		t = newtail;

		for (i = 0; i < newtail->nb_segs - 1; ++i) {
			t->next = rte_pktmbuf_alloc(mb->pool);

			if (t->next == NULL) {
				rte_pktmbuf_free(newtail);
				return -1;
			}
			t = t->next;
			t->data_off = 0;
			/* The last segment's size is not trivial*/
			t->data_len = i == newtail->nb_segs - 2 ?
				      newtailsize % newtail->buf_len :
				      t->buf_len;
		}
		if (rte_pktmbuf_chain(mb, newtail)) {
			rte_pktmbuf_free(newtail);
			return -1;
		}
		/* Expand the original tail */
		m_last->data_len = m_last->buf_len - m_last->data_off;
		mb->pkt_len += len - newtailsize;
		packet_hdr(*pkt)->event_hdr.totsize +=
				newtail->nb_segs * newtail->buf_len;
	} else {
		rte_pktmbuf_append(mb, len);
	}

	if (seg_len)
		odp_packet_offset(*pkt, old_pkt_len, seg_len, NULL);

	return 0;
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = pkt_to_mbuf(pkt);
	struct rte_mbuf *mb_last = rte_pktmbuf_lastseg(mb);

	if (odp_unlikely(len >= mb_last->data_len))
		return NULL;

	if (rte_pktmbuf_trim(mb, len))
		return NULL;
	else
		return odp_packet_tail(pkt);
}

int odp_packet_trunc_tail(odp_packet_t *pkt, uint32_t len, void **tail_ptr,
			  uint32_t *tailroom)
{
	struct rte_mbuf *mb = pkt_to_mbuf(*pkt);
	struct rte_mbuf *last_mb = rte_pktmbuf_lastseg(mb);

	if (odp_unlikely(len >= odp_packet_len(*pkt)))
		return -1;

	/*
	 * Trim only if the last segment does not become zero length.
	 */
	if (odp_likely(len < last_mb->data_len)) {
		if (odp_unlikely(rte_pktmbuf_trim(mb, len)))
			return -1;
	} else {
		struct rte_mbuf *reverse[mb->nb_segs];
		struct rte_mbuf *t = mb;
		int i;

		for (i = 0; i < mb->nb_segs; ++i) {
			reverse[i] = t;
			t = t->next;
		}
		for (i = mb->nb_segs - 1; i >= 0 && len > 0; --i) {
			t = reverse[i];
			if (len >= t->data_len) {
				len -= t->data_len;
				mb->pkt_len -= t->data_len;
				t->data_len = 0;
				if (i > 0) {
					rte_pktmbuf_free_seg(t);
					--mb->nb_segs;
					reverse[i - 1]->next = NULL;
				}
			} else {
				t->data_len -= len;
				mb->pkt_len -= len;
				len = 0;
			}
		}
	}

	if (tail_ptr)
		*tail_ptr = odp_packet_tail(*pkt);
	if (tailroom)
		*tailroom = odp_packet_tailroom(*pkt);

	return 0;
}

/*
 *
 * Meta-data
 * ********************************************************
 *
 */

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ptr)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (odp_unlikely(ptr == NULL)) {
		pkt_hdr->p.flags.user_ptr_set = 0;
		return;
	}

	pkt_hdr->user_ptr = ptr;
	pkt_hdr->p.flags.user_ptr_set = 1;
}

void odp_packet_input_set(odp_packet_t pkt, odp_pktio_t pktio)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->input = pktio;
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;

	packet_hdr_has_l2_set(pkt_hdr, 1);
	pkt_hdr->p.l2_offset = offset;
	return 0;
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;

	pkt_hdr->p.l3_offset = offset;
	return 0;
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;

	pkt_hdr->p.l4_offset = offset;
	return 0;
}

uint16_t odp_packet_ones_comp(odp_packet_t pkt, odp_packet_data_range_t *range)
{
	(void)pkt;
	range->length = 0;
	range->offset = 0;
	return 0;
}

void odp_packet_l3_chksum_insert(odp_packet_t pkt, int insert)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.l3_chksum_set = 1;
	pkt_hdr->p.flags.l3_chksum = insert;
}

void odp_packet_l4_chksum_insert(odp_packet_t pkt, int insert)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.l4_chksum_set = 1;
	pkt_hdr->p.flags.l4_chksum = insert;
}

odp_packet_chksum_status_t odp_packet_l3_chksum_status(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (!pkt_hdr->p.input_flags.l3_chksum_done)
		return ODP_PACKET_CHKSUM_UNKNOWN;

	if (pkt_hdr->p.flags.l3_chksum_err)
		return ODP_PACKET_CHKSUM_BAD;

	return ODP_PACKET_CHKSUM_OK;
}

odp_packet_chksum_status_t odp_packet_l4_chksum_status(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (!pkt_hdr->p.input_flags.l4_chksum_done)
		return ODP_PACKET_CHKSUM_UNKNOWN;

	if (pkt_hdr->p.flags.l4_chksum_err)
		return ODP_PACKET_CHKSUM_BAD;

	return ODP_PACKET_CHKSUM_OK;
}

void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	packet_set_ts(pkt_hdr, &timestamp);
}

/*
 *
 * Manipulation
 * ********************************************************
 *
 */

int odp_packet_add_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t pktlen = odp_packet_len(pkt);
	pool_t *pool = pkt_hdr->event_hdr.pool_ptr;
	odp_packet_t newpkt;

	if (offset > pktlen)
		return -1;

	newpkt = odp_packet_alloc(pool->pool_hdl, pktlen + len);

	if (newpkt == ODP_PACKET_INVALID)
		return -1;

	if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, offset) != 0 ||
	    odp_packet_copy_from_pkt(newpkt, offset + len, pkt, offset,
				     pktlen - offset) != 0) {
		odp_packet_free(newpkt);
		return -1;
	}

	_odp_packet_copy_md(packet_hdr(newpkt), pkt_hdr, 0);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 1;
}

int odp_packet_rem_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t pktlen = odp_packet_len(pkt);
	pool_t *pool = pkt_hdr->event_hdr.pool_ptr;
	odp_packet_t newpkt;

	if (odp_unlikely(offset + len >= pktlen))
		return -1;

	newpkt = odp_packet_alloc(pool->pool_hdl, pktlen - len);

	if (newpkt == ODP_PACKET_INVALID)
		return -1;

	if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, offset) != 0 ||
	    odp_packet_copy_from_pkt(newpkt, offset, pkt, offset + len,
				     pktlen - offset - len) != 0) {
		odp_packet_free(newpkt);
		return -1;
	}

	_odp_packet_copy_md(packet_hdr(newpkt), pkt_hdr, 0);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 1;
}

int odp_packet_align(odp_packet_t *pkt, uint32_t offset, uint32_t len,
		     uint32_t align)
{
	int rc;
	uint32_t shift;
	uint32_t seglen = 0;  /* GCC */
	void *addr = odp_packet_offset(*pkt, offset, &seglen, NULL);
	uint64_t uaddr = (uint64_t)(uintptr_t)addr;
	uint64_t misalign;

	if (align > ODP_CACHE_LINE_SIZE)
		return -1;

	if (seglen >= len) {
		misalign = align <= 1 ? 0 :
			_ODP_ROUNDUP_ALIGN(uaddr, align) - uaddr;
		if (misalign == 0)
			return 0;
		shift = align - misalign;
	} else {
		if (len > odp_packet_seg_len(*pkt))
			return -1;
		shift  = len - seglen;
		uaddr -= shift;
		misalign = align <= 1 ? 0 :
			_ODP_ROUNDUP_ALIGN(uaddr, align) - uaddr;
		if (misalign)
			shift += align - misalign;
	}

	rc = odp_packet_extend_head(pkt, shift, NULL, NULL);
	if (rc < 0)
		return rc;

	(void)odp_packet_move_data(*pkt, 0, shift,
				   odp_packet_len(*pkt) - shift);

	(void)odp_packet_trunc_tail(pkt, shift, NULL, NULL);
	return 1;
}

int odp_packet_concat(odp_packet_t *dst, odp_packet_t src)
{
	odp_packet_hdr_t *dst_hdr = packet_hdr(*dst);
	odp_packet_hdr_t *src_hdr = packet_hdr(src);
	struct rte_mbuf *mb_dst = pkt_to_mbuf(*dst);
	struct rte_mbuf *mb_src = pkt_to_mbuf(src);
	odp_packet_t new_dst;
	odp_pool_t pool;
	uint32_t dst_len;
	uint32_t src_len;

	if (odp_likely(!rte_pktmbuf_chain(mb_dst, mb_src))) {
		dst_hdr->event_hdr.totsize += src_hdr->event_hdr.totsize;
		return 0;
	}

	/* Fall back to using standard copy operations after maximum number of
	 * segments has been reached. */
	dst_len = odp_packet_len(*dst);
	src_len = odp_packet_len(src);
	pool = odp_packet_pool(*dst);

	new_dst = odp_packet_copy(*dst, pool);
	if (odp_unlikely(new_dst == ODP_PACKET_INVALID))
		return -1;

	if (odp_packet_extend_tail(&new_dst, src_len, NULL, NULL) >= 0) {
		(void)odp_packet_copy_from_pkt(new_dst, dst_len,
					       src, 0, src_len);
		odp_packet_free(*dst);
		odp_packet_free(src);
		*dst = new_dst;
		return 1;
	}

	odp_packet_free(new_dst);
	return -1;
}

int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail)
{
	uint32_t pktlen = odp_packet_len(*pkt);

	if (odp_unlikely(len == 0 || len >= pktlen || tail == NULL))
		return -1;

	*tail = odp_packet_copy_part(*pkt, len, pktlen - len,
				     odp_packet_pool(*pkt));

	if (*tail == ODP_PACKET_INVALID)
		return -1;

	return odp_packet_trunc_tail(pkt, pktlen - len, NULL, NULL);
}

/*
 *
 * Copy
 * ********************************************************
 *
 */

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (odp_unlikely(_odp_packet_copy_md_possible(pool, odp_packet_pool(pkt)) < 0)) {
		ODP_ERR("Unable to copy packet metadata\n");
		return ODP_PACKET_INVALID;
	}

	newpkt = odp_packet_alloc(pool, pktlen);
	if (odp_unlikely(newpkt == ODP_PACKET_INVALID))
		return ODP_PACKET_INVALID;

	if (odp_unlikely(odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, pktlen))) {
		odp_packet_free(newpkt);
		newpkt = ODP_PACKET_INVALID;
	}

	_odp_packet_copy_md(packet_hdr(newpkt), packet_hdr(pkt), 1);

	return newpkt;
}

odp_packet_t odp_packet_copy_part(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, odp_pool_t pool)
{
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset >= pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pool, len);
	if (newpkt != ODP_PACKET_INVALID)
		odp_packet_copy_from_pkt(newpkt, 0, pkt, offset, len);

	return newpkt;
}

int odp_packet_copy_from_pkt(odp_packet_t dst, uint32_t dst_offset,
			     odp_packet_t src, uint32_t src_offset,
			     uint32_t len)
{
	odp_packet_hdr_t *dst_hdr = packet_hdr(dst);
	odp_packet_hdr_t *src_hdr = packet_hdr(src);
	void *dst_map;
	void *src_map;
	uint32_t cpylen, minseg;
	uint32_t dst_seglen = 0; /* GCC */
	uint32_t src_seglen = 0; /* GCC */
	int overlap;

	if (dst_offset + len > odp_packet_len(dst) ||
	    src_offset + len > odp_packet_len(src))
		return -1;

	overlap = (dst_hdr == src_hdr &&
		   ((dst_offset <= src_offset &&
		     dst_offset + len >= src_offset) ||
		    (src_offset <= dst_offset &&
		     src_offset + len >= dst_offset)));

	if (overlap && src_offset < dst_offset) {
		odp_packet_t temp =
			odp_packet_copy_part(src, src_offset, len,
					     odp_packet_pool(src));
		if (temp == ODP_PACKET_INVALID)
			return -1;
		odp_packet_copy_from_pkt(dst, dst_offset, temp, 0, len);
		odp_packet_free(temp);
		return 0;
	}

	while (len > 0) {
		dst_map = odp_packet_offset(dst, dst_offset, &dst_seglen, NULL);
		src_map = odp_packet_offset(src, src_offset, &src_seglen, NULL);

		minseg = dst_seglen > src_seglen ? src_seglen : dst_seglen;
		cpylen = len > minseg ? minseg : len;

		if (overlap)
			memmove(dst_map, src_map, cpylen);
		else
			memcpy(dst_map, src_map, cpylen);

		dst_offset += cpylen;
		src_offset += cpylen;
		len        -= cpylen;
	}

	return 0;
}

int odp_packet_copy_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

int odp_packet_move_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

int _odp_packet_set_data(odp_packet_t pkt, uint32_t offset,
			 uint8_t c, uint32_t len)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t setlen;

	if (offset + len > odp_packet_len(pkt))
		return -1;

	while (len > 0) {
		mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		setlen = len > seglen ? seglen : len;
		if (odp_unlikely(setlen == 0))
			return -1;
		memset(mapaddr, c, setlen);
		offset  += setlen;
		len     -= setlen;
	}

	return 0;
}

int _odp_packet_cmp_data(odp_packet_t pkt, uint32_t offset,
			 const void *s, uint32_t len)
{
	const uint8_t *ptr = s;
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cmplen;
	int ret;

	ODP_ASSERT(offset + len <= odp_packet_len(pkt));

	while (len > 0) {
		mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		cmplen = len > seglen ? seglen : len;
		ret = memcmp(mapaddr, ptr, cmplen);
		if (ret != 0)
			return ret;
		offset  += cmplen;
		len     -= cmplen;
		ptr     += cmplen;
	}

	return 0;
}

/*
 *
 * Debugging
 * ********************************************************
 *
 */
static int packet_print_input_flags(odp_packet_hdr_t *hdr, char *str, int max)
{
	int len = 0;

	if (hdr->p.input_flags.l2)
		len += snprintf(&str[len], max - len, "l2 ");
	if (hdr->p.input_flags.l3)
		len += snprintf(&str[len], max - len, "l3 ");
	if (hdr->p.input_flags.l4)
		len += snprintf(&str[len], max - len, "l4 ");
	if (hdr->p.input_flags.eth)
		len += snprintf(&str[len], max - len, "eth ");
	if (hdr->p.input_flags.vlan)
		len += snprintf(&str[len], max - len, "vlan ");
	if (hdr->p.input_flags.arp)
		len += snprintf(&str[len], max - len, "arp ");
	if (hdr->p.input_flags.ipv4)
		len += snprintf(&str[len], max - len, "ipv4 ");
	if (hdr->p.input_flags.ipv6)
		len += snprintf(&str[len], max - len, "ipv6 ");
	if (hdr->p.input_flags.ipsec)
		len += snprintf(&str[len], max - len, "ipsec ");
	if (hdr->p.input_flags.udp)
		len += snprintf(&str[len], max - len, "udp ");
	if (hdr->p.input_flags.tcp)
		len += snprintf(&str[len], max - len, "tcp ");
	if (hdr->p.input_flags.sctp)
		len += snprintf(&str[len], max - len, "sctp ");
	if (hdr->p.input_flags.icmp)
		len += snprintf(&str[len], max - len, "icmp ");

	return len;
}

void odp_packet_print(odp_packet_t pkt)
{
	odp_packet_seg_t seg;
	int max_len = 1024;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	odp_packet_hdr_t *hdr = packet_hdr(pkt);
	pool_t *pool = hdr->event_hdr.pool_ptr;

	len += snprintf(&str[len], n - len, "Packet\n------\n");
	len += snprintf(&str[len], n - len, "  pool index   %u\n", pool->pool_idx);
	len += snprintf(&str[len], n - len, "  buf index    %u\n", hdr->event_hdr.index);
	len += snprintf(&str[len], n - len, "  ev subtype   %i\n", hdr->subtype);
	len += snprintf(&str[len], n - len, "  input_flags  0x%" PRIx64 "\n",
			hdr->p.input_flags.all);
	if (hdr->p.input_flags.all) {
		len += snprintf(&str[len], n - len, "               ");
		len += packet_print_input_flags(hdr, &str[len], n - len);
		len += snprintf(&str[len], n - len, "\n");
	}
	len += snprintf(&str[len], n - len, "  flags        0x%" PRIx32 "\n",
			hdr->p.flags.all_flags);
	len += snprintf(&str[len], n - len, "  cls_mark     %" PRIu64 "\n",
			odp_packet_cls_mark(pkt));
	len += snprintf(&str[len], n - len,
			"  l2_offset    %" PRIu32 "\n", hdr->p.l2_offset);
	len += snprintf(&str[len], n - len,
			"  l3_offset    %" PRIu32 "\n", hdr->p.l3_offset);
	len += snprintf(&str[len], n - len,
			"  l4_offset    %" PRIu32 "\n", hdr->p.l4_offset);
	len += snprintf(&str[len], n - len,
			"  frame_len    %" PRIu32 "\n",
			hdr->event_hdr.mb.pkt_len);
	len += snprintf(&str[len], n - len,
			"  input        %" PRIu64 "\n",
			odp_pktio_to_u64(hdr->input));
	len += snprintf(&str[len], n - len,
			"  headroom     %" PRIu32 "\n",
			odp_packet_headroom(pkt));
	len += snprintf(&str[len], n - len,
			"  tailroom     %" PRIu32 "\n",
			odp_packet_tailroom(pkt));
	len += snprintf(&str[len], n - len,
			"  num_segs     %i\n", odp_packet_num_segs(pkt));

	seg = odp_packet_first_seg(pkt);

	for (int seg_idx = 0; seg != ODP_PACKET_SEG_INVALID; seg_idx++) {
		len += snprintf(&str[len], n - len,
				"    [%d] seg_len    %-4" PRIu32 "  seg_data %p\n",
				seg_idx, odp_packet_seg_data_len(pkt, seg),
				odp_packet_seg_data(pkt, seg));

		seg = odp_packet_next_seg(pkt, seg);
	}

	str[len] = '\0';

	ODP_PRINT("\n%s\n", str);
}

void odp_packet_print_data(odp_packet_t pkt, uint32_t offset,
			   uint32_t byte_len)
{
	odp_packet_hdr_t *hdr = packet_hdr(pkt);
	uint32_t bytes_per_row = 16;
	int num_rows = (byte_len + bytes_per_row - 1) / bytes_per_row;
	int max_len = 256 + (3 * byte_len) + (3 * num_rows);
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	uint32_t data_len = odp_packet_len(pkt);
	pool_t *pool = hdr->event_hdr.pool_ptr;

	len += snprintf(&str[len], n - len, "Packet\n------\n");
	len += snprintf(&str[len], n - len,
			"  pool name     %s\n", pool->name);
	len += snprintf(&str[len], n - len,
			"  buf index     %" PRIu32 "\n", hdr->event_hdr.index);
	len += snprintf(&str[len], n - len,
			"  segcount      %" PRIu8 "\n",
			hdr->event_hdr.mb.nb_segs);
	len += snprintf(&str[len], n - len,
			"  data len      %" PRIu32 "\n", data_len);
	len += snprintf(&str[len], n - len,
			"  data ptr      %p\n", odp_packet_data(pkt));
	len += snprintf(&str[len], n - len,
			"  print offset  %" PRIu32 "\n", offset);
	len += snprintf(&str[len], n - len,
			"  print length  %" PRIu32 "\n", byte_len);

	if (offset + byte_len > data_len) {
		len += snprintf(&str[len], n - len, " BAD OFFSET OR LEN\n");
		ODP_PRINT("%s\n", str);
		return;
	}

	while (byte_len) {
		uint32_t copy_len;
		uint8_t data[bytes_per_row];
		uint32_t i;

		if (byte_len > bytes_per_row)
			copy_len = bytes_per_row;
		else
			copy_len = byte_len;

		odp_packet_copy_to_mem(pkt, offset, copy_len, data);

		len += snprintf(&str[len], n - len, " ");

		for (i = 0; i < copy_len; i++)
			len += snprintf(&str[len], n - len, " %02x", data[i]);

		len += snprintf(&str[len], n - len, "\n");

		byte_len -= copy_len;
		offset   += copy_len;
	}

	ODP_PRINT("%s\n", str);
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	odp_event_t ev;

	if (pkt == ODP_PACKET_INVALID)
		return 0;

	ev = odp_packet_to_event(pkt);

	if (_odp_event_is_valid(ev) == 0)
		return 0;

	if (odp_event_type(ev) != ODP_EVENT_PACKET)
		return 0;

	switch (odp_event_subtype(ev)) {
	case ODP_EVENT_PACKET_BASIC:
		/* Fall through */
	case ODP_EVENT_PACKET_COMP:
		/* Fall through */
	case ODP_EVENT_PACKET_CRYPTO:
		/* Fall through */
	case ODP_EVENT_PACKET_IPSEC:
		/* Fall through */
		break;
	default:
		return 0;
	}

	return 1;
}

/*
 *
 * Internal Use Routines
 * ********************************************************
 *
 */

static uint64_t packet_sum_partial(odp_packet_hdr_t *pkt_hdr,
				   uint32_t l3_offset,
				   uint32_t offset,
				   uint32_t len)
{
	uint64_t sum = 0;
	uint32_t frame_len = odp_packet_len(packet_handle(pkt_hdr));

	if (offset + len > frame_len)
		return 0;

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */
		void *mapaddr = odp_packet_offset(packet_handle(pkt_hdr), offset, &seglen, NULL);

		if (seglen > len)
			seglen = len;

		sum += chksum_partial(mapaddr, seglen, offset - l3_offset);
		len -= seglen;
		offset += seglen;
	}

	return sum;
}

static inline uint16_t packet_sum(odp_packet_hdr_t *pkt_hdr,
				  uint32_t l3_offset,
				  uint32_t offset,
				  uint32_t len,
				  uint64_t sum)
{
	sum += packet_sum_partial(pkt_hdr, l3_offset, offset, len);
	return chksum_finalize(sum);
}

static uint32_t packet_sum_crc32c(odp_packet_hdr_t *pkt_hdr,
				  uint32_t offset,
				  uint32_t len,
				  uint32_t init_val)
{
	uint32_t sum = init_val;

	if (offset + len > odp_packet_len(packet_handle(pkt_hdr)))
		return sum;

	while (len > 0) {
		uint32_t seglen = 0; /* GCC */

		void *mapaddr = odp_packet_offset(packet_handle(pkt_hdr),
						  offset, &seglen, NULL);

		if (seglen > len)
			seglen = len;

		sum = odp_hash_crc32c(mapaddr, seglen, sum);
		len -= seglen;
		offset += seglen;
	}

	return sum;
}

static inline int packet_ipv4_chksum(odp_packet_t pkt,
				     uint32_t offset,
				     _odp_ipv4hdr_t *ip,
				     odp_u16sum_t *chksum)
{
	unsigned int nleft = _ODP_IPV4HDR_IHL(ip->ver_ihl) * 4;
	uint16_t buf[nleft / 2];
	int res;

	if (odp_unlikely(nleft < sizeof(*ip)))
		return -1;
	ip->chksum = 0;
	memcpy(buf, ip, sizeof(*ip));
	res = odp_packet_copy_to_mem(pkt, offset + sizeof(*ip),
				     nleft - sizeof(*ip),
				     buf + sizeof(*ip) / 2);
	if (odp_unlikely(res < 0))
		return res;

	*chksum = ~chksum_finalize(chksum_partial(buf, nleft, 0));

	return 0;
}

#define _ODP_IPV4HDR_CSUM_OFFSET ODP_OFFSETOF(_odp_ipv4hdr_t, chksum)
#define _ODP_IPV4ADDR_OFFSSET ODP_OFFSETOF(_odp_ipv4hdr_t, src_addr)
#define _ODP_IPV6ADDR_OFFSSET ODP_OFFSETOF(_odp_ipv6hdr_t, src_addr)
#define _ODP_IPV4HDR_CSUM_OFFSET ODP_OFFSETOF(_odp_ipv4hdr_t, chksum)
#define _ODP_UDP_LEN_OFFSET ODP_OFFSETOF(_odp_udphdr_t, length)
#define _ODP_UDP_CSUM_OFFSET ODP_OFFSETOF(_odp_udphdr_t, chksum)

/**
 * Calculate and fill in IPv4 checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_ipv4_chksum_insert(odp_packet_t pkt)
{
	uint32_t offset;
	_odp_ipv4hdr_t ip;
	odp_u16sum_t chksum;
	int res;

	offset = odp_packet_l3_offset(pkt);
	if (offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	res = odp_packet_copy_to_mem(pkt, offset, sizeof(ip), &ip);
	if (odp_unlikely(res < 0))
		return res;

	res = packet_ipv4_chksum(pkt, offset, &ip, &chksum);
	if (odp_unlikely(res < 0))
		return res;

	return odp_packet_copy_from_mem(pkt,
					offset + _ODP_IPV4HDR_CSUM_OFFSET,
					2, &chksum);
}

static int _odp_packet_tcp_udp_chksum_insert(odp_packet_t pkt, uint16_t proto)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t zero = 0;
	uint64_t sum;
	uint16_t l3_ver = 0; /* GCC */
	uint16_t chksum;
	uint32_t chksum_offset;
	uint32_t frame_len = odp_packet_len(pkt);

	if (pkt_hdr->p.l3_offset == ODP_PACKET_OFFSET_INVALID)
		return -1;
	if (pkt_hdr->p.l4_offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	odp_packet_copy_to_mem(pkt, pkt_hdr->p.l3_offset, 2, &l3_ver);

	if (_ODP_IPV4HDR_VER(l3_ver) == _ODP_IPV4)
		sum = packet_sum_partial(pkt_hdr,
					 pkt_hdr->p.l3_offset,
					 pkt_hdr->p.l3_offset +
					 _ODP_IPV4ADDR_OFFSSET,
					 2 * _ODP_IPV4ADDR_LEN);
	else
		sum = packet_sum_partial(pkt_hdr,
					 pkt_hdr->p.l3_offset,
					 pkt_hdr->p.l3_offset +
					 _ODP_IPV6ADDR_OFFSSET,
					 2 * _ODP_IPV6ADDR_LEN);
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
	sum += proto;
#else
	sum += proto << 8;
#endif

	if (proto == _ODP_IPPROTO_TCP) {
		sum += odp_cpu_to_be_16(frame_len -
					pkt_hdr->p.l4_offset);
		chksum_offset = pkt_hdr->p.l4_offset + _ODP_UDP_CSUM_OFFSET;
	} else {
		sum += packet_sum_partial(pkt_hdr,
					  pkt_hdr->p.l3_offset,
					  pkt_hdr->p.l4_offset +
					  _ODP_UDP_LEN_OFFSET,
					  2);
		chksum_offset = pkt_hdr->p.l4_offset + _ODP_UDP_CSUM_OFFSET;
	}
	odp_packet_copy_from_mem(pkt, chksum_offset, 2, &zero);

	sum += packet_sum_partial(pkt_hdr,
				  pkt_hdr->p.l3_offset,
				  pkt_hdr->p.l4_offset,
				  frame_len -
				  pkt_hdr->p.l4_offset);

	chksum = ~chksum_finalize(sum);

	if (proto == _ODP_IPPROTO_UDP && chksum == 0)
		chksum = 0xffff;

	return odp_packet_copy_from_mem(pkt,
					chksum_offset,
					2, &chksum);
}

/**
 * Calculate and fill in TCP checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_tcp_chksum_insert(odp_packet_t pkt)
{
	return _odp_packet_tcp_udp_chksum_insert(pkt, _ODP_IPPROTO_TCP);
}

/**
 * Calculate and fill in UDP checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_udp_chksum_insert(odp_packet_t pkt)
{
	return _odp_packet_tcp_udp_chksum_insert(pkt, _ODP_IPPROTO_UDP);
}

/**
 * Calculate and fill in SCTP checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_packet_sctp_chksum_insert(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t sum;
	uint32_t frame_len = odp_packet_len(pkt);

	if (pkt_hdr->p.l4_offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	sum = 0;
	odp_packet_copy_from_mem(pkt, pkt_hdr->p.l4_offset + 8, 4, &sum);
	sum = ~packet_sum_crc32c(pkt_hdr, pkt_hdr->p.l4_offset,
				 frame_len - pkt_hdr->p.l4_offset,
				 ~0);
	return odp_packet_copy_from_mem(pkt, pkt_hdr->p.l4_offset + 8, 4, &sum);
}

int _odp_packet_l4_chksum(odp_packet_hdr_t *pkt_hdr, odp_proto_chksums_t chksums,
			  uint64_t l4_part_sum)
{
	uint32_t frame_len = odp_packet_len(packet_handle(pkt_hdr));

	/* UDP chksum == 0 case is covered in parse_udp() */
	if (chksums.chksum.udp &&
	    pkt_hdr->p.input_flags.udp &&
	    !pkt_hdr->p.input_flags.ipfrag &&
	    !pkt_hdr->p.input_flags.udp_chksum_zero) {
		uint16_t sum = ~packet_sum(pkt_hdr,
					   pkt_hdr->p.l3_offset,
					   pkt_hdr->p.l4_offset,
					   frame_len -
					   pkt_hdr->p.l4_offset,
					   l4_part_sum);

		pkt_hdr->p.input_flags.l4_chksum_done = 1;
		if (sum != 0) {
			pkt_hdr->p.flags.l4_chksum_err = 1;
			pkt_hdr->p.flags.udp_err = 1;
			ODP_DBG("UDP chksum fail (%x)!\n", sum);
		}
	}

	if (chksums.chksum.tcp &&
	    pkt_hdr->p.input_flags.tcp &&
	    !pkt_hdr->p.input_flags.ipfrag) {
		uint16_t sum = ~packet_sum(pkt_hdr,
					   pkt_hdr->p.l3_offset,
					   pkt_hdr->p.l4_offset,
					   frame_len -
					   pkt_hdr->p.l4_offset,
					   l4_part_sum);

		pkt_hdr->p.input_flags.l4_chksum_done = 1;
		if (sum != 0) {
			pkt_hdr->p.flags.l4_chksum_err = 1;
			pkt_hdr->p.flags.tcp_err = 1;
			ODP_DBG("TCP chksum fail (%x)!\n", sum);
		}
	}

	if (chksums.chksum.sctp &&
	    pkt_hdr->p.input_flags.sctp &&
	    !pkt_hdr->p.input_flags.ipfrag) {
		uint32_t seg_len = 0;
		_odp_sctphdr_t hdr_copy;
		uint32_t sum = ~packet_sum_crc32c(pkt_hdr,
						  pkt_hdr->p.l4_offset +
						  _ODP_SCTPHDR_LEN,
						  frame_len -
						  pkt_hdr->p.l4_offset -
						  _ODP_SCTPHDR_LEN,
						  l4_part_sum);
		_odp_sctphdr_t *sctp = odp_packet_offset(packet_handle(pkt_hdr),
							 pkt_hdr->p.l4_offset,
							 &seg_len, NULL);
		if (odp_unlikely(seg_len < sizeof(*sctp))) {
			odp_packet_t pkt = packet_handle(pkt_hdr);

			sctp = &hdr_copy;
			odp_packet_copy_to_mem(pkt, pkt_hdr->p.l4_offset,
					       sizeof(*sctp), sctp);
		}
		pkt_hdr->p.input_flags.l4_chksum_done = 1;
		if (sum != sctp->chksum) {
			pkt_hdr->p.flags.l4_chksum_err = 1;
			pkt_hdr->p.flags.sctp_err = 1;
			ODP_DBG("SCTP chksum fail (%x/%x)!\n", sum,
				sctp->chksum);
		}
	}

	return pkt_hdr->p.flags.all.error != 0;
}

int odp_packet_parse(odp_packet_t pkt, uint32_t offset,
		     const odp_packet_parse_param_t *param)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	const uint8_t *data;
	uint32_t seg_len;
	uint32_t packet_len = odp_packet_len(pkt);
	odp_proto_t proto = param->proto;
	odp_proto_layer_t layer = param->last_layer;
	int ret;
	uint16_t ethtype;
	uint64_t l4_part_sum = 0;
	const uint32_t min_seglen = PARSE_ETH_BYTES + PARSE_L3_L4_BYTES;
	uint8_t buf[min_seglen];
	odp_pktin_config_opt_t opt;

	if (proto == ODP_PROTO_NONE || layer == ODP_PROTO_LAYER_NONE)
		return -1;

	data = odp_packet_offset(pkt, offset, &seg_len, NULL);

	if (data == NULL)
		return -1;

	/*
	 * We must not have a packet segment boundary within the parsed
	 * packet data range. Copy enough data to a temporary buffer for
	 * parsing if necessary.
	 */
	if (odp_unlikely(pkt_hdr->event_hdr.mb.nb_segs > 1) &&
	    odp_unlikely(seg_len < min_seglen)) {
		seg_len = min_seglen;
		if (seg_len > packet_len - offset)
			seg_len = packet_len - offset;
		odp_packet_copy_to_mem(pkt, offset, seg_len, buf);
		data = buf;
	}

	/* Reset parser flags, keep other flags */
	packet_parse_reset(pkt_hdr, 0);

	if (proto == ODP_PROTO_ETH) {
		/* Assume valid L2 header, no CRC/FCS check in SW */
		pkt_hdr->p.l2_offset = offset;

		ethtype = _odp_parse_eth(&pkt_hdr->p, &data, &offset, packet_len);
	} else if (proto == ODP_PROTO_IPV4) {
		ethtype = _ODP_ETHTYPE_IPV4;
	} else if (proto == ODP_PROTO_IPV6) {
		ethtype = _ODP_ETHTYPE_IPV6;
	} else {
		ethtype = 0; /* Invalid */
	}

	opt.all_bits = 0;

	ret = _odp_packet_parse_common_l3_l4(&pkt_hdr->p, data, offset,
					     packet_len, seg_len, layer,
					     ethtype, param->chksums,
					     &l4_part_sum, opt);

	if (ret)
		return -1;

	if (layer >= ODP_PROTO_LAYER_L4) {
		ret = _odp_packet_l4_chksum(pkt_hdr, param->chksums, l4_part_sum);
		if (ret)
			return -1;
	}

	return 0;
}

int odp_packet_parse_multi(const odp_packet_t pkt[], const uint32_t offset[],
			   int num, const odp_packet_parse_param_t *param)
{
	int i;

	for (i = 0; i < num; i++)
		if (odp_packet_parse(pkt[i], offset[i], param))
			return i;

	return num;
}

void odp_packet_parse_result(odp_packet_t pkt,
			     odp_packet_parse_result_t *result)
{
	/* TODO: optimize to single word copy when packet header stores bits
	 * directly into odp_packet_parse_result_flag_t */
	result->flag.all           = 0;
	result->flag.has_error     = odp_packet_has_error(pkt);
	result->flag.has_l2_error  = odp_packet_has_l2_error(pkt);
	result->flag.has_l3_error  = odp_packet_has_l3_error(pkt);
	result->flag.has_l4_error  = odp_packet_has_l4_error(pkt);
	result->flag.has_l2        = odp_packet_has_l2(pkt);
	result->flag.has_l3        = odp_packet_has_l3(pkt);
	result->flag.has_l4        = odp_packet_has_l4(pkt);
	result->flag.has_eth       = odp_packet_has_eth(pkt);
	result->flag.has_eth_bcast = odp_packet_has_eth_bcast(pkt);
	result->flag.has_eth_mcast = odp_packet_has_eth_mcast(pkt);
	result->flag.has_jumbo     = odp_packet_has_jumbo(pkt);
	result->flag.has_vlan      = odp_packet_has_vlan(pkt);
	result->flag.has_vlan_qinq = odp_packet_has_vlan_qinq(pkt);
	result->flag.has_arp       = odp_packet_has_arp(pkt);
	result->flag.has_ipv4      = odp_packet_has_ipv4(pkt);
	result->flag.has_ipv6      = odp_packet_has_ipv6(pkt);
	result->flag.has_ip_bcast  = odp_packet_has_ip_bcast(pkt);
	result->flag.has_ip_mcast  = odp_packet_has_ip_mcast(pkt);
	result->flag.has_ipfrag    = odp_packet_has_ipfrag(pkt);
	result->flag.has_ipopt     = odp_packet_has_ipopt(pkt);
	result->flag.has_ipsec     = odp_packet_has_ipsec(pkt);
	result->flag.has_udp       = odp_packet_has_udp(pkt);
	result->flag.has_tcp       = odp_packet_has_tcp(pkt);
	result->flag.has_sctp      = odp_packet_has_sctp(pkt);
	result->flag.has_icmp      = odp_packet_has_icmp(pkt);

	result->packet_len       = odp_packet_len(pkt);
	result->l2_offset        = odp_packet_l2_offset(pkt);
	result->l3_offset        = odp_packet_l3_offset(pkt);
	result->l4_offset        = odp_packet_l4_offset(pkt);
	result->l3_chksum_status = odp_packet_l3_chksum_status(pkt);
	result->l4_chksum_status = odp_packet_l4_chksum_status(pkt);
	result->l2_type          = odp_packet_l2_type(pkt);
	result->l3_type          = odp_packet_l3_type(pkt);
	result->l4_type          = odp_packet_l4_type(pkt);
}

void odp_packet_parse_result_multi(const odp_packet_t pkt[],
				   odp_packet_parse_result_t *result[],
				   int num)
{
	int i;

	for (i = 0; i < num; i++)
		odp_packet_parse_result(pkt[i], result[i]);
}

uint64_t odp_packet_to_u64(odp_packet_t hdl)
{
	return _odp_pri(hdl);
}

uint64_t odp_packet_seg_to_u64(odp_packet_seg_t hdl)
{
	return _odp_pri(hdl);
}

odp_packet_t odp_packet_ref(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_t new;
	int ret;

	ODP_ASSERT(!odp_packet_has_ref(pkt));

	new = odp_packet_copy(pkt, odp_packet_pool(pkt));

	if (new == ODP_PACKET_INVALID) {
		ODP_ERR("copy failed\n");
		return ODP_PACKET_INVALID;
	}

	ret = odp_packet_trunc_head(&new, offset, NULL, NULL);

	if (ret < 0) {
		ODP_ERR("trunk_head failed\n");
		odp_packet_free(new);
		return ODP_PACKET_INVALID;
	}

	return new;
}

odp_packet_t odp_packet_ref_pkt(odp_packet_t pkt, uint32_t offset,
				odp_packet_t hdr)
{
	odp_packet_t new;
	int ret;

	ODP_ASSERT(!odp_packet_has_ref(pkt));

	new = odp_packet_copy(pkt, odp_packet_pool(pkt));

	if (new == ODP_PACKET_INVALID) {
		ODP_ERR("copy failed\n");
		return ODP_PACKET_INVALID;
	}

	if (offset) {
		ret = odp_packet_trunc_head(&new, offset, NULL, NULL);

		if (ret < 0) {
			ODP_ERR("trunk_head failed\n");
			odp_packet_free(new);
			return ODP_PACKET_INVALID;
		}
	}

	ret = odp_packet_concat(&hdr, new);

	if (ret < 0) {
		ODP_ERR("concat failed\n");
		odp_packet_free(new);
		return ODP_PACKET_INVALID;
	}

	return hdr;
}

odp_proto_l2_type_t odp_packet_l2_type(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.input_flags.eth)
		return ODP_PROTO_L2_TYPE_ETH;

	return ODP_PROTO_L2_TYPE_NONE;
}

odp_proto_l3_type_t odp_packet_l3_type(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.input_flags.ipv4)
		return ODP_PROTO_L3_TYPE_IPV4;
	else if (pkt_hdr->p.input_flags.ipv6)
		return ODP_PROTO_L3_TYPE_IPV6;
	else if (pkt_hdr->p.input_flags.arp)
		return ODP_PROTO_L3_TYPE_ARP;

	return ODP_PROTO_L3_TYPE_NONE;
}

odp_proto_l4_type_t odp_packet_l4_type(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.input_flags.tcp)
		return ODP_PROTO_L4_TYPE_TCP;
	else if (pkt_hdr->p.input_flags.udp)
		return ODP_PROTO_L4_TYPE_UDP;
	else if (pkt_hdr->p.input_flags.sctp)
		return ODP_PROTO_L4_TYPE_SCTP;
	else if (pkt_hdr->p.input_flags.ipsec_ah)
		return ODP_PROTO_L4_TYPE_AH;
	else if (pkt_hdr->p.input_flags.ipsec_esp)
		return ODP_PROTO_L4_TYPE_ESP;
	else if (pkt_hdr->p.input_flags.icmp &&
		 pkt_hdr->p.input_flags.ipv4)
		return ODP_PROTO_L4_TYPE_ICMPV4;
	else if (pkt_hdr->p.input_flags.icmp &&
		 pkt_hdr->p.input_flags.ipv6)
		return ODP_PROTO_L4_TYPE_ICMPV6;
	else if (pkt_hdr->p.input_flags.no_next_hdr)
		return ODP_PROTO_L4_TYPE_NO_NEXT;

	return ODP_PROTO_L4_TYPE_NONE;
}

uint64_t odp_packet_cls_mark(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.input_flags.cls_mark)
		return pkt_hdr->cls_mark;

	return 0;
}

void odp_packet_ts_request(odp_packet_t pkt, int enable)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.ts_set = !!enable;
}

void odp_packet_lso_request_clr(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.lso = 0;
}

int odp_packet_has_lso_request(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return pkt_hdr->p.flags.lso;
}

uint32_t odp_packet_payload_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (pkt_hdr->p.flags.payload_off)
		return pkt_hdr->payload_offset;

	return ODP_PACKET_OFFSET_INVALID;
}

int odp_packet_payload_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.payload_off = 1;
	pkt_hdr->payload_offset      = offset;

	return 0;
}

void odp_packet_aging_tmo_set(odp_packet_t pkt, uint64_t tmo_ns)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.tx_aging = tmo_ns ? 1 : 0;
	pkt_hdr->tx_aging_ns = tmo_ns;
}

uint64_t odp_packet_aging_tmo(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return pkt_hdr->p.flags.tx_aging ? pkt_hdr->tx_aging_ns : 0;
}

int odp_packet_tx_compl_request(odp_packet_t pkt, const odp_packet_tx_compl_opt_t *opt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.tx_compl = opt->mode == ODP_PACKET_TX_COMPL_ALL ? 1 : 0;
	pkt_hdr->dst_queue = opt->queue;

	return 0;
}

int odp_packet_has_tx_compl_request(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	return pkt_hdr->p.flags.tx_compl;
}

void odp_packet_tx_compl_free(odp_packet_tx_compl_t tx_compl)
{
	if (odp_unlikely(tx_compl == ODP_PACKET_TX_COMPL_INVALID)) {
		ODP_ERR("Bad TX completion event handle\n");
		return;
	}

	odp_buffer_free((odp_buffer_t)tx_compl);
}

void *odp_packet_tx_compl_user_ptr(odp_packet_tx_compl_t tx_compl)
{
	if (odp_unlikely(tx_compl == ODP_PACKET_TX_COMPL_INVALID)) {
		ODP_ERR("Bad TX completion event handle\n");
		return NULL;
	}

	_odp_pktio_tx_compl_t *data = odp_buffer_addr((odp_buffer_t)tx_compl);

	return (void *)(uintptr_t)data->user_ptr;
}

odp_packet_reass_status_t odp_packet_reass_status(odp_packet_t pkt)
{
	(void)pkt;
	return ODP_PACKET_REASS_NONE;
}

int odp_packet_reass_info(odp_packet_t pkt, odp_packet_reass_info_t *info)
{
	(void)pkt;
	(void)info;
	return -1;
}

int odp_packet_reass_partial_state(odp_packet_t pkt, odp_packet_t frags[],
				   odp_packet_reass_partial_state_t *res)
{
	(void)pkt;
	(void)frags;
	(void)res;
	return -ENOTSUP;
}

static inline odp_packet_hdr_t *packet_buf_to_hdr(odp_packet_buf_t pkt_buf)
{
	return (odp_packet_hdr_t *)(uintptr_t)pkt_buf;
}

void *odp_packet_buf_head(odp_packet_buf_t pkt_buf)
{
	odp_packet_hdr_t *pkt_hdr = packet_buf_to_hdr(pkt_buf);
	pool_t *pool = pkt_hdr->event_hdr.pool_ptr;

	if (odp_unlikely(pool->pool_ext == 0)) {
		ODP_ERR("Not an external memory pool\n");
		return NULL;
	}

	return (uint8_t *)pkt_hdr + pool->hdr_size;
}

uint32_t odp_packet_buf_size(odp_packet_buf_t pkt_buf)
{
	odp_packet_hdr_t *pkt_hdr = packet_buf_to_hdr(pkt_buf);
	pool_t *pool = pkt_hdr->event_hdr.pool_ptr;

	return pool->seg_len;
}

uint32_t odp_packet_buf_data_offset(odp_packet_buf_t pkt_buf)
{
	void *data = odp_packet_seg_data(ODP_PACKET_INVALID,
					 (odp_packet_seg_t)pkt_buf);
	void *head = odp_packet_buf_head(pkt_buf);

	return (uintptr_t)data - (uintptr_t)head;
}

uint32_t odp_packet_buf_data_len(odp_packet_buf_t pkt_buf)
{
	return odp_packet_seg_data_len(ODP_PACKET_INVALID,
				       (odp_packet_seg_t)pkt_buf);
}

void odp_packet_buf_data_set(odp_packet_buf_t pkt_buf, uint32_t data_offset,
			     uint32_t data_len)
{
	odp_packet_hdr_t *pkt_hdr = packet_buf_to_hdr(pkt_buf);

	pkt_hdr->event_hdr.mb.data_off = data_offset;
	pkt_hdr->event_hdr.mb.data_len = data_len;
}

odp_packet_buf_t odp_packet_buf_from_head(odp_pool_t pool_hdl, void *head)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	if (odp_unlikely(pool->type != ODP_POOL_PACKET)) {
		ODP_ERR("Not a packet pool\n");
		return ODP_PACKET_BUF_INVALID;
	}

	if (odp_unlikely(pool->pool_ext == 0)) {
		ODP_ERR("Not an external memory pool\n");
		return ODP_PACKET_BUF_INVALID;
	}

	return (odp_packet_buf_t)((uintptr_t)head - pool->hdr_size);
}

uint32_t odp_packet_disassemble(odp_packet_t pkt, odp_packet_buf_t pkt_buf[],
				uint32_t num)
{
	uint32_t i;
	odp_packet_seg_t seg;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	pool_t *pool = pkt_hdr->event_hdr.pool_ptr;
	uint32_t num_segs = odp_packet_num_segs(pkt);

	if (odp_unlikely(pool->type != ODP_POOL_PACKET)) {
		ODP_ERR("Not a packet pool\n");
		return 0;
	}

	if (odp_unlikely(pool->pool_ext == 0)) {
		ODP_ERR("Not an external memory pool\n");
		return 0;
	}

	if (odp_unlikely(num < num_segs)) {
		ODP_ERR("Not enough buffer handles %u. Packet has %u segments.\n",
			num, num_segs);
		return 0;
	}

	seg = odp_packet_first_seg(pkt);

	for (i = 0; i < num_segs; i++) {
		pkt_buf[i] = (odp_packet_buf_t)(uintptr_t)seg;
		seg = odp_packet_next_seg(pkt, seg);
	}

	return num_segs;
}

odp_packet_t odp_packet_reassemble(odp_pool_t pool_hdl,
				   odp_packet_buf_t pkt_buf[], uint32_t num)
{
	uint32_t i, data_len;
	odp_packet_hdr_t *cur_seg, *next_seg;
	odp_packet_hdr_t *pkt_hdr = (odp_packet_hdr_t *)(uintptr_t)pkt_buf[0];
	uint32_t headroom = odp_packet_buf_data_offset(pkt_buf[0]);

	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	if (odp_unlikely(pool->type != ODP_POOL_PACKET)) {
		ODP_ERR("Not a packet pool\n");
		return ODP_PACKET_INVALID;
	}

	if (odp_unlikely(pool->pool_ext == 0)) {
		ODP_ERR("Not an external memory pool\n");
		return ODP_PACKET_INVALID;
	}

	if (odp_unlikely(num == 0)) {
		ODP_ERR("Bad number of buffers: %u\n", num);
		return ODP_PACKET_INVALID;
	}

	cur_seg = pkt_hdr;
	data_len = 0;

	for (i = 0; i < num; i++) {
		struct rte_mbuf *mb;

		next_seg = NULL;
		if (i < num - 1)
			next_seg = (odp_packet_hdr_t *)(uintptr_t)pkt_buf[i + 1];

		data_len += cur_seg->event_hdr.mb.data_len;
		mb = (struct rte_mbuf *)(uintptr_t)cur_seg;
		mb->next = (struct rte_mbuf *)next_seg;
		cur_seg = next_seg;
	}

	pkt_hdr->event_hdr.mb.nb_segs = num;
	pkt_hdr->event_hdr.mb.pkt_len = data_len;
	pkt_hdr->event_hdr.mb.data_off = headroom;

	/* Reset metadata */
	pkt_hdr->subtype = ODP_EVENT_PACKET_BASIC;
	pkt_hdr->input = ODP_PKTIO_INVALID;
	packet_parse_reset(pkt_hdr, 1);

	return packet_handle(pkt_hdr);
}

void odp_packet_proto_stats_request(odp_packet_t pkt, odp_packet_proto_stats_opt_t *opt)
{
	(void)pkt;
	(void)opt;
}

odp_proto_stats_t odp_packet_proto_stats(odp_packet_t pkt)
{
	(void)pkt;

	return ODP_PROTO_STATS_INVALID;
}
