/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp_init_internal.h>
#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/cpumask.h>
#include <odp_libconfig_internal.h>
#include <odp_event_vector_internal.h>

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <inttypes.h>

#include <odp/api/plat/pool_inline_types.h>

#include <rte_config.h>
#include <rte_errno.h>
#include <rte_version.h>

#ifdef POOL_USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp/api/spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#endif

/* Pool name format */
#define POOL_NAME_FORMAT "%" PRIu64 "-%d-%s"

/* Define a practical limit for contiguous memory allocations */
#define MAX_SIZE   (10 * 1024 * 1024)

/* The pool table ptr - resides in shared memory */
pool_global_t *_odp_pool_glb;

#include <odp/visibility_begin.h>

/* Fill in pool header field offsets for inline functions */
const _odp_pool_inline_offset_t _odp_pool_inline ODP_ALIGNED_CACHE = {
	.pool_hdl          = offsetof(pool_t, pool_hdl),
	.uarea_size        = offsetof(pool_t, params.pkt.uarea_size)
};

#include <odp/visibility_end.h>

static inline odp_pool_t pool_index_to_handle(uint32_t pool_idx)
{
	return _odp_cast_scalar(odp_pool_t, pool_idx + 1);
}

struct mem_cb_arg_t {
	uint8_t *addr;
	odp_bool_t match;
};

static void ptr_from_mempool(struct rte_mempool *mp ODP_UNUSED, void *opaque,
			     struct rte_mempool_memhdr *memhdr,
			     unsigned int mem_idx ODP_UNUSED)
{
	struct mem_cb_arg_t *args = (struct mem_cb_arg_t *)opaque;
	uint8_t *min_addr = (uint8_t *)memhdr->addr;
	uint8_t *max_addr = min_addr + memhdr->len;

	/* Match found already */
	if (args->match)
		return;

	if (args->addr >= min_addr && args->addr < max_addr)
		args->match = true;
}

static pool_t *find_pool(odp_buffer_hdr_t *buf_hdr)
{
	int i;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_t *pool = pool_entry(i);
		struct mem_cb_arg_t args;

		if (pool->rte_mempool == NULL)
			continue;

		args.addr = (uint8_t *)buf_hdr;
		args.match = false;
		rte_mempool_mem_iter(pool->rte_mempool, ptr_from_mempool, &args);

		if (args.match)
			return pool;
	}

	return NULL;
}

static int read_config_file(pool_global_t *pool_gbl)
{
	const char *str;
	int val = 0;

	ODP_PRINT("Pool config:\n");

	str = "pool.pkt.max_num";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val < 0 || val > CONFIG_POOL_MAX_NUM) {
		ODP_ERR("Bad value %s = %u\n", str, val);
		return -1;
	}

	pool_gbl->config.pkt_max_num = val;
	ODP_PRINT("  %s: %i\n", str, val);

	ODP_PRINT("\n");

	return 0;
}

int _odp_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_pool_glb", sizeof(pool_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	_odp_pool_glb = odp_shm_addr(shm);

	if (_odp_pool_glb == NULL)
		return -1;

	memset(_odp_pool_glb, 0, sizeof(pool_global_t));
	_odp_pool_glb->shm = shm;

	if (read_config_file(_odp_pool_glb)) {
		odp_shm_free(shm);
		 _odp_pool_glb = NULL;
		return -1;
	}

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_t *pool = pool_entry(i);

		LOCK_INIT(&pool->lock);
		pool->pool_hdl = pool_index_to_handle(i);
	}

	ODP_DBG("\nPool init global\n");
	ODP_DBG("  odp_buffer_hdr_t size:       %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("  odp_packet_hdr_t size:       %zu\n", sizeof(odp_packet_hdr_t));
	ODP_DBG("  odp_timeout_hdr_t size:      %zu\n", sizeof(odp_timeout_hdr_t));
	ODP_DBG("  odp_event_vector_hdr_t size: %zu\n", sizeof(odp_event_vector_hdr_t));

	ODP_DBG("\n");

	return 0;
}

int _odp_pool_init_local(void)
{
	return 0;
}

int _odp_pool_term_global(void)
{
	int ret;

	if (_odp_pool_glb == NULL)
		return 0;

	ret = odp_shm_free(_odp_pool_glb->shm);
	if (ret < 0)
		ODP_ERR("SHM free failed\n");

	return ret;
}

int _odp_pool_term_local(void)
{
	return 0;
}

int _odp_buffer_is_valid(odp_buffer_t buf)
{
	pool_t *pool;
	odp_buffer_hdr_t *buf_hdr = buf_hdl_to_hdr(buf);

	if (buf == ODP_BUFFER_INVALID)
		return 0;

	/* Check that buffer header is from a known pool */
	pool = find_pool(buf_hdr);
	if (pool == NULL)
		return 0;

	if (pool != buf_hdr->pool_ptr)
		return 0;

	if (buf_hdr->index >= pool->rte_mempool->size)
		return 0;

	return 1;
}

int odp_pool_capability(odp_pool_capability_t *capa)
{
	unsigned int max_pools;

	memset(capa, 0, sizeof(odp_pool_capability_t));

	/* Reserve one pool for internal usage */
	max_pools = ODP_CONFIG_POOLS - 1;

	/* Buffer pools */
	capa->buf.max_pools = max_pools;
	capa->buf.max_align = ODP_CONFIG_BUFFER_ALIGN_MAX;
	capa->buf.max_size  = MAX_SIZE;
	capa->buf.max_num   = CONFIG_POOL_MAX_NUM;
	capa->buf.min_cache_size   = 0;
	capa->buf.max_cache_size   = RTE_MEMPOOL_CACHE_MAX_SIZE;

	/* Packet pools */
	capa->pkt.max_align        = ODP_CONFIG_BUFFER_ALIGN_MIN;
	capa->pkt.max_pools        = max_pools;
	capa->pkt.max_len          = 0;
	capa->pkt.max_num	   = _odp_pool_glb->config.pkt_max_num;
	capa->pkt.min_headroom     = CONFIG_PACKET_HEADROOM;
	capa->pkt.max_headroom     = CONFIG_PACKET_HEADROOM;
	capa->pkt.min_tailroom     = CONFIG_PACKET_TAILROOM;
	capa->pkt.max_segs_per_pkt = CONFIG_PACKET_MAX_SEGS;
	capa->pkt.min_seg_len      = CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_seg_len      = CONFIG_PACKET_SEG_LEN_MAX;
	capa->pkt.max_uarea_size   = MAX_SIZE;
	capa->pkt.min_cache_size   = 0;
	capa->pkt.max_cache_size   = RTE_MEMPOOL_CACHE_MAX_SIZE;

	/* Timeout pools */
	capa->tmo.max_pools = max_pools;
	capa->tmo.max_num   = CONFIG_POOL_MAX_NUM;
	capa->tmo.min_cache_size   = 0;
	capa->tmo.max_cache_size   = RTE_MEMPOOL_CACHE_MAX_SIZE;

	/* Vector pools */
	capa->vector.max_pools      = max_pools;
	capa->vector.max_num        = CONFIG_POOL_MAX_NUM;
	capa->vector.max_size       = CONFIG_PACKET_VECTOR_MAX_SIZE;
	capa->vector.min_cache_size = 0;
	capa->vector.max_cache_size = RTE_MEMPOOL_CACHE_MAX_SIZE;

	return 0;
}

struct mbuf_ctor_arg {
	pool_t	*pool;
	uint16_t seg_buf_offset; /* To skip the ODP buf/pkt/tmo header */
	uint16_t seg_buf_size;   /* size of user data */
	int type;                /* ODP pool type */
	int event_type;          /* ODP event type */
	int pkt_uarea_size;      /* size of user area in bytes */
};

/* ODP DPDK mbuf constructor.
 * This is a combination of rte_pktmbuf_init in rte_mbuf.c
 * and testpmd_mbuf_ctor in testpmd.c
 */
static void
odp_dpdk_mbuf_ctor(struct rte_mempool *mp,
		   void *opaque_arg,
		   void *raw_mbuf,
		   unsigned i)
{
	struct mbuf_ctor_arg *mb_ctor_arg;
	struct rte_mbuf *mb = raw_mbuf;
	struct odp_buffer_hdr_t *buf_hdr;

	/* The rte_mbuf is at the begninning in all cases */
	mb_ctor_arg = (struct mbuf_ctor_arg *)opaque_arg;
	mb = (struct rte_mbuf *)raw_mbuf;

	RTE_ASSERT(mp->elt_size >= sizeof(struct rte_mbuf));

	memset(mb, 0, mp->elt_size);

	/* Start of buffer is just after the ODP type specific header
	 * which contains in the very beginning the rte_mbuf struct */
	mb->buf_addr     = (char *)mb + mb_ctor_arg->seg_buf_offset;
#if RTE_VERSION < RTE_VERSION_NUM(17, 11, 0, 0)
	mb->buf_physaddr = rte_mempool_virt2phy(mp, mb) +
			mb_ctor_arg->seg_buf_offset;
#else
	mb->buf_physaddr = rte_mempool_virt2iova(mb) +
			mb_ctor_arg->seg_buf_offset;
#endif
	mb->buf_len      = mb_ctor_arg->seg_buf_size;
	mb->priv_size = rte_pktmbuf_priv_size(mp);

	/* keep some headroom between start of buffer and data */
	if (mb_ctor_arg->type == ODP_POOL_PACKET) {
		mb->data_off = RTE_PKTMBUF_HEADROOM;
		mb->port = 0xff;
		mb->vlan_tci = 0;
	} else {
		mb->data_off = 0;
	}

	/* init some constant fields */
	mb->pool = mp;
	mb->nb_segs = 1;
	mb->ol_flags = 0;
	rte_mbuf_refcnt_set(mb, 1);
	mb->next = NULL;

	/* Save index, might be useful for debugging purposes */
	buf_hdr = (struct odp_buffer_hdr_t *)raw_mbuf;
	buf_hdr->index = i;
	buf_hdr->pool_ptr = mb_ctor_arg->pool;
	buf_hdr->type = mb_ctor_arg->type;
	buf_hdr->event_type = mb_ctor_arg->event_type;

	/* Initialize event vector metadata */
	if (mb_ctor_arg->type == ODP_POOL_VECTOR) {
		odp_event_vector_hdr_t *vect_hdr;

		vect_hdr = (odp_event_vector_hdr_t *)raw_mbuf;
		vect_hdr->size = 0;
	}
}

#define CHECK_U16_OVERFLOW(X)	do {			\
	if (odp_unlikely(X > UINT16_MAX)) {		\
		ODP_ERR("Invalid size: %d\n", X);	\
		UNLOCK(&pool->lock);			\
		return ODP_POOL_INVALID;		\
	}						\
} while (0)

static int check_params(const odp_pool_param_t *params)
{
	odp_pool_capability_t capa;

	if (!params || odp_pool_capability(&capa) < 0)
		return -1;

	switch (params->type) {
	case ODP_POOL_BUFFER:
		if (params->buf.num > capa.buf.max_num) {
			ODP_ERR("buf.num too large %u\n", params->buf.num);
			return -1;
		}

		if (params->buf.size > capa.buf.max_size) {
			ODP_ERR("buf.size too large %u\n", params->buf.size);
			return -1;
		}

		if (params->buf.align > capa.buf.max_align) {
			ODP_ERR("buf.align too large %u\n", params->buf.align);
			return -1;
		}

		if (params->buf.cache_size > capa.buf.max_cache_size) {
			ODP_ERR("buf.cache_size too large %u\n",
				params->buf.cache_size);
			return -1;
		}

		break;

	case ODP_POOL_PACKET:
		if (params->pkt.align > capa.pkt.max_align) {
			ODP_ERR("pkt.align too large %u\n", params->pkt.align);
			return -1;
		}
		if (params->pkt.num > capa.pkt.max_num) {
			ODP_ERR("pkt.num too large %u\n", params->pkt.num);
			return -1;
		}

		if (params->pkt.max_num > capa.pkt.max_num) {
			ODP_ERR("pkt.max_num too large %u\n",
				params->pkt.max_num);
			return -1;
		}

		if (params->pkt.num > capa.pkt.max_num) {
			ODP_ERR("pkt.num too large %u\n", params->pkt.num);
			return -1;
		}

		if (params->pkt.seg_len > capa.pkt.max_seg_len) {
			ODP_ERR("pkt.seg_len too large %u\n",
				params->pkt.seg_len);
			return -1;
		}

		if (params->pkt.uarea_size > capa.pkt.max_uarea_size) {
			ODP_ERR("pkt.uarea_size too large %u\n",
				params->pkt.uarea_size);
			return -1;
		}

		if (params->pkt.headroom > CONFIG_PACKET_HEADROOM) {
			ODP_ERR("pkt.headroom too large %u\n",
				params->pkt.headroom);
			return -1;
		}

		if (params->pkt.cache_size > capa.pkt.max_cache_size) {
			ODP_ERR("pkt.cache_size too large %u\n",
				params->pkt.cache_size);
			return -1;
		}

		break;

	case ODP_POOL_TIMEOUT:
		if (params->tmo.num > capa.tmo.max_num) {
			ODP_ERR("tmo.num too large %u\n", params->tmo.num);
			return -1;
		}

		if (params->tmo.cache_size > capa.tmo.max_cache_size) {
			ODP_ERR("tmo.cache_size too large %u\n",
				params->tmo.cache_size);
			return -1;
		}

		break;

	case ODP_POOL_VECTOR:
		if (params->vector.num == 0) {
			ODP_ERR("vector.num zero\n");
			return -1;
		}

		if (params->vector.num > capa.vector.max_num) {
			ODP_ERR("vector.num too large %u\n", params->vector.num);
			return -1;
		}

		if (params->vector.max_size == 0) {
			ODP_ERR("vector.max_size zero\n");
			return -1;
		}

		if (params->vector.max_size > capa.vector.max_size) {
			ODP_ERR("vector.max_size too large %u\n", params->vector.max_size);
			return -1;
		}

		if (params->vector.cache_size > capa.vector.max_cache_size) {
			ODP_ERR("vector.cache_size too large %u\n", params->vector.cache_size);
			return -1;
		}

		break;

	default:
		ODP_ERR("bad pool type %i\n", params->type);
		return -1;
	}

	return 0;
}

static unsigned int calc_cache_size(uint32_t pool_size, uint32_t max_num)
{
	unsigned int cache_size;
	unsigned int max_supported = pool_size / 1.5;
	int num_threads = odp_global_ro.init_param.num_control +
				odp_global_ro.init_param.num_worker;

	if (max_num == 0)
		return 0;

	cache_size = RTE_MIN(max_num, max_supported);

	while (cache_size) {
		if ((pool_size % cache_size) == 0)
			break;
		cache_size--;
	}

	if (odp_unlikely(cache_size == 0)) {
		cache_size = RTE_MIN(max_num, max_supported);
		ODP_DBG("Using nonoptimal cache size: %d\n", cache_size);
	}

	/* Cache size of one exposes DPDK implementation bug */
	if (cache_size == 1)
		cache_size = 0;

	ODP_DBG("Cache_size: %d\n", cache_size);

	if (num_threads && cache_size) {
		unsigned int total_cache_size = num_threads * cache_size;

		if (total_cache_size >= pool_size)
			ODP_DBG("Entire pool fits into thread local caches. "
				"Pool starvation may occur if the pool is used "
				"by multiple threads.\n");
	}

	return cache_size;
}

static void format_pool_name(const char *name, char *rte_name)
{
	int i = 0;

	/* Use pid and counter to make name unique */
	do {
		snprintf(rte_name, RTE_MEMPOOL_NAMESIZE, POOL_NAME_FORMAT,
			 (odp_instance_t)odp_global_ro.main_pid, i++, name);
		rte_name[RTE_MEMPOOL_NAMESIZE - 1] = 0;
	} while (rte_mempool_lookup(rte_name) != NULL);
}

odp_pool_t odp_pool_create(const char *name, const odp_pool_param_t *params)
{
	struct rte_pktmbuf_pool_private mbp_ctor_arg;
	struct mbuf_ctor_arg mb_ctor_arg;
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	unsigned int mb_size, i, cache_size;
	size_t hdr_size;
	pool_t *pool;
	uint32_t buf_align, blk_size, headroom, tailroom, min_seg_len;
	uint32_t max_len, min_align;
	int8_t event_type;
	char pool_name[ODP_POOL_NAME_LEN];
	char rte_name[RTE_MEMPOOL_NAMESIZE];

	if (check_params(params))
		return ODP_POOL_INVALID;

	if (name == NULL) {
		pool_name[0] = 0;
	} else {
		strncpy(pool_name, name, ODP_POOL_NAME_LEN - 1);
		pool_name[ODP_POOL_NAME_LEN - 1] = 0;
	}

	/* Find an unused buffer pool slot and initialize it as requested */
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		uint32_t num;
		struct rte_mempool *mp;

		pool = pool_entry(i);

		LOCK(&pool->lock);
		if (pool->rte_mempool != NULL) {
			UNLOCK(&pool->lock);
			continue;
		}

		switch (params->type) {
		case ODP_POOL_BUFFER:
			buf_align = params->buf.align;
			blk_size = params->buf.size;
			cache_size = params->buf.cache_size;

			/* Validate requested buffer alignment */
			if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
			    buf_align !=
			    ROUNDDOWN_POWER2(buf_align, buf_align)) {
				UNLOCK(&pool->lock);
				return ODP_POOL_INVALID;
			}

			/* Set correct alignment based on input request */
			if (buf_align == 0)
				buf_align = ODP_CACHE_LINE_SIZE;
			else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
				buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

			if (params->buf.align != 0)
				blk_size = ROUNDUP_ALIGN(blk_size,
							 buf_align);

			hdr_size = sizeof(odp_buffer_hdr_t);
			CHECK_U16_OVERFLOW(blk_size);
			mbp_ctor_arg.mbuf_data_room_size = blk_size;
			num = params->buf.num;
			event_type = ODP_EVENT_BUFFER;

			ODP_DBG("type: buffer, name: %s, num: %u, size: %u, align: %u\n",
				pool_name, num, params->buf.size, params->buf.align);
			break;
		case ODP_POOL_PACKET:
			headroom = CONFIG_PACKET_HEADROOM;
			tailroom = CONFIG_PACKET_TAILROOM;
			min_seg_len = CONFIG_PACKET_SEG_LEN_MIN;
			min_align = ODP_CONFIG_BUFFER_ALIGN_MIN;
			cache_size = params->pkt.cache_size;

			blk_size = min_seg_len;
			if (params->pkt.seg_len > blk_size)
				blk_size = params->pkt.seg_len;
			if (params->pkt.len > blk_size)
				blk_size = params->pkt.len;
			/* Make sure at least one max len packet fits in the
			 * pool.
			 */
			max_len = 0;
			if (params->pkt.max_len != 0)
				max_len = params->pkt.max_len;
			if ((max_len + blk_size) / blk_size > params->pkt.num)
				blk_size = (max_len + params->pkt.num) /
					params->pkt.num;
			blk_size = ROUNDUP_ALIGN(headroom + blk_size +
						 tailroom, min_align);
			/* Segment size minus headroom might be rounded down by
			 * the driver to the nearest multiple of 1024. Round it
			 * up here to make sure the requested size still going
			 * to fit there without segmentation.
			 */
			blk_size = ROUNDUP_ALIGN(blk_size - headroom,
						 min_seg_len) + headroom;

			hdr_size = sizeof(odp_packet_hdr_t) +
				   params->pkt.uarea_size;
			mb_ctor_arg.pkt_uarea_size = params->pkt.uarea_size;
			CHECK_U16_OVERFLOW(blk_size);
			mbp_ctor_arg.mbuf_data_room_size = blk_size;
			num = params->pkt.num;
			event_type = ODP_EVENT_PACKET;

			ODP_DBG("type: packet, name: %s, num: %u, len: %u, blk_size: %u, "
				"uarea_size: %d, hdr_size: %d\n", pool_name, num, params->pkt.len,
				blk_size, params->pkt.uarea_size, hdr_size);
			break;
		case ODP_POOL_TIMEOUT:
			hdr_size = sizeof(odp_timeout_hdr_t);
			mbp_ctor_arg.mbuf_data_room_size = 0;
			num = params->tmo.num;
			cache_size = params->tmo.cache_size;
			event_type = ODP_EVENT_TIMEOUT;

			ODP_DBG("type: tmo, name: %s, num: %u\n", pool_name, num);
			break;
		case ODP_POOL_VECTOR:
			hdr_size = sizeof(odp_event_vector_hdr_t) +
					(params->vector.max_size * sizeof(odp_packet_t));
			mbp_ctor_arg.mbuf_data_room_size = 0;
			num = params->vector.num;
			cache_size = params->vector.cache_size;
			event_type = ODP_EVENT_PACKET_VECTOR;

			ODP_DBG("type: vector, name: %s, num: %u\n", pool_name, num);
			break;
		default:
			ODP_ERR("Bad type %i\n",
				params->type);
			UNLOCK(&pool->lock);
			return ODP_POOL_INVALID;
		}

		mb_ctor_arg.seg_buf_offset =
			(uint16_t)ROUNDUP_CACHE_LINE(hdr_size);
		mb_ctor_arg.seg_buf_size = mbp_ctor_arg.mbuf_data_room_size;
		mb_ctor_arg.type = params->type;
		mb_ctor_arg.event_type = event_type;
		mb_size = mb_ctor_arg.seg_buf_offset + mb_ctor_arg.seg_buf_size;
		mb_ctor_arg.pool = pool;
		mbp_ctor_arg.mbuf_priv_size = mb_ctor_arg.seg_buf_offset -
			sizeof(struct rte_mbuf);

		ODP_DBG("Metadata size: %u, mb_size %d\n",
			mb_ctor_arg.seg_buf_offset, mb_size);

		cache_size = calc_cache_size(num, cache_size);

		format_pool_name(pool_name, rte_name);

		if (params->type == ODP_POOL_PACKET) {
			uint16_t data_room_size, priv_size;

			data_room_size  = mbp_ctor_arg.mbuf_data_room_size;
			priv_size = mbp_ctor_arg.mbuf_priv_size;
			mp = rte_pktmbuf_pool_create(rte_name, num, cache_size,
						     priv_size, data_room_size,
						     rte_socket_id());
			pool->seg_len = data_room_size;
		} else {
			unsigned int priv_size;

			priv_size = sizeof(struct rte_pktmbuf_pool_private);
			mp = rte_mempool_create(rte_name, num, mb_size,
						cache_size, priv_size,
						rte_pktmbuf_pool_init,
						&mbp_ctor_arg, NULL, NULL,
						rte_socket_id(), 0);
		}
		if (mp == NULL) {
			ODP_ERR("Cannot init DPDK mbuf pool: %s\n",
				rte_strerror(rte_errno));
			UNLOCK(&pool->lock);
			return ODP_POOL_INVALID;
		}

		/* Initialize pool objects */
		rte_mempool_obj_iter(mp, odp_dpdk_mbuf_ctor, &mb_ctor_arg);

		if (name == NULL) {
			pool->name[0] = 0;
		} else {
			strncpy(pool->name, name,
				ODP_POOL_NAME_LEN - 1);
			pool->name[ODP_POOL_NAME_LEN - 1] = 0;
		}

		pool->rte_mempool = mp;
		pool->params = *params;
		ODP_DBG("Header/element/trailer size: %u/%u/%u, "
			"total pool size: %lu\n",
			mp->header_size, mp->elt_size, mp->trailer_size,
			(unsigned long)((mp->header_size + mp->elt_size +
			mp->trailer_size) * num));
		UNLOCK(&pool->lock);
		pool_hdl = pool->pool_hdl;
		break;
	}

	return pool_hdl;
}

odp_pool_t odp_pool_lookup(const char *name)
{
	uint32_t i;
	pool_t *pool;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool = pool_entry(i);

		LOCK(&pool->lock);
		if (strcmp(name, pool->name) == 0) {
			/* Found it */
			UNLOCK(&pool->lock);
			return pool->pool_hdl;
		}
		UNLOCK(&pool->lock);
	}

	return ODP_POOL_INVALID;
}

static inline int buffer_alloc_multi(pool_t *pool, odp_buffer_hdr_t *buf_hdr[],
				     int num)
{
	int i;
	struct rte_mempool *mp = pool->rte_mempool;

	ODP_ASSERT(pool->params.type == ODP_POOL_BUFFER ||
		   pool->params.type == ODP_POOL_TIMEOUT ||
		   pool->params.type == ODP_POOL_VECTOR);

	for (i = 0; i < num; i++) {
		struct rte_mbuf *mbuf;

		mbuf = rte_mbuf_raw_alloc(mp);
		if (odp_unlikely(mbuf == NULL))
			return i;

		buf_hdr[i] = mbuf_to_buf_hdr(mbuf);
	}

	return i;
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	odp_buffer_t buf;
	pool_t *pool;
	int ret;

	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	pool = pool_entry_from_hdl(pool_hdl);
	ret  = buffer_alloc_multi(pool, (odp_buffer_hdr_t **)&buf, 1);

	if (odp_likely(ret == 1))
		return buf;

	return ODP_BUFFER_INVALID;
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num)
{
	pool_t *pool;

	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	pool = pool_entry_from_hdl(pool_hdl);

	return buffer_alloc_multi(pool, (odp_buffer_hdr_t **)buf, num);
}

void odp_buffer_free(odp_buffer_t buf)
{
	rte_mbuf_raw_free(buf_to_mbuf(buf));
}

void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	buffer_free_multi((odp_buffer_hdr_t **)(uintptr_t)buf, num);
}

void odp_pool_print(odp_pool_t pool_hdl)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);

	rte_mempool_dump(stdout, pool->rte_mempool);
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	pool_t *pool = pool_entry_from_hdl(pool_hdl);
	struct rte_mempool_memhdr *hdr;

	if (pool == NULL || info == NULL)
		return -1;

	info->name = pool->name;
	info->params = pool->params;

	if (pool->params.type == ODP_POOL_PACKET)
		info->pkt.max_num = pool->rte_mempool->size;

	hdr = STAILQ_FIRST(&pool->rte_mempool->mem_list);
	info->min_data_addr = (uintptr_t)hdr->addr;
	info->max_data_addr = (uintptr_t)hdr->addr + hdr->len - 1;

	return 0;
}

int odp_pool_destroy(odp_pool_t pool_hdl)
{
	pool_t *pool;

	if (pool_hdl == ODP_POOL_INVALID) {
		ODP_ERR("Invalid pool handle\n");
		return -1;
	}

	pool = pool_entry_from_hdl(pool_hdl);
	if (pool->rte_mempool == NULL) {
		ODP_ERR("No rte_mempool handle available\n");
		return -1;
	}

	rte_mempool_free(pool->rte_mempool);
	pool->rte_mempool = NULL;

	return 0;
}

odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	pool_t *pool = buf_hdl_to_hdr(buf)->pool_ptr;

	return pool->pool_hdl;
}

void odp_pool_param_init(odp_pool_param_t *params)
{
	memset(params, 0, sizeof(odp_pool_param_t));
	params->pkt.headroom = CONFIG_PACKET_HEADROOM;
	params->buf.cache_size = RTE_MEMPOOL_CACHE_MAX_SIZE;
	params->pkt.cache_size = RTE_MEMPOOL_CACHE_MAX_SIZE;
	params->tmo.cache_size = RTE_MEMPOOL_CACHE_MAX_SIZE;
	params->vector.cache_size = RTE_MEMPOOL_CACHE_MAX_SIZE;
}

uint64_t odp_pool_to_u64(odp_pool_t hdl)
{
	return _odp_pri(hdl);
}
