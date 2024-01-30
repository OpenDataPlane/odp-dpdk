/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp/api/dma.h>
#include <odp/api/hints.h>

#include <odp/api/plat/strong_types.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <rte_version.h>

#if RTE_VERSION >= RTE_VERSION_NUM(21, 11, 0, 0)

#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/shared_memory.h>
#include <odp/api/stash.h>
#include <odp/api/ticketlock.h>

#include <odp_global_data.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_if.h>
#include <odp_schedule_if.h>

#include <rte_dmadev.h>
#include <rte_mbuf_core.h>
#include <rte_memory.h>

#include <sys/queue.h>

#include <stdio.h>
#include <string.h>

#define MAX_SESSIONS CONFIG_MAX_DMA_SESSIONS
#define CONF_BASE_STR "dma"
#define CONF_SEG_LEN "max_seg_len"
#define CONF_INFLIGHT "max_inflight"
#define MAX_SEG_LEN UINT16_MAX
#define MAX_TRANSFERS 256U
#define DEF_VCHAN 0U
#define MAX_DEQ 32U
#define LOCK_IF(cond, lock) \
	do { \
		if ((cond)) \
			odp_ticketlock_lock((lock)); \
	} while (0)
#define UNLOCK_IF(cond, lock) \
	do { \
		if ((cond)) \
			odp_ticketlock_unlock((lock)); \
	} while (0)

ODP_STATIC_ASSERT(MAX_TRANSFERS <= UINT16_MAX + 1U, "Too many inflight transfers");
ODP_STATIC_ASSERT(MAX_DEQ <= UINT8_MAX, "Too large dequeue burst");

typedef struct {
	struct rte_dma_info dev;
	uint32_t num_devices;
	uint32_t max_seg_len;
	uint32_t max_transfers;
} dev_info_t;

typedef int32_t (*trs_fn_t)(int16_t dev_id, const odp_dma_transfer_param_t *trs_param);

typedef struct transfer_s {
	TAILQ_ENTRY(transfer_s) q;

	void *user_ptr;
	odp_event_t ev;
	odp_queue_t queue;
	uint16_t idx;
	int8_t status;
	uint8_t is_m_none;
} transfer_t;

typedef struct ODP_ALIGNED_CACHE {
	TAILQ_HEAD(transfers_s, transfer_s) infl_trs;

	odp_ticketlock_t lock;
	odp_stash_t trs_stash;
	trs_fn_t trs_fn;
	odp_dma_param_t dma_param;
	int32_t latest_idx;
	int16_t dev_id;
	uint8_t max_deq;
	uint8_t is_mt;
	uint8_t is_active;
	transfer_t trs[MAX_TRANSFERS];
	transfer_t *trs_map[UINT16_MAX + 1U];
	char name[ODP_DMA_NAME_LEN];
} dma_session_t;

typedef struct {
	odp_shm_t shm;
	/* Buffer pool capability and default parameters */
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;
	dev_info_t dev_info;
	dma_session_t sessions[MAX_SESSIONS];
} dma_global_t;

static dma_global_t *_odp_dma_glb;

static odp_bool_t is_matching_capa(const struct rte_dma_info *first,
				   const struct rte_dma_info *second)
{
	return first->dev_capa == second->dev_capa &&
	       first->max_vchans == second->max_vchans &&
	       first->max_desc == second->max_desc &&
	       first->min_desc == second->min_desc &&
	       first->max_sges == second->max_sges;
}

static odp_bool_t parse_options(dev_info_t *dev_info)
{
	/* No way to reliably get supported maximum segment length or maximum number of inflight
	 * transfers via RTE capabilities, so use config file values. */
	int val;

	if (!_odp_libconfig_lookup_ext_int(CONF_BASE_STR, NULL, CONF_SEG_LEN, &val)) {
		_ODP_ERR("Unable to parse " CONF_SEG_LEN " configuration\n");
		return false;
	}

	dev_info->max_seg_len = val;

	if (!_odp_libconfig_lookup_ext_int(CONF_BASE_STR, NULL, CONF_INFLIGHT, &val)) {
		_ODP_ERR("Unable to parse " CONF_INFLIGHT " configuration\n");
		return false;
	}

	dev_info->max_transfers = val;
	_ODP_DBG("DMA device: (%s):\n", dev_info->dev.dev_name);
	_ODP_DBG("  max_seg_len:   %u\n", dev_info->max_seg_len);
	_ODP_DBG("  max_transfers: %u\n", dev_info->max_transfers);

	return true;
}

static odp_bool_t get_dma_dev_info(dma_global_t *config)
{
	uint32_t num_devices = 0U, max_transfers;
	int16_t id = 0;
	struct rte_dma_info dev_info;
	odp_bool_t is_dev_found = false;
	dma_session_t *session;

	memset(&dev_info, 0, sizeof(dev_info));

	while (true) {
		if (num_devices == MAX_SESSIONS)
			break;

		id = rte_dma_next_dev(id);

		if (id == -1)
			break;

		if (rte_dma_info_get(id, &dev_info) < 0)
			continue;

		/* Find matching devices based on the ones matching the first found one. */
		if (num_devices == 0U)
			config->dev_info.dev = dev_info;

		if (is_matching_capa(&config->dev_info.dev, &dev_info))
			is_dev_found = true;

		if (is_dev_found) {
			session = &config->sessions[num_devices];
			session->dev_id = id;
			++num_devices;
			is_dev_found = false;
		}

		id++;
	}

	/* Based on scatter-gather support, set to actual maximum for ease of use later. */
	config->dev_info.dev.max_sges = config->dev_info.dev.dev_capa & RTE_DMA_CAPA_OPS_COPY_SG ?
						config->dev_info.dev.max_sges : 1U;
	config->dev_info.num_devices = num_devices;

	if (!parse_options(&config->dev_info))
		return false;

	max_transfers = _ODP_MIN(config->dev_info.dev.max_desc, MAX_TRANSFERS);
	max_transfers = _ODP_MIN(config->dev_info.max_transfers, max_transfers);
	config->dev_info.max_transfers = max_transfers;

	return true;
}

int _odp_dma_init_global(void)
{
	odp_shm_t shm;

	if (odp_global_ro.disable.dma) {
		_ODP_PRINT("DMA is DISABLED\n");
		return 0;
	}

	shm = odp_shm_reserve("_odp_dma_global", sizeof(dma_global_t), ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		_ODP_ERR("SHM reserve failed\n");
		return -1;
	}

	_odp_dma_glb = odp_shm_addr(shm);

	if (_odp_dma_glb == NULL) {
		_ODP_ERR("SHM address resolution failed\n");
		return -1;
	}

	memset(_odp_dma_glb, 0, sizeof(dma_global_t));
	_odp_dma_glb->shm = shm;
	odp_pool_param_init(&_odp_dma_glb->pool_param);

	if (odp_pool_capability(&_odp_dma_glb->pool_capa)) {
		_ODP_ERR("Pool capability failed\n");
		return -1;
	}

	for (int i = 0; i < MAX_SESSIONS; i++)
		odp_ticketlock_init(&_odp_dma_glb->sessions[i].lock);

	if (!get_dma_dev_info(_odp_dma_glb)) {
		_ODP_ERR("Device info parsing failed\n");
		return -1;
	}

	return 0;
}

int _odp_dma_term_global(void)
{
	if (odp_global_ro.disable.dma || _odp_dma_glb == NULL)
		return 0;

	for (uint32_t i = 0U; i < _odp_dma_glb->dev_info.num_devices; ++i)
		(void)rte_dma_close(_odp_dma_glb->sessions[i].dev_id);

	if (odp_shm_free(_odp_dma_glb->shm)) {
		_ODP_ERR("SHM free failed\n");
		return -1;
	}

	return 0;
}

int odp_dma_capability(odp_dma_capability_t *capa)
{
	_ODP_ASSERT(capa != NULL);

	memset(capa, 0, sizeof(*capa));

	if (odp_global_ro.disable.dma) {
		_ODP_ERR("DMA is disabled\n");
		return -1;
	}

	if ((_odp_dma_glb->dev_info.dev.dev_capa & RTE_DMA_CAPA_MEM_TO_MEM) == 0U ||
	    ((_odp_dma_glb->dev_info.dev.dev_capa & RTE_DMA_CAPA_OPS_COPY) == 0U &&
	     (_odp_dma_glb->dev_info.dev.dev_capa & RTE_DMA_CAPA_OPS_COPY_SG) == 0U))
		return 0;

	capa->max_sessions = _odp_dma_glb->dev_info.num_devices;
	capa->max_transfers = _odp_dma_glb->dev_info.max_transfers;
	capa->max_src_segs = _odp_dma_glb->dev_info.dev.max_sges;
	capa->max_dst_segs = _odp_dma_glb->dev_info.dev.max_sges;
	capa->max_segs = 2U * _odp_dma_glb->dev_info.dev.max_sges;
	capa->max_seg_len = _odp_dma_glb->dev_info.max_seg_len;
	capa->compl_mode_mask = ODP_DMA_COMPL_SYNC | ODP_DMA_COMPL_NONE | ODP_DMA_COMPL_POLL |
				ODP_DMA_COMPL_EVENT;
	capa->queue_type_sched = 1;
	capa->queue_type_plain = 1;
	capa->pool.max_pools = _odp_dma_glb->pool_capa.buf.max_pools;
	capa->pool.max_num = _odp_dma_glb->pool_capa.buf.max_num;
	capa->pool.max_uarea_size = _odp_dma_glb->pool_capa.buf.max_uarea_size;
	capa->pool.uarea_persistence = _odp_dma_glb->pool_capa.buf.uarea_persistence;
	capa->pool.min_cache_size = _odp_dma_glb->pool_capa.buf.min_cache_size;
	capa->pool.max_cache_size = _odp_dma_glb->pool_capa.buf.max_cache_size;

	return 0;
}

void odp_dma_param_init(odp_dma_param_t *param)
{
	_ODP_ASSERT(param != NULL);

	memset(param, 0, sizeof(*param));
	param->direction = ODP_DMA_MAIN_TO_MAIN;
	param->type = ODP_DMA_TYPE_COPY;
	param->mt_mode = ODP_DMA_MT_SAFE;
	param->order = ODP_DMA_ORDER_NONE;
}

static odp_stash_t create_trs_stash(transfer_t trs[], odp_stash_op_mode_t mode, uint32_t num)
{
	odp_stash_param_t stash_param;
	odp_stash_t stash;
	uint32_t i;
	uintptr_t tmp;
	int32_t ret = 0;

	odp_stash_param_init(&stash_param);
	stash_param.put_mode = mode;
	stash_param.get_mode = mode;
	stash_param.num_obj = num;
	stash_param.obj_size = sizeof(uintptr_t);
	stash_param.cache_size = 0;
	stash = odp_stash_create("_odp_dma_transfer_id", &stash_param);

	if (stash == ODP_STASH_INVALID) {
		_ODP_ERR("Stash create failed\n");
		return ODP_STASH_INVALID;
	}

	for (i = 0U; i < num; ++i) {
		tmp = (uintptr_t)&trs[i];
		ret = odp_stash_put_ptr(stash, &tmp, 1);

		if (ret != 1) {
			_ODP_ERR("Stash put failed: %d\n", ret);
			break;
		}
	}

	if (ret != 1) {
		for (uint32_t j = 0; j < i; ++j) {
			if (odp_stash_get_ptr(stash, &tmp, 1) != 1) {
				_ODP_ERR("Stash get failed: %d\n", j);
				break;
			}
		}

		if (odp_stash_destroy(stash))
			_ODP_ERR("Stash destroy failed\n");

		return ODP_STASH_INVALID;
	}

	return stash;
}

static odp_bool_t configure_dma_dev(uint32_t dev_id, uint16_t num_desc)
{
	const struct rte_dma_conf dev_config = {
		.nb_vchans = 1 };
	int ret;
	const struct rte_dma_vchan_conf qconf = {
		.direction = RTE_DMA_DIR_MEM_TO_MEM,
		.nb_desc = num_desc };

	ret = rte_dma_configure(dev_id, &dev_config);

	if (ret < 0) {
		_ODP_ERR("DMA device configuration failed for ID %u: %d\n", dev_id, ret);
		return false;
	}

	ret = rte_dma_vchan_setup(dev_id, DEF_VCHAN, &qconf);

	if (ret < 0) {
		_ODP_ERR("DMA device vchannel setup failed for ID %u: %d\n", dev_id, ret);
		return false;
	}

	ret = rte_dma_start(dev_id);

	if (ret < 0) {
		_ODP_ERR("DMA device start failed for ID %u: %d\n", dev_id, ret);
		return false;
	}

	return true;
}

static void destroy_trs_stash(odp_stash_t stash)
{
	uintptr_t tmp;
	int32_t num;

	while (true) {
		num = odp_stash_get_ptr(stash, &tmp, 1);

		if (num == 1)
			continue;

		if (num == 0)
			break;

		_ODP_ERR("Stash get failed: %d\n", num);
		break;
	}

	if (odp_stash_destroy(stash))
		_ODP_ERR("Stash destroy failed\n");
}

static inline rte_iova_t get_iova(odp_dma_data_format_t format, const odp_dma_seg_t *seg)
{
	if (format == ODP_DMA_FORMAT_ADDR)
		return rte_mem_virt2iova(seg->addr);

	return rte_pktmbuf_iova_offset(pkt_to_mbuf(seg->packet), seg->offset);
}

static int32_t enqueue_single_trs(int16_t dev_id, const odp_dma_transfer_param_t *trs_param)
{
	rte_iova_t src = get_iova(trs_param->src_format, trs_param->src_seg),
	dst = get_iova(trs_param->dst_format, trs_param->dst_seg);
	int32_t ret;

	ret = rte_dma_copy(dev_id, DEF_VCHAN, src, dst, trs_param->src_seg->len,
			   RTE_DMA_OP_FLAG_SUBMIT);

	if (odp_unlikely(ret < 0))
		return ret == -ENOSPC ? -1 : -2;

	return ret;
}

static inline void prepare_trs_sg_arr(odp_dma_data_format_t format, const odp_dma_seg_t segs[],
				      struct rte_dma_sge out_segs[], uint32_t num)
{
	struct rte_dma_sge *out_seg;
	const odp_dma_seg_t *seg;

	for (uint32_t i = 0U; i < num; ++i) {
		seg = &segs[i];
		out_seg = &out_segs[i];
		out_seg->addr = get_iova(format, seg);
		out_seg->length = seg->len;
	}
}

static int32_t enqueue_sg_trs(int16_t dev_id, const odp_dma_transfer_param_t *trs_param)
{
	const uint32_t num_src = trs_param->num_src, num_dst = trs_param->num_dst;
	struct rte_dma_sge src_segs[num_src], dst_segs[num_dst];
	int32_t ret;

	prepare_trs_sg_arr(trs_param->src_format, trs_param->src_seg, src_segs, num_src);
	prepare_trs_sg_arr(trs_param->dst_format, trs_param->dst_seg, dst_segs, num_dst);
	ret = rte_dma_copy_sg(dev_id, DEF_VCHAN, src_segs, dst_segs, num_src, num_dst,
			      RTE_DMA_OP_FLAG_SUBMIT);

	if (odp_unlikely(ret < 0))
		return ret == -ENOSPC ? -1 : -2;

	return ret;
}

odp_dma_t odp_dma_create(const char *name, const odp_dma_param_t *param)
{
	odp_dma_capability_t dma_capa;
	dma_session_t *temp, *session = NULL;

	_ODP_ASSERT(param != NULL);

	if (odp_global_ro.disable.dma) {
		_ODP_ERR("DMA is disabled\n");
		return ODP_DMA_INVALID;
	}

	if ((param->direction != ODP_DMA_MAIN_TO_MAIN) || (param->type != ODP_DMA_TYPE_COPY)) {
		_ODP_ERR("Bad DMA parameter\n");
		return ODP_DMA_INVALID;
	}

	if (param->compl_mode_mask == 0) {
		_ODP_ERR("Empty compl mode mask\n");
		return ODP_DMA_INVALID;
	}

	if (odp_dma_capability(&dma_capa) < 0) {
		_ODP_ERR("DMA capa failed\n");
		return ODP_DMA_INVALID;
	}

	if (param->compl_mode_mask & ~dma_capa.compl_mode_mask) {
		_ODP_ERR("Compl mode not supported\n");
		return ODP_DMA_INVALID;
	}

	for (int i = 0; i < MAX_SESSIONS; i++) {
		temp = &_odp_dma_glb->sessions[i];

		if (temp->is_active)
			continue;

		odp_ticketlock_lock(&temp->lock);

		if (temp->is_active) {
			odp_ticketlock_unlock(&temp->lock);
			continue;
		}

		session = temp;
		session->is_active = 1;
		odp_ticketlock_unlock(&temp->lock);
		break;
	}

	if (session == NULL) {
		_ODP_ERR("Out of DMA sessions\n");
		return ODP_DMA_INVALID;
	}

	session->trs_stash = create_trs_stash(session->trs, param->mt_mode == ODP_DMA_MT_SAFE ?
								ODP_STASH_OP_MT : ODP_STASH_OP_ST,
					      _odp_dma_glb->dev_info.max_transfers);

	if (session->trs_stash == ODP_STASH_INVALID) {
		session->is_active = 0;
		return ODP_DMA_INVALID;
	}

	if (!configure_dma_dev(session->dev_id, _odp_dma_glb->dev_info.dev.max_desc)) {
		destroy_trs_stash(session->trs_stash);
		session->is_active = 0;
		return ODP_DMA_INVALID;
	}

	session->trs_fn = _odp_dma_glb->dev_info.dev.max_sges == 1U ?
				enqueue_single_trs : enqueue_sg_trs;
	session->dma_param = *param;
	TAILQ_INIT(&session->infl_trs);
	session->latest_idx = -1;
	session->max_deq = _ODP_MIN(MAX_DEQ, _odp_dma_glb->dev_info.max_transfers);
	session->is_mt = param->mt_mode == ODP_DMA_MT_SAFE;
	session->name[0] = 0;

	if (name) {
		strncpy(session->name, name, ODP_DMA_NAME_LEN - 1);
		session->name[ODP_DMA_NAME_LEN - 1] = 0;
	}

	return (odp_dma_t)session;
}

static inline dma_session_t *dma_session_from_handle(odp_dma_t dma)
{
	return (dma_session_t *)(uintptr_t)dma;
}

int odp_dma_destroy(odp_dma_t dma)
{
	dma_session_t *session = dma_session_from_handle(dma);

	_ODP_ASSERT(dma != ODP_DMA_INVALID);

	odp_ticketlock_lock(&session->lock);

	if (session->is_active == 0) {
		_ODP_ERR("Session not created\n");
		odp_ticketlock_unlock(&session->lock);
		return -1;
	}

	(void)rte_dma_stop(session->dev_id);
	destroy_trs_stash(session->trs_stash);
	session->is_active = 0;
	odp_ticketlock_unlock(&session->lock);

	return 0;
}

odp_dma_t odp_dma_lookup(const char *name)
{
	dma_session_t *session;

	for (int i = 0; i < MAX_SESSIONS; i++) {
		session = &_odp_dma_glb->sessions[i];
		odp_ticketlock_lock(&session->lock);

		if (session->is_active == 0) {
			odp_ticketlock_unlock(&session->lock);
			continue;
		}

		if (strcmp(session->name, name) == 0) {
			odp_ticketlock_unlock(&session->lock);
			return (odp_dma_t)session;
		}

		odp_ticketlock_unlock(&session->lock);
	}

	return ODP_DMA_INVALID;
}

static uint32_t get_transfer_len(const odp_dma_transfer_param_t *trs_param)
{
	uint32_t src_len = 0, dst_len = 0;

	for (uint32_t i = 0U; i < trs_param->num_src; ++i)
		src_len += trs_param->src_seg[i].len;

	for (uint32_t i = 0U; i < trs_param->num_dst; ++i)
		dst_len += trs_param->dst_seg[i].len;

	if (src_len != dst_len)
		return 0U;

	return src_len;
}

static inline void dequeue_trs(dma_session_t *session)
{
	const uint16_t dev_id = session->dev_id;
	uint16_t num_deq = 0U, done_idx, real_idx;
	bool has_error = false, is_op_error;
	const uint8_t max_deq = session->max_deq;
	enum rte_dma_status_code status[max_deq];
	int32_t *latest_idx = &session->latest_idx;

	num_deq = rte_dma_completed(dev_id, DEF_VCHAN, max_deq, &done_idx, &has_error);

	if (odp_unlikely(has_error))
		num_deq = rte_dma_completed_status(dev_id, DEF_VCHAN, num_deq, &done_idx, status);

	for (uint16_t i = 0U; i < num_deq; ++i) {
		is_op_error = false;
		real_idx = *latest_idx + 1U + i;

		if (odp_unlikely(has_error && status[i] != RTE_DMA_STATUS_SUCCESSFUL)) {
			is_op_error = true;
			_ODP_DBG("Transfer failed, index: %u, status: %d\n", real_idx, status[i]);
		}

		session->trs_map[real_idx]->status = is_op_error ? -1 : 1;
	}

	if (num_deq)
		*latest_idx = done_idx;
}

static inline transfer_t *trs_from_id(odp_dma_transfer_id_t id)
{
	return (transfer_t *)(uintptr_t)id;
}

int odp_dma_transfer(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param,
		     odp_dma_result_t *result)
{
	dma_session_t *session = dma_session_from_handle(dma);
	odp_dma_transfer_id_t id;
	int32_t idx;
	transfer_t *trs;

	_ODP_ASSERT(dma != ODP_DMA_INVALID);
	_ODP_ASSERT(trs_param != NULL);
	_ODP_ASSERT(session->is_active > 0U);
	_ODP_ASSERT(trs_param->num_src > 0U ||
		    trs_param->num_src <= _odp_dma_glb->dev_info.dev.max_sges);
	_ODP_ASSERT(trs_param->num_dst > 0U ||
		    trs_param->num_dst <= _odp_dma_glb->dev_info.dev.max_sges);
	_ODP_ASSERT(get_transfer_len(trs_param) != 0U);

	id = odp_dma_transfer_id_alloc(dma);

	if (odp_unlikely(id == ODP_DMA_TRANSFER_ID_INVALID))
		return 0;

	LOCK_IF(session->is_mt, &session->lock);
	idx = session->trs_fn(session->dev_id, trs_param);
	UNLOCK_IF(session->is_mt, &session->lock);

	if (odp_unlikely(idx < 0)) {
		odp_dma_transfer_id_free(dma, id);
		return idx == -1 ? 0 : -1;
	}

	trs = trs_from_id(id);
	trs->status = 0;
	session->trs_map[idx] = trs;
	LOCK_IF(session->is_mt, &session->lock);

	while (trs->status == 0)
		dequeue_trs(session);

	UNLOCK_IF(session->is_mt, &session->lock);

	if (result)
		result->success = trs->status == 1;

	odp_dma_transfer_id_free(dma, id);

	return trs->status == 1 ? 1 : -1;
}

int odp_dma_transfer_multi(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param[],
			   odp_dma_result_t *result[], int num)
{
	int i;
	odp_dma_result_t *res = NULL;
	int ret = -1;

	_ODP_ASSERT(num > 0);

	for (i = 0; i < num; i++) {
		if (result)
			res = result[i];

		ret = odp_dma_transfer(dma, trs_param[i], res);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

static inline void free_ord_entry(struct transfers_s *head, transfer_t *entry,
				  dma_session_t *session)
{
	TAILQ_REMOVE(head, entry, q);
	odp_dma_transfer_id_free((odp_dma_t)session, (odp_dma_transfer_id_t)(uintptr_t)entry);
}

static int get_ordered_evs(dma_session_t *session, odp_queue_t queue, _odp_event_hdr_t **ev_hdr,
			   int num)
{
	transfer_t *e;
	int num_evs = 0;
	odp_dma_result_t *res;

	TAILQ_FOREACH(e, &session->infl_trs, q) {
		if (session->dma_param.order != ODP_DMA_ORDER_NONE && e->queue != queue &&
		    e->status == 0)
			break;

		if (e->is_m_none && e->status != 0) {
			free_ord_entry(&session->infl_trs, e, session);
			continue;
		}

		if (e->queue != queue || e->status == 0)
			continue;

		if (num - num_evs) {
			res = odp_buffer_addr((odp_buffer_t)(uintptr_t)e->ev);
			res->success = e->status == 1;
			res->user_ptr = e->user_ptr;
			ev_hdr[num_evs++] = _odp_event_hdr(e->ev);
			free_ord_entry(&session->infl_trs, e, session);
		} else {
			break;
		}
	}

	return num_evs;
}

static int dequeue_evs(dma_session_t *session, odp_queue_t queue, _odp_event_hdr_t **event_hdr,
		       int num)
{
	int num_deq = 0;

	if (odp_ticketlock_trylock(&session->lock) == 0)
		return num_deq;

	dequeue_trs(session);
	num_deq = get_ordered_evs(session, queue, event_hdr, num);
	odp_ticketlock_unlock(&session->lock);

	return num_deq;
}

int odp_dma_transfer_start(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param,
			   const odp_dma_compl_param_t *compl_param)
{
	dma_session_t *session = dma_session_from_handle(dma);
	odp_dma_transfer_id_t id = ODP_DMA_TRANSFER_ID_INVALID;
	int32_t idx;
	transfer_t *trs;

	_ODP_ASSERT(dma != ODP_DMA_INVALID);
	_ODP_ASSERT(trs_param != NULL);
	_ODP_ASSERT(compl_param != NULL);
	_ODP_ASSERT(session->is_active > 0U);
	_ODP_ASSERT(trs_param->num_src > 0U ||
		    trs_param->num_src <= _odp_dma_glb->dev_info.dev.max_sges);
	_ODP_ASSERT(trs_param->num_dst > 0U ||
		    trs_param->num_dst <= _odp_dma_glb->dev_info.dev.max_sges);
	_ODP_ASSERT(get_transfer_len(trs_param) != 0U);

	if (compl_param->compl_mode != ODP_DMA_COMPL_POLL) {
		id = odp_dma_transfer_id_alloc(dma);

		if (odp_unlikely(id == ODP_DMA_TRANSFER_ID_INVALID))
			return 0;
	}

	LOCK_IF(session->is_mt, &session->lock);
	idx = session->trs_fn(session->dev_id, trs_param);

	if (odp_unlikely(idx < 0)) {
		if (compl_param->compl_mode != ODP_DMA_COMPL_POLL)
			odp_dma_transfer_id_free(dma, id);

		UNLOCK_IF(session->is_mt, &session->lock);
		return idx == -1 ? 0 : -1;
	}

	if (compl_param->compl_mode == ODP_DMA_COMPL_POLL) {
		_ODP_ASSERT(compl_param->transfer_id != ODP_DMA_TRANSFER_ID_INVALID);

		trs = trs_from_id(compl_param->transfer_id);
		trs->ev = ODP_EVENT_INVALID;
		trs->queue = ODP_QUEUE_INVALID;
	} else {
		trs = trs_from_id(id);
		trs->ev = ODP_EVENT_INVALID;
		trs->queue = ODP_QUEUE_INVALID;

		if (compl_param->compl_mode == ODP_DMA_COMPL_EVENT) {
			_ODP_ASSERT(compl_param->event != ODP_EVENT_INVALID);
			_ODP_ASSERT(compl_param->queue != ODP_QUEUE_INVALID);

			trs->ev = compl_param->event;
			trs->queue = compl_param->queue;
		}
	}

	trs->user_ptr = compl_param->user_ptr;
	trs->idx = idx;
	trs->status = 0;
	trs->is_m_none = compl_param->compl_mode == ODP_DMA_COMPL_NONE;
	TAILQ_INSERT_TAIL(&session->infl_trs, trs, q);
	session->trs_map[idx] = trs;
	UNLOCK_IF(session->is_mt, &session->lock);

	/* TODO: Remove the following section once proper DMA-dequeue support in scheduling. */
	if (compl_param->compl_mode == ODP_DMA_COMPL_EVENT) {
		_odp_event_hdr_t *event_hdr = NULL;
		int ret;

		do {
			ret = dequeue_evs(session, compl_param->queue, &event_hdr, 1);
		} while (ret < 1);

		if (odp_unlikely(odp_queue_enq(compl_param->queue, (odp_event_t)event_hdr) < 0))
			_ODP_ABORT("Completion event enqueue failed\n");
	}

	return 1;
}

int odp_dma_transfer_start_multi(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param[],
				 const odp_dma_compl_param_t *compl_param[], int num)
{
	int i;
	int ret = -1;

	_ODP_ASSERT(num > 0);

	for (i = 0; i < num; i++) {
		ret = odp_dma_transfer_start(dma, trs_param[i], compl_param[i]);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

static int8_t get_ordered_polled(dma_session_t *session, const transfer_t *trs)
{
	transfer_t *e;
	int8_t status = -1;

	TAILQ_FOREACH(e, &session->infl_trs, q) {
		if (session->dma_param.order != ODP_DMA_ORDER_NONE && e != trs &&
		    e->status == 0) {
			status = 0;
			break;
		}

		if (e->is_m_none && e->status != 0) {
			free_ord_entry(&session->infl_trs, e, session);
			continue;
		}

		if (e != trs)
			continue;

		status = e->status;

		if (status != 0)
			TAILQ_REMOVE(&session->infl_trs, e, q);

		break;
	}

	return status;
}

int odp_dma_transfer_done(odp_dma_t dma, odp_dma_transfer_id_t transfer_id,
			  odp_dma_result_t *result)
{
	dma_session_t *session = dma_session_from_handle(dma);
	transfer_t *trs = trs_from_id(transfer_id);
	int8_t status;

	_ODP_ASSERT(dma != ODP_DMA_INVALID);
	_ODP_ASSERT(transfer_id != ODP_DMA_TRANSFER_ID_INVALID);

	LOCK_IF(session->is_mt, &session->lock);

	if (!trs->status)
		dequeue_trs(session);

	status = get_ordered_polled(session, trs);
	UNLOCK_IF(session->is_mt, &session->lock);

	if (result) {
		result->success = status == 1;
		result->user_ptr = trs->user_ptr;
	}

	return status;
}

odp_dma_transfer_id_t odp_dma_transfer_id_alloc(odp_dma_t dma)
{
	dma_session_t *session = dma_session_from_handle(dma);
	uintptr_t trs;
	int32_t num;

	_ODP_ASSERT(dma != ODP_DMA_INVALID);

	num = odp_stash_get_ptr(session->trs_stash, &trs, 1);

	if (odp_unlikely(num != 1))
		return ODP_DMA_TRANSFER_ID_INVALID;

	return (odp_dma_transfer_id_t)trs;
}

void odp_dma_transfer_id_free(odp_dma_t dma, odp_dma_transfer_id_t transfer_id)
{
	dma_session_t *session = dma_session_from_handle(dma);
	uintptr_t trs = (uintptr_t)transfer_id;
	int32_t num;

	_ODP_ASSERT(dma != ODP_DMA_INVALID);
	_ODP_ASSERT(transfer_id != ODP_DMA_TRANSFER_ID_INVALID);

	num = odp_stash_put_ptr(session->trs_stash, &trs, 1);

	if (odp_unlikely(num != 1))
		_ODP_ABORT("Stash put failed\n");
}

uint64_t odp_dma_to_u64(odp_dma_t dma)
{
	return _odp_pri(dma);
}

void odp_dma_print(odp_dma_t dma)
{
	const dma_session_t *session = dma_session_from_handle(dma);

	_ODP_ASSERT(dma != ODP_DMA_INVALID);

	_ODP_PRINT("\nDMA info\n");
	_ODP_PRINT("--------\n");
	_ODP_PRINT("  DMA handle      0x%" PRIx64 "\n", odp_dma_to_u64(dma));
	_ODP_PRINT("  name            %s\n", session->name);
	_ODP_PRINT("  device info:\n\n");
	(void)rte_dma_dump(session->dev_id, stdout);
	_ODP_PRINT("\n");
}

uint64_t odp_dma_compl_to_u64(odp_dma_compl_t dma_compl)
{
	return _odp_pri(dma_compl);
}

void odp_dma_compl_print(odp_dma_compl_t dma_compl)
{
	odp_dma_result_t result;
	int ret;

	_ODP_ASSERT(dma_compl != ODP_DMA_COMPL_INVALID);

	ret = odp_dma_compl_result(dma_compl, &result);
	_ODP_PRINT("\nDMA completion\n");
	_ODP_PRINT("--------------\n");
	_ODP_PRINT("  Compl event handle: 0x%" PRIx64 "\n", _odp_pri(dma_compl));

	if (ret == 0) {
		_ODP_PRINT("  Result:             %s\n", result.success ? "success" : "fail");
		_ODP_PRINT("  User pointer:       0x%" PRIx64 "\n", _odp_pri(result.user_ptr));
	} else {
		_ODP_PRINT("  No result metadata\n");
	}

	_ODP_PRINT("\n");
}

void odp_dma_pool_param_init(odp_dma_pool_param_t *pool_param)
{
	memset(pool_param, 0, sizeof(*pool_param));
	pool_param->cache_size = _odp_dma_glb->pool_param.buf.cache_size;
}

odp_pool_t odp_dma_pool_create(const char *name, const odp_dma_pool_param_t *pool_param)
{
	const uint32_t num = pool_param->num;
	const uint32_t uarea_size = pool_param->uarea_size;
	const uint32_t cache_size = pool_param->cache_size;
	odp_pool_param_t param;

	if (num > _odp_dma_glb->pool_capa.buf.max_num) {
		_ODP_ERR("Too many DMA completion events: %u\n", num);
		return ODP_POOL_INVALID;
	}

	if (uarea_size > _odp_dma_glb->pool_capa.buf.max_uarea_size) {
		_ODP_ERR("Bad uarea size: %u\n", uarea_size);
		return ODP_POOL_INVALID;
	}

	if (cache_size < _odp_dma_glb->pool_capa.buf.min_cache_size ||
	    cache_size > _odp_dma_glb->pool_capa.buf.max_cache_size) {
		_ODP_ERR("Bad cache size: %u\n", cache_size);
		return ODP_POOL_INVALID;
	}

	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.uarea_init.init_fn = pool_param->uarea_init.init_fn;
	param.uarea_init.args = pool_param->uarea_init.args;
	param.buf.num = num;
	param.buf.uarea_size = uarea_size;
	param.buf.cache_size = cache_size;
	param.buf.size = sizeof(odp_dma_result_t);

	return _odp_pool_create(name, &param, ODP_POOL_DMA_COMPL);
}

#else

int _odp_dma_init_global(void)
{
	return 0;
}

int _odp_dma_term_global(void)
{
	return 0;
}

int odp_dma_capability(odp_dma_capability_t *capa)
{
	_ODP_ASSERT(capa != NULL);

	memset(capa, 0, sizeof(*capa));

	return 0;
}

void odp_dma_param_init(odp_dma_param_t *param ODP_UNUSED)
{
}

odp_dma_t odp_dma_create(const char *name ODP_UNUSED, const odp_dma_param_t *param ODP_UNUSED)
{
	return ODP_DMA_INVALID;
}

int odp_dma_destroy(odp_dma_t dma ODP_UNUSED)
{
	return 0;
}

odp_dma_t odp_dma_lookup(const char *name ODP_UNUSED)
{
	return ODP_DMA_INVALID;
}

int odp_dma_transfer(odp_dma_t dma ODP_UNUSED,
		     const odp_dma_transfer_param_t *trs_param ODP_UNUSED,
		     odp_dma_result_t *result ODP_UNUSED)
{
	return -1;
}

int odp_dma_transfer_multi(odp_dma_t dma ODP_UNUSED,
			   const odp_dma_transfer_param_t *trs_param[] ODP_UNUSED,
			   odp_dma_result_t *result[] ODP_UNUSED, int num ODP_UNUSED)
{
	return -1;
}

int odp_dma_transfer_start(odp_dma_t dma ODP_UNUSED,
			   const odp_dma_transfer_param_t *trs_param ODP_UNUSED,
			   const odp_dma_compl_param_t *compl_param ODP_UNUSED)
{
	return -1;
}

int odp_dma_transfer_start_multi(odp_dma_t dma ODP_UNUSED,
				 const odp_dma_transfer_param_t *trs_param[] ODP_UNUSED,
				 const odp_dma_compl_param_t *compl_param[] ODP_UNUSED,
				 int num ODP_UNUSED)
{
	return -1;
}

int odp_dma_transfer_done(odp_dma_t dma ODP_UNUSED, odp_dma_transfer_id_t transfer_id ODP_UNUSED,
			  odp_dma_result_t *result ODP_UNUSED)
{
	return -1;
}

odp_dma_transfer_id_t odp_dma_transfer_id_alloc(odp_dma_t dma ODP_UNUSED)
{
	return ODP_DMA_TRANSFER_ID_INVALID;
}

void odp_dma_transfer_id_free(odp_dma_t dma ODP_UNUSED,
			      odp_dma_transfer_id_t transfer_id ODP_UNUSED)
{
}

uint64_t odp_dma_to_u64(odp_dma_t dma ODP_UNUSED)
{
	return _odp_pri(ODP_DMA_INVALID);
}

void odp_dma_print(odp_dma_t dma ODP_UNUSED)
{
}

uint64_t odp_dma_compl_to_u64(odp_dma_compl_t dma_compl ODP_UNUSED)
{
	return _odp_pri(ODP_DMA_COMPL_INVALID);
}

void odp_dma_compl_print(odp_dma_compl_t dma_compl ODP_UNUSED)
{
}

void odp_dma_pool_param_init(odp_dma_pool_param_t *pool_param ODP_UNUSED)
{
}

odp_pool_t odp_dma_pool_create(const char *name ODP_UNUSED,
			       const odp_dma_pool_param_t *pool_param ODP_UNUSED)
{
	return ODP_POOL_INVALID;
}

#endif
