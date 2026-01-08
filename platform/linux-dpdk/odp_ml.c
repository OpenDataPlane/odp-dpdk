/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023-2025 Nokia
 */

#include <odp/autoheader_external.h>

#include <odp/api/atomic.h>
#include <odp/api/buffer.h>
#include <odp/api/cpu.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/ml.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/stash.h>
#include <odp/api/std_types.h>
#include <odp/api/ticketlock.h>

#include <odp/api/plat/event_inline_types.h>
#include <odp/api/plat/strong_types.h>

#include <odp_buffer_internal.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_pool_internal.h>
#include <odp_string_internal.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_mldev.h>
#include <rte_errno.h>

#define ML_MAX_IO_SEGS UINT32_MAX
#define ML_MAX_COMPL_ID 32
#define ML_MAX_STR_LEN 64
#define ML_MAX_MODEL_SIZE (1024 * 1024 * 1024)
#define ML_MAX_MODELS_CREATED CONFIG_ML_MAX_MODELS
#define ML_MAX_MODELS_LOADED CONFIG_ML_MAX_MODELS
#define ML_MAX_ENGINES 1

/* Error codes */
enum {
	/* Feature not supported */
	ML_FEATURE_NOT_SUPPORTED = 1,

	/* Model is not created */
	ML_NOT_CREATED,

	/* Model was not loaded */
	ML_NOT_LOADED,

	/* Model has already loaded */
	ML_LOADED,

	/* Bad input */
	ML_BAD_INPUT,

	/* Fail from underlying library */
	ML_LIB_FAILED,

	/* Bad output */
	ML_BAD_OUTPUT,

	/* Bad handle */
	ML_BAD_HDL
};

/* Model info */
typedef struct ml_model_t {
	/* Guards state, which must be accessed atomically */
	odp_ticketlock_t	lock;

	enum {
		ML_STATE_FREE = 0, /* Not allocated */
		ML_STATE_CREATED, /* Model is created */
		ML_STATE_LOADED, /* Model is loaded */
		ML_STATE_INFERENCING, /* Model is inferencing */
	} state;

	struct {
		uint16_t id;
		struct rte_ml_model_info info;
		uint64_t inp_size;
		uint64_t out_size;
		struct rte_ml_buff_seg inp_seg;
		struct rte_ml_buff_seg *inp_seg_p;
		struct rte_ml_buff_seg out_seg;
		struct rte_ml_buff_seg *out_seg_p;
		const struct rte_memzone *inp_mz;
		const struct rte_memzone *out_mz;
	} rte;

	uint32_t		max_compl_id;

	odp_ml_model_info_t	info;
	odp_ml_input_info_t	input_info[CONFIG_ML_MAX_INPUTS];
	uint64_t		input_sizes[CONFIG_ML_MAX_INPUTS];
	odp_ml_output_info_t	output_info[CONFIG_ML_MAX_OUTPUTS];
	uint64_t		output_sizes[CONFIG_ML_MAX_OUTPUTS];

	struct {
		void *user_ptr;
	} result[ML_MAX_COMPL_ID + 1];
} ml_model_t;

typedef struct ml_conf_t {
	int			dev_id;
	int			num_queue_pairs;
} ml_conf_t;

typedef struct ml_global_t {
	odp_shm_t		shm;
	odp_ml_capability_t	capa;
	odp_ml_config_t		ml_config;
	odp_pool_param_t	pool_param;
	ml_conf_t		conf;
	odp_stash_t		qp_stash;
	struct {
		struct rte_ml_dev_info dev_info;
		struct rte_mempool *op_pool;
		struct rte_ml_dev_config conf;
	} rte;

	ml_model_t		models[ML_MAX_MODELS_CREATED];

} ml_global_t;

static ml_global_t *_odp_ml_glb;

static inline ml_model_t *ml_model_from_handle(odp_ml_model_t model)
{
	return (ml_model_t *)(uintptr_t)model;
}

int odp_ml_num_engines(void)
{
	if (odp_global_ro.disable.ml) {
		_ODP_PRINT("ML is disabled\n");
		return 0;
	}

	return ML_MAX_ENGINES;
}

int odp_ml_capability(odp_ml_capability_t *capa)
{
	odp_pool_capability_t pool_capa;

	memset(capa, 0, sizeof(odp_ml_capability_t));

	if (odp_global_ro.disable.ml) {
		_ODP_PRINT("ML is disabled\n");
		return 0;
	}

	if (_odp_ml_glb == NULL) {
		_ODP_PRINT("No ML devices\n");
		return 0;
	}

	const struct rte_ml_dev_info *info = &_odp_ml_glb->rte.dev_info;

	capa->max_model_size = ML_MAX_MODEL_SIZE;
	capa->max_models = _ODP_MIN(ML_MAX_MODELS_CREATED, info->max_models);
	capa->max_models_loaded = _ODP_MIN(ML_MAX_MODELS_LOADED, (int)capa->max_models);
	capa->max_compl_id = ML_MAX_COMPL_ID;
	capa->max_inputs = _ODP_MIN(CONFIG_ML_MAX_INPUTS, info->max_io);
	capa->max_outputs = _ODP_MIN(CONFIG_ML_MAX_OUTPUTS, info->max_io);
	capa->max_segs_per_input = ML_MAX_IO_SEGS;
	capa->max_segs_per_output = ML_MAX_IO_SEGS;
	capa->min_input_align = 1;
	capa->min_output_align = 1;

	capa->load.compl_mode_mask = ODP_ML_COMPL_MODE_SYNC |
				     ODP_ML_COMPL_MODE_POLL |
				     ODP_ML_COMPL_MODE_EVENT;
	capa->load.compl_queue_plain = 1;
	capa->load.compl_queue_sched = 1;

	capa->run.compl_mode_mask =  ODP_ML_COMPL_MODE_SYNC |
				     ODP_ML_COMPL_MODE_POLL |
				     ODP_ML_COMPL_MODE_EVENT;
	capa->run.compl_queue_plain = 1;
	capa->run.compl_queue_sched = 1;

	if (odp_pool_capability(&pool_capa)) {
		_ODP_ERR("Pool capability failed\n");
		return -1;
	}

	capa->pool.max_pools = pool_capa.buf.max_pools;
	capa->pool.max_num = pool_capa.buf.max_num;
	capa->pool.max_uarea_size = pool_capa.buf.max_uarea_size;
	capa->pool.uarea_persistence = pool_capa.buf.uarea_persistence;
	capa->pool.max_cache_size = pool_capa.buf.max_cache_size;
	capa->pool.min_cache_size = pool_capa.buf.min_cache_size;

	return 0;
}

int odp_ml_engine_capability(uint32_t engine_id, odp_ml_capability_t *capa)
{
	if (engine_id > ML_MAX_ENGINES) {
		_ODP_ERR("Engine ID %u exceeds maximum number of engines %d\n",
			 engine_id, ML_MAX_ENGINES);
		return -1;
	}

	return odp_ml_capability(capa);
}

void odp_ml_config_init(odp_ml_config_t *config)
{
	memset(config, 0, sizeof(odp_ml_config_t));
	config->engine_id = ODP_ML_ENGINE_ANY;
	config->max_models_created = 1;
	config->max_models_loaded = 1;
}

int odp_ml_config(const odp_ml_config_t *config)
{
	if (!config) {
		_ODP_ERR("Config must not be NULL\n");
		return -1;
	}

	if (config->engine_id > ML_MAX_ENGINES) {
		_ODP_ERR("Engine ID %u exceeds maximum number of engines %d\n",
			 config->engine_id, ML_MAX_ENGINES);
		return -1;
	}

	if (config->max_model_size == 0 || config->max_models_created == 0 ||
	    config->max_models_loaded == 0) {
		_ODP_ERR("max_model_size, max_models_created and max_models_loaded"
			 " must be bigger than 0\n");
		return -1;
	}

	if (config->max_models_loaded > config->max_models_created) {
		_ODP_ERR("max_models_loaded %d exceeds max_models_created %d\n",
			 config->max_models_loaded, config->max_models_created);
		return -1;
	}

	odp_ml_capability_t capa;

	if (odp_ml_capability(&capa) < 0)
		return -1;

	if (config->max_models_created > capa.max_models) {
		_ODP_ERR("max_models_created %d exceeds maximum number"
			 " of models that can be created in this driver %u\n",
			 config->max_models_created, capa.max_models);
		return -1;
	}

	if (config->max_models_loaded > capa.max_models_loaded) {
		_ODP_ERR("max_models_loaded %d exceeds maximum number"
			 " of models that can be loaded in this driver %u\n",
			 config->max_models_loaded, capa.max_models_loaded);
		return -1;
	}

	if (config->max_model_size > capa.max_model_size) {
		_ODP_ERR("max_model_size %" PRIu64
			 " exceeds supported maximum model size %" PRIu64 "\n",
			 config->max_model_size, capa.max_model_size);
		return -1;
	}

	_odp_ml_glb->ml_config = *config;
	if (_odp_ml_glb->ml_config.engine_id == ODP_ML_ENGINE_ANY)
		_odp_ml_glb->ml_config.engine_id = 1; /* Default to first engine */

	return 0;
}

void odp_ml_model_param_init(odp_ml_model_param_t *param)
{
	memset(param, 0, sizeof(odp_ml_model_param_t));
}

static odp_ml_data_type_t dtype_from_rte(enum rte_ml_io_type dtype)
{
	switch (dtype) {
	case RTE_ML_IO_TYPE_INT8:
		return ODP_ML_DATA_TYPE_INT8;
	case RTE_ML_IO_TYPE_UINT8:
		return ODP_ML_DATA_TYPE_UINT8;
	case RTE_ML_IO_TYPE_INT16:
		return ODP_ML_DATA_TYPE_INT16;
	case RTE_ML_IO_TYPE_UINT16:
		return ODP_ML_DATA_TYPE_UINT16;
	case RTE_ML_IO_TYPE_INT32:
		return ODP_ML_DATA_TYPE_INT32;
	case RTE_ML_IO_TYPE_UINT32:
		return ODP_ML_DATA_TYPE_UINT32;
	case RTE_ML_IO_TYPE_FP16:
		return ODP_ML_DATA_TYPE_FP16;
	case RTE_ML_IO_TYPE_FP32:
		return ODP_ML_DATA_TYPE_FP32;
	case RTE_ML_IO_TYPE_BFLOAT16:
		return ODP_ML_DATA_TYPE_BFP16;
	default:
		_ODP_ERR("datatype %d not supported by odp ml\n", dtype);
		return ODP_ML_DATA_TYPE_NONE;
	}
}

/* Get the size of given odp_ml_data_type_t in bytes */
static uint32_t size_of_odp_ml_data_type(odp_ml_data_type_t data_type)
{
	switch (data_type) {
	case ODP_ML_DATA_TYPE_NONE:
		return 0;

	case ODP_ML_DATA_TYPE_INT8:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT8:
		return 1;

	case ODP_ML_DATA_TYPE_INT16:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT16:
		/* Fall through */
	case ODP_ML_DATA_TYPE_FP16:
		/* Fall through */
	case ODP_ML_DATA_TYPE_BFP16:
		return 2;

	case ODP_ML_DATA_TYPE_INT24:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT24:
		return 3;

	case ODP_ML_DATA_TYPE_INT32:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT32:
		/* Fall through */
	case ODP_ML_DATA_TYPE_FP32:
		return 4;

	case ODP_ML_DATA_TYPE_INT64:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT64:
		/* Fall through */
	case ODP_ML_DATA_TYPE_FP64:
		return 8;

	default:
		return 0;
	}
}

static void calculate_model_io_size(const odp_ml_shape_info_t *shape, uint32_t datatype_size,
				    uint64_t *size)
{
	*size = datatype_size;

	for (size_t i = 0; i < shape->num_dim; i++) {
		if (shape->dim[i] == ODP_ML_DIM_DYNAMIC)
			continue;
		(*size) *= shape->dim[i];
	}
}

static int io_setup(ml_model_t *mdl)
{
	if (mdl->rte.info.io_layout != RTE_ML_IO_LAYOUT_PACKED) {
		_ODP_ERR("Model IO layout is not packed\n");
		return -1;
	}

	struct rte_ml_model_info *mi = &mdl->rte.info;
	uint64_t inp_size = 0, out_size = 0;

	for (uint32_t i = 0; i < mdl->rte.info.nb_inputs; i++) {
		uint64_t size = mi->input_info[i].size;

		if (mdl->input_info[i].shape.type == ODP_ML_SHAPE_BATCH)
			size = size / mi->min_batches * mi->max_batches;

		inp_size += size;
	}

	for (uint32_t i = 0; i < mdl->rte.info.nb_outputs; i++) {
		uint64_t size = mi->output_info[i].size;

		if (mdl->output_info[i].shape.type == ODP_ML_SHAPE_BATCH)
			size = size / mi->min_batches * mi->max_batches;

		out_size += size;
	}

	int socket_id = _odp_ml_glb->rte.conf.socket_id;
	int align = _odp_ml_glb->rte.dev_info.align_size;
	char name[ML_MAX_STR_LEN] = { 0 };

	snprintf(name, ML_MAX_STR_LEN - 1, "_odp_ml_%u_input", mdl->rte.id);
	name[ML_MAX_STR_LEN - 1] = 0;
	mdl->rte.inp_mz = rte_memzone_reserve_aligned(name, inp_size, socket_id,
						      RTE_MEMZONE_IOVA_CONTIG, align);
	if (!mdl->rte.inp_mz) {
		_ODP_ERR("Failed to reserve memzone for %" PRIu64 " bytes\n", inp_size);
		goto error;
	}
	mdl->rte.inp_seg.addr = mdl->rte.inp_mz->addr;
	mdl->rte.inp_seg.length = inp_size;
	mdl->rte.inp_seg.iova_addr = rte_mem_virt2iova(mdl->rte.inp_seg.addr);
	if (mdl->rte.inp_seg.iova_addr == RTE_BAD_IOVA) {
		_ODP_ERR("Failed to get IOVA address\n");
		goto error;
	}
	mdl->rte.inp_seg_p = &mdl->rte.inp_seg;
	_ODP_DBG("Input addr: %p, length: %u, iova: %p\n", mdl->rte.inp_seg.addr,
		 mdl->rte.inp_seg.length, (void *)mdl->rte.inp_seg.iova_addr);

	snprintf(name, ML_MAX_STR_LEN - 1, "_odp_ml_%u_output", mdl->rte.id);
	name[ML_MAX_STR_LEN - 1] = 0;
	mdl->rte.out_mz = rte_memzone_reserve_aligned(name, out_size, socket_id,
						      RTE_MEMZONE_IOVA_CONTIG, align);
	if (!mdl->rte.out_mz) {
		_ODP_ERR("Failed to reserve memzone for %" PRIu64 " bytes\n", out_size);
		goto error;
	}
	mdl->rte.out_seg.addr = mdl->rte.out_mz->addr;
	mdl->rte.out_seg.length = out_size;
	mdl->rte.out_seg.iova_addr = rte_mem_virt2iova(mdl->rte.out_seg.addr);
	if (mdl->rte.out_seg.iova_addr == RTE_BAD_IOVA) {
		_ODP_ERR("Failed to get IOVA address\n");
		goto error;
	}
	mdl->rte.out_seg_p = &mdl->rte.out_seg;
	_ODP_DBG("Output addr: %p, length: %u, iova: %p\n", mdl->rte.out_seg.addr,
		 mdl->rte.out_seg.length, (void *)mdl->rte.out_seg.iova_addr);

	return 0;

error:
	rte_memzone_free(mdl->rte.inp_mz);
	rte_memzone_free(mdl->rte.out_mz);

	return -1;
}

static void shape_from_rte(const struct rte_ml_model_info *rte_mdl,
			   const struct rte_ml_io_info *rte_io, odp_ml_shape_info_t *shape)
{
	int batch_done = 0;

	shape->num_dim = rte_io->nb_dims;
	shape->type = ODP_ML_SHAPE_STATIC;

	for (int i = 0; i < (int)shape->num_dim; i++) {
		shape->dim[i] = rte_io->shape[i];
		shape->dim_min[i] = rte_io->shape[i];
		shape->dim_max[i] = rte_io->shape[i];

		if (!batch_done && rte_mdl->max_batches > 1 &&
		    rte_io->shape[i] == rte_mdl->min_batches) {
			/*
			 * The first dimension that matches the minimum batch size is considered to
			 * be the batch dimension.
			 */
			shape->type = ODP_ML_SHAPE_BATCH;
			shape->dim[i] = ODP_ML_DIM_DYNAMIC;
			shape->dim_min[i] = rte_mdl->min_batches;
			shape->dim_max[i] = rte_mdl->max_batches;
			batch_done = 1;
		}
	}
}

static char *shape_str(const struct rte_ml_io_info *info, char *str, size_t len)
{
	for (int p = 0, i = 0; i < (int)info->nb_dims; i++) {
		int n = snprintf(str + p, len - p, "%u ", info->shape[i]);

		if (n < 0 || n >= (int)len - p)
			return NULL;

		p += n;
	}

	str[len - 1] = 0;

	return str;
}

static const char *io_layout_str(enum rte_ml_io_layout layout)
{
	switch (layout) {
	case RTE_ML_IO_LAYOUT_PACKED:
		return "Packed";
	case RTE_ML_IO_LAYOUT_SPLIT:
		return "Split";
	default:
		return "Unknown";
	}
}

static void dbg_print_rte_model_info(const struct rte_ml_model_info *rtei)
{
	if (!ODP_DEBUG_PRINT)
		return;

	char str[64];

	_ODP_DBG("ML model info\n");
	_ODP_DBG("Model Name: %s\n", rtei->name);
	_ODP_DBG("Version: %s\n", rtei->version);
	_ODP_DBG("Model ID: %u\n", rtei->model_id);
	_ODP_DBG("Device ID: %u\n", rtei->device_id);
	_ODP_DBG("IO Layout: %d (%s)\n", rtei->io_layout, io_layout_str(rtei->io_layout));
	_ODP_DBG("Min Batches: %u\n", rtei->min_batches);
	_ODP_DBG("Max Batches: %u\n", rtei->max_batches);
	_ODP_DBG("Number of Inputs: %u\n", rtei->nb_inputs);
	_ODP_DBG("Number of Outputs: %u\n", rtei->nb_outputs);
	_ODP_DBG("Size of weights and biases: %lu\n", rtei->wb_size);

	for (int j = 0; j < (int)rtei->nb_inputs; j++) {
		const struct rte_ml_io_info *inp = &rtei->input_info[j];

		_ODP_DBG("Input %d Name: %s\n", j, inp->name);
		_ODP_DBG("Input %d Number of Dimensions: %u\n", j, inp->nb_dims);
		_ODP_DBG("Input %d Shape: %s\n", j, shape_str(inp, str, sizeof(str)));
		_ODP_DBG("Input %d Type: %d\n", j, inp->type);
		_ODP_DBG("Input %d Number of Elements: %lu\n", j, inp->nb_elements);
		_ODP_DBG("Input %d Size: %lu\n", j, inp->size);
	}

	for (int j = 0; j < (int)rtei->nb_outputs; j++) {
		const struct rte_ml_io_info *out = &rtei->output_info[j];

		_ODP_DBG("Output %d Name: %s\n", j, out->name);
		_ODP_DBG("Output %d Number of Dimensions: %u\n", j, out->nb_dims);
		_ODP_DBG("Output %d Shape: %s\n", j, shape_str(out, str, sizeof(str)));
		_ODP_DBG("Output %d Type: %d\n", j, out->type);
		_ODP_DBG("Output %d Number of Elements: %lu\n", j, out->nb_elements);
		_ODP_DBG("Output %d Size: %lu\n", j, out->size);
	}
}

odp_ml_model_t odp_ml_model_create(const char *name, const odp_ml_model_param_t *param)
{
	odp_ml_model_info_t *info;
	uint32_t i = 0;
	ml_model_t *mdl = NULL;

	if (odp_unlikely(odp_global_ro.disable.ml)) {
		_ODP_ERR("ML is disabled\n");
		return ODP_ML_MODEL_INVALID;
	}

	if (_odp_ml_glb == NULL) {
		_ODP_ERR("No ML devices\n");
		return ODP_ML_MODEL_INVALID;
	}

	if (odp_unlikely(param->engine_id > ML_MAX_ENGINES)) {
		_ODP_ERR("Engine ID %u exceeds maximum number of engines %d\n",
			 param->engine_id, ML_MAX_ENGINES);
		return ODP_ML_MODEL_INVALID;
	}

	if (odp_unlikely(param->size > _odp_ml_glb->ml_config.max_model_size)) {
		_ODP_ERR("Model size %" PRIu64 " exceeds maximum model size configured %" PRIu64
			 "\n",
			 param->size, _odp_ml_glb->ml_config.max_model_size);
		return ODP_ML_MODEL_INVALID;
	}

	if (odp_unlikely(!param->size || !param->model)) {
		_ODP_ERR("Invalid model param: param->model: %p, param->size: %" PRIu64 "\n",
			 param->model, param->size);
		return ODP_ML_MODEL_INVALID;
	}

	if (odp_unlikely(param->max_compl_id > ML_MAX_COMPL_ID)) {
		_ODP_ERR("param->max_compl_id: %u exceeds maximum completion id supported: %d\n",
			 param->max_compl_id, ML_MAX_COMPL_ID);
		return ODP_ML_MODEL_INVALID;
	}

	/* Find an empty slot to store the new model */
	for (i = 0; i < ML_MAX_MODELS_CREATED; i++) {
		if (_odp_ml_glb->models[i].state)
			continue;

		odp_ticketlock_lock(&_odp_ml_glb->models[i].lock);

		if (_odp_ml_glb->models[i].state) {
			odp_ticketlock_unlock(&_odp_ml_glb->models[i].lock);
			continue;
		}

		mdl = &_odp_ml_glb->models[i];
		break;
	}

	if (i == ML_MAX_MODELS_CREATED) {
		_ODP_ERR("Maximum number of models has already been created!\n");
		return ODP_ML_MODEL_INVALID;
	}

	struct rte_ml_model_params rte_param = {
		.addr = param->model,
		.size = param->size,
	};

	if (rte_ml_model_load(_odp_ml_glb->conf.dev_id, &rte_param, &mdl->rte.id)) {
		_ODP_ERR("Failed to load model\n");
		goto error;
	}

	if (rte_ml_model_start(_odp_ml_glb->conf.dev_id, mdl->rte.id)) {
		_ODP_ERR("Failed to start model\n");
		goto error;
	}

	if (rte_ml_model_info_get(_odp_ml_glb->conf.dev_id, mdl->rte.id, &mdl->rte.info)) {
		_ODP_ERR("Failed to get model info\n");
		goto error;
	}

	const struct rte_ml_model_info *rtei = &mdl->rte.info;

	dbg_print_rte_model_info(rtei);

	/* Free model entry was found and is now locked */
	mdl->state = ML_STATE_CREATED;

	/* Store model info */
	info = &mdl->info;
	memset(info, 0, sizeof(*info));
	info->index = i;
	info->num_inputs = rtei->nb_inputs;
	info->num_outputs = rtei->nb_outputs;
	if (param->engine_id == ODP_ML_ENGINE_ANY)
		info->engine_id = _odp_ml_glb->ml_config.engine_id;
	else
		info->engine_id = param->engine_id;

	for (int j = 0; j < (int)rtei->nb_inputs; j++) {
		odp_ml_input_info_t *inp_info = &mdl->input_info[j];
		const struct rte_ml_io_info *rte_inp_info = &rtei->input_info[j];

		_odp_strcpy(inp_info->name, rte_inp_info->name, ODP_ML_MODEL_IO_NAME_LEN);
		inp_info->data_type = dtype_from_rte(rte_inp_info->type);
		inp_info->data_type_size = size_of_odp_ml_data_type(inp_info->data_type);
		shape_from_rte(rtei, rte_inp_info, &inp_info->shape);
		calculate_model_io_size(&inp_info->shape, inp_info->data_type_size,
					&mdl->input_sizes[j]);
	}

	for (int j = 0; j < (int)rtei->nb_outputs; j++) {
		odp_ml_output_info_t *out_info = &mdl->output_info[j];
		const struct rte_ml_io_info *rte_out_info = &rtei->output_info[j];

		_odp_strcpy(out_info->name, rte_out_info->name, ODP_ML_MODEL_IO_NAME_LEN);
		out_info->data_type = dtype_from_rte(rte_out_info->type);
		out_info->data_type_size = size_of_odp_ml_data_type(out_info->data_type);
		shape_from_rte(rtei, rte_out_info, &out_info->shape);
		calculate_model_io_size(&out_info->shape, out_info->data_type_size,
					&mdl->output_sizes[j]);
	}

	if (io_setup(mdl)) {
		_ODP_ERR("Failed to setup model IO\n");
		goto error;
	}

	if (name)
		_odp_strcpy(info->name, name, ODP_ML_MODEL_NAME_LEN);

	mdl->max_compl_id = param->max_compl_id;

	odp_ticketlock_unlock(&mdl->lock);
	return (odp_ml_model_t)mdl;

error:
	odp_ticketlock_unlock(&mdl->lock);
	return ODP_ML_MODEL_INVALID;
}

int odp_ml_model_destroy(odp_ml_model_t model)
{
	ml_model_t *mdl = ml_model_from_handle(model);

	if (model == ODP_ML_MODEL_INVALID) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	odp_ticketlock_lock(&mdl->lock);

	if (mdl->state != ML_STATE_CREATED) {
		_ODP_ERR("Model not created\n");
		goto error;
	}

	if (rte_ml_model_stop(_odp_ml_glb->conf.dev_id, mdl->rte.id)) {
		_ODP_ERR("Failed to stop model\n");
		goto error;
	}

	if (rte_ml_model_unload(_odp_ml_glb->conf.dev_id, mdl->rte.id)) {
		_ODP_ERR("Failed to unload model\n");
		goto error;
	}

	rte_memzone_free(mdl->rte.inp_mz);
	rte_memzone_free(mdl->rte.out_mz);

	mdl->state = ML_STATE_FREE;
	odp_ticketlock_unlock(&mdl->lock);

	return 0;

error:
	odp_ticketlock_unlock(&mdl->lock);
	return -1;
}

int odp_ml_model_info(odp_ml_model_t model, odp_ml_model_info_t *info)
{
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	if (odp_unlikely(!info)) {
		_ODP_ERR("info must not be NULL\n");
		return -1;
	}

	odp_ticketlock_lock(&mdl->lock);
	if (odp_unlikely(mdl->state == ML_STATE_FREE)) {
		_ODP_ERR("Model not created\n");
		odp_ticketlock_unlock(&mdl->lock);
		return -1;
	}

	*info = mdl->info;

	odp_ticketlock_unlock(&mdl->lock);
	return 0;
}

uint32_t odp_ml_model_input_info(odp_ml_model_t model, odp_ml_input_info_t info[], uint32_t num)
{
	uint32_t num_model_inputs;
	uint32_t num_written;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return 0;
	}

	odp_ticketlock_lock(&mdl->lock);
	num_model_inputs = mdl->info.num_inputs;
	num_written = num_model_inputs >= num ? num : num_model_inputs;

	if (num == 0) {
		odp_ticketlock_unlock(&mdl->lock);
		return num_model_inputs;
	}

	for (uint32_t i = 0; i < num_written; i++)
		info[i] = mdl->input_info[i];

	odp_ticketlock_unlock(&mdl->lock);
	return num_model_inputs;
}

uint32_t odp_ml_model_output_info(odp_ml_model_t model, odp_ml_output_info_t info[], uint32_t num)
{
	uint32_t num_model_outputs;
	uint32_t num_written;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return 0;
	}

	odp_ticketlock_lock(&mdl->lock);
	num_model_outputs = mdl->info.num_outputs;
	num_written = num_model_outputs >= num ? num : num_model_outputs;

	if (num == 0) {
		odp_ticketlock_unlock(&mdl->lock);
		return num_model_outputs;
	}

	for (uint32_t i = 0; i < num_written; i++)
		info[i] = mdl->output_info[i];

	odp_ticketlock_unlock(&mdl->lock);
	return num_model_outputs;
}

odp_ml_model_t odp_ml_model_lookup(const char *name)
{
	uint32_t i;
	ml_model_t *mdl;

	for (i = 0; i < ML_MAX_MODELS_CREATED; i++) {
		mdl = &_odp_ml_glb->models[i];

		odp_ticketlock_lock(&mdl->lock);

		if (mdl->state == ML_STATE_FREE) {
			odp_ticketlock_unlock(&mdl->lock);
			continue;
		}

		if (!strcmp(mdl->info.name, name)) {
			/* found it */
			odp_ticketlock_unlock(&mdl->lock);
			return (odp_ml_model_t)mdl;
		}
		odp_ticketlock_unlock(&mdl->lock);
	}

	return ODP_ML_MODEL_INVALID;
}

uint64_t odp_ml_model_to_u64(odp_ml_model_t model)
{
	return _odp_pri(model);
}

static const char *data_type_str(odp_ml_data_type_t data_type)
{
	switch (data_type) {
	case ODP_ML_DATA_TYPE_INT8:
		return "int8";
	case ODP_ML_DATA_TYPE_UINT8:
		return "uint8";
	case ODP_ML_DATA_TYPE_UINT16:
		return "uint16";
	case ODP_ML_DATA_TYPE_INT16:
		return "int16";
	case ODP_ML_DATA_TYPE_INT32:
		return "int32";
	case ODP_ML_DATA_TYPE_UINT32:
		return "uint32";
	case ODP_ML_DATA_TYPE_INT64:
		return "int64";
	case ODP_ML_DATA_TYPE_UINT64:
		return "uint64";
	case ODP_ML_DATA_TYPE_FP16:
		return "fp16";
	case ODP_ML_DATA_TYPE_FP32:
		return "fp32";
	case ODP_ML_DATA_TYPE_BFP16:
		return "bfp16";
	default:
		return "unknown";
	}
}

static const char *shape_type_str(odp_ml_shape_type_t shape_type)
{
	switch (shape_type) {
	case ODP_ML_SHAPE_NONE:
		return "none";
	case ODP_ML_SHAPE_STATIC:
		return "static";
	case ODP_ML_SHAPE_BATCH:
		return "batch";
	default:
		return "Unknown";
	}
}

static void print_shape(const odp_ml_shape_info_t *shape)
{
	/* Print shape */
	_ODP_PRINT("Shape: %s [", shape_type_str(shape->type));

	for (uint32_t i = 0; i < shape->num_dim; i++) {
		if (shape->dim[i] == ODP_ML_DIM_DYNAMIC)
			_ODP_PRINT("Dyn");
		else
			_ODP_PRINT("%" PRIu32, shape->dim[i]);

		if (i == (shape->num_dim - 1))
			_ODP_PRINT("]\n");
		else
			_ODP_PRINT(", ");
	}

	/* The number of dimensions for a scalar input is 0, in which case did not
	 * go into above for loop */
	if (shape->num_dim == 0)
		_ODP_PRINT("]\n");
}

void odp_ml_model_print(odp_ml_model_t model)
{
	ml_model_t *mdl = ml_model_from_handle(model);
	const odp_ml_model_info_t *const info = &mdl->info;
	const odp_ml_input_info_t *const input_info = mdl->input_info;
	const odp_ml_output_info_t *const output_info = mdl->output_info;

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return;
	}

	odp_ticketlock_lock(&mdl->lock);
	if (odp_unlikely(mdl->state == ML_STATE_FREE)) {
		odp_ticketlock_unlock(&mdl->lock);
		_ODP_ERR("Model not created\n");
		return;
	}

	_ODP_PRINT("\nModel info\n");
	_ODP_PRINT("----------\n");
	_ODP_PRINT("  Model handle: 0x%" PRIx64 "\n", odp_ml_model_to_u64(model));
	_ODP_PRINT("  Name: %s\n", info->name);
	_ODP_PRINT("  Model version: %" PRIu64 "\n", info->model_version);
	_ODP_PRINT("  Model interface version: %" PRIu64 "\n", info->interface_version);
	_ODP_PRINT("  Index: %u\n", info->index);
	_ODP_PRINT("  Number of inputs: %u\n", info->num_inputs);

	for (uint32_t i = 0; i < info->num_inputs; i++) {
		_ODP_PRINT("    Input[%u]: ", i);
		_ODP_PRINT("Name: %s, ", input_info[i].name);
		_ODP_PRINT("Data_type: %s, ", data_type_str(input_info[i].data_type));
		print_shape(&input_info[i].shape);
	}

	_ODP_PRINT("  Number of outputs: %u\n", info->num_outputs);
	for (uint32_t i = 0; i < info->num_outputs; i++) {
		_ODP_PRINT("    Output[%u]: ", i);
		_ODP_PRINT("Name: %s, ", output_info[i].name);
		_ODP_PRINT("Data_type: %s, ", data_type_str(output_info[i].data_type));
		print_shape(&output_info[i].shape);
	}

	odp_ticketlock_unlock(&mdl->lock);

	_ODP_PRINT("\n");
}

static inline void mode_print(odp_ml_compl_mode_t compl_mode_mask)
{
	if (compl_mode_mask & ODP_ML_COMPL_MODE_SYNC)
		_ODP_PRINT(" syn");

	if (compl_mode_mask & ODP_ML_COMPL_MODE_POLL)
		_ODP_PRINT(" poll");

	if (compl_mode_mask & ODP_ML_COMPL_MODE_EVENT)
		_ODP_PRINT(" event");
}

static void ml_device_info_print(void)
{
	const struct rte_ml_dev_info *info = &_odp_ml_glb->rte.dev_info;

	_ODP_PRINT("  Device info:\n");
	_ODP_PRINT("    name: %s\n", info->driver_name);
	_ODP_PRINT("    max models: %u\n", info->max_models);
	_ODP_PRINT("    max queue pairs: %u\n", info->max_queue_pairs);
	_ODP_PRINT("    max descriptors: %u\n", info->max_desc);
	_ODP_PRINT("    max inputs/outputs: %u\n", info->max_io);
	_ODP_PRINT("    max segments: %u\n", info->max_segments);
	_ODP_PRINT("    alignment size: %u\n", info->align_size);
}

static void ml_device_stats_print(void)
{
	struct rte_ml_dev_stats stats;

	if (rte_ml_dev_stats_get(_odp_ml_glb->conf.dev_id, &stats)) {
		_ODP_ERR("Failed to get device stats\n");
		return;
	}

	_ODP_PRINT("  Device stats:\n");
	_ODP_PRINT("    enqueued_count: %" PRIu64 "\n", stats.enqueued_count);
	_ODP_PRINT("    dequeued_count: %" PRIu64 "\n", stats.dequeued_count);
	_ODP_PRINT("    enqueue_err_count: %" PRIu64 "\n", stats.enqueue_err_count);
	_ODP_PRINT("    dequeue_err_count: %" PRIu64 "\n", stats.dequeue_err_count);
}

static void ml_device_xstats_print(void)
{
	int n = rte_ml_dev_xstats_names_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_DEVICE, 0,
					    NULL, 0);

	if (n < 1)
		return;

	struct rte_ml_dev_xstats_map xstats_map[n];

	if (rte_ml_dev_xstats_names_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_DEVICE, 0,
					xstats_map, n) != n) {
		_ODP_ERR("Failed to get device xstats\n");
		return;
	}

	uint16_t stat_ids[n];
	uint64_t values[n];

	for (int i = 0; i < n; i++)
		stat_ids[i] = xstats_map[i].id;

	if (rte_ml_dev_xstats_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_DEVICE, 0, stat_ids,
				  values, n) != n) {
		_ODP_ERR("Failed to get device xstats\n");
		return;
	}

	_ODP_PRINT("  Device xstats:\n");

	for (int i = 0; i < n; i++)
		_ODP_PRINT("    %u %s: %" PRIu64 "\n", stat_ids[i], xstats_map[i].name, values[i]);
}

void odp_ml_print(void)
{
	_ODP_PRINT("\nML info\n");
	_ODP_PRINT("-----------\n");
	_ODP_PRINT("  max_model_size: %u\n", ML_MAX_MODEL_SIZE);
	_ODP_PRINT("  max_compl_id: %u\n", ML_MAX_COMPL_ID);
	_ODP_PRINT("  max_models_created: %u\n", ML_MAX_MODELS_CREATED);
	_ODP_PRINT("  max_models_loaded: %u\n", ML_MAX_MODELS_LOADED);
	_ODP_PRINT("  model_max_inputs: %u\n", CONFIG_ML_MAX_INPUTS);
	_ODP_PRINT("  model_max_outputs: %u\n", CONFIG_ML_MAX_OUTPUTS);

	_ODP_PRINT("  load:\n");
	_ODP_PRINT("    completion mode: ");
	mode_print(_odp_ml_glb->capa.load.compl_mode_mask);
	_ODP_PRINT(", plain queue: %c, schedule queue: %c\n",
		   _odp_ml_glb->capa.load.compl_queue_plain ? 'Y' : 'N',
		   _odp_ml_glb->capa.load.compl_queue_sched ? 'Y' : 'N');

	_ODP_PRINT("  run:\n");
	_ODP_PRINT("    completion mode:");
	mode_print(_odp_ml_glb->capa.run.compl_mode_mask);
	_ODP_PRINT(", plain queue: %c, schedule queue: %c\n",
		   _odp_ml_glb->capa.run.compl_queue_plain ? 'Y' : 'N',
		   _odp_ml_glb->capa.run.compl_queue_sched ? 'Y' : 'N');

	ml_device_info_print();
	ml_device_stats_print();
	ml_device_xstats_print();

	_ODP_PRINT("\n");
}

int odp_ml_model_extra_stat_info(odp_ml_model_t model, odp_ml_extra_stat_info_t info[], int num)
{
	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	int n = rte_ml_dev_xstats_names_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_MODEL, 0,
					    NULL, 0);

	if (n < 1)
		return n;

	struct rte_ml_dev_xstats_map xstats_map[n];

	if (rte_ml_dev_xstats_names_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_MODEL, 0,
					xstats_map, n) != n) {
		_ODP_ERR("Failed to get model xstats\n");
		return -1;
	}

	for (int i = 0; i < n && i < num; i++)
		_odp_strcpy(info[i].name, xstats_map[i].name, ODP_ML_EXTRA_STAT_NAME_LEN);

	return n;
}

int odp_ml_model_extra_stats(odp_ml_model_t model, uint64_t stats[], int num)
{
	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	int n = rte_ml_dev_xstats_names_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_MODEL, 0,
					    NULL, 0);

	if (n < 1)
		return n;

	struct rte_ml_dev_xstats_map xstats_map[n];

	if (rte_ml_dev_xstats_names_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_MODEL, 0,
					xstats_map, n) != n) {
		_ODP_ERR("Failed to get model xstats\n");
		return -1;
	}

	uint16_t stat_ids[n];
	uint64_t values[n];

	for (int i = 0; i < n; i++)
		stat_ids[i] = xstats_map[i].id;

	if (rte_ml_dev_xstats_get(_odp_ml_glb->conf.dev_id, RTE_ML_DEV_XSTATS_MODEL, 0, stat_ids,
				  values, n) != n) {
		_ODP_ERR("Failed to get model xstats\n");
		return -1;
	}

	for (int i = 0; i < n && i < num; i++)
		stats[i] = values[i];

	return n;
}

void odp_ml_compl_pool_param_init(odp_ml_compl_pool_param_t *pool_param)
{
	if (odp_unlikely(!pool_param)) {
		_ODP_ERR("Param 'pool_param' must not be NULL\n");
		return;
	}

	memset(pool_param, 0, sizeof(odp_ml_compl_pool_param_t));

	pool_param->cache_size = _odp_ml_glb->pool_param.buf.cache_size;
}

odp_pool_t odp_ml_compl_pool_create(const char *name, const odp_ml_compl_pool_param_t *pool_param)
{
	odp_pool_param_t ml_pool_param;
	uint32_t num = pool_param->num;
	uint32_t uarea_size = pool_param->uarea_size;
	uint32_t cache_size = pool_param->cache_size;
	uint32_t buf_size = _ODP_MAX(sizeof(odp_ml_run_result_t),
				     sizeof(odp_ml_load_result_t));

	if (num > _odp_ml_glb->capa.pool.max_num) {
		_ODP_ERR("Too many ML completion events: %u\n", num);
		return ODP_POOL_INVALID;
	}

	if (uarea_size > _odp_ml_glb->capa.pool.max_uarea_size) {
		_ODP_ERR("Bad uarea size: %u\n", uarea_size);
		return ODP_POOL_INVALID;
	}

	if (cache_size < _odp_ml_glb->capa.pool.min_cache_size ||
	    cache_size > _odp_ml_glb->capa.pool.max_cache_size) {
		_ODP_ERR("Bad cache size: %u\n", cache_size);
		return ODP_POOL_INVALID;
	}

	odp_pool_param_init(&ml_pool_param);
	ml_pool_param.type               = ODP_POOL_BUFFER;
	ml_pool_param.uarea_init.init_fn = pool_param->uarea_init.init_fn;
	ml_pool_param.uarea_init.args    = pool_param->uarea_init.args;
	ml_pool_param.buf.num            = num;
	ml_pool_param.buf.cache_size     = cache_size;
	ml_pool_param.buf.size           = buf_size;
	ml_pool_param.buf.uarea_size     = uarea_size;

	return _odp_pool_create(name, &ml_pool_param, ODP_POOL_ML_COMPL);
}

odp_ml_compl_t odp_ml_compl_alloc(odp_pool_t pool)
{
	odp_buffer_t buf;
	odp_event_t ev;
	odp_ml_run_result_t *result;
	uint32_t buf_size = _ODP_MAX(sizeof(odp_ml_run_result_t),
				     sizeof(odp_ml_load_result_t));

	buf = odp_buffer_alloc(pool);

	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_ML_COMPL_INVALID;

	result = odp_buffer_addr(buf);
	memset(result, 0, buf_size);

	ev = odp_buffer_to_event(buf);
	_odp_event_type_set(ev, ODP_EVENT_ML_COMPL);

	return (odp_ml_compl_t)(uintptr_t)buf;
}

void odp_ml_compl_free(odp_ml_compl_t ml_compl)
{
	odp_event_t ev;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)ml_compl;

	if (odp_unlikely(ml_compl == ODP_ML_COMPL_INVALID)) {
		_ODP_ERR("Bad ML job completion handle\n");
		return;
	}

	ev = odp_buffer_to_event(buf);
	_odp_event_type_set(ev, ODP_EVENT_BUFFER);

	odp_buffer_free(buf);
}

int odp_ml_compl_run_result(odp_ml_compl_t ml_compl, odp_ml_run_result_t *result)
{
	odp_event_subtype_t subtype;
	odp_ml_run_result_t *run_result;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)ml_compl;
	odp_event_t ev = odp_buffer_to_event(buf);

	if (odp_unlikely(ml_compl == ODP_ML_COMPL_INVALID)) {
		_ODP_ERR("Given ML completion event is invalid\n");
		return -2;
	}

	if (odp_event_types(ev, &subtype) != ODP_EVENT_ML_COMPL ||
	    subtype != ODP_EVENT_ML_COMPL_RUN) {
		_ODP_ERR("Given completion event has wrong event type or subtype\n");
		return -2;
	}

	run_result = odp_buffer_addr(buf);
	if (result)
		*result = *run_result;

	return run_result->error_code ? -1 : 0;
}

int odp_ml_compl_load_result(odp_ml_compl_t ml_compl, odp_ml_load_result_t *result)
{
	odp_event_subtype_t subtype;
	odp_ml_load_result_t *load_result;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)ml_compl;
	odp_event_t ev = odp_buffer_to_event(buf);

	if (odp_unlikely(ml_compl == ODP_ML_COMPL_INVALID)) {
		_ODP_ERR("Given ML completion event is invalid\n");
		return -2;
	}

	if (odp_event_types(ev, &subtype) != ODP_EVENT_ML_COMPL ||
	    subtype != ODP_EVENT_ML_COMPL_LOAD) {
		_ODP_ERR("Given completion event has wrong event type or subtype\n");
		return -2;
	}

	load_result = odp_buffer_addr(buf);
	if (result)
		*result = *load_result;

	return load_result->error_code ? -1 : 0;
}

void *odp_ml_compl_user_area(odp_ml_compl_t ml_compl)
{
	return odp_buffer_user_area((odp_buffer_t)(uintptr_t)ml_compl);
}

odp_ml_compl_t odp_ml_compl_from_event(odp_event_t event)
{
	_ODP_ASSERT(_odp_event_hdr_field(event, int8_t, event_type) == ODP_EVENT_ML_COMPL);

	return (odp_ml_compl_t)(uintptr_t)event;
}

odp_event_t odp_ml_compl_to_event(odp_ml_compl_t ml_compl)
{
	return (odp_event_t)(uintptr_t)ml_compl;
}

uint64_t odp_ml_compl_to_u64(odp_ml_compl_t ml_compl)
{
	return (uint64_t)(uintptr_t)ml_compl;
}

void odp_ml_compl_param_init(odp_ml_compl_param_t *compl_param)
{
	memset(compl_param, 0, sizeof(odp_ml_compl_param_t));

	compl_param->queue = ODP_QUEUE_INVALID;
	compl_param->event = ODP_EVENT_INVALID;
}

int odp_ml_model_load(odp_ml_model_t model, odp_ml_load_result_t *result)
{
	odp_ml_load_result_t result_local;
	int ret = -1;
	ml_model_t *mdl = ml_model_from_handle(model);

	memset(&result_local, 0, sizeof(result_local));

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		result_local.error_code = ML_BAD_HDL;
		goto load_fail;
	}

	odp_ticketlock_lock(&mdl->lock);
	if (odp_unlikely(mdl->state != ML_STATE_CREATED)) {
		_ODP_ERR("Model has not been created yet or is already loaded\n");
		odp_ticketlock_unlock(&mdl->lock);
		result_local.error_code = ML_NOT_CREATED;
		goto load_fail;
	}

	mdl->state = ML_STATE_LOADED;
	odp_ticketlock_unlock(&mdl->lock);
	ret = 0;

load_fail:
	if (result)
		*result = result_local;

	return ret;
}

static inline int check_compl_param(const odp_ml_compl_param_t *compl_param,
				    uint32_t max_compl_id, odp_bool_t is_load)
{
	odp_ml_config_t *config = &_odp_ml_glb->ml_config;

	switch (compl_param->mode) {
	case ODP_ML_COMPL_MODE_POLL:
		if (is_load && !(config->load_mode_mask & ODP_ML_COMPL_MODE_POLL)) {
			_ODP_ERR("Poll mode loading/unloading is not configured\n");
			return -1;
		}

		if (!is_load && !(config->run_mode_mask & ODP_ML_COMPL_MODE_POLL)) {
			_ODP_ERR("Poll mode run is not configured\n");
			return -1;
		}

		if (compl_param->compl_id > max_compl_id) {
			_ODP_ERR("Bad compl_id: %u, exceeding model max completion id %u\n",
				 compl_param->compl_id, max_compl_id);
			return -1;
		}
		break;
	case ODP_ML_COMPL_MODE_EVENT:
		if (is_load && !(config->load_mode_mask & ODP_ML_COMPL_MODE_EVENT)) {
			_ODP_ERR("Event mode loading/unloading is not configured\n");
			return -1;
		}

		if (!is_load && !(config->run_mode_mask & ODP_ML_COMPL_MODE_EVENT)) {
			_ODP_ERR("Event mode run is not configured\n");
			return -1;
		}

		if (compl_param->event == ODP_EVENT_INVALID ||
		    compl_param->queue == ODP_QUEUE_INVALID) {
			_ODP_ERR("Bad event or queue\n");
			return -1;
		}

		if (odp_event_type(compl_param->event) != ODP_EVENT_ML_COMPL) {
			_ODP_ERR("Bad completion event type\n");
			return -1;
		}
		break;
	default:
		/* Including ODP_ML_COMPL_MODE_SYNC, which is not supported by
		 * asynchrous functions (e.g. *_start()) either.
		 */
		_ODP_ERR("Invalid completion mode %u\n", compl_param->mode);
		return -1;
	}

	return 0;
}

int odp_ml_model_load_start(odp_ml_model_t model, const odp_ml_compl_param_t *compl_param)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad model handle\n");
		return -1;
	}

	if (odp_unlikely(check_compl_param(compl_param, mdl->max_compl_id, true)))
		return -1;

	ret = odp_ml_model_load(model, NULL);

	if (odp_unlikely(ret))
		return -1;

	/* Send a completion event to the given queue */
	if (compl_param->mode == ODP_ML_COMPL_MODE_EVENT) {
		odp_ml_load_result_t *result;
		odp_buffer_t buf = (odp_buffer_t)(uintptr_t)compl_param->event;

		_odp_buffer_subtype_set(buf, ODP_EVENT_ML_COMPL_LOAD);

		result = odp_buffer_addr(buf);
		result->error_code = 0;
		result->user_ptr = compl_param->user_ptr;

		if (odp_unlikely(odp_queue_enq(compl_param->queue, compl_param->event))) {
			_ODP_ERR("Completion event enqueue failed %" PRIu64 "\n",
				 odp_queue_to_u64(compl_param->queue));
			if (odp_ml_model_unload(model, NULL))
				_ODP_ERR("Failed to unload model\n");
			return -1;
		}

		return 0;
	}

	mdl->result[compl_param->compl_id].user_ptr = compl_param->user_ptr;
	return 0;
}

int odp_ml_model_load_status(odp_ml_model_t model, uint32_t compl_id, odp_ml_load_result_t *result)
{
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID || compl_id > mdl->max_compl_id)) {
		_ODP_ERR("Invalid model or compl_id: %u\n", compl_id);
		return -2;
	}

	if (result) {
		result->error_code = 0;
		result->user_ptr = mdl->result[compl_id].user_ptr;
	}

	return 1;
}

int odp_ml_model_unload(odp_ml_model_t model, odp_ml_load_result_t *result)
{
	odp_ml_load_result_t result_local;
	int ret = -1;
	ml_model_t *mdl = ml_model_from_handle(model);

	memset(&result_local, 0, sizeof(result_local));

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		result_local.error_code = ML_BAD_HDL;
		_ODP_ERR("Bad ML model handle\n");
		goto unload_fail;
	}

	odp_ticketlock_lock(&mdl->lock);
	/* mdl->state == ML_STATE_FREE, ML_STATE_CREATED, ML_STATE_INFERENCING */
	if (odp_unlikely(mdl->state != ML_STATE_LOADED)) {
		_ODP_ERR("Model has not been created/loaded or inferencing has not finished yet\n");
		odp_ticketlock_unlock(&mdl->lock);
		result_local.error_code = ML_NOT_LOADED;
		goto unload_fail;
	}

	mdl->state = ML_STATE_CREATED;
	odp_ticketlock_unlock(&mdl->lock);

	ret = 0;

unload_fail:
	if (result)
		*result = result_local;

	return ret;
}

int odp_ml_model_unload_start(odp_ml_model_t model, const odp_ml_compl_param_t *compl_param)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad model handle\n");
		return -1;
	}

	if (odp_unlikely(check_compl_param(compl_param, mdl->max_compl_id, true)))
		return -1;

	ret = odp_ml_model_unload(model, NULL);

	if (odp_unlikely(ret))
		return -1;

	/* Upon successful unloading, send a completion event to the given queue */
	if (compl_param->mode == ODP_ML_COMPL_MODE_EVENT) {
		odp_ml_load_result_t *result;
		odp_buffer_t buf = (odp_buffer_t)(uintptr_t)compl_param->event;

		_odp_buffer_subtype_set(buf, ODP_EVENT_ML_COMPL_LOAD);

		result = odp_buffer_addr(buf);
		result->error_code = 0;
		result->user_ptr = compl_param->user_ptr;

		if (odp_unlikely(odp_queue_enq(compl_param->queue, compl_param->event))) {
			_ODP_ERR("Completion event enqueue failed %" PRIu64 "\n",
				 odp_queue_to_u64(compl_param->queue));
			return -1;
		}

		return 0;
	}

	mdl->result[compl_param->compl_id].user_ptr = compl_param->user_ptr;
	return 0;
}

int odp_ml_model_unload_status(odp_ml_model_t model, uint32_t compl_id,
			       odp_ml_load_result_t *result)
{
	return odp_ml_model_load_status(model, compl_id, result);
}

void odp_ml_run_param_init(odp_ml_run_param_t *param)
{
	memset(param, 0, sizeof(odp_ml_run_param_t));
}

static void ml_shape_to_int64(const odp_ml_shape_info_t *shape, uint32_t batch_size, int64_t *array)
{
	for (uint32_t i = 0; i < shape->num_dim; i++) {
		/* Replace dynamic dimension size with provided batch_size */
		if (shape->dim[i] == ODP_ML_DIM_DYNAMIC)
			array[i] = batch_size;
		else
			array[i] = shape->dim[i];
	}
}

/* Get the number of elements in given shape */
static inline uint64_t get_num_elem(uint32_t batch_size, const odp_ml_shape_info_t *shape)
{
	uint64_t num_elements = 1;
	int64_t dim[ODP_ML_MAX_DIMS] = {0};

	ml_shape_to_int64(shape, batch_size, dim);

	for (uint32_t i = 0; i < shape->num_dim; i++)
		num_elements *= (uint64_t)dim[i];

	return num_elements;
}

static inline uint32_t dyn_io_size(const odp_ml_shape_info_t *shape, uint32_t data_type_size,
				   const odp_ml_run_param_t *param)
{
	uint32_t size;

	if (!param || !param->batch_size) {
		_ODP_ERR("Parameter 'param' must not be NULL and batch_size must be "
			 "provided when a input/output has dynamic dimension size\n");
		return 0;
	}

	size = get_num_elem(param->batch_size, shape);
	size *= data_type_size;

	return size;
}

static int verify_run_params(odp_ml_model_t model, const odp_ml_data_t *data,
			     const odp_ml_run_param_t *param)
{
	const ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	if (odp_unlikely(!data)) {
		_ODP_ERR("Parameter 'data' must not be NULL\n");
		return -1;
	}

	/* Make sure that the number of input data segments equals or bigger than
	 * the number of model inputs. */
	if (mdl->info.num_inputs > data->num_input_seg) {
		_ODP_ERR("The num of input data segments %u must not be less than "
			 "the number of model inputs %u\n", data->num_input_seg,
			 mdl->info.num_inputs);
		return -1;
	}

	if (mdl->info.num_outputs > data->num_output_seg) {
		_ODP_ERR("The num of output data segments %u must not be less than "
			 "the number of model outputs %u\n", data->num_output_seg,
			 mdl->info.num_outputs);
		return -1;
	}

	if (data->num_input_seg > mdl->info.num_inputs &&
	    (_odp_ml_glb->capa.max_segs_per_input == 1)) {
		_ODP_ERR("Segmented input data is not supported\n");
		return -1;
	}

	if (data->num_output_seg > mdl->info.num_outputs &&
	    (_odp_ml_glb->capa.max_segs_per_output == 1)) {
		_ODP_ERR("Segmented output data is not supported");
		return -1;
	}

	uint32_t size = 0;
	uint32_t input_index = 0;
	uint32_t seg_size_sum = 0;
	odp_bool_t index_new = true;
	uint32_t segs_per_input = 1;

	for (uint32_t i = 0; i < data->num_input_seg; i++) {
		if (data->input_seg[i].addr == NULL) {
			_ODP_ERR("data->input_seg[%u].addr must not be NULL\n", i);
			return -1;
		};

		if (index_new) {
			if (input_index > mdl->info.num_inputs - 1) {
				_ODP_ERR("Too many input segments given\n");
				return -1;
			}

			/* Input with dynamic batch size */
			if (mdl->input_info[input_index].shape.type == ODP_ML_SHAPE_BATCH)
				size = dyn_io_size(&mdl->input_info[input_index].shape,
						   mdl->input_info[input_index].data_type_size,
						   param);
			else
				size = mdl->input_sizes[input_index];

			if (!size) {
				_ODP_ERR("Size for %uth input is 0\n", input_index);
				return -1;
			}
		}

		seg_size_sum += data->input_seg[i].size;

		if (seg_size_sum > size) {
			_ODP_ERR("Sum of segment sizes %u exceeds %uth input data size %u\n",
				 seg_size_sum, input_index, size);
			return -1;
		}

		if (seg_size_sum == size) {
			if (segs_per_input > _odp_ml_glb->capa.max_segs_per_input) {
				_ODP_ERR("Number of segments %u for input[%u] exceeds maximum"
					 " number of data segments per model input %u\n",
					 segs_per_input, input_index,
					 _odp_ml_glb->capa.max_segs_per_input);
				return -1;
			}
			input_index++;
			index_new = true;
			seg_size_sum = 0;
			segs_per_input = 1;
		} else {
			segs_per_input++;
			index_new = false;
		}
	}

	if (input_index != mdl->info.num_inputs) {
		_ODP_ERR("Data is not provided for all model inputs\n");
		return -1;
	}

	seg_size_sum = 0;
	index_new = true;
	uint32_t output_index = 0;
	uint32_t segs_per_output = 1;

	for (uint32_t i = 0; i < data->num_output_seg; i++) {
		if (data->output_seg[i].addr == NULL) {
			_ODP_ERR("data->output_seg[%u].addr must not be NULL\n", i);
			return -1;
		}

		if (index_new) {
			if (output_index > mdl->info.num_outputs - 1) {
				_ODP_ERR("Too many output segments given\n");
				return -1;
			}

			/* Output with dynamic batch size */
			if (mdl->output_info[output_index].shape.type == ODP_ML_SHAPE_BATCH)
				size = dyn_io_size(&mdl->output_info[output_index].shape,
						   mdl->output_info[output_index].data_type_size,
						   param);
			else
				size = mdl->output_sizes[output_index];

			if (!size) {
				_ODP_ERR("Size for %uth output is 0\n", output_index);
				return -1;
			}
		}

		seg_size_sum += data->output_seg[i].size;

		if (seg_size_sum > size) {
			_ODP_ERR("Sum of segment sizes %u exceeds %uth output data size %u\n",
				 seg_size_sum, output_index, size);
			return -1;
		}

		if (seg_size_sum >= size) {
			if (segs_per_output > _odp_ml_glb->capa.max_segs_per_output) {
				_ODP_ERR("Number of segments %u for output[%u] exceeds maximum"
					 " number of data segments per model output %u\n",
					 segs_per_output, output_index,
					 _odp_ml_glb->capa.max_segs_per_output);
				return -1;
			}
			output_index++;
			index_new = true;
			seg_size_sum = 0;
			segs_per_output = 1;
		} else {
			segs_per_output++;
			index_new = false;
		}
	}

	if (output_index != mdl->info.num_outputs) {
		_ODP_ERR("Not enough output_segs to hold all output data\n");
		return -1;
	}

	return 0;
}

int odp_ml_run(odp_ml_model_t model, const odp_ml_data_t *data, const odp_ml_run_param_t *param)
{
	int batch_size = 1;
	int retval = -1; /* Return value of this function */
	ml_model_t *mdl = ml_model_from_handle(model);
	uint32_t qp_id = UINT32_MAX;
	struct rte_ml_op *op = NULL;
	struct rte_ml_op_error op_err = { 0 };

	odp_ticketlock_lock(&mdl->lock);
	/*
	 * To keep things simple, we allocate memzone memory for one inference in
	 * odp_ml_model_create(). This means that we can run only one inference at a time.
	 */
	if (odp_unlikely(mdl->state == ML_STATE_INFERENCING)) {
		odp_ticketlock_unlock(&mdl->lock);
		return 0;
	}
	if (odp_unlikely(mdl->state != ML_STATE_LOADED)) {
		_ODP_ERR("Wrong model state: not created or not loaded\n");
		odp_ticketlock_unlock(&mdl->lock);
		return -1;
	}
	mdl->state = ML_STATE_INFERENCING;
	odp_ticketlock_unlock(&mdl->lock);

	if (ODP_DEBUG && verify_run_params(model, data, param))
		goto error;

	/*
	 * Queue pairs are not MT-safe. By managing them in a stash we ensure that they're not
	 * concurrently used by multiple threads.
	 */
	int32_t n = odp_stash_get_u32(_odp_ml_glb->qp_stash, &qp_id, 1);

	if (!n) {
		/* All queue pairs in use. */
		retval = 0;
		goto error;
	}

	if (n < 0) {
		_ODP_ERR("Failed to get queue pair id from stash\n");
		goto error;
	}

	if (param && param->batch_size)
		batch_size = param->batch_size;

	uint64_t offset = 0;
	uint64_t total_size = 0;

	for (int i = 0; i < (int)mdl->rte.info.nb_inputs; i++) {
		if (mdl->input_info[i].shape.type == ODP_ML_SHAPE_BATCH)
			total_size += mdl->input_sizes[i] * batch_size;
		else
			total_size += mdl->input_sizes[i];
	}

	for (int i = 0; i < (int)data->num_input_seg; i++) {
		if (offset + data->input_seg[i].size > total_size) {
			_ODP_ERR("Excess input data\n");
			goto error;
		}
		rte_memcpy((uint8_t *)mdl->rte.inp_seg.addr + offset, data->input_seg[i].addr,
			   data->input_seg[i].size);
		offset += data->input_seg[i].size;
	}

	if (offset < total_size) {
		_ODP_ERR("Insufficient input data\n");
		goto error;
	}

	if (rte_mempool_get(_odp_ml_glb->rte.op_pool, (void **)&op)) {
		_ODP_ERR("Failed to get op from mempool\n");
		goto error;
	}

	op->model_id = mdl->rte.id;
	op->nb_batches = batch_size;
	op->mempool = _odp_ml_glb->rte.op_pool;
	op->input = &mdl->rte.inp_seg_p;
	op->output = &mdl->rte.out_seg_p;
	op->user_u64 = 0;

	if (rte_ml_enqueue_burst(_odp_ml_glb->conf.dev_id, qp_id, &op, 1) != 1) {
		_ODP_ERR("Failed to enqueue model\n");
		goto error;
	}

	/*
	 * For simplicity, wait for the operation to complete. This means that inference is always
	 * synchronous, even in poll mode, and that the number of queue pairs limits the maximum
	 * number of concurrent inferences.
	 */
	while (rte_ml_dequeue_burst(_odp_ml_glb->conf.dev_id, qp_id, &op, 1) != 1)
		odp_cpu_pause();

	if (op->status == RTE_ML_OP_STATUS_ERROR) {
		rte_ml_op_error_get(_odp_ml_glb->conf.dev_id, op, &op_err);
		_ODP_DBG("rte_ml_op_error_get(): error_code = 0x%" PRIx64 ", error_message = %s\n",
			 op_err.errcode, op_err.message);
		goto error;
	}

	offset = 0;
	total_size = 0;

	for (int i = 0; i < (int)mdl->rte.info.nb_outputs; i++) {
		if (mdl->output_info[i].shape.type == ODP_ML_SHAPE_BATCH)
			total_size += mdl->output_sizes[i] * batch_size;
		else
			total_size += mdl->output_sizes[i];
	}

	for (int i = 0; i < (int)data->num_output_seg; i++) {
		rte_memcpy(data->output_seg[i].addr, (uint8_t *)mdl->rte.out_seg.addr + offset,
			   data->output_seg[i].size);
		offset += data->output_seg[i].size;
	}

	if (offset < total_size) {
		_ODP_ERR("Insufficient output space\n");
		goto error;
	}

	retval = 1;

error:
	if (op)
		rte_mempool_put(_odp_ml_glb->rte.op_pool, op);

	if (qp_id != UINT32_MAX) {
		if (odp_stash_put_u32(_odp_ml_glb->qp_stash, &qp_id, 1) != 1)
			_ODP_ERR("Failed to put qp_id to stash\n");
	}

	odp_ticketlock_lock(&mdl->lock);
	mdl->state = ML_STATE_LOADED;
	odp_ticketlock_unlock(&mdl->lock);

	if (param && param->result)
		param->result->error_code = op_err.errcode;

	return retval;
}

int odp_ml_run_multi(odp_ml_model_t model, const odp_ml_data_t data[],
		     const odp_ml_run_param_t param[], int num)
{
	int i;
	int ret;

	if (odp_unlikely(num < 1)) {
		_ODP_ERR("Bad number of runs\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		if (param)
			ret = odp_ml_run(model, &data[i], &param[i]);
		else
			ret = odp_ml_run(model, &data[i], NULL);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

int odp_ml_run_start(odp_ml_model_t model, const odp_ml_data_t *data,
		     const odp_ml_compl_param_t *compl_param,
		     const odp_ml_run_param_t *run_param)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad model handle\n");
		return -1;
	}

	if (odp_unlikely(!compl_param)) {
		_ODP_ERR("Completion parameter is NULL\n");
		return -1;
	}

	/* Check completion mode */
	if (odp_unlikely(check_compl_param(compl_param, mdl->max_compl_id, false))) {
		_ODP_ERR("Bad ML job completion parameter\n");
		return -1;
	}

	ret = odp_ml_run(model, data, run_param);

	if (odp_unlikely(ret < 1))
		return ret;

	/* Send a completion event to the given queue */
	if (compl_param->mode == ODP_ML_COMPL_MODE_EVENT) {
		odp_ml_run_result_t *result;
		odp_buffer_t buf = (odp_buffer_t)(uintptr_t)compl_param->event;

		_odp_buffer_subtype_set(buf, ODP_EVENT_ML_COMPL_RUN);

		result = odp_buffer_addr(buf);
		result->error_code = 0;
		result->user_ptr = compl_param->user_ptr;

		if (odp_unlikely(odp_queue_enq(compl_param->queue, compl_param->event))) {
			_ODP_ERR("Completion event enqueue failed %" PRIu64 "\n",
				 odp_queue_to_u64(compl_param->queue));
			return -1;
		}

		return 1;
	}

	/* compl_param->mode == ODP_ML_COMPL_MODE_POLL */
	mdl->result[compl_param->compl_id].user_ptr = compl_param->user_ptr;

	return 1;
}

int odp_ml_run_start_multi(odp_ml_model_t model, const odp_ml_data_t data[],
			   const odp_ml_compl_param_t compl_param[],
			   const odp_ml_run_param_t run_param[], int num)
{
	int i;
	int ret = 0;

	if (odp_unlikely(num < 1)) {
		_ODP_ERR("Bad number of runs\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		if (run_param)
			ret = odp_ml_run_start(model, &data[i], &compl_param[i], &run_param[i]);
		else
			ret = odp_ml_run_start(model, &data[i], &compl_param[i], NULL);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

int odp_ml_run_status(odp_ml_model_t model, uint32_t compl_id, odp_ml_run_result_t *result)
{
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID ||
			 compl_id > mdl->max_compl_id)) {
		_ODP_ERR("Invalid model handle or completion id: %u\n", compl_id);
		return -2;
	}

	if (result) {
		result->error_code = 0;
		result->user_ptr = mdl->result[compl_id].user_ptr;
	}

	return 1;
}

static int read_config_file(void)
{
	const char *conf_str;

	_ODP_PRINT("ML config:\n");

	conf_str = "ml.dev_id";
	if (!_odp_libconfig_lookup_int(conf_str, &_odp_ml_glb->conf.dev_id)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", conf_str, _odp_ml_glb->conf.dev_id);

	conf_str = "ml.num_queue_pairs";
	if (!_odp_libconfig_lookup_int(conf_str, &_odp_ml_glb->conf.num_queue_pairs)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", conf_str, _odp_ml_glb->conf.num_queue_pairs);

	return 0;
}

int _odp_ml_init_global(void)
{
	int i;
	odp_shm_t shm;

	if (odp_global_ro.disable.ml) {
		_ODP_ERR("ML is disabled\n");
		return 0;
	}

	if (rte_ml_dev_count() < 1) {
		_ODP_WARN("No ML devices found\n");
		return 0;
	}

	shm = odp_shm_reserve("_odp_ml_global", sizeof(ml_global_t), ODP_CACHE_LINE_SIZE, 0);
	_odp_ml_glb = odp_shm_addr(shm);

	if (_odp_ml_glb == NULL) {
		_ODP_ERR("SHM reserve failed for odp_ml\n");
		return -1;
	}

	memset(_odp_ml_glb, 0, sizeof(ml_global_t));
	_odp_ml_glb->shm = shm;
	odp_pool_param_init(&_odp_ml_glb->pool_param);

	if (read_config_file())
		goto error;

	const int id = _odp_ml_glb->conf.dev_id;
	struct rte_ml_dev_info *info = &_odp_ml_glb->rte.dev_info;

	_ODP_DBG("ML device count: %d\n", rte_ml_dev_count());
	_ODP_DBG("ML device %d\n", id);
	if (!rte_ml_dev_is_valid_dev(id)) {
		_ODP_ERR("ML device %d is not valid\n", id);
		goto error;
	}
	if (rte_ml_dev_info_get(id, info)) {
		_ODP_ERR("ML device info get failed: %s\n", rte_strerror(rte_errno));
		goto error;
	}

	if (!info->align_size) {
		_ODP_ERR("ML device alignment size is 0\n");
		goto error;
	}

	if (_ODP_ROUNDUP_POWER2_U32(info->align_size) != info->align_size) {
		_ODP_ERR("ML device alignment size is not a power of two\n");
		goto error;
	}

	if (odp_ml_capability(&_odp_ml_glb->capa)) {
		_ODP_ERR("ML capability failed\n");
		goto error;
	}

	struct rte_ml_dev_config *conf = &_odp_ml_glb->rte.conf;
	int socket_id = rte_ml_dev_socket_id(id);

	conf->socket_id = socket_id;
	conf->nb_models = _odp_ml_glb->capa.max_models;
	conf->nb_queue_pairs = _ODP_MIN(_odp_ml_glb->conf.num_queue_pairs, info->max_queue_pairs);

	_ODP_DBG("ML configuration\n");
	_ODP_DBG("socket id: %d\n", conf->socket_id);
	_ODP_DBG("number of models: %u\n", conf->nb_models);
	_ODP_DBG("number of queue pairs: %u\n", conf->nb_queue_pairs);

	if (rte_ml_dev_configure(id, conf)) {
		_ODP_ERR("ML device configure failed: %s\n", rte_strerror(rte_errno));
		goto error;
	}

	struct rte_ml_dev_qp_conf qp_conf = {
		.nb_desc = 1,
	};

	_ODP_DBG("ML queue pair conf number of descriptors: %u\n", qp_conf.nb_desc);

	for (i = 0; i < conf->nb_queue_pairs; i++) {
		if (rte_ml_dev_queue_pair_setup(id, i, &qp_conf, socket_id)) {
			_ODP_ERR("ML device queue pair %d setup failed: %s\n", i,
				 rte_strerror(rte_errno));
			goto error;
		}
	}

	if (rte_ml_dev_start(id)) {
		_ODP_ERR("ML device start failed: %s\n", rte_strerror(rte_errno));
		goto error;
	}

	odp_stash_param_t stash_param;

	odp_stash_param_init(&stash_param);
	stash_param.num_obj = conf->nb_queue_pairs;
	stash_param.obj_size = sizeof(uint32_t);
	_odp_ml_glb->qp_stash = odp_stash_create("_odp_ml_qp_stash", &stash_param);

	if (_odp_ml_glb->qp_stash == ODP_STASH_INVALID) {
		_ODP_ERR("Stash create failed\n");
		goto error;
	}

	for (uint32_t qp_id = 0; qp_id < conf->nb_queue_pairs; qp_id++) {
		if (odp_stash_put_u32(_odp_ml_glb->qp_stash, &qp_id, 1) != 1) {
			_ODP_ERR("Stash put failed\n");
			goto error;
		}
	}

	if (ODP_DEBUG_PRINT)
		odp_stash_print(_odp_ml_glb->qp_stash);

	uint32_t num_op = conf->nb_queue_pairs * qp_conf.nb_desc;

	_ODP_DBG("ML operation pool size: %u\n", num_op);
	_odp_ml_glb->rte.op_pool =
		rte_ml_op_pool_create("_odp_ml_rte_op_pool", num_op, 0, 0, socket_id);

	if (!_odp_ml_glb->rte.op_pool) {
		_ODP_ERR("ML device op pool create failed: %s\n", rte_strerror(rte_errno));
		goto error;
	}

	for (i = 0; i < ML_MAX_MODELS_CREATED; i++)
		odp_ticketlock_init(&_odp_ml_glb->models[i].lock);

	return 0;

error:
	_odp_ml_term_global();

	return -1;
}

int _odp_ml_term_global(void)
{
	if (odp_global_ro.disable.ml)
		return 0;

	if (_odp_ml_glb == NULL)
		return 0;

	const int id = _odp_ml_glb->conf.dev_id;

	if (rte_ml_dev_is_valid_dev(id)) {
		if (rte_ml_dev_stop(id))
			_ODP_ERR("ML device stop failed: %s\n", rte_strerror(rte_errno));

		/* Destroys queue pairs. */
		if (rte_ml_dev_close(id))
			_ODP_ERR("ML device close failed: %s\n", rte_strerror(rte_errno));

		if (_odp_ml_glb->rte.op_pool)
			rte_ml_op_pool_free(_odp_ml_glb->rte.op_pool);

		if (_odp_ml_glb->qp_stash) {
			uint32_t tmp;

			while (odp_stash_get_u32(_odp_ml_glb->qp_stash, &tmp, 1) == 1)
				;

			if (odp_stash_destroy(_odp_ml_glb->qp_stash))
				_ODP_ERR("Stash destroy failed\n");
		}
	}

	if (odp_shm_free(_odp_ml_glb->shm)) {
		_ODP_ERR("Shm free failed for odp_ml\n");
		return -1;
	}

	return 0;
}
