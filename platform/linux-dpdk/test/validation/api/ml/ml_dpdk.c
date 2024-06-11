/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include "odp_cunit_common.h"

#define TIMEOUT		5
#define MODEL_NAME	"Test"
#define NUM_INPUTS	1
#define NUM_OUTPUTS	1
#define INP_ELEMS	2
#define OUT_ELEMS	2
#define NUM_BATCH	4
#define RUN_NUM		2
#define BUF_LEN		256
#define CONFIG_MAX_MODEL_SIZE (1024 * 1024)

#define COMPL_POOL_NAME "ML compl pool"
#define NUM_COMPL	10

typedef struct global_t {
	int disabled;
	odp_ml_capability_t ml_capa;
	odp_ml_config_t ml_config;
	odp_ml_model_param_t model_param;
	odp_ml_model_t ml_model;
	odp_pool_t compl_pool;
	odp_queue_t queue;
	odp_ml_data_t data;
	odp_ml_data_seg_t input_seg;
	odp_ml_data_seg_t output_seg;
	uint64_t wait_ns;
	float input[INP_ELEMS * NUM_BATCH];
	float output[OUT_ELEMS * NUM_BATCH];
	float reference[OUT_ELEMS * NUM_BATCH];
	uint16_t input_q[INP_ELEMS * NUM_BATCH];
	uint16_t output_q[OUT_ELEMS * NUM_BATCH];

} global_t;

static global_t global;

static int fill_model_param(const char *model_name, odp_ml_model_param_t *model_param)
{
	size_t size;
	FILE *model_file;

	odp_ml_model_param_init(model_param);

	model_file = fopen(model_name, "rb");
	if (model_file == NULL) {
		perror("Failed to open model file");
		return -1;
	}

	/* Get the model file size in bytes */
	fseek(model_file, 0, SEEK_END);
	model_param->size = ftell(model_file);
	rewind(model_file);

	model_param->model = malloc(model_param->size);
	if (!model_param->model) {
		ODPH_ERR("\n\nMemory allocation failed\n");
		fclose(model_file);
		return -1;
	}
	size = fread(model_param->model, model_param->size, 1, model_file);

	fclose(model_file);
	if (size != 1) {
		ODPH_ERR("\n\nRead model file failed\n");
		return -1;
	}

	model_param->max_compl_id = 0;

	return 0;
}

static int ml_suite_init(void)
{
	odp_ml_capability_t *ml_capa = &global.ml_capa;
	odp_queue_param_t queue_param;
	odp_ml_compl_pool_param_t ml_pool_param;

	global.queue = ODP_QUEUE_INVALID;
	global.compl_pool = ODP_POOL_INVALID;

	if (odp_ml_capability(ml_capa)) {
		ODPH_ERR("ML capability failed\n");
		return -1;
	}

	if (ml_capa->max_models == 0) {
		global.disabled = 1;
		ODPH_DBG("ML test disabled\n");
		return 0;
	}

	/* Configure ML */
	odp_ml_config_init(&global.ml_config);
	global.ml_config.max_models_created = ml_capa->max_models;
	global.ml_config.max_models_loaded = ml_capa->max_models_loaded;
	global.ml_config.max_model_size = CONFIG_MAX_MODEL_SIZE;

	if (ml_capa->load.compl_mode_mask & ODP_ML_COMPL_MODE_SYNC)
		global.ml_config.load_mode_mask |= ODP_ML_COMPL_MODE_SYNC;

	if (ml_capa->load.compl_mode_mask & ODP_ML_COMPL_MODE_POLL)
		global.ml_config.load_mode_mask |= ODP_ML_COMPL_MODE_POLL;

	if (ml_capa->load.compl_mode_mask & ODP_ML_COMPL_MODE_EVENT)
		global.ml_config.load_mode_mask |= ODP_ML_COMPL_MODE_EVENT;

	if (ml_capa->run.compl_mode_mask & ODP_ML_COMPL_MODE_SYNC)
		global.ml_config.run_mode_mask |= ODP_ML_COMPL_MODE_SYNC;

	if (ml_capa->run.compl_mode_mask & ODP_ML_COMPL_MODE_POLL)
		global.ml_config.run_mode_mask |= ODP_ML_COMPL_MODE_POLL;

	if (ml_capa->run.compl_mode_mask & ODP_ML_COMPL_MODE_EVENT)
		global.ml_config.run_mode_mask |= ODP_ML_COMPL_MODE_EVENT;

	if (odp_ml_config(&global.ml_config)) {
		ODPH_ERR("\n\nConfiguring ML failed\n");
		return -1;
	}

	global.wait_ns = 500 * ODP_TIME_MSEC_IN_NS;

	/* Prepare input and reference. */

	int num = INP_ELEMS * NUM_BATCH;

	for (int i = 0; i < num; i++) {
		global.input[i] = i + 1;
		global.reference[i] = global.input[i] * 2;
	}

	odp_ml_fp32_to_fp16(global.input_q, global.input, num);

	/* Set up segments. */

	global.data.num_input_seg = NUM_INPUTS;
	global.data.input_seg = &global.input_seg;
	global.input_seg.addr = &global.input_q;

	global.data.num_output_seg = NUM_OUTPUTS;
	global.data.output_seg = &global.output_seg;
	global.output_seg.addr = &global.output_q;

	/* Create ML model */
	global.ml_model = odp_ml_model_create(MODEL_NAME, &global.model_param);
	if (global.ml_model == ODP_ML_MODEL_INVALID) {
		ODPH_ERR("Create ML model failed\n");
		goto error;
	}

	/* Asynchronous mode with event completion is not supported */
	if (!((ml_capa->load.compl_mode_mask & ODP_ML_COMPL_MODE_EVENT) ||
	      (ml_capa->run.compl_mode_mask & ODP_ML_COMPL_MODE_EVENT)))
		return 0;

	/* Create a queue for sending ML completion event to */
	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	queue_param.sched.prio  = odp_schedule_default_prio();
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	global.queue = odp_queue_create("ML compl queue", &queue_param);
	if (global.queue == ODP_QUEUE_INVALID) {
		ODPH_ERR("Queue create failed\n");
		goto error;
	}

	/* Create an ML job completion pool */
	if (ml_capa->pool.max_num < NUM_COMPL) {
		ODPH_ERR("Too small ML compl pool %u\n", ml_capa->pool.max_num);
		goto error;
	}

	odp_ml_compl_pool_param_init(&ml_pool_param);
	ml_pool_param.num = NUM_COMPL;

	global.compl_pool = odp_ml_compl_pool_create(COMPL_POOL_NAME, &ml_pool_param);
	if (global.compl_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Create ML completion pool failed\n");
		goto error;
	}

	return 0;

error:
	free(global.model_param.model);
	return -1;
}

static int ml_suite_term(void)
{
	if (global.compl_pool != ODP_POOL_INVALID && odp_pool_destroy(global.compl_pool)) {
		ODPH_ERR("Completion pool destroy failed\n");
		return -1;
	}

	if (global.ml_model && odp_ml_model_destroy(global.ml_model)) {
		ODPH_ERR("Destroy ML model failed\n");
		return -1;
	}

	if (global.queue != ODP_QUEUE_INVALID && odp_queue_destroy(global.queue)) {
		ODPH_ERR("Destroy ML queue failed\n");
		return -1;
	}

	free(global.model_param.model);

	return 0;
}

static int check_ml_support(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int check_load_sync(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.ml_config.load_mode_mask & ODP_ML_COMPL_MODE_SYNC)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_load_poll(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.ml_config.load_mode_mask & ODP_ML_COMPL_MODE_POLL)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_load_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.ml_config.load_mode_mask & ODP_ML_COMPL_MODE_EVENT)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_run_sync(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	/* Model run test uses synchronous load */
	if ((global.ml_config.run_mode_mask & ODP_ML_COMPL_MODE_SYNC) &&
	    (global.ml_config.load_mode_mask & ODP_ML_COMPL_MODE_SYNC))
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_run_poll(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	/* Poll mode model run test uses synchronous load */
	if ((global.ml_config.run_mode_mask & ODP_ML_COMPL_MODE_POLL) &&
	    (global.ml_config.load_mode_mask & ODP_ML_COMPL_MODE_SYNC))
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_run_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	/* Poll mode model run test uses synchronous load */
	if ((global.ml_config.run_mode_mask & ODP_ML_COMPL_MODE_EVENT) &&
	    (global.ml_config.load_mode_mask & ODP_ML_COMPL_MODE_SYNC))
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_run_poll_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	/* test_ml_run_start_multi uses synchronous load, poll mode and event mode run */
	if ((global.ml_config.run_mode_mask & ODP_ML_COMPL_MODE_EVENT) &&
	    (global.ml_config.run_mode_mask & ODP_ML_COMPL_MODE_POLL) &&
	    (global.ml_config.load_mode_mask & ODP_ML_COMPL_MODE_SYNC))
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static void test_ml_debug(void)
{
	uint64_t u64;

	u64 = odp_ml_model_to_u64(global.ml_model);
	CU_ASSERT(u64 != odp_ml_model_to_u64(ODP_ML_MODEL_INVALID));
	printf("\n    ML model handle: 0x%" PRIx64 "\n", u64);

	odp_ml_model_print(global.ml_model);
}

static void test_ml_model_create(void)
{
	uint32_t i;
	/* One for global.ml_model */
	uint32_t max_models = global.ml_config.max_models_created - 1;
	odp_ml_model_t models[max_models];

	for (i = 0; i < max_models; i++) {
		models[i] = odp_ml_model_create(NULL, &global.model_param);

		if (models[i] == ODP_ML_MODEL_INVALID) {
			ODPH_ERR("ML model create failed: %u / %u\n", i, max_models);
			break;
		}
	}

	CU_ASSERT(i == max_models);
	max_models = i;

	/* Destroy valid models */
	for (i = 0; i < max_models; i++)
		CU_ASSERT_FATAL(odp_ml_model_destroy(models[i]) == 0);
}

static void test_ml_model_lookup(void)
{
	odp_ml_model_t model2;
	odp_ml_model_t model_lookup;

	/* Look up model with the same name, should find one with equal handle */
	model_lookup = odp_ml_model_lookup(MODEL_NAME);
	CU_ASSERT_FATAL(model_lookup != ODP_ML_MODEL_INVALID);
	CU_ASSERT(odp_ml_model_to_u64(global.ml_model) == odp_ml_model_to_u64(model_lookup));

	/* Look up model with a different name, should return invalid handle */
	model_lookup = odp_ml_model_lookup("diff");
	CU_ASSERT_FATAL(model_lookup == ODP_ML_MODEL_INVALID);

	model2 = odp_ml_model_create(MODEL_NAME, &global.model_param);
	CU_ASSERT_FATAL(model2 != ODP_ML_MODEL_INVALID);
	CU_ASSERT(odp_ml_model_to_u64(global.ml_model) != odp_ml_model_to_u64(model2));

	model_lookup = odp_ml_model_lookup(MODEL_NAME);
	CU_ASSERT(odp_ml_model_to_u64(model_lookup) == odp_ml_model_to_u64(global.ml_model) ||
		  odp_ml_model_to_u64(model_lookup) == odp_ml_model_to_u64(model2));

	CU_ASSERT(odp_ml_model_destroy(model2) == 0);
}

static void test_ml_model_info(void)
{
	int ret;
	uint32_t num_ret;
	odp_ml_model_info_t ml_info;
	odp_ml_input_info_t input_info[2];
	odp_ml_output_info_t output_info[2];

	memset(&ml_info, 0x88, sizeof(odp_ml_model_info_t));
	ret = odp_ml_model_info(global.ml_model, &ml_info);
	CU_ASSERT(ret == 0);
	CU_ASSERT(!strcmp(ml_info.name, MODEL_NAME));
	CU_ASSERT(ml_info.num_inputs == NUM_INPUTS);
	CU_ASSERT(ml_info.num_outputs == NUM_OUTPUTS);

	num_ret = odp_ml_model_input_info(global.ml_model, input_info, NUM_INPUTS);
	CU_ASSERT(num_ret == NUM_INPUTS);
	CU_ASSERT(!strcmp(input_info[0].name, "single_input"));
	CU_ASSERT(input_info[0].shape.num_dim == 4);
	CU_ASSERT(input_info[0].shape.dim[0] == ODP_ML_DIM_DYNAMIC);
	CU_ASSERT(input_info[0].shape.dim[1] == 1);
	CU_ASSERT(input_info[0].shape.dim[2] == 1);
	CU_ASSERT(input_info[0].shape.dim[3] == INP_ELEMS);
	CU_ASSERT((int)input_info[0].data_type == ODP_ML_DATA_TYPE_FP16);

	/* When num is 0, return normally, and input_info is ignored */
	num_ret = odp_ml_model_input_info(global.ml_model, input_info, 0);
	CU_ASSERT(num_ret == NUM_INPUTS);

	/* When num is bigger than actual number of inputs, extra input_info is left untouched */
	input_info[1].data_type = (odp_ml_data_type_t)-1;
	num_ret = odp_ml_model_input_info(global.ml_model, input_info, NUM_INPUTS + 1);
	CU_ASSERT(num_ret == NUM_INPUTS);
	CU_ASSERT(!strcmp(input_info[0].name, "single_input"));
	CU_ASSERT(input_info[0].shape.num_dim == 4);
	CU_ASSERT(input_info[0].shape.dim[0] == ODP_ML_DIM_DYNAMIC);
	CU_ASSERT(input_info[0].shape.dim[1] == 1);
	CU_ASSERT(input_info[0].shape.dim[2] == 1);
	CU_ASSERT(input_info[0].shape.dim[3] == INP_ELEMS);
	CU_ASSERT((int)input_info[0].data_type == ODP_ML_DATA_TYPE_FP16);
	/* input_info[1] is left untouched */
	CU_ASSERT(input_info[1].data_type == (odp_ml_data_type_t)-1);

	num_ret = odp_ml_model_output_info(global.ml_model, output_info, NUM_OUTPUTS);
	CU_ASSERT(num_ret == NUM_OUTPUTS);
	CU_ASSERT(!strcmp(output_info[0].name, "Y"));
	CU_ASSERT(output_info[0].shape.num_dim == 1);
	CU_ASSERT(output_info[0].shape.dim[0] == OUT_ELEMS);
	CU_ASSERT((int)output_info[0].data_type == ODP_ML_DATA_TYPE_FP16);

	/* When num is 0, return normally, and input_info is ignored */
	num_ret = odp_ml_model_output_info(global.ml_model, output_info, 0);
	CU_ASSERT(num_ret == NUM_OUTPUTS);

	/* When num is bigger than actual number of inputs, extra output_info is left untouched */
	num_ret = odp_ml_model_output_info(global.ml_model, output_info, NUM_OUTPUTS + 1);
	output_info[1].shape.num_dim = 98876;
	CU_ASSERT(num_ret == NUM_OUTPUTS);
	CU_ASSERT(!strcmp(output_info[0].name, "Y"));
	CU_ASSERT(output_info[0].shape.num_dim == 1);
	CU_ASSERT(output_info[0].shape.dim[0] == OUT_ELEMS);
	CU_ASSERT((int)output_info[0].data_type == ODP_ML_DATA_TYPE_FP16);
	/* output_info[1] is left untouched */
	CU_ASSERT(output_info[1].shape.num_dim == 98876);
}

static void test_ml_model_load(void)
{
	int ret;
	odp_ml_model_t test_model;
	odp_ml_load_result_t result;

	test_model = odp_ml_model_create(NULL, &global.model_param);
	CU_ASSERT_FATAL(test_model != ODP_ML_MODEL_INVALID);

	ret = odp_ml_model_load(test_model, &result);
	CU_ASSERT(ret == 0);
	CU_ASSERT(result.error_code == 0);

	ret = odp_ml_model_unload(test_model, NULL);
	CU_ASSERT(ret == 0);

	CU_ASSERT(odp_ml_model_destroy(test_model) == 0);
}

/* Test asynchronous model loading in ODP_ML_COMPL_MODE_POLL mode */
static void test_ml_model_load_async_poll(void)
{
	int ret;
	odp_ml_load_result_t result;
	odp_ml_compl_param_t compl_param;
	int dummy = 6;
	void *user_ptr = &dummy;
	uint64_t wait_ns = 500 * ODP_TIME_MSEC_IN_NS;

	memset(&result, 0, sizeof(result));
	odp_ml_compl_param_init(&compl_param);
	compl_param.mode = ODP_ML_COMPL_MODE_POLL;
	compl_param.compl_id = 0;
	compl_param.user_ptr = user_ptr;

	ret = odp_ml_model_load_start(global.ml_model, &compl_param);
	CU_ASSERT_FATAL(ret == 0);

	/* When odp_ml_model_load_start() succeeded, continue to check completion status */
	for (int i = 0; i < TIMEOUT; i++) {
		ret = odp_ml_model_load_status(global.ml_model, 0, &result);
		if (ret)
			break;

		/* ret = 0 meaning run has not finished, continue to check status */
		odp_time_wait_ns(wait_ns);
	}

	CU_ASSERT(ret > 0);
	CU_ASSERT(result.error_code == 0);
	CU_ASSERT(result.user_ptr == user_ptr);
	/* odp_ml_model_load does not modify data in user_ptr */
	if (result.user_ptr)
		CU_ASSERT(*(int *)result.user_ptr == dummy);

	ret = odp_ml_model_unload_start(global.ml_model, &compl_param);
	CU_ASSERT_FATAL(ret == 0);

	/* When odp_ml_model_unload_start() succeeded, continue to check completion
	 * status */
	for (int i = 0; i < TIMEOUT; i++) {
		ret = odp_ml_model_unload_status(global.ml_model, 0, &result);
		if (ret)
			break;

		/* ret = 0 meaning run has not finished, continue to check status */
		odp_time_wait_ns(wait_ns);
	}

	CU_ASSERT_FATAL(ret > 0);
	CU_ASSERT(result.error_code == 0);
	CU_ASSERT(result.user_ptr == user_ptr);

	/* odp_ml_model_unload does not modify data in user_ptr */
	if (result.user_ptr)
		CU_ASSERT(*(int *)result.user_ptr == dummy);
}

static int get_result_from_ml_compl_event(odp_ml_load_result_t *load_result,
					  odp_ml_run_result_t *run_result)
{
	int ret;
	odp_event_t ev;
	odp_ml_compl_t compl;
	odp_event_type_t ev_type;
	odp_queue_t from_queue = ODP_QUEUE_INVALID;
	uint64_t sched_wait = odp_schedule_wait_time(global.wait_ns);

	/* Run event scheduler to find the ml completion event */
	for (int i = 0; i < TIMEOUT; i++) {
		ev = odp_schedule(&from_queue, sched_wait);
		if (ev != ODP_EVENT_INVALID)
			break;
	}

	CU_ASSERT(ev != ODP_EVENT_INVALID);
	if (ev == ODP_EVENT_INVALID) {
		ODPH_ERR("Timeout while waiting for completion event\n");
		return -1;
	}

	ev_type = odp_event_type(ev);
	CU_ASSERT(from_queue == global.queue);
	CU_ASSERT(ev_type == ODP_EVENT_ML_COMPL);
	if (from_queue != global.queue || ev_type != ODP_EVENT_ML_COMPL) {
		odp_event_free(ev);
		ODPH_ERR("Received unexpected event while waiting for completion\n");
		return -1;
	}

	compl = odp_ml_compl_from_event(ev);
	CU_ASSERT(compl != ODP_ML_COMPL_INVALID);

	if (load_result) {
		CU_ASSERT(odp_ml_compl_load_result(compl, NULL) == 0);
		ret = odp_ml_compl_load_result(compl, load_result);
	} else {
		CU_ASSERT(odp_ml_compl_run_result(compl, NULL) == 0);
		ret = odp_ml_compl_run_result(compl, run_result);
	}

	CU_ASSERT(ret == 0);
	odp_ml_compl_free(compl);

	return ret;
}

/* Test asynchronous model loading in ODP_ML_COMPL_MODE_EVENT mode */
static void test_ml_model_load_async_event(void)
{
	int ret;
	odp_ml_compl_t compl;
	odp_ml_load_result_t result;
	odp_ml_compl_param_t compl_param;
	int dummy = 6;
	void *user_ptr = &dummy;

	compl = odp_ml_compl_alloc(global.compl_pool);
	CU_ASSERT_FATAL(compl != ODP_ML_COMPL_INVALID);

	odp_ml_compl_param_init(&compl_param);
	compl_param.mode = ODP_ML_COMPL_MODE_EVENT;
	compl_param.event = odp_ml_compl_to_event(compl);
	compl_param.queue = global.queue;
	compl_param.user_ptr = user_ptr;

	ret = odp_ml_model_load_start(global.ml_model, &compl_param);
	CU_ASSERT(ret == 0);

	/* Return when odp_ml_model_load_start() failed */
	if (ret) {
		odp_ml_compl_free(compl);
		ODPH_ERR("ML model odp_ml_model_load_start() failed\n");
		return;
	}

	/* Run event scheduler to find the ml completion event and verify it */
	if (get_result_from_ml_compl_event(&result, NULL))
		return;

	CU_ASSERT(result.error_code == 0);
	CU_ASSERT(result.user_ptr == user_ptr);

	/* Model load does not modify data in user_ptr */
	if (result.user_ptr)
		CU_ASSERT(*(int *)result.user_ptr == dummy);

	compl = odp_ml_compl_alloc(global.compl_pool);
	CU_ASSERT(compl != ODP_ML_COMPL_INVALID);

	if (compl == ODP_ML_COMPL_INVALID)
		return;

	compl_param.event = odp_ml_compl_to_event(compl);
	ret = odp_ml_model_unload_start(global.ml_model, &compl_param);
	CU_ASSERT_FATAL(ret == 0);

	/* Run event scheduler to find the ml completion event and verify it */
	if (get_result_from_ml_compl_event(&result, NULL))
		return;

	CU_ASSERT(result.error_code == 0);
	CU_ASSERT(result.user_ptr == user_ptr);

	/* odp_ml_model_unload does not modify data in user_ptr */
	if (result.user_ptr)
		CU_ASSERT(*(int *)result.user_ptr == dummy);
}

static void clear_output(void)
{
	memset(global.output, 0, sizeof(global.output));
}

static void dequantize_output(int num_inference)
{
	odp_ml_fp32_from_fp16(global.output, global.output_q, OUT_ELEMS * num_inference);
}

static int check_reference(int num_inference)
{
	int i;

	for (i = 0; i < OUT_ELEMS * num_inference; i++) {
		if (fabs(global.output[i] - global.reference[i]) / global.reference[i] > 0.01)
			return -1;
	}

	return 0;
}

static void test_ml_run_batch(int num_batch)
{
	int ret = 0;
	odp_ml_run_result_t result;
	odp_ml_run_param_t run_param;

	ret = odp_ml_model_load(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);

	/* Prepare data for running model inference */
	odp_ml_run_param_init(&run_param);

	run_param.batch_size = num_batch;
	run_param.result = &result;
	global.input_seg.size = num_batch * INP_ELEMS * sizeof(uint16_t);
	global.output_seg.size = OUT_ELEMS * sizeof(uint16_t);
	clear_output();

	ret = odp_ml_run(global.ml_model, &global.data, &run_param);
	CU_ASSERT(ret == 1);
	CU_ASSERT(!result.error_code);

	dequantize_output(1);
	CU_ASSERT(!check_reference(1));

	ret = odp_ml_model_unload(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);
}

static void test_ml_run(void)
{
	test_ml_run_batch(1);
}

static void test_ml_run_batch4(void)
{
	test_ml_run_batch(4);
}

static void test_ml_run_multi(void)
{
	int ret;
	odp_ml_data_t data[RUN_NUM];
	odp_ml_data_seg_t input_seg[RUN_NUM];
	odp_ml_data_seg_t output_seg[RUN_NUM];
	odp_ml_run_param_t param[RUN_NUM];
	odp_ml_run_result_t result[RUN_NUM];
	uint64_t wait_ns = 500 * ODP_TIME_MSEC_IN_NS;

	ret = odp_ml_model_load(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);

	odp_ml_run_param_init(&param[0]);
	param[0].batch_size = 1;
	param[0].result = &result[0];
	odp_ml_run_param_init(&param[1]);
	param[1].batch_size = 1;
	param[1].result = &result[1];

	/* Prepare data for running model inference */

	data[0].num_input_seg = NUM_INPUTS;
	data[0].input_seg = &input_seg[0];
	input_seg[0].size = INP_ELEMS * sizeof(int16_t);
	input_seg[0].addr = &(global.input_q[0]);

	data[0].num_output_seg = NUM_OUTPUTS;
	data[0].output_seg = &output_seg[0];
	output_seg[0].size = OUT_ELEMS * sizeof(int16_t);
	output_seg[0].addr = &(global.output_q[0]);

	data[1].num_input_seg = NUM_INPUTS;
	data[1].input_seg = &input_seg[1];
	input_seg[1].size = INP_ELEMS * sizeof(int16_t);
	input_seg[1].addr = &(global.input_q[INP_ELEMS]);

	data[1].num_output_seg = NUM_OUTPUTS;
	data[1].output_seg = &output_seg[1];
	output_seg[1].size = OUT_ELEMS * sizeof(int16_t);
	output_seg[1].addr = &(global.output_q[OUT_ELEMS]);

	clear_output();

	int num_completed = 0;

	for (int i = 0; i < TIMEOUT; i++) {
		ret = odp_ml_run_multi(global.ml_model, data + num_completed, param + num_completed,
				       RUN_NUM - num_completed);
		CU_ASSERT(ret >= 0);
		if (ret < 0)
			break;

		num_completed += ret;

		if (num_completed >= RUN_NUM)
			break;

		odp_time_wait_ns(wait_ns);
	}

	CU_ASSERT(num_completed == RUN_NUM);
	CU_ASSERT(!result[0].error_code);
	CU_ASSERT(!result[1].error_code);
	dequantize_output(RUN_NUM);
	CU_ASSERT(!check_reference(RUN_NUM));

	ret = odp_ml_model_unload(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);
}

/* Test asynchronous inference running in ODP_ML_COMPL_MODE_EVENT mode */
static void test_ml_model_run_async_event(void)
{
	int ret;
	void *user_ptr;
	odp_ml_compl_t compl;
	odp_ml_run_result_t result;
	odp_ml_compl_param_t compl_param;
	odp_ml_run_param_t param;

	/* Load model in order to run inference */
	ret = odp_ml_model_load(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);

	compl = odp_ml_compl_alloc(global.compl_pool);
	CU_ASSERT_FATAL(compl != ODP_ML_COMPL_INVALID);

	odp_ml_compl_param_init(&compl_param);
	compl_param.mode = ODP_ML_COMPL_MODE_EVENT;
	compl_param.event = odp_ml_compl_to_event(compl);
	compl_param.queue = global.queue;

	odp_ml_run_param_init(&param);
	param.batch_size = 1;

	/* user_ptr structure maintains the output data pointer for output retrieval */
	user_ptr = &global.output_seg;
	compl_param.user_ptr = user_ptr;

	global.input_seg.size = INP_ELEMS * sizeof(uint16_t);
	global.output_seg.size = OUT_ELEMS * sizeof(uint16_t);

	clear_output();

	ret = odp_ml_run_start(global.ml_model, &global.data, &compl_param, &param);
	CU_ASSERT_FATAL(ret == 1);

	/* Run event scheduler to find the ml completion event and verify it */
	if (get_result_from_ml_compl_event(NULL, &result))
		return;

	CU_ASSERT(!result.error_code);
	CU_ASSERT(result.user_ptr == user_ptr);
	dequantize_output(1);
	CU_ASSERT(!check_reference(1));

	/* Unload model */
	ret = odp_ml_model_unload(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);
}

/* Test asynchronous inference running in ODP_ML_COMPL_MODE_POLL mode */
static void test_ml_model_run_async_poll(void)
{
	int ret;
	void *user_ptr;
	odp_ml_run_result_t result;
	odp_ml_compl_param_t compl_param;
	odp_ml_run_param_t param;
	uint64_t wait_ns = 500 * ODP_TIME_MSEC_IN_NS;

	memset(&result, 0, sizeof(result));
	/* Load model in order to run inference */
	ret = odp_ml_model_load(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);

	odp_ml_compl_param_init(&compl_param);
	compl_param.mode = ODP_ML_COMPL_MODE_POLL;
	compl_param.compl_id = 0;

	odp_ml_run_param_init(&param);
	param.batch_size = 1;

	/* user_ptr structure maintains the output data pointer for output retrieval */
	user_ptr = &global.output_seg;
	compl_param.user_ptr = user_ptr;

	global.input_seg.size = INP_ELEMS * sizeof(uint16_t);
	global.output_seg.size = OUT_ELEMS * sizeof(uint16_t);

	clear_output();

	ret = odp_ml_run_start(global.ml_model, &global.data, &compl_param, &param);
	CU_ASSERT_FATAL(ret == 1);

	/* When odp_ml_run_start() succeeded, continue to check completion status */
	for (int i = 0; i < TIMEOUT; i++) {
		ret = odp_ml_run_status(global.ml_model, 0, &result);
		if (ret)
			break;

		/* ret = 0 meaning run has not finished, continue to check status */
		odp_time_wait_ns(wait_ns);
	}

	CU_ASSERT(ret > 0);
	CU_ASSERT(!result.error_code);
	CU_ASSERT(result.user_ptr == user_ptr);
	dequantize_output(1);
	CU_ASSERT(!check_reference(1));

	/* Unload model */
	ret = odp_ml_model_unload(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);
}

static void test_ml_run_start_multi(void)
{
	int ret;
	odp_ml_compl_t compl;
	odp_ml_data_t data[RUN_NUM];
	odp_ml_data_seg_t input_seg[RUN_NUM];
	odp_ml_data_seg_t output_seg[RUN_NUM];
	odp_ml_compl_param_t compl_param[RUN_NUM];
	odp_ml_run_param_t param[RUN_NUM];
	odp_ml_run_result_t run_result[RUN_NUM];
	uint64_t wait_ns = 500 * ODP_TIME_MSEC_IN_NS;

	/* Load model in order to run inference */
	ret = odp_ml_model_load(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);

	compl = odp_ml_compl_alloc(global.compl_pool);
	CU_ASSERT_FATAL(compl != ODP_ML_COMPL_INVALID);

	/* Prepare data for running model inference */

	data[0].num_input_seg = NUM_INPUTS;
	data[0].input_seg = &input_seg[0];
	input_seg[0].size = INP_ELEMS * sizeof(int16_t);
	input_seg[0].addr = &(global.input_q[0]);

	data[0].num_output_seg = NUM_OUTPUTS;
	data[0].output_seg = &output_seg[0];
	output_seg[0].size = OUT_ELEMS * sizeof(int16_t);
	output_seg[0].addr = &(global.output_q[0]);

	data[1].num_input_seg = NUM_INPUTS;
	data[1].input_seg = &input_seg[1];
	input_seg[1].size = INP_ELEMS * sizeof(int16_t);
	input_seg[1].addr = &(global.input_q[INP_ELEMS]);

	data[1].num_output_seg = NUM_OUTPUTS;
	data[1].output_seg = &output_seg[1];
	output_seg[1].size = OUT_ELEMS * sizeof(int16_t);
	output_seg[1].addr = &(global.output_q[OUT_ELEMS]);

	clear_output();

	/* Two completion parameters: one use event mode, another poll mode */
	odp_ml_compl_param_init(&compl_param[0]);
	compl_param[0].mode = ODP_ML_COMPL_MODE_EVENT;
	compl_param[0].event = odp_ml_compl_to_event(compl);
	compl_param[0].queue = global.queue;
	/* user_ptr structure maintains the output data pointer for output retrieval */
	compl_param[0].user_ptr = &output_seg[0];

	odp_ml_compl_param_init(&compl_param[1]);
	compl_param[1].mode = ODP_ML_COMPL_MODE_POLL;
	compl_param[1].compl_id = 0;
	/* user_ptr structure maintains the output data pointer for output retrieval */
	compl_param[1].user_ptr = &output_seg[1];

	odp_ml_run_param_init(&param[0]);
	param[0].batch_size = 1;

	odp_ml_run_param_init(&param[1]);
	param[1].batch_size = 1;

	clear_output();

	int num_completed = 0;

	for (int i = 0; i < TIMEOUT; i++) {
		ret = odp_ml_run_start_multi(global.ml_model, data + num_completed,
					     compl_param + num_completed, param + num_completed,
					     RUN_NUM - num_completed);
		CU_ASSERT(ret >= 0);
		if (ret < 0)
			break;

		num_completed += ret;

		if (num_completed >= RUN_NUM)
			break;

		odp_time_wait_ns(wait_ns);
	}

	CU_ASSERT(num_completed == RUN_NUM);

	/* Run event scheduler to find the ml completion event and verify it */
	if (get_result_from_ml_compl_event(NULL, &run_result[0])) {
		ret = odp_ml_model_unload(global.ml_model, NULL);
		return;
	}

	CU_ASSERT(!run_result[0].error_code);
	CU_ASSERT(run_result[0].user_ptr == &output_seg[0]);

	/* Check completion status for the poll mode */
	for (int i = 0; i < TIMEOUT; i++) {
		ret = odp_ml_run_status(global.ml_model, 0, &run_result[1]);
		if (ret)
			break;

		/* ret = 0 meaning run has not finished, continue to check status */
		odp_time_wait_ns(wait_ns);
	}

	CU_ASSERT(ret > 0);
	CU_ASSERT(!run_result[1].error_code);
	CU_ASSERT(run_result[1].user_ptr == &output_seg[1]);
	dequantize_output(RUN_NUM);
	CU_ASSERT(!check_reference(RUN_NUM));

	/* Unload model */
	ret = odp_ml_model_unload(global.ml_model, NULL);
	CU_ASSERT_FATAL(ret == 0);
}

static void test_ml_model_extra_stats(void)
{
	int num = odp_ml_model_extra_stat_info(global.ml_model, NULL, 0);

	CU_ASSERT(num >= 0);
	CU_ASSERT(odp_ml_model_extra_stats(global.ml_model, NULL, 0) == num);

	if (num > 0) {
		odp_ml_extra_stat_info_t xinfo[num];
		uint64_t xstats[num];

		CU_ASSERT(odp_ml_model_extra_stat_info(global.ml_model, xinfo, num) == num);
		CU_ASSERT(odp_ml_model_extra_stats(global.ml_model, xstats, num) == num);

		printf("  Extra stats\n");
		for (int i = 0; i < num; i++)
			printf("    %s: %" PRIu64 "\n", xinfo[i].name, xstats[i]);
	}
}

odp_testinfo_t ml_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_create, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_lookup, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_info, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_load, check_load_sync),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_load_async_poll, check_load_poll),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_load_async_event, check_load_event),
	/* Synchronous load/unload is used load/unload model before/after model run */
	ODP_TEST_INFO_CONDITIONAL(test_ml_run, check_run_sync),
	ODP_TEST_INFO_CONDITIONAL(test_ml_run_batch4, check_run_sync),
	ODP_TEST_INFO_CONDITIONAL(test_ml_run_multi, check_run_sync),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_run_async_event, check_run_event),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_run_async_poll, check_run_poll),
	ODP_TEST_INFO_CONDITIONAL(test_ml_run_start_multi, check_run_poll_event),
	ODP_TEST_INFO_CONDITIONAL(test_ml_debug, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_model_extra_stats, check_ml_support),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t ml_suites[] = {
	{"ML", ml_suite_init, ml_suite_term, ml_suite},
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(ml_suites);

	if (argc < 2) {
		ODPH_ERR("Model file name is not provided\n");
		return -1;
	}

	memset(&global, 0, sizeof(global_t));

	if (fill_model_param(argv[1], &global.model_param))
		return -1;

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}
