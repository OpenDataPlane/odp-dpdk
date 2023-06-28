/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2019-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/deprecated.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/std.h>
#include <odp/api/thread.h>
#include <odp/api/ticketlock.h>
#include <odp/api/time.h>
#include <odp/api/timer.h>

#include <odp/api/plat/queue_inlines.h>
#include <odp/api/plat/timer_inlines.h>

#include <odp/api/plat/timer_inline_types.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_pool_internal.h>
#include <odp_print_internal.h>
#include <odp_queue_if.h>
#include <odp_ring_u32_internal.h>
#include <odp_thread_internal.h>
#include <odp_timer_internal.h>

#include <rte_cycles.h>
#include <rte_timer.h>

#include <inttypes.h>
#include <string.h>

/* One divided by one nanosecond in Hz */
#define GIGA_HZ 1000000000

/* Timer states */
#define NOT_TICKING 0
#define EXPIRED     1
#define TICKING     2

/* One second in nanoseconds */
#define SEC_IN_NS ((uint64_t)1000000000)

/* Maximum number of timer pools */
#define MAX_TIMER_POOLS  8

/* Maximum ring size for storing timer pool timers. Must be a power of two. */
#define MAX_TIMER_RING_SIZE (32 * 1024)

/* Maximum number of timers per timer pool. Validation test expects 2000 timers
 * per thread and up to 32 threads. */
#define MAX_TIMERS (MAX_TIMER_RING_SIZE - 1)

ODP_STATIC_ASSERT(MAX_TIMERS < MAX_TIMER_RING_SIZE,
		  "MAX_TIMER_RING_SIZE too small");

/* Special expiration tick used for detecting final periodic timer events */
#define PERIODIC_CANCELLED  ((uint64_t)0xFFFFFFFFFFFFFFFF)

/* Max timeout in capability. One year in nsec (0x0070 09D3 2DA3 0000). */
#define MAX_TMO_NS       (365 * 24 * 3600 * ODP_TIME_SEC_IN_NS)

/* Actual resolution depends on application polling frequency. Promise
 * 10 usec resolution. */
#define MAX_RES_NS       10000
#define MAX_RES_HZ       (GIGA_HZ / MAX_RES_NS)

/* Limit minimum supported timeout in timer (CPU) cycles. Timer setup, polling,
 * timer management, timeout enqueue, etc takes about this many CPU cycles.
 * It does not make sense to set up shorter timeouts than this. */
#define MIN_TMO_CYCLES   2000

/* Duration of a spin loop */
#define WAIT_SPINS 30

/* Minimum periodic timer base frequency */
#define MIN_BASE_HZ 1

/* Maximum periodic timer base frequency */
#define MAX_BASE_HZ MAX_RES_HZ

/* Maximum periodic timer multiplier */
#define MAX_MULTIPLIER 1000000

/* Maximum number of periodic timers per pool */
#define MAX_PERIODIC_TIMERS 100

/* Periodic tick fractional part accumulator size */
#define ACC_SIZE (1ull << 32)

typedef struct {
	odp_ticketlock_t     lock;
	uint64_t             tick;
	const void          *user_ptr;
	odp_queue_t          queue;
	odp_event_t          tmo_event;
	struct timer_pool_s *timer_pool;
	int                  state;
	uint32_t             timer_idx;

	/* Period of periodic timer in ticks, includes PERIODIC_CANCELLED flag. */
	uint64_t             periodic_ticks;
	/* Periodic ticks fractional part. */
	uint32_t periodic_ticks_frac;
	/* Periodic ticks fractional part accumulator. */
	uint32_t periodic_ticks_frac_acc;

	struct rte_timer     rte_timer;

} timer_entry_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef struct timer_pool_s {
	timer_entry_t timer[MAX_TIMER_RING_SIZE];

	struct {
		uint32_t ring_mask;

		ring_u32_t ring_hdr;
		uint32_t ring_data[MAX_TIMER_RING_SIZE];

	} free_timer;

	odp_timer_pool_param_t param;
	char name[ODP_TIMER_POOL_NAME_LEN + 1];
	int used;
	odp_ticketlock_t lock;
	uint32_t cur_timers;
	uint32_t hwm_timers;
	double base_freq;
	uint64_t max_multiplier;
	uint8_t periodic;

} timer_pool_t;
#pragma GCC diagnostic pop

/* Wrappers for alternative DPDK timer implementation */
typedef int (*timer_stop_fn)(struct rte_timer *tim);
typedef int (*timer_manage_fn)(void);
typedef int (*timer_reset_fn)(struct rte_timer *tim, uint64_t ticks,
			      enum rte_timer_type type, unsigned int tim_lcore,
			      rte_timer_cb_t fct, void *arg);

typedef struct timer_ops_t {
	timer_stop_fn   stop;
	timer_manage_fn manage;
	timer_reset_fn  reset;
} timer_ops_t;

typedef struct {
	timer_pool_t timer_pool[MAX_TIMER_POOLS];
	odp_shm_t shm;
	odp_ticketlock_t lock;
	volatile uint64_t wait_counter;
	uint64_t poll_interval_nsec;
	odp_time_t poll_interval_time;
	int num_timer_pools;
	int poll_interval;
	uint32_t data_id;
	uint8_t use_alternate;
	timer_ops_t ops;

} timer_global_t;

typedef struct timer_local_t {
	odp_time_t   last_run;
	uint64_t     thrmask_epoch;
	int          run_cnt;
	int          num_poll_cores;
	unsigned int poll_cores[ODP_THREAD_COUNT_MAX];

} timer_local_t;

/* Points to timer global data */
static timer_global_t *timer_global;

/* Timer thread local data */
static __thread timer_local_t timer_local;

#include <odp/visibility_begin.h>

/* Fill in timeout header field offsets for inline functions */
const _odp_timeout_inline_offset_t
_odp_timeout_inline_offset ODP_ALIGNED_CACHE = {
	.expiration = offsetof(odp_timeout_hdr_t, expiration),
	.timer = offsetof(odp_timeout_hdr_t, timer),
	.user_ptr = offsetof(odp_timeout_hdr_t, user_ptr),
	.uarea_addr = offsetof(odp_timeout_hdr_t, uarea_addr)
};

#include <odp/visibility_end.h>

static void timer_cb(struct rte_timer *rte_timer, void *arg ODP_UNUSED)
{
	timer_entry_t *timer = rte_timer->arg;
	odp_event_t event;
	odp_queue_t queue;

	odp_ticketlock_lock(&timer->lock);

	if (timer->state != TICKING) {
		_ODP_ERR("Timer has been cancelled or freed.\n");
		odp_ticketlock_unlock(&timer->lock);
		return;
	}

	queue = timer->queue;
	event = timer->tmo_event;
	timer->state = EXPIRED;

	if (!timer->timer_pool->periodic)
		timer->tmo_event = ODP_EVENT_INVALID;

	odp_ticketlock_unlock(&timer->lock);

	if (odp_unlikely(odp_queue_enq(queue, event))) {
		_ODP_ERR("Timeout event enqueue failed.\n");
		odp_event_free(event);
	}
}

static void timer_alt_manage_cb(struct rte_timer *rte_timer)
{
	timer_cb(rte_timer, NULL);
}

static inline int timer_stop(struct rte_timer *tim)
{
	return rte_timer_stop(tim);
}

static inline int timer_alt_stop(struct rte_timer *tim)
{
	return rte_timer_alt_stop(timer_global->data_id, tim);
}

static inline int timer_manage(void)
{
	return rte_timer_manage();
}

static inline int timer_alt_manage(void)
{
	uint64_t thrmask_epoch = _odp_thread_thrmask_epoch();

	if (odp_unlikely(timer_local.thrmask_epoch != thrmask_epoch)) {
		int cpu_ids = _odp_thread_cpu_ids(timer_local.poll_cores,
							ODP_THREAD_COUNT_MAX);

		timer_local.num_poll_cores = cpu_ids;
		timer_local.thrmask_epoch = thrmask_epoch;
	}

	return rte_timer_alt_manage(timer_global->data_id,
				    timer_local.poll_cores,
				    timer_local.num_poll_cores,
				    timer_alt_manage_cb);
}

static inline int timer_reset(struct rte_timer *tim, uint64_t ticks,
			      enum rte_timer_type type, unsigned int tim_lcore,
			      rte_timer_cb_t fct, void *arg)
{
	return rte_timer_reset(tim, ticks, type, tim_lcore, fct, arg);
}

static inline  int timer_alt_reset(struct rte_timer *tim, uint64_t ticks,
				   enum rte_timer_type type,
				   unsigned int tim_lcore, rte_timer_cb_t fct,
				   void *arg)
{
	return rte_timer_alt_reset(timer_global->data_id, tim, ticks, type,
				   tim_lcore, fct, arg);
}

static inline timer_pool_t *timer_pool_from_hdl(odp_timer_pool_t hdl)
{
	return (timer_pool_t *)(uintptr_t)hdl;
}

static inline odp_timer_pool_t timer_pool_to_hdl(timer_pool_t *tp)
{
	return (odp_timer_pool_t)tp;
}

static inline timer_entry_t *timer_from_hdl(odp_timer_t timer_hdl)
{
	return (timer_entry_t *)(uintptr_t)timer_hdl;
}

static uint64_t max_multiplier_capa(double freq)
{
	uint64_t mult;

	if (freq < MIN_BASE_HZ)
		return 0;

	mult = MAX_BASE_HZ / freq;
	if (mult > MAX_MULTIPLIER)
		mult = MAX_MULTIPLIER;

	return mult;
}

int _odp_timer_init_global(const odp_init_t *params)
{
	odp_shm_t shm;
	const char *conf_str;
	int val = 0;

	/* Timers are not polled until at least one timer pool has been
	 * created. */
	odp_global_rw->inline_timers = false;

	if (params && params->not_used.feat.timer) {
		timer_global = NULL;
		return 0;
	}

	shm = odp_shm_reserve("_odp_timer_global", sizeof(timer_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		_ODP_ERR("Global data alloc (%zu bytes) failed\n", sizeof(timer_global_t));
		return -1;
	}

	timer_global = odp_shm_addr(shm);
	memset(timer_global, 0, sizeof(timer_global_t));

	timer_global->shm = shm;
	odp_ticketlock_init(&timer_global->lock);

	_ODP_PRINT("\nTimer config:\n");

	conf_str =  "timer.inline_poll_interval";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->poll_interval = val;
	_ODP_PRINT("  %s: %d\n", conf_str, val);

	conf_str =  "timer.inline_poll_interval_nsec";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->poll_interval_nsec = val;
	timer_global->poll_interval_time =
		odp_time_global_from_ns(timer_global->poll_interval_nsec);
	_ODP_PRINT("  %s: %d\n", conf_str, val);

	conf_str =  "timer.alternate";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->use_alternate = !!val;
	_ODP_PRINT("  %s: %" PRIu8 "\n", conf_str, timer_global->use_alternate);

	_ODP_PRINT("\n");

	if (rte_timer_subsystem_init()) {
		_ODP_ERR("Initializing  DPDK timer library failed\n");
		odp_shm_free(shm);
		return -1;
	}

	if (timer_global->use_alternate) {
		if (rte_timer_data_alloc(&timer_global->data_id)) {
			_ODP_ERR("Failed to allocate DPDK timer data instance\n");
			odp_shm_free(shm);
			return -1;
		}
		timer_global->ops.stop = timer_alt_stop;
		timer_global->ops.manage = timer_alt_manage;
		timer_global->ops.reset = timer_alt_reset;
	} else {
		timer_global->ops.stop = timer_stop;
		timer_global->ops.manage = timer_manage;
		timer_global->ops.reset = timer_reset;
	}

	return 0;
}

int _odp_timer_term_global(void)
{
	if (timer_global && timer_global->use_alternate) {
		if (rte_timer_data_dealloc(timer_global->data_id)) {
			_ODP_ERR("Failed to deallocate DPDK timer data instance\n");
			return -1;
		}
	}
	rte_timer_subsystem_finalize();

	if (timer_global && odp_shm_free(timer_global->shm)) {
		_ODP_ERR("Shm free failed for odp_timer\n");
		return -1;
	}

	return 0;
}

int _odp_timer_init_local(void)
{
	timer_local.last_run = odp_time_global_from_ns(0);
	timer_local.run_cnt = 1;

	return 0;
}

int _odp_timer_term_local(void)
{
	return 0;
}

void _odp_timer_run_inline(int dec)
{
	int poll_interval = timer_global->poll_interval;
	odp_time_t now;
	int ret;

	/* Rate limit how often this thread checks the timer pools. */

	if (poll_interval > 1) {
		timer_local.run_cnt -= dec;
		if (timer_local.run_cnt > 0)
			return;
		timer_local.run_cnt = poll_interval;
	}

	now = odp_time_global();

	if (poll_interval > 1) {
		odp_time_t period = odp_time_diff(now, timer_local.last_run);

		if (odp_time_cmp(period, timer_global->poll_interval_time) < 0)
			return;
		timer_local.last_run = now;
	}

	/* Check timer pools */
	ret = timer_global->ops.manage();
	if (odp_unlikely(ret))
		_ODP_ERR("RTE timer manage failed: %d\n", ret);
}

static inline uint64_t tmo_ticks_to_ns_round_up(uint64_t tmo_ticks)
{
	uint64_t tmo_ns = odp_timer_tick_to_ns(NULL, tmo_ticks);

	/* Make sure the ns value will not be rounded down when converted back
	 * to ticks. */
	while (odp_timer_ns_to_tick(NULL, tmo_ns) < tmo_ticks)
		tmo_ns++;

	return tmo_ns;
}

int odp_timer_capability(odp_timer_clk_src_t clk_src,
			 odp_timer_capability_t *capa)
{
	uint64_t min_tmo = tmo_ticks_to_ns_round_up(MIN_TMO_CYCLES);

	if (clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	memset(capa, 0, sizeof(odp_timer_capability_t));

	capa->max_pools_combined = MAX_TIMER_POOLS;
	capa->max_pools = MAX_TIMER_POOLS;
	capa->max_timers = MAX_TIMERS;
	capa->periodic.max_pools  = MAX_TIMER_POOLS;
	capa->periodic.max_timers = MAX_PERIODIC_TIMERS;
	capa->highest_res_ns = MAX_RES_NS;
	capa->max_res.res_ns  = MAX_RES_NS;
	capa->max_res.res_hz  = MAX_RES_HZ;
	capa->max_res.min_tmo = min_tmo;
	capa->max_res.max_tmo = MAX_TMO_NS;
	capa->max_tmo.res_ns  = MAX_RES_NS;
	capa->max_tmo.res_hz  = MAX_RES_HZ;
	capa->max_tmo.min_tmo = min_tmo;
	capa->max_tmo.max_tmo = MAX_TMO_NS;
	capa->queue_type_sched = true;
	capa->queue_type_plain = true;

	capa->periodic.min_base_freq_hz.integer = MIN_BASE_HZ;
	capa->periodic.max_base_freq_hz.integer = MAX_BASE_HZ;

	return 0;
}

int odp_timer_res_capability(odp_timer_clk_src_t clk_src,
			     odp_timer_res_capability_t *res_capa)
{
	uint64_t min_tmo = tmo_ticks_to_ns_round_up(MIN_TMO_CYCLES);

	if (clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	if (res_capa->min_tmo) {
		_ODP_ERR("Only res_ns or max_tmo based queries supported\n");
		return -1;
	}

	if (res_capa->res_ns || res_capa->res_hz) {
		if (res_capa->res_ns && res_capa->res_ns < MAX_RES_NS) {
			_ODP_DBG("Timeout resolution capability (res_ns) exceeded\n");
			return -1;
		}
		if (res_capa->res_hz && res_capa->res_hz > MAX_RES_HZ) {
			_ODP_DBG("Timeout resolution capability (res_hz) exceeded\n");
			return -1;
		}
		res_capa->min_tmo = min_tmo;
		res_capa->max_tmo = MAX_TMO_NS;
	} else { /* max_tmo */
		if (res_capa->max_tmo > MAX_TMO_NS) {
			_ODP_DBG("Maximum relative timeout capability (max_tmo) exceeded\n");
			return -1;
		}
		res_capa->min_tmo = min_tmo;
		res_capa->res_ns  = MAX_RES_NS;
		res_capa->res_hz = MAX_RES_HZ;
	}

	return 0;
}

int odp_timer_periodic_capability(odp_timer_clk_src_t clk_src,
				  odp_timer_periodic_capability_t *capa)
{
	double freq;
	uint64_t multiplier;

	if (clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	freq = odp_fract_u64_to_dbl(&capa->base_freq_hz);
	if (freq < MIN_BASE_HZ || freq > MAX_BASE_HZ) {
		_ODP_ERR("Base frequency not supported (min: %f, max %f)\n",
			 (double)MIN_BASE_HZ, (double)MAX_BASE_HZ);
		return -1;
	}

	multiplier = max_multiplier_capa(freq);

	if (capa->max_multiplier > multiplier)
		return -1;

	if (capa->res_ns && capa->res_ns < MAX_RES_NS)
		return -1;

	/* Update capa with supported values */
	capa->max_multiplier = multiplier;
	capa->res_ns = MAX_RES_NS;

	/* All base frequencies within the range are supported */
	return 1;
}

void odp_timer_pool_param_init(odp_timer_pool_param_t *param)
{
	memset(param, 0, sizeof(odp_timer_pool_param_t));
	param->timer_type = ODP_TIMER_TYPE_SINGLE;
	param->clk_src = ODP_CLOCK_DEFAULT;
	param->exp_mode = ODP_TIMER_EXP_AFTER;
}

odp_timer_pool_t odp_timer_pool_create(const char *name,
				       const odp_timer_pool_param_t *param)
{
	timer_pool_t *timer_pool;
	timer_entry_t *timer;
	uint32_t i, num_timers;
	uint64_t res_ns, nsec_per_scan;
	uint64_t max_multiplier = 0;
	double base_freq = 0.0;
	int periodic = (param->timer_type == ODP_TIMER_TYPE_PERIODIC) ? 1 : 0;

	if (odp_global_ro.init_param.not_used.feat.timer) {
		_ODP_ERR("Trying to use disabled ODP feature.\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", param->clk_src);
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->timer_type != ODP_TIMER_TYPE_SINGLE &&
	    param->timer_type != ODP_TIMER_TYPE_PERIODIC) {
		_ODP_ERR("Bad timer type %i\n", param->timer_type);
		return ODP_TIMER_POOL_INVALID;
	}

	if ((param->res_ns && param->res_hz) ||
	    (param->res_ns == 0 && param->res_hz == 0)) {
		_ODP_ERR("Invalid timeout resolution\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->res_hz == 0 && param->res_ns < MAX_RES_NS) {
		_ODP_ERR("Too high resolution\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->res_ns == 0 && param->res_hz > MAX_RES_HZ) {
		_ODP_ERR("Too high resolution\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->num_timers > MAX_TIMERS) {
		_ODP_ERR("Too many timers\n");
		return ODP_TIMER_POOL_INVALID;
	}

	num_timers = param->num_timers;

	if (param->res_ns)
		res_ns = param->res_ns;
	else
		res_ns = GIGA_HZ / param->res_hz;

	if (periodic) {
		uint64_t max_capa, min_period_ns;

		base_freq = odp_fract_u64_to_dbl(&param->periodic.base_freq_hz);
		max_multiplier = param->periodic.max_multiplier;

		if (base_freq < MIN_BASE_HZ || base_freq > MAX_BASE_HZ) {
			_ODP_ERR("Bad base frequency: %f\n", base_freq);
			return ODP_TIMER_POOL_INVALID;
		}

		max_capa = max_multiplier_capa(base_freq);

		if (max_multiplier == 0 || max_multiplier > max_capa) {
			_ODP_ERR("Bad max multiplier: %" PRIu64 "\n", max_multiplier);
			return ODP_TIMER_POOL_INVALID;
		}

		min_period_ns = GIGA_HZ / (base_freq * max_multiplier);

		if (res_ns > min_period_ns)
			res_ns = min_period_ns;
	}

	/* Scan timer pool twice during resolution interval */
	if (res_ns > ODP_TIME_USEC_IN_NS)
		nsec_per_scan = res_ns / 2;
	else
		nsec_per_scan = res_ns;

	/* Ring size must larger than param->num_timers */
	if (_ODP_CHECK_IS_POWER2(num_timers))
		num_timers++;
	num_timers = _ODP_ROUNDUP_POWER2_U32(num_timers);

	odp_ticketlock_lock(&timer_global->lock);

	if (timer_global->num_timer_pools >= MAX_TIMER_POOLS) {
		odp_ticketlock_unlock(&timer_global->lock);
		_ODP_DBG("No more free timer pools\n");
		return ODP_TIMER_POOL_INVALID;
	}

	for (i = 0; i < MAX_TIMER_POOLS; i++) {
		timer_pool = &timer_global->timer_pool[i];

		if (timer_pool->used == 0) {
			timer_pool->used = 1;
			break;
		}
	}
	timer_global->num_timer_pools++;

	/* Enable inline timer polling */
	if (timer_global->num_timer_pools == 1)
		odp_global_rw->inline_timers = true;

	/* Increase poll rate to match the highest resolution */
	if (timer_global->poll_interval_nsec > nsec_per_scan) {
		timer_global->poll_interval_nsec = nsec_per_scan;
		timer_global->poll_interval_time =
			odp_time_global_from_ns(nsec_per_scan);
	}

	odp_ticketlock_unlock(&timer_global->lock);
	if (name) {
		strncpy(timer_pool->name, name,
			ODP_TIMER_POOL_NAME_LEN);
		timer_pool->name[ODP_TIMER_POOL_NAME_LEN] = 0;
	}

	timer_pool->param = *param;
	timer_pool->param.res_ns = res_ns;

	timer_pool->periodic = periodic;
	timer_pool->base_freq = base_freq;
	timer_pool->max_multiplier = max_multiplier;

	ring_u32_init(&timer_pool->free_timer.ring_hdr);
	timer_pool->free_timer.ring_mask = num_timers - 1;

	odp_ticketlock_init(&timer_pool->lock);
	timer_pool->cur_timers = 0;
	timer_pool->hwm_timers = 0;

	for (i = 0; i < timer_pool->free_timer.ring_mask; i++) {
		timer = &timer_pool->timer[i];
		memset(timer, 0, sizeof(timer_entry_t));

		odp_ticketlock_init(&timer->lock);
		rte_timer_init(&timer->rte_timer);
		timer->rte_timer.arg = timer;
		timer->timer_pool = timer_pool;
		timer->timer_idx  = i;

		ring_u32_enq(&timer_pool->free_timer.ring_hdr,
			     timer_pool->free_timer.ring_mask, i);
	}

	return timer_pool_to_hdl(timer_pool);
}

void odp_timer_pool_start(void)
{
	/* Nothing to do */
}

void odp_timer_pool_destroy(odp_timer_pool_t tp)
{
	timer_pool_t *timer_pool = timer_pool_from_hdl(tp);

	odp_ticketlock_lock(&timer_global->lock);

	timer_pool->used = 0;
	timer_global->num_timer_pools--;

	/* Disable inline timer polling */
	if (timer_global->num_timer_pools == 0)
		odp_global_rw->inline_timers = false;

	odp_ticketlock_unlock(&timer_global->lock);
}

uint64_t odp_timer_tick_to_ns(odp_timer_pool_t tp, uint64_t ticks)
{
	uint64_t nsec;
	uint64_t freq_hz = rte_get_timer_hz();
	uint64_t sec = 0;
	(void)tp;

	if (ticks >= freq_hz) {
		sec   = ticks / freq_hz;
		ticks = ticks - sec * freq_hz;
	}

	nsec = (SEC_IN_NS * ticks) / freq_hz;

	return (sec * SEC_IN_NS) + nsec;
}

uint64_t odp_timer_ns_to_tick(odp_timer_pool_t tp, uint64_t ns)
{
	uint64_t ticks;
	uint64_t freq_hz = rte_get_timer_hz();
	uint64_t sec = 0;
	(void)tp;

	if (ns >= SEC_IN_NS) {
		sec = ns / SEC_IN_NS;
		ns  = ns - sec * SEC_IN_NS;
	}

	ticks  = sec * freq_hz;
	ticks += (ns * freq_hz) / SEC_IN_NS;

	return ticks;
}

uint64_t odp_timer_current_tick(odp_timer_pool_t tp)
{
	(void)tp;

	return rte_get_timer_cycles();
}

int odp_timer_pool_info(odp_timer_pool_t tp,
			odp_timer_pool_info_t *info)
{
	timer_pool_t *timer_pool;
	uint64_t freq_hz = rte_get_timer_hz();

	if (odp_unlikely(tp == ODP_TIMER_POOL_INVALID)) {
		_ODP_ERR("Invalid timer pool.\n");
		return -1;
	}

	timer_pool = timer_pool_from_hdl(tp);

	memset(info, 0, sizeof(odp_timer_pool_info_t));
	info->param      = timer_pool->param;
	info->cur_timers = timer_pool->cur_timers;
	info->hwm_timers = timer_pool->hwm_timers;
	info->name       = timer_pool->name;

	info->tick_info.freq.integer = freq_hz;
	info->tick_info.nsec.integer = SEC_IN_NS / freq_hz;
	if (SEC_IN_NS % freq_hz) {
		info->tick_info.nsec.numer = SEC_IN_NS - (info->tick_info.nsec.integer * freq_hz);
		info->tick_info.nsec.denom = freq_hz;
	}
	/* Leave source clock information to zero as there is no direct link
	 * between a source clock signal and a timer tick. */

	return 0;
}

uint64_t odp_timer_pool_to_u64(odp_timer_pool_t tp)
{
	return _odp_pri(tp);
}

odp_timer_t odp_timer_alloc(odp_timer_pool_t tp,
			    odp_queue_t queue,
			    const void *user_ptr)
{
	uint32_t timer_idx;
	timer_entry_t *timer;
	timer_pool_t *timer_pool = timer_pool_from_hdl(tp);

	if (odp_unlikely(tp == ODP_TIMER_POOL_INVALID)) {
		_ODP_ERR("Invalid timer pool.\n");
		return ODP_TIMER_INVALID;
	}

	if (odp_unlikely(queue == ODP_QUEUE_INVALID)) {
		_ODP_ERR("%s: Invalid queue handle.\n", timer_pool->name);
		return ODP_TIMER_INVALID;
	}

	if (ring_u32_deq(&timer_pool->free_timer.ring_hdr,
			 timer_pool->free_timer.ring_mask,
			 &timer_idx) == 0)
		return ODP_TIMER_INVALID;

	timer = &timer_pool->timer[timer_idx];

	timer->state     = NOT_TICKING;
	timer->user_ptr  = user_ptr;
	timer->queue     = queue;
	timer->tmo_event = ODP_EVENT_INVALID;

	/* Add timer to queue */
	_odp_queue_fn->timer_add(queue);

	odp_ticketlock_lock(&timer_pool->lock);

	timer_pool->cur_timers++;

	if (timer_pool->cur_timers > timer_pool->hwm_timers)
		timer_pool->hwm_timers = timer_pool->cur_timers;

	odp_ticketlock_unlock(&timer_pool->lock);

	return (odp_timer_t)timer;
}

odp_event_t odp_timer_free(odp_timer_t timer_hdl)
{
	odp_event_t ev;
	timer_entry_t *timer = timer_from_hdl(timer_hdl);
	timer_pool_t *timer_pool = timer->timer_pool;
	uint32_t timer_idx = timer->timer_idx;

retry:
	odp_ticketlock_lock(&timer->lock);

	if (timer->state == TICKING) {
		_ODP_DBG("Freeing active timer.\n");

		if (timer_global->ops.stop(&timer->rte_timer)) {
			/* Another core runs timer callback function. */
			odp_ticketlock_unlock(&timer->lock);
			goto retry;
		}

		ev = timer->tmo_event;
		timer->tmo_event = ODP_EVENT_INVALID;
		timer->state = NOT_TICKING;
	} else {
		ev = ODP_EVENT_INVALID;
	}

	/* Remove timer from queue */
	_odp_queue_fn->timer_rem(timer->queue);

	odp_ticketlock_unlock(&timer->lock);

	odp_ticketlock_lock(&timer_pool->lock);

	timer_pool->cur_timers--;

	odp_ticketlock_unlock(&timer_pool->lock);

	ring_u32_enq(&timer_pool->free_timer.ring_hdr,
		     timer_pool->free_timer.ring_mask, timer_idx);

	return ev;
}

static inline odp_timeout_hdr_t *timeout_to_hdr(odp_timeout_t tmo)
{
	return (odp_timeout_hdr_t *)(uintptr_t)tmo;
}

static inline int timer_set(odp_timer_t timer_hdl, uint64_t tick,
			    odp_event_t *event, int absolute)
{
	odp_event_t old_ev, tmo_event;
	uint64_t cur_tick, rel_tick, abs_tick;
	timer_entry_t *timer = timer_from_hdl(timer_hdl);
	int num_retry = 0;
	unsigned int lcore = rte_lcore_id();

retry:
	cur_tick = rte_get_timer_cycles();

	if (absolute) {
		abs_tick = tick;
		rel_tick = abs_tick - cur_tick;

		if (odp_unlikely(abs_tick < cur_tick))
			rel_tick = 0;
	} else {
		rel_tick = tick;
		abs_tick = rel_tick + cur_tick;
	}

	if (rel_tick < MIN_TMO_CYCLES) {
		_ODP_DBG("Too early\n");
		_ODP_DBG("  cur_tick %" PRIu64 ", abs_tick %" PRIu64 "\n", cur_tick, abs_tick);
		_ODP_DBG("  num_retry %i\n", num_retry);
		return ODP_TIMER_TOO_NEAR;
	}

	odp_ticketlock_lock(&timer->lock);

	if (timer->tmo_event == ODP_EVENT_INVALID)
		if (event == NULL || (event && *event == ODP_EVENT_INVALID)) {
			odp_ticketlock_unlock(&timer->lock);
			/* Event missing, or timer already expired and
			 * enqueued the event. */
			return ODP_TIMER_FAIL;
	}

	if (odp_unlikely(timer_global->ops.reset(&timer->rte_timer, rel_tick,
						 SINGLE, lcore, timer_cb, timer))) {
		int do_retry = 0;

		/* Another core is currently running the callback function.
		 * State is:
		 * - TICKING, when callback has not yet started
		 * - EXPIRED, when callback has not yet finished, or this cpu
		 *            does not yet see that it has been finished
		 */

		if (timer->state == EXPIRED)
			do_retry = 1;

		odp_ticketlock_unlock(&timer->lock);

		if (do_retry) {
			/* Timer has been expired, wait and retry until DPDK on
			 * this CPU sees it. */
			int i;

			for (i = 0; i < WAIT_SPINS; i++)
				timer_global->wait_counter++;

			num_retry++;
			goto retry;
		}

		/* Timer was just about to expire. Too late to reset this timer.
		 * Return code is NOEVENT, even when application did give
		 * an event. */
		return ODP_TIMER_FAIL;
	}

	if (event) {
		old_ev = timer->tmo_event;

		if (*event != ODP_EVENT_INVALID)
			timer->tmo_event = *event;

		*event = old_ev;
	}

	tmo_event    = timer->tmo_event;
	timer->tick  = abs_tick;
	timer->state = TICKING;

	if (odp_event_type(tmo_event) == ODP_EVENT_TIMEOUT) {
		odp_timeout_hdr_t *timeout_hdr;

		timeout_hdr = timeout_to_hdr((odp_timeout_t)tmo_event);
		timeout_hdr->expiration = abs_tick;
		timeout_hdr->user_ptr   = timer->user_ptr;
		timeout_hdr->timer      = (odp_timer_t)timer;
	}

	odp_ticketlock_unlock(&timer->lock);
	return ODP_TIMER_SUCCESS;
}

int ODP_DEPRECATE(odp_timer_set_abs)(odp_timer_t timer_hdl, uint64_t abs_tick,
				     odp_event_t *tmo_ev)
{
	return timer_set(timer_hdl, abs_tick, tmo_ev, 1);
}

int ODP_DEPRECATE(odp_timer_set_rel)(odp_timer_t timer_hdl, uint64_t rel_tick,
				     odp_event_t *tmo_ev)
{
	return timer_set(timer_hdl, rel_tick, tmo_ev, 0);
}

int odp_timer_start(odp_timer_t timer, const odp_timer_start_t *start_param)
{
	odp_event_t tmo_ev = start_param->tmo_ev;
	int abs = start_param->tick_type == ODP_TIMER_TICK_ABS;
	int ret;

	ret = timer_set(timer, start_param->tick, &tmo_ev, abs);
	if (odp_unlikely(ret != ODP_TIMER_SUCCESS))
		return ret;

	/* Check that timer was not active */
	if (odp_unlikely(tmo_ev != ODP_EVENT_INVALID)) {
		_ODP_ERR("Timer was active already\n");
		odp_event_free(tmo_ev);
	}

	return ODP_TIMER_SUCCESS;
}

int odp_timer_restart(odp_timer_t timer, const odp_timer_start_t *start_param)
{
	int abs = start_param->tick_type == ODP_TIMER_TICK_ABS;

	/* Reset timer without changing the event */
	return timer_set(timer, start_param->tick, NULL, abs);
}

int odp_timer_periodic_start(odp_timer_t timer_hdl,
			     const odp_timer_periodic_start_t *start_param)
{
	uint64_t period_ns;
	uint64_t first_tick;
	odp_event_t tmo_ev = start_param->tmo_ev;
	timer_entry_t *timer = timer_from_hdl(timer_hdl);
	timer_pool_t *tp = timer->timer_pool;
	uint64_t multiplier = start_param->freq_multiplier;
	double freq = multiplier * tp->base_freq;
	double period_ns_dbl;
	int absolute;
	int ret;

	if (odp_unlikely(!tp->periodic)) {
		_ODP_ERR("Not a periodic timer\n");
		return ODP_TIMER_FAIL;
	}

	if (odp_unlikely(multiplier == 0 || multiplier > tp->max_multiplier)) {
		_ODP_ERR("Bad frequency multiplier: %" PRIu64 "\n", multiplier);
		return ODP_TIMER_FAIL;
	}

	if (odp_unlikely(odp_event_type(tmo_ev) != ODP_EVENT_TIMEOUT)) {
		_ODP_ERR("Event type is not timeout\n");
		return ODP_TIMER_FAIL;
	}

	period_ns_dbl = (double)ODP_TIME_SEC_IN_NS / freq;
	period_ns = period_ns_dbl;

	if (period_ns == 0) {
		_ODP_ERR("Too high periodic timer frequency: %f\n", freq);
		return ODP_TIMER_FAIL;
	}

	timer->periodic_ticks = odp_timer_ns_to_tick(timer_pool_to_hdl(tp), period_ns);
	timer->periodic_ticks_frac = (period_ns_dbl - period_ns) * ACC_SIZE;
	timer->periodic_ticks_frac_acc = 0;

	first_tick = timer->periodic_ticks;
	absolute = 0;

	if (start_param->first_tick) {
		first_tick = start_param->first_tick;
		absolute = 1;
	}

	ret = timer_set(timer_hdl, first_tick, &tmo_ev, absolute);
	if (odp_unlikely(ret != ODP_TIMER_SUCCESS))
		return ret;

	/* Check that timer was not active */
	if (odp_unlikely(tmo_ev != ODP_EVENT_INVALID)) {
		_ODP_ERR("Timer was active already\n");
		odp_event_free(tmo_ev);
	}

	return ODP_TIMER_SUCCESS;
}

int odp_timer_periodic_ack(odp_timer_t timer_hdl, odp_event_t tmo_ev)
{
	uint64_t abs_tick, acc;
	odp_timeout_t tmo = odp_timeout_from_event(tmo_ev);
	timer_entry_t *timer = timer_from_hdl(timer_hdl);
	odp_timeout_hdr_t *timeout_hdr;
	int ret;

	if (odp_unlikely(odp_event_type(tmo_ev) != ODP_EVENT_TIMEOUT)) {
		_ODP_ERR("Event type is not timeout\n");
		return -1;
	}

	abs_tick = timer->periodic_ticks;

	if (odp_unlikely(abs_tick == PERIODIC_CANCELLED))
		return 2;

	acc = (uint64_t)timer->periodic_ticks_frac_acc + (uint64_t)timer->periodic_ticks_frac;

	if (acc >= ACC_SIZE) {
		abs_tick++;
		acc -= ACC_SIZE;
	}

	timer->periodic_ticks_frac_acc = acc;

	timeout_hdr = timeout_to_hdr(tmo);
	abs_tick += timeout_hdr->expiration;
	timeout_hdr->expiration = abs_tick;

	ret = timer_set(timer_hdl, abs_tick, NULL, 1);
	if (odp_likely(ret == ODP_TIMER_SUCCESS))
		return 0;

	/* Send delayed timeout immediately to catch-up */
	if (ret == ODP_TIMER_TOO_NEAR) {
		if (odp_unlikely(odp_queue_enq(timer->queue, tmo_ev))) {
			_ODP_ERR("Failed to enqueue catch-up timeout event\n");
			return -1;
		}
		return 0;
	}
	_ODP_ERR("Failed to re-arm periodic timer: %d\n", ret);
	return -1;
}

int odp_timer_cancel(odp_timer_t timer_hdl, odp_event_t *tmo_ev)
{
	timer_entry_t *timer = timer_from_hdl(timer_hdl);

	odp_ticketlock_lock(&timer->lock);

	if (odp_unlikely(timer->state < TICKING)) {
		int state = timer->state;

		odp_ticketlock_unlock(&timer->lock);

		if (state == EXPIRED)
			return ODP_TIMER_TOO_NEAR;
		return ODP_TIMER_FAIL;
	}

	if (odp_unlikely(timer_global->ops.stop(&timer->rte_timer))) {
		/* Another core runs timer callback function. */
		odp_ticketlock_unlock(&timer->lock);
		return ODP_TIMER_TOO_NEAR;
	}

	*tmo_ev = timer->tmo_event;
	timer->tmo_event = ODP_EVENT_INVALID;
	timer->state = NOT_TICKING;

	odp_ticketlock_unlock(&timer->lock);
	return ODP_TIMER_SUCCESS;
}

int odp_timer_periodic_cancel(odp_timer_t timer_hdl)
{
	timer_pool_t *tp;
	timer_entry_t *timer;
	odp_event_t event;
	int ret;

	if (odp_unlikely(timer_hdl == ODP_TIMER_INVALID)) {
		_ODP_ERR("Bad timer handle\n");
		return -1;
	}

	timer = timer_from_hdl(timer_hdl);
	tp = timer->timer_pool;
	event = timer->tmo_event;

	if (odp_unlikely(!tp->periodic)) {
		_ODP_ERR("Not a periodic timer\n");
		return -1;
	}

	odp_ticketlock_lock(&timer->lock);

	ret = timer_global->ops.stop(&timer->rte_timer);

	/* Mark timer cancelled, so that a following ack call stops restarting it. */
	timer->periodic_ticks = PERIODIC_CANCELLED;

	/* Timer successfully cancelled, so send the final event manually. */
	if (ret == 0 && timer->state == TICKING) {
		timer->state = NOT_TICKING;
		if (odp_unlikely(odp_queue_enq(timer->queue, event))) {
			_ODP_ERR("Failed to enqueue final timeout event\n");
			_odp_event_free(event);
		}
	}

	odp_ticketlock_unlock(&timer->lock);

	return 0;
}

uint64_t odp_timer_to_u64(odp_timer_t timer_hdl)
{
	return (uint64_t)(uintptr_t)timer_hdl;
}

uint64_t odp_timeout_to_u64(odp_timeout_t tmo)
{
	return (uint64_t)(uintptr_t)tmo;
}

int odp_timeout_fresh(odp_timeout_t tmo)
{
	timer_entry_t *timer;
	odp_timeout_hdr_t *timeout_hdr = timeout_to_hdr(tmo);

	/* Timeout not connected to a timer */
	if (odp_unlikely(timeout_hdr->timer == ODP_TIMER_INVALID))
		return 0;

	timer = timer_from_hdl(timeout_hdr->timer);

	if (timer->timer_pool->periodic)
		return timer->periodic_ticks != PERIODIC_CANCELLED;

	/* Check if timer has been reused after timeout sent. */
	return timeout_hdr->expiration == timer->tick;
}

odp_timeout_t odp_timeout_alloc(odp_pool_t pool_hdl)
{
	odp_timeout_hdr_t *timeout_hdr;
	odp_event_t event;
	pool_t *pool;

	_ODP_ASSERT(pool_hdl != ODP_POOL_INVALID);

	pool = _odp_pool_entry(pool_hdl);

	_ODP_ASSERT(pool->type == ODP_POOL_TIMEOUT);

	event = _odp_event_alloc(pool);
	if (odp_unlikely(event == ODP_EVENT_INVALID))
		return ODP_TIMEOUT_INVALID;

	timeout_hdr = timeout_to_hdr(odp_timeout_from_event(event));
	timeout_hdr->timer = ODP_TIMER_INVALID;

	return odp_timeout_from_event(event);
}

void odp_timeout_free(odp_timeout_t tmo)
{
	_odp_event_free(odp_timeout_to_event(tmo));
}

void odp_timer_pool_print(odp_timer_pool_t timer_pool)
{
	timer_pool_t *tp;
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		_ODP_ERR("Bad timer pool handle\n");
		return;
	}

	tp = timer_pool_from_hdl(timer_pool);

	len += _odp_snprint(&str[len], n - len, "Timer pool info\n");
	len += _odp_snprint(&str[len], n - len, "---------------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_timer_pool_to_u64(timer_pool));
	len += _odp_snprint(&str[len], n - len, "  name           %s\n", tp->name);
	len += _odp_snprint(&str[len], n - len, "  num timers     %u\n", tp->cur_timers);
	len += _odp_snprint(&str[len], n - len, "  hwm timers     %u\n", tp->hwm_timers);
	len += _odp_snprint(&str[len], n - len, "  num tp         %i\n",
			    timer_global->num_timer_pools);
	len += _odp_snprint(&str[len], n - len, "  periodic       %" PRIu8 "\n", tp->periodic);
	str[len] = 0;

	_ODP_PRINT("%s\n", str);
}

void odp_timer_print(odp_timer_t timer_hdl)
{
	timer_entry_t *timer = timer_from_hdl(timer_hdl);
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (timer_hdl == ODP_TIMER_INVALID) {
		_ODP_ERR("Bad timer handle\n");
		return;
	}

	len += _odp_snprint(&str[len], n - len, "Timer info\n");
	len += _odp_snprint(&str[len], n - len, "----------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_timer_to_u64(timer_hdl));
	len += _odp_snprint(&str[len], n - len, "  timer pool     0x%" PRIx64 "\n",
			    odp_timer_pool_to_u64(timer_pool_to_hdl(timer->timer_pool)));
	len += _odp_snprint(&str[len], n - len, "  timer index    %" PRIu32 "\n", timer->timer_idx);
	len += _odp_snprint(&str[len], n - len, "  dest queue     0x%" PRIx64 "\n",
			    odp_queue_to_u64(timer->queue));
	len += _odp_snprint(&str[len], n - len, "  user ptr       %p\n", timer->user_ptr);
	len += _odp_snprint(&str[len], n - len, "  state          %s\n",
			    (timer->state == NOT_TICKING) ? "not ticking" :
			    (timer->state == EXPIRED ? "expired" : "ticking"));
	len += _odp_snprint(&str[len], n - len, "  periodic ticks %" PRIu64 "\n",
			    timer->periodic_ticks);
	str[len] = 0;

	_ODP_PRINT("%s\n", str);
}

void odp_timeout_print(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *tmo_hdr;
	odp_timer_t timer;
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (tmo == ODP_TIMEOUT_INVALID) {
		_ODP_ERR("Bad timeout handle\n");
		return;
	}

	tmo_hdr = timeout_to_hdr(tmo);
	timer = tmo_hdr->timer;

	len += _odp_snprint(&str[len], n - len, "Timeout info\n");
	len += _odp_snprint(&str[len], n - len, "------------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_timeout_to_u64(tmo));
	len += _odp_snprint(&str[len], n - len, "  expiration     %" PRIu64 "\n",
			    tmo_hdr->expiration);
	len += _odp_snprint(&str[len], n - len, "  user ptr       %p\n", tmo_hdr->user_ptr);
	len += _odp_snprint(&str[len], n - len, "  user area      %p\n", tmo_hdr->uarea_addr);

	if (timer != ODP_TIMER_INVALID) {
		timer_entry_t *timer_entry = timer_from_hdl(timer);
		timer_pool_t *tp = timer_entry->timer_pool;

		len += _odp_snprint(&str[len], n - len, "  timer pool     0x%" PRIx64 "\n",
				    odp_timer_pool_to_u64(timer_pool_to_hdl(tp)));
		len += _odp_snprint(&str[len], n - len, "  timer          0x%" PRIx64 "\n",
				    odp_timer_to_u64(timer));
		len += _odp_snprint(&str[len], n - len, "  timer index    %u\n",
				    timer_entry->timer_idx);
		len += _odp_snprint(&str[len], n - len, "  periodic       %i\n", tp->periodic);
	}
	str[len] = 0;

	_ODP_PRINT("%s\n", str);
}
