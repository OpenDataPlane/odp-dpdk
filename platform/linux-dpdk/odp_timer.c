/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2019-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/shared_memory.h>
#include <odp/api/ticketlock.h>
#include <odp/api/timer.h>
#include <odp/api/plat/queue_inlines.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_queue_if.h>
#include <odp_ring_u32_internal.h>
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

typedef struct {
	odp_ticketlock_t     lock;
	int                  state;
	uint64_t             tick;
	const void          *user_ptr;
	odp_queue_t          queue;
	odp_event_t          tmo_event;
	struct timer_pool_s *timer_pool;
	uint32_t             timer_idx;

	struct rte_timer     rte_timer;

} timer_entry_t;

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

} timer_pool_t;

typedef struct {
	timer_pool_t timer_pool[MAX_TIMER_POOLS];
	odp_shm_t shm;
	odp_ticketlock_t lock;
	volatile uint64_t wait_counter;
	uint64_t poll_interval_nsec;
	odp_time_t poll_interval_time;
	int num_timer_pools;
	int poll_interval;

} timer_global_t;

typedef struct timer_local_t {
	odp_time_t last_run;
	int        run_cnt;

} timer_local_t;

/* Points to timer global data */
static timer_global_t *timer_global;

/* Timer thread local data */
static __thread timer_local_t timer_local;

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
		ODP_ERR("Global data alloc (%zu bytes) failed\n",
			sizeof(timer_global_t));
		return -1;
	}

	timer_global = odp_shm_addr(shm);
	memset(timer_global, 0, sizeof(timer_global_t));

	timer_global->shm = shm;
	odp_ticketlock_init(&timer_global->lock);

	conf_str =  "timer.inline_poll_interval";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->poll_interval = val;

	conf_str =  "timer.inline_poll_interval_nsec";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->poll_interval_nsec = val;
	timer_global->poll_interval_time =
		odp_time_global_from_ns(timer_global->poll_interval_nsec);

	rte_timer_subsystem_init();

	return 0;
}

int _odp_timer_term_global(void)
{
	if (timer_global && odp_shm_free(timer_global->shm)) {
		ODP_ERR("Shm free failed for odp_timer\n");
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
	rte_timer_manage();
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
		ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	memset(capa, 0, sizeof(odp_timer_capability_t));

	capa->max_pools_combined = MAX_TIMER_POOLS;
	capa->max_pools = MAX_TIMER_POOLS;
	capa->max_timers = MAX_TIMERS;
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

	return 0;
}

int odp_timer_res_capability(odp_timer_clk_src_t clk_src,
			     odp_timer_res_capability_t *res_capa)
{
	uint64_t min_tmo = tmo_ticks_to_ns_round_up(MIN_TMO_CYCLES);

	if (clk_src != ODP_CLOCK_DEFAULT) {
		ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	if (res_capa->min_tmo) {
		ODP_ERR("Only res_ns or max_tmo based quaries supported\n");
		return -1;
	}

	if (res_capa->res_ns || res_capa->res_hz) {
		res_capa->min_tmo = min_tmo;
		res_capa->max_tmo = MAX_TMO_NS;
	} else { /* max_tmo */
		res_capa->min_tmo = min_tmo;
		res_capa->res_ns  = MAX_RES_NS;
		res_capa->res_hz = MAX_RES_HZ;
	}

	return 0;
}

odp_timer_pool_t odp_timer_pool_create(const char *name,
				       const odp_timer_pool_param_t *param)
{
	timer_pool_t *timer_pool;
	timer_entry_t *timer;
	uint32_t i, num_timers;
	uint64_t res_ns, nsec_per_scan;

	if (odp_global_ro.init_param.not_used.feat.timer) {
		ODP_ERR("Trying to use disabled ODP feature.\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if ((param->res_ns && param->res_hz) ||
	    (param->res_ns == 0 && param->res_hz == 0)) {
		ODP_ERR("Invalid timeout resolution\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->res_hz == 0 && param->res_ns < MAX_RES_NS) {
		ODP_ERR("Too high resolution\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->res_ns == 0 && param->res_hz > MAX_RES_HZ) {
		ODP_ERR("Too high resolution\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->num_timers > MAX_TIMERS) {
		ODP_ERR("Too many timers\n");
		return ODP_TIMER_POOL_INVALID;
	}

	num_timers = param->num_timers;

	if (param->res_ns)
		res_ns = param->res_ns;
	else
		res_ns = GIGA_HZ / param->res_hz;


	/* Scan timer pool twice during resolution interval */
	if (res_ns > ODP_TIME_USEC_IN_NS)
		nsec_per_scan = res_ns / 2;
	else
		nsec_per_scan = res_ns;

	/* Ring size must larger than param->num_timers */
	if (CHECK_IS_POWER2(num_timers))
		num_timers++;
	num_timers = ROUNDUP_POWER2_U32(num_timers);

	odp_ticketlock_lock(&timer_global->lock);

	if (timer_global->num_timer_pools >= MAX_TIMER_POOLS) {
		odp_ticketlock_unlock(&timer_global->lock);
		ODP_DBG("No more free timer pools\n");
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
		ODP_ERR("Invalid timer pool.\n");
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
		ODP_ERR("Invalid timer pool.\n");
		return ODP_TIMER_INVALID;
	}

	if (odp_unlikely(queue == ODP_QUEUE_INVALID)) {
		ODP_ERR("%s: Invalid queue handle.\n", timer_pool->name);
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
		ODP_DBG("Freeing active timer.\n");

		if (rte_timer_stop(&timer->rte_timer)) {
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

static void timer_cb(struct rte_timer *rte_timer, void *arg)
{
	timer_entry_t *timer = arg;
	odp_event_t event;
	odp_queue_t queue;
	(void)rte_timer;

	odp_ticketlock_lock(&timer->lock);

	if (timer->state != TICKING) {
		ODP_ERR("Timer has been cancelled or freed.\n");
		odp_ticketlock_unlock(&timer->lock);
		return;
	}

	queue = timer->queue;
	event = timer->tmo_event;
	timer->tmo_event = ODP_EVENT_INVALID;
	timer->state = EXPIRED;

	odp_ticketlock_unlock(&timer->lock);

	if (odp_unlikely(odp_queue_enq(queue, event))) {
		ODP_ERR("Timeout event enqueue failed.\n");
		odp_event_free(event);
	}
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
		ODP_DBG("Too early\n");
		ODP_DBG("  cur_tick %" PRIu64 ", abs_tick %" PRIu64 "\n",
			cur_tick, abs_tick);
		ODP_DBG("  num_retry %i\n", num_retry);
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

	if (odp_unlikely(rte_timer_reset(&timer->rte_timer, rel_tick, SINGLE,
					 lcore, timer_cb, timer))) {
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

int odp_timer_set_abs(odp_timer_t timer_hdl, uint64_t abs_tick,
		      odp_event_t *tmo_ev)
{
	return timer_set(timer_hdl, abs_tick, tmo_ev, 1);
}

int odp_timer_set_rel(odp_timer_t timer_hdl, uint64_t rel_tick,
		      odp_event_t *tmo_ev)
{
	return timer_set(timer_hdl, rel_tick, tmo_ev, 0);
}

int odp_timer_cancel(odp_timer_t timer_hdl, odp_event_t *tmo_ev)
{
	timer_entry_t *timer = timer_from_hdl(timer_hdl);

	odp_ticketlock_lock(&timer->lock);

	if (odp_unlikely(timer->state < TICKING)) {
		odp_ticketlock_unlock(&timer->lock);
		return -1;
	}

	if (odp_unlikely(rte_timer_stop(&timer->rte_timer))) {
		/* Another core runs timer callback function. */
		odp_ticketlock_unlock(&timer->lock);
		return -1;
	}

	*tmo_ev = timer->tmo_event;
	timer->tmo_event = ODP_EVENT_INVALID;
	timer->state = NOT_TICKING;

	odp_ticketlock_unlock(&timer->lock);
	return 0;
}

uint64_t odp_timer_to_u64(odp_timer_t timer_hdl)
{
	return (uint64_t)(uintptr_t)timer_hdl;
}

odp_timeout_t odp_timeout_from_event(odp_event_t ev)
{
	return (odp_timeout_t)ev;
}

odp_event_t odp_timeout_to_event(odp_timeout_t tmo)
{
	return (odp_event_t)tmo;
}

uint64_t odp_timeout_to_u64(odp_timeout_t tmo)
{
	return (uint64_t)(uintptr_t)tmo;
}

int odp_timeout_fresh(odp_timeout_t tmo)
{
	odp_timeout_hdr_t *timeout_hdr = timeout_to_hdr(tmo);
	timer_entry_t *timer = timer_from_hdl(timeout_hdr->timer);

	/* Check if timer has been reused after timeout sent. */
	return timeout_hdr->expiration == timer->tick;
}

odp_timer_t odp_timeout_timer(odp_timeout_t tmo)
{
	odp_timeout_hdr_t *timeout_hdr = timeout_to_hdr(tmo);

	return timeout_hdr->timer;
}

uint64_t odp_timeout_tick(odp_timeout_t tmo)
{
	odp_timeout_hdr_t *timeout_hdr = timeout_to_hdr(tmo);

	return timeout_hdr->expiration;
}

void *odp_timeout_user_ptr(odp_timeout_t tmo)
{
	odp_timeout_hdr_t *timeout_hdr = timeout_to_hdr(tmo);

	return (void *)(uintptr_t)timeout_hdr->user_ptr;
}

odp_timeout_t odp_timeout_alloc(odp_pool_t pool)
{
	odp_buffer_t buf = odp_buffer_alloc(pool);

	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_TIMEOUT_INVALID;
	return odp_timeout_from_event(odp_buffer_to_event(buf));
}

void odp_timeout_free(odp_timeout_t tmo)
{
	odp_event_t ev = odp_timeout_to_event(tmo);

	odp_buffer_free(odp_buffer_from_event(ev));
}

void odp_timer_pool_print(odp_timer_pool_t timer_pool)
{
	timer_pool_t *tp;

	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		ODP_ERR("Bad timer pool handle\n");
		return;
	}

	tp = timer_pool_from_hdl(timer_pool);

	ODP_PRINT("\nTimer pool info\n");
	ODP_PRINT("---------------\n");
	ODP_PRINT("  timer pool     %p\n", tp);
	ODP_PRINT("  name           %s\n", tp->name);
	ODP_PRINT("  num timers     %u\n", tp->cur_timers);
	ODP_PRINT("  hwm timers     %u\n", tp->hwm_timers);
	ODP_PRINT("  num tp         %i\n", timer_global->num_timer_pools);
	ODP_PRINT("\n");
}

void odp_timer_print(odp_timer_t timer_hdl)
{
	timer_entry_t *timer = timer_from_hdl(timer_hdl);

	if (timer_hdl == ODP_TIMER_INVALID) {
		ODP_ERR("Bad timer handle\n");
		return;
	}

	ODP_PRINT("\nTimer info\n");
	ODP_PRINT("----------\n");
	ODP_PRINT("  timer pool     %p\n", timer->timer_pool);
	ODP_PRINT("  timer index    %" PRIu32 "\n", timer->timer_idx);
	ODP_PRINT("  dest queue     0x%" PRIx64 "\n", odp_queue_to_u64(timer->queue));
	ODP_PRINT("  user ptr       %p\n", timer->user_ptr);
	ODP_PRINT("  state          %s\n",
		  (timer->state == NOT_TICKING) ? "not ticking" :
		  (timer->state == EXPIRED ? "expired" : "ticking"));
	ODP_PRINT("\n");
}

void odp_timeout_print(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *timeout_hdr = timeout_to_hdr(tmo);
	odp_timer_t timer_hdl;
	timer_pool_t *tp = NULL;
	uint32_t idx = 0;

	if (tmo == ODP_TIMEOUT_INVALID) {
		ODP_ERR("Bad timeout handle\n");
		return;
	}

	timer_hdl = timeout_hdr->timer;

	if (timer_hdl != ODP_TIMER_INVALID) {
		timer_entry_t *timer = timer_from_hdl(timer_hdl);

		tp  = timer->timer_pool;
		idx = timer->timer_idx;
	}

	ODP_PRINT("\nTimeout info\n");
	ODP_PRINT("------------\n");
	ODP_PRINT("  tmo handle     0x%" PRIx64 "\n", odp_timeout_to_u64(tmo));
	ODP_PRINT("  timer pool     %p\n", tp);
	ODP_PRINT("  timer index    %u\n", idx);
	ODP_PRINT("  expiration     %" PRIu64 "\n", timeout_hdr->expiration);
	ODP_PRINT("  user ptr       %p\n", timeout_hdr->user_ptr);
	ODP_PRINT("\n");
}
