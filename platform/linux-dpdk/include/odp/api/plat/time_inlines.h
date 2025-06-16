/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2020-2024 Nokia
 */

#ifndef ODP_PLAT_TIME_INLINES_H_
#define ODP_PLAT_TIME_INLINES_H_

#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/time_types.h>

#include <rte_config.h>
#include <rte_atomic.h>
#include <rte_cycles.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

typedef struct _odp_time_global_t {
	uint64_t        freq_hz;
	uint64_t        start_cycles;
	uint64_t        start_ns;

} _odp_time_global_t;

extern _odp_time_global_t _odp_time_glob;

static inline odp_time_t _odp_time_cur(void)
{
	odp_time_t time;

	time.u64 = rte_get_timer_cycles();

	return time;
}

static inline odp_time_t _odp_time_cur_strict(void)
{
	odp_time_t time;

	rte_mb();
	time.u64 = rte_get_timer_cycles();

	return time;
}

static inline uint64_t _odp_time_to_ns(odp_time_t time)
{
	uint64_t nsec;
	uint64_t count = time.count;
	uint64_t sec = 0;
	const uint64_t freq_hz = _odp_time_glob.freq_hz;
	const uint64_t giga_hz = 1000000000;

	if (count >= freq_hz) {
		sec   = count / freq_hz;
		count = count - sec * freq_hz;
	}

	nsec = (giga_hz * count) / freq_hz;

	return (sec * giga_hz) + nsec;
}

static inline odp_time_t _odp_time_from_ns(uint64_t ns)
{
	odp_time_t time;
	uint64_t count;
	uint64_t sec = 0;
	const uint64_t freq_hz = _odp_time_glob.freq_hz;

	if (ns >= ODP_TIME_SEC_IN_NS) {
		sec = ns / ODP_TIME_SEC_IN_NS;
		ns  = ns - sec * ODP_TIME_SEC_IN_NS;
	}

	count  = sec * freq_hz;
	count += (ns * freq_hz) / ODP_TIME_SEC_IN_NS;

	time.count = count;

	return time;
}

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_time_local_res __odp_time_local_res
	#define odp_time_global_res __odp_time_global_res
	#define odp_time_local __odp_time_local
	#define odp_time_global __odp_time_global
	#define odp_time_local_strict __odp_time_local_strict
	#define odp_time_global_strict __odp_time_global_strict
	#define odp_time_local_ns __odp_time_local_ns
	#define odp_time_global_ns __odp_time_global_ns
	#define odp_time_local_from_ns __odp_time_local_from_ns
	#define odp_time_global_from_ns __odp_time_global_from_ns
	#define odp_time_local_strict_ns __odp_time_local_strict_ns
	#define odp_time_global_strict_ns __odp_time_global_strict_ns
	#define odp_time_to_ns __odp_time_to_ns
	#define odp_time_cmp __odp_time_cmp
	#define odp_time_diff __odp_time_diff
	#define odp_time_diff_ns __odp_time_diff_ns
	#define odp_time_add_ns __odp_time_add_ns
	#define odp_time_sum __odp_time_sum
	#define odp_time_wait_ns __odp_time_wait_ns
	#define odp_time_wait_until __odp_time_wait_until
	#define odp_time_startup __odp_time_startup
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE uint64_t odp_time_local_res(void)
{
	return _odp_time_glob.freq_hz;
}

_ODP_INLINE uint64_t odp_time_global_res(void)
{
	return _odp_time_glob.freq_hz;
}

_ODP_INLINE odp_time_t odp_time_local(void)
{
	return _odp_time_cur();
}

_ODP_INLINE odp_time_t odp_time_global(void)
{
	return _odp_time_cur();
}

_ODP_INLINE odp_time_t odp_time_local_strict(void)
{
	return _odp_time_cur_strict();
}

_ODP_INLINE odp_time_t odp_time_global_strict(void)
{
	return _odp_time_cur_strict();
}

_ODP_INLINE uint64_t odp_time_local_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur());
}

_ODP_INLINE uint64_t odp_time_global_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur());
}

_ODP_INLINE odp_time_t odp_time_local_from_ns(uint64_t ns)
{
	return _odp_time_from_ns(ns);
}

_ODP_INLINE odp_time_t odp_time_global_from_ns(uint64_t ns)
{
	return _odp_time_from_ns(ns);
}

_ODP_INLINE uint64_t odp_time_local_strict_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur_strict());
}

_ODP_INLINE uint64_t odp_time_global_strict_ns(void)
{
	return _odp_time_to_ns(_odp_time_cur_strict());
}

_ODP_INLINE uint64_t odp_time_to_ns(odp_time_t time)
{
	return _odp_time_to_ns(time);
}

_ODP_INLINE int odp_time_cmp(odp_time_t t2, odp_time_t t1)
{
	if (odp_likely(t2.u64 > t1.u64))
		return 1;

	if (t2.u64 < t1.u64)
		return -1;

	return 0;
}

_ODP_INLINE odp_time_t odp_time_diff(odp_time_t t2, odp_time_t t1)
{
	odp_time_t time;

	time.u64 = t2.u64 - t1.u64;

	return time;
}

_ODP_INLINE uint64_t odp_time_diff_ns(odp_time_t t2, odp_time_t t1)
{
	odp_time_t time;

	time.u64 = t2.u64 - t1.u64;

	return odp_time_to_ns(time);
}

_ODP_INLINE odp_time_t odp_time_add_ns(odp_time_t time, uint64_t ns)
{
	odp_time_t t = _odp_time_from_ns(ns);

	t.u64 += time.u64;

	return t;
}

_ODP_INLINE odp_time_t odp_time_sum(odp_time_t t1, odp_time_t t2)
{
	odp_time_t time;

	time.u64 = t1.u64 + t2.u64;

	return time;
}

static inline void _odp_time_wait_until(odp_time_t time)
{
	odp_time_t cur;

	do {
		cur = _odp_time_cur();
	} while (odp_time_cmp(time, cur) > 0);
}

_ODP_INLINE void odp_time_wait_ns(uint64_t ns)
{
	const odp_time_t cur = _odp_time_cur();
	const odp_time_t wait = _odp_time_from_ns(ns);
	const odp_time_t end_time = odp_time_sum(cur, wait);

	_odp_time_wait_until(end_time);
}

_ODP_INLINE void odp_time_wait_until(odp_time_t time)
{
	_odp_time_wait_until(time);
}

_ODP_INLINE void odp_time_startup(odp_time_startup_t *startup)
{
	startup->global.u64 = _odp_time_glob.start_cycles;
	startup->global_ns = _odp_time_glob.start_ns;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
