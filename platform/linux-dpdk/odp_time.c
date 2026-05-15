/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2021-2026 Nokia
 */

#include <odp/api/plat/time_inlines.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <rte_config.h>
#include <rte_cycles.h>

#include <inttypes.h>
#include <string.h>

#define YEAR_IN_SEC (365 * 24 * 3600)

#include <odp/visibility_begin.h>

_odp_time_global_t _odp_time_glob;

#include <odp/visibility_end.h>

int _odp_time_init_global(void)
{
	uint64_t diff, years;
	odp_time_t time;

	memset(&_odp_time_glob, 0, sizeof(_odp_time_global_t));

#ifdef RTE_LIBEAL_USE_HPET
	if (rte_eal_hpet_init(1) != 0)
		_ODP_WARN("HPET init failed. Using TSC time.\n");
#endif

	_odp_time_glob.freq_hz = rte_get_timer_hz();
	if (_odp_time_glob.freq_hz == 0) {
		_ODP_ERR("Reading default time counter frequency failed\n");
		return -1;
	}

#ifdef __SIZEOF_INT128__
	/* Find the maximum shift for which the multiplier fits into 64 bits */
	for (_odp_time_glob.shift_to_ns = 63; _odp_time_glob.shift_to_ns > 0;
	     _odp_time_glob.shift_to_ns--) {
		__uint128_t cur = ((__uint128_t)_ODP_TIME_GIGA_HZ << _odp_time_glob.shift_to_ns) /
					_odp_time_glob.freq_hz;
		if (cur <= UINT64_MAX) {
			_odp_time_glob.mult_to_ns = (uint64_t)cur;
			break;
		}
	}

	for (_odp_time_glob.shift_from_ns = 63; _odp_time_glob.shift_from_ns > 0;
	     _odp_time_glob.shift_from_ns--) {
		__uint128_t cur = ((__uint128_t)_odp_time_glob.freq_hz <<
				   _odp_time_glob.shift_from_ns) / ODP_TIME_SEC_IN_NS;
		if (cur <= UINT64_MAX) {
			_odp_time_glob.mult_from_ns = (uint64_t)cur;
			break;
		}
	}
#endif

	_odp_time_glob.start_cycles = rte_get_timer_cycles();
	if (_odp_time_glob.start_cycles == 0) {
		_ODP_ERR("Initializing start cycles failed.\n");
		return -1;
	}

	time.u64 = _odp_time_glob.start_cycles;
	_odp_time_glob.start_ns = _odp_time_to_ns(time);

	/* Make sure that counters will not wrap */
	diff = UINT64_MAX - _odp_time_glob.start_cycles;
	years = (diff / _odp_time_glob.freq_hz) / YEAR_IN_SEC;

	if (years < 10) {
		_ODP_ERR("Time counter would wrap in 10 years: %" PRIu64 "\n",
			 _odp_time_glob.start_cycles);
		return -1;
	}

	diff = UINT64_MAX - _odp_time_glob.start_ns;
	years = (diff / ODP_TIME_SEC_IN_NS) / YEAR_IN_SEC;

	if (years < 10) {
		_ODP_ERR("Time in nsec would wrap in 10 years: %" PRIu64 "\n",
			 _odp_time_glob.start_ns);
		return -1;
	}

	return 0;
}

int _odp_time_term_global(void)
{
	return 0;
}
