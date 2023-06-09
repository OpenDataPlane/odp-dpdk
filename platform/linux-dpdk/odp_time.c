/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/plat/time_inlines.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <rte_config.h>
#include <rte_cycles.h>

#include <string.h>

#include <odp/visibility_begin.h>

_odp_time_global_t _odp_time_glob;

#include <odp/visibility_end.h>

int _odp_time_init_global(void)
{
	memset(&_odp_time_glob, 0, sizeof(_odp_time_global_t));

#ifdef RTE_LIBEAL_USE_HPET
	if (rte_eal_hpet_init(1) != 0)
		_ODP_WARN("HPET init failed. Using TSC time.\n");
#endif

	_odp_time_glob.freq_hz = rte_get_timer_hz();
	_odp_time_glob.start_cycles = rte_get_timer_cycles();
	if (_odp_time_glob.start_cycles == 0) {
		_ODP_ERR("Initializing start cycles failed.\n");
		return -1;
	}

	return 0;
}

int _odp_time_term_global(void)
{
	return 0;
}
