/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_API_ABI_CPU_H_
#define ODP_API_ABI_CPU_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>

#define ODP_CACHE_LINE_SIZE RTE_CACHE_LINE_SIZE

/* Inlined functions for non-ABI compat mode */
#include <odp/api/plat/cpu_inlines.h>

#ifdef __cplusplus
}
#endif

#endif
