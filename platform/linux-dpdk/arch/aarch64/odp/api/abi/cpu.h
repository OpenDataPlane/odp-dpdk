/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_API_ABI_CPU_H_
#define ODP_API_ABI_CPU_H_

#include <rte_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ODP_CACHE_LINE_SIZE RTE_CACHE_LINE_SIZE

#ifdef __cplusplus
}
#endif

/* Inlined functions for non-ABI compat mode */
#include <odp/api/plat/cpu_inlines.h>

#endif
