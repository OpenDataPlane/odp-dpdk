/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP error number define
 */

#ifndef ODP_ERRNO_DEFINE_H_
#define ODP_ERRNO_DEFINE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_errno.h>

#define _odp_errno (rte_errno)

#ifdef __cplusplus
}
#endif

#endif
