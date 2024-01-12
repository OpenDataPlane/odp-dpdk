/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_TIMER_INLINE_TYPES_H_
#define ODP_PLAT_TIMER_INLINE_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/* Timeout header field accessor */
#define _odp_timeout_hdr_field(hdr, cast, field) \
	(*(cast *)(uintptr_t)((uint8_t *)hdr + \
	 _odp_timeout_inline_offset.field))

/* Timeout header field offsets for inline functions */
typedef struct _odp_timeout_inline_offset_t {
	uint16_t expiration;
	uint16_t timer;
	uint16_t user_ptr;
	uint16_t uarea_addr;

} _odp_timeout_inline_offset_t;

extern const _odp_timeout_inline_offset_t _odp_timeout_inline_offset;

/* Timer global data */
typedef struct _odp_timer_global_t {
	uint64_t freq_hz;

} _odp_timer_global_t;

extern _odp_timer_global_t _odp_timer_glob;

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
