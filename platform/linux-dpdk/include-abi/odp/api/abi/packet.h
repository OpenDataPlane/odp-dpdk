/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_API_ABI_PACKET_H_
#define ODP_API_ABI_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_packet
 *  @{
 */

typedef ODP_HANDLE_T(odp_packet_t);

#define ODP_PACKET_INVALID _odp_cast_scalar(odp_packet_t, 0)

#define ODP_PACKET_OFFSET_INVALID 0xffff

typedef ODP_HANDLE_T(odp_packet_seg_t);

#define ODP_PACKET_SEG_INVALID _odp_cast_scalar(odp_packet_seg_t, NULL)

typedef enum {
	ODP_PACKET_GREEN = 0,
	ODP_PACKET_YELLOW = 1,
	ODP_PACKET_RED = 2,
	ODP_PACKET_ALL_COLORS = 3,
} odp_packet_color_t;

#define ODP_NUM_PACKET_COLORS 3

#define _ODP_INLINE static inline
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_inlines_api.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
