/* Copyright (c) 2018-2018, Linaro Limited
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_PACKET_IO_INLINES_H_
#define ODP_PLAT_PACKET_IO_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/abi/packet_io_types.h>

#include <stdint.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_pktio_index __odp_pktio_index
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

_ODP_INLINE int odp_pktio_index(odp_pktio_t pktio)
{
	return (int)(uintptr_t)pktio - 1;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
