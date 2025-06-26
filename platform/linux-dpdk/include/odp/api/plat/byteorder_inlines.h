/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP byteorder
 */

#ifndef ODP_PLAT_BYTEORDER_INLINES_H_
#define ODP_PLAT_BYTEORDER_INLINES_H_

#include <odp/api/abi/byteorder.h>

#include <rte_config.h>
#include <rte_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef __odp_force
#define __odp_force
#endif

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_be_to_cpu_16 __odp_be_to_cpu_16
	#define odp_be_to_cpu_32 __odp_be_to_cpu_32
	#define odp_be_to_cpu_64 __odp_be_to_cpu_64
	#define odp_cpu_to_be_16 __odp_cpu_to_be_16
	#define odp_cpu_to_be_32 __odp_cpu_to_be_32
	#define odp_cpu_to_be_64 __odp_cpu_to_be_64
	#define odp_le_to_cpu_16 __odp_le_to_cpu_16
	#define odp_le_to_cpu_32 __odp_le_to_cpu_32
	#define odp_le_to_cpu_64 __odp_le_to_cpu_64
	#define odp_cpu_to_le_16 __odp_cpu_to_le_16
	#define odp_cpu_to_le_32 __odp_cpu_to_le_32
	#define odp_cpu_to_le_64 __odp_cpu_to_le_64
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE uint16_t odp_be_to_cpu_16(odp_u16be_t be16)
{
	return rte_be_to_cpu_16((__odp_force uint16_t)be16);
}

_ODP_INLINE uint32_t odp_be_to_cpu_32(odp_u32be_t be32)
{
	return rte_be_to_cpu_32((__odp_force uint32_t)be32);
}

_ODP_INLINE uint64_t odp_be_to_cpu_64(odp_u64be_t be64)
{
	return rte_be_to_cpu_64((__odp_force uint64_t)be64);
}

_ODP_INLINE odp_u16be_t odp_cpu_to_be_16(uint16_t cpu16)
{
	return (__odp_force odp_u16be_t)rte_cpu_to_be_16(cpu16);
}

_ODP_INLINE odp_u32be_t odp_cpu_to_be_32(uint32_t cpu32)
{
	return (__odp_force odp_u32be_t)rte_cpu_to_be_32(cpu32);
}

_ODP_INLINE odp_u64be_t odp_cpu_to_be_64(uint64_t cpu64)
{
	return (__odp_force odp_u64be_t)rte_cpu_to_be_64(cpu64);
}

_ODP_INLINE uint16_t odp_le_to_cpu_16(odp_u16le_t le16)
{
	return rte_le_to_cpu_16((__odp_force uint16_t)le16);
}

_ODP_INLINE uint32_t odp_le_to_cpu_32(odp_u32le_t le32)
{
	return rte_le_to_cpu_32((__odp_force uint32_t)le32);
}

_ODP_INLINE uint64_t odp_le_to_cpu_64(odp_u64le_t le64)
{
	return rte_le_to_cpu_64((__odp_force uint64_t)le64);
}

_ODP_INLINE odp_u16le_t odp_cpu_to_le_16(uint16_t cpu16)
{
	return (__odp_force odp_u16le_t)rte_cpu_to_le_16(cpu16);
}

_ODP_INLINE odp_u32le_t odp_cpu_to_le_32(uint32_t cpu32)
{
	return (__odp_force odp_u32le_t)rte_cpu_to_le_32(cpu32);
}

_ODP_INLINE odp_u64le_t odp_cpu_to_le_64(uint64_t cpu64)
{
	return (__odp_force odp_u64le_t)rte_cpu_to_le_64(cpu64);
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
