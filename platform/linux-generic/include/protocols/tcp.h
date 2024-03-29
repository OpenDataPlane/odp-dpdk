/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP TCP header
 */

#ifndef ODP_TCP_H_
#define ODP_TCP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/byteorder.h>

/** @addtogroup odp_header ODP HEADER
 *  @{
 */

#define _ODP_TCPHDR_LEN 20 /**< Min length of TCP header (no options) */

/** TCP header */
typedef struct ODP_PACKED {
	odp_u16be_t src_port; /**< Source port */
	odp_u16be_t dst_port; /**< Destination port */
	odp_u32be_t seq_no;   /**< Sequence number */
	odp_u32be_t ack_no;   /**< Acknowledgment number */
	union {
		odp_u16be_t doffset_flags;
#if ODP_BIG_ENDIAN_BITFIELD
		struct {
			odp_u16be_t rsvd1:8;
			odp_u16be_t flags:8; /**< TCP flags as a byte */
		};
		struct {
			odp_u16be_t hl:4;    /**< Hdr len, in words */
			odp_u16be_t rsvd3:4; /**< Reserved */
			odp_u16be_t cwr:1;
			odp_u16be_t ece:1;
			odp_u16be_t urg:1;
			odp_u16be_t ack:1;
			odp_u16be_t psh:1;
			odp_u16be_t rst:1;
			odp_u16be_t syn:1;
			odp_u16be_t fin:1;
		};
#elif ODP_LITTLE_ENDIAN_BITFIELD
		struct {
			odp_u16be_t flags:8;
			odp_u16be_t rsvd1:8; /**< TCP flags as a byte */
		};
		struct {
			odp_u16be_t rsvd3:4; /**< Reserved */
			odp_u16be_t hl:4;    /**< Hdr len, in words */
			odp_u16be_t fin:1;
			odp_u16be_t syn:1;
			odp_u16be_t rst:1;
			odp_u16be_t psh:1;
			odp_u16be_t ack:1;
			odp_u16be_t urg:1;
			odp_u16be_t ece:1;
			odp_u16be_t cwr:1;
		};

#else
#error "Endian BitField order not defined!"
#endif
	};
	odp_u16be_t window; /**< Window size */
	odp_u16be_t cksm;   /**< Checksum */
	odp_u16be_t urgptr; /**< Urgent pointer */
} _odp_tcphdr_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
