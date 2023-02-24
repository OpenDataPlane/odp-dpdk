/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CONFIG_INTERNAL_H_
#define ODP_CONFIG_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_config.h>

#include <stdint.h>

/*
 * Maximum number of supported CPU identifiers. The maximum supported CPU ID is
 * CONFIG_NUM_CPU_IDS - 1. Note that the maximum number of ODP threads is
 * defined by ODP_THREAD_COUNT_MAX.
 */
#define CONFIG_NUM_CPU_IDS 256

/*
 * Maximum number of pools
 */
#define ODP_CONFIG_POOLS 256

/*
 * Queues reserved for ODP internal use
 */
#define CONFIG_INTERNAL_QUEUES 64

/*
 * Maximum number of plain ODP queues
 */
#define CONFIG_MAX_PLAIN_QUEUES 1024

/*
 * Maximum number of scheduled ODP queues
 *
 * Must be a power of two.
 */
#define CONFIG_MAX_SCHED_QUEUES 1024

/*
 * Maximum number of queues
 */
#define CONFIG_MAX_QUEUES (CONFIG_INTERNAL_QUEUES + \
			   CONFIG_MAX_PLAIN_QUEUES + \
			   CONFIG_MAX_SCHED_QUEUES)

/*
 * Maximum number of ordered locks per queue
 */
#define CONFIG_QUEUE_MAX_ORD_LOCKS 2

/*
 * Maximum number of DMA sessions
 */
#define CONFIG_MAX_DMA_SESSIONS 32

/*
 * Stashes reserved for internal usage
 */
#define CONFIG_INTERNAL_STASHES CONFIG_MAX_DMA_SESSIONS

/*
 * Maximum number of stashes
 */
#define CONFIG_MAX_STASHES 2048

/*
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 64

/*
 * Minimum buffer alignment
 *
 * This defines the minimum supported buffer alignment. Requests for values
 * below this will be rounded up to this value.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MIN 16

/*
 * Maximum buffer alignment
 *
 * This defines the maximum supported buffer alignment. Requests for values
 * above this will fail.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MAX (4 * 1024)

/*
 * Default packet tailroom
 *
 * This defines the minimum number of tailroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations are free to add to this as desired
 * without restriction. Note that most implementations will automatically
 * consider any unused portion of the last segment of a packet as tailroom
 */
#define CONFIG_PACKET_TAILROOM 0

/*
 * Maximum packet segment size including head- and tailrooms
 */
#define CONFIG_PACKET_SEG_SIZE (UINT16_MAX)

/*
 * Minimum packet segment length
 *
 * This defines the minimum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) will be rounded up into
 * this value.
 */
#define CONFIG_PACKET_SEG_LEN_MIN 1024

/*
 * Maximum packet segment length
 *
 * This defines the maximum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) must not be larger than
 * this.
 */
#define CONFIG_PACKET_MAX_SEG_LEN (CONFIG_PACKET_SEG_SIZE - \
				   RTE_PKTMBUF_HEADROOM - \
				   CONFIG_PACKET_TAILROOM - \
				   ODP_CONFIG_BUFFER_ALIGN_MIN)

/*
 * Number of shared memory blocks reserved for implementation internal use.
 *
 * Each packet pool requires one SHM block and 20 blocks are reserved for
 * ODP module global data.
 */
#define CONFIG_INTERNAL_SHM_BLOCKS (ODP_CONFIG_POOLS + 20)

/*
 * Maximum number of shared memory blocks.
 *
 * This is the number of separate SHM blocks that an application can reserve
 * concurrently.
 */
#define CONFIG_SHM_BLOCKS 64

/*
 * Maximum event burst size
 *
 * This controls the burst size on various enqueue, dequeue, etc calls. Large
 * burst size improves throughput, but may degrade QoS (increase latency).
 */
#define CONFIG_BURST_SIZE 32

/*
 * Maximum number of events in a pool. Power of two minus one results optimal
 * memory usage.
 */
#define CONFIG_POOL_MAX_NUM ((1024 * 1024) - 1)

/* Maximum packet vector size */
#define CONFIG_PACKET_VECTOR_MAX_SIZE 256

/*
 * Maximum number of IPsec SAs. The actual maximum number can be further
 * limited by the number of sessions supported by the crypto subsystem and
 * is reported by odp_ipsec_capability().
 */
#define CONFIG_IPSEC_MAX_NUM_SA 4000

#ifdef __cplusplus
}
#endif

#endif
