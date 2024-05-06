/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_RING_MPMC_INTERNAL_H_
#define ODP_RING_MPMC_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/queue.h>

#include <odp_debug_internal.h>

#include <rte_config.h>
#include <rte_ring.h>
#include <rte_errno.h>

/* Lock-free ring for multi-producer / multi-consumer usage.
 *
 * Enqueue and dequeue operations can be done concurrently.
 */
typedef struct rte_ring *ring_mpmc_t;

static void ring_mpmc_name_to_mz_name(const char *name, char *ring_name)
{
	int i = 0;
	int max_len = ODP_QUEUE_NAME_LEN < RTE_RING_NAMESIZE  ?
			ODP_QUEUE_NAME_LEN : RTE_RING_NAMESIZE;

	do {
		snprintf(ring_name, max_len, "%d-mpmc-%s", i++, name);
		ring_name[max_len - 1] = 0;
	} while (rte_ring_lookup(ring_name) != NULL);
}

/* Initialize ring. Ring size must be a power of two. */
static inline ring_mpmc_t ring_mpmc_create(const char *name, uint32_t size)
{
	struct rte_ring *rte_ring;
	char ring_name[RTE_RING_NAMESIZE];

	/* Ring name must be unique */
	ring_mpmc_name_to_mz_name(name, ring_name);

	rte_ring = rte_ring_create(ring_name, size, rte_socket_id(), 0);
	if (rte_ring == NULL) {
		_ODP_ERR("Creating DPDK ring failed: %s\n", rte_strerror(rte_errno));
		return NULL;
	}

	return rte_ring;
}

/*  Free all memory used by the ring. */
static inline void ring_mpmc_free(ring_mpmc_t ring)
{
	rte_ring_free(ring);
}

/* Dequeue data from the ring head. Max_num is smaller than ring size.*/
static inline uint32_t ring_mpmc_deq_multi(ring_mpmc_t ring, void **data,
					   uint32_t max_num)
{
	return rte_ring_mc_dequeue_burst(ring, data, max_num, NULL);
}

/* Enqueue data into the ring tail. Num_data is smaller than ring size. */
static inline uint32_t ring_mpmc_enq_multi(ring_mpmc_t ring, void **data,
					   uint32_t num_data)
{
	return rte_ring_mp_enqueue_burst(ring, data, num_data, NULL);
}

/* Check if ring is empty */
static inline int ring_mpmc_is_empty(ring_mpmc_t ring)
{
	return rte_ring_empty(ring);
}

/* Return current ring length */
static inline int ring_mpmc_length(ring_mpmc_t ring)
{
	return rte_ring_count(ring);
}

/* Return maximum ring length */
static inline int ring_mpmc_max_length(ring_mpmc_t ring)
{
	return rte_ring_get_capacity(ring);
}

#ifdef __cplusplus
}
#endif

#endif
