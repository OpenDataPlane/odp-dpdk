/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_RING_ST_INTERNAL_H_
#define ODP_RING_ST_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/queue.h>

#include <odp_debug_internal.h>

#include <rte_config.h>
#include <rte_ring.h>
#include <rte_errno.h>

typedef struct rte_ring *ring_st_t;

/* Basic ring for single thread usage. Operations must be synchronized by using
 * locks (or other means), when multiple threads use the same ring. */

static void name_to_mz_name(const char *name, char *ring_name)
{
	int i = 0;
	int max_len = ODP_QUEUE_NAME_LEN < RTE_RING_NAMESIZE  ?
			ODP_QUEUE_NAME_LEN : RTE_RING_NAMESIZE;

	do {
		snprintf(ring_name, max_len, "%d-%s", i++, name);
		ring_name[max_len - 1] = 0;
	} while (rte_ring_lookup(ring_name) != NULL);
}

/* Initialize ring. Ring size must be a power of two. */
static inline ring_st_t ring_st_create(const char *name, uint32_t size)
{
	struct rte_ring *rte_ring;
	char ring_name[RTE_RING_NAMESIZE];

	/* Ring name must be unique */
	name_to_mz_name(name, ring_name);

	rte_ring =  rte_ring_create(ring_name, size, rte_socket_id(),
				    RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (rte_ring == NULL) {
		_ODP_ERR("Creating DPDK ring failed: %s\n", rte_strerror(rte_errno));
		return NULL;
	}

	return rte_ring;
}

static inline void ring_st_free(ring_st_t ring)
{
	rte_ring_free(ring);
}

/* Dequeue data from the ring head. Max_num is smaller than ring size.*/
static inline uint32_t ring_st_deq_multi(ring_st_t ring, void **data,
					 uint32_t max_num)
{
	return rte_ring_dequeue_burst(ring, data, max_num, NULL);
}

/* Enqueue data into the ring tail. Num_data is smaller than ring size. */
static inline uint32_t ring_st_enq_multi(ring_st_t ring, void **data,
					 uint32_t num_data)
{
	return rte_ring_enqueue_burst(ring, data, num_data, NULL);
}

/* Check if ring is empty */
static inline int ring_st_is_empty(ring_st_t ring)
{
	return rte_ring_empty(ring);
}

/* Return current ring length */
static inline int ring_st_length(ring_st_t ring)
{
	return rte_ring_count(ring);
}

/* Return maximum ring length */
static inline int ring_st_max_length(ring_st_t ring)
{
	return rte_ring_get_capacity(ring);
}

#ifdef __cplusplus
}
#endif

#endif
