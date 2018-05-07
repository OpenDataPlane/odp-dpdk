/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP eventdev - implementation internal
 */

#ifndef ODP_EVENTDEV_H_
#define ODP_EVENTDEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>
#include <odp/api/queue.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_queue_if.h>
#include <odp_buffer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/ticketlock.h>
#include <odp_config_internal.h>
#include <odp_ring_st_internal.h>
#include <odp/api/schedule_types.h>

#include <rte_config.h>
#include <rte_eventdev.h>

#include <stdint.h>

#define MAX_EVENT_QUEUES UINT8_MAX
ODP_STATIC_ASSERT(sizeof(((struct rte_event *)0)->queue_id) == sizeof(uint8_t),
		  "eventdev queue ID size changed");

#define RX_ADAPTER_INIT           0
#define RX_ADAPTER_STOPPED        1
#define RX_ADAPTER_RUNNING        2

/* Maximum schedule burst size */
#define MAX_SCHED_BURST 128
ODP_STATIC_ASSERT(MAX_SCHED_BURST <= UINT16_MAX,
		  "too large schedule burst");

/* Number of scheduling groups */
#define NUM_SCHED_GRPS 32

typedef struct {
	uint8_t id;
	uint8_t status;
} eventdev_queue_t;

struct queue_entry_s {
	odp_ticketlock_t  ODP_ALIGNED_CACHE lock;
	ring_st_t         ring_st;
	int               status;
	eventdev_queue_t  event_queue;

	queue_enq_fn_t       ODP_ALIGNED_CACHE enqueue;
	queue_deq_fn_t       dequeue;
	queue_enq_multi_fn_t enqueue_multi;
	queue_deq_multi_fn_t dequeue_multi;

	uint32_t          index;
	odp_queue_t       handle;
	odp_queue_type_t  type;
	odp_queue_param_t param;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	char              name[ODP_QUEUE_NAME_LEN];
};

union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct queue_entry_s))];
};

/* Eventdev global data */
typedef struct {
	odp_shm_t   shm;
	struct rte_event_dev_config config;
	struct {
		odp_spinlock_t lock;
		int  status;
		uint8_t id;
		uint8_t single_queue;
	} rx_adapter;
	odp_atomic_u32_t num_started;
	uint8_t     dev_id;
	uint8_t     num_event_ports;
	uint8_t     num_prio;

	odp_ticketlock_t ODP_ALIGNED_CACHE lock;
	queue_entry_t   queue[ODP_CONFIG_QUEUES];
	odp_queue_t queue_id_to_queue[MAX_EVENT_QUEUES];
	struct {
		eventdev_queue_t atomic[MAX_EVENT_QUEUES];
		eventdev_queue_t ordered[MAX_EVENT_QUEUES];
		eventdev_queue_t parallel[MAX_EVENT_QUEUES];
		uint8_t num_atomic;
		uint8_t num_ordered;
		uint8_t num_parallel;
	} event_queue;
	pktio_entry_t *pktio[RTE_MAX_ETHPORTS];

	struct {
		odp_spinlock_t lock;
		uint8_t linked;
	} port[ODP_THREAD_COUNT_MAX];

	struct {
		uint32_t max_queue_size;
		uint32_t default_queue_size;
	} plain_config;

	struct {
		uint32_t max_queue_size;
	} sched_config;

	/* Schedule groups */
	odp_thrmask_t    mask_all;
	struct {
		char           name[ODP_SCHED_GROUP_NAME_LEN];
		odp_thrmask_t  mask;
		uint8_t	       allocated;
		queue_entry_t *queue[MAX_EVENT_QUEUES];
	} grp[NUM_SCHED_GRPS];
	odp_spinlock_t   grp_lock;
} eventdev_global_t;

/* Eventdev local data */
typedef struct {
	struct {
		struct rte_event event[MAX_SCHED_BURST];
		uint16_t idx;
		uint16_t count;
	} cache;
	uint8_t thr;
	uint8_t paused;
	uint8_t started;
} eventdev_local_t;

extern eventdev_global_t *eventdev_gbl;
extern __thread eventdev_local_t eventdev_local;

int service_setup(uint32_t service_id);

int link_all_queues(uint8_t dev_id,
		    const struct rte_event_dev_config *dev_conf);

int unlink_all_queues(uint8_t dev_id,
		      const struct rte_event_dev_config *dev_conf);

int resume_scheduling(uint8_t dev_id, uint8_t port_id);

void rx_adapter_port_stop(uint16_t port_id);

int rx_adapter_close(void);

/* Check that DPDK schedule types have not changed */
ODP_STATIC_ASSERT(RTE_SCHED_TYPE_ORDERED == 0,
		  "RTE_SCHED_TYPE_ORDERED value changed");
ODP_STATIC_ASSERT(RTE_SCHED_TYPE_ATOMIC == 1,
		  "RTE_SCHED_TYPE_ATOMIC value changed");
ODP_STATIC_ASSERT(RTE_SCHED_TYPE_PARALLEL == 2,
		  "RTE_SCHED_TYPE_PARALLEL value changed");

static inline uint8_t event_schedule_type(odp_schedule_sync_t sync)
{
	/* This shortcut matches ODP scheduling types to RTE_SCHED_TYPE_ORDERED,
	 * RTE_SCHED_TYPE_ATOMIC and RTE_SCHED_TYPE_PARALLE. */
	return 2 - (uint8_t)sync;
}

static inline queue_t queue_index_to_qint(uint32_t queue_id)
{
	return (queue_t)&eventdev_gbl->queue[queue_id];
}

static inline uint32_t queue_to_index(odp_queue_t handle)
{
	return _odp_typeval(handle) - 1;
}

static inline odp_queue_t queue_from_index(uint32_t queue_id)
{
	return _odp_cast_scalar(odp_queue_t, queue_id + 1);
}

static inline queue_entry_t *qentry_from_int(queue_t q_int)
{
	return (queue_entry_t *)(void *)(q_int);
}

static inline queue_t qentry_to_int(queue_entry_t *qentry)
{
	return (queue_t)(qentry);
}

static inline queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &eventdev_gbl->queue[queue_id];
}

static inline queue_entry_t *handle_to_qentry(odp_queue_t handle)
{
	uint32_t queue_id = queue_to_index(handle);

	return get_qentry(queue_id);
}

#ifdef __cplusplus
}
#endif

#endif
