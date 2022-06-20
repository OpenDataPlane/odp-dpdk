/* Copyright (c) 2019, Nokia
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

#include <odp/api/align.h>
#include <odp/api/packet_io.h>
#include <odp/api/plat/strong_types.h>
#include <odp/api/queue.h>
#include <odp/api/schedule_types.h>
#include <odp/api/thread.h>
#include <odp/api/ticketlock.h>

#include <odp_config_internal.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_ptr_ring_mpmc_internal.h>
#include <odp_queue_if.h>
#include <odp_schedule_if.h>

#include <rte_config.h>
#include <rte_eventdev.h>

#include <stdint.h>

#define _ODP_SCHED_ID_EVENTDEV (_ODP_SCHED_ID_SCALABLE + 1)

#define RX_ADAPTER_INIT           0
#define RX_ADAPTER_STOPPED        1
#define RX_ADAPTER_RUNNING        2

/* Maximum schedule burst size */
#define MAX_SCHED_BURST 128
ODP_STATIC_ASSERT(MAX_SCHED_BURST <= UINT16_MAX,
		  "too large schedule burst");

/* Number of scheduling groups */
#define NUM_SCHED_GRPS 32

ODP_STATIC_ASSERT(sizeof(((struct rte_event *)0)->queue_id) == sizeof(uint8_t),
		  "eventdev queue ID size changed");

ODP_STATIC_ASSERT(CONFIG_MAX_QUEUES >= RTE_EVENT_MAX_QUEUES_PER_DEV,
		  "unable to map all eventdev queues");

struct queue_entry_s {
	/* The first cache line is read only */
	queue_enq_fn_t       enqueue ODP_ALIGNED_CACHE;
	queue_deq_fn_t       dequeue;
	queue_enq_multi_fn_t enqueue_multi;
	queue_deq_multi_fn_t dequeue_multi;
	uint32_t          index;
	odp_queue_type_t  type;

	struct {
		uint8_t prio;
	} eventdev;

	ring_mpmc_t       ring_mpmc;

	odp_ticketlock_t  lock;

	odp_atomic_u64_t  num_timers;
	int               status;
	odp_schedule_sync_t sync;

	queue_deq_multi_fn_t orig_dequeue_multi;
	odp_queue_param_t param;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	char              name[ODP_QUEUE_NAME_LEN];
};

union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[_ODP_ROUNDUP_CACHE_LINE(sizeof(struct queue_entry_s))];
};

/* Eventdev global data */
typedef struct {
	queue_entry_t   queue[CONFIG_MAX_QUEUES];
	odp_shm_t       shm;
	struct rte_event_dev_config config;
	struct {
		odp_ticketlock_t lock;
		int  status;
		uint8_t id;
		uint8_t single_queue;
	} rx_adapter;
	odp_atomic_u32_t num_started;
	uint8_t     dev_id;
	uint8_t     num_event_ports;
	uint8_t     num_prio;

	struct {
		uint8_t num_atomic;
		uint8_t num_ordered;
		uint8_t num_parallel;
	} event_queue;
	pktio_entry_t *pktio[RTE_MAX_ETHPORTS];

	odp_ticketlock_t port_lock;
	struct {
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
		queue_entry_t *queue[RTE_EVENT_MAX_QUEUES_PER_DEV];
	} grp[NUM_SCHED_GRPS];
	odp_ticketlock_t grp_lock;

	/* Scheduler interface config options (not used in fast path) */
	schedule_config_t config_if;

} eventdev_global_t;

/* Eventdev local data */
typedef struct {
	struct {
		struct rte_event event[MAX_SCHED_BURST];
		uint16_t idx;
		uint16_t count;
	} cache;
	uint8_t port_id;
	uint8_t paused;
	uint8_t started;
} eventdev_local_t;

extern eventdev_global_t *_odp_eventdev_gbl;
extern __thread eventdev_local_t _odp_eventdev_local;

int _odp_service_setup(uint32_t service_id);

int _odp_dummy_link_queues(uint8_t dev_id, uint8_t dummy_linked_queues[], int num);

int _odp_dummy_unlink_queues(uint8_t dev_id, uint8_t dummy_linked_queues[], int num);

void _odp_rx_adapter_port_stop(uint16_t port_id);

int _odp_rx_adapter_close(void);

static inline uint8_t event_schedule_type(odp_schedule_sync_t sync)
{
	/* Ordered queues implemented using atomic queues */
	if (sync == ODP_SCHED_SYNC_PARALLEL)
		return RTE_SCHED_TYPE_PARALLEL;
	else
		return RTE_SCHED_TYPE_ATOMIC;
}

static inline odp_queue_t queue_from_qentry(queue_entry_t *queue)
{
	return (odp_queue_t)queue;
}

static inline queue_entry_t *qentry_from_index(uint32_t queue_id)
{
	return &_odp_eventdev_gbl->queue[queue_id];
}

static inline queue_entry_t *qentry_from_handle(odp_queue_t handle)
{
	return (queue_entry_t *)(uintptr_t)handle;
}

#ifdef __cplusplus
}
#endif

#endif
