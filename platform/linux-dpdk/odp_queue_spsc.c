/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#include <odp/api/hints.h>

#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_queue_basic_internal.h>

static inline int spsc_enq_multi(odp_queue_t handle,
				 _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	ring_spsc_t ring_spsc;

	queue = qentry_from_handle(handle);
	ring_spsc = queue->ring_spsc;

	if (odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	return ring_spsc_enq_multi(ring_spsc, (void **)event_hdr, num);
}

static inline int spsc_deq_multi(odp_queue_t handle,
				 _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	ring_spsc_t ring_spsc;

	queue = qentry_from_handle(handle);
	ring_spsc = queue->ring_spsc;

	if (odp_unlikely(queue->status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return -1;
	}

	return ring_spsc_deq_multi(ring_spsc, (void **)event_hdr, num);
}

static int queue_spsc_enq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
				int num)
{
	return spsc_enq_multi(handle, event_hdr, num);
}

static int queue_spsc_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	int ret;

	ret = spsc_enq_multi(handle, &event_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_spsc_deq_multi(odp_queue_t handle, _odp_event_hdr_t *event_hdr[],
				int num)
{
	return spsc_deq_multi(handle, event_hdr, num);
}

static _odp_event_hdr_t *queue_spsc_deq(odp_queue_t handle)
{
	_odp_event_hdr_t *event_hdr = NULL;
	int ret;

	ret = spsc_deq_multi(handle, &event_hdr, 1);

	if (ret == 1)
		return event_hdr;
	else
		return NULL;
}

void _odp_queue_spsc_init(queue_entry_t *queue, uint32_t queue_size)
{
	queue->enqueue = queue_spsc_enq;
	queue->dequeue = queue_spsc_deq;
	queue->enqueue_multi = queue_spsc_enq_multi;
	queue->dequeue_multi = queue_spsc_deq_multi;
	queue->orig_dequeue_multi = queue_spsc_deq_multi;

	queue->ring_spsc = ring_spsc_create(queue->name, queue_size);
	if (queue->ring_spsc == NULL)
		_ODP_ABORT("Creating SPSC ring failed\n");
}
