/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp/api/hints.h>
#include <odp_queue_basic_internal.h>

#include <odp_debug_internal.h>

static inline int spsc_enq_multi(odp_queue_t handle,
				 odp_buffer_hdr_t *buf_hdr[], int num)
{
	queue_entry_t *queue;
	ring_spsc_t ring_spsc;

	queue = qentry_from_handle(handle);
	ring_spsc = queue->s.ring_spsc;

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	return ring_spsc_enq_multi(ring_spsc, (void **)buf_hdr, num);
}

static inline int spsc_deq_multi(odp_queue_t handle,
				 odp_buffer_hdr_t *buf_hdr[], int num)
{
	queue_entry_t *queue;
	ring_spsc_t ring_spsc;

	queue = qentry_from_handle(handle);
	ring_spsc = queue->s.ring_spsc;

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		return -1;
	}

	return ring_spsc_deq_multi(ring_spsc, (void **)buf_hdr, num);
}

static int queue_spsc_enq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
				int num)
{
	return spsc_enq_multi(handle, buf_hdr, num);
}

static int queue_spsc_enq(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = spsc_enq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_spsc_deq_multi(odp_queue_t handle, odp_buffer_hdr_t *buf_hdr[],
				int num)
{
	return spsc_deq_multi(handle, buf_hdr, num);
}

static odp_buffer_hdr_t *queue_spsc_deq(odp_queue_t handle)
{
	odp_buffer_hdr_t *buf_hdr = NULL;
	int ret;

	ret = spsc_deq_multi(handle, &buf_hdr, 1);

	if (ret == 1)
		return buf_hdr;
	else
		return NULL;
}

void _odp_queue_spsc_init(queue_entry_t *queue, uint32_t queue_size)
{
	queue->s.enqueue = queue_spsc_enq;
	queue->s.dequeue = queue_spsc_deq;
	queue->s.enqueue_multi = queue_spsc_enq_multi;
	queue->s.dequeue_multi = queue_spsc_deq_multi;
	queue->s.orig_dequeue_multi = queue_spsc_deq_multi;

	queue->s.ring_spsc = ring_spsc_create(queue->s.name, queue_size);
	if (queue->s.ring_spsc == NULL)
		ODP_ABORT("Creating SPSC ring failed\n");
}
