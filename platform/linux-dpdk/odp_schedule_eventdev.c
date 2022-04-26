/* Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/cpu.h>
#include <odp/api/event.h>
#include <odp/api/packet_io.h>
#include <odp/api/queue.h>
#include <odp/api/ticketlock.h>
#include <odp/api/thrmask.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_eventdev_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_schedule_if.h>
#include <odp_timer_internal.h>

#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_service.h>

#include <inttypes.h>
#include <string.h>

/* Start of named groups in group mask arrays */
#define SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Number of scheduling groups */
#define NUM_SCHED_GRPS 32

static inline odp_pktio_t index_to_pktio(int pktio_index)
{
	return (odp_pktio_t)(uintptr_t)pktio_index + 1;
}

static inline odp_queue_t queue_id_to_queue(uint8_t queue_id)
{
	return queue_from_qentry(qentry_from_index(queue_id));
}

static odp_event_t mbuf_to_event(struct rte_mbuf *mbuf)
{
	return (odp_event_t)mbuf;
}

static int link_port(uint8_t dev_id, uint8_t port_id, uint8_t queue_ids[],
		     uint8_t priorities[], uint16_t nb_links, uint8_t link_now)
{
	int ret;

	odp_ticketlock_lock(&_odp_eventdev_gbl->port_lock);

	if (!_odp_eventdev_gbl->port[port_id].linked && !link_now) {
		odp_ticketlock_unlock(&_odp_eventdev_gbl->port_lock);
		return 0;
	}

	ret = rte_event_port_link(dev_id, port_id, queue_ids, priorities,
				  nb_links);
	if (ret < 0 || (queue_ids && ret != nb_links)) {
		ODP_ERR("rte_event_port_link failed: %d\n", ret);
		odp_ticketlock_unlock(&_odp_eventdev_gbl->port_lock);
		return ret;
	}

	_odp_eventdev_gbl->port[port_id].linked = 1;

	odp_ticketlock_unlock(&_odp_eventdev_gbl->port_lock);

	return ret;
}

static int unlink_port(uint8_t dev_id, uint8_t port_id, uint8_t queue_ids[],
		       uint16_t nb_links)
{
	int ret;

	odp_ticketlock_lock(&_odp_eventdev_gbl->port_lock);

	if (!_odp_eventdev_gbl->port[port_id].linked) {
		odp_ticketlock_unlock(&_odp_eventdev_gbl->port_lock);
		return 0;
	}

	ret = rte_event_port_unlink(dev_id, port_id, queue_ids, nb_links);
	if (ret < 0) {
		ODP_ERR("rte_event_port_unlink failed: %d\n", ret);
		odp_ticketlock_unlock(&_odp_eventdev_gbl->port_lock);
		return ret;
	}

	do {
		ret = rte_event_port_unlinks_in_progress(dev_id, port_id);
		if (ret < 0) {
			ODP_ERR("rte_event_port_unlinks_in_progress failed: "
				"%d\n", ret);
			break;
		}
		odp_cpu_pause();
	} while (ret > 0);

	if (queue_ids == NULL)
		_odp_eventdev_gbl->port[port_id].linked = 0;

	odp_ticketlock_unlock(&_odp_eventdev_gbl->port_lock);

	return ret;
}

static int resume_scheduling(uint8_t dev_id, uint8_t port_id)
{
	uint8_t queue_ids[RTE_EVENT_MAX_QUEUES_PER_DEV];
	uint8_t priorities[RTE_EVENT_MAX_QUEUES_PER_DEV];
	int nb_links = 0;
	int ret;
	int i;

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		int j;

		if (!_odp_eventdev_gbl->grp[i].allocated ||
		    !odp_thrmask_isset(&_odp_eventdev_gbl->grp[i].mask,
				       _odp_eventdev_local.port_id))
			continue;

		for (j = 0; j < RTE_EVENT_MAX_QUEUES_PER_DEV; j++) {
			queue_entry_t *queue = _odp_eventdev_gbl->grp[i].queue[j];

			if (!queue)
				continue;

			queue_ids[nb_links] = queue->s.index;
			priorities[nb_links] = queue->s.eventdev.prio;
			nb_links++;
		}
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);

	if (!nb_links)
		return 0;

	ret = link_port(dev_id, port_id, queue_ids, priorities, nb_links, 1);
	if (ret != nb_links)
		return -1;

	if (_odp_eventdev_local.started == 0) {
		odp_atomic_inc_u32(&_odp_eventdev_gbl->num_started);
		_odp_eventdev_local.started = 1;
	}

	return 0;
}

static int link_group(int group, const odp_thrmask_t *mask, odp_bool_t unlink)
{
	odp_thrmask_t new_mask;
	uint8_t dev_id = _odp_eventdev_gbl->dev_id;
	uint8_t queue_ids[RTE_EVENT_MAX_QUEUES_PER_DEV];
	uint8_t priorities[RTE_EVENT_MAX_QUEUES_PER_DEV];
	int nb_links = 0;
	int ret;
	int thr;
	int i;

	for (i = 0; i < RTE_EVENT_MAX_QUEUES_PER_DEV; i++) {
		queue_entry_t *queue = _odp_eventdev_gbl->grp[group].queue[i];

		if (queue == NULL)
			continue;

		queue_ids[nb_links] = queue->s.index;
		priorities[nb_links] = queue->s.eventdev.prio;
		nb_links++;
	}

	new_mask = *mask;
	thr = odp_thrmask_first(&new_mask);
	while (thr >= 0) {
		uint8_t port_id = thr;

		thr = odp_thrmask_next(&new_mask, thr);

		if (unlink)
			ret = unlink_port(dev_id, port_id, queue_ids, nb_links);
		else
			ret = link_port(dev_id, port_id, queue_ids, priorities,
					nb_links, 0);
		if (ret < 0) {
			ODP_ERR("Modifying port links failed\n");
			return -1;
		}
	}

	return 0;
}

static int rx_adapter_create(uint8_t dev_id, uint8_t rx_adapter_id,
			     const struct rte_event_dev_config *config)
{
	struct rte_event_port_conf port_config;
	uint32_t capa;
	int ret;

	ret = rte_event_eth_rx_adapter_caps_get(dev_id, rx_adapter_id, &capa);
	if (ret) {
		ODP_ERR("rte_event_eth_rx_adapter_caps_get failed: %d\n", ret);
		return -1;
	}
	if ((capa & RTE_EVENT_ETH_RX_ADAPTER_CAP_MULTI_EVENTQ) == 0)
		_odp_eventdev_gbl->rx_adapter.single_queue = 1;

	memset(&port_config, 0, sizeof(struct rte_event_port_conf));
	port_config.new_event_threshold = config->nb_events_limit;
	port_config.dequeue_depth = config->nb_event_port_dequeue_depth;
	port_config.enqueue_depth = config->nb_event_port_enqueue_depth;
	ret = rte_event_eth_rx_adapter_create(rx_adapter_id, dev_id,
					      &port_config);
	if (ret) {
		ODP_ERR("rte_event_eth_rx_adapter_create failed: %d\n", ret);
		return -1;
	}

	_odp_eventdev_gbl->rx_adapter.status = RX_ADAPTER_STOPPED;

	return 0;
}

static int rx_adapter_add_queues(uint8_t rx_adapter_id, uint8_t port_id,
				 int num_pktin, int pktin_idx[],
				 odp_queue_t queues[])
{
	int num_dummy_links = _odp_eventdev_gbl->config.nb_event_queues;
	uint8_t dummy_links[num_dummy_links];
	int ret = 0;
	int i;

	/* SW eventdev requires that all queues have ports linked */
	num_dummy_links = _odp_dummy_link_queues(_odp_eventdev_gbl->dev_id, dummy_links,
						 num_dummy_links);

	for (i = 0; i < num_pktin; i++) {
		queue_entry_t *queue = qentry_from_handle(queues[i]);
		struct rte_event_eth_rx_adapter_queue_conf qconf;
		struct rte_event ev;
		int32_t rx_queue_id = pktin_idx[i];

		memset(&ev, 0, sizeof(struct rte_event));
		ev.queue_id = queue->s.index;
		ev.flow_id = 0;
		ev.priority = queue->s.eventdev.prio;
		ev.sched_type = event_schedule_type(queue->s.param.sched.sync);

		memset(&qconf, 0,
		       sizeof(struct rte_event_eth_rx_adapter_queue_conf));
		qconf.ev = ev;
		qconf.rx_queue_flags = 0;
		qconf.servicing_weight = 1;

		if (_odp_eventdev_gbl->rx_adapter.single_queue)
			rx_queue_id = -1;

		ret = rte_event_eth_rx_adapter_queue_add(rx_adapter_id, port_id,
							 rx_queue_id, &qconf);
		if (ret) {
			ODP_ERR("rte_event_eth_rx_adapter_queue_add failed\n");
			return -1;
		}

		if (_odp_eventdev_gbl->rx_adapter.single_queue)
			break;
	}

	if (_odp_dummy_unlink_queues(_odp_eventdev_gbl->dev_id, dummy_links,
				     num_dummy_links))
		return -1;

	return ret;
}

int _odp_rx_adapter_close(void)
{
	uint16_t port_id;
	uint8_t rx_adapter_id = _odp_eventdev_gbl->rx_adapter.id;
	int ret = 0;

	if (_odp_eventdev_gbl->rx_adapter.status == RX_ADAPTER_INIT)
		return ret;

	if (_odp_eventdev_gbl->rx_adapter.status != RX_ADAPTER_STOPPED &&
	    rte_event_eth_rx_adapter_stop(rx_adapter_id)) {
		ODP_ERR("Failed to stop RX adapter\n");
		ret = -1;
	}

	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_close(port_id);
	}

	_odp_eventdev_gbl->rx_adapter.status = RX_ADAPTER_INIT;

	return ret;
}

void _odp_rx_adapter_port_stop(uint16_t port_id)
{
	uint8_t rx_adapter_id = _odp_eventdev_gbl->rx_adapter.id;

	if (rte_event_eth_rx_adapter_queue_del(rx_adapter_id, port_id, -1))
		ODP_ERR("Failed to delete RX queue\n");

	rte_eth_dev_stop(port_id);
}

static int schedule_init_global(void)
{
	ODP_DBG("Using eventdev scheduler\n");
	return 0;
}

static int schedule_init_local(void)
{
	return 0;
}

static int schedule_term_local(void)
{
	return 0;
}

static int schedule_term_global(void)
{
	return 0;
}

static uint32_t schedule_max_ordered_locks(void)
{
	return 1;
}

static inline int schedule_min_prio(void)
{
	return 0;
}

static inline  int schedule_max_prio(void)
{
	return _odp_eventdev_gbl->num_prio - 1;
}

static inline  int schedule_default_prio(void)
{
	return schedule_max_prio() / 2;
}

static int schedule_create_queue(uint32_t qi,
				 const odp_schedule_param_t *sched_param)
{
	queue_entry_t *queue = qentry_from_index(qi);
	odp_thrmask_t mask;
	uint8_t dev_id = _odp_eventdev_gbl->dev_id;
	uint8_t queue_id = queue->s.index;
	uint8_t priority = queue->s.eventdev.prio;
	int thr;

	if (sched_param->group < 0 || sched_param->group >= NUM_SCHED_GRPS) {
		ODP_ERR("Bad schedule group\n");
		return -1;
	}

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	_odp_eventdev_gbl->grp[sched_param->group].queue[queue_id] = queue;

	mask = _odp_eventdev_gbl->grp[sched_param->group].mask;
	thr = odp_thrmask_first(&mask);
	while (0 <= thr) {
		link_port(dev_id, thr, &queue_id, &priority, 1, 0);
		thr = odp_thrmask_next(&mask, thr);
	}
	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);

	return 0;
}

static void schedule_destroy_queue(uint32_t qi)
{
	queue_entry_t *queue = qentry_from_index(qi);
	odp_thrmask_t mask;
	odp_schedule_group_t group = queue->s.param.sched.group;
	uint8_t dev_id = _odp_eventdev_gbl->dev_id;
	uint8_t queue_id = queue->s.index;
	int thr;

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	_odp_eventdev_gbl->grp[group].queue[queue_id] = NULL;

	mask = _odp_eventdev_gbl->grp[group].mask;
	thr = odp_thrmask_first(&mask);
	while (0 <= thr) {
		unlink_port(dev_id, thr, &queue_id, 1);
		thr = odp_thrmask_next(&mask, thr);
	}
	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
}

static void schedule_pktio_start(int pktio_index, int num_pktin,
				 int pktin_idx[], odp_queue_t queue[])
{
	pktio_entry_t *entry = get_pktio_entry(index_to_pktio(pktio_index));
	uint16_t port_id = _odp_dpdk_pktio_port_id(entry);
	uint8_t rx_adapter_id = _odp_eventdev_gbl->rx_adapter.id;

	/* All eventdev pktio devices should to be started before calling
	 * odp_schedule(). This is due to the SW eventdev requirement that all
	 * event queues are linked when rte_event_eth_rx_adapter_queue_add() is
	 * called. */
	if (odp_atomic_load_u32(&_odp_eventdev_gbl->num_started))
		ODP_PRINT("All ODP pktio devices used by the scheduler should "
			  "be started before calling odp_schedule() for the "
			  "first time.\n");

	_odp_eventdev_gbl->pktio[port_id] = entry;

	odp_ticketlock_lock(&_odp_eventdev_gbl->rx_adapter.lock);

	if (_odp_eventdev_gbl->rx_adapter.status == RX_ADAPTER_INIT &&
	    rx_adapter_create(_odp_eventdev_gbl->dev_id, rx_adapter_id,
			      &_odp_eventdev_gbl->config))
		ODP_ABORT("Creating eventdev RX adapter failed\n");

	if (rx_adapter_add_queues(rx_adapter_id, port_id, num_pktin, pktin_idx,
				  queue))
		ODP_ABORT("Adding RX adapter queues failed\n");

	if (_odp_eventdev_gbl->rx_adapter.status == RX_ADAPTER_STOPPED) {
		uint32_t service_id = 0;
		int ret;

		ret = rte_event_eth_rx_adapter_service_id_get(rx_adapter_id,
							      &service_id);
		if (ret && ret != -ESRCH) {
			ODP_ABORT("Unable to retrieve service ID\n");
		} else if (!ret) {
			if (_odp_service_setup(service_id))
				ODP_ABORT("Unable to start RX service\n");
		}

		if (rte_event_eth_rx_adapter_start(rx_adapter_id))
			ODP_ABORT("Unable to start RX adapter\n");

		_odp_eventdev_gbl->rx_adapter.status = RX_ADAPTER_RUNNING;
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->rx_adapter.lock);
}

static inline int classify_pkts(odp_packet_t packets[], int num)
{
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	int i, num_rx, num_ev, num_dst;
	odp_queue_t cur_queue;
	odp_event_t ev[num];
	odp_queue_t dst[num];
	int dst_idx[num];

	num_rx = 0;
	num_dst = 0;
	num_ev = 0;

	/* Some compilers need this dummy initialization */
	cur_queue = ODP_QUEUE_INVALID;

	for (i = 0; i < num; i++) {
		pkt = packets[i];
		pkt_hdr = packet_hdr(pkt);

		if (odp_unlikely(pkt_hdr->p.input_flags.dst_queue)) {
			/* Sort events for enqueue multi operation(s) */
			if (odp_unlikely(num_dst == 0)) {
				num_dst = 1;
				cur_queue = pkt_hdr->dst_queue;
				dst[0] = cur_queue;
				dst_idx[0] = 0;
			}

			ev[num_ev] = odp_packet_to_event(pkt);

			if (cur_queue != pkt_hdr->dst_queue) {
				cur_queue = pkt_hdr->dst_queue;
				dst[num_dst] = cur_queue;
				dst_idx[num_dst] = num_ev;
				num_dst++;
			}

			num_ev++;
			continue;
		}
		packets[num_rx++] = pkt;
	}

	/* Optimization for the common case */
	if (odp_likely(num_dst == 0))
		return num_rx;

	for (i = 0; i < num_dst; i++) {
		int num_enq, ret;
		int idx = dst_idx[i];

		if (i == (num_dst - 1))
			num_enq = num_ev - idx;
		else
			num_enq = dst_idx[i + 1] - idx;

		ret = odp_queue_enq_multi(dst[i], &ev[idx], num_enq);

		if (ret < 0)
			ret = 0;

		if (ret < num_enq)
			odp_event_free_multi(&ev[idx + ret], num_enq - ret);
	}

	return num_rx;
}

static inline uint16_t event_input(struct rte_event ev[], odp_event_t out_ev[],
				   uint16_t nb_events, odp_queue_t *out_queue)
{
	struct rte_mbuf *pkt_table[nb_events];
	uint16_t num_pkts = 0;
	uint16_t num_events = 0;
	uint16_t i;
	uint8_t first_queue;

	if (odp_unlikely(nb_events == 0))
		return 0;

	first_queue = ev[0].queue_id;

	for (i = 0; i < nb_events;  i++) {
		struct rte_event *event = &ev[i];

		if (odp_unlikely(event->queue_id != first_queue)) {
			uint16_t cache_idx, j;

			_odp_eventdev_local.cache.idx = 0;
			for (j = i; j < nb_events; j++) {
				cache_idx = _odp_eventdev_local.cache.count;
				_odp_eventdev_local.cache.event[cache_idx] = ev[j];
				_odp_eventdev_local.cache.count++;
			}
			break;
		}

		/* Packets have to be initialized */
		if (event->event_type == RTE_EVENT_TYPE_ETH_RX_ADAPTER) {
			pkt_table[num_pkts++] = event->mbuf;
			continue;
		}

		out_ev[num_events++] = mbuf_to_event(event->mbuf);
	}

	if (num_pkts) {
		pktio_entry_t *entry = _odp_eventdev_gbl->pktio[pkt_table[0]->port];

		num_pkts = _odp_input_pkts(entry, (odp_packet_t *)pkt_table, num_pkts);

		if (!odp_global_ro.init_param.not_used.feat.cls)
			num_pkts = classify_pkts((odp_packet_t *)pkt_table,
						 num_pkts);

		for (i = 0; i < num_pkts; i++)
			out_ev[num_events++] = mbuf_to_event(pkt_table[i]);
	}

	if (out_queue && num_events)
		*out_queue = queue_id_to_queue(first_queue);

	return num_events;
}

/* Fetch consecutive events from the same queue from cache */
static inline uint16_t input_cached(odp_event_t out_ev[], unsigned int max_num,
				    odp_queue_t *out_queue)
{
	struct rte_event ev[max_num];
	uint16_t idx = _odp_eventdev_local.cache.idx;
	uint16_t i;
	uint8_t first_queue = _odp_eventdev_local.cache.event[idx].queue_id;

	for (i = 0; i < max_num && _odp_eventdev_local.cache.count; i++) {
		uint16_t idx = _odp_eventdev_local.cache.idx;
		struct rte_event *event = &_odp_eventdev_local.cache.event[idx];

		if (odp_unlikely(event->queue_id != first_queue))
			break;

		_odp_eventdev_local.cache.idx++;
		_odp_eventdev_local.cache.count--;
		ev[i] = *event;
	}

	return event_input(ev, out_ev, i, out_queue);
}

static inline int schedule_loop(odp_queue_t *out_queue, uint64_t wait,
				odp_event_t out_ev[], unsigned int max_num)
{
	odp_time_t next, wtime;
	struct rte_event ev[max_num];
	int first = 1;
	uint16_t num_deq;
	uint8_t dev_id = _odp_eventdev_gbl->dev_id;
	uint8_t port_id = _odp_eventdev_local.port_id;

	if (odp_unlikely(port_id >= _odp_eventdev_gbl->num_event_ports)) {
		ODP_ERR("Max %" PRIu8 " scheduled workers supported\n",
			_odp_eventdev_gbl->num_event_ports);
		return 0;
	}

	/* Check that port is linked */
	if (odp_unlikely(!_odp_eventdev_gbl->port[port_id].linked &&
			 !_odp_eventdev_local.paused)) {
		if (resume_scheduling(dev_id, port_id))
			return 0;
	}

	if (odp_unlikely(max_num > MAX_SCHED_BURST))
		max_num = MAX_SCHED_BURST;

	if (odp_unlikely(_odp_eventdev_local.cache.count)) {
		num_deq = input_cached(out_ev, max_num, out_queue);
	} else {
		while (1) {
			num_deq = rte_event_dequeue_burst(dev_id, port_id, ev,
							  max_num, 0);
			if (num_deq) {
				num_deq = event_input(ev, out_ev, num_deq,
						      out_queue);
				timer_run(2);
				/* Classifier may enqueue events back to
				 * eventdev */
				if (odp_unlikely(num_deq == 0))
					continue;
				break;
			}
			timer_run(1);

			if (wait == ODP_SCHED_WAIT)
				continue;

			if (wait == ODP_SCHED_NO_WAIT)
				return 0;

			if (first) {
				wtime = odp_time_local_from_ns(wait);
				next = odp_time_sum(odp_time_local(), wtime);
				first = 0;
				continue;
			}

			if (odp_time_cmp(next, odp_time_local()) < 0)
				return 0;
		}
	}

	return num_deq;
}

static odp_event_t schedule(odp_queue_t *out_queue, uint64_t wait)
{
	odp_event_t ev;

	ev = ODP_EVENT_INVALID;

	schedule_loop(out_queue, wait, &ev, 1);

	return ev;
}

static int schedule_multi(odp_queue_t *out_queue, uint64_t wait,
			  odp_event_t events[], int num)
{
	return schedule_loop(out_queue, wait, events, num);
}

static int schedule_multi_wait(odp_queue_t *out_queue, odp_event_t events[],
			       int num)
{
	return schedule_loop(out_queue, ODP_SCHED_WAIT, events, num);
}

static int schedule_multi_no_wait(odp_queue_t *out_queue, odp_event_t events[],
				  int num)
{
	return schedule_loop(out_queue, ODP_SCHED_NO_WAIT, events, num);
}

static void schedule_pause(void)
{
	if (unlink_port(_odp_eventdev_gbl->dev_id,
			_odp_eventdev_local.port_id, NULL, 0) < 0)
		ODP_ERR("Unable to pause scheduling\n");

	_odp_eventdev_local.paused = 1;
}

static void schedule_resume(void)
{
	if (resume_scheduling(_odp_eventdev_gbl->dev_id, _odp_eventdev_local.port_id))
		ODP_ERR("Unable to resume scheduling\n");

	_odp_eventdev_local.paused = 0;
}

static void schedule_release_atomic(void)
{
	/* Nothing to do */
}

static void schedule_release_ordered(void)
{
	/* Nothing to do */
}

static uint64_t schedule_wait_time(uint64_t ns)
{
	return ns;
}

static inline void grp_update_mask(int grp, const odp_thrmask_t *new_mask)
{
	odp_thrmask_copy(&_odp_eventdev_gbl->grp[grp].mask, new_mask);
}

static int schedule_thr_add(odp_schedule_group_t group, int thr)
{
	odp_thrmask_t mask;
	odp_thrmask_t new_mask;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	odp_thrmask_or(&new_mask, &_odp_eventdev_gbl->grp[group].mask, &mask);
	grp_update_mask(group, &new_mask);

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);

	return 0;
}

static int schedule_thr_rem(odp_schedule_group_t group, int thr)
{
	odp_thrmask_t mask;
	odp_thrmask_t new_mask;

	if (group < 0 || group >= SCHED_GROUP_NAMED)
		return -1;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);
	odp_thrmask_xor(&new_mask, &mask, &_odp_eventdev_gbl->mask_all);

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	odp_thrmask_and(&new_mask, &_odp_eventdev_gbl->grp[group].mask,
			&new_mask);
	grp_update_mask(group, &new_mask);

	unlink_port(_odp_eventdev_gbl->dev_id, thr, NULL, 0);

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);

	return 0;
}

static void schedule_prefetch(int num)
{
	(void)num;
}

static int schedule_num_prio(void)
{
	return _odp_eventdev_gbl->num_prio;
}

static int schedule_num_grps(void)
{
	return NUM_SCHED_GRPS - SCHED_GROUP_NAMED;
}

static odp_schedule_group_t schedule_group_create(const char *name,
						  const odp_thrmask_t *mask)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	for (i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (!_odp_eventdev_gbl->grp[i].allocated) {
			char *grp_name = _odp_eventdev_gbl->grp[i].name;

			if (name == NULL) {
				grp_name[0] = 0;
			} else {
				strncpy(grp_name, name,
					ODP_SCHED_GROUP_NAME_LEN - 1);
				grp_name[ODP_SCHED_GROUP_NAME_LEN - 1] = 0;
			}

			grp_update_mask(i, mask);
			group = (odp_schedule_group_t)i;
			_odp_eventdev_gbl->grp[i].allocated = 1;
			break;
		}
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
	return group;
}

static int schedule_group_destroy(odp_schedule_group_t group)
{
	odp_thrmask_t zero;
	int ret;

	odp_thrmask_zero(&zero);

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    _odp_eventdev_gbl->grp[group].allocated) {
		grp_update_mask(group, &zero);
		memset(_odp_eventdev_gbl->grp[group].name, 0,
		       ODP_SCHED_GROUP_NAME_LEN);
		_odp_eventdev_gbl->grp[group].allocated = 0;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
	return ret;
}

static odp_schedule_group_t schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	for (i = SCHED_GROUP_NAMED; i < NUM_SCHED_GRPS; i++) {
		if (strcmp(name, _odp_eventdev_gbl->grp[i].name) == 0) {
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
	return group;
}

static int schedule_group_join(odp_schedule_group_t group,
			       const odp_thrmask_t *mask)
{
	int ret = 0;

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    _odp_eventdev_gbl->grp[group].allocated) {
		odp_thrmask_t new_mask;
		odp_thrmask_t link_mask;

		odp_thrmask_and(&link_mask, &_odp_eventdev_gbl->grp[group].mask,
				mask);
		odp_thrmask_xor(&link_mask, &link_mask, mask);
		odp_thrmask_or(&new_mask, &_odp_eventdev_gbl->grp[group].mask,
			       mask);
		grp_update_mask(group, &new_mask);

		ret = link_group(group, &link_mask, 0);
	} else {
		ret = -1;
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
	return ret;
}

static int schedule_group_leave(odp_schedule_group_t group,
				const odp_thrmask_t *mask)
{
	odp_thrmask_t new_mask;
	odp_thrmask_t unlink_mask;
	int ret = 0;

	odp_thrmask_xor(&new_mask, mask, &_odp_eventdev_gbl->mask_all);
	odp_thrmask_and(&unlink_mask, mask, &_odp_eventdev_gbl->mask_all);

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    _odp_eventdev_gbl->grp[group].allocated) {
		odp_thrmask_and(&unlink_mask, &_odp_eventdev_gbl->grp[group].mask,
				&unlink_mask);
		odp_thrmask_and(&new_mask, &_odp_eventdev_gbl->grp[group].mask,
				&new_mask);
		grp_update_mask(group, &new_mask);

		ret = link_group(group, &unlink_mask, 1);
	} else {
		ret = -1;
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
	return ret;
}

static int schedule_group_thrmask(odp_schedule_group_t group,
				  odp_thrmask_t *thrmask)
{
	int ret;

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    _odp_eventdev_gbl->grp[group].allocated) {
		*thrmask = _odp_eventdev_gbl->grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
	return ret;
}

static int schedule_group_info(odp_schedule_group_t group,
			       odp_schedule_group_info_t *info)
{
	int ret;

	odp_ticketlock_lock(&_odp_eventdev_gbl->grp_lock);

	if (group < NUM_SCHED_GRPS && group >= SCHED_GROUP_NAMED &&
	    _odp_eventdev_gbl->grp[group].allocated) {
		info->name    = _odp_eventdev_gbl->grp[group].name;
		info->thrmask = _odp_eventdev_gbl->grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_ticketlock_unlock(&_odp_eventdev_gbl->grp_lock);
	return ret;
}

static void schedule_order_lock(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_unlock(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_unlock_lock(uint32_t unlock_index,
				       uint32_t lock_index)
{
	(void)unlock_index;
	(void)lock_index;
}

static void schedule_order_lock_start(uint32_t lock_index)
{
	(void)lock_index;
}

static void schedule_order_lock_wait(uint32_t lock_index)
{
	(void)lock_index;
}

static void order_lock(void)
{
	/* Nothing to do */
}

static void order_unlock(void)
{
	/* Nothing to do */
}

static int schedule_capability(odp_schedule_capability_t *capa)
{
	uint16_t max_sched;

	memset(capa, 0, sizeof(odp_schedule_capability_t));

	max_sched = RTE_MAX(RTE_MAX(_odp_eventdev_gbl->event_queue.num_atomic,
				    _odp_eventdev_gbl->event_queue.num_ordered),
			    _odp_eventdev_gbl->event_queue.num_parallel);
	capa->max_queues        = RTE_MIN(CONFIG_MAX_SCHED_QUEUES, max_sched);
	capa->max_queue_size    = _odp_eventdev_gbl->config.nb_events_limit;
	capa->max_ordered_locks = schedule_max_ordered_locks();
	capa->max_groups        = schedule_num_grps();
	capa->max_prios         = odp_schedule_num_prio();

	return 0;
}

static void schedule_config_init(odp_schedule_config_t *config)
{
	odp_schedule_capability_t capa;

	schedule_capability(&capa);

	memset(config, 0, sizeof(odp_schedule_config_t));

	config->num_queues = capa.max_queues;
	config->queue_size = capa.max_queue_size / 2;
	config->max_flow_id = 0;
}

static int schedule_config(const odp_schedule_config_t *config)
{
	(void)config;

	return 0;
}

static void schedule_print(void)
{
	odp_schedule_capability_t capa;

	(void)schedule_capability(&capa);

	ODP_PRINT("\nScheduler debug info\n");
	ODP_PRINT("--------------------\n");
	ODP_PRINT("  scheduler:         eventdev\n");
	ODP_PRINT("  max groups:        %u\n", capa.max_groups);
	ODP_PRINT("  max priorities:    %u\n", capa.max_prios);
	ODP_PRINT("\n");
}

/* Fill in scheduler interface */
const schedule_fn_t _odp_schedule_eventdev_fn = {
	.pktio_start = schedule_pktio_start,
	.thr_add = schedule_thr_add,
	.thr_rem = schedule_thr_rem,
	.num_grps = schedule_num_grps,
	.create_queue = schedule_create_queue,
	.destroy_queue = schedule_destroy_queue,
	.sched_queue = NULL,
	.ord_enq_multi = NULL,
	.init_global = schedule_init_global,
	.term_global = schedule_term_global,
	.init_local  = schedule_init_local,
	.term_local  = schedule_term_local,
	.order_lock = order_lock,
	.order_unlock = order_unlock,
	.max_ordered_locks = schedule_max_ordered_locks,
	.get_config = NULL
};

/* Fill in scheduler API calls */
const schedule_api_t _odp_schedule_eventdev_api = {
	.schedule_wait_time       = schedule_wait_time,
	.schedule_capability      = schedule_capability,
	.schedule_config_init     = schedule_config_init,
	.schedule_config          = schedule_config,
	.schedule                 = schedule,
	.schedule_multi           = schedule_multi,
	.schedule_multi_wait      = schedule_multi_wait,
	.schedule_multi_no_wait   = schedule_multi_no_wait,
	.schedule_pause           = schedule_pause,
	.schedule_resume          = schedule_resume,
	.schedule_release_atomic  = schedule_release_atomic,
	.schedule_release_ordered = schedule_release_ordered,
	.schedule_prefetch        = schedule_prefetch,
	.schedule_min_prio        = schedule_min_prio,
	.schedule_max_prio        = schedule_max_prio,
	.schedule_default_prio    = schedule_default_prio,
	.schedule_num_prio        = schedule_num_prio,
	.schedule_group_create    = schedule_group_create,
	.schedule_group_destroy   = schedule_group_destroy,
	.schedule_group_lookup    = schedule_group_lookup,
	.schedule_group_join      = schedule_group_join,
	.schedule_group_leave     = schedule_group_leave,
	.schedule_group_thrmask   = schedule_group_thrmask,
	.schedule_group_info      = schedule_group_info,
	.schedule_order_lock      = schedule_order_lock,
	.schedule_order_unlock    = schedule_order_unlock,
	.schedule_order_unlock_lock  = schedule_order_unlock_lock,
	.schedule_order_lock_start   = schedule_order_lock_start,
	.schedule_order_lock_wait    = schedule_order_lock_wait,
	.schedule_print = schedule_print
};
