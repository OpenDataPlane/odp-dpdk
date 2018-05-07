/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/queue.h>
#include <odp_queue_if.h>
#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp_config_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/sync.h>
#include <odp/api/traffic_mngr.h>
#include <odp_libconfig_internal.h>
#include <odp_eventdev_internal.h>

#include <rte_config.h>
#include <rte_service.h>
#include <rte_eventdev.h>

#include <odp/api/plat/ticketlock_inlines.h>

#define LOCK(queue_ptr)      _odp_ticketlock_lock(&((queue_ptr)->s.lock))
#define UNLOCK(queue_ptr)    _odp_ticketlock_unlock(&((queue_ptr)->s.lock))
#define LOCK_INIT(queue_ptr)  odp_ticketlock_init(&((queue_ptr)->s.lock))

#include <string.h>
#include <inttypes.h>

#define MIN_QUEUE_SIZE 8
#define DEFAULT_QUEUE_SIZE (4 * 1024)
#define MAX_QUEUE_SIZE (8 * 1024)

#define EVENT_QUEUE_FLOWS 32

#define EVENT_QUEUE_STATUS_UNUSED    0
#define EVENT_QUEUE_STATUS_FREE      1
#define EVENT_QUEUE_STATUS_RESERVED  2

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_READY        1
#define QUEUE_STATUS_SCHED        2

/* Number of priority levels  */
#define NUM_PRIO 8

ODP_STATIC_ASSERT(ODP_SCHED_PRIO_LOWEST == (NUM_PRIO - 1),
		  "lowest_prio_does_not_match_with_num_prios");

ODP_STATIC_ASSERT((ODP_SCHED_PRIO_NORMAL > 0) &&
		  (ODP_SCHED_PRIO_NORMAL < (NUM_PRIO - 1)),
		  "normal_prio_is_not_between_highest_and_lowest");

/* Thread local eventdev context */
__thread eventdev_local_t eventdev_local;

/* Global eventdev context */
eventdev_global_t *eventdev_gbl;

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param);

static eventdev_queue_t *event_queues(odp_schedule_sync_t sync)
{
	if (sync == ODP_SCHED_SYNC_PARALLEL)
		return eventdev_gbl->event_queue.parallel;
	else if (sync == ODP_SCHED_SYNC_ATOMIC)
		return eventdev_gbl->event_queue.atomic;
	else if (sync == ODP_SCHED_SYNC_ORDERED)
		return eventdev_gbl->event_queue.ordered;

	ODP_ABORT("Invalid schedule sync type\n");
	return NULL;
}

static int read_config_file(eventdev_global_t *eventdev)
{
	const char *str;
	int val = 0;

	ODP_PRINT("\nScheduler config\n----------------\n");

	str = "sched_eventdev.num_atomic_queues";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	ODP_PRINT("%s: %i\n", str, val);
	eventdev->event_queue.num_atomic = val;

	str = "sched_eventdev.num_ordered_queues";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	ODP_PRINT("%s: %i\n", str, val);
	eventdev->event_queue.num_ordered = val;

	str = "sched_eventdev.num_parallel_queues";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	ODP_PRINT("%s: %i\n\n", str, val);
	eventdev->event_queue.num_parallel = val;

	str = "sched_eventdev.num_ports";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	ODP_PRINT("%s: %i\n\n", str, val);
	eventdev->num_event_ports = val;

	return 0;
}

static int queue_capa(odp_queue_capability_t *capa, int sched)
{
	uint16_t max_sched;

	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = ODP_CONFIG_QUEUES;
	capa->plain.max_num     = ODP_CONFIG_QUEUES;
	capa->plain.max_size    = eventdev_gbl->plain_config.max_queue_size - 1;
	capa->plain.lockfree.max_num  = 0;
	capa->plain.lockfree.max_size = 0;

	max_sched = RTE_MAX(RTE_MAX(eventdev_gbl->event_queue.num_atomic,
				    eventdev_gbl->event_queue.num_ordered),
			    eventdev_gbl->event_queue.num_parallel);
	capa->sched.max_num     = RTE_MIN(ODP_CONFIG_QUEUES, max_sched);
	capa->sched.max_size    = eventdev_gbl->config.nb_events_limit;

	if (sched) {
		capa->max_ordered_locks = sched_fn->max_ordered_locks();
		capa->max_sched_groups  = sched_fn->num_grps();
		capa->sched_prios       = odp_schedule_num_prio();
	}

	return 0;
}

static void print_dev_info(const struct rte_event_dev_info *info)
{
	ODP_PRINT("\nEvent device info\n"
		  "-----------------\n"
		  "driver name: %s\n"
		  "min_dequeue_timeout_ns: %" PRIu32 "\n"
		  "max_dequeue_timeout_ns: %" PRIu32 "\n"
		  "dequeue_timeout_ns: %" PRIu32 "\n"
		  "max_event_queues: %" PRIu8 "\n"
		  "max_event_queue_flows: %" PRIu32 "\n"
		  "max_event_queue_priority_levels: %" PRIu8 "\n"
		  "max_event_priority_levels: %" PRIu8 "\n"
		  "max_event_ports: %" PRIu8 "\n"
		  "max_event_port_dequeue_depth: %" PRIu8 "\n"
		  "max_event_port_enqueue_depth: %" PRIu32 "\n"
		  "max_num_events: %" PRId32 "\n"
		  "event_dev_cap: %" PRIu32 "\n",
		  info->driver_name,
		  info->min_dequeue_timeout_ns,
		  info->max_dequeue_timeout_ns,
		  info->dequeue_timeout_ns,
		  info->max_event_queues,
		  info->max_event_queue_flows,
		  info->max_event_queue_priority_levels,
		  info->max_event_priority_levels,
		  info->max_event_ports,
		  info->max_event_port_dequeue_depth,
		  info->max_event_port_enqueue_depth,
		  info->max_num_events,
		  info->event_dev_cap);
}

int service_setup(uint32_t service_id)
{
	uint32_t cores[RTE_MAX_LCORE];
	uint32_t lcore = 0;
	int32_t num_cores;
	int32_t num_serv;
	int32_t min_num_serv = INT32_MAX;

	if (!rte_service_lcore_count()) {
		ODP_ERR("No service cores available\n");
		return -1;
	}

	/* Use the service core with the smallest number of running services */
	num_cores = rte_service_lcore_list(cores, RTE_MAX_LCORE);
	while (num_cores--) {
		rte_service_map_lcore_set(service_id, cores[num_cores], 0);
		num_serv = rte_service_lcore_count_services(cores[num_cores]);
		if (num_serv < min_num_serv) {
			lcore = cores[num_cores];
			min_num_serv = num_serv;
		}
	}
	if (rte_service_map_lcore_set(service_id, lcore, 1)) {
		ODP_ERR("Unable to map service to core\n");
		return -1;
	}
	return 0;
}

static int alloc_queues(eventdev_global_t *eventdev,
			const struct rte_event_dev_info *info)
{
	int num_queues;

	if (!eventdev->event_queue.num_atomic &&
	    !eventdev->event_queue.num_ordered &&
	    !eventdev->event_queue.num_parallel) {
		uint8_t queue_per_type = info->max_event_queues / 3;

		/* Divide eventdev queues evenly to ODP queue types */
		eventdev->event_queue.num_atomic = queue_per_type;
		eventdev->event_queue.num_ordered = queue_per_type;
		eventdev->event_queue.num_parallel = queue_per_type;

		num_queues = 3 * queue_per_type;
	} else {
		num_queues = eventdev->event_queue.num_atomic +
			     eventdev->event_queue.num_ordered +
			     eventdev->event_queue.num_parallel;
	}

	return num_queues;
}

static int setup_queues(uint8_t dev_id, uint8_t first_queue_id,
			uint8_t num_queues, uint32_t num_flows,
			odp_schedule_sync_t sync)
{
	eventdev_queue_t *queues = event_queues(sync);
	uint8_t i, j;
	uint8_t priority = ODP_SCHED_PRIO_NORMAL;

	for (i = first_queue_id, j = 0; j < num_queues; i++, j++) {
		struct rte_event_queue_conf queue_conf;
		eventdev_queue_t *event_queue = &queues[i];

		if (rte_event_queue_default_conf_get(dev_id, i, &queue_conf)) {
			ODP_ERR("rte_event_queue_default_conf_get failed\n");
			return -1;
		}
		queue_conf.schedule_type = event_schedule_type(sync);
		queue_conf.priority = priority;

		if (sync == ODP_SCHED_SYNC_ATOMIC)
			queue_conf.nb_atomic_flows = num_flows;
		else if (sync == ODP_SCHED_SYNC_ORDERED)
			queue_conf.nb_atomic_order_sequences = num_flows;

		if (rte_event_queue_setup(dev_id, i, &queue_conf)) {
			ODP_ERR("rte_event_queue_setup failed\n");
			return -1;
		}
		event_queue->id = i;
		event_queue->status = EVENT_QUEUE_STATUS_FREE;
	}
	return 0;
}

static int configure_queues(const eventdev_global_t *eventdev, uint8_t dev_id,
			    uint32_t num_flows)
{
	uint8_t first_queue_id = 0;

	if (setup_queues(dev_id, first_queue_id,
			 eventdev->event_queue.num_atomic, num_flows,
			 ODP_SCHED_SYNC_ATOMIC))
		return -1;
	first_queue_id += eventdev->event_queue.num_atomic;

	if (setup_queues(dev_id, first_queue_id,
			 eventdev->event_queue.num_parallel, num_flows,
			 ODP_SCHED_SYNC_PARALLEL))
		return -1;
	first_queue_id += eventdev->event_queue.num_parallel;

	if (setup_queues(dev_id, first_queue_id,
			 eventdev->event_queue.num_ordered, num_flows,
			 ODP_SCHED_SYNC_ORDERED))
		return -1;

	return 0;
}

/* Dummy link all queues to port zero to pass evendev start */
int link_all_queues(uint8_t dev_id,
		    const struct rte_event_dev_config *dev_conf)
{
	int ret;
	uint8_t priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
	uint8_t queue_id;

	for (queue_id = 0; queue_id < dev_conf->nb_event_queues; queue_id++) {
		ret = rte_event_port_link(dev_id, 0, &queue_id, &priority, 1);
		if (ret != 1) {
			ODP_ERR("rte_event_port_link failed: %d\n", ret);
			return -1;
		}
	}
	return 0;
}

/* Remove dummy links required for evendev start */
int unlink_all_queues(uint8_t dev_id,
		      const struct rte_event_dev_config *dev_conf)
{
	int i;

	for (i = 0; i < dev_conf->nb_event_ports; i++) {
		if (rte_event_port_unlink(dev_id, i, NULL, 0) < 0) {
			ODP_ERR("rte_event_port_unlink failed\n");
			return -1;
		}
	}
	return 0;
}

static int configure_ports(uint8_t dev_id, uint8_t nb_ports)
{
	struct rte_event_port_conf port_conf;
	uint8_t i;

	for (i = 0; i < nb_ports; i++) {
		if (rte_event_port_default_conf_get(dev_id, i, &port_conf)) {
			ODP_ERR("rte_event_port_default_conf_get failed\n");
			return -1;
		}

		if (rte_event_port_setup(dev_id, i, &port_conf)) {
			ODP_ERR("rte_event_port_setup failed\n");
			return -1;
		}
	}
	return 0;
}

static int init_event_dev(void)
{
	uint32_t num_flows;
	uint8_t dev_id = 0;
	uint8_t rx_adapter_id = 0;
	struct rte_event_dev_info info;
	struct rte_event_dev_config config;
	int ret;
	int i;

	if (rte_event_dev_count() < 1) {
		ODP_ERR("No eventdev devices found\n");
		return -1;
	}

	if (read_config_file(eventdev_gbl))
		return -1;

	eventdev_gbl->dev_id = dev_id;
	eventdev_gbl->rx_adapter.id = rx_adapter_id;
	eventdev_gbl->rx_adapter.status = RX_ADAPTER_INIT;
	odp_spinlock_init(&eventdev_gbl->rx_adapter.lock);
	odp_atomic_init_u32(&eventdev_gbl->num_started, 0);

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		odp_spinlock_init(&eventdev_gbl->port[i].lock);
		eventdev_gbl->port[i].linked = 0;
	}

	if (rte_event_dev_info_get(dev_id, &info)) {
		ODP_ERR("rte_event_dev_info_get failed\n");
		return -1;
	}
	print_dev_info(&info);

	eventdev_gbl->num_prio = NUM_PRIO;
	if (!(info.event_dev_cap & RTE_EVENT_DEV_CAP_EVENT_QOS)) {
		ODP_PRINT("  Only one QoS level supported!\n");
		eventdev_gbl->num_prio = 1;
	}

	memset(&config, 0, sizeof(struct rte_event_dev_config));
	config.dequeue_timeout_ns = 0;
	config.nb_events_limit  = info.max_num_events;
	config.nb_event_queues = alloc_queues(eventdev_gbl, &info);

	config.nb_event_ports = (ODP_THREAD_COUNT_MAX < info.max_event_ports) ?
			ODP_THREAD_COUNT_MAX : info.max_event_ports;
	/* RX adapter requires additional port which is reserved when
	 * rte_event_eth_rx_adapter_queue_add() is called. */
	config.nb_event_ports -= 1;
	if (eventdev_gbl->num_event_ports &&
	    eventdev_gbl->num_event_ports < config.nb_event_ports)
		config.nb_event_ports = eventdev_gbl->num_event_ports;

	num_flows = (EVENT_QUEUE_FLOWS < info.max_event_queue_flows) ?
			EVENT_QUEUE_FLOWS : info.max_event_queue_flows;
	config.nb_event_queue_flows = num_flows;
	config.nb_event_port_dequeue_depth = (MAX_SCHED_BURST <
			info.max_event_port_dequeue_depth) ? MAX_SCHED_BURST :
					info.max_event_port_dequeue_depth;
	config.nb_event_port_enqueue_depth = (MAX_SCHED_BURST <
			info.max_event_port_enqueue_depth) ? MAX_SCHED_BURST :
					info.max_event_port_enqueue_depth;
	/* RTE_EVENT_DEV_CFG_PER_DEQUEUE_TIMEOUT not supported by the SW
	 * eventdev */
	config.event_dev_cfg = 0;

	ret = rte_event_dev_configure(dev_id, &config);
	if (ret < 0) {
		ODP_ERR("rte_event_dev_configure failed\n");
		return -1;
	}
	eventdev_gbl->config = config;
	eventdev_gbl->num_event_ports = config.nb_event_ports;

	if (configure_ports(dev_id, config.nb_event_ports)) {
		ODP_ERR("Configuring eventdev ports failed\n");
		return -1;
	}

	if (configure_queues(eventdev_gbl, dev_id, num_flows)) {
		ODP_ERR("Configuring eventdev queues failed\n");
		return -1;
	}

	/* Eventdev requires that each queue is linked to at least one
	 * port at startup. */
	link_all_queues(dev_id, &config);

	if (!(info.event_dev_cap & RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED)) {
		uint32_t service_id;

		ret = rte_event_dev_service_id_get(dev_id, &service_id);
		if (ret) {
			ODP_ERR("Unable to retrieve service ID\n");
			return -1;
		}
		if (service_setup(service_id)) {
			ODP_ERR("Failed to setup service core\n");
			return -1;
		}
	}

	if (rte_event_dev_start(dev_id)) {
		ODP_ERR("rte_event_dev_start failed\n");
		return -1;
	}

	/* Unlink all ports from queues. Thread specific ports will be linked
	 * when the application calls schedule/enqueue for the first time. */
	if (unlink_all_queues(dev_id, &config)) {
		rte_event_dev_stop(dev_id);
		rte_event_dev_close(dev_id);
		return -1;
	}

	/* Scheduling groups */
	odp_spinlock_init(&eventdev_gbl->grp_lock);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		memset(eventdev_gbl->grp[i].name, 0,
		       ODP_SCHED_GROUP_NAME_LEN);
		odp_thrmask_zero(&eventdev_gbl->grp[i].mask);
	}

	eventdev_gbl->grp[ODP_SCHED_GROUP_ALL].allocated = 1;
	eventdev_gbl->grp[ODP_SCHED_GROUP_WORKER].allocated = 1;
	eventdev_gbl->grp[ODP_SCHED_GROUP_CONTROL].allocated = 1;

	odp_thrmask_setall(&eventdev_gbl->mask_all);

	return 0;
}

static int queue_init_global(void)
{
	uint32_t max_queue_size;
	uint32_t i;
	odp_shm_t shm;
	odp_queue_capability_t capa;

	ODP_DBG("Starts...\n");

	shm = odp_shm_reserve("_odp_eventdev_gbl",
			      sizeof(eventdev_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	eventdev_gbl = odp_shm_addr(shm);

	if (eventdev_gbl == NULL)
		return -1;

	memset(eventdev_gbl, 0, sizeof(eventdev_global_t));
	eventdev_gbl->shm = shm;

	if (init_event_dev())
		return -1;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_qentry(i);

		LOCK_INIT(queue);
		queue->s.index  = i;
		queue->s.handle = queue_from_index(i);
	}
	odp_ticketlock_init(&eventdev_gbl->lock);

	max_queue_size = eventdev_gbl->config.nb_events_limit;
	eventdev_gbl->plain_config.default_queue_size = DEFAULT_QUEUE_SIZE;
	eventdev_gbl->plain_config.max_queue_size = MAX_QUEUE_SIZE;
	eventdev_gbl->sched_config.max_queue_size = max_queue_size;

	queue_capa(&capa, 0);

	ODP_DBG("... done.\n");
	ODP_DBG("  queue_entry_t size %u\n", sizeof(queue_entry_t));
	ODP_DBG("  max num queues     %u\n", capa.max_queues);
	ODP_DBG("  max plain queue size     %u\n", capa.plain.max_size);
	ODP_DBG("  max sched queue size     %u\n", capa.sched.max_size);
	ODP_DBG("  max num lockfree   %u\n", capa.plain.lockfree.max_num);
	ODP_DBG("  max lockfree size  %u\n\n", capa.plain.lockfree.max_size);

	return 0;
}

static int queue_init_local(void)
{
	int thread_id = odp_thread_id();

	memset(&eventdev_local, 0, sizeof(eventdev_local_t));

	ODP_ASSERT(thread_id <= UINT8_MAX);
	eventdev_local.thr = thread_id;
	eventdev_local.paused = 0;
	eventdev_local.started = 0;

	return 0;
}

static int queue_term_local(void)
{
	return 0;
}

static int queue_term_global(void)
{
	int ret = 0;
	queue_entry_t *queue;
	int i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &eventdev_gbl->queue[i];
		LOCK(queue);
		if (queue->s.status != QUEUE_STATUS_FREE) {
			ODP_ERR("Not destroyed queue: %s\n", queue->s.name);
			ret = -1;
		}
		UNLOCK(queue);
	}

	if (rx_adapter_close())
		ret = -1;

	rte_event_dev_stop(eventdev_gbl->dev_id);
	if (rte_event_dev_close(eventdev_gbl->dev_id)) {
		ODP_ERR("Failed to close event device\n");
		ret = -1;
	}

	if (odp_shm_free(eventdev_gbl->shm)) {
		ODP_ERR("Shm free failed for evendev\n");
		ret = -1;
	}

	return ret;
}

static int queue_capability(odp_queue_capability_t *capa)
{
	return queue_capa(capa, 1);
}

static odp_queue_type_t queue_type(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.sched.group;
}

static uint32_t queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		queue->s.param.sched.lock_count : 0;
}

static odp_queue_t queue_create(const char *name,
				const odp_queue_param_t *param)
{
	uint32_t i;
	queue_entry_t *queue;
	odp_queue_t handle = ODP_QUEUE_INVALID;
	odp_queue_type_t type = ODP_QUEUE_TYPE_PLAIN;
	odp_queue_param_t default_param;

	if (param == NULL) {
		odp_queue_param_init(&default_param);
		param = &default_param;
	}

	if (param->nonblocking == ODP_BLOCKING &&
	    param->type == ODP_QUEUE_TYPE_PLAIN) {
		if (param->size > eventdev_gbl->plain_config.max_queue_size) {
			ODP_ERR("Invalid queue size\n");
			return ODP_QUEUE_INVALID;
		}
	} else if (param->nonblocking == ODP_BLOCKING &&
		   param->type == ODP_QUEUE_TYPE_SCHED) {
		if (param->size > eventdev_gbl->sched_config.max_queue_size) {
			ODP_ERR("Invalid queue size\n");
			return ODP_QUEUE_INVALID;
		}
	} else {
		ODP_ERR("Unsupported queue blocking status\n");
		return ODP_QUEUE_INVALID;
	}

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &eventdev_gbl->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		LOCK(queue);
		if (queue->s.status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(queue);
				ODP_ERR("Queue init failed\n");
				return ODP_QUEUE_INVALID;
			}

			type = queue->s.type;

			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->s.status = QUEUE_STATUS_SCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;
			UNLOCK(queue);
			break;
		}
		UNLOCK(queue);
	}

	if (handle == ODP_QUEUE_INVALID) {
		ODP_ERR("Invalid handle\n");
		return ODP_QUEUE_INVALID;
	}

	if (type == ODP_QUEUE_TYPE_SCHED) {
		if (sched_fn->init_queue(queue->s.index,
					 &queue->s.param.sched)) {
			queue->s.status = QUEUE_STATUS_FREE;
			ODP_ERR("schedule queue init failed\n");
			return ODP_QUEUE_INVALID;
		}
	}

	return handle;
}

static int queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = handle_to_qentry(handle);

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	LOCK(queue);
	if (queue->s.status == QUEUE_STATUS_FREE) {
		UNLOCK(queue);
		ODP_ERR("queue \"%s\" already free\n", queue->s.name);
		return -1;
	}
	if (queue->s.type == ODP_QUEUE_TYPE_PLAIN) {
		if (ring_st_is_empty(queue->s.ring_st) == 0) {
			UNLOCK(queue);
			ODP_ERR("queue \"%s\" not empty\n", queue->s.name);
			return -1;
		}
		ring_st_free(queue->s.ring_st);
	} else {
		uint8_t queue_id = queue->s.event_queue.id;
		eventdev_queue_t *queues;

		odp_ticketlock_lock(&eventdev_gbl->lock);

		queues = event_queues(queue->s.param.sched.sync);

		eventdev_gbl->queue_id_to_queue[queue_id] = ODP_QUEUE_INVALID;
		queues[queue_id].status = EVENT_QUEUE_STATUS_FREE;

		odp_ticketlock_unlock(&eventdev_gbl->lock);
	}

	switch (queue->s.status) {
	case QUEUE_STATUS_READY:
		queue->s.status = QUEUE_STATUS_FREE;
		break;
	case QUEUE_STATUS_SCHED:
		queue->s.status = QUEUE_STATUS_FREE;
		sched_fn->destroy_queue(queue->s.index);
		break;
	default:
		ODP_ABORT("Unexpected queue status\n");
	}

	UNLOCK(queue);

	return 0;
}

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	handle_to_qentry(handle)->s.param.context = context;
	odp_mb_full();
	return 0;
}

static void *queue_context(odp_queue_t handle)
{
	return handle_to_qentry(handle)->s.param.context;
}

static odp_queue_t queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &eventdev_gbl->queue[i];

		if (queue->s.status == QUEUE_STATUS_FREE)
			continue;

		LOCK(queue);
		if (strcmp(name, queue->s.name) == 0) {
			/* found it */
			UNLOCK(queue);
			return queue->s.handle;
		}
		UNLOCK(queue);
	}

	return ODP_QUEUE_INVALID;
}

static inline int enq_multi(queue_t q_int, odp_buffer_hdr_t *buf_hdr[],
			    int num)
{
	queue_entry_t *queue;
	struct rte_event ev[CONFIG_BURST_SIZE];
	uint16_t num_enq = 0;
	int i;

	queue = qentry_from_int(q_int);

	LOCK(queue);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		UNLOCK(queue);
		ODP_ERR("Bad queue status\n");
		return -1;
	}

	/* Use ring for unscheduled queues */
	if (queue->s.type == ODP_QUEUE_TYPE_PLAIN) {
		num_enq = ring_st_enq_multi(queue->s.ring_st,
					    (void **)buf_hdr, num);
		UNLOCK(queue);
	} else {
		uint8_t dev_id = eventdev_gbl->dev_id;
		uint8_t port_id = eventdev_local.thr;
		uint8_t sched = event_schedule_type(queue->s.param.sched.sync);
		uint8_t queue_id = queue->s.event_queue.id;
		uint8_t priority = queue->s.param.sched.prio;

		UNLOCK(queue);

		if (odp_unlikely(port_id >= eventdev_gbl->num_event_ports)) {
			ODP_ERR("Max %" PRIu8 " scheduled workers supported\n",
				eventdev_gbl->num_event_ports);
			return 0;
		}

		/* Check that port is linked. Should not be needed but SW
		 * eventdev schedules events to invalid ports unless this is
		 * done. */
		if (odp_unlikely(!eventdev_gbl->port[port_id].linked)) {
			if (resume_scheduling(dev_id, port_id))
				return 0;
		}

		for (i = 0; i < num; i++) {
			ev[i].flow_id = 0;
			ev[i].op = RTE_EVENT_OP_NEW;
			ev[i].sched_type = sched;
			ev[i].queue_id = queue_id;
			ev[i].event_type = RTE_EVENT_TYPE_CPU;
			ev[i].sub_event_type = 0;
			ev[i].priority = priority;
			ev[i].mbuf = &buf_hdr[i]->mb;
		}

		num_enq = rte_event_enqueue_new_burst(dev_id, port_id, ev, num);
	}

	return num_enq;
}

static int queue_int_enq_multi(queue_t q_int, odp_buffer_hdr_t *buf_hdr[],
			       int num)
{
	return enq_multi(q_int, buf_hdr, num);
}

static int queue_int_enq(queue_t q_int, odp_buffer_hdr_t *buf_hdr)
{
	int ret;

	ret = enq_multi(q_int, &buf_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	if (odp_unlikely(num == 0))
		return 0;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	return queue->s.enqueue_multi(qentry_to_int(queue),
				      (odp_buffer_hdr_t **)(uintptr_t)ev, num);
}

static int queue_enq(odp_queue_t handle, odp_event_t ev)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	return queue->s.enqueue(qentry_to_int(queue),
				(odp_buffer_hdr_t *)(uintptr_t)ev);
}

static inline int deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			    int num, int update_status ODP_UNUSED)
{
	int num_deq;

	LOCK(queue);

	if (odp_unlikely(queue->s.status < QUEUE_STATUS_READY)) {
		/* Bad queue, or queue has been destroyed. */
		UNLOCK(queue);
		return -1;
	}

	num_deq = ring_st_deq_multi(queue->s.ring_st, (void **)buf_hdr, num);

	UNLOCK(queue);

	return num_deq;
}

static int queue_int_deq_multi(queue_t q_int, odp_buffer_hdr_t *buf_hdr[],
			       int num)
{
	queue_entry_t *queue = qentry_from_int(q_int);

	return deq_multi(queue, buf_hdr, num, 0);
}

static odp_buffer_hdr_t *queue_int_deq(queue_t q_int)
{
	queue_entry_t *queue = qentry_from_int(q_int);
	odp_buffer_hdr_t *buf_hdr = NULL;
	int ret;

	ret = deq_multi(queue, &buf_hdr, 1, 0);

	if (ret == 1)
		return buf_hdr;
	else
		return NULL;
}

static int queue_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	return queue->s.dequeue_multi(qentry_to_int(queue),
				      (odp_buffer_hdr_t **)ev, num);
}

static odp_event_t queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue = handle_to_qentry(handle);

	return (odp_event_t)queue->s.dequeue(qentry_to_int(queue));
}

static int alloc_event_queue(odp_schedule_sync_t sync,
			     eventdev_queue_t *out_queue)
{
	eventdev_queue_t *queues = event_queues(sync);
	uint8_t i;
	const char *type_str;

	for (i = 0; i < MAX_EVENT_QUEUES; i++) {
		eventdev_queue_t *event_queue = &queues[i];

		if (event_queue->status == EVENT_QUEUE_STATUS_FREE) {
			event_queue->status = EVENT_QUEUE_STATUS_RESERVED;
			*out_queue = *event_queue;
			return 0;
		}
	}

	if (sync == ODP_SCHED_SYNC_ATOMIC)
		type_str = "atomic";
	else if (sync == ODP_SCHED_SYNC_ORDERED)
		type_str = "ordered";
	else
		type_str = "parallel";

	ODP_ERR("No free %s eventdev queues left\n", type_str);

	return -1;
}

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param)
{
	uint32_t queue_size;

	if (name == NULL) {
		queue->s.name[0] = 0;
	} else {
		strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);
		queue->s.name[ODP_QUEUE_NAME_LEN - 1] = 0;
	}
	memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	if (queue->s.param.sched.lock_count > sched_fn->max_ordered_locks())
		return -1;

	if (param->type == ODP_QUEUE_TYPE_SCHED) {
		eventdev_queue_t event_queue;
		uint8_t queue_id;

		queue->s.param.deq_mode = ODP_QUEUE_OP_DISABLED;

		odp_ticketlock_lock(&eventdev_gbl->lock);

		if (alloc_event_queue(param->sched.sync, &event_queue)) {
			odp_ticketlock_unlock(&eventdev_gbl->lock);
			return -1;
		}
		queue_id = event_queue.id;
		eventdev_gbl->queue_id_to_queue[queue_id] = queue->s.handle;
		queue->s.event_queue = event_queue;

		odp_ticketlock_unlock(&eventdev_gbl->lock);
	}

	queue->s.type = queue->s.param.type;

	queue->s.enqueue = queue_int_enq;
	queue->s.dequeue = queue_int_deq;
	queue->s.enqueue_multi = queue_int_enq_multi;
	queue->s.dequeue_multi = queue_int_deq_multi;

	queue->s.pktin = PKTIN_INVALID;
	queue->s.pktout = PKTOUT_INVALID;

	if (param->type == ODP_QUEUE_TYPE_SCHED)
		return 0;

	/* Use default size for all small queues to guarantee performance
	 * level. */
	queue_size = eventdev_gbl->plain_config.default_queue_size;
	if (param->size > eventdev_gbl->plain_config.default_queue_size)
		queue_size = param->size;

	/* Round up if not already a power of two */
	queue_size = ROUNDUP_POWER2_U32(queue_size);

	if (queue_size > eventdev_gbl->plain_config.max_queue_size) {
		ODP_ERR("Too large queue size %u\n", queue_size);
		return -1;
	}
	queue->s.ring_st = ring_st_create(queue->s.name, queue_size);
	if (queue->s.ring_st == NULL)
		return -1;

	return 0;
}

static void queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->nonblocking = ODP_BLOCKING;
	params->sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	params->sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	params->sched.group = ODP_SCHED_GROUP_ALL;
}

static int queue_info(odp_queue_t handle, odp_queue_info_t *info)
{
	uint32_t queue_id;
	queue_entry_t *queue;
	int status;

	if (odp_unlikely(info == NULL)) {
		ODP_ERR("Unable to store info, NULL ptr given\n");
		return -1;
	}

	queue_id = queue_to_index(handle);

	if (odp_unlikely(queue_id >= ODP_CONFIG_QUEUES)) {
		ODP_ERR("Invalid queue handle:%" PRIu64 "\n",
			odp_queue_to_u64(handle));
		return -1;
	}

	queue = get_qentry(queue_id);

	LOCK(queue);
	status = queue->s.status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE)) {
		UNLOCK(queue);
		ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->s.name;
	info->param = queue->s.param;

	UNLOCK(queue);

	return 0;
}

static uint64_t queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pktout_queue_t queue_get_pktout(queue_t q_int)
{
	return qentry_from_int(q_int)->s.pktout;
}

static void queue_set_pktout(queue_t q_int, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_int(q_int);

	qentry->s.pktout.pktio = pktio;
	qentry->s.pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(queue_t q_int)
{
	return qentry_from_int(q_int)->s.pktin;
}

static void queue_set_pktin(queue_t q_int, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_int(q_int);

	qentry->s.pktin.pktio = pktio;
	qentry->s.pktin.index = index;
}

static void queue_set_enq_deq_func(queue_t q_int,
				   queue_enq_fn_t enq,
				   queue_enq_multi_fn_t enq_multi,
				   queue_deq_fn_t deq,
				   queue_deq_multi_fn_t deq_multi)
{
	queue_entry_t *qentry = qentry_from_int(q_int);

	LOCK(qentry);

	if (enq)
		qentry->s.enqueue = enq;

	if (enq_multi)
		qentry->s.enqueue_multi = enq_multi;

	if (deq)
		qentry->s.dequeue = deq;

	if (deq_multi)
		qentry->s.dequeue_multi = deq_multi;

	UNLOCK(qentry);
}

static queue_t queue_from_ext(odp_queue_t handle)
{
	return qentry_to_int(handle_to_qentry(handle));
}

static odp_queue_t queue_to_ext(queue_t q_int)
{
	return qentry_from_int(q_int)->s.handle;
}

/* API functions */
queue_api_t queue_eventdev_api = {
	.queue_create = queue_create,
	.queue_destroy = queue_destroy,
	.queue_lookup = queue_lookup,
	.queue_capability = queue_capability,
	.queue_context_set = queue_context_set,
	.queue_context = queue_context,
	.queue_enq = queue_enq,
	.queue_enq_multi = queue_enq_multi,
	.queue_deq = queue_deq,
	.queue_deq_multi = queue_deq_multi,
	.queue_type = queue_type,
	.queue_sched_type = queue_sched_type,
	.queue_sched_prio = queue_sched_prio,
	.queue_sched_group = queue_sched_group,
	.queue_lock_count = queue_lock_count,
	.queue_to_u64 = queue_to_u64,
	.queue_param_init = queue_param_init,
	.queue_info = queue_info
};

/* Functions towards internal components */
queue_fn_t queue_eventdev_fn = {
	.init_global = queue_init_global,
	.term_global = queue_term_global,
	.init_local = queue_init_local,
	.term_local = queue_term_local,
	.from_ext = queue_from_ext,
	.to_ext = queue_to_ext,
	.enq = queue_int_enq,
	.enq_multi = queue_int_enq_multi,
	.deq = queue_int_deq,
	.deq_multi = queue_int_deq_multi,
	.get_pktout = queue_get_pktout,
	.set_pktout = queue_set_pktout,
	.get_pktin = queue_get_pktin,
	.set_pktin = queue_set_pktin,
	.set_enq_deq_fn = queue_set_enq_deq_func
};
