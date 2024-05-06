/* Copyright (c) 2019-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_eventdev_internal.h>
#include <odp/api/hints.h>
#include <odp/api/queue.h>
#include <odp/api/schedule.h>
#include <odp/api/shared_memory.h>
#include <odp/api/sync.h>
#include <odp/api/plat/queue_inline_types.h>
#include <odp/api/plat/ticketlock_inlines.h>

#include <odp_config_internal.h>
#include <odp_event_internal.h>
#include <odp_debug_internal.h>
#include <odp_macros_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_queue_if.h>
#include <odp_schedule_if.h>
#include <odp_string_internal.h>
#include <odp_timer_internal.h>

#include <rte_config.h>
#include <rte_eventdev.h>
#include <rte_service.h>

#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#define LOCK(queue_ptr)      odp_ticketlock_lock(&((queue_ptr)->lock))
#define UNLOCK(queue_ptr)    odp_ticketlock_unlock(&((queue_ptr)->lock))
#define LOCK_INIT(queue_ptr) odp_ticketlock_init(&((queue_ptr)->lock))

#define MIN_QUEUE_SIZE 8
#define DEFAULT_QUEUE_SIZE (4 * 1024)
#define MAX_QUEUE_SIZE (8 * 1024)

#define EVENT_QUEUE_FLOWS 32

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_READY        1
#define QUEUE_STATUS_SCHED        2

/* Number of priority levels  */
#define NUM_PRIO 8

/* Thread local eventdev context */
__thread eventdev_local_t _odp_eventdev_local;

/* Global eventdev context */
eventdev_global_t *_odp_eventdev_gbl;

extern _odp_queue_inline_offset_t _odp_queue_inline_offset;

static inline uint32_t queue_to_index(odp_queue_t handle)
{
	queue_entry_t *qentry = (queue_entry_t *)(uintptr_t)handle;

	return qentry->index;
}

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param);

static uint8_t event_queue_ids(odp_schedule_sync_t sync, uint8_t *first_id)
{
	*first_id = 0;
	if (sync == ODP_SCHED_SYNC_ATOMIC)
		return _odp_eventdev_gbl->event_queue.num_atomic;

	*first_id += _odp_eventdev_gbl->event_queue.num_atomic;
	if (sync == ODP_SCHED_SYNC_PARALLEL)
		return _odp_eventdev_gbl->event_queue.num_parallel;

	*first_id += _odp_eventdev_gbl->event_queue.num_parallel;
	if (sync == ODP_SCHED_SYNC_ORDERED)
		return _odp_eventdev_gbl->event_queue.num_ordered;

	_ODP_ABORT("Invalid schedule sync type\n");
	return 0;
}

static int read_config_file(eventdev_global_t *eventdev)
{
	const char *str;
	int val = 0;

	_ODP_PRINT("\nScheduler config\n----------------\n");

	str = "sched_eventdev.num_atomic_queues";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	_ODP_PRINT("%s: %i\n", str, val);
	eventdev->event_queue.num_atomic = val;

	str = "sched_eventdev.num_ordered_queues";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	_ODP_PRINT("%s: %i\n", str, val);
	eventdev->event_queue.num_ordered = val;

	str = "sched_eventdev.num_parallel_queues";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	_ODP_PRINT("%s: %i\n\n", str, val);
	eventdev->event_queue.num_parallel = val;

	str = "sched_eventdev.num_ports";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	_ODP_PRINT("%s: %i\n\n", str, val);
	eventdev->num_event_ports = val;

	return 0;
}

static int queue_capa(odp_queue_capability_t *capa, int sched ODP_UNUSED)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = CONFIG_MAX_QUEUES;
	capa->plain.max_num     = CONFIG_MAX_PLAIN_QUEUES;
	capa->plain.max_size    = _odp_eventdev_gbl->plain_config.max_queue_size - 1;
	capa->plain.lockfree.max_num  = 0;
	capa->plain.lockfree.max_size = 0;

	return 0;
}

static void print_dev_info(const struct rte_event_dev_info *info)
{
	_ODP_PRINT("\nEvent device info\n"
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

int _odp_service_setup(uint32_t service_id)
{
	uint32_t cores[RTE_MAX_LCORE];
	uint32_t lcore = 0;
	int32_t num_cores;
	int32_t num_serv;
	int32_t min_num_serv = INT32_MAX;

	if (!rte_service_lcore_count()) {
		_ODP_ERR("No service cores available\n");
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
		_ODP_ERR("Unable to map service to core\n");
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
	uint8_t i, j;

	for (i = first_queue_id, j = 0; j < num_queues; i++, j++) {
		struct rte_event_queue_conf queue_conf;
		queue_entry_t *queue = qentry_from_index(i);

		queue->sync = sync;

		if (rte_event_queue_default_conf_get(dev_id, i, &queue_conf)) {
			_ODP_ERR("rte_event_queue_default_conf_get failed\n");
			return -1;
		}
		queue_conf.schedule_type = event_schedule_type(sync);

		/* Ordered queues implemented using atomic queues */
		if (sync == ODP_SCHED_SYNC_ATOMIC ||
		    sync == ODP_SCHED_SYNC_ORDERED)
			queue_conf.nb_atomic_flows = num_flows;

		if (rte_event_queue_setup(dev_id, i, &queue_conf)) {
			_ODP_ERR("rte_event_queue_setup failed\n");
			return -1;
		}
	}
	return 0;
}

static int configure_queues(uint8_t dev_id, uint32_t num_flows)
{
	uint8_t first_queue_id;
	uint8_t num_queues;

	num_queues = event_queue_ids(ODP_SCHED_SYNC_ATOMIC, &first_queue_id);
	if (setup_queues(dev_id, first_queue_id, num_queues, num_flows,
			 ODP_SCHED_SYNC_ATOMIC))
		return -1;

	num_queues = event_queue_ids(ODP_SCHED_SYNC_PARALLEL, &first_queue_id);
	if (setup_queues(dev_id, first_queue_id, num_queues, num_flows,
			 ODP_SCHED_SYNC_PARALLEL))
		return -1;

	num_queues = event_queue_ids(ODP_SCHED_SYNC_ORDERED, &first_queue_id);
	if (setup_queues(dev_id, first_queue_id, num_queues, num_flows,
			 ODP_SCHED_SYNC_ORDERED))
		return -1;

	return 0;
}

static int queue_is_linked(uint8_t dev_id, uint8_t queue_id)
{
	uint8_t i;

	for (i = 0; i < _odp_eventdev_gbl->config.nb_event_ports; i++) {
		uint8_t queues[RTE_EVENT_MAX_QUEUES_PER_DEV];
		uint8_t priorities[RTE_EVENT_MAX_QUEUES_PER_DEV];
		int num_links;
		int j;

		num_links = rte_event_port_links_get(dev_id, i, queues,
						     priorities);
		for (j = 0; j < num_links; j++) {
			if (queues[j] == queue_id)
				return 1;
		}
	}
	return 0;
}

/* Dummy link all unlinked queues to port zero to pass evendev start */
int _odp_dummy_link_queues(uint8_t dev_id, uint8_t dummy_linked_queues[], int num)
{
	uint8_t priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
	uint8_t queue_id;
	int ret;
	int num_linked = 0;

	for (queue_id = 0; queue_id < num; queue_id++) {
		if (queue_is_linked(dev_id, queue_id))
			continue;

		ret = rte_event_port_link(dev_id, 0, &queue_id, &priority, 1);
		if (ret != 1) {
			_ODP_ERR("rte_event_port_link failed: %d\n", ret);
			return -1;
		}
		dummy_linked_queues[num_linked++] = queue_id;
	}
	return num_linked;
}

/* Remove dummy links to port zero */
int _odp_dummy_unlink_queues(uint8_t dev_id, uint8_t dummy_linked_queues[], int num)
{
	int i;

	for (i = 0; i < num; i++) {
		if (rte_event_port_unlink(dev_id, 0, &dummy_linked_queues[i],
					  1) < 0) {
			_ODP_ERR("rte_event_port_unlink failed\n");
			return -1;
		}
	}
	return 0;
}

static int configure_ports(uint8_t dev_id,
			   const struct rte_event_dev_config *dev_conf)
{
	struct rte_event_port_conf port_conf;
	uint8_t i;

	for (i = 0; i < dev_conf->nb_event_ports; i++) {
		if (rte_event_port_default_conf_get(dev_id, i, &port_conf)) {
			_ODP_ERR("rte_event_port_default_conf_get failed\n");
			return -1;
		}

		port_conf.new_event_threshold = dev_conf->nb_events_limit;
		port_conf.dequeue_depth = dev_conf->nb_event_port_dequeue_depth;
		port_conf.enqueue_depth = dev_conf->nb_event_port_enqueue_depth;

		if (rte_event_port_setup(dev_id, i, &port_conf)) {
			_ODP_ERR("rte_event_port_setup failed\n");
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
	uint8_t dummy_links[RTE_EVENT_MAX_QUEUES_PER_DEV];
	struct rte_event_dev_info info;
	struct rte_event_dev_config config;
	int num_dummy_links;
	int ret;
	int i;

	if (rte_event_dev_count() < 1) {
		_ODP_ERR("No eventdev devices found\n");
		return -1;
	}

	if (read_config_file(_odp_eventdev_gbl))
		return -1;

	_odp_eventdev_gbl->dev_id = dev_id;
	_odp_eventdev_gbl->rx_adapter.id = rx_adapter_id;
	_odp_eventdev_gbl->rx_adapter.status = RX_ADAPTER_INIT;
	odp_ticketlock_init(&_odp_eventdev_gbl->rx_adapter.lock);
	odp_atomic_init_u32(&_odp_eventdev_gbl->num_started, 0);

	odp_ticketlock_init(&_odp_eventdev_gbl->port_lock);
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		_odp_eventdev_gbl->port[i].linked = 0;

	if (rte_event_dev_info_get(dev_id, &info)) {
		_ODP_ERR("rte_event_dev_info_get failed\n");
		return -1;
	}
	print_dev_info(&info);

	_odp_eventdev_gbl->num_prio = RTE_MIN(NUM_PRIO,
					      info.max_event_queue_priority_levels);
	if (!(info.event_dev_cap & RTE_EVENT_DEV_CAP_QUEUE_QOS)) {
		_ODP_PRINT("  Only one QoS level supported!\n");
		_odp_eventdev_gbl->num_prio = 1;
	}

	memset(&config, 0, sizeof(struct rte_event_dev_config));
	config.dequeue_timeout_ns = 0;
	config.nb_events_limit  = info.max_num_events;
	config.nb_event_queues = alloc_queues(_odp_eventdev_gbl, &info);

	config.nb_event_ports = RTE_MIN(ODP_THREAD_COUNT_MAX,
					(int)info.max_event_ports);
	/* RX adapter requires additional port which is reserved when
	 * rte_event_eth_rx_adapter_queue_add() is called. */
	config.nb_event_ports -= 1;
	if (_odp_eventdev_gbl->num_event_ports &&
	    _odp_eventdev_gbl->num_event_ports < config.nb_event_ports)
		config.nb_event_ports = _odp_eventdev_gbl->num_event_ports;

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
		_ODP_ERR("rte_event_dev_configure failed\n");
		return -1;
	}
	_odp_eventdev_gbl->config = config;
	_odp_eventdev_gbl->num_event_ports = config.nb_event_ports;

	if (configure_ports(dev_id, &config)) {
		_ODP_ERR("Configuring eventdev ports failed\n");
		return -1;
	}

	if (configure_queues(dev_id, num_flows)) {
		_ODP_ERR("Configuring eventdev queues failed\n");
		return -1;
	}

	/* Eventdev requires that each queue is linked to at least one
	 * port at startup. */
	num_dummy_links = _odp_dummy_link_queues(dev_id, dummy_links,
						 config.nb_event_queues);

	if (!(info.event_dev_cap & RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED)) {
		uint32_t service_id;

		ret = rte_event_dev_service_id_get(dev_id, &service_id);
		if (ret) {
			_ODP_ERR("Unable to retrieve service ID\n");
			return -1;
		}
		if (_odp_service_setup(service_id)) {
			_ODP_ERR("Failed to setup service core\n");
			return -1;
		}
	}

	if (rte_event_dev_start(dev_id)) {
		_ODP_ERR("rte_event_dev_start failed\n");
		return -1;
	}

	/* Unlink all ports from queues. Thread specific ports will be linked
	 * when the application calls schedule/enqueue for the first time. */
	if (_odp_dummy_unlink_queues(dev_id, dummy_links, num_dummy_links)) {
		rte_event_dev_stop(dev_id);
		rte_event_dev_close(dev_id);
		return -1;
	}

	/* Scheduling groups */
	odp_ticketlock_init(&_odp_eventdev_gbl->grp_lock);

	for (i = 0; i < NUM_SCHED_GRPS; i++) {
		memset(_odp_eventdev_gbl->grp[i].name, 0,
		       ODP_SCHED_GROUP_NAME_LEN);
		odp_thrmask_zero(&_odp_eventdev_gbl->grp[i].mask);
	}

	_odp_eventdev_gbl->grp[ODP_SCHED_GROUP_ALL].allocated = 1;
	_odp_eventdev_gbl->grp[ODP_SCHED_GROUP_WORKER].allocated = 1;
	_odp_eventdev_gbl->grp[ODP_SCHED_GROUP_CONTROL].allocated = 1;

	odp_thrmask_setall(&_odp_eventdev_gbl->mask_all);

	return 0;
}

static int queue_init_global(void)
{
	uint32_t max_queue_size;
	uint32_t i;
	odp_shm_t shm;
	odp_queue_capability_t capa;

	_ODP_DBG("Queue init global\n");

	/* Fill in queue entry field offsets for inline functions */
	memset(&_odp_queue_inline_offset, 0,
	       sizeof(_odp_queue_inline_offset_t));
	_odp_queue_inline_offset.context = offsetof(queue_entry_t, param.context);

	shm = odp_shm_reserve("_odp_queue_eventdev_global",
			      sizeof(eventdev_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	_odp_eventdev_gbl = odp_shm_addr(shm);

	if (_odp_eventdev_gbl == NULL)
		return -1;

	memset(_odp_eventdev_gbl, 0, sizeof(eventdev_global_t));
	_odp_eventdev_gbl->shm = shm;

	if (init_event_dev())
		return -1;

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = qentry_from_index(i);

		LOCK_INIT(queue);
		queue->index  = i;
	}

	max_queue_size = _odp_eventdev_gbl->config.nb_events_limit;
	_odp_eventdev_gbl->plain_config.default_queue_size = DEFAULT_QUEUE_SIZE;
	_odp_eventdev_gbl->plain_config.max_queue_size = MAX_QUEUE_SIZE;
	_odp_eventdev_gbl->sched_config.max_queue_size = max_queue_size;

	queue_capa(&capa, 0);

	_ODP_DBG("  queue_entry_t size %zu\n", sizeof(queue_entry_t));
	_ODP_DBG("  max num queues     %u\n", capa.max_queues);
	_ODP_DBG("  max plain queue size     %u\n", capa.plain.max_size);
	_ODP_DBG("  max num lockfree   %u\n", capa.plain.lockfree.max_num);
	_ODP_DBG("  max lockfree size  %u\n\n", capa.plain.lockfree.max_size);

	return 0;
}

static int queue_init_local(void)
{
	int thread_id = odp_thread_id();

	memset(&_odp_eventdev_local, 0, sizeof(eventdev_local_t));

	_ODP_ASSERT(thread_id <= UINT8_MAX);
	_odp_eventdev_local.port_id = thread_id;
	_odp_eventdev_local.paused = 0;
	_odp_eventdev_local.started = 0;

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

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue = qentry_from_index(i);
		LOCK(queue);
		if (queue->status != QUEUE_STATUS_FREE) {
			_ODP_ERR("Not destroyed queue: %s\n", queue->name);
			ret = -1;
		}
		UNLOCK(queue);
	}

	if (_odp_rx_adapter_close())
		ret = -1;

	rte_event_dev_stop(_odp_eventdev_gbl->dev_id);

	/* Fix for DPDK 17.11 sync bug */
	sleep(1);

	if (rte_event_dev_close(_odp_eventdev_gbl->dev_id)) {
		_ODP_ERR("Failed to close event device\n");
		ret = -1;
	}

	if (odp_shm_free(_odp_eventdev_gbl->shm)) {
		_ODP_ERR("Shm free failed for evendev\n");
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
	return qentry_from_handle(handle)->type;
}

static odp_schedule_sync_t queue_sched_type(odp_queue_t handle)
{
	return qentry_from_handle(handle)->param.sched.sync;
}

static odp_schedule_prio_t queue_sched_prio(odp_queue_t handle)
{
	return qentry_from_handle(handle)->param.sched.prio;
}

static odp_schedule_group_t queue_sched_group(odp_queue_t handle)
{
	return qentry_from_handle(handle)->param.sched.group;
}

static uint32_t queue_lock_count(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
		queue->param.sched.lock_count : 0;
}

static odp_queue_t queue_create(const char *name,
				const odp_queue_param_t *param)
{
	uint32_t i;
	uint32_t max_idx;
	queue_entry_t *queue;
	odp_queue_type_t type;
	odp_queue_param_t default_param;
	odp_queue_t handle = ODP_QUEUE_INVALID;

	if (param == NULL) {
		odp_queue_param_init(&default_param);
		param = &default_param;
	}

	type = param->type;

	if (type == ODP_QUEUE_TYPE_SCHED) {
		if (param->sched.prio < odp_schedule_min_prio() ||
		    param->sched.prio > odp_schedule_max_prio()) {
			_ODP_ERR("Bad queue priority: %i\n", param->sched.prio);
			return ODP_QUEUE_INVALID;
		}
		if (param->size > _odp_eventdev_gbl->sched_config.max_queue_size)
			return ODP_QUEUE_INVALID;
	} else {
		if (param->size > _odp_eventdev_gbl->plain_config.max_queue_size)
			return ODP_QUEUE_INVALID;
	}

	/* Only blocking queues supported */
	if (param->nonblocking != ODP_BLOCKING)
		return ODP_QUEUE_INVALID;

	/* First RTE_EVENT_MAX_QUEUES_PER_DEV IDs are mapped directly
	 * to eventdev queue IDs */
	if (type == ODP_QUEUE_TYPE_SCHED) {
		/* Start scheduled queue indices from zero to enable direct
		 * mapping to scheduler implementation indices. */
		i = 0;
		max_idx = RTE_EVENT_MAX_QUEUES_PER_DEV;
	} else {
		i = RTE_EVENT_MAX_QUEUES_PER_DEV;
		/* All internal queues are of type plain */
		max_idx = CONFIG_MAX_QUEUES;
	}

	for (; i < max_idx; i++) {
		queue = qentry_from_index(i);

		if (queue->status != QUEUE_STATUS_FREE)
			continue;

		if (type == ODP_QUEUE_TYPE_SCHED &&
		    queue->sync != param->sched.sync)
			continue;

		LOCK(queue);
		if (queue->status == QUEUE_STATUS_FREE) {
			if (queue_init(queue, name, param)) {
				UNLOCK(queue);
				_ODP_ERR("Queue init failed\n");
				return ODP_QUEUE_INVALID;
			}

			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->status = QUEUE_STATUS_SCHED;
			else
				queue->status = QUEUE_STATUS_READY;
			handle = queue_from_qentry(queue);
			UNLOCK(queue);
			break;
		}
		UNLOCK(queue);
	}

	if (handle == ODP_QUEUE_INVALID) {
		_ODP_ERR("No free queues left\n");
		return ODP_QUEUE_INVALID;
	}

	if (type == ODP_QUEUE_TYPE_SCHED) {
		if (_odp_sched_fn->create_queue(queue->index,
						&queue->param.sched)) {
			queue->status = QUEUE_STATUS_FREE;
			_ODP_ERR("schedule queue init failed\n");
			return ODP_QUEUE_INVALID;
		}
	}

	return handle;
}

static int queue_destroy(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = qentry_from_handle(handle);

	if (handle == ODP_QUEUE_INVALID)
		return -1;

	LOCK(queue);
	if (queue->status == QUEUE_STATUS_FREE) {
		UNLOCK(queue);
		_ODP_ERR("queue \"%s\" already free\n", queue->name);
		return -1;
	}
	if (queue->type == ODP_QUEUE_TYPE_PLAIN) {
		if (ring_mpmc_is_empty(queue->ring_mpmc) == 0) {
			UNLOCK(queue);
			_ODP_ERR("queue \"%s\" not empty\n", queue->name);
			return -1;
		}
		ring_mpmc_free(queue->ring_mpmc);
	}

	switch (queue->status) {
	case QUEUE_STATUS_READY:
		queue->status = QUEUE_STATUS_FREE;
		break;
	case QUEUE_STATUS_SCHED:
		queue->status = QUEUE_STATUS_FREE;
		_odp_sched_fn->destroy_queue(queue->index);
		break;
	default:
		_ODP_ABORT("Unexpected queue status\n");
	}

	UNLOCK(queue);

	return 0;
}

static int queue_context_set(odp_queue_t handle, void *context,
			     uint32_t len ODP_UNUSED)
{
	odp_mb_full();
	qentry_from_handle(handle)->param.context = context;
	odp_mb_full();
	return 0;
}

static odp_queue_t queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < CONFIG_MAX_QUEUES; i++) {
		queue_entry_t *queue = qentry_from_index(i);

		if (queue->status == QUEUE_STATUS_FREE)
			continue;

		LOCK(queue);
		if (strcmp(name, queue->name) == 0) {
			/* found it */
			UNLOCK(queue);
			return queue_from_qentry(queue);
		}
		UNLOCK(queue);
	}

	return ODP_QUEUE_INVALID;
}

static inline int _plain_queue_enq_multi(odp_queue_t handle,
					 _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	int num_enq;
	ring_mpmc_t ring_mpmc;

	queue = qentry_from_handle(handle);
	ring_mpmc = queue->ring_mpmc;

	num_enq = ring_mpmc_enq_multi(ring_mpmc, (void **)event_hdr, num);

	return num_enq;
}

static inline int _plain_queue_deq_multi(odp_queue_t handle,
					 _odp_event_hdr_t *event_hdr[], int num)
{
	int num_deq;
	queue_entry_t *queue;
	ring_mpmc_t ring_mpmc;

	queue = qentry_from_handle(handle);
	ring_mpmc = queue->ring_mpmc;

	num_deq = ring_mpmc_deq_multi(ring_mpmc, (void **)event_hdr, num);

	return num_deq;
}

static int plain_queue_enq_multi(odp_queue_t handle,
				 _odp_event_hdr_t *event_hdr[], int num)
{
	return _plain_queue_enq_multi(handle, event_hdr, num);
}

static int plain_queue_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	int ret;

	ret = _plain_queue_enq_multi(handle, &event_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int plain_queue_deq_multi(odp_queue_t handle,
				 _odp_event_hdr_t *event_hdr[], int num)
{
	return _plain_queue_deq_multi(handle, event_hdr, num);
}

static _odp_event_hdr_t *plain_queue_deq(odp_queue_t handle)
{
	_odp_event_hdr_t *event_hdr = NULL;
	int ret;

	ret = _plain_queue_deq_multi(handle, &event_hdr, 1);

	if (ret == 1)
		return event_hdr;
	else
		return NULL;
}

static int error_enqueue(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	(void)event_hdr;

	_ODP_ERR("Enqueue not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

	return -1;
}

static int error_enqueue_multi(odp_queue_t handle,
			       _odp_event_hdr_t *event_hdr[], int num)

{
	(void)event_hdr;
	(void)num;

	_ODP_ERR("Enqueue multi not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

	return -1;
}

static _odp_event_hdr_t *error_dequeue(odp_queue_t handle)
{
	_ODP_ERR("Dequeue not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

	return NULL;
}

static int error_dequeue_multi(odp_queue_t handle,
			       _odp_event_hdr_t *event_hdr[], int num)
{
	(void)event_hdr;
	(void)num;

	_ODP_ERR("Dequeue multi not supported (0x%" PRIx64 ")\n", odp_queue_to_u64(handle));

	return -1;
}

static void queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
	params->type = ODP_QUEUE_TYPE_PLAIN;
	params->enq_mode = ODP_QUEUE_OP_MT;
	params->deq_mode = ODP_QUEUE_OP_MT;
	params->nonblocking = ODP_BLOCKING;
	params->sched.prio  = odp_schedule_default_prio();
	params->sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	params->sched.group = ODP_SCHED_GROUP_ALL;
}

static int queue_info(odp_queue_t handle, odp_queue_info_t *info)
{
	uint32_t queue_id;
	queue_entry_t *queue;
	int status;

	if (odp_unlikely(info == NULL)) {
		_ODP_ERR("Unable to store info, NULL ptr given\n");
		return -1;
	}

	queue_id = queue_to_index(handle);

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
		_ODP_ERR("Invalid queue handle: 0x%" PRIx64 "\n", odp_queue_to_u64(handle));
		return -1;
	}

	queue = qentry_from_index(queue_id);

	LOCK(queue);
	status = queue->status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE)) {
		UNLOCK(queue);
		_ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->name;
	info->param = queue->param;

	UNLOCK(queue);

	return 0;
}

static void queue_print(odp_queue_t handle)
{
	odp_pktio_info_t pktio_info;
	queue_entry_t *queue;
	uint32_t queue_id;
	int status;

	queue_id = queue_to_index(handle);

	if (odp_unlikely(queue_id >= CONFIG_MAX_QUEUES)) {
		_ODP_ERR("Invalid queue handle: 0x%" PRIx64 "\n", odp_queue_to_u64(handle));
		return;
	}

	queue = qentry_from_index(queue_id);

	LOCK(queue);
	status = queue->status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE)) {
		UNLOCK(queue);
		_ODP_ERR("Invalid queue status:%d\n", status);
		return;
	}
	_ODP_PRINT("\nQueue info\n");
	_ODP_PRINT("----------\n");
	_ODP_PRINT("  handle          %p\n", (void *)handle);
	_ODP_PRINT("  index           %" PRIu32 "\n", queue->index);
	_ODP_PRINT("  name            %s\n", queue->name);
	_ODP_PRINT("  enq mode        %s\n",
		   queue->param.enq_mode == ODP_QUEUE_OP_MT ? "ODP_QUEUE_OP_MT" :
		   (queue->param.enq_mode == ODP_QUEUE_OP_MT_UNSAFE ? "ODP_QUEUE_OP_MT_UNSAFE" :
		    (queue->param.enq_mode == ODP_QUEUE_OP_DISABLED ? "ODP_QUEUE_OP_DISABLED" :
		     "unknown")));
	_ODP_PRINT("  deq mode        %s\n",
		   queue->param.deq_mode == ODP_QUEUE_OP_MT ? "ODP_QUEUE_OP_MT" :
		   (queue->param.deq_mode == ODP_QUEUE_OP_MT_UNSAFE ? "ODP_QUEUE_OP_MT_UNSAFE" :
		    (queue->param.deq_mode == ODP_QUEUE_OP_DISABLED ? "ODP_QUEUE_OP_DISABLED" :
		     "unknown")));
	_ODP_PRINT("  non-blocking    %s\n",
		   queue->param.nonblocking == ODP_BLOCKING ? "ODP_BLOCKING" :
		   (queue->param.nonblocking == ODP_NONBLOCKING_LF ? "ODP_NONBLOCKING_LF" :
		    (queue->param.nonblocking == ODP_NONBLOCKING_WF ? "ODP_NONBLOCKING_WF" :
		     "unknown")));
	_ODP_PRINT("  type            %s\n",
		   queue->type == ODP_QUEUE_TYPE_PLAIN ? "ODP_QUEUE_TYPE_PLAIN" :
		   (queue->type == ODP_QUEUE_TYPE_SCHED ? "ODP_QUEUE_TYPE_SCHED" : "unknown"));
	if (queue->type == ODP_QUEUE_TYPE_SCHED) {
		_ODP_PRINT("    sync          %s\n",
			   queue->param.sched.sync == ODP_SCHED_SYNC_PARALLEL ?
			   "ODP_SCHED_SYNC_PARALLEL" :
			   (queue->param.sched.sync == ODP_SCHED_SYNC_ATOMIC ?
			    "ODP_SCHED_SYNC_ATOMIC" :
			    (queue->param.sched.sync == ODP_SCHED_SYNC_ORDERED ?
			     "ODP_SCHED_SYNC_ORDERED" : "unknown")));
		_ODP_PRINT("    priority      %d\n", queue->param.sched.prio);
		_ODP_PRINT("    group         %d\n", queue->param.sched.group);
	}
	if (queue->pktin.pktio != ODP_PKTIO_INVALID) {
		if (!odp_pktio_info(queue->pktin.pktio, &pktio_info))
			_ODP_PRINT("  pktin           %s\n", pktio_info.name);
	}
	if (queue->pktout.pktio != ODP_PKTIO_INVALID) {
		if (!odp_pktio_info(queue->pktout.pktio, &pktio_info))
			_ODP_PRINT("  pktout          %s\n", pktio_info.name);
	}
	_ODP_PRINT("  timers          %" PRIu64 "\n",
		   odp_atomic_load_u64(&queue->num_timers));
	_ODP_PRINT("  status          %s\n",
		   queue->status == QUEUE_STATUS_READY ? "ready" :
		   (queue->status == QUEUE_STATUS_SCHED ? "scheduled" : "clearunknown"));
	_ODP_PRINT("  param.size      %" PRIu32 "\n", queue->param.size);
	if (queue->type == ODP_QUEUE_TYPE_PLAIN) {
		_ODP_PRINT("  implementation  ring_mpmc\n");
		_ODP_PRINT("  length          %" PRIu32 "/%" PRIu32 "\n",
			   ring_mpmc_length(queue->ring_mpmc),
			   ring_mpmc_max_length(queue->ring_mpmc));
	} else {
		_ODP_PRINT("  implementation  eventdev\n");
	}
	_ODP_PRINT("\n");

	UNLOCK(queue);
}

static inline int _sched_queue_enq_multi(odp_queue_t handle,
					 _odp_event_hdr_t *event_hdr[], int num)
{
	queue_entry_t *queue;
	struct rte_event ev[CONFIG_BURST_SIZE];
	uint16_t num_enq = 0;
	uint8_t dev_id = _odp_eventdev_gbl->dev_id;
	uint8_t port_id = _odp_eventdev_local.port_id;
	uint8_t sched;
	uint8_t queue_id;
	uint8_t priority;
	int i;

	queue = qentry_from_handle(handle);

	LOCK(queue);

	if (odp_unlikely(queue->status != QUEUE_STATUS_SCHED)) {
		UNLOCK(queue);
		_ODP_ERR("Bad queue status\n");
		return -1;
	}

	sched = event_schedule_type(queue->param.sched.sync);
	queue_id = queue->index;
	priority = queue->eventdev.prio;

	UNLOCK(queue);

	if (odp_unlikely(port_id >= _odp_eventdev_gbl->num_event_ports)) {
		_ODP_ERR("Max %" PRIu8 " scheduled workers supported\n",
			 _odp_eventdev_gbl->num_event_ports);
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
		ev[i].mbuf = &event_hdr[i]->mb;
	}

	num_enq = rte_event_enqueue_new_burst(dev_id, port_id, ev, num);

	return num_enq;
}

static int sched_queue_enq_multi(odp_queue_t handle,
				 _odp_event_hdr_t *event_hdr[], int num)
{
	return _sched_queue_enq_multi(handle, event_hdr, num);
}

static int sched_queue_enq(odp_queue_t handle, _odp_event_hdr_t *event_hdr)
{
	int ret;

	ret = _sched_queue_enq_multi(handle, &event_hdr, 1);

	if (ret == 1)
		return 0;
	else
		return -1;
}

static int queue_init(queue_entry_t *queue, const char *name,
		      const odp_queue_param_t *param)
{
	uint32_t queue_size;
	odp_queue_type_t queue_type;

	queue_type = param->type;

	if (name == NULL)
		queue->name[0] = 0;
	else
		_odp_strcpy(queue->name, name, ODP_QUEUE_NAME_LEN);

	memcpy(&queue->param, param, sizeof(odp_queue_param_t));
	if (queue->param.sched.lock_count > _odp_sched_fn->max_ordered_locks())
		return -1;

	/* Convert ODP priority to eventdev priority:
	 *     ODP_SCHED_PRIO_HIGHEST == RTE_EVENT_DEV_PRIORITY_LOWEST */
	queue->eventdev.prio = odp_schedule_max_prio() - param->sched.prio;

	if (queue_type == ODP_QUEUE_TYPE_SCHED)
		queue->param.deq_mode = ODP_QUEUE_OP_DISABLED;

	queue->type = queue_type;
	odp_atomic_init_u64(&queue->num_timers, 0);

	queue->pktin = PKTIN_INVALID;
	queue->pktout = PKTOUT_INVALID;

	queue_size = param->size;
	if (queue_size == 0)
		queue_size = _odp_eventdev_gbl->plain_config.default_queue_size;

	if (queue_size < MIN_QUEUE_SIZE)
		queue_size = MIN_QUEUE_SIZE;

	if (queue_type == ODP_QUEUE_TYPE_PLAIN &&
	    queue_size > _odp_eventdev_gbl->plain_config.max_queue_size) {
		_ODP_ERR("Too large queue size %u\n", queue_size);
		return -1;
	}

	/* Ring size must larger than queue_size */
	if (_ODP_CHECK_IS_POWER2(queue_size))
		queue_size++;

	/* Round up if not already a power of two */
	queue_size = _ODP_ROUNDUP_POWER2_U32(queue_size);

	/* Default to error functions */
	queue->enqueue            = error_enqueue;
	queue->enqueue_multi      = error_enqueue_multi;
	queue->dequeue            = error_dequeue;
	queue->dequeue_multi      = error_dequeue_multi;
	queue->orig_dequeue_multi = error_dequeue_multi;

	if (queue_type == ODP_QUEUE_TYPE_PLAIN) {
		queue->enqueue            = plain_queue_enq;
		queue->enqueue_multi      = plain_queue_enq_multi;
		queue->dequeue            = plain_queue_deq;
		queue->dequeue_multi      = plain_queue_deq_multi;
		queue->orig_dequeue_multi = plain_queue_deq_multi;

		queue->ring_mpmc = ring_mpmc_create(queue->name, queue_size);
		if (queue->ring_mpmc == NULL) {
			_ODP_ERR("Creating MPMC ring failed\n");
			return -1;
		}
	} else {
		queue->enqueue            = sched_queue_enq;
		queue->enqueue_multi      = sched_queue_enq_multi;
	}
	return 0;
}

static uint64_t queue_to_u64(odp_queue_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pktout_queue_t queue_get_pktout(odp_queue_t handle)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	return qentry->pktout;
}

static void queue_set_pktout(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	qentry->pktout.pktio = pktio;
	qentry->pktout.index = index;
}

static odp_pktin_queue_t queue_get_pktin(odp_queue_t handle)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	return qentry->pktin;
}

static void queue_set_pktin(odp_queue_t handle, odp_pktio_t pktio, int index)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	qentry->pktin.pktio = pktio;
	qentry->pktin.index = index;
}

static void queue_set_enq_deq_func(odp_queue_t handle,
				   queue_enq_fn_t enq,
				   queue_enq_multi_fn_t enq_multi,
				   queue_deq_fn_t deq,
				   queue_deq_multi_fn_t deq_multi)
{
	queue_entry_t *qentry = qentry_from_handle(handle);

	if (enq)
		qentry->enqueue = enq;

	if (enq_multi)
		qentry->enqueue_multi = enq_multi;

	if (deq)
		qentry->dequeue = deq;

	if (deq_multi)
		qentry->dequeue_multi = deq_multi;
}

static int queue_orig_multi(odp_queue_t handle,
			    _odp_event_hdr_t **event_hdr, int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->orig_dequeue_multi(handle, event_hdr, num);
}

static int queue_api_enq_multi(odp_queue_t handle,
			       const odp_event_t ev[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	if (odp_unlikely(num == 0))
		return 0;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	return queue->enqueue_multi(handle, (_odp_event_hdr_t **)(uintptr_t)ev, num);
}

static void queue_timer_add(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	odp_atomic_inc_u64(&queue->num_timers);
}

static void queue_timer_rem(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	odp_atomic_dec_u64(&queue->num_timers);
}

static int queue_api_enq(odp_queue_t handle, odp_event_t ev)
{
	queue_entry_t *queue = qentry_from_handle(handle);

	return queue->enqueue(handle, (_odp_event_hdr_t *)(uintptr_t)ev);
}

static int queue_api_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	int ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	ret = queue->dequeue_multi(handle, (_odp_event_hdr_t **)ev, num);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->num_timers))
		timer_run(ret ? 2 : 1);

	return ret;
}

static odp_event_t queue_api_deq(odp_queue_t handle)
{
	queue_entry_t *queue = qentry_from_handle(handle);
	odp_event_t ev = (odp_event_t)queue->dequeue(handle);

	if (odp_global_rw->inline_timers &&
	    odp_atomic_load_u64(&queue->num_timers))
		timer_run(ev != ODP_EVENT_INVALID ? 2 : 1);

	return ev;
}

/* API functions */
_odp_queue_api_fn_t _odp_queue_eventdev_api = {
	.queue_create = queue_create,
	.queue_destroy = queue_destroy,
	.queue_lookup = queue_lookup,
	.queue_capability = queue_capability,
	.queue_context_set = queue_context_set,
	.queue_enq = queue_api_enq,
	.queue_enq_multi = queue_api_enq_multi,
	.queue_deq = queue_api_deq,
	.queue_deq_multi = queue_api_deq_multi,
	.queue_type = queue_type,
	.queue_sched_type = queue_sched_type,
	.queue_sched_prio = queue_sched_prio,
	.queue_sched_group = queue_sched_group,
	.queue_lock_count = queue_lock_count,
	.queue_to_u64 = queue_to_u64,
	.queue_param_init = queue_param_init,
	.queue_info = queue_info,
	.queue_print = queue_print
};

/* Functions towards internal components */
queue_fn_t _odp_queue_eventdev_fn = {
	.init_global = queue_init_global,
	.term_global = queue_term_global,
	.init_local = queue_init_local,
	.term_local = queue_term_local,
	.get_pktout = queue_get_pktout,
	.set_pktout = queue_set_pktout,
	.get_pktin = queue_get_pktin,
	.set_pktin = queue_set_pktin,
	.set_enq_deq_fn = queue_set_enq_deq_func,
	.orig_deq_multi = queue_orig_multi,
	.timer_add = queue_timer_add,
	.timer_rem = queue_timer_rem
};
