/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet IO - implementation internal
 */

#ifndef ODP_PACKET_IO_INTERNAL_H_
#define ODP_PACKET_IO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/hints.h>
#include <odp/api/packet_io.h>
#include <odp/api/spinlock.h>
#include <odp/api/ticketlock.h>

#include <odp/api/plat/packet_io_inlines.h>

#include <odp_align_internal.h>
#include <odp_classification_datamodel.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_queue_if.h>

#include <inttypes.h>
#include <linux/if_ether.h>
#include <sys/select.h>

#define PKTIO_MAX_QUEUES 64
#define PKTIO_LSO_PROFILES 16
/* Assume at least Ethernet header per each segment */
#define PKTIO_LSO_MIN_PAYLOAD_OFFSET 14
#define PKTIO_LSO_MAX_PAYLOAD_OFFSET 128
/* Allow 64 kB packet to be split into about 1kB segments */
#define PKTIO_LSO_MAX_SEGMENTS 64

ODP_STATIC_ASSERT(PKTIO_LSO_PROFILES < UINT8_MAX, "PKTIO_LSO_PROFILES_ERROR");

#define PKTIO_NAME_LEN 256

#define PKTIN_INVALID  ((odp_pktin_queue_t) {ODP_PKTIO_INVALID, 0})
#define PKTOUT_INVALID ((odp_pktout_queue_t) {ODP_PKTIO_INVALID, 0})

/* Forward declaration */
struct pktio_if_ops;

#define PKTIO_PRIVATE_SIZE 1536

struct pktio_entry {
	const struct pktio_if_ops *ops; /**< Implementation specific methods */
	/* These two locks together lock the whole pktio device */
	odp_ticketlock_t rxl;		/**< RX ticketlock */
	odp_ticketlock_t txl;		/**< TX ticketlock */
	uint16_t pktin_frame_offset;

	struct {
		union {
			uint8_t all_flags;

			struct {
				/* Pktout checksum offload */
				uint8_t chksum_insert : 1;
				/* Classifier */
				uint8_t cls : 1;
				/* Tx timestamp */
				uint8_t tx_ts : 1;
			};
		};
	} enabled;

	odp_pktio_t handle;		/**< pktio handle */
	unsigned char pkt_priv[PKTIO_PRIVATE_SIZE] ODP_ALIGNED_CACHE;
	enum {
		/* Not allocated */
		PKTIO_STATE_FREE = 0,
		/* Close pending on scheduler response. Next state after this
		 * is PKTIO_STATE_FREE. */
		PKTIO_STATE_CLOSE_PENDING,
		/* Open in progress.
		   Marker for all active states following under. */
		PKTIO_STATE_ACTIVE,
		/* Open completed */
		PKTIO_STATE_OPENED,
		/* Start completed */
		PKTIO_STATE_STARTED,
		/* Stop pending on scheduler response */
		PKTIO_STATE_STOP_PENDING,
		/* Stop completed */
		PKTIO_STATE_STOPPED
	} state;
	odp_pktio_config_t config;	/**< Device configuration */
	classifier_t cls;		/**< classifier linked with this pktio*/
	/* Driver level statistics counters */
	odp_pktio_stats_t stats;
	/* Statistics counters used outside drivers */
	struct {
		odp_atomic_u64_t in_discards;
		odp_atomic_u64_t out_discards;
	} stats_extra;
	/* Latest Tx timestamp */
	odp_atomic_u64_t tx_ts;
	odp_proto_chksums_t in_chksums; /**< Checksums validation settings */
	char name[PKTIO_NAME_LEN];	/**< name of pktio provided to
					     internal pktio_open() calls */
	char full_name[PKTIO_NAME_LEN];	/**< original pktio name passed to
					     odp_pktio_open() and returned by
					     odp_pktio_info() */
	odp_pool_t pool;
	odp_pktio_param_t param;
	odp_pktio_capability_t capa;	/**< Packet IO capabilities */

	/* Storage for queue handles
	 * Multi-queue support is pktio driver specific */
	unsigned num_in_queue;
	unsigned num_out_queue;

	struct {
		odp_queue_t        queue;
		odp_pktin_queue_t  pktin;
		odp_pktin_vector_config_t vector;
	} in_queue[PKTIO_MAX_QUEUES];

	struct {
		odp_queue_t        queue;
		odp_pktout_queue_t pktout;
	} out_queue[PKTIO_MAX_QUEUES];

	/* inotify instance for pcapng fifos */
	struct {
		enum {
			PCAPNG_WR_STOP = 0,
			PCAPNG_WR_PKT,
		} state[PKTIO_MAX_QUEUES];
		int fd[PKTIO_MAX_QUEUES];
	} pcapng;
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct pktio_entry))];
} pktio_entry_t;

typedef struct {
	odp_lso_profile_param_t param;
	int used;
	uint8_t index;

} lso_profile_t;

/* Global variables */
typedef struct {
	odp_spinlock_t lock;
	odp_shm_t      shm;

	struct {
		/* Frame start offset from base pointer at packet input */
		uint16_t pktin_frame_offset;
	} config;

	pktio_entry_t  entries[ODP_CONFIG_PKTIO_ENTRIES];

	lso_profile_t lso_profile[PKTIO_LSO_PROFILES];
	int num_lso_profiles;

} pktio_global_t;

typedef struct pktio_if_ops {
	const char *name;
	void (*print)(pktio_entry_t *pktio_entry);
	int (*init_global)(void);
	int (*init_local)(void);
	int (*term)(void);
	int (*open)(odp_pktio_t pktio, pktio_entry_t *pktio_entry,
		    const char *devname, odp_pool_t pool);
	int (*close)(pktio_entry_t *pktio_entry);
	int (*start)(pktio_entry_t *pktio_entry);
	int (*stop)(pktio_entry_t *pktio_entry);
	int (*stats)(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats);
	int (*stats_reset)(pktio_entry_t *pktio_entry);
	int (*pktin_queue_stats)(pktio_entry_t *pktio_entry, uint32_t index,
				 odp_pktin_queue_stats_t *pktin_stats);
	int (*pktout_queue_stats)(pktio_entry_t *pktio_entry, uint32_t index,
				  odp_pktout_queue_stats_t *pktout_stats);
	int (*extra_stat_info)(pktio_entry_t *pktio_entry, odp_pktio_extra_stat_info_t info[],
			       int num);
	int (*extra_stats)(pktio_entry_t *pktio_entry, uint64_t stats[], int num);
	int (*extra_stat_counter)(pktio_entry_t *pktio_entry, uint32_t id, uint64_t *stat);
	uint64_t (*pktio_ts_res)(pktio_entry_t *pktio_entry);
	odp_time_t (*pktio_ts_from_ns)(pktio_entry_t *pktio_entry, uint64_t ns);
	odp_time_t (*pktio_time)(pktio_entry_t *pktio_entry, odp_time_t *global_ts);
	int (*recv)(pktio_entry_t *entry, int index, odp_packet_t packets[],
		    int num);
	int (*recv_tmo)(pktio_entry_t *entry, int index, odp_packet_t packets[],
			int num, uint64_t wait_usecs);
	int (*recv_mq_tmo)(pktio_entry_t *entry[], int index[], int num_q,
			   odp_packet_t packets[], int num, unsigned *from,
			   uint64_t wait_usecs);
	int (*fd_set)(pktio_entry_t *entry, int index, fd_set *readfds);
	int (*send)(pktio_entry_t *entry, int index,
		    const odp_packet_t packets[], int num);
	uint32_t (*maxlen_get)(pktio_entry_t *pktio_entry);
	int (*maxlen_set)(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
			  uint32_t maxlen_output);
	int (*promisc_mode_set)(pktio_entry_t *pktio_entry,  int enable);
	int (*promisc_mode_get)(pktio_entry_t *pktio_entry);
	int (*mac_get)(pktio_entry_t *pktio_entry, void *mac_addr);
	int (*mac_set)(pktio_entry_t *pktio_entry, const void *mac_addr);
	int (*link_status)(pktio_entry_t *pktio_entry);
	int (*link_info)(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info);
	int (*capability)(pktio_entry_t *pktio_entry,
			  odp_pktio_capability_t *capa);
	int (*config)(pktio_entry_t *pktio_entry,
		      const odp_pktio_config_t *config);
	int (*input_queues_config)(pktio_entry_t *pktio_entry,
				   const odp_pktin_queue_param_t *param);
	int (*output_queues_config)(pktio_entry_t *pktio_entry,
				    const odp_pktout_queue_param_t *p);
} pktio_if_ops_t;

extern void *_odp_pktio_entry_ptr[];

static inline pktio_entry_t *get_pktio_entry(odp_pktio_t pktio)
{
	int idx;

	if (odp_unlikely(pktio == ODP_PKTIO_INVALID))
		return NULL;

	if (odp_unlikely(_odp_typeval(pktio) > ODP_CONFIG_PKTIO_ENTRIES)) {
		ODP_DBG("pktio limit %" PRIuPTR "/%d exceed\n",
			_odp_typeval(pktio), ODP_CONFIG_PKTIO_ENTRIES);
		return NULL;
	}

	idx = odp_pktio_index(pktio);

	return _odp_pktio_entry_ptr[idx];
}

static inline int pktio_cls_enabled(pktio_entry_t *entry)
{
	return entry->s.enabled.cls;
}

uint16_t _odp_dpdk_pktio_port_id(pktio_entry_t *entry);

int _odp_input_pkts(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[], int num);

static inline int _odp_pktio_tx_ts_enabled(pktio_entry_t *entry)
{
	return entry->s.enabled.tx_ts;
}

static inline void _odp_pktio_tx_ts_set(pktio_entry_t *entry)
{
	odp_time_t ts_val = odp_time_global();

	odp_atomic_store_u64(&entry->s.tx_ts, ts_val.u64);
}

extern const pktio_if_ops_t _odp_loopback_pktio_ops;
extern const pktio_if_ops_t _odp_null_pktio_ops;
extern const pktio_if_ops_t _odp_dpdk_pktio_ops;
extern const pktio_if_ops_t * const _odp_pktio_if_ops[];

/* Dummy function required by odp_pktin_recv_mq_tmo() */
static inline int
_odp_sock_recv_mq_tmo_try_int_driven(const struct odp_pktin_queue_t queues[],
				     unsigned int num_q ODP_UNUSED,
				     unsigned int *from ODP_UNUSED,
				     odp_packet_t packets[] ODP_UNUSED,
				     int num ODP_UNUSED,
				     uint64_t usecs ODP_UNUSED,
				     int *trial_successful) {
	(void)queues;

	*trial_successful = 0;
	return 0;
}

/* Setup PKTOUT with single queue for TM */
int _odp_pktio_pktout_tm_config(odp_pktio_t pktio_hdl,
				odp_pktout_queue_t *queue, bool reconf);

/* LSO functions shared with TM */
odp_lso_profile_t _odp_lso_prof_from_idx(uint8_t idx);

int _odp_lso_num_packets(odp_packet_t packet, const odp_packet_lso_opt_t *lso_opt,
			 uint32_t *len_out, uint32_t *left_over_out);

int _odp_lso_create_packets(odp_packet_t packet, const odp_packet_lso_opt_t *lso_opt,
			    uint32_t payload_len, uint32_t left_over_len,
			    odp_packet_t pkt_out[], int num_pkt);

#ifdef __cplusplus
}
#endif

#endif
