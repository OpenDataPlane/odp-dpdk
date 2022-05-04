/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/pool.h>
#include <odp/api/std_types.h>
#include <odp/api/ticketlock.h>
#include <odp/api/time.h>

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/time_inlines.h>

#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp_eventdev_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_packet_dpdk.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <protocols/eth.h>

#include <rte_config.h>
#if defined(__clang__)
#undef RTE_TOOLCHAIN_GCC
#endif
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ip_frag.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_version.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
	#define RTE_MBUF_F_TX_IPV4 PKT_TX_IPV4
	#define RTE_MBUF_F_TX_IPV6 PKT_TX_IPV6
	#define RTE_MBUF_F_TX_IP_CKSUM PKT_TX_IP_CKSUM
	#define RTE_MBUF_F_TX_UDP_CKSUM PKT_TX_UDP_CKSUM
	#define RTE_MBUF_F_TX_TCP_CKSUM PKT_TX_TCP_CKSUM
#endif

/* DPDK poll mode drivers requiring minimum RX burst size DPDK_MIN_RX_BURST */
#define IXGBE_DRV_NAME "net_ixgbe"
#define I40E_DRV_NAME "net_i40e"

/* Minimum RX burst size */
#define DPDK_MIN_RX_BURST 4

/* Limits for setting link MTU */
#define DPDK_MTU_MIN (RTE_ETHER_MIN_MTU + _ODP_ETHHDR_LEN)
#define DPDK_MTU_MAX (9000 + _ODP_ETHHDR_LEN)

/* Number of packet buffers to prefetch in RX */
#define NUM_RX_PREFETCH 4

/** DPDK runtime configuration options */
typedef struct {
	int multicast_enable;
	int num_rx_desc;
	int num_tx_desc_default;
	int rx_drop_en;
} dpdk_opt_t;

/** Packet socket using dpdk mmaped rings for both Rx and Tx */
typedef struct ODP_ALIGNED_CACHE {
	/** Supported RTE_PTYPE_XXX flags in a mask */
	uint32_t supported_ptypes;
	/** RSS configuration */
	struct rte_eth_rss_conf rss_conf;
	char ifname[32];
	/** DPDK port identifier */
	uint16_t port_id;
	/** Maximum transmission unit */
	uint16_t mtu;
	/** Maximum supported MTU value */
	uint32_t mtu_max;
	/** DPDK MTU has been modified */
	odp_bool_t mtu_set;
	struct {
		/** No locking for rx */
		uint8_t lockless_rx : 1;
		/** No locking for tx */
		uint8_t lockless_tx : 1;
		/** Promiscuous mode defined with system call */
		uint8_t vdev_sysc_promisc : 1;
	} flags;
	/** Minimum RX burst size */
	uint8_t min_rx_burst;
	 /** Number of TX descriptors per queue */
	uint16_t num_tx_desc[PKTIO_MAX_QUEUES];
	/** RX queue locks */
	odp_ticketlock_t rx_lock[PKTIO_MAX_QUEUES] ODP_ALIGNED_CACHE;
	/** TX queue locks */
	odp_ticketlock_t tx_lock[PKTIO_MAX_QUEUES] ODP_ALIGNED_CACHE;
	/** Configuration options */
	dpdk_opt_t opt;
} pkt_dpdk_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_dpdk_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_dpdk_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_dpdk_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

/* Ops for all implementation of pktio.
 * Order matters. The first implementation to setup successfully
 * will be picked.
 * Array must be NULL terminated */
const pktio_if_ops_t * const _odp_pktio_if_ops[]  = {
	&_odp_loopback_pktio_ops,
	&_odp_null_pktio_ops,
	&_odp_dpdk_pktio_ops,
	NULL
};

extern void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];

static uint32_t mtu_get_pkt_dpdk(pktio_entry_t *pktio_entry);

uint16_t _odp_dpdk_pktio_port_id(pktio_entry_t *pktio_entry)
{
	const pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);

	return pkt_dpdk->port_id;
}

static int lookup_opt(const char *opt_name, const char *drv_name, int *val)
{
	const char *base = "pktio_dpdk";
	int ret;

	ret = _odp_libconfig_lookup_ext_int(base, drv_name, opt_name, val);
	if (ret == 0)
		ODP_ERR("Unable to find DPDK configuration option: %s\n",
			opt_name);

	return ret;
}

static int init_options(pktio_entry_t *pktio_entry,
			const struct rte_eth_dev_info *dev_info)
{
	dpdk_opt_t *opt = &pkt_priv(pktio_entry)->opt;

	if (!lookup_opt("num_rx_desc", dev_info->driver_name,
			&opt->num_rx_desc))
		return -1;
	if (opt->num_rx_desc < dev_info->rx_desc_lim.nb_min ||
	    opt->num_rx_desc > dev_info->rx_desc_lim.nb_max ||
	    opt->num_rx_desc % dev_info->rx_desc_lim.nb_align) {
		ODP_ERR("Invalid number of RX descriptors\n");
		return -1;
	}

	if (!lookup_opt("num_tx_desc", dev_info->driver_name,
			&opt->num_tx_desc_default))
		return -1;

	if (!lookup_opt("rx_drop_en", dev_info->driver_name,
			&opt->rx_drop_en))
		return -1;
	opt->rx_drop_en = !!opt->rx_drop_en;

	if (!lookup_opt("multicast_en", dev_info->driver_name,
			&opt->multicast_enable))
		return -1;
	opt->multicast_enable = !!opt->multicast_enable;

	ODP_DBG("DPDK interface (%s): %" PRIu16 "\n", dev_info->driver_name,
		pkt_priv(pktio_entry)->port_id);
	ODP_DBG("  multicast:   %d\n", opt->multicast_enable);
	ODP_DBG("  num_rx_desc: %d\n", opt->num_rx_desc);
	ODP_DBG("  num_tx_desc: %d\n", opt->num_tx_desc_default);
	ODP_DBG("  rx_drop_en:  %d\n", opt->rx_drop_en);

	return 0;
}

/* Test if s has only digits or not. Dpdk pktio uses only digits.*/
static int _dpdk_netdev_is_valid(const char *s)
{
	while (*s) {
		if (!isdigit(*s))
			return 0;
		s++;
	}

	return 1;
}

static void hash_proto_to_rss_conf(struct rte_eth_rss_conf *rss_conf,
				   const odp_pktin_hash_proto_t *hash_proto)
{
	if (hash_proto->proto.ipv4_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_UDP;
	if (hash_proto->proto.ipv4_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_TCP;
	if (hash_proto->proto.ipv4)
		rss_conf->rss_hf |= ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
				    ETH_RSS_NONFRAG_IPV4_OTHER;
	if (hash_proto->proto.ipv6_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_UDP |
				    ETH_RSS_IPV6_UDP_EX;
	if (hash_proto->proto.ipv6_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_TCP |
				    ETH_RSS_IPV6_TCP_EX;
	if (hash_proto->proto.ipv6)
		rss_conf->rss_hf |= ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
				    ETH_RSS_NONFRAG_IPV6_OTHER |
				    ETH_RSS_IPV6_EX;
	rss_conf->rss_key = NULL;
}

static int dpdk_maxlen_set(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
			   uint32_t maxlen_output ODP_UNUSED)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t mtu;
	int ret;

	/* DPDK MTU value does not include Ethernet header */
	mtu = maxlen_input - _ODP_ETHHDR_LEN;

	ret = rte_eth_dev_set_mtu(pkt_dpdk->port_id, mtu);
	if (odp_unlikely(ret))
		ODP_ERR("rte_eth_dev_set_mtu() failed: %d\n", ret);

	pkt_dpdk->mtu = maxlen_input;
	pkt_dpdk->mtu_set = true;

	return ret;
}

static int dpdk_setup_eth_dev(pktio_entry_t *pktio_entry)
{
	int ret;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	struct rte_eth_conf eth_conf;
	pool_t *pool = pool_entry_from_hdl(pktio_entry->s.pool);
	uint64_t rx_offloads = 0;
	uint64_t tx_offloads = 0;

	memset(&eth_conf, 0, sizeof(eth_conf));

	eth_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	eth_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	eth_conf.rx_adv_conf.rss_conf = pkt_dpdk->rss_conf;

	/* Setup RX checksum offloads */
	if (pktio_entry->s.config.pktin.bit.ipv4_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM;

	if (pktio_entry->s.config.pktin.bit.udp_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_UDP_CKSUM;

	if (pktio_entry->s.config.pktin.bit.tcp_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_TCP_CKSUM;

	eth_conf.rxmode.offloads = rx_offloads;

	/* Setup TX checksum offloads */
	if (pktio_entry->s.config.pktout.bit.ipv4_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;

	if (pktio_entry->s.config.pktout.bit.udp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;

	if (pktio_entry->s.config.pktout.bit.tcp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;

	if (pktio_entry->s.config.pktout.bit.sctp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_SCTP_CKSUM;

	eth_conf.txmode.offloads = tx_offloads;

	if (tx_offloads)
		pktio_entry->s.enabled.chksum_insert = 1;

	/* RX packet len same size as pool segment minus headroom and double
	 * VLAN tag
	 */
#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
	eth_conf.rxmode.max_rx_pkt_len =
#else
	eth_conf.rxmode.mtu =
#endif
		rte_pktmbuf_data_room_size(pool->rte_mempool) -
		2 * 4 - RTE_PKTMBUF_HEADROOM;

	ret = rte_eth_dev_configure(pkt_dpdk->port_id,
				    pktio_entry->s.num_in_queue,
				    pktio_entry->s.num_out_queue, &eth_conf);
	if (ret < 0) {
		ODP_ERR("Failed to setup device: err=%d, port=%" PRIu8 "\n",
			ret, pkt_dpdk->port_id);
		return -1;
	}
	return 0;
}

static void _dpdk_print_port_mac(uint16_t port_id)
{
	struct rte_ether_addr eth_addr;

	memset(&eth_addr, 0, sizeof(eth_addr));
	rte_eth_macaddr_get(port_id, &eth_addr);
	ODP_DBG("Port %" PRIu16 ", "
		"MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
		port_id,
		eth_addr.addr_bytes[0],
		eth_addr.addr_bytes[1],
		eth_addr.addr_bytes[2],
		eth_addr.addr_bytes[3],
		eth_addr.addr_bytes[4],
		eth_addr.addr_bytes[5]);
}

static void prepare_rss_conf(pktio_entry_t *pktio_entry,
			     const odp_pktin_queue_param_t *p)
{
	struct rte_eth_dev_info dev_info;
	uint64_t rss_hf_capa;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t port_id = pkt_dpdk->port_id;

	memset(&pkt_dpdk->rss_conf, 0, sizeof(struct rte_eth_rss_conf));

	if (!p->hash_enable)
		return;

	rte_eth_dev_info_get(port_id, &dev_info);
	rss_hf_capa = dev_info.flow_type_rss_offloads;

	/* Print debug info about unsupported hash protocols */
	if (p->hash_proto.proto.ipv4 &&
	    ((rss_hf_capa & ETH_RSS_IPV4) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv4 not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv4_udp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV4_UDP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv4_udp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv4_tcp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV4_TCP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv4_tcp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6 &&
	    ((rss_hf_capa & ETH_RSS_IPV6) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv6 not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6_udp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV6_UDP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv6_udp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6_tcp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV6_TCP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv6_tcp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	hash_proto_to_rss_conf(&pkt_dpdk->rss_conf, &p->hash_proto);

	/* Filter out unsupported hash functions */
	pkt_dpdk->rss_conf.rss_hf &= rss_hf_capa;
}

static int dpdk_input_queues_config(pktio_entry_t *pktio_entry,
				    const odp_pktin_queue_param_t *p)
{
	odp_pktin_mode_t mode = pktio_entry->s.param.in_mode;
	uint8_t lockless;

	prepare_rss_conf(pktio_entry, p);

	/**
	 * Scheduler synchronizes input queue polls. Only single thread
	 * at a time polls a queue */
	if (mode == ODP_PKTIN_MODE_SCHED ||
	    p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	pkt_priv(pktio_entry)->flags.lockless_rx = lockless;

	return 0;
}

static int dpdk_output_queues_config(pktio_entry_t *pktio_entry,
				     const odp_pktout_queue_param_t *p)
{
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint8_t lockless;
	int ret;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	pkt_dpdk->flags.lockless_tx = lockless;

	ret  = rte_eth_dev_info_get(pkt_dpdk->port_id, &dev_info);
	if (ret) {
		ODP_ERR("DPDK: rte_eth_dev_info_get() failed: %d\n", ret);
		return -1;
	}

	/* Configure TX descriptors */
	for (uint32_t i = 0; i  < p->num_queues; i++) {
		uint16_t num_tx_desc = pkt_dpdk->opt.num_tx_desc_default;

		if (p->queue_size[i] != 0) {
			num_tx_desc = p->queue_size[i];
			/* Make sure correct alignment is used */
			if (dev_info.tx_desc_lim.nb_align)
				num_tx_desc = RTE_ALIGN_MUL_CEIL(num_tx_desc,
								 dev_info.tx_desc_lim.nb_align);
		}

		if (num_tx_desc < dev_info.tx_desc_lim.nb_min ||
		    num_tx_desc > dev_info.tx_desc_lim.nb_max ||
		    (dev_info.tx_desc_lim.nb_align &&
		     num_tx_desc % dev_info.tx_desc_lim.nb_align)) {
			ODP_ERR("DPDK: invalid number of TX descriptors\n");
			return -1;
		}
		pkt_dpdk->num_tx_desc[i] = num_tx_desc;
	}
	return 0;
}

static int dpdk_init_global(void)
{
	return 0;
}

static int dpdk_term_global(void)
{
	/* Eventdev takes care of closing pktio devices */
	if (!_odp_eventdev_gbl ||
	    _odp_eventdev_gbl->rx_adapter.status == RX_ADAPTER_INIT) {
		uint16_t port_id;

		RTE_ETH_FOREACH_DEV(port_id) {
			rte_eth_dev_close(port_id);
		}
	}
	return 0;
}

static int dpdk_init_capability(pktio_entry_t *pktio_entry,
				const struct rte_eth_dev_info *dev_info)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	odp_pktio_capability_t *capa = &pktio_entry->s.capa;
	struct rte_ether_addr mac_addr;
	int ret;
	int ptype_cnt;
	int ptype_l3_ipv4 = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues = RTE_MIN(dev_info->max_rx_queues,
					 PKTIO_MAX_QUEUES);

	/* ixgbe devices support only 16 RX queues in RSS mode */
	if (!strncmp(dev_info->driver_name, IXGBE_DRV_NAME,
		     strlen(IXGBE_DRV_NAME)))
		capa->max_input_queues = RTE_MIN(16,
						 (int)capa->max_input_queues);

	capa->max_output_queues = RTE_MIN(dev_info->max_tx_queues,
					  PKTIO_MAX_QUEUES);
	capa->min_output_queue_size = dev_info->tx_desc_lim.nb_min;
	capa->max_output_queue_size = dev_info->tx_desc_lim.nb_max;

	capa->set_op.op.promisc_mode = 1;

	/* Check if setting default MAC address is supported */
	rte_eth_macaddr_get(pkt_dpdk->port_id, &mac_addr);
	ret = rte_eth_dev_default_mac_addr_set(pkt_dpdk->port_id, &mac_addr);
	if (ret == 0) {
		capa->set_op.op.mac_addr = 1;
	} else if (ret != -ENOTSUP && ret != -EPERM) {
		ODP_ERR("Failed to set interface default MAC: %d\n",
			ret);
		return -1;
	}

	/* Check if setting MTU is supported */
	ret = rte_eth_dev_set_mtu(pkt_dpdk->port_id, pkt_dpdk->mtu - _ODP_ETHHDR_LEN);
	/* From DPDK 21.11 onwards, calling rte_eth_dev_set_mtu() before device is configured with
	 * rte_eth_dev_configure() will result in failure. The least hacky (unfortunately still
	 * very hacky) way to continue checking the support is to take into account that the
	 * function will fail earlier with -ENOTSUP if MTU setting is not supported by device than
	 * if the device was not yet configured. */
	if (ret != -ENOTSUP) {
		capa->set_op.op.maxlen = 1;
		capa->maxlen.equal = true;
		capa->maxlen.min_input = DPDK_MTU_MIN;
		capa->maxlen.max_input = pkt_dpdk->mtu_max;
		capa->maxlen.min_output = DPDK_MTU_MIN;
		capa->maxlen.max_output = pkt_dpdk->mtu_max;
	}

	ptype_cnt = rte_eth_dev_get_supported_ptypes(pkt_dpdk->port_id,
						     ptype_mask, NULL, 0);
	if (ptype_cnt > 0) {
		uint32_t ptypes[ptype_cnt];
		int i;

		ptype_cnt = rte_eth_dev_get_supported_ptypes(pkt_dpdk->port_id,
							     ptype_mask, ptypes,
							     ptype_cnt);
		for (i = 0; i < ptype_cnt; i++)
			switch (ptypes[i]) {
			case RTE_PTYPE_L3_IPV4:
			/* Fall through */
			case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
			/* Fall through */
			case RTE_PTYPE_L3_IPV4_EXT:
				ptype_l3_ipv4 = 1;
				break;
			case RTE_PTYPE_L4_TCP:
				ptype_l4_tcp = 1;
				break;
			case RTE_PTYPE_L4_UDP:
				ptype_l4_udp = 1;
				break;
			}
	}

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;

	capa->config.pktin.bit.ipv4_chksum = ptype_l3_ipv4 &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.ipv4_chksum)
		capa->config.pktin.bit.drop_ipv4_err = 1;

	capa->config.pktin.bit.udp_chksum = ptype_l4_udp &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.udp_chksum)
		capa->config.pktin.bit.drop_udp_err = 1;

	capa->config.pktin.bit.tcp_chksum = ptype_l4_tcp &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.tcp_chksum)
		capa->config.pktin.bit.drop_tcp_err = 1;

	capa->config.pktout.bit.ipv4_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) ? 1 : 0;
	capa->config.pktout.bit.udp_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) ? 1 : 0;
	capa->config.pktout.bit.tcp_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) ? 1 : 0;

	capa->config.pktout.bit.ipv4_chksum_ena =
		capa->config.pktout.bit.ipv4_chksum;
	capa->config.pktout.bit.udp_chksum_ena =
		capa->config.pktout.bit.udp_chksum;
	capa->config.pktout.bit.tcp_chksum_ena =
		capa->config.pktout.bit.tcp_chksum;

	capa->config.pktout.bit.ts_ena = 1;

	capa->stats.pktio.counter.in_octets = 1;
	capa->stats.pktio.counter.in_packets = 1;
	capa->stats.pktio.counter.in_discards = 1;
	capa->stats.pktio.counter.in_errors = 1;
	capa->stats.pktio.counter.out_octets = 1;
	capa->stats.pktio.counter.out_packets = 1;
	capa->stats.pktio.counter.out_errors = 1;

	capa->stats.pktin_queue.counter.octets = 1;
	capa->stats.pktin_queue.counter.packets = 1;
	capa->stats.pktin_queue.counter.errors = 1;

	capa->stats.pktout_queue.counter.octets = 1;
	capa->stats.pktout_queue.counter.packets = 1;

	return 0;
}

/* Some DPDK PMD virtual devices, like PCAP, do not support promisc
 * mode change. Use system call for them. */
static void promisc_mode_check(pkt_dpdk_t *pkt_dpdk)
{
	int ret;

	ret = rte_eth_promiscuous_enable(pkt_dpdk->port_id);

	if (!rte_eth_promiscuous_get(pkt_dpdk->port_id))
		pkt_dpdk->flags.vdev_sysc_promisc = 1;

	ret += rte_eth_promiscuous_disable(pkt_dpdk->port_id);

	if (ret)
		pkt_dpdk->flags.vdev_sysc_promisc = 1;
}

static int setup_pkt_dpdk(odp_pktio_t pktio ODP_UNUSED,
			  pktio_entry_t *pktio_entry,
			  const char *netdev, odp_pool_t pool ODP_UNUSED)
{
	uint32_t mtu;
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t * const pkt_dpdk = pkt_priv(pktio_entry);
	int i, ret;
	uint16_t port_id;

	if (!rte_eth_dev_get_port_by_name(netdev, &port_id))
		pkt_dpdk->port_id = port_id;
	else if (_dpdk_netdev_is_valid(netdev))
		pkt_dpdk->port_id = atoi(netdev);
	else {
		ODP_ERR("Invalid interface name!: %s\n", netdev);
		return -1;
	}

	if (!rte_eth_dev_is_valid_port(pkt_dpdk->port_id)) {
		ODP_ERR("Port id=%" PRIu16 " not attached\n", pkt_dpdk->port_id);
		return -1;
	}

	memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
	ret = rte_eth_dev_info_get(pkt_dpdk->port_id, &dev_info);
	if (ret) {
		ODP_ERR("Failed to read device info: %d\n", ret);
		return -1;
	}

	/* Initialize runtime options */
	if (init_options(pktio_entry, &dev_info)) {
		ODP_ERR("Initializing runtime options failed\n");
		return -1;
	}

	/* Drivers requiring minimum burst size. Supports also *_vf versions
	 * of the drivers. */
	if (!strncmp(dev_info.driver_name, IXGBE_DRV_NAME,
		     strlen(IXGBE_DRV_NAME)) ||
	    !strncmp(dev_info.driver_name, I40E_DRV_NAME,
		     strlen(I40E_DRV_NAME)))
		pkt_dpdk->min_rx_burst = DPDK_MIN_RX_BURST;
	else
		pkt_dpdk->min_rx_burst = 0;

	_dpdk_print_port_mac(pkt_dpdk->port_id);

	mtu = mtu_get_pkt_dpdk(pktio_entry);
	if (mtu == 0) {
		ODP_ERR("Failed to read interface MTU\n");
		return -1;
	}
	pkt_dpdk->mtu = mtu + _ODP_ETHHDR_LEN;
	pkt_dpdk->mtu_max = RTE_MAX(pkt_dpdk->mtu, DPDK_MTU_MAX);
	pkt_dpdk->mtu_set = false;

	if (dpdk_init_capability(pktio_entry, &dev_info)) {
		ODP_ERR("Failed to initialize capability\n");
		return -1;
	}

	/* Setup promiscuous mode and multicast */
	promisc_mode_check(pkt_dpdk);
	if (pkt_dpdk->opt.multicast_enable)
		rte_eth_allmulticast_enable(pkt_dpdk->port_id);
	else
		rte_eth_allmulticast_disable(pkt_dpdk->port_id);

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		odp_ticketlock_init(&pkt_dpdk->rx_lock[i]);
		odp_ticketlock_init(&pkt_dpdk->tx_lock[i]);
	}

	return 0;
}

static int close_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t * const pkt_dpdk = pkt_priv(pktio_entry);

	if (_odp_eventdev_gbl &&
	    _odp_eventdev_gbl->rx_adapter.status != RX_ADAPTER_INIT)
		_odp_rx_adapter_port_stop(pkt_dpdk->port_id);
	else
		rte_eth_dev_stop(pkt_dpdk->port_id);

	return 0;
}

static int dpdk_setup_eth_tx(pktio_entry_t *pktio_entry,
			     const pkt_dpdk_t *pkt_dpdk,
			     const struct rte_eth_dev_info *dev_info)
{
	uint32_t i;
	int ret;
	uint16_t port_id = pkt_dpdk->port_id;

	for (i = 0; i < pktio_entry->s.num_out_queue; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i,
					     pkt_dpdk->num_tx_desc[i],
					     rte_eth_dev_socket_id(port_id),
					     &dev_info->default_txconf);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}

	/* Set per queue statistics mappings. Not supported by all PMDs, so
	 * ignore the return value. */
	for (i = 0; i < pktio_entry->s.num_out_queue && i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		ret = rte_eth_dev_set_tx_queue_stats_mapping(port_id, i, i);
		if (ret) {
			ODP_DBG("Mapping per TX queue statistics not supported: %d\n", ret);
			break;
		}
	}
	ODP_DBG("Mapped %" PRIu32 "/%d TX counters\n", i, RTE_ETHDEV_QUEUE_STAT_CNTRS);

	return 0;
}

static int dpdk_setup_eth_rx(const pktio_entry_t *pktio_entry,
			     const pkt_dpdk_t *pkt_dpdk,
			     const struct rte_eth_dev_info *dev_info)
{
	struct rte_eth_rxconf rxconf;
	uint32_t i;
	int ret;
	uint16_t port_id = pkt_dpdk->port_id;
	pool_t *pool = pool_entry_from_hdl(pktio_entry->s.pool);

	rxconf = dev_info->default_rxconf;

	rxconf.rx_drop_en = pkt_dpdk->opt.rx_drop_en;

	for (i = 0; i < pktio_entry->s.num_in_queue; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i,
					     pkt_dpdk->opt.num_rx_desc,
					     rte_eth_dev_socket_id(port_id),
					     &rxconf, pool->rte_mempool);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}

	/* Set per queue statistics mappings. Not supported by all PMDs, so
	 * ignore the return value. */
	for (i = 0; i < pktio_entry->s.num_in_queue && i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		ret = rte_eth_dev_set_rx_queue_stats_mapping(port_id, i, i);
		if (ret) {
			ODP_DBG("Mapping per RX queue statistics not supported: %d\n", ret);
			break;
		}
	}
	ODP_DBG("Mapped %" PRIu32 "/%d RX counters\n", i, RTE_ETHDEV_QUEUE_STAT_CNTRS);

	return 0;
}

static void dpdk_ptype_support_set(pktio_entry_t *pktio_entry, uint16_t port_id)
{
	int max_num, num, i;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint32_t mask = RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK |
			RTE_PTYPE_L4_MASK;

	pkt_dpdk->supported_ptypes = 0;

	max_num = rte_eth_dev_get_supported_ptypes(port_id, mask, NULL, 0);
	if (max_num <= 0) {
		ODP_DBG("Device does not support any ptype flags\n");
		return;
	}

	uint32_t ptype[max_num];

	num = rte_eth_dev_get_supported_ptypes(port_id, mask, ptype, max_num);
	if (num <= 0) {
		ODP_ERR("Device does not support any ptype flags\n");
		return;
	}

	for (i = 0; i < num; i++) {
		ODP_DBG("  supported ptype: 0x%x\n", ptype[i]);

		if (ptype[i] == RTE_PTYPE_L2_ETHER_VLAN)
			pkt_dpdk->supported_ptypes |= PTYPE_VLAN;
		else if (ptype[i] == RTE_PTYPE_L2_ETHER_QINQ)
			pkt_dpdk->supported_ptypes |= PTYPE_VLAN_QINQ;
		else if (ptype[i] == RTE_PTYPE_L2_ETHER_ARP)
			pkt_dpdk->supported_ptypes |= PTYPE_ARP;
		else if (RTE_ETH_IS_IPV4_HDR(ptype[i]))
			pkt_dpdk->supported_ptypes |= PTYPE_IPV4;
		else if (RTE_ETH_IS_IPV6_HDR(ptype[i]))
			pkt_dpdk->supported_ptypes |= PTYPE_IPV6;
		else if (ptype[i] == RTE_PTYPE_L4_UDP)
			pkt_dpdk->supported_ptypes |= PTYPE_UDP;
		else if (ptype[i] == RTE_PTYPE_L4_TCP)
			pkt_dpdk->supported_ptypes |= PTYPE_TCP;
	}
}

static int dpdk_start(pktio_entry_t *pktio_entry)
{
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t port_id = pkt_dpdk->port_id;
	int ret;

	if (pktio_entry->s.state == PKTIO_STATE_STOPPED ||
	    pktio_entry->s.state == PKTIO_STATE_STOP_PENDING)
		rte_eth_dev_stop(pkt_dpdk->port_id);

	/* DPDK doesn't support nb_rx_q/nb_tx_q being 0 */
	if (!pktio_entry->s.num_in_queue)
		pktio_entry->s.num_in_queue = 1;
	if (!pktio_entry->s.num_out_queue)
		pktio_entry->s.num_out_queue = 1;

	rte_eth_dev_info_get(port_id, &dev_info);

	/* Setup device */
	if (dpdk_setup_eth_dev(pktio_entry)) {
		ODP_ERR("Failed to configure device\n");
		return -1;
	}

	/* Setup TX queues */
	if (dpdk_setup_eth_tx(pktio_entry, pkt_dpdk, &dev_info))
		return -1;

	/* Setup RX queues */
	if (dpdk_setup_eth_rx(pktio_entry, pkt_dpdk, &dev_info))
		return -1;

	/* Restore MTU value resetted by dpdk_setup_eth_rx() */
	if (pkt_dpdk->mtu_set && pktio_entry->s.capa.set_op.op.maxlen) {
		ret = dpdk_maxlen_set(pktio_entry, pkt_dpdk->mtu, 0);
		if (ret) {
			ODP_ERR("Restoring device MTU failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}

	/* Start device */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		ODP_ERR("Device start failed: err=%d, port=%" PRIu8 "\n",
			ret, port_id);
		return -1;
	}

	/* Record supported parser ptype flags */
	dpdk_ptype_support_set(pktio_entry, port_id);

	return 0;
}

static int stop_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	unsigned int i;
	uint16_t port_id = pkt_dpdk->port_id;

	for (i = 0; i < pktio_entry->s.num_in_queue; i++)
		rte_eth_dev_rx_queue_stop(port_id, i);
	for (i = 0; i < pktio_entry->s.num_out_queue; i++)
		rte_eth_dev_tx_queue_stop(port_id, i);

	return 0;
}

static inline void prefetch_pkt(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	odp_prefetch(&pkt_hdr->p);
}

int _odp_input_pkts(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[], int num)
{
	pkt_dpdk_t * const pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t i;
	uint16_t num_pkts = 0;
	odp_pktin_config_opt_t pktin_cfg = pktio_entry->s.config.pktin;
	odp_pktio_t input = pktio_entry->s.handle;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	uint16_t num_prefetch = RTE_MIN(num, NUM_RX_PREFETCH);
	const odp_proto_layer_t layer = pktio_entry->s.parse_layer;

	for (i = 0; i < num_prefetch; i++)
		prefetch_pkt(pkt_table[i]);

	if (pktin_cfg.bit.ts_all || pktin_cfg.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	for (i = 0; i < num; ++i) {
		odp_packet_t pkt = pkt_table[i];
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
		struct rte_mbuf *mbuf = pkt_to_mbuf(pkt);

		if (odp_likely(i + num_prefetch < num))
			prefetch_pkt(pkt_table[i + num_prefetch]);

		packet_init(pkt_hdr, input);

		if (layer != ODP_PROTO_LAYER_NONE) {
			if (_odp_dpdk_packet_parse_common(&pkt_hdr->p,
							  rte_pktmbuf_mtod(mbuf, uint8_t *),
							  rte_pktmbuf_pkt_len(mbuf),
							  rte_pktmbuf_data_len(mbuf),
							  mbuf, layer,
							  pkt_dpdk->supported_ptypes, pktin_cfg)) {
				odp_packet_free(pkt);
				continue;
			}
			if (odp_unlikely(num_pkts != i))
				pkt_table[num_pkts] = pkt;
		}
		packet_set_ts(pkt_hdr, ts);

		odp_prefetch(rte_pktmbuf_mtod(mbuf, char *));
		num_pkts++;
	}

	if (pktio_cls_enabled(pktio_entry)) {
		int failed = 0, success = 0;

		for (i = 0; i < num_pkts; i++) {
			odp_packet_t pkt = pkt_table[i];
			odp_pool_t new_pool;
			uint8_t *data;
			odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

			data = odp_packet_data(pkt);

			if (_odp_cls_classify_packet(pktio_entry, data,
						     &new_pool, pkt_hdr)) {
				odp_packet_free(pkt);
				continue;
			}
			if (new_pool != odp_packet_pool(pkt)) {
				odp_packet_t new_pkt = odp_packet_copy(pkt, new_pool);

				odp_packet_free(pkt);
				if (odp_unlikely(new_pkt == ODP_PACKET_INVALID)) {
					failed++;
					continue;
				}
				pkt_table[i] = new_pkt;
				pkt = new_pkt;
			}

			pktio_entry->s.stats.in_octets += odp_packet_len(pkt);
			if (success != i)
				pkt_table[success] = pkt;
			++success;
		}
		pktio_entry->s.stats.in_errors += failed;
		pktio_entry->s.stats.in_ucast_pkts += num_pkts - failed;
		num_pkts = success;
	}

	return num_pkts;
}

static int recv_pkt_dpdk(pktio_entry_t *pktio_entry, int index,
			 odp_packet_t pkt_table[], int num)
{
	pkt_dpdk_t * const pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t nb_rx;
	uint8_t min = pkt_dpdk->min_rx_burst;

	if (!pkt_dpdk->flags.lockless_rx)
		odp_ticketlock_lock(&pkt_dpdk->rx_lock[index]);

	if (odp_likely(num >= min)) {
		nb_rx = rte_eth_rx_burst(pkt_dpdk->port_id, (uint16_t)index,
					 (struct rte_mbuf **)pkt_table,
					 (uint16_t)num);
	} else {
		odp_packet_t min_burst[min];
		uint16_t i;

		ODP_DBG("PMD requires >%d buffers burst.  Current %d, dropped "
			"%d\n", min, num, min - num);
		nb_rx = rte_eth_rx_burst(pkt_dpdk->port_id, (uint16_t)index,
					 (struct rte_mbuf **)min_burst, min);

		for (i = 0; i < nb_rx; i++) {
			if (i < num)
				pkt_table[i] = min_burst[i];
			else
				odp_packet_free(min_burst[i]);
		}

		pktio_entry->s.stats.in_discards += nb_rx - num;
		nb_rx = RTE_MIN(num, nb_rx);
	}

	if (!pkt_dpdk->flags.lockless_rx)
		odp_ticketlock_unlock(&pkt_dpdk->rx_lock[index]);

	/* Packets may also me received through eventdev, so don't add any
	 * processing here. Instead, perform all processing in _odp_input_pkts()
	 * which is also called by eventdev. */
	if (nb_rx)
		return _odp_input_pkts(pktio_entry, pkt_table, nb_rx);
	return 0;
}

static inline int check_proto(void *l3_hdr, odp_bool_t *l3_proto_v4,
			      uint8_t *l4_proto)
{
	uint8_t l3_proto_ver = _ODP_IPV4HDR_VER(*(uint8_t *)l3_hdr);

	if (l3_proto_ver == _ODP_IPV4) {
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)l3_hdr;

		*l3_proto_v4 = 1;
		if (!rte_ipv4_frag_pkt_is_fragmented(ip))
			*l4_proto = ip->next_proto_id;
		else
			*l4_proto = 0;

		return 0;
	} else if (l3_proto_ver == _ODP_IPV6) {
		struct rte_ipv6_hdr *ipv6 = (struct rte_ipv6_hdr *)l3_hdr;

		*l3_proto_v4 = 0;
		*l4_proto = ipv6->proto;
		return 0;
	}

	return -1;
}

static inline uint16_t phdr_csum(odp_bool_t ipv4, void *l3_hdr,
				 uint64_t ol_flags)
{
	if (ipv4)
		return rte_ipv4_phdr_cksum(l3_hdr, ol_flags);
	else /*ipv6*/
		return rte_ipv6_phdr_cksum(l3_hdr, ol_flags);
}

#define OL_TX_CHKSUM_PKT(_cfg, _capa, _proto, _ovr_set, _ovr) \
	(_capa && _proto && (_ovr_set ? _ovr : _cfg))

static inline void pkt_set_ol_tx(odp_pktout_config_opt_t *pktout_cfg,
				 odp_pktout_config_opt_t *pktout_capa,
				 odp_packet_hdr_t *pkt_hdr,
				 struct rte_mbuf *mbuf,
				 char *mbuf_data)
{
	void *l3_hdr, *l4_hdr;
	uint8_t l4_proto;
	odp_bool_t l3_proto_v4;
	odp_bool_t ipv4_chksum_pkt, udp_chksum_pkt, tcp_chksum_pkt;
	packet_parser_t *pkt_p = &pkt_hdr->p;

	if (pkt_p->l3_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	l3_hdr = (void *)(mbuf_data + pkt_p->l3_offset);

	if (check_proto(l3_hdr, &l3_proto_v4, &l4_proto))
		return;

	ipv4_chksum_pkt = OL_TX_CHKSUM_PKT(pktout_cfg->bit.ipv4_chksum,
					   pktout_capa->bit.ipv4_chksum,
					   l3_proto_v4,
					   pkt_p->flags.l3_chksum_set,
					   pkt_p->flags.l3_chksum);
	udp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.udp_chksum,
					   pktout_capa->bit.udp_chksum,
					   (l4_proto == _ODP_IPPROTO_UDP),
					   pkt_p->flags.l4_chksum_set,
					   pkt_p->flags.l4_chksum);
	tcp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.tcp_chksum,
					   pktout_capa->bit.tcp_chksum,
					   (l4_proto == _ODP_IPPROTO_TCP),
					   pkt_p->flags.l4_chksum_set,
					   pkt_p->flags.l4_chksum);

	if (!ipv4_chksum_pkt && !udp_chksum_pkt && !tcp_chksum_pkt)
		return;

	mbuf->l2_len = pkt_p->l3_offset - pkt_p->l2_offset;

	if (l3_proto_v4)
		mbuf->ol_flags = RTE_MBUF_F_TX_IPV4;
	else
		mbuf->ol_flags = RTE_MBUF_F_TX_IPV6;

	if (ipv4_chksum_pkt) {
		mbuf->ol_flags |=  RTE_MBUF_F_TX_IP_CKSUM;

		((struct rte_ipv4_hdr *)l3_hdr)->hdr_checksum = 0;
		mbuf->l3_len = _ODP_IPV4HDR_IHL(*(uint8_t *)l3_hdr) * 4;
	}

	if (pkt_p->l4_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	mbuf->l3_len = pkt_p->l4_offset - pkt_p->l3_offset;

	l4_hdr = (void *)(mbuf_data + pkt_p->l4_offset);

	if (udp_chksum_pkt) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;

		((struct rte_udp_hdr *)l4_hdr)->dgram_cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	} else if (tcp_chksum_pkt) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

		((struct rte_tcp_hdr *)l4_hdr)->cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	}
}

static int send_pkt_dpdk(pktio_entry_t *pktio_entry, int index,
			 const odp_packet_t pkt_table[], int num)
{
	pkt_dpdk_t * const pkt_dpdk = pkt_priv(pktio_entry);
	uint8_t chksum_insert_ena = pktio_entry->s.enabled.chksum_insert;
	uint8_t tx_ts_ena = pktio_entry->s.enabled.tx_ts;
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->s.config.pktout;
	odp_pktout_config_opt_t *pktout_capa =
		&pktio_entry->s.capa.config.pktout;
	int tx_ts_idx = 0;
	int pkts;

	if (chksum_insert_ena || tx_ts_ena) {
		int i;

		for (i = 0; i < num; i++) {
			struct rte_mbuf *mbuf = pkt_to_mbuf(pkt_table[i]);
			odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt_table[i]);

			if (chksum_insert_ena)
				pkt_set_ol_tx(pktout_cfg, pktout_capa, pkt_hdr, mbuf,
					      rte_pktmbuf_mtod(mbuf, char *));

			if (odp_unlikely(tx_ts_ena && tx_ts_idx == 0 && pkt_hdr->p.flags.ts_set))
				tx_ts_idx = i + 1;
		}
	}

	if (!pkt_dpdk->flags.lockless_tx)
		odp_ticketlock_lock(&pkt_dpdk->tx_lock[index]);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	pkts = rte_eth_tx_burst(pkt_dpdk->port_id, index,
				(struct rte_mbuf **)pkt_table, num);
#pragma GCC diagnostic pop

	if (!pkt_dpdk->flags.lockless_tx)
		odp_ticketlock_unlock(&pkt_dpdk->tx_lock[index]);

	if (pkts == 0) {
		struct rte_mbuf *mbuf = pkt_to_mbuf(pkt_table[0]);

		if (odp_unlikely(rte_errno != 0))
			return -1;

		if (odp_unlikely(mbuf->pkt_len > pkt_dpdk->mtu)) {
			_odp_errno = EMSGSIZE;
			return -1;
		}
	} else if (odp_unlikely(tx_ts_idx && pkts >= tx_ts_idx)) {
		_odp_pktio_tx_ts_set(pktio_entry);
	}
	rte_errno = 0;
	return pkts;
}

static uint32_t _dpdk_vdev_mtu(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	close(sockfd);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return 0;
	}

	return ifr.ifr_mtu;
}

static uint32_t mtu_get_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	uint16_t mtu = 0;
	int ret;

	ret = rte_eth_dev_get_mtu(pkt_priv(pktio_entry)->port_id, &mtu);
	if (ret < 0)
		return 0;

	/* some dpdk PMD vdev does not support getting mtu size,
	 * try to use system call if dpdk cannot get mtu value.
	 */
	if (mtu == 0)
		mtu = _dpdk_vdev_mtu(pkt_priv(pktio_entry)->port_id);
	return mtu;
}

static uint32_t dpdk_maxlen_get(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);

	return pkt_dpdk->mtu;
}

static int _dpdk_vdev_promisc_mode_set(uint16_t port_id, int enable)
{
	struct rte_eth_dev_info dev_info;
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~(IFF_PROMISC);

	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCSIFFLAGS error\n");
		return -1;
	}

	ret = ioctl(sockfd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		close(sockfd);
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return -1;
	}

	ODP_DBG("vdev promisc set to %d\n", enable);
	close(sockfd);
	return 0;
}

static int promisc_mode_set_pkt_dpdk(pktio_entry_t *pktio_entry,  int enable)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;

	if (enable)
		rte_eth_promiscuous_enable(port_id);
	else
		rte_eth_promiscuous_disable(port_id);

	if (pkt_priv(pktio_entry)->flags.vdev_sysc_promisc) {
		int ret = _dpdk_vdev_promisc_mode_set(port_id, enable);

		if (ret < 0)
			ODP_DBG("vdev promisc mode fail\n");
	}

	return 0;
}

static int _dpdk_vdev_promisc_mode(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
	struct ifreq ifr;
	int ret;
	int sockfd;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	close(sockfd);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (ifr.ifr_flags & IFF_PROMISC) {
		ODP_DBG("promisc is 1\n");
		return 1;
	} else {
		return 0;
	}
}

static int promisc_mode_get_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t * const pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t port_id = pkt_dpdk->port_id;

	if (pkt_dpdk->flags.vdev_sysc_promisc)
		return _dpdk_vdev_promisc_mode(port_id);
	else
		return rte_eth_promiscuous_get(port_id);
}

static int mac_get_pkt_dpdk(pktio_entry_t *pktio_entry, void *mac_addr)
{
	rte_eth_macaddr_get(pkt_priv(pktio_entry)->port_id,
			    (struct rte_ether_addr *)mac_addr);
	return ETH_ALEN;
}

static int mac_set_pkt_dpdk(pktio_entry_t *pktio_entry, const void *mac_addr)
{
	struct rte_ether_addr addr = *(const struct rte_ether_addr *)mac_addr;

	return rte_eth_dev_default_mac_addr_set(pkt_priv(pktio_entry)->port_id,
						&addr);
}

static int capability_pkt_dpdk(pktio_entry_t *pktio_entry,
			       odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->s.capa;
	return 0;
}

static int link_status_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	struct rte_eth_link link;

	rte_eth_link_get(pkt_priv(pktio_entry)->port_id, &link);

	if (link.link_status)
		return ODP_PKTIO_LINK_STATUS_UP;
	return ODP_PKTIO_LINK_STATUS_DOWN;
}

static int dpdk_link_info(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info)
{
	struct rte_eth_link link;
	struct rte_eth_fc_conf fc_conf;
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	int ret;

	memset(&fc_conf, 0, sizeof(struct rte_eth_fc_conf));
	memset(&link, 0, sizeof(struct rte_eth_link));

	ret = rte_eth_dev_flow_ctrl_get(port_id, &fc_conf);
	if (ret && ret != -ENOTSUP) {
		ODP_ERR("rte_eth_dev_flow_ctrl_get() failed\n");
		return -1;
	}

	memset(info, 0, sizeof(odp_pktio_link_info_t));
	info->pause_rx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->pause_tx = ODP_PKTIO_LINK_PAUSE_OFF;
	if (fc_conf.mode == RTE_FC_RX_PAUSE) {
		info->pause_rx = ODP_PKTIO_LINK_PAUSE_ON;
	} else if (fc_conf.mode == RTE_FC_TX_PAUSE) {
		info->pause_tx = ODP_PKTIO_LINK_PAUSE_ON;
	} else if (fc_conf.mode == RTE_FC_FULL) {
		info->pause_rx = ODP_PKTIO_LINK_PAUSE_ON;
		info->pause_tx = ODP_PKTIO_LINK_PAUSE_ON;
	}

	rte_eth_link_get_nowait(port_id, &link);
	if (link.link_autoneg == ETH_LINK_AUTONEG)
		info->autoneg = ODP_PKTIO_LINK_AUTONEG_ON;
	else
		info->autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;

	if (link.link_duplex == ETH_LINK_FULL_DUPLEX)
		info->duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
	else
		info->duplex = ODP_PKTIO_LINK_DUPLEX_HALF;

	if (link.link_speed == ETH_SPEED_NUM_NONE)
		info->speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
	else
		info->speed = link.link_speed;

	if (link.link_status == ETH_LINK_UP)
		info->status = ODP_PKTIO_LINK_STATUS_UP;
	else
		info->status = ODP_PKTIO_LINK_STATUS_DOWN;

	info->media = "unknown";

	return 0;
}

static void stats_convert(struct rte_eth_stats *rte_stats,
			  odp_pktio_stats_t *stats)
{
	stats->in_octets = rte_stats->ibytes;
	stats->in_packets = rte_stats->ipackets;
	stats->in_ucast_pkts = 0;
	stats->in_mcast_pkts = 0;
	stats->in_bcast_pkts = 0;
	stats->in_discards = rte_stats->imissed;
	stats->in_errors = rte_stats->ierrors;
	stats->out_octets = rte_stats->obytes;
	stats->out_packets = rte_stats->opackets;
	stats->out_ucast_pkts = 0;
	stats->out_mcast_pkts = 0;
	stats->out_bcast_pkts = 0;
	stats->out_discards = 0;
	stats->out_errors = rte_stats->oerrors;
}

static int stats_pkt_dpdk(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats)
{
	int ret;
	struct rte_eth_stats rte_stats;

	ret = rte_eth_stats_get(pkt_priv(pktio_entry)->port_id, &rte_stats);

	if (ret == 0) {
		stats_convert(&rte_stats, stats);
		return 0;
	}

	if (ret > 0)
		return -ret;
	else
		return ret;
}

static int stats_reset_pkt_dpdk(pktio_entry_t *pktio_entry)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;

	(void)rte_eth_stats_reset(port_id);
	(void)rte_eth_xstats_reset(port_id);
	return 0;
}

static int dpdk_extra_stat_info(pktio_entry_t *pktio_entry,
				odp_pktio_extra_stat_info_t info[], int num)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	int num_stats, ret, i;

	num_stats = rte_eth_xstats_get_names(port_id, NULL, 0);
	if (num_stats < 0) {
		ODP_ERR("rte_eth_xstats_get_names() failed: %d\n", num_stats);
		return num_stats;
	} else if (info == NULL || num == 0 || num_stats == 0) {
		return num_stats;
	}

	struct rte_eth_xstat_name xstats_names[num_stats];

	ret = rte_eth_xstats_get_names(port_id, xstats_names, num_stats);
	if (ret < 0 || ret > num_stats) {
		ODP_ERR("rte_eth_xstats_get_names() failed: %d\n", ret);
		return -1;
	}
	num_stats = ret;

	for (i = 0; i < num && i < num_stats; i++)
		strncpy(info[i].name, xstats_names[i].name,
			ODP_PKTIO_STATS_EXTRA_NAME_LEN - 1);

	return num_stats;
}

static int dpdk_extra_stats(pktio_entry_t *pktio_entry,
			    uint64_t stats[], int num)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	int num_stats, ret, i;

	num_stats = rte_eth_xstats_get(port_id, NULL, 0);
	if (num_stats < 0) {
		ODP_ERR("rte_eth_xstats_get() failed: %d\n", num_stats);
		return num_stats;
	} else if (stats == NULL || num == 0 || num_stats == 0) {
		return num_stats;
	}

	struct rte_eth_xstat xstats[num_stats];

	ret = rte_eth_xstats_get(port_id, xstats, num_stats);
	if (ret < 0 || ret > num_stats) {
		ODP_ERR("rte_eth_xstats_get() failed: %d\n", ret);
		return -1;
	}
	num_stats = ret;

	for (i = 0; i < num && i < num_stats; i++)
		stats[i] = xstats[i].value;

	return num_stats;
}

static int dpdk_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
				   uint64_t *stat)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	uint64_t xstat_id = id;
	int ret;

	ret = rte_eth_xstats_get_by_id(port_id, &xstat_id, stat, 1);
	if (ret != 1) {
		ODP_ERR("rte_eth_xstats_get_by_id() failed: %d\n", ret);
		return -1;
	}

	return 0;
}

static int dpdk_pktin_stats(pktio_entry_t *pktio_entry, uint32_t index,
			    odp_pktin_queue_stats_t *pktin_stats)
{
	struct rte_eth_stats rte_stats;
	int ret;

	if (odp_unlikely(index > RTE_ETHDEV_QUEUE_STAT_CNTRS - 1)) {
		ODP_ERR("DPDK supports max %d per queue counters\n",
			RTE_ETHDEV_QUEUE_STAT_CNTRS);
		return -1;
	}

	ret = rte_eth_stats_get(pkt_priv(pktio_entry)->port_id, &rte_stats);
	if (odp_unlikely(ret)) {
		ODP_ERR("Failed to read DPDK pktio stats: %d\n", ret);
		return -1;
	}

	memset(pktin_stats, 0, sizeof(odp_pktin_queue_stats_t));

	pktin_stats->packets = rte_stats.q_ipackets[index];
	pktin_stats->octets = rte_stats.q_ibytes[index];
	pktin_stats->errors = rte_stats.q_errors[index];

	return 0;
}

static int dpdk_pktout_stats(pktio_entry_t *pktio_entry, uint32_t index,
			     odp_pktout_queue_stats_t *pktout_stats)
{
	struct rte_eth_stats rte_stats;
	int ret;

	if (odp_unlikely(index > RTE_ETHDEV_QUEUE_STAT_CNTRS - 1)) {
		ODP_ERR("DPDK supports max %d per queue counters\n",
			RTE_ETHDEV_QUEUE_STAT_CNTRS);
		return -1;
	}

	ret = rte_eth_stats_get(pkt_priv(pktio_entry)->port_id, &rte_stats);
	if (odp_unlikely(ret)) {
		ODP_ERR("Failed to read DPDK pktio stats: %d\n", ret);
		return -1;
	}

	memset(pktout_stats, 0, sizeof(odp_pktout_queue_stats_t));

	pktout_stats->packets = rte_stats.q_opackets[index];
	pktout_stats->octets = rte_stats.q_obytes[index];

	return 0;
}

const pktio_if_ops_t _odp_dpdk_pktio_ops = {
	.name = "odp-dpdk",
	.print = NULL,
	.init_global = dpdk_init_global,
	.init_local = NULL,
	.term = dpdk_term_global,
	.open = setup_pkt_dpdk,
	.close = close_pkt_dpdk,
	.start = dpdk_start,
	.stop = stop_pkt_dpdk,
	.stats = stats_pkt_dpdk,
	.stats_reset = stats_reset_pkt_dpdk,
	.pktin_queue_stats = dpdk_pktin_stats,
	.pktout_queue_stats = dpdk_pktout_stats,
	.extra_stat_info = dpdk_extra_stat_info,
	.extra_stats = dpdk_extra_stats,
	.extra_stat_counter = dpdk_extra_stat_counter,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.maxlen_get = dpdk_maxlen_get,
	.maxlen_set = dpdk_maxlen_set,
	.promisc_mode_set = promisc_mode_set_pkt_dpdk,
	.promisc_mode_get = promisc_mode_get_pkt_dpdk,
	.mac_get = mac_get_pkt_dpdk,
	.mac_set = mac_set_pkt_dpdk,
	.link_status = link_status_pkt_dpdk,
	.link_info = dpdk_link_info,
	.capability = capability_pkt_dpdk,
	.config = NULL,
	.input_queues_config = dpdk_input_queues_config,
	.output_queues_config = dpdk_output_queues_config,
	.recv = recv_pkt_dpdk,
	.send = send_pkt_dpdk
};
