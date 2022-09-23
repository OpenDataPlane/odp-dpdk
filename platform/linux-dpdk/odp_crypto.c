/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2018-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp/api/crypto.h>
#include <odp/api/debug.h>
#include <odp/api/hints.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/packet.h>
#include <odp/api/random.h>
#include <odp/api/time.h>

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/time_inlines.h>

#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_packet_internal.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/queue_inlines.h>

#include <rte_config.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>

#include <string.h>
#include <math.h>

#define MAX_SESSIONS 4000
/*
 * Max size of per-thread session object cache. May be useful if sessions
 * are created and destroyed very frequently.
 */
#define SESSION_CACHE_SIZE 16
/*
 * Max size of per-thread crypto operation cache. We can have only one
 * operation per thread in flight at a time so this can be very small.
 */
#define OP_CACHE_SIZE 16
#define NB_DESC_PER_QUEUE_PAIR  16
#define MAX_IV_LENGTH 16
#define AES_CCM_AAD_OFFSET 18
#define IV_OFFSET	(sizeof(struct rte_crypto_op) + \
			 sizeof(struct rte_crypto_sym_op))

/* Max number of rte_cryptodev_dequeue_burst() retries (1 usec wait between
 * retries). */
#define MAX_DEQ_RETRIES 100000

typedef struct crypto_session_entry_s {
	struct crypto_session_entry_s *next;

	/* Session creation parameters */
	odp_crypto_session_param_t p;
	struct rte_cryptodev_sym_session *rte_session;
	struct {
		unsigned int cdev_qpairs_shared:1;
		unsigned int chained_bufs_ok:1;
	} flags;
	uint16_t cdev_nb_qpairs;
	uint8_t cdev_id;
#if ODP_DEPRECATED_API
	uint8_t cipher_iv_data[MAX_IV_LENGTH];
	uint8_t auth_iv_data[MAX_IV_LENGTH];
#endif
} crypto_session_entry_t;

typedef struct crypto_global_s {
	odp_spinlock_t                lock;
	uint8_t enabled_crypto_devs;
	uint8_t enabled_crypto_dev_ids[RTE_CRYPTO_MAX_DEVS];
	uint16_t enabled_crypto_dev_qpairs[RTE_CRYPTO_MAX_DEVS];
	odp_bool_t enabled_crypto_dev_qpairs_shared[RTE_CRYPTO_MAX_DEVS];
	int is_crypto_dev_initialized;
	struct rte_mempool *crypto_op_pool;
	struct rte_mempool *session_mempool[RTE_MAX_NUMA_NODES];
	odp_shm_t shm;
	crypto_session_entry_t *free;
	crypto_session_entry_t sessions[];
} crypto_global_t;

static crypto_global_t *global;

static inline int is_valid_size(uint16_t length,
				const struct rte_crypto_param_range *range)
{
	uint16_t supp_size;

	if (length < range->min)
		return -1;

	if (range->min != length && range->increment == 0)
		return -1;

	for (supp_size = range->min;
	     supp_size <= range->max;
	     supp_size += range->increment) {
		if (length == supp_size)
			return 0;
	}

	return -1;
}

static int cipher_is_aead(odp_cipher_alg_t cipher_alg)
{
	switch (cipher_alg) {
	case ODP_CIPHER_ALG_AES_GCM:
	case ODP_CIPHER_ALG_AES_CCM:
		return 1;
	default:
		return 0;
	}
}

static int auth_is_aead(odp_auth_alg_t auth_alg)
{
	switch (auth_alg) {
	case ODP_AUTH_ALG_AES_GCM:
	case ODP_AUTH_ALG_AES_CCM:
		return 1;
	default:
		return 0;
	}
}

static int cipher_aead_alg_odp_to_rte(odp_cipher_alg_t cipher_alg,
				      struct rte_crypto_sym_xform *aead_xform)
{
	int rc = 0;

	switch (cipher_alg) {
	case ODP_CIPHER_ALG_AES_GCM:
		aead_xform->aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		aead_xform->aead.algo = RTE_CRYPTO_AEAD_AES_CCM;
		break;
	default:
		rc = -1;
	}

	return rc;
}

static int auth_aead_alg_odp_to_rte(odp_auth_alg_t auth_alg,
				    struct rte_crypto_sym_xform *aead_xform)
{
	int rc = 0;

	switch (auth_alg) {
	case ODP_AUTH_ALG_AES_GCM:
		aead_xform->aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		aead_xform->aead.algo = RTE_CRYPTO_AEAD_AES_CCM;
		break;
	default:
		rc = -1;
	}

	return rc;
}

static int cipher_alg_odp_to_rte(odp_cipher_alg_t cipher_alg,
				 struct rte_crypto_sym_xform *cipher_xform)
{
	int rc = 0;

	switch (cipher_alg) {
	case ODP_CIPHER_ALG_NULL:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_NULL;
		break;
	case ODP_CIPHER_ALG_DES:
	case ODP_CIPHER_ALG_3DES_CBC:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_3DES_CBC;
		break;
	case ODP_CIPHER_ALG_3DES_ECB:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_3DES_ECB;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_CBC;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_CTR;
		break;
	case ODP_CIPHER_ALG_AES_ECB:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_ECB;
		break;
	case ODP_CIPHER_ALG_AES_XTS:
		cipher_xform->cipher.algo = RTE_CRYPTO_CIPHER_AES_XTS;
		break;
	default:
		rc = -1;
	}

	return rc;
}

static int auth_alg_odp_to_rte(odp_auth_alg_t auth_alg,
			       struct rte_crypto_sym_xform *auth_xform)
{
	int rc = 0;

	/* Process based on auth */
	switch (auth_alg) {
	case ODP_AUTH_ALG_NULL:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_NULL;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_MD5_HMAC;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA256_HMAC;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA1_HMAC;
		break;
	case ODP_AUTH_ALG_SHA224_HMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA224_HMAC;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA384_HMAC;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_SHA512_HMAC;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_AES_GMAC;
		break;
	case ODP_AUTH_ALG_AES_CMAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_AES_CMAC;
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		auth_xform->auth.algo = RTE_CRYPTO_AUTH_AES_XCBC_MAC;
		break;
	default:
		rc = -1;
	}

	return rc;
}

static crypto_session_entry_t *alloc_session(void)
{
	crypto_session_entry_t *session = NULL;

	odp_spinlock_lock(&global->lock);
	session = global->free;
	if (session) {
		global->free = session->next;
		session->next = NULL;
	}
	odp_spinlock_unlock(&global->lock);

	return session;
}

static void free_session(crypto_session_entry_t *session)
{
	odp_spinlock_lock(&global->lock);
	session->next = global->free;
	global->free = session;
	odp_spinlock_unlock(&global->lock);
}

int _odp_crypto_init_global(void)
{
	size_t mem_size;
	int idx;
	int16_t cdev_id, cdev_count;
	int rc = -1;
	unsigned int pool_size;
	unsigned int nb_queue_pairs = 0, queue_pair;
	uint32_t max_sess_sz = 0, sess_sz;
	odp_shm_t shm;

	if (odp_global_ro.disable.crypto) {
		ODP_PRINT("\nODP crypto is DISABLED\n");
		return 0;
	}

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(crypto_session_entry_t));

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("_odp_crypto_global", mem_size,
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm != ODP_SHM_INVALID) {
		global = odp_shm_addr(shm);
		if (global == NULL) {
			ODP_ERR("Failed to find the reserved shm block");
			return -1;
		}
	} else {
		ODP_ERR("Shared memory reserve failed.\n");
		return -1;
	}

	/* Clear it out */
	memset(global, 0, mem_size);
	global->shm = shm;

	/* Initialize free list and lock */
	for (idx = 0; idx < MAX_SESSIONS; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}

	global->enabled_crypto_devs = 0;
	odp_spinlock_init(&global->lock);

	if (global->is_crypto_dev_initialized)
		return 0;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_PRINT("No crypto devices available\n");
		return 0;
	}

	for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++) {
		sess_sz = rte_cryptodev_sym_get_private_session_size(cdev_id);

		if (sess_sz > max_sess_sz)
			max_sess_sz = sess_sz;
	}

	for (cdev_id = cdev_count - 1; cdev_id >= 0; cdev_id--) {
		struct rte_cryptodev_info dev_info;
		struct rte_mempool *mp;
		odp_bool_t queue_pairs_shared = false;

		rte_cryptodev_info_get(cdev_id, &dev_info);
		nb_queue_pairs = odp_thread_count_max();
		if (nb_queue_pairs > dev_info.max_nb_queue_pairs) {
			nb_queue_pairs = dev_info.max_nb_queue_pairs;
			queue_pairs_shared = true;
			ODP_PRINT("Using shared queue pairs for crypto device %"
				  PRIu16 " (driver: %s)\n",
				  cdev_id, dev_info.driver_name);
		}

		struct rte_cryptodev_qp_conf qp_conf;
		uint8_t socket_id = rte_cryptodev_socket_id(cdev_id);

		struct rte_cryptodev_config conf = {
			.nb_queue_pairs = nb_queue_pairs,
			.socket_id = socket_id,
		};

		if (global->session_mempool[socket_id] == NULL) {
			char mp_name[RTE_MEMPOOL_NAMESIZE];

			snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
				 "sess_mp_%u", socket_id);

			/*
			 * Create enough objects for session headers and
			 * device private data. Since we use shared pool,
			 * the pool has to have twice as many elements
			 * as the maximum number of sessions.
			 */
			pool_size = 2 * MAX_SESSIONS;
			/*
			 * Add the number of elements that may get lost
			 * in thread local caches. The mempool implementation
			 * can actually cache a bit more than the specified
			 * cache size, so we multiply by 2.
			 */
			pool_size += 2 * odp_thread_count_max() * SESSION_CACHE_SIZE;
			mp = rte_cryptodev_sym_session_pool_create(mp_name,
								   pool_size,
								   max_sess_sz,
								   SESSION_CACHE_SIZE,
								   0,
								   socket_id);
			if (mp == NULL) {
				ODP_ERR("Cannot create session pool on socket %d\n",
					socket_id);
				return -1;
			}

			ODP_PRINT("Allocated session pool on socket %d\n",
				  socket_id);
			global->session_mempool[socket_id] = mp;
		}
		mp = global->session_mempool[socket_id];

		rc = rte_cryptodev_configure(cdev_id, &conf);
		if (rc < 0) {
			ODP_ERR("Failed to configure cryptodev %u", cdev_id);
			return -1;
		}

		qp_conf.nb_descriptors = NB_DESC_PER_QUEUE_PAIR;

		for (queue_pair = 0; queue_pair < nb_queue_pairs;
							queue_pair++) {
			qp_conf.mp_session = mp;
			qp_conf.mp_session_private = mp;
			rc = rte_cryptodev_queue_pair_setup(cdev_id, queue_pair,
							    &qp_conf,
							    socket_id);
			if (rc < 0) {
				ODP_ERR("Fail to setup queue pair %u on dev %u",
					queue_pair, cdev_id);
				return -1;
			}
		}

		rc = rte_cryptodev_start(cdev_id);
		if (rc < 0) {
			ODP_ERR("Failed to start device %u: error %d\n",
				cdev_id, rc);
			return -1;
		}

		global->enabled_crypto_dev_ids[global->enabled_crypto_devs] =
			cdev_id;
		global->enabled_crypto_dev_qpairs[cdev_id] = nb_queue_pairs;
		global->enabled_crypto_dev_qpairs_shared[cdev_id] =
			queue_pairs_shared;
		global->enabled_crypto_devs++;
	}

	/*
	 * Make pool size big enough to fill all per-thread caches but
	 * not much bigger since we only have single operation in
	 * flight per thread. Multiply by 2 since mempool can cache
	 * 1.5 times more elements than the specified cache size.
	 */
	pool_size = 2 * odp_thread_count_max() * OP_CACHE_SIZE;

	/* create crypto op pool */
	global->crypto_op_pool =
		rte_crypto_op_pool_create("crypto_op_pool",
					  RTE_CRYPTO_OP_TYPE_SYMMETRIC,
					  pool_size, OP_CACHE_SIZE,
					  2 * MAX_IV_LENGTH,
					  rte_socket_id());

	if (global->crypto_op_pool == NULL) {
		ODP_ERR("Cannot create crypto op pool\n");
		return -1;
	}

	global->is_crypto_dev_initialized = 1;

	return 0;
}

int _odp_crypto_init_local(void)
{
	return 0;
}

int _odp_crypto_term_local(void)
{
	return 0;
}

static int is_dev_aesni_mb(const struct rte_cryptodev_info *dev_info)
{
	return dev_info->driver_name &&
		!strcmp(dev_info->driver_name, "crypto_aesni_mb");
}

static void capability_process(struct rte_cryptodev_info *dev_info,
			       odp_crypto_cipher_algos_t *ciphers,
			       odp_crypto_auth_algos_t *auths)
{
	const struct rte_cryptodev_capabilities *cap;

	/* NULL is always supported, it is done in software */
	ciphers->bit.null = 1;
	auths->bit.null = 1;

	for (cap = &dev_info->capabilities[0];
	     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED;
	     cap++) {
		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
			enum rte_crypto_cipher_algorithm cap_cipher_algo;

			cap_cipher_algo = cap->sym.cipher.algo;
			if (cap_cipher_algo == RTE_CRYPTO_CIPHER_3DES_CBC) {
				ciphers->bit.trides_cbc = 1;
				ciphers->bit.des = 1;
			}
			cap_cipher_algo = cap->sym.cipher.algo;
			if (cap_cipher_algo == RTE_CRYPTO_CIPHER_3DES_ECB) {
				ciphers->bit.trides_ecb = 1;
				ciphers->bit.des = 1;
			}
			if (cap_cipher_algo == RTE_CRYPTO_CIPHER_AES_CBC)
				ciphers->bit.aes_cbc = 1;
			if (cap_cipher_algo == RTE_CRYPTO_CIPHER_AES_CTR)
				ciphers->bit.aes_ctr = 1;
			if (cap_cipher_algo == RTE_CRYPTO_CIPHER_AES_ECB)
				ciphers->bit.aes_ecb = 1;
			if (cap_cipher_algo == RTE_CRYPTO_CIPHER_AES_XTS)
				ciphers->bit.aes_xts = 1;
		}

		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH) {
			enum rte_crypto_auth_algorithm cap_auth_algo;

			cap_auth_algo = cap->sym.auth.algo;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_MD5_HMAC)
				auths->bit.md5_hmac = 1;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_SHA256_HMAC)
				auths->bit.sha256_hmac = 1;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_SHA1_HMAC)
				auths->bit.sha1_hmac = 1;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_SHA224_HMAC)
				auths->bit.sha224_hmac = 1;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_SHA384_HMAC)
				auths->bit.sha384_hmac = 1;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_SHA512_HMAC)
				auths->bit.sha512_hmac = 1;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_AES_GMAC)
				auths->bit.aes_gmac = 1;

			/* Using AES-CMAC with the aesni_mb driver for IPsec
			 * causes a crash inside the intel-mb library.
			 * As a workaround, we do not use AES-CMAC with
			 * the aesni_mb driver.
			 */
			if (cap_auth_algo == RTE_CRYPTO_AUTH_AES_CMAC &&
			    !is_dev_aesni_mb(dev_info))
				auths->bit.aes_cmac = 1;

			/* Combination of (3)DES-CBC and AES-XCBC-MAC does not
			 * work with the aesni_mb crypto driver but causes
			 * crash inside the intel-mb library. As a workaround,
			 * we do not use aes-xcbc-mac with the aesni_mb driver.
			 */
			if (cap_auth_algo == RTE_CRYPTO_AUTH_AES_XCBC_MAC &&
			    !is_dev_aesni_mb(dev_info))
				auths->bit.aes_xcbc_mac = 1;

		}

		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD) {
			enum rte_crypto_aead_algorithm cap_aead_algo;

			cap_aead_algo = cap->sym.aead.algo;
			if (cap_aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
				ciphers->bit.aes_gcm = 1;
				auths->bit.aes_gcm = 1;
			}
			/* AES-CCM algorithm produces errors in Ubuntu Trusty,
			 * so it is disabled for now
			if (cap_aead_algo == RTE_CRYPTO_AEAD_AES_CCM) {
				ciphers->bit.aes_ccm = 1;
				auths->bit.aes_ccm = 1;
			}
			*/
		}
	}
}

int odp_crypto_capability(odp_crypto_capability_t *capability)
{
	uint8_t cdev_id, cdev_count;

	if (odp_global_ro.disable.crypto) {
		ODP_ERR("Crypto is disabled\n");
		return -1;
	}

	if (NULL == capability)
		return -1;

	/* Initialize crypto capability structure */
	memset(capability, 0, sizeof(odp_crypto_capability_t));

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return 0;
	}

	capability->sync_mode = ODP_SUPPORT_YES;
	capability->async_mode = ODP_SUPPORT_PREFERRED;
	capability->max_sessions = MAX_SESSIONS;
	capability->queue_type_plain = 1;
	capability->queue_type_sched = 1;

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);
		capability_process(&dev_info, &capability->ciphers,
				   &capability->auths);
		if ((dev_info.feature_flags &
		     RTE_CRYPTODEV_FF_HW_ACCELERATED)) {
			capability->hw_ciphers = capability->ciphers;
			capability->hw_auths = capability->auths;
		}

		/* Report the lowest max_nb_sessions of all devices */
		if (dev_info.sym.max_nb_sessions != 0 &&
		    dev_info.sym.max_nb_sessions < capability->max_sessions)
			capability->max_sessions = dev_info.sym.max_nb_sessions;
	}

	return 0;
}

static int cipher_capa_insert(odp_crypto_cipher_capability_t *src,
			      odp_crypto_cipher_capability_t *capa,
			      int idx,
			      int size)
{
	int i = 0;

	while (1) {
		if (i >= size) {
			return idx + 1;
		} else if (i == idx) {
			src[i] = *capa;
			return idx + 1;
		} else if (src[i].key_len < capa->key_len ||
			   (src[i].key_len == capa->key_len &&
			    src[i].iv_len < capa->iv_len)) {
			i++;
		} else {
			memmove(&src[i + 1], &src[i],
				sizeof(*capa) * (idx - i));
			src[i] = *capa;
			return idx + 1;
		}
	}
}

static int cipher_gen_capability(const struct rte_crypto_param_range *key_size,
				 const struct rte_crypto_param_range *iv_size,
				 odp_crypto_cipher_capability_t *src,
				 int offset,
				 int num_copy)
{
	int idx = offset;

	uint32_t key_size_min = key_size->min;
	uint32_t key_size_max = key_size->max;
	uint32_t key_inc = key_size->increment;
	uint32_t iv_size_max = iv_size->max;
	uint32_t iv_size_min = iv_size->min;
	uint32_t iv_inc = iv_size->increment;

	for (uint32_t key_len = key_size_min; key_len <= key_size_max;
	     key_len += key_inc) {
		for (uint32_t iv_size = iv_size_min;
		     iv_size <= iv_size_max; iv_size += iv_inc) {
			odp_crypto_cipher_capability_t capa;

			capa.key_len = key_len;
			capa.iv_len = iv_size;
			capa.bit_mode = false;

			idx = cipher_capa_insert(src, &capa, idx, num_copy);

			if (iv_inc == 0)
				break;
		}

		if (key_inc == 0)
			break;
	}

	return idx;
}

static int cipher_aead_capability(odp_cipher_alg_t cipher,
				  odp_crypto_cipher_capability_t dst[],
				  int num_copy)
{
	odp_crypto_cipher_capability_t src[num_copy];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_cipher_capability_t);

	uint8_t cdev_id, cdev_count;
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform aead_xform;

	rc = cipher_aead_alg_odp_to_rte(cipher, &aead_xform);

	/* Check result */
	if (rc)
		return -1;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);

		for (cap = &dev_info.capabilities[0];
		     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED &&
		     !(cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD &&
		       cap->sym.aead.algo == aead_xform.aead.algo);
		     cap++)
			;

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		idx = cipher_gen_capability(&cap->sym.aead.key_size,
					    &cap->sym.aead.iv_size,
					    src, idx,
					    num_copy);
	}

	if (idx < num_copy)
		num_copy = idx;

	memcpy(dst, src, num_copy * size);

	return idx;
}

static int cipher_capability(odp_cipher_alg_t cipher,
			     odp_crypto_cipher_capability_t dst[],
			     int num_copy)
{
	odp_crypto_cipher_capability_t src[num_copy];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_cipher_capability_t);

	uint8_t cdev_id, cdev_count;
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform cipher_xform;

	rc = cipher_alg_odp_to_rte(cipher, &cipher_xform);

	/* Check result */
	if (rc)
		return -1;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);

		for (cap = &dev_info.capabilities[0];
		     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED &&
		     !(cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
		       cap->sym.cipher.algo == cipher_xform.cipher.algo);
		     cap++)
			;

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		idx = cipher_gen_capability(&cap->sym.cipher.key_size,
					    &cap->sym.cipher.iv_size,
					    src, idx,
					    num_copy);
	}

	if (idx < num_copy)
		num_copy = idx;

	memcpy(dst, src, num_copy * size);

	return idx;
}

int odp_crypto_cipher_capability(odp_cipher_alg_t cipher,
				 odp_crypto_cipher_capability_t dst[],
				 int num_copy)
{
	/* We implement NULL in software, so always return capability */
	if (cipher == ODP_CIPHER_ALG_NULL) {
		if (num_copy >= 1)
			memset(dst, 0, sizeof(odp_crypto_cipher_capability_t));
		return 1;
	}

	if (cipher_is_aead(cipher))
		return cipher_aead_capability(cipher, dst, num_copy);
	else
		return cipher_capability(cipher, dst, num_copy);
}

static int auth_capa_insert(odp_crypto_auth_capability_t *src,
			    odp_crypto_auth_capability_t *capa,
			    int idx,
			    int size)
{
	int i = 0;

	while (1) {
		if (i >= size) {
			return idx + 1;
		} else if (i == idx) {
			src[i] = *capa;
			return idx + 1;
		} else if (src[i].digest_len < capa->digest_len ||
			   (src[i].digest_len == capa->digest_len &&
			    src[i].key_len < capa->key_len) ||
			   (src[i].digest_len == capa->digest_len &&
			    src[i].key_len == capa->key_len &&
			    src[i].iv_len < capa->iv_len)) {
			i++;
		} else {
			memmove(&src[i + 1], &src[i],
				sizeof(*capa) * (idx - i));
			src[i] = *capa;
			return idx + 1;
		}
	}
}

static int auth_gen_capability(const struct rte_crypto_param_range *key_size,
			       const struct rte_crypto_param_range *iv_size,
			       const struct rte_crypto_param_range *digest_size,
			       const struct rte_crypto_param_range *aad_size,
			       odp_crypto_auth_capability_t *src,
			       int offset,
			       int num_copy)
{
	int idx = offset;

	uint16_t key_size_min = key_size->min;
	uint16_t key_size_max = key_size->max;
	uint16_t key_inc = key_size->increment;
	uint16_t iv_size_max = iv_size->max;
	uint16_t iv_size_min = iv_size->min;
	uint16_t iv_inc = iv_size->increment;
	uint16_t digest_size_min = digest_size->min;
	uint16_t digest_size_max = digest_size->max;
	uint16_t digest_inc = digest_size->increment;

	for (uint16_t digest_len = digest_size_min;
	     digest_len <= digest_size_max;
	     digest_len += digest_inc) {
		for (uint16_t key_len = key_size_min;
		     key_len <= key_size_max;
		     key_len += key_inc) {
			for (uint16_t iv_size = iv_size_min;
			     iv_size <= iv_size_max;
			     iv_size += iv_inc) {
				odp_crypto_auth_capability_t capa;

				capa.digest_len = digest_len;
				capa.key_len = key_len;
				capa.iv_len = iv_size;
				capa.bit_mode = false;
				capa.aad_len.min = aad_size->min;
				capa.aad_len.max = aad_size->max;
				capa.aad_len.inc = aad_size->increment;

				idx = auth_capa_insert(src, &capa, idx,
						       num_copy);

				if (iv_inc == 0)
					break;
			}

			if (key_inc == 0)
				break;
		}

		if (digest_inc == 0)
			break;
	}

	return idx;
}

static const struct rte_crypto_param_range zero_range = {
	.min = 0, .max = 0, .increment = 0
};

static int auth_aead_capability(odp_auth_alg_t auth,
				odp_crypto_auth_capability_t dst[],
				int num_copy)
{
	odp_crypto_auth_capability_t src[num_copy];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_auth_capability_t);

	uint8_t cdev_id, cdev_count;
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform aead_xform;

	rc = auth_aead_alg_odp_to_rte(auth, &aead_xform);

	/* Check result */
	if (rc)
		return -1;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);

		for (cap = &dev_info.capabilities[0];
		     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED &&
		     !(cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD &&
		       cap->sym.auth.algo == aead_xform.auth.algo);
		     cap++)
			;

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		idx = auth_gen_capability(&zero_range,
					  &zero_range,
					  &cap->sym.aead.digest_size,
					  &cap->sym.aead.aad_size,
					  src, idx,
					  num_copy);
	}

	if (idx < num_copy)
		num_copy = idx;

	memcpy(dst, src, num_copy * size);

	return idx;
}

static int auth_capability(odp_auth_alg_t auth,
			   odp_crypto_auth_capability_t dst[],
			   int num_copy)
{
	odp_crypto_auth_capability_t src[num_copy];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_auth_capability_t);
	uint8_t cdev_id, cdev_count;
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform auth_xform;
	uint16_t key_size_override;
	struct rte_crypto_param_range key_range_override;

	rc = auth_alg_odp_to_rte(auth, &auth_xform);

	/* Check result */
	if (rc)
		return -1;

	/* Don't generate thousands of useless capabilities for HMAC
	 * algorithms. In ODP we need support for small amount of key
	 * lengths. So we limit key size to what is practical for ODP. */
	switch (auth) {
	case ODP_AUTH_ALG_MD5_HMAC:
		key_size_override = 16;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		key_size_override = 20;
		break;
	case ODP_AUTH_ALG_SHA224_HMAC:
		key_size_override = 28;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		key_size_override = 32;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		key_size_override = 48;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		key_size_override = 64;
		break;
	default:
		key_size_override = 0;
		break;
	}

	key_range_override.min = key_size_override;
	key_range_override.max = key_size_override;
	key_range_override.increment = 0;

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		ODP_ERR("No crypto devices available\n");
		return -1;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(cdev_id, &dev_info);

		for (cap = &dev_info.capabilities[0];
		     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED &&
		     !(cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		       cap->sym.auth.algo == auth_xform.auth.algo);
		     cap++)
			;

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		if (key_size_override != 0 &&
		    is_valid_size(key_size_override,
				  &cap->sym.auth.key_size) != 0)
			continue;

		idx = auth_gen_capability(key_size_override ?
					  &key_range_override :
					  &cap->sym.auth.key_size,
					  &cap->sym.auth.iv_size,
					  &cap->sym.auth.digest_size,
					  &cap->sym.auth.aad_size,
					  src, idx,
					  num_copy);
	}

	if (idx < num_copy)
		num_copy = idx;

	memcpy(dst, src, num_copy * size);

	return idx;
}

int odp_crypto_auth_capability(odp_auth_alg_t auth,
			       odp_crypto_auth_capability_t dst[],
			       int num_copy)
{
	/* We implement NULL in software, so always return capability */
	if (auth == ODP_AUTH_ALG_NULL) {
		if (num_copy >= 1)
			memset(dst, 0, sizeof(odp_crypto_auth_capability_t));
		return 1;
	}

	if (auth_is_aead(auth))
		return auth_aead_capability(auth, dst, num_copy);
	else
		return auth_capability(auth, dst, num_copy);
}

static int get_crypto_aead_dev(struct rte_crypto_sym_xform *aead_xform,
			       uint8_t *dev_id)
{
	uint8_t cdev_id, id;
	const struct rte_cryptodev_capabilities *cap;

	for (id = 0; id < global->enabled_crypto_devs; id++) {
		struct rte_cryptodev_info dev_info;

		cdev_id = global->enabled_crypto_dev_ids[id];
		rte_cryptodev_info_get(cdev_id, &dev_info);

		for (cap = &dev_info.capabilities[0];
		     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED &&
		     !(cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD &&
		       cap->sym.aead.algo == aead_xform->aead.algo);
		     cap++)
			;

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		/* Check if key size is supported by the algorithm. */
		if (is_valid_size(aead_xform->aead.key.length,
				  &cap->sym.aead.key_size) != 0) {
			ODP_ERR("Unsupported aead key length\n");
			continue;
		}

		/* Check if iv length is supported by the algorithm. */
		if (aead_xform->aead.iv.length > MAX_IV_LENGTH ||
		    is_valid_size(aead_xform->aead.iv.length,
				  &cap->sym.aead.iv_size) != 0) {
			ODP_ERR("Unsupported iv length\n");
			continue;
		}

		/* Check if digest size is supported by the algorithm. */
		if (is_valid_size(aead_xform->aead.digest_length,
				  &cap->sym.aead.digest_size) != 0) {
			ODP_ERR("Unsupported digest length\n");
			continue;
		}

		*dev_id = cdev_id;
		return 0;
	}

	return -1;
}

static int get_crypto_dev(struct rte_crypto_sym_xform *cipher_xform,
			  struct rte_crypto_sym_xform *auth_xform,
			  uint8_t *dev_id)
{
	uint8_t cdev_id, id;
	const struct rte_cryptodev_capabilities *cap;

	for (id = 0; id < global->enabled_crypto_devs; id++) {
		struct rte_cryptodev_info dev_info;

		cdev_id = global->enabled_crypto_dev_ids[id];
		rte_cryptodev_info_get(cdev_id, &dev_info);
		if (cipher_xform->cipher.algo == RTE_CRYPTO_CIPHER_NULL)
			goto check_auth;

		for (cap = &dev_info.capabilities[0];
		     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED &&
		     !(cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
		       cap->sym.cipher.algo == cipher_xform->cipher.algo);
		     cap++)
			;

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		/* Check if key size is supported by the algorithm. */
		if (is_valid_size(cipher_xform->cipher.key.length,
				  &cap->sym.cipher.key_size) != 0) {
			ODP_ERR("Unsupported cipher key length\n");
			continue;
		}

		/* Check if iv length is supported by the algorithm. */
		if (cipher_xform->cipher.iv.length > MAX_IV_LENGTH ||
		    is_valid_size(cipher_xform->cipher.iv.length,
				  &cap->sym.cipher.iv_size) != 0) {
			ODP_ERR("Unsupported iv length\n");
			continue;
		}

check_auth:
		if (auth_xform->auth.algo == RTE_CRYPTO_AUTH_NULL &&
		    cipher_xform->cipher.algo != RTE_CRYPTO_CIPHER_NULL)
			goto check_finish;

		for (cap = &dev_info.capabilities[0];
		     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED &&
		     !(cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		       cap->sym.auth.algo == auth_xform->auth.algo);
		     cap++)
			;

		if (cap->op == RTE_CRYPTO_OP_TYPE_UNDEFINED)
			continue;

		/* As a bug workaround, we do not use AES_CMAC with
		 * the aesni-mb crypto driver.
		 */
		if (auth_xform->auth.algo == RTE_CRYPTO_AUTH_AES_CMAC &&
		    is_dev_aesni_mb(&dev_info))
			continue;

		/* As a bug workaround, we do not use AES_XCBC_MAC with
		 * the aesni-mb crypto driver.
		 */
		if (auth_xform->auth.algo == RTE_CRYPTO_AUTH_AES_XCBC_MAC &&
		    is_dev_aesni_mb(&dev_info))
			continue;

		/* Check if key size is supported by the algorithm. */
		if (is_valid_size(auth_xform->auth.key.length,
				  &cap->sym.auth.key_size) != 0) {
			ODP_ERR("Unsupported auth key length\n");
			continue;
		}

		/* Check if digest size is supported by the algorithm. */
		if (is_valid_size(auth_xform->auth.digest_length,
				  &cap->sym.auth.digest_size) != 0) {
			ODP_ERR("Unsupported digest length\n");
			continue;
		}

		/* Check if iv length is supported by the algorithm. */
		if (auth_xform->auth.iv.length > MAX_IV_LENGTH ||
		    is_valid_size(auth_xform->auth.iv.length,
				  &cap->sym.auth.iv_size) != 0) {
			ODP_ERR("Unsupported iv length\n");
			continue;
		}

check_finish:
		*dev_id = cdev_id;
		return 0;
	}

	return -1;
}

static int chained_bufs_ok(const odp_crypto_session_param_t *param,
			   uint8_t cdev_id)
{
	struct rte_cryptodev_info dev_info;
	int chained_bufs_ok;

	rte_cryptodev_info_get(cdev_id, &dev_info);
	chained_bufs_ok = !!(dev_info.feature_flags & RTE_CRYPTODEV_FF_IN_PLACE_SGL);

	/*
	 * Some crypto devices do not support chained buffers with all
	 * algorithms despite advertizing SG support in feature flags.
	 */

	if (dev_info.driver_name &&
	    !strcmp(dev_info.driver_name, "crypto_aesni_gcm") &&
	    param->auth_alg == ODP_AUTH_ALG_AES_GMAC)
		chained_bufs_ok = 0;

	if (dev_info.driver_name &&
	    !strcmp(dev_info.driver_name, "crypto_openssl") &&
	    (param->cipher_alg == ODP_CIPHER_ALG_AES_GCM ||
	     param->auth_alg == ODP_AUTH_ALG_AES_GMAC))
		chained_bufs_ok = 0;

	return chained_bufs_ok;
}

static int crypto_fill_cipher_xform(struct rte_crypto_sym_xform *cipher_xform,
				    odp_crypto_session_param_t *param)
{
	cipher_xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cipher_xform->next = NULL;

	if (cipher_alg_odp_to_rte(param->cipher_alg, cipher_xform))
		return -1;

	cipher_xform->cipher.key.data = param->cipher_key.data;
	cipher_xform->cipher.key.length = param->cipher_key.length;
	cipher_xform->cipher.iv.offset = IV_OFFSET;
	cipher_xform->cipher.iv.length = param->cipher_iv_len;

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == param->op)
		cipher_xform->cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	else
		cipher_xform->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;

	return 0;
}

static int crypto_fill_auth_xform(struct rte_crypto_sym_xform *auth_xform,
				  odp_crypto_session_param_t *param)
{
	auth_xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
	auth_xform->next = NULL;

	if (auth_alg_odp_to_rte(param->auth_alg, auth_xform))
		return -1;

	auth_xform->auth.digest_length = param->auth_digest_len;
	if (auth_xform->auth.digest_length > PACKET_DIGEST_MAX) {
		ODP_ERR("Requested too long digest\n");
		return -1;
	}

	auth_xform->auth.key.data = param->auth_key.data;
	auth_xform->auth.key.length = param->auth_key.length;
	auth_xform->auth.iv.offset = IV_OFFSET + MAX_IV_LENGTH;
	auth_xform->auth.iv.length = param->auth_iv_len;

	if (ODP_CRYPTO_OP_ENCODE == param->op)
		auth_xform->auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
	else
		auth_xform->auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;

	return 0;
}

static int crypto_fill_aead_xform(struct rte_crypto_sym_xform *aead_xform,
				  odp_crypto_session_param_t *param)
{
	aead_xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
	aead_xform->next = NULL;

	if (cipher_aead_alg_odp_to_rte(param->cipher_alg, aead_xform))
		return -1;

	aead_xform->aead.key.data = param->cipher_key.data;
	aead_xform->aead.key.length = param->cipher_key.length;
	aead_xform->aead.iv.offset = IV_OFFSET;
	aead_xform->aead.iv.length = param->cipher_iv_len;

	aead_xform->aead.aad_length = param->auth_aad_len;
	if (aead_xform->aead.aad_length > PACKET_AAD_MAX) {
		ODP_ERR("Requested too long AAD\n");
		return -1;
	}

	if (aead_xform->aead.algo == RTE_CRYPTO_AEAD_AES_CCM &&
	    aead_xform->aead.aad_length + AES_CCM_AAD_OFFSET >
	    PACKET_AAD_MAX) {
		ODP_ERR("Requested too long AAD for CCM\n");
		return -1;
	}

	aead_xform->aead.digest_length = param->auth_digest_len;
	if (aead_xform->aead.digest_length > PACKET_DIGEST_MAX) {
		ODP_ERR("Requested too long digest\n");
		return -1;
	}

	/* Derive order */
	if (ODP_CRYPTO_OP_ENCODE == param->op)
		aead_xform->aead.op = RTE_CRYPTO_AEAD_OP_ENCRYPT;
	else
		aead_xform->aead.op = RTE_CRYPTO_AEAD_OP_DECRYPT;

	return 0;
}

int odp_crypto_session_create(const odp_crypto_session_param_t *param,
			      odp_crypto_session_t *session_out,
			      odp_crypto_ses_create_err_t *status)
{
	int rc = 0;
	uint8_t cdev_id = 0;
	uint8_t socket_id;
	struct rte_crypto_sym_xform cipher_xform;
	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform *first_xform;
	struct rte_cryptodev_sym_session *rte_session;
	struct rte_mempool *sess_mp;
	crypto_session_entry_t *session = NULL;

	if (odp_global_ro.disable.crypto) {
		ODP_ERR("Crypto is disabled\n");
		/* Dummy output to avoid compiler warning about uninitialized
		 * variables */
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	if (rte_cryptodev_count() == 0) {
		ODP_ERR("No crypto devices available\n");
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	/* Allocate memory for this session */
	session = alloc_session();
	if (session == NULL) {
		ODP_ERR("Failed to allocate a session session");
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	/* Copy parameters */
	session->p = *param;

	if (cipher_is_aead(param->cipher_alg)) {
		if (crypto_fill_aead_xform(&cipher_xform, &session->p) < 0) {
			*status = ODP_CRYPTO_SES_ERR_CIPHER;
			goto err;
		}

		first_xform = &cipher_xform;

		rc = get_crypto_aead_dev(&cipher_xform,
					 &cdev_id);
	} else {
		odp_bool_t do_cipher_first;

		if (crypto_fill_cipher_xform(&cipher_xform, &session->p) < 0) {
			*status = ODP_CRYPTO_SES_ERR_CIPHER;
			goto err;
		}

		if (crypto_fill_auth_xform(&auth_xform, &session->p) < 0) {
			*status = ODP_CRYPTO_SES_ERR_AUTH;
			goto err;
		}

		/* Derive order */
		if (ODP_CRYPTO_OP_ENCODE == param->op)
			do_cipher_first =  param->auth_cipher_text;
		else
			do_cipher_first = !param->auth_cipher_text;

		/* Derive order */
		if (param->cipher_alg == ODP_CIPHER_ALG_NULL &&
		    param->auth_alg == ODP_AUTH_ALG_NULL) {
			rte_session = NULL;
			cdev_id = ~0;
			session->flags.chained_bufs_ok = 1;
			session->cdev_nb_qpairs = 0;
			goto out_null;
		} else if (param->cipher_alg == ODP_CIPHER_ALG_NULL) {
			first_xform = &auth_xform;
		} else if (param->auth_alg == ODP_AUTH_ALG_NULL) {
			first_xform = &cipher_xform;
		} else if (do_cipher_first) {
			first_xform = &cipher_xform;
			first_xform->next = &auth_xform;
		} else {
			first_xform = &auth_xform;
			first_xform->next = &cipher_xform;
		}

		rc = get_crypto_dev(&cipher_xform,
				    &auth_xform,
				    &cdev_id);
	}
	if (rc) {
		ODP_ERR("Couldn't find a crypto device");
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	socket_id = rte_cryptodev_socket_id(cdev_id);
	sess_mp = global->session_mempool[socket_id];

	/* Setup session */
	rte_session = rte_cryptodev_sym_session_create(sess_mp);
	if (rte_session == NULL) {
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	if (rte_cryptodev_sym_session_init(cdev_id, rte_session,
					   first_xform, sess_mp) < 0) {
		/* remove the crypto_session_entry_t */
		rte_cryptodev_sym_session_free(rte_session);
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	session->flags.chained_bufs_ok = chained_bufs_ok(param, cdev_id);
	session->cdev_nb_qpairs = global->enabled_crypto_dev_qpairs[cdev_id];
	if (global->enabled_crypto_dev_qpairs_shared[cdev_id])
		session->flags.cdev_qpairs_shared = 1;
	else
		session->flags.cdev_qpairs_shared = 0;
out_null:
	session->rte_session  = rte_session;
	session->cdev_id = cdev_id;
#if ODP_DEPRECATED_API
	if (param->cipher_iv.data)
		memcpy(session->cipher_iv_data,
		       param->cipher_iv.data,
		       param->cipher_iv.length);
	if (param->auth_iv.data)
		memcpy(session->auth_iv_data,
		       param->auth_iv.data,
		       param->auth_iv.length);
#endif
	/* We're happy */
	*session_out = (intptr_t)session;
	*status = ODP_CRYPTO_SES_ERR_NONE;

	return 0;

err:
	/* error status should be set at this moment */
	if (session != NULL) {
		memset(session, 0, sizeof(*session));
		free_session(session);
	}
	*session_out = ODP_CRYPTO_SESSION_INVALID;
	return -1;
}

int odp_crypto_session_destroy(odp_crypto_session_t _session)
{
	struct rte_cryptodev_sym_session *rte_session = NULL;
	crypto_session_entry_t *session;

	session = (crypto_session_entry_t *)(intptr_t)_session;

	rte_session = session->rte_session;

	if (rte_session != NULL) {
		if (rte_cryptodev_sym_session_clear(session->cdev_id,
						    rte_session) < 0)
			return -1;

		if (rte_cryptodev_sym_session_free(rte_session) < 0)
			return -1;
	}

	/* remove the crypto_session_entry_t */
	memset(session, 0, sizeof(*session));
	free_session(session);

	return 0;
}

int _odp_crypto_term_global(void)
{
	int rc = 0;
	int ret;
	int count = 0;
	crypto_session_entry_t *session;

	if (odp_global_ro.disable.crypto || global == NULL)
		return 0;

	for (session = global->free; session != NULL; session = session->next)
		count++;
	if (count != MAX_SESSIONS) {
		ODP_ERR("crypto sessions still active\n");
		rc = -1;
	}

	if (global->crypto_op_pool != NULL)
		rte_mempool_free(global->crypto_op_pool);

	ret = odp_shm_free(global->shm);
	if (ret < 0) {
		ODP_ERR("shm free failed for crypto_pool\n");
		rc = -1;
	}

	return rc;
}

#if ODP_DEPRECATED_API
odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	if (odp_event_type(ev) != ODP_EVENT_CRYPTO_COMPL)
		ODP_ABORT("Event not a crypto completion");
	return (odp_crypto_compl_t)ev;
}

odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event)
{
	return (odp_event_t)completion_event;
}

void odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			     odp_crypto_op_result_t *result)
{
	(void)completion_event;
	(void)result;

	/* We won't get such events anyway, so there can be no result */
	ODP_ASSERT(0);
}

void odp_crypto_compl_free(odp_crypto_compl_t completion_event)
{
	odp_event_t ev = odp_crypto_compl_to_event(completion_event);

	odp_buffer_free(odp_buffer_from_event(ev));
}

uint64_t odp_crypto_compl_to_u64(odp_crypto_compl_t hdl)
{
	return _odp_pri(hdl);
}
#endif

void odp_crypto_session_param_init(odp_crypto_session_param_t *param)
{
	memset(param, 0, sizeof(odp_crypto_session_param_t));
}

uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl)
{
	return (uint64_t)hdl;
}

odp_packet_t odp_crypto_packet_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET);
	ODP_ASSERT(odp_event_subtype(ev) == ODP_EVENT_PACKET_CRYPTO);

	return odp_packet_from_event(ev);
}

odp_event_t odp_crypto_packet_to_event(odp_packet_t pkt)
{
	return odp_packet_to_event(pkt);
}

static
odp_crypto_packet_result_t *get_op_result_from_packet(odp_packet_t pkt)
{
	odp_packet_hdr_t *hdr = packet_hdr(pkt);

	return &hdr->crypto_op_result;
}

int odp_crypto_result(odp_crypto_packet_result_t *result,
		      odp_packet_t packet)
{
	odp_crypto_packet_result_t *op_result;

	ODP_ASSERT(odp_event_subtype(odp_packet_to_event(packet)) ==
		   ODP_EVENT_PACKET_CRYPTO);

	op_result = get_op_result_from_packet(packet);

	memcpy(result, op_result, sizeof(*result));

	return 0;
}

static uint8_t *crypto_prepare_digest(crypto_session_entry_t *session,
				      odp_packet_t pkt,
				      const odp_crypto_packet_op_param_t *param,
				      rte_iova_t *phys_addr)
{
	struct rte_mbuf *mb;
	uint8_t *data;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (session->p.op == ODP_CRYPTO_OP_DECODE) {
		odp_packet_copy_to_mem(pkt, param->hash_result_offset,
				       session->p.auth_digest_len,
				       pkt_hdr->crypto_digest_buf);
		if (odp_unlikely(session->p.hash_result_in_auth_range))
			_odp_packet_set_data(pkt, param->hash_result_offset, 0,
					     session->p.auth_digest_len);
	}
	data = pkt_hdr->crypto_digest_buf;
	mb = &pkt_hdr->event_hdr.mb;
	*phys_addr =
		rte_pktmbuf_iova_offset(mb, data -
					rte_pktmbuf_mtod(mb, uint8_t *));

	return data;
}

static void crypto_fill_aead_param(crypto_session_entry_t *session,
				   odp_packet_t pkt,
				   const odp_crypto_packet_op_param_t *param,
				   struct rte_crypto_op *op)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	uint32_t iv_len = session->p.cipher_iv_len;
	uint8_t *iv_ptr;

	op->sym->aead.digest.data =
		crypto_prepare_digest(session, pkt, param,
				      &op->sym->aead.digest.phys_addr);

	if (session->p.cipher_alg == ODP_CIPHER_ALG_AES_CCM)
		memcpy(pkt_hdr->crypto_aad_buf + AES_CCM_AAD_OFFSET,
		       param->aad_ptr,
		       session->p.auth_aad_len);
	else
		memcpy(pkt_hdr->crypto_aad_buf,
		       param->aad_ptr,
		       session->p.auth_aad_len);
	op->sym->aead.aad.data = pkt_hdr->crypto_aad_buf;
	op->sym->aead.aad.phys_addr =
		rte_pktmbuf_iova_offset(&pkt_hdr->event_hdr.mb,
					op->sym->aead.aad.data -
					rte_pktmbuf_mtod(&pkt_hdr->event_hdr.mb,
							 uint8_t *));
	iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	if (session->p.cipher_alg == ODP_CIPHER_ALG_AES_CCM) {
		*iv_ptr = iv_len;
		iv_ptr++;
	}

#if ODP_DEPRECATED_API
	if (param->cipher_iv_ptr)
		memcpy(iv_ptr, param->cipher_iv_ptr, iv_len);
	else if (session->p.cipher_iv.data)
		memcpy(iv_ptr, session->cipher_iv_data, iv_len);
	else
		ODP_ASSERT(iv_len == 0);
#else
	ODP_ASSERT(iv_len == 0 || param->cipher_iv_ptr != NULL);
	memcpy(iv_ptr, param->cipher_iv_ptr, iv_len);
#endif

	op->sym->aead.data.offset = param->cipher_range.offset;
	op->sym->aead.data.length = param->cipher_range.length;
}

static void crypto_fill_sym_param(crypto_session_entry_t *session,
				  odp_packet_t pkt,
				  const odp_crypto_packet_op_param_t *param,
				  struct rte_crypto_op *op)
{
	uint32_t cipher_iv_len = session->p.cipher_iv_len;
	uint32_t auth_iv_len = session->p.auth_iv_len;
	uint8_t *iv_ptr;

	if (session->p.auth_digest_len == 0) {
		op->sym->auth.digest.data = NULL;
		op->sym->auth.digest.phys_addr = 0;
	} else {
		op->sym->auth.digest.data =
			crypto_prepare_digest(session, pkt, param,
					      &op->sym->auth.digest.phys_addr);
	}

#if ODP_DEPRECATED_API
	if (param->cipher_iv_ptr) {
		iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
		memcpy(iv_ptr, param->cipher_iv_ptr, cipher_iv_len);
	} else if (session->p.cipher_iv.data) {
		iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
		memcpy(iv_ptr, session->cipher_iv_data, cipher_iv_len);
	} else {
		ODP_ASSERT(cipher_iv_len == 0);
	}

	if (param->auth_iv_ptr) {
		iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *,
						   IV_OFFSET + MAX_IV_LENGTH);
		memcpy(iv_ptr, param->auth_iv_ptr, auth_iv_len);
	} else if (session->p.auth_iv.data) {
		iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *,
						   IV_OFFSET + MAX_IV_LENGTH);
		memcpy(iv_ptr, session->auth_iv_data, auth_iv_len);
	} else {
		ODP_ASSERT(auth_iv_len == 0);
	}
#else
	ODP_ASSERT(cipher_iv_len == 0 || param->cipher_iv_ptr != NULL);
	ODP_ASSERT(auth_iv_len == 0 || param->auth_iv_ptr != NULL);
	iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	memcpy(iv_ptr, param->cipher_iv_ptr, cipher_iv_len);

	if (odp_unlikely(auth_iv_len > 0)) {
		iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET + MAX_IV_LENGTH);
		memcpy(iv_ptr, param->auth_iv_ptr, auth_iv_len);
	}
#endif

	op->sym->cipher.data.offset = param->cipher_range.offset;
	op->sym->cipher.data.length = param->cipher_range.length;

	op->sym->auth.data.offset = param->auth_range.offset;
	op->sym->auth.data.length = param->auth_range.length;
}

/*
 * Attempt to change a multi segment packet to a single segment packet by
 * reducing the headroom. Shift packet data toward the start of the first
 * segment and trim the tail, hopefully getting rid of the tail segment.
 *
 * This fails if the packet data does not fit in the first segment with
 * the new headroom. A temporary copy to a bigger buffer would be needed
 * in that case.
 *
 * Do nothing for single segment packets.
 *
 * We assume that odp_crypto_operation() makes no promise to not shift
 * packet data within the packet. If that is not the case, the shifting
 * done here needs to be undone after the crypto operation.
 *
 */
static int linearize_pkt(const crypto_session_entry_t *session, odp_packet_t pkt)
{
	const uint32_t new_headroom = RTE_PKTMBUF_HEADROOM;
	uint32_t headroom;
	uint32_t len;
	uint32_t shift;
	int rc;

	if (odp_likely(odp_packet_num_segs(pkt) == 1))
		return 0;
	if (session->flags.chained_bufs_ok)
		return 0;

	headroom = odp_packet_headroom(pkt);
	if (odp_unlikely(new_headroom >= headroom))
		return -1;

	len = odp_packet_len(pkt);
	shift = headroom - new_headroom;
	odp_packet_push_head(pkt, shift);
	odp_packet_move_data(pkt, 0, shift, len);
	/* We rely on our trunc implementation to not change the handle */
	rc = odp_packet_trunc_tail(&pkt, shift, NULL, NULL);
	ODP_ASSERT(rc == 0);

	return odp_packet_num_segs(pkt) != 1;
}

static int copy_data_and_metadata(odp_packet_t dst, odp_packet_t src)
{
	int md_copy;
	int rc;

	md_copy = _odp_packet_copy_md_possible(odp_packet_pool(dst),
					       odp_packet_pool(src));
	if (odp_unlikely(md_copy < 0)) {
		ODP_ERR("Unable to copy packet metadata\n");
		return -1;
	}

	rc = odp_packet_copy_from_pkt(dst, 0, src, 0, odp_packet_len(src));
	if (odp_unlikely(rc < 0)) {
		ODP_ERR("Unable to copy packet data\n");
		return -1;
	}

	_odp_packet_copy_md(packet_hdr(dst), packet_hdr(src), md_copy);
	return 0;
}

static odp_packet_t get_output_packet(const crypto_session_entry_t *session,
				      odp_packet_t pkt_in,
				      odp_packet_t pkt_out)
{
	int rc;

	if (odp_likely(pkt_in == pkt_out))
		return pkt_out;

	if (pkt_out == ODP_PACKET_INVALID) {
		odp_pool_t pool = session->p.output_pool;

		ODP_ASSERT(pool != ODP_POOL_INVALID);
		if (pool == odp_packet_pool(pkt_in)) {
			pkt_out = pkt_in;
		} else {
			pkt_out = odp_packet_copy(pkt_in, pool);
			if (odp_likely(pkt_out != ODP_PACKET_INVALID))
				odp_packet_free(pkt_in);
		}
		return pkt_out;
	}
	rc = copy_data_and_metadata(pkt_out, pkt_in);
	if (odp_unlikely(rc < 0))
		return ODP_PACKET_INVALID;

	odp_packet_free(pkt_in);
	return pkt_out;
}

static
int odp_crypto_int(odp_packet_t pkt_in,
		   odp_packet_t *pkt_out,
		   const odp_crypto_packet_op_param_t *param)
{
	crypto_session_entry_t *session;
	odp_crypto_alg_err_t rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
	odp_crypto_alg_err_t rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	struct rte_cryptodev_sym_session *rte_session = NULL;
	struct rte_crypto_op *op = NULL;
	odp_packet_t out_pkt;
	odp_crypto_packet_result_t *op_result;
	odp_bool_t result_ok = true;

	session = (crypto_session_entry_t *)(intptr_t)param->session;
	if (odp_unlikely(session == NULL))
		return -1;

	op = rte_crypto_op_alloc(global->crypto_op_pool,
				 RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (odp_unlikely(op == NULL)) {
		ODP_ERR("Failed to allocate crypto operation\n");
		goto err;
	}

	out_pkt = get_output_packet(session, pkt_in, *pkt_out);
	if (odp_unlikely(out_pkt == ODP_PACKET_INVALID))
		goto err;

	if (odp_unlikely(linearize_pkt(session, out_pkt))) {
		result_ok = false;
		rc_cipher = ODP_CRYPTO_ALG_ERR_DATA_SIZE;
		rc_auth = ODP_CRYPTO_ALG_ERR_DATA_SIZE;
		goto out;
	}

	rte_session = session->rte_session;
	/* NULL rte_session means that it is a NULL-NULL operation.
	 * Just return new packet. */
	if (odp_unlikely(rte_session == NULL))
		goto out;

	if (cipher_is_aead(session->p.cipher_alg))
		crypto_fill_aead_param(session, out_pkt, param, op);
	else
		crypto_fill_sym_param(session, out_pkt, param, op);

	if (odp_likely(rc_cipher == ODP_CRYPTO_ALG_ERR_NONE &&
		       rc_auth == ODP_CRYPTO_ALG_ERR_NONE)) {
		int retry_count = 0;
		int queue_pair;
		int rc;
		odp_bool_t queue_pairs_shared = session->flags.cdev_qpairs_shared;

		if (odp_unlikely(queue_pairs_shared))
			queue_pair = odp_thread_id() % session->cdev_nb_qpairs;
		else
			queue_pair = odp_thread_id();

		/* Set crypto operation data parameters */
		rte_crypto_op_attach_sym_session(op, rte_session);

		op->sym->m_src = (struct rte_mbuf *)(intptr_t)out_pkt;
		/*
		 * If queue pairs are shared between multiple threads,
		 * we protect enqueue and dequeue using a lock. In addition,
		 * we keep the lock over the whole enqueue-dequeue sequence
		 * to guarantee that we get the same op back as what we
		 * enqueued. Otherwise synchronous ODP crypto operations
		 * could report the completion and status of an unrelated
		 * operation that was sent to the same queue pair from
		 * another thread.
		 */
		if (odp_unlikely(queue_pairs_shared))
			odp_spinlock_lock(&global->lock);
		rc = rte_cryptodev_enqueue_burst(session->cdev_id,
						 queue_pair, &op, 1);
		if (odp_unlikely(rc == 0)) {
			if (odp_unlikely(queue_pairs_shared))
				odp_spinlock_unlock(&global->lock);
			ODP_ERR("Failed to enqueue packet\n");
			result_ok = false;
			goto out;
		}

		/* There may be a delay until the crypto operation is
		 * completed. */
		while (1) {
			rc = rte_cryptodev_dequeue_burst(session->cdev_id,
							 queue_pair, &op, 1);
			if (odp_unlikely(rc == 0) &&
			    retry_count < MAX_DEQ_RETRIES) {
				odp_time_wait_ns(ODP_TIME_USEC_IN_NS);
				retry_count++;
				continue;
			}
			break;
		}
		if (odp_unlikely(queue_pairs_shared))
			odp_spinlock_unlock(&global->lock);
		if (odp_unlikely(rc == 0)) {
			ODP_ERR("Failed to dequeue packet\n");
			result_ok = false;
			op = NULL;
			goto out;
		}

		out_pkt = (odp_packet_t)op->sym->m_src;
		switch (op->status) {
		case RTE_CRYPTO_OP_STATUS_SUCCESS:
			rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
			rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
			break;
		case RTE_CRYPTO_OP_STATUS_AUTH_FAILED:
			result_ok = false;
			rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
			rc_auth = ODP_CRYPTO_ALG_ERR_ICV_CHECK;
			break;
		default:
			result_ok = false;
			rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
			rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
			break;
		}
	} else {
		result_ok = false;
	}

	if (session->p.op == ODP_CRYPTO_OP_ENCODE &&
	    session->p.auth_digest_len != 0 &&
	    op->status == RTE_CRYPTO_OP_STATUS_SUCCESS) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(out_pkt);

		odp_packet_copy_from_mem(out_pkt, param->hash_result_offset,
					 session->p.auth_digest_len,
					 pkt_hdr->crypto_digest_buf);
	}

out:
	if (odp_likely(op))
		rte_crypto_op_free(op);
	/* Fill in result */
	packet_subtype_set(out_pkt, ODP_EVENT_PACKET_CRYPTO);
	op_result = get_op_result_from_packet(out_pkt);
	op_result->cipher_status.alg_err = rc_cipher;
	op_result->cipher_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	op_result->auth_status.alg_err = rc_auth;
	op_result->auth_status.hw_err = ODP_CRYPTO_HW_ERR_NONE;
	op_result->ok = result_ok;

	/* Synchronous, simply return results */
	*pkt_out = out_pkt;

	return 0;

err:
	if (op)
		rte_crypto_op_free(op);

	return -1;
}

#if ODP_DEPRECATED_API
int odp_crypto_operation(odp_crypto_op_param_t *param,
			 odp_bool_t *posted,
			 odp_crypto_op_result_t *result)
{
	odp_crypto_packet_op_param_t packet_param;
	odp_packet_t out_pkt = param->out_pkt;
	odp_crypto_packet_result_t packet_result;
	odp_crypto_op_result_t local_result;
	int rc;

	packet_param.session = param->session;
	packet_param.cipher_iv_ptr = param->cipher_iv_ptr;
	packet_param.auth_iv_ptr = param->auth_iv_ptr;
	packet_param.hash_result_offset = param->hash_result_offset;
	packet_param.aad_ptr = param->aad_ptr;
	packet_param.cipher_range = param->cipher_range;
	packet_param.auth_range = param->auth_range;

	rc = odp_crypto_int(param->pkt, &out_pkt, &packet_param);
	if (rc < 0)
		return rc;

	rc = odp_crypto_result(&packet_result, out_pkt);
	if (rc < 0) {
		/*
		 * We cannot fail since odp_crypto_op() has already processed
		 * the packet. Let's indicate error in the result instead.
		 */
		packet_result.ok = false;
	}

	/* Indicate to caller operation was sync */
	*posted = 0;

	packet_subtype_set(out_pkt, ODP_EVENT_PACKET_BASIC);

	/* Fill in result */
	local_result.ctx = param->ctx;
	local_result.pkt = out_pkt;
	local_result.cipher_status = packet_result.cipher_status;
	local_result.auth_status = packet_result.auth_status;
	local_result.ok = packet_result.ok;

	/*
	 * Be bug-to-bug compatible. Return output packet also through params.
	 */
	param->out_pkt = out_pkt;

	*result = local_result;

	return 0;
}
#endif

int odp_crypto_op(const odp_packet_t pkt_in[],
		  odp_packet_t pkt_out[],
		  const odp_crypto_packet_op_param_t param[],
		  int num_pkt)
{
	crypto_session_entry_t *session;
	int i, rc;

	for (i = 0; i < num_pkt; i++) {
		session = (crypto_session_entry_t *)(intptr_t)param[i].session;
		ODP_ASSERT(ODP_CRYPTO_SYNC == session->p.op_mode);

		rc = odp_crypto_int(pkt_in[i], &pkt_out[i], &param[i]);
		if (rc < 0)
			break;
	}

	return i;
}

int odp_crypto_op_enq(const odp_packet_t pkt_in[],
		      const odp_packet_t pkt_out[],
		      const odp_crypto_packet_op_param_t param[],
		      int num_pkt)
{
	odp_packet_t pkt;
	odp_event_t event;
	crypto_session_entry_t *session;
	int i, rc;

	for (i = 0; i < num_pkt; i++) {
		session = (crypto_session_entry_t *)(intptr_t)param[i].session;
		ODP_ASSERT(ODP_CRYPTO_ASYNC == session->p.op_mode);
		ODP_ASSERT(ODP_QUEUE_INVALID != session->p.compl_queue);

		pkt = pkt_out[i];
		rc = odp_crypto_int(pkt_in[i], &pkt, &param[i]);
		if (rc < 0)
			break;

		event = odp_packet_to_event(pkt);
		if (odp_queue_enq(session->p.compl_queue, event)) {
			odp_event_free(event);
			break;
		}
	}

	return i;
}
