/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2018-2025 Nokia
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
#include <odp_macros_internal.h>
#include <odp_libconfig_internal.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/queue_inlines.h>

#include <rte_config.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_version.h>

#include <string.h>
#include <math.h>

#define MAX_BURST 32
/*
 * Max size of per-thread session object cache. May be useful if sessions
 * are created and destroyed very frequently.
 */
#define SESSION_CACHE_SIZE 16
/*
 * Max size of per-thread crypto operation cache. We can have at most
 * MAX_BURST operations per thread in flight at a time. Make op cache
 * larger than MAX_BURST to avoid frequent access of the shared pool.
 */
#define OP_CACHE_SIZE (2 * MAX_BURST)
/*
 * Have enough descriptors for a full burst plus some extra as required
 * by the crypto drivers.
 */
#define NB_DESC_PER_QUEUE_PAIR (2 * MAX_BURST)
/* Required by crypto_aesni_mb driver */
ODP_STATIC_ASSERT(NB_DESC_PER_QUEUE_PAIR > MAX_BURST,
		  "NB_DESC_PER_QUEUE_PAIR must be greater than MAX_BURST");
/* Required by crypto_aesni_mb driver */
ODP_STATIC_ASSERT(_ODP_CHECK_IS_POWER2(NB_DESC_PER_QUEUE_PAIR),
		  "NB_DESC_PER_QUEUE_PAIR must be a power of 2");

#define MAX_IV_LENGTH 16
#define AES_CCM_AAD_OFFSET 18

/* Max number of rte_cryptodev_dequeue_burst() retries before error printout */
#define MAX_DEQ_RETRIES (10 * 1000 * 1000)
/* Min delay between rte_cryptodev_dequeue_burst() retries in nanoseconds */
#define DEQ_RETRY_DELAY_NS 10

#define MAX_CRYPTODEVS 16

typedef struct cryptodev_s {
	uint8_t dev_id;
	odp_bool_t disable_aes_cmac;
	odp_bool_t qpairs_shared;
	uint16_t num_qpairs;
} cryptodev_t;

typedef struct crypto_session_entry_s {
	struct crypto_session_entry_s *next;

	/* Session creation parameters */
	odp_crypto_session_param_t p;
	struct rte_cryptodev_sym_session *rte_session;
	struct {
		unsigned int cdev_qpairs_shared:1;
		unsigned int chained_bufs_ok:1;
		unsigned int aead:1;
	} flags;
	uint8_t cdev_id;
	cryptodev_t *dev;
} crypto_session_entry_t;

typedef struct crypto_config_s {
	uint32_t max_sessions;
	odp_bool_t allow_queue_pair_sharing;
	odp_bool_t openssl_disable_aes_cmac;
} crypto_config_t;

typedef struct crypto_global_s {
	odp_spinlock_t                lock;
	uint8_t num_devs;
	cryptodev_t devs[MAX_CRYPTODEVS];
	struct rte_mempool *crypto_op_pool;
	struct rte_mempool *session_mempool[RTE_MAX_NUMA_NODES];
	odp_shm_t shm;
	crypto_config_t config;
	crypto_session_entry_t *free;
	crypto_session_entry_t sessions[];
} crypto_global_t;

typedef enum op_status_t {
	S_OK,		/* everything ok this far */
	S_NOP,		/* no-op: null crypto & null auth */
	S_DEV,		/* processed by cryptodev */
	S_ERROR,	/* error occurred */
	S_ERROR_LIN,	/* packet linearization error occurred */
	S_ERROR_HASH_OFFSET, /* hash offset in cipher range */
} op_status_t;

typedef struct crypto_op_state_t {
	uint8_t cipher_iv[MAX_IV_LENGTH] ODP_ALIGNED(8);
	uint8_t auth_iv[MAX_IV_LENGTH] ODP_ALIGNED(8);
	odp_packet_t pkt;
	op_status_t status;
	crypto_session_entry_t *session;
	uint32_t hash_result_offset;
} crypto_op_state_t;

typedef struct crypto_op_t {
	/* these must be first */
	struct rte_crypto_op op;
	struct rte_crypto_sym_op sym_op;

	crypto_op_state_t state;
} crypto_op_t;

#define IV_OFFSET offsetof(crypto_op_t, state.cipher_iv)
#define AUTH_IV_OFFSET offsetof(crypto_op_t, state.auth_iv)

static crypto_global_t *global;

static inline int is_valid_size(uint16_t length,
				const struct rte_crypto_param_range *range)
{
	uint16_t supp_size;

	if (length < range->min)
		return 0;

	if (range->min != length && range->increment == 0)
		return 0;

	for (supp_size = range->min;
	     supp_size <= range->max;
	     supp_size += range->increment) {
		if (length == supp_size)
			return 1;
	}

	return 0;
}

static int cipher_is_aead(odp_cipher_alg_t cipher_alg)
{
	switch (cipher_alg) {
	case ODP_CIPHER_ALG_AES_GCM:
	case ODP_CIPHER_ALG_AES_CCM:
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
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
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
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
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		aead_xform->aead.algo = RTE_CRYPTO_AEAD_CHACHA20_POLY1305;
		break;
#endif
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
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		aead_xform->aead.algo = RTE_CRYPTO_AEAD_CHACHA20_POLY1305;
		break;
#endif
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

static int read_config(crypto_config_t *config)
{
	const char *str;
	int val;

	_ODP_PRINT("Crypto config:\n");

	str = "crypto.max_num_sessions";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	_ODP_PRINT("  %s: %d\n", str, val);
	if (val <= 0) {
		_ODP_ERR("Invalid value for config option '%s'\n", str);
		return -1;
	}
	config->max_sessions = val;

	str = "crypto.allow_queue_pair_sharing";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	config->allow_queue_pair_sharing = !!val;
	_ODP_PRINT("  %s: %d\n", str, val);

	str = "crypto.openssl.disable_aes_cmac";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	config->openssl_disable_aes_cmac = !!val;
	_ODP_PRINT("  %s: %d\n", str, val);

	_ODP_PRINT("\n");
	return 0;
}

int _odp_crypto_init_global(void)
{
	crypto_config_t config;
	size_t mem_size;
	uint8_t cdev_id, cdev_count;
	int rc = -1;
	unsigned int pool_size;
	unsigned int nb_queue_pairs = 0, queue_pair;
	uint32_t max_sess_sz = 0, sess_sz;
	odp_shm_t shm;

	if (read_config(&config))
		return -1;

	if (odp_global_ro.disable.crypto) {
		_ODP_PRINT("\nODP crypto is DISABLED\n");
		return 0;
	}

	cdev_count = rte_cryptodev_count();
	if (cdev_count == 0) {
		_ODP_PRINT("No crypto devices available\n");
		return 0;
	}

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (config.max_sessions * sizeof(crypto_session_entry_t));

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("_odp_crypto_global", mem_size,
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm != ODP_SHM_INVALID) {
		global = odp_shm_addr(shm);
		if (global == NULL) {
			_ODP_ERR("Failed to find the reserved shm block");
			return -1;
		}
	} else {
		_ODP_ERR("Shared memory reserve failed.\n");
		return -1;
	}

	memset(global, 0, mem_size);
	global->shm = shm;
	global->config = config;

	/* Initialize free list and lock */
	for (uint32_t idx = 0; idx < config.max_sessions; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}

	global->num_devs = 0;
	odp_spinlock_init(&global->lock);

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		sess_sz = rte_cryptodev_sym_get_private_session_size(cdev_id);

		if (sess_sz > max_sess_sz)
			max_sess_sz = sess_sz;
	}

	for (cdev_id = 0; cdev_id < cdev_count; cdev_id++) {
		struct rte_cryptodev_info dev_info;
		struct rte_mempool *mp;
		odp_bool_t queue_pairs_shared = false;

		rte_cryptodev_info_get(cdev_id, &dev_info);
		nb_queue_pairs = odp_thread_count_max();
		if (nb_queue_pairs > dev_info.max_nb_queue_pairs) {
			if (!config.allow_queue_pair_sharing) {
				_ODP_ERR("Crypto device %" PRIu16 " (driver: %s), "
					 "does not have enough queue pairs. "
					 "Check ODP config file.\n",
					 cdev_id, dev_info.driver_name);
				goto fail;
			}
			nb_queue_pairs = dev_info.max_nb_queue_pairs;
			queue_pairs_shared = true;
			_ODP_PRINT("Using shared queue pairs for crypto device %"
				  PRIu16 " (driver: %s)\n",
				  cdev_id, dev_info.driver_name);
		}

		struct rte_cryptodev_qp_conf qp_conf;
		uint8_t socket_id = rte_cryptodev_socket_id(cdev_id);

		struct rte_cryptodev_config conf = {
			.nb_queue_pairs = nb_queue_pairs,
			.socket_id = socket_id,
		};

		if (dev_info.driver_name && !strcmp(dev_info.driver_name, "crypto_openssl")) {
			global->devs[global->num_devs].disable_aes_cmac =
				config.openssl_disable_aes_cmac;
			if (odp_global_ro.init_param.mem_model == ODP_MEM_MODEL_PROCESS) {
				_ODP_ERR("Disabling crypto_openssl: process mode not supported\n");
				continue;
			}
		}

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
			pool_size = 2 * config.max_sessions;
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
				_ODP_ERR("Cannot create session pool on socket %d\n", socket_id);
				goto fail;
			}

			_ODP_PRINT("Allocated session pool on socket %d\n", socket_id);
			global->session_mempool[socket_id] = mp;
		}
		mp = global->session_mempool[socket_id];

		rc = rte_cryptodev_configure(cdev_id, &conf);
		if (rc < 0) {
			_ODP_ERR("Failed to configure cryptodev %u", cdev_id);
			goto fail;
		}

		qp_conf.nb_descriptors = NB_DESC_PER_QUEUE_PAIR;

		for (queue_pair = 0; queue_pair < nb_queue_pairs;
							queue_pair++) {
			qp_conf.mp_session = mp;
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 0)
			qp_conf.mp_session_private = mp;
#endif
			rc = rte_cryptodev_queue_pair_setup(cdev_id, queue_pair,
							    &qp_conf,
							    socket_id);
			if (rc < 0) {
				_ODP_ERR("Fail to setup queue pair %u on dev %u",
					 queue_pair, cdev_id);
				goto fail;
			}
		}

		rc = rte_cryptodev_start(cdev_id);
		if (rc < 0) {
			_ODP_ERR("Failed to start device %u: error %d\n", cdev_id, rc);
			goto fail;
		}

		global->devs[global->num_devs].dev_id = cdev_id;
		global->devs[global->num_devs].qpairs_shared = queue_pairs_shared;
		global->devs[global->num_devs].num_qpairs = nb_queue_pairs;
		global->num_devs++;
		if (global->num_devs >= MAX_CRYPTODEVS) {
			_ODP_ERR("Too many crypto devices, skipping the rest\n");
			break;
		}
	}

	/*
	 * Make pool size big enough to fill all per-thread caches.
	 * Multiply by 2 since mempool can cache 1.5 times more elements
	 * than the specified cache size.
	 */
	pool_size = 2 * odp_thread_count_max() * OP_CACHE_SIZE;

	/* create crypto op pool */
	global->crypto_op_pool =
		rte_crypto_op_pool_create("crypto_op_pool",
					  RTE_CRYPTO_OP_TYPE_SYMMETRIC,
					  pool_size, OP_CACHE_SIZE,
					  sizeof(crypto_op_t)
					  - sizeof(struct rte_crypto_op)
					  - sizeof(struct rte_crypto_sym_op),
					  rte_socket_id());

	if (global->crypto_op_pool == NULL) {
		_ODP_ERR("Cannot create crypto op pool\n");
		goto fail;
	}

	return 0;

fail:
	(void)_odp_crypto_term_global();
	return -1;
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
		if (cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
			continue;

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
			if (cap_auth_algo == RTE_CRYPTO_AUTH_AES_CMAC)
				auths->bit.aes_cmac = 1;
			if (cap_auth_algo == RTE_CRYPTO_AUTH_AES_XCBC_MAC)
				auths->bit.aes_xcbc_mac = 1;
		}

		if (cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD) {
			enum rte_crypto_aead_algorithm cap_aead_algo;

			cap_aead_algo = cap->sym.aead.algo;
			if (cap_aead_algo == RTE_CRYPTO_AEAD_AES_GCM) {
				ciphers->bit.aes_gcm = 1;
				auths->bit.aes_gcm = 1;
			}
			if (cap_aead_algo == RTE_CRYPTO_AEAD_AES_CCM) {
				ciphers->bit.aes_ccm = 1;
				auths->bit.aes_ccm = 1;
			}
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
			if (cap_aead_algo == RTE_CRYPTO_AEAD_CHACHA20_POLY1305) {
				ciphers->bit.chacha20_poly1305 = 1;
				auths->bit.chacha20_poly1305 = 1;
			}
#endif
		}
	}
}

int odp_crypto_capability(odp_crypto_capability_t *capability)
{
	if (odp_global_ro.disable.crypto) {
		_ODP_ERR("Crypto is disabled\n");
		return -1;
	}

	if (NULL == capability)
		return -1;

	/* Initialize crypto capability structure */
	memset(capability, 0, sizeof(odp_crypto_capability_t));

	if (!global || global->num_devs == 0)
		return 0;

	capability->sync_mode = ODP_SUPPORT_YES;
	capability->async_mode = ODP_SUPPORT_PREFERRED;
	capability->max_sessions = global->config.max_sessions;
	capability->queue_type_plain = 1;
	capability->queue_type_sched = 1;

	for (int n = 0; n < global->num_devs; n++) {
		struct rte_cryptodev_info dev_info;
		odp_crypto_cipher_algos_t ciphers = {.all_bits = 0};
		odp_crypto_auth_algos_t auths = {.all_bits = 0};

		rte_cryptodev_info_get(global->devs[n].dev_id, &dev_info);
		capability_process(&dev_info, &ciphers, &auths);

		if (global->devs[n].disable_aes_cmac)
			auths.bit.aes_cmac = 0;

		capability->ciphers.all_bits |= ciphers.all_bits;
		capability->auths.all_bits |= auths.all_bits;

		if ((dev_info.feature_flags &
		     RTE_CRYPTODEV_FF_HW_ACCELERATED)) {
			capability->hw_ciphers.all_bits |= ciphers.all_bits;
			capability->hw_auths.all_bits |= auths.all_bits;
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
		for (uint32_t iv_len = iv_size_min; iv_len <= iv_size_max; iv_len += iv_inc) {
			odp_crypto_cipher_capability_t capa;

			capa.key_len = key_len;
			capa.iv_len = iv_len;
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

static const struct rte_cryptodev_capabilities *
find_capa_for_alg(const struct rte_cryptodev_info *dev_info,
		  const struct rte_crypto_sym_xform *xform)
{
	const struct rte_cryptodev_capabilities *cap;

	for (cap = &dev_info->capabilities[0];
	     cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED;
	     cap++) {
		if (cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC ||
		    cap->sym.xform_type != xform->type)
			continue;
		if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER &&
		    cap->sym.cipher.algo == xform->cipher.algo)
			return cap;
		if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH &&
		    cap->sym.auth.algo == xform->auth.algo)
			return cap;
		if (xform->type == RTE_CRYPTO_SYM_XFORM_AEAD &&
		    cap->sym.aead.algo == xform->aead.algo)
			return cap;
	}
	return NULL;
}

static int cipher_aead_capability(odp_cipher_alg_t cipher,
				  odp_crypto_cipher_capability_t dst[],
				  int num_copy)
{
	odp_crypto_cipher_capability_t src[_ODP_MAX(num_copy, 1)];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_cipher_capability_t);
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform aead_xform;

	aead_xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	rc = cipher_aead_alg_odp_to_rte(cipher, &aead_xform);
	if (rc)
		return -1;

	for (int n = 0; n < global->num_devs; n++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(global->devs[n].dev_id, &dev_info);
		cap = find_capa_for_alg(&dev_info, &aead_xform);
		if (cap == NULL)
			continue;

		idx = cipher_gen_capability(&cap->sym.aead.key_size,
					    &cap->sym.aead.iv_size,
					    src, idx,
					    num_copy);
	}

	if (idx < num_copy)
		num_copy = idx;

	if (dst)
		memcpy(dst, src, num_copy * size);

	return idx;
}

static int cipher_capability(odp_cipher_alg_t cipher,
			     odp_crypto_cipher_capability_t dst[],
			     int num_copy)
{
	odp_crypto_cipher_capability_t src[_ODP_MAX(num_copy, 1)];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_cipher_capability_t);
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform cipher_xform;

	cipher_xform.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	rc = cipher_alg_odp_to_rte(cipher, &cipher_xform);
	if (rc)
		return -1;

	for (int n = 0; n < global->num_devs; n++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(global->devs[n].dev_id, &dev_info);
		cap = find_capa_for_alg(&dev_info, &cipher_xform);
		if (cap == NULL)
			continue;

		idx = cipher_gen_capability(&cap->sym.cipher.key_size,
					    &cap->sym.cipher.iv_size,
					    src, idx,
					    num_copy);
	}

	if (idx < num_copy)
		num_copy = idx;

	if (dst)
		memcpy(dst, src, num_copy * size);

	return idx;
}

int odp_crypto_cipher_capability(odp_cipher_alg_t cipher,
				 odp_crypto_cipher_capability_t dst[],
				 int num_copy)
{
	if (!global || global->num_devs == 0)
		return 0;

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
			for (uint16_t iv_len = iv_size_min;
			     iv_len <= iv_size_max;
			     iv_len += iv_inc) {
				odp_crypto_auth_capability_t capa;

				capa.digest_len = digest_len;
				capa.key_len = key_len;
				capa.iv_len = iv_len;
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
	odp_crypto_auth_capability_t src[_ODP_MAX(num_copy, 1)];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_auth_capability_t);
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform aead_xform;

	aead_xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	rc = auth_aead_alg_odp_to_rte(auth, &aead_xform);
	if (rc)
		return -1;

	for (int n = 0; n < global->num_devs; n++) {
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(global->devs[n].dev_id, &dev_info);
		cap = find_capa_for_alg(&dev_info, &aead_xform);
		if (cap == NULL)
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

	if (dst)
		memcpy(dst, src, num_copy * size);

	return idx;
}

static int auth_capability(odp_auth_alg_t auth,
			   odp_crypto_auth_capability_t dst[],
			   int num_copy)
{
	odp_crypto_auth_capability_t src[_ODP_MAX(num_copy, 1)];
	int idx = 0, rc = 0;
	int size = sizeof(odp_crypto_auth_capability_t);
	const struct rte_cryptodev_capabilities *cap;
	struct rte_crypto_sym_xform auth_xform;
	uint16_t key_size_override;
	struct rte_crypto_param_range key_range_override;

	auth_xform.type = RTE_CRYPTO_SYM_XFORM_AUTH;
	rc = auth_alg_odp_to_rte(auth, &auth_xform);
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

	for (int n = 0; n < global->num_devs; n++) {
		struct rte_cryptodev_info dev_info;

		if (auth == ODP_AUTH_ALG_AES_CMAC && global->devs[n].disable_aes_cmac)
			continue;

		rte_cryptodev_info_get(global->devs[n].dev_id, &dev_info);
		cap = find_capa_for_alg(&dev_info, &auth_xform);
		if (cap == NULL)
			continue;

		if (key_size_override != 0 &&
		    !is_valid_size(key_size_override,
				   &cap->sym.auth.key_size))
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

	if (dst)
		memcpy(dst, src, num_copy * size);

	return idx;
}

int odp_crypto_auth_capability(odp_auth_alg_t auth,
			       odp_crypto_auth_capability_t dst[],
			       int num_copy)
{
	if (!global || global->num_devs == 0)
		return 0;

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

static odp_crypto_ses_create_err_t
get_crypto_aead_dev(struct rte_crypto_sym_xform *aead_xform,
		    cryptodev_t **device)
{
	const struct rte_cryptodev_capabilities *cap;

	for (int n = 0; n < global->num_devs; n++) {
		cryptodev_t *dev = &global->devs[n];
		struct rte_cryptodev_info dev_info;

		rte_cryptodev_info_get(dev->dev_id, &dev_info);

		cap = find_capa_for_alg(&dev_info, aead_xform);
		if (cap == NULL)
			continue;

		/* Check if key size is supported by the algorithm. */
		if (!is_valid_size(aead_xform->aead.key.length,
				   &cap->sym.aead.key_size)) {
			_ODP_DBG("Unsupported aead key length\n");
			continue;
		}

		/* Check if iv length is supported by the algorithm. */
		if (aead_xform->aead.iv.length > MAX_IV_LENGTH ||
		    !is_valid_size(aead_xform->aead.iv.length,
				   &cap->sym.aead.iv_size)) {
			_ODP_DBG("Unsupported iv length\n");
			continue;
		}

		/* Check if digest size is supported by the algorithm. */
		if (!is_valid_size(aead_xform->aead.digest_length,
				   &cap->sym.aead.digest_size)) {
			_ODP_DBG("Unsupported digest length\n");
			continue;
		}

		*device = dev;
		return ODP_CRYPTO_SES_ERR_NONE;
	}

	return ODP_CRYPTO_SES_ERR_CIPHER;
}

static int is_cipher_supported(const struct rte_cryptodev_info *dev_info,
			       const struct rte_crypto_sym_xform *cipher_xform)
{
	const struct rte_cryptodev_capabilities *cap;

	_ODP_ASSERT(cipher_xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER);

	if (cipher_xform->cipher.algo == RTE_CRYPTO_CIPHER_NULL)
		return 1;

	cap = find_capa_for_alg(dev_info, cipher_xform);
	if (cap == NULL)
		return 0;

	/* Check if key size is supported by the algorithm. */
	if (!is_valid_size(cipher_xform->cipher.key.length,
			   &cap->sym.cipher.key_size)) {
		_ODP_DBG("Unsupported cipher key length\n");
		return 0;
	}

	/* Check if iv length is supported by the algorithm. */
	if (cipher_xform->cipher.iv.length > MAX_IV_LENGTH ||
	    !is_valid_size(cipher_xform->cipher.iv.length,
			   &cap->sym.cipher.iv_size)) {
		_ODP_DBG("Unsupported iv length\n");
		return 0;
	}

	return 1;
}

static int is_auth_supported(const struct rte_cryptodev_info *dev_info,
			     const struct rte_crypto_sym_xform *auth_xform)
{
	const struct rte_cryptodev_capabilities *cap;

	_ODP_ASSERT(auth_xform->type == RTE_CRYPTO_SYM_XFORM_AUTH);

	if (auth_xform->auth.algo == RTE_CRYPTO_AUTH_NULL)
		return 1;

	cap = find_capa_for_alg(dev_info, auth_xform);
	if (cap == NULL)
		return 0;

	/* Check if key size is supported by the algorithm. */
	if (!is_valid_size(auth_xform->auth.key.length,
			   &cap->sym.auth.key_size)) {
		_ODP_DBG("Unsupported auth key length\n");
		return 0;
	}

	/* Check if digest size is supported by the algorithm. */
	if (!is_valid_size(auth_xform->auth.digest_length,
			   &cap->sym.auth.digest_size)) {
		_ODP_DBG("Unsupported digest length\n");
		return 0;
	}

	/* Check if iv length is supported by the algorithm. */
	if (auth_xform->auth.iv.length > MAX_IV_LENGTH ||
	    !is_valid_size(auth_xform->auth.iv.length,
			   &cap->sym.auth.iv_size)) {
		_ODP_DBG("Unsupported iv length\n");
		return 0;
	}

	return 1;
}

static int is_combo_buggy(struct rte_cryptodev_info *dev_info,
			  enum rte_crypto_cipher_algorithm cipher,
			  enum rte_crypto_auth_algorithm auth)
{
	/*
	 * Certain algorithm combinations do not work in the aesni_mb
	 * crypto driver because of bugs in the driver.
	 */
	if (is_dev_aesni_mb(dev_info)) {
		if (cipher == RTE_CRYPTO_CIPHER_3DES_CBC &&
		    (auth == RTE_CRYPTO_AUTH_AES_XCBC_MAC ||
		     auth == RTE_CRYPTO_AUTH_AES_CMAC))
			return 1;
	}
	return 0;
}

static odp_crypto_ses_create_err_t
get_crypto_dev(struct rte_crypto_sym_xform *cipher_xform,
	       struct rte_crypto_sym_xform *auth_xform,
	       cryptodev_t **device)
{
	int cipher_supported = 0;
	int auth_supported = 0;

	for (int n = 0; n < global->num_devs; n++) {
		cryptodev_t *dev = &global->devs[n];
		struct rte_cryptodev_info dev_info;
		int cipher_ok, auth_ok;

		rte_cryptodev_info_get(dev->dev_id, &dev_info);

		cipher_ok = is_cipher_supported(&dev_info, cipher_xform);
		auth_ok = is_auth_supported(&dev_info, auth_xform);

		if (auth_xform->auth.algo == RTE_CRYPTO_AUTH_AES_CMAC &&
		    dev->disable_aes_cmac)
			auth_ok = 0;

		if (cipher_ok)
			cipher_supported = 1;
		if (auth_ok)
			auth_supported = 1;

		if (cipher_ok && auth_ok) {
			if (is_combo_buggy(&dev_info,
					   cipher_xform->cipher.algo,
					   auth_xform->auth.algo))
				continue;
			*device = dev;
			return ODP_CRYPTO_SES_ERR_NONE;
		}
	}
	if (cipher_supported && auth_supported)
		return ODP_CRYPTO_SES_ERR_ALG_COMBO;

	return !cipher_supported ? ODP_CRYPTO_SES_ERR_CIPHER
				 : ODP_CRYPTO_SES_ERR_AUTH;
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
	    !strcmp(dev_info.driver_name, "crypto_aesni_mb"))
		chained_bufs_ok = 0;

	if (dev_info.driver_name &&
	    !strcmp(dev_info.driver_name, "crypto_aesni_gcm") &&
	    param->auth_alg == ODP_AUTH_ALG_AES_GMAC)
		chained_bufs_ok = 0;

	if (dev_info.driver_name &&
	    !strcmp(dev_info.driver_name, "crypto_openssl") &&
	    (param->cipher_alg == ODP_CIPHER_ALG_AES_GCM ||
	     param->cipher_alg == ODP_CIPHER_ALG_AES_CCM ||
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
		_ODP_ERR("Requested too long digest\n");
		return -1;
	}

	auth_xform->auth.key.data = param->auth_key.data;
	auth_xform->auth.key.length = param->auth_key.length;
	auth_xform->auth.iv.offset = AUTH_IV_OFFSET;
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
		_ODP_ERR("Requested too long AAD\n");
		return -1;
	}

	if (aead_xform->aead.algo == RTE_CRYPTO_AEAD_AES_CCM &&
	    aead_xform->aead.aad_length + AES_CCM_AAD_OFFSET >
	    PACKET_AAD_MAX) {
		_ODP_ERR("Requested too long AAD for CCM\n");
		return -1;
	}

	aead_xform->aead.digest_length = param->auth_digest_len;
	if (aead_xform->aead.digest_length > PACKET_DIGEST_MAX) {
		_ODP_ERR("Requested too long digest\n");
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
	odp_crypto_ses_create_err_t rc = ODP_CRYPTO_SES_ERR_NONE;
	cryptodev_t *dev;
	uint8_t cdev_id = 0;
	uint8_t socket_id;
	struct rte_crypto_sym_xform cipher_xform;
	struct rte_crypto_sym_xform auth_xform;
	struct rte_crypto_sym_xform *first_xform;
	struct rte_cryptodev_sym_session *rte_session;
	struct rte_mempool *sess_mp;
	crypto_session_entry_t *session = NULL;

	if (!global || global->num_devs == 0) {
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	if (param->cipher_range_in_bits) {
		*status = ODP_CRYPTO_SES_ERR_CIPHER;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}
	if (param->auth_range_in_bits) {
		*status = ODP_CRYPTO_SES_ERR_AUTH;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}
	if (param->auth_alg == ODP_AUTH_ALG_AES_GMAC &&
	    param->cipher_alg != ODP_CIPHER_ALG_NULL) {
		*status = ODP_CRYPTO_SES_ERR_ALG_COMBO;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	if (param->op_type != ODP_CRYPTO_OP_TYPE_BASIC &&
	    param->op_type != ODP_CRYPTO_OP_TYPE_LEGACY) {
		*status = ODP_CRYPTO_SES_ERR_PARAMS;
		*session_out = ODP_CRYPTO_SESSION_INVALID;
		return -1;
	}

	/* Allocate memory for this session */
	session = alloc_session();
	if (session == NULL) {
		_ODP_ERR("Failed to allocate a session session");
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}

	/* Copy parameters */
	session->p = *param;

	if (cipher_is_aead(param->cipher_alg)) {
		session->flags.aead = 1;

		if (crypto_fill_aead_xform(&cipher_xform, &session->p) < 0) {
			*status = ODP_CRYPTO_SES_ERR_CIPHER;
			goto err;
		}

		first_xform = &cipher_xform;

		rc = get_crypto_aead_dev(&cipher_xform, &dev);
	} else {
		odp_bool_t do_cipher_first;

		session->flags.aead = 0;

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

		rc = get_crypto_dev(&cipher_xform, &auth_xform, &dev);
	}
	if (rc != ODP_CRYPTO_SES_ERR_NONE) {
		_ODP_DBG("Couldn't find a crypto device (error %d)", rc);
		*status = rc;
		goto err;
	}

	cdev_id = dev->dev_id;
	socket_id = rte_cryptodev_socket_id(dev->dev_id);
	sess_mp = global->session_mempool[socket_id];

	/* Setup session */
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 0)
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
#else
	rte_session = rte_cryptodev_sym_session_create(cdev_id, first_xform, sess_mp);
	if (rte_session == NULL) {
		*status = ODP_CRYPTO_SES_ERR_ENOMEM;
		goto err;
	}
#endif

	session->flags.chained_bufs_ok = chained_bufs_ok(param, cdev_id);
	session->flags.cdev_qpairs_shared = dev->qpairs_shared;
	session->dev = dev;

out_null:
	session->rte_session  = rte_session;
	session->cdev_id = cdev_id;

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
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 0)
		if (rte_cryptodev_sym_session_clear(session->cdev_id,
						    rte_session) < 0)
			return -1;

		if (rte_cryptodev_sym_session_free(rte_session) < 0)
			return -1;
#else
		if (rte_cryptodev_sym_session_free(session->cdev_id, rte_session) < 0)
			return -1;
#endif
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
	uint32_t count = 0;
	crypto_session_entry_t *session;

	if (global == NULL)
		return 0;

	for (session = global->free; session != NULL; session = session->next)
		count++;
	if (count != global->config.max_sessions) {
		_ODP_ERR("crypto sessions still active\n");
		rc = -1;
	}

	for (uint8_t dev = 0; dev < global->num_devs; dev++) {
		rte_cryptodev_stop(global->devs[dev].dev_id);
		rte_cryptodev_close(global->devs[dev].dev_id);
	}
	global->num_devs = 0;

	if (global->crypto_op_pool != NULL) {
		rte_mempool_free(global->crypto_op_pool);
		global->crypto_op_pool = NULL;
	}

	for (int socket_id = 0; socket_id < RTE_MAX_NUMA_NODES; socket_id++)
		if (global->session_mempool[socket_id] != NULL) {
			rte_mempool_free(global->session_mempool[socket_id]);
			global->session_mempool[socket_id] = NULL;
		}

	ret = odp_shm_free(global->shm);
	if (ret < 0) {
		_ODP_ERR("shm free failed for crypto_pool\n");
		rc = -1;
	}

	return rc;
}

void odp_crypto_session_param_init(odp_crypto_session_param_t *param)
{
	memset(param, 0, sizeof(odp_crypto_session_param_t));
}

uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl)
{
	return (uint64_t)hdl;
}

static uint8_t *crypto_prepare_digest(const crypto_session_entry_t *session,
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
	mb = &pkt_hdr->mb;
	*phys_addr = rte_pktmbuf_iova_offset(mb, data - rte_pktmbuf_mtod(mb, uint8_t *));

	return data;
}

static void crypto_fill_aead_param(const crypto_session_entry_t *session,
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
		rte_pktmbuf_iova_offset(&pkt_hdr->mb,
					op->sym->aead.aad.data -
					rte_pktmbuf_mtod(&pkt_hdr->mb, uint8_t *));
	iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
	if (session->p.cipher_alg == ODP_CIPHER_ALG_AES_CCM) {
		*iv_ptr = iv_len;
		iv_ptr++;
	}

	_ODP_ASSERT(iv_len == 0 || param->cipher_iv_ptr != NULL);
	memcpy(iv_ptr, param->cipher_iv_ptr, iv_len);

	op->sym->aead.data.offset = param->cipher_range.offset;
	op->sym->aead.data.length = param->cipher_range.length;
}

static void crypto_fill_sym_param(const crypto_session_entry_t *session,
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

	_ODP_ASSERT(cipher_iv_len == 0 || param->cipher_iv_ptr != NULL);
	_ODP_ASSERT(auth_iv_len == 0 || param->auth_iv_ptr != NULL);

	if (cipher_iv_len > 0) {
		iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET);
		memcpy(iv_ptr, param->cipher_iv_ptr, cipher_iv_len);
	}
	if (odp_unlikely(auth_iv_len > 0)) {
		iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t *, IV_OFFSET + MAX_IV_LENGTH);
		memcpy(iv_ptr, param->auth_iv_ptr, auth_iv_len);
	}

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
	_ODP_ASSERT(rc == 0);

	return odp_packet_num_segs(pkt) != 1;
}

static int copy_data_and_metadata(odp_packet_t dst, odp_packet_t src)
{
	int md_copy;
	int rc;

	md_copy = _odp_packet_copy_md_possible(odp_packet_pool(dst),
					       odp_packet_pool(src));
	if (odp_unlikely(md_copy < 0)) {
		_ODP_ERR("Unable to copy packet metadata\n");
		return -1;
	}

	rc = odp_packet_copy_from_pkt(dst, 0, src, 0, odp_packet_len(src));
	if (odp_unlikely(rc < 0)) {
		_ODP_ERR("Unable to copy packet data\n");
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

		_ODP_ASSERT(pool != ODP_POOL_INVALID);
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

/*
 * Return number of ops allocated and packets consumed.
 */
static int op_alloc(crypto_op_t *op[],
		    const odp_packet_t pkt_in[],
		    odp_packet_t pkt_out[],
		    const odp_crypto_packet_op_param_t param[],
		    int num_pkts)
{
	crypto_session_entry_t *session;
	int n;

	if (odp_unlikely(rte_crypto_op_bulk_alloc(global->crypto_op_pool,
						  RTE_CRYPTO_OP_TYPE_SYMMETRIC,
						  (struct rte_crypto_op **)op,
						  num_pkts) == 0)) {
		/* This should not happen since we made op pool big enough */
		_ODP_DBG("falling back to single crypto op alloc\n");
		op[0] = (crypto_op_t *)rte_crypto_op_alloc(global->crypto_op_pool,
							   RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (odp_unlikely(op[0] == NULL)) {
			_ODP_ERR("Failed to allocate crypto operation\n");
			return 0;
		}
		num_pkts = 1;
	}

	for (n = 0; n < num_pkts; n++) {
		odp_packet_t pkt;

		session = (crypto_session_entry_t *)(intptr_t)param[n].session;
		_ODP_ASSERT(session != NULL);

		if (odp_likely(session->p.op_type == ODP_CRYPTO_OP_TYPE_BASIC)) {
			pkt = pkt_in[n];
		} else {
			pkt = get_output_packet(session, pkt_in[n], pkt_out[n]);
			if (odp_unlikely(pkt == ODP_PACKET_INVALID)) {
				for (int i = n; i < num_pkts; i++)
					rte_crypto_op_free((struct rte_crypto_op *)op[i]);
				break;
			}
		}
		op[n]->state.pkt = pkt;
	}
	return n;
}

static int is_op_supported(const crypto_session_entry_t *session,
			   const odp_crypto_packet_op_param_t *param)
{
	const uint32_t c_start = param->cipher_range.offset;
	const uint32_t c_end = param->cipher_range.offset + param->cipher_range.length;

	if (odp_likely(c_end <= param->hash_result_offset))
		return 1;
	if (odp_likely(c_start >= param->hash_result_offset + session->p.auth_digest_len))
		return 1;
	if (session->p.cipher_alg == ODP_CIPHER_ALG_NULL)
		return 1;
	if (odp_unlikely(session->p.auth_alg == ODP_AUTH_ALG_NULL))
		return 1;

	return 0;
}

static void op_prepare(crypto_op_t *ops[],
		       const odp_crypto_packet_op_param_t param[],
		       int num_op)
{
	for (int n = 0; n < num_op; n++) {
		struct crypto_op_t *op = ops[n];
		struct rte_crypto_op *rte_op = (struct rte_crypto_op *)op;
		crypto_session_entry_t *session;
		struct rte_cryptodev_sym_session *rte_session;

		session = (crypto_session_entry_t *)(intptr_t)param[n].session;
		rte_session = session->rte_session;

		op->state.status = S_OK;
		op->state.session = session;
		op->state.hash_result_offset = param[n].hash_result_offset;

		/* NULL rte_session means that it is a NULL-NULL operation. */
		if (odp_unlikely(rte_session == NULL)) {
			op->state.status = S_NOP;
			continue;
		}
		if (odp_unlikely(session->p.null_crypto_enable && param->null_crypto)) {
			op->state.status = S_NOP;
			continue;
		}

		if (odp_unlikely(linearize_pkt(session, op->state.pkt))) {
			op->state.status = S_ERROR_LIN;
			continue;
		}

		if (session->flags.aead) {
			crypto_fill_aead_param(session, op->state.pkt, &param[n], rte_op);
		} else {
			if (odp_unlikely(!is_op_supported(session, &param[n]))) {
				op->state.status = S_ERROR_HASH_OFFSET;
				continue;
			}
			crypto_fill_sym_param(session, op->state.pkt, &param[n], rte_op);
		}

		rte_crypto_op_attach_sym_session(rte_op, rte_session);
		rte_op->sym->m_src = pkt_to_mbuf(op->state.pkt);
	}
}

static void dev_enq_deq(uint8_t cdev_id, int thread_id, crypto_op_t *op[], int num_op)
{
	int retry_count = 0;
	int rc;
	int queue_pairs_shared;
	int queue_pair;
	struct rte_crypto_op *deq_op[MAX_BURST];

	queue_pairs_shared = op[0]->state.session->flags.cdev_qpairs_shared;
	if (odp_unlikely(queue_pairs_shared))
		queue_pair = thread_id % op[0]->state.session->dev->num_qpairs;
	else
		queue_pair = thread_id;

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

	rc = rte_cryptodev_enqueue_burst(cdev_id, queue_pair,
					 (struct rte_crypto_op **)op, num_op);
	if (odp_unlikely(rc < num_op)) {
		if (odp_unlikely(queue_pairs_shared))
			odp_spinlock_unlock(&global->lock);
		/*
		 * This should not happen since we allocated enough
		 * descriptors for our max burst and there are no other ops
		 * in flight using this queue pair.
		 */
		for (int n = rc; n < num_op; n++)
			op[n]->state.status = S_ERROR;
		_ODP_ERR("Failed to enqueue crypto operations\n");
		num_op = rc;
		if (num_op == 0)
			return;
	}

	/* There may be a delay until the crypto operation is completed. */
	int num_dequeued = 0;

	while (1) {
		int num_left = num_op - num_dequeued;

		rc = rte_cryptodev_dequeue_burst(cdev_id, queue_pair,
						 &deq_op[num_dequeued],
						 num_left);
		num_dequeued += rc;
		if (odp_likely(rc == num_left))
			break;
		if (odp_unlikely(rc == 0)) {
			odp_time_wait_ns(DEQ_RETRY_DELAY_NS);
			if (++retry_count == MAX_DEQ_RETRIES) {
				_ODP_ERR("Failed to dequeue crypto operations\n");
				/*
				 * We cannot give up and return to the caller
				 * since some packets and crypto operations
				 * are still owned by the cryptodev.
				 */
			}
		}
	};

	if (odp_unlikely(queue_pairs_shared))
		odp_spinlock_unlock(&global->lock);

	for (int n = 0; n < num_dequeued; n++) {
		_ODP_ASSERT((crypto_op_t *)deq_op[n] == op[n]);
		_ODP_ASSERT((odp_packet_t)deq_op[n]->sym->m_src == op[n]->state.pkt);
	}
}

static void op_enq_deq(crypto_op_t *op[], int num_op)
{
	crypto_op_t *burst[MAX_BURST];
	int burst_size = 0;
	int idx = 0;
	uint8_t cdev_id;
	int tid = odp_thread_id();
	int done = 0;

	while (done < num_op) {
		if (op[idx]->state.status != S_OK) {
			idx++;
			done++;
			continue;
		}
		burst[0] = op[idx];
		burst_size = 1;
		cdev_id = op[idx]->state.session->cdev_id;
		op[idx]->state.status = S_DEV;
		idx++;

		/*
		 * Build a burst of ops that are for the same device
		 * and have not failed already and are not no-ops.
		 */
		for (int n = idx; n < num_op; n++) {
			if (odp_likely(op[n]->state.session->cdev_id == cdev_id) &&
			    odp_likely(op[n]->state.status == S_OK)) {
				burst[burst_size++] = op[n];
				op[n]->state.status = S_DEV;
			}
		}
		/*
		 * Process burst.
		 */
		dev_enq_deq(cdev_id, tid, burst, burst_size);
		done += burst_size;
	}
}

static void op_finish(crypto_op_t *op)
{
	crypto_session_entry_t *session = op->state.session;
	odp_packet_t pkt = op->state.pkt;
	struct rte_crypto_op *rte_op = (struct rte_crypto_op *)op;
	odp_crypto_alg_err_t rc_cipher;
	odp_crypto_alg_err_t rc_auth;
	odp_crypto_packet_result_t *op_result;

	if (odp_likely(op->state.status == S_DEV)) {
		/* cryptodev processed packet */
		if (odp_likely(rte_op->status == RTE_CRYPTO_OP_STATUS_SUCCESS)) {
			rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
			rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
			if (session->p.op == ODP_CRYPTO_OP_ENCODE &&
			    session->p.auth_digest_len != 0) {
				odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

				odp_packet_copy_from_mem(pkt,
							 op->state.hash_result_offset,
							 session->p.auth_digest_len,
							 pkt_hdr->crypto_digest_buf);
			}
		} else if (rte_op->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED) {
			rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
			rc_auth = ODP_CRYPTO_ALG_ERR_ICV_CHECK;
		} else {
			rc_cipher = ODP_CRYPTO_ALG_ERR_OTHER;
			rc_auth = ODP_CRYPTO_ALG_ERR_OTHER;
		}
	} else if (odp_unlikely(op->state.status == S_NOP)) {
		/* null cipher & null auth, cryptodev skipped */
		rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
		rc_auth = ODP_CRYPTO_ALG_ERR_NONE;
	} else if (op->state.status == S_ERROR_LIN) {
		/* packet linearization error before cryptodev enqueue */
		rc_cipher = ODP_CRYPTO_ALG_ERR_DATA_SIZE;
		rc_auth = ODP_CRYPTO_ALG_ERR_DATA_SIZE;
	} else if (op->state.status == S_ERROR_HASH_OFFSET) {
		/* hash offset not supported */
		rc_cipher = ODP_CRYPTO_ALG_ERR_NONE;
		rc_auth = ODP_CRYPTO_ALG_ERR_DATA_SIZE;
	} else {
		/*
		 * other error before cryptodev enqueue
		 */
		rc_cipher = ODP_CRYPTO_ALG_ERR_OTHER;
		rc_auth = ODP_CRYPTO_ALG_ERR_OTHER;
	}

	/* Fill in result */
	packet_subtype_set(pkt, ODP_EVENT_PACKET_CRYPTO);
	op_result = &packet_hdr(pkt)->crypto_op_result;
	op_result->cipher_status.alg_err = rc_cipher;
	op_result->auth_status.alg_err = rc_auth;
}

static
int odp_crypto_int(const odp_packet_t pkt_in[],
		   odp_packet_t pkt_out[],
		   const odp_crypto_packet_op_param_t param[],
		   int num_pkt)
{
	crypto_op_t *op[MAX_BURST];

	num_pkt = op_alloc(op, pkt_in, pkt_out, param, num_pkt);
	if (odp_unlikely(num_pkt == 0))
		return 0;

	op_prepare(op, param, num_pkt);

	op_enq_deq(op, num_pkt);

	for (int n = 0; n < num_pkt; n++) {
		op_finish(op[n]);
		pkt_out[n] = op[n]->state.pkt;
		rte_crypto_op_free((struct rte_crypto_op *)op[n]);
	}
	return num_pkt;
}

int odp_crypto_op(const odp_packet_t pkt_in[],
		  odp_packet_t pkt_out[],
		  const odp_crypto_packet_op_param_t param[],
		  int num_pkt)
{
	crypto_session_entry_t *session;
	int i;

	if (num_pkt > MAX_BURST)
		num_pkt = MAX_BURST;

	for (i = 0; i < num_pkt; i++) {
		session = (crypto_session_entry_t *)(intptr_t)param[i].session;
		_ODP_ASSERT(ODP_CRYPTO_SYNC == session->p.op_mode);
	}
	return odp_crypto_int(pkt_in, pkt_out, param, num_pkt);
}

int odp_crypto_op_enq(const odp_packet_t pkt_in[],
		      const odp_packet_t pkt_out[],
		      const odp_crypto_packet_op_param_t param[],
		      int num_pkt)
{
	odp_event_t event;
	crypto_session_entry_t *session;
	int i;
	odp_packet_t out_pkts[MAX_BURST];

	if (num_pkt > MAX_BURST)
		num_pkt = MAX_BURST;

	for (i = 0; i < num_pkt; i++) {
		session = (crypto_session_entry_t *)(intptr_t)param[i].session;
		_ODP_ASSERT(ODP_CRYPTO_ASYNC == session->p.op_mode);
		_ODP_ASSERT(ODP_QUEUE_INVALID != session->p.compl_queue);

		if (session->p.op_type != ODP_CRYPTO_OP_TYPE_BASIC)
			out_pkts[i] = pkt_out[i];
	}

	num_pkt = odp_crypto_int(pkt_in, out_pkts, param, num_pkt);

	for (i = 0; i < num_pkt; i++) {
		session = (crypto_session_entry_t *)(intptr_t)param[i].session;
		event = odp_packet_to_event(out_pkts[i]);
		if (odp_queue_enq(session->p.compl_queue, event)) {
			odp_event_free(event);
			break;
		}
	}

	return i;
}
