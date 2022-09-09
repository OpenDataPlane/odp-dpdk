/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/buffer.h>

#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <odp_pool_internal.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

uint32_t odp_buffer_size(odp_buffer_t buf)
{
	struct rte_mbuf *mbuf = _odp_buf_to_mbuf(buf);

	return mbuf->buf_len;
}

int _odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = _odp_buf_hdr(buf);

	return hdr->event_hdr.type;
}

void _odp_buffer_type_set(odp_buffer_t buf, int type)
{
	odp_buffer_hdr_t *hdr = _odp_buf_hdr(buf);

	hdr->event_hdr.type = type;
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	if (odp_event_is_valid(odp_buffer_to_event(buf)) == 0)
		return 0;

	if (odp_event_type(odp_buffer_to_event(buf)) != ODP_EVENT_BUFFER)
		return 0;

	return 1;
}

void odp_buffer_print(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	pool_t *pool;
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (!odp_buffer_is_valid(buf)) {
		ODP_ERR("Buffer is not valid.\n");
		return;
	}

	hdr = _odp_buf_hdr(buf);
	pool = _odp_pool_entry(hdr->event_hdr.pool);

	len += snprintf(&str[len], n - len, "Buffer\n------\n");
	len += snprintf(&str[len], n - len, "  pool index    %u\n", pool->pool_idx);
	len += snprintf(&str[len], n - len, "  buffer index  %u\n", hdr->event_hdr.index);
	len += snprintf(&str[len], n - len, "  addr          %p\n", odp_buffer_addr(buf));
	len += snprintf(&str[len], n - len, "  size          %u\n", odp_buffer_size(buf));
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}

uint64_t odp_buffer_to_u64(odp_buffer_t hdl)
{
	return _odp_pri(hdl);
}
