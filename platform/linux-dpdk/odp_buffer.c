/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <odp_pool_internal.h>
#include <odp/api/plat/buffer_inline_types.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <odp/visibility_begin.h>

/* Fill in buffer header field offsets for inline functions */
const _odp_buffer_inline_offset_t _odp_buffer_inline_offset ODP_ALIGNED_CACHE = {
	.event_type = offsetof(odp_buffer_hdr_t, event_type),
	.base_data  = offsetof(odp_buffer_hdr_t, mb.buf_addr)
};

#include <odp/visibility_end.h>

uint32_t odp_buffer_size(odp_buffer_t buf)
{
	struct rte_mbuf *mbuf = buf_to_mbuf(buf);

	return mbuf->buf_len;
}

int _odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);

	return hdr->type;
}

void _odp_buffer_type_set(odp_buffer_t buf, int type)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);

	hdr->type = type;
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	if (_odp_buffer_is_valid(buf) == 0)
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

	hdr = buf_hdl_to_hdr(buf);
	pool = hdr->pool_ptr;

	len += snprintf(&str[len], n - len, "Buffer\n------\n");
	len += snprintf(&str[len], n - len, "  pool index    %u\n", pool->pool_idx);
	len += snprintf(&str[len], n - len, "  buffer index  %u\n", hdr->index);
	len += snprintf(&str[len], n - len, "  addr          %p\n", odp_buffer_addr(buf));
	len += snprintf(&str[len], n - len, "  size          %u\n", odp_buffer_size(buf));
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}

uint64_t odp_buffer_to_u64(odp_buffer_t hdl)
{
	return _odp_pri(hdl);
}
