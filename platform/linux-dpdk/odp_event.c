/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/event.h>
#include <odp/api/buffer.h>
#include <odp/api/crypto.h>
#include <odp/api/dma.h>
#include <odp/api/packet.h>
#include <odp/api/timer.h>
#include <odp/api/pool.h>

#include <odp_buffer_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp_event_internal.h>
#include <odp_event_validation_internal.h>
#include <odp_event_vector_internal.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_vector_inlines.h>
#include <odp/api/plat/timer_inlines.h>

#include <odp/api/plat/event_inline_types.h>

#include <odp/visibility_begin.h>

/* Fill in event header field offsets for inline functions */
const _odp_event_inline_offset_t
_odp_event_inline_offset ODP_ALIGNED_CACHE = {
	.event_type = offsetof(_odp_event_hdr_t, hdr.event_type),
	.base_data  = offsetof(_odp_event_hdr_t, mb.buf_addr),
	.flow_id    = offsetof(_odp_event_hdr_t, hdr.flow_id),
	.pool       = offsetof(_odp_event_hdr_t, hdr.pool),
	.buf_len    = offsetof(_odp_event_hdr_t, mb.buf_len)
};

#include <odp/visibility_end.h>

static inline void event_free(odp_event_t event, _odp_ev_id_t id)
{
	switch (odp_event_type(event)) {
	case ODP_EVENT_BUFFER:
		_odp_buffer_validate(odp_buffer_from_event(event), id);
		odp_buffer_free(odp_buffer_from_event(event));
		break;
	case ODP_EVENT_PACKET:
		_odp_packet_validate(odp_packet_from_event(event), id);
		odp_packet_free(odp_packet_from_event(event));
		break;
	case ODP_EVENT_PACKET_VECTOR:
		_odp_packet_vector_free_full(odp_packet_vector_from_event(event));
		break;
	case ODP_EVENT_TIMEOUT:
		odp_timeout_free(odp_timeout_from_event(event));
		break;
	case ODP_EVENT_IPSEC_STATUS:
		_odp_ipsec_status_free(_odp_ipsec_status_from_event(event));
		break;
	case ODP_EVENT_PACKET_TX_COMPL:
		odp_packet_tx_compl_free(odp_packet_tx_compl_from_event(event));
		break;
	case ODP_EVENT_DMA_COMPL:
		odp_dma_compl_free(odp_dma_compl_from_event(event));
		break;
	default:
		_ODP_ABORT("Invalid event type: %d\n", odp_event_type(event));
	}
}

void odp_event_free(odp_event_t event)
{
	event_free(event, _ODP_EV_EVENT_FREE);
}

void odp_event_free_multi(const odp_event_t event[], int num)
{
	for (int i = 0; i < num; i++)
		event_free(event[i], _ODP_EV_EVENT_FREE_MULTI);
}

void odp_event_free_sp(const odp_event_t event[], int num)
{
	for (int i = 0; i < num; i++)
		event_free(event[i], _ODP_EV_EVENT_FREE_SP);
}

uint64_t odp_event_to_u64(odp_event_t hdl)
{
	return _odp_pri(hdl);
}

int odp_event_is_valid(odp_event_t event)
{
	if (event == ODP_EVENT_INVALID)
		return 0;

	if (_odp_event_is_valid(event) == 0)
		return 0;

	switch (odp_event_type(event)) {
	case ODP_EVENT_BUFFER:
		return !_odp_buffer_validate(odp_buffer_from_event(event), _ODP_EV_EVENT_IS_VALID);
	case ODP_EVENT_PACKET:
		return !_odp_packet_validate(odp_packet_from_event(event), _ODP_EV_EVENT_IS_VALID);
	case ODP_EVENT_TIMEOUT:
		/* Fall through */
	case ODP_EVENT_IPSEC_STATUS:
		/* Fall through */
	case ODP_EVENT_PACKET_VECTOR:
		/* Fall through */
	case ODP_EVENT_DMA_COMPL:
		/* Fall through */
	case ODP_EVENT_PACKET_TX_COMPL:
		break;
	default:
		return 0;
	}

	return 1;
}
