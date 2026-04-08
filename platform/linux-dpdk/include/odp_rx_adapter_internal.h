/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#ifndef ODP_RX_ADAPTER_INTERNAL_H_
#define ODP_RX_ADAPTER_INTERNAL_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int _odp_rx_adapter_initialized(void);

void _odp_rx_adapter_port_stop(uint16_t port_id);

int _odp_rx_adapter_close(void);

#ifdef __cplusplus
}
#endif

#endif
