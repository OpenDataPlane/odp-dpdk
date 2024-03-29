/* Copyright (c) 2021, Marvell
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ipsec.h"

/* The source file includes below test vectors */

/* IPv6:
 *
 *	1) pkt_ipv6_udp_p1
 *		pkt_ipv6_udp_p1_f1
 *		pkt_ipv6_udp_p1_f2
 *
 *	2) pkt_ipv6_udp_p2
 *		pkt_ipv6_udp_p2_f1
 *		pkt_ipv6_udp_p2_f2
 *		pkt_ipv6_udp_p2_f3
 *		pkt_ipv6_udp_p2_f4
 */

/* IPv4:
 *
 *	1) pkt_ipv4_udp_p1
 *		pkt_ipv4_udp_p1_f1
 *		pkt_ipv4_udp_p1_f2
 *
 *	2) pkt_ipv4_udp_p2
 *		pkt_ipv4_udp_p2_f1
 *		pkt_ipv4_udp_p2_f2
 *		pkt_ipv4_udp_p2_f3
 *		pkt_ipv4_udp_p2_f4
 */

ipsec_test_packet pkt_ipv6_udp_p1 = {
	.len = 1514,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 54,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0xb4, 0x11, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xb4, 0x2b, 0xe8,
	},
};

ipsec_test_packet pkt_ipv6_udp_p1_f1 = {
	.len = 1398,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 62,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x00, 0x01, 0x5c, 0x92, 0xac, 0xf1,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xb4, 0x2b, 0xe8,
	},
};

ipsec_test_packet pkt_ipv6_udp_p1_f2 = {
	.len = 186,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 62,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x00, 0x84, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x05, 0x38, 0x5c, 0x92, 0xac, 0xf1,
	},
};

ipsec_test_packet pkt_ipv6_udp_p2 = {
	.len = 4496,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 54,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x11, 0x5a, 0x11, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x5a, 0x8a, 0x11,
	},
};

ipsec_test_packet pkt_ipv6_udp_p2_f1 = {
	.len = 1398,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 62,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x00, 0x01, 0x64, 0x6c, 0x68, 0x9f,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x5a, 0x8a, 0x11,
	},
};

ipsec_test_packet pkt_ipv6_udp_p2_f2 = {
	.len = 1398,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 62,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x05, 0x39, 0x64, 0x6c, 0x68, 0x9f,
	},
};

ipsec_test_packet pkt_ipv6_udp_p2_f3 = {
	.len = 1398,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 62,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x05, 0x40, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x0a, 0x71, 0x64, 0x6c, 0x68, 0x9f,
	},
};

ipsec_test_packet pkt_ipv6_udp_p2_f4 = {
	.len = 496,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 62,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x86, 0xdd,

		/* IP */
		0x60, 0x00, 0x00, 0x00, 0x01, 0xba, 0x2c, 0x40,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x0d, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x00, 0x02,
		0x11, 0x00, 0x0f, 0xa8, 0x64, 0x6c, 0x68, 0x9f,
	},
};

ipsec_test_packet pkt_ipv4_udp_p1 = {
	.len = 1514,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x05, 0xdc, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x66, 0x0d, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xc8, 0xb8, 0x4c,
	},
};

ipsec_test_packet pkt_ipv4_udp_p1_f1 = {
	.len = 1434,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x01, 0x20, 0x00,
		0x40, 0x11, 0x46, 0x5d, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x05, 0xc8, 0xb8, 0x4c,
	},
};

ipsec_test_packet pkt_ipv4_udp_p1_f2 = {
	.len = 114,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x00, 0x64, 0x00, 0x01, 0x00, 0xaf,
		0x40, 0x11, 0x6a, 0xd6, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

ipsec_test_packet pkt_ipv4_udp_p2 = {
	.len = 4496,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x11, 0x82, 0x00, 0x02, 0x00, 0x00,
		0x40, 0x11, 0x5a, 0x66, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x6e, 0x16, 0x76,
	},
};

ipsec_test_packet pkt_ipv4_udp_p2_f1 = {
	.len = 1434,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x02, 0x20, 0x00,
		0x40, 0x11, 0x46, 0x5c, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,

		/* UDP */
		0x08, 0x00, 0x27, 0x10, 0x11, 0x6e, 0x16, 0x76,
	},
};

ipsec_test_packet pkt_ipv4_udp_p2_f2 = {
	.len = 1434,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x02, 0x20, 0xaf,
		0x40, 0x11, 0x45, 0xad, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

ipsec_test_packet pkt_ipv4_udp_p2_f3 = {
	.len = 1434,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x05, 0x8c, 0x00, 0x02, 0x21, 0x5e,
		0x40, 0x11, 0x44, 0xfe, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};

ipsec_test_packet pkt_ipv4_udp_p2_f4 = {
	.len = 296,
	.l2_offset = 0,
	.l3_offset = 14,
	.l4_offset = 34,
	.data = {
		/* ETH */
		0xf1, 0xf1, 0xf1, 0xf1, 0xf1, 0xf1,
		0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0x08, 0x00,

		/* IP */
		0x45, 0x00, 0x01, 0x1a, 0x00, 0x02, 0x02, 0x0d,
		0x40, 0x11, 0x68, 0xc1, 0x0d, 0x00, 0x00, 0x02,
		0x02, 0x00, 0x00, 0x02,
	},
};
