/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef TEST_PACKET_IPV4_H_
#define TEST_PACKET_IPV4_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Test packets without CRC */

/* ARP request */
static const uint8_t test_packet_arp[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x08, 0x06, 0x00, 0x01,
	0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0xC0, 0xA8, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8,
	0x01, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11
};

/* ICMPv4 echo reply */
static const uint8_t test_packet_ipv4_icmp[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01,
	0xF3, 0x7B, 0xC0, 0xA8, 0x01, 0x01, 0xC4, 0xA8,
	0x01, 0x02, 0x00, 0x00, 0xB7, 0xAB, 0x00, 0x01,
	0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11
};

/* IPv4 TCP */
static const uint8_t test_packet_ipv4_tcp[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
	0xF3, 0x76, 0xC0, 0xA8, 0x01, 0x02, 0xC4, 0xA8,
	0x01, 0x01, 0x04, 0xD2, 0x10, 0xE1, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x02,
	0x00, 0x00, 0x0C, 0xCA, 0x00, 0x00, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05
};

/* IPv4 UDP */
static const uint8_t test_packet_ipv4_udp[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
	0xF3, 0x6B, 0xC0, 0xA8, 0x01, 0x02, 0xC4, 0xA8,
	0x01, 0x01, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x1A,
	0x2F, 0x97, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11
};

/* ETH SNAP IPv4 UDP */
static const uint8_t test_packet_snap_ipv4_udp[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x00, 0x36, 0xAA, 0xAA,
	0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
	0xF7, 0x6B, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8,
	0x01, 0x01, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x1A,
	0x33, 0x97, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11
};

/* VLAN IPv4 UDP
 * - type 0x8100, tag 23
 */
static const uint8_t test_packet_vlan_ipv4_udp[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x81, 0x00, 0x00, 0x17,
	0x08, 0x00, 0x45, 0x00, 0x00, 0x2A, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x11, 0xF3, 0x6F, 0xC0, 0xA8,
	0x01, 0x02, 0xC4, 0xA8, 0x01, 0x01, 0x00, 0x3F,
	0x00, 0x3F, 0x00, 0x16, 0x4D, 0xBF, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0A, 0x0B, 0x0C, 0x0D
};

/* VLAN Q-in-Q IPv4 UDP
 * - Outer: type 0x88a8, tag 1
 * - Inner: type 0x8100, tag 2
 */
static const uint8_t test_packet_vlan_qinq_ipv4_udp[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x88, 0xA8, 0x00, 0x01,
	0x81, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
	0xF3, 0x73, 0xC0, 0xA8, 0x01, 0x02, 0xC4, 0xA8,
	0x01, 0x01, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x12,
	0x63, 0xDF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09
};

/* IPv4 SCTP
 * - chunk type: payload data
 */
static const uint8_t test_packet_ipv4_sctp[] = {
	0x00, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x77, 0x00, 0x01, 0x00, 0x00, 0x40, 0x84,
	0xF8, 0xAE, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8,
	0x00, 0x02, 0x04, 0xD2, 0x16, 0x2E, 0xDE, 0xAD,
	0xBE, 0xEF, 0x31, 0x44, 0xE3, 0xFE, 0x00, 0x00,
	0x00, 0x57, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x6D, 0x79,
	0x20, 0x64, 0x75, 0x6D, 0x6D, 0x79, 0x20, 0x70,
	0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64, 0x20, 0x73,
	0x74, 0x72, 0x69, 0x6E, 0x67, 0x2E, 0x20, 0x54,
	0x68, 0x65, 0x20, 0x6C, 0x65, 0x6E, 0x67, 0x74,
	0x68, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x69,
	0x73, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
	0x20, 0x69, 0x73, 0x20, 0x37, 0x31, 0x20, 0x62,
	0x79, 0x74, 0x65, 0x73, 0x2E
};

static const uint8_t test_packet_mcast_eth_ipv4_udp[] = {
	0x03, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x02, 0x00,
	0x00, 0x03, 0x04, 0x05, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x63, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0xC8, 0xDB, 0xC0, 0xA8, 0x00, 0x01, 0xEF, 0x01,
	0x02, 0x03, 0x04, 0xD2, 0x16, 0x2E, 0x00, 0x4F,
	0x25, 0x61, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
	0x73, 0x20, 0x6D, 0x79, 0x20, 0x64, 0x75, 0x6D,
	0x6D, 0x79, 0x20, 0x70, 0x61, 0x79, 0x6C, 0x6F,
	0x61, 0x64, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E,
	0x67, 0x2E, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6C,
	0x65, 0x6E, 0x67, 0x74, 0x68, 0x20, 0x6F, 0x66,
	0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74,
	0x72, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x73, 0x20,
	0x37, 0x31, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73,
	0x2E
};

static const uint8_t test_packet_bcast_eth_ipv4_udp[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x00,
	0x00, 0x03, 0x04, 0x05, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x63, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0xB9, 0xE0, 0xC0, 0xA8, 0x00, 0x01, 0xFF, 0xFF,
	0xFF, 0xFF, 0x04, 0xD2, 0x16, 0x2E, 0x00, 0x4F,
	0x16, 0x66, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
	0x73, 0x20, 0x6D, 0x79, 0x20, 0x64, 0x75, 0x6D,
	0x6D, 0x79, 0x20, 0x70, 0x61, 0x79, 0x6C, 0x6F,
	0x61, 0x64, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E,
	0x67, 0x2E, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6C,
	0x65, 0x6E, 0x67, 0x74, 0x68, 0x20, 0x6F, 0x66,
	0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74,
	0x72, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x73, 0x20,
	0x37, 0x31, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73,
	0x2E
};

static const uint8_t test_packet_ipv4_udp_first_frag[] = {
	0x02, 0x00, 0x00, 0x04, 0x05, 0x06, 0x02, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x63, 0x00, 0x01, 0x20, 0x00, 0x40, 0x11,
	0xD9, 0x35, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8,
	0x00, 0x02, 0x04, 0xD2, 0x16, 0x2E, 0x01, 0x17,
	0x54, 0xF3, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
	0x73, 0x20, 0x6D, 0x79, 0x20, 0x64, 0x75, 0x6D,
	0x6D, 0x79, 0x20, 0x70, 0x61, 0x79, 0x6C, 0x6F,
	0x61, 0x64, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E,
	0x67, 0x2E, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6C,
	0x65, 0x6E, 0x67, 0x74, 0x68, 0x20, 0x6F, 0x66,
	0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74,
	0x72, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x73, 0x20,
	0x37, 0x31, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73,
	0x2E
};

static const uint8_t test_packet_ipv4_udp_last_frag[] = {
	0x02, 0x00, 0x00, 0x04, 0x05, 0x06, 0x02, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x5B, 0x00, 0x01, 0x00, 0x0A, 0x40, 0x11,
	0xF9, 0x33, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8,
	0x00, 0x02, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
	0x73, 0x20, 0x6D, 0x79, 0x20, 0x64, 0x75, 0x6D,
	0x6D, 0x79, 0x20, 0x70, 0x61, 0x79, 0x6C, 0x6F,
	0x61, 0x64, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E,
	0x67, 0x2E, 0x20, 0x54, 0x68, 0x65, 0x20, 0x6C,
	0x65, 0x6E, 0x67, 0x74, 0x68, 0x20, 0x6F, 0x66,
	0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74,
	0x72, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x73, 0x20,
	0x37, 0x31, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73,
	0x2E
};

/* IPv4 / Record Route + NOP options / ICMP */
static const uint8_t test_packet_ipv4_rr_nop_icmp[] = {
	0x02, 0x00, 0x00, 0x04, 0x05, 0x06, 0x02, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x08, 0x00, 0x49, 0x00,
	0x00, 0x2C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01,
	0x8E, 0xE2, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8,
	0x00, 0x02, 0x07, 0x0F, 0x0C, 0xC0, 0xA8, 0x04,
	0x01, 0xC0, 0xA8, 0x05, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x08, 0x00, 0xF7, 0xFF, 0x00, 0x00,
	0x00, 0x00
};

/* Ethernet/IPv4/UDP packet. Ethernet frame length 325 bytes (+ CRC).
 * - source IP addr:      192.168.1.2
 * - destination IP addr: 192.168.1.1
 */
static const uint8_t test_packet_ipv4_udp_325[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x01, 0x37, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
	0xF6, 0x62, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8,
	0x01, 0x01, 0x00, 0x3F, 0x00, 0x3F, 0x01, 0x23,
	0x02, 0xED, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
	0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
	0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
	0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
	0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
	0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
	0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
	0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
	0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
	0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
	0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
	0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
	0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
	0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
	0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
	0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
	0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
	0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A
};

/* Ethernet/IPv4/UDP packet. Ethernet frame length 1500 bytes (+ CRC). */
static const uint8_t test_packet_ipv4_udp_1500[] = {
	0x00, 0x00, 0x09, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x09, 0x00, 0x04, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x05, 0xCE, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
	0xF1, 0xCB, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8,
	0x01, 0x01, 0x00, 0x3F, 0x00, 0x3F, 0x05, 0xBA,
	0xF8, 0x59, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
	0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
	0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
	0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
	0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
	0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
	0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
	0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
	0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
	0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
	0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
	0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
	0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
	0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
	0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
	0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
	0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
	0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
	0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
	0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
	0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
	0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
	0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
	0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
	0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
	0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
	0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
	0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
	0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
	0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
	0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
	0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
	0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
	0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
	0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
	0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
	0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
	0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
	0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
	0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
	0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
	0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
	0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
	0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
	0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
	0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
	0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
	0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
	0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
	0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
	0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
	0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
	0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
	0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
	0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
	0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
	0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
	0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
	0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
	0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
	0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
	0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
	0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
	0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
	0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
	0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
	0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
	0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
	0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
	0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
	0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
	0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
	0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
	0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
	0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
	0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
	0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
	0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
	0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
	0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
	0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
	0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
	0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
	0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
	0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
	0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
	0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
	0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
	0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
	0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
	0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
	0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
	0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
	0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D,
	0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
	0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
	0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
	0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
	0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
	0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
	0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
	0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
	0xAE, 0xAF, 0xB0, 0xB1
};

#ifdef __cplusplus
}
#endif

#endif
