// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Network helper functions for libbpf tools

#ifndef __NETWORK_HELPERS_H
#define __NETWORK_HELPERS_H

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

/* Format IPv4 address to string */
const char *format_ipv4(uint32_t addr);

/* Format IPv6 address to string */
const char *format_ipv6(const uint8_t *addr);

/* Format MAC address to string */
const char *format_mac(const uint8_t *addr);

/* Format port number */
const char *format_port(uint16_t port);

/* Format protocol number to name */
const char *format_protocol(uint8_t protocol);

/* Get stage name for system network latency tools */
const char *get_stage_name(int stage_id);

/* Get direction name (tx/rx) */
const char *get_direction_name(int direction);

/* Check if IP address matches filter */
bool ip_matches_filter(uint32_t addr, uint32_t filter);

/* Check if port matches filter */
bool port_matches_filter(uint16_t port, uint16_t filter);

/* Parse IP address from command line argument */
int parse_ipv4_addr(const char *str, uint32_t *addr);

/* Parse port from command line argument */
int parse_port(const char *str, uint16_t *port);

/* Get interface index by name */
int get_interface_index(const char *ifname);

/* Parse comma-separated interface names */
int parse_interfaces(const char *str, int *ifindex1, int *ifindex2);

#endif /* __NETWORK_HELPERS_H */
