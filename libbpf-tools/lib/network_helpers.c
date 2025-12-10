// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Network helper functions for libbpf tools

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "network_helpers.h"

/* Thread-local buffers for formatting */
static __thread char ipv4_buf[INET_ADDRSTRLEN];
static __thread char ipv6_buf[INET6_ADDRSTRLEN];
static __thread char mac_buf[18];
static __thread char port_buf[6];
static __thread char proto_buf[16];

/* Format IPv4 address to string */
const char *format_ipv4(uint32_t addr)
{
    struct in_addr in = { .s_addr = addr };
    return inet_ntop(AF_INET, &in, ipv4_buf, sizeof(ipv4_buf));
}

/* Format IPv6 address to string */
const char *format_ipv6(const uint8_t *addr)
{
    struct in6_addr in6;
    memcpy(&in6, addr, sizeof(in6));
    return inet_ntop(AF_INET6, &in6, ipv6_buf, sizeof(ipv6_buf));
}

/* Format MAC address to string */
const char *format_mac(const uint8_t *addr)
{
    snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    return mac_buf;
}

/* Format port number */
const char *format_port(uint16_t port)
{
    snprintf(port_buf, sizeof(port_buf), "%u", ntohs(port));
    return port_buf;
}

/* Format protocol number to name */
const char *format_protocol(uint8_t protocol)
{
    switch (protocol) {
    case 1:
        return "ICMP";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 41:
        return "IPv6";
    case 47:
        return "GRE";
    case 50:
        return "ESP";
    case 51:
        return "AH";
    case 58:
        return "ICMPv6";
    case 89:
        return "OSPF";
    case 132:
        return "SCTP";
    default:
        snprintf(proto_buf, sizeof(proto_buf), "proto=%u", protocol);
        return proto_buf;
    }
}

/* Stage name mapping for system network latency */
static const char *stage_names[] = {
    /* TX path */
    [0]  = "TX_S0_ip_layer_entry",
    [1]  = "TX_S1_internal_dev_xmit",
    [2]  = "TX_S2_ovs_dp_process",
    [3]  = "TX_S3_ovs_dp_upcall",
    [4]  = "TX_S4_ovs_flow_key_extract",
    [5]  = "TX_S5_ovs_vport_send",
    [6]  = "TX_S6_dev_queue_xmit",

    /* RX path */
    [7]  = "RX_S0_netif_receive_skb",
    [8]  = "RX_S1_netdev_frame_hook",
    [9]  = "RX_S2_ovs_dp_process",
    [10] = "RX_S3_ovs_dp_upcall",
    [11] = "RX_S4_ovs_flow_key_extract",
    [12] = "RX_S5_ovs_vport_send",
    [13] = "RX_S6_tcp_v4_rcv/udp_rcv",
};

#define MAX_STAGE_NAMES (sizeof(stage_names) / sizeof(stage_names[0]))

/* Get stage name for system network latency tools */
const char *get_stage_name(int stage_id)
{
    static char unknown_buf[32];

    if (stage_id >= 0 && stage_id < (int)MAX_STAGE_NAMES && stage_names[stage_id])
        return stage_names[stage_id];

    snprintf(unknown_buf, sizeof(unknown_buf), "UNKNOWN_%d", stage_id);
    return unknown_buf;
}

/* Get direction name */
const char *get_direction_name(int direction)
{
    switch (direction) {
    case 1:
        return "TX (System -> Physical)";
    case 2:
        return "RX (Physical -> System)";
    default:
        return "Unknown";
    }
}

/* Check if IP address matches filter (0 means match all) */
bool ip_matches_filter(uint32_t addr, uint32_t filter)
{
    if (filter == 0)
        return true;
    return addr == filter;
}

/* Check if port matches filter (0 means match all) */
bool port_matches_filter(uint16_t port, uint16_t filter)
{
    if (filter == 0)
        return true;
    return port == filter;
}

/* Parse IP address from command line argument */
int parse_ipv4_addr(const char *str, uint32_t *addr)
{
    struct in_addr in;

    if (!str || !addr)
        return -EINVAL;

    if (inet_pton(AF_INET, str, &in) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", str);
        return -EINVAL;
    }

    *addr = in.s_addr;
    return 0;
}

/* Parse port from command line argument */
int parse_port(const char *str, uint16_t *port)
{
    long val;
    char *endptr;

    if (!str || !port)
        return -EINVAL;

    val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > 65535) {
        fprintf(stderr, "Invalid port: %s\n", str);
        return -EINVAL;
    }

    *port = (uint16_t)val;
    return 0;
}

/* Get interface index by name */
int get_interface_index(const char *ifname)
{
    unsigned int ifindex;

    if (!ifname)
        return -EINVAL;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n", ifname, strerror(errno));
        return -errno;
    }

    return (int)ifindex;
}

/* Parse comma-separated interface names */
int parse_interfaces(const char *str, int *ifindex1, int *ifindex2)
{
    char buf[256];
    char *comma;
    int idx1, idx2;

    if (!str || !ifindex1 || !ifindex2)
        return -EINVAL;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    comma = strchr(buf, ',');
    if (comma) {
        *comma = '\0';
        idx1 = get_interface_index(buf);
        if (idx1 < 0)
            return idx1;

        idx2 = get_interface_index(comma + 1);
        if (idx2 < 0)
            return idx2;
    } else {
        idx1 = get_interface_index(buf);
        if (idx1 < 0)
            return idx1;
        idx2 = idx1;
    }

    *ifindex1 = idx1;
    *ifindex2 = idx2;
    return 0;
}
