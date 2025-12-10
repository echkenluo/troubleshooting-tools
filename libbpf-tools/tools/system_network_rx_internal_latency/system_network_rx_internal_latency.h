// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_rx_internal_latency - Detailed RX path latency measurement
// Shared types between BPF and userspace

#ifndef __SYSTEM_NETWORK_RX_INTERNAL_LATENCY_H
#define __SYSTEM_NETWORK_RX_INTERNAL_LATENCY_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_SLOTS       32

/* Detailed RX path stages */
#define RX_S5_0_OVS_VPORT_SEND          0
#define RX_S5_1_INTERNAL_DEV_RECV       1
#define RX_S5_2_NETIF_RX                2
#define RX_S5_3_NETIF_RX_INTERNAL       3
#define RX_S5_4_ENQUEUE_TO_BACKLOG      4  /* CRITICAL */
#define RX_S5_5_PROCESS_BACKLOG         5  /* CRITICAL ASYNC BOUNDARY */
#define RX_S5_6_NETIF_RECEIVE_SKB       6
#define RX_S5_7_IP_RCV                  7
#define RX_S5_8_IP_LOCAL_DELIVER        8
#define RX_S6_PROTOCOL_RCV              9  /* tcp_v4_rcv / udp_rcv */
#define MAX_STAGES                      10

/* Packet key for tracking */
struct packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 pad[3];
    __be32 seq;  /* TCP seq or IP id */
};

/* Flow tracking data */
struct flow_data {
    __u64 first_ts;
    __u64 last_ts;
    __u8 last_stage;
    __u8 enqueue_cpu;
    __u8 process_cpu;
    __u8 pad;
};

/* Stage pair histogram key */
struct stage_pair_key {
    __u8 prev_stage;
    __u8 curr_stage;
    __u8 latency_bucket;
    __u8 pad;
};

/* CPU pair histogram key */
struct cpu_pair_key {
    __u8 enqueue_cpu;
    __u8 process_cpu;
    __u8 latency_bucket;
    __u8 pad;
};

/* Counter indices */
#define CNT_RX_PACKETS     0
#define CNT_CROSS_CPU      1
#define CNT_MAX            2

/* Stage names for userspace */
static const char *stage_names[] = {
    "ovs_vport_send",
    "internal_dev_recv",
    "netif_rx",
    "netif_rx_internal",
    "enqueue_to_backlog",      /* CRITICAL */
    "process_backlog",         /* CRITICAL ASYNC */
    "netif_receive_skb",
    "ip_rcv",
    "ip_local_deliver",
    "tcp_v4_rcv/udp_rcv"
};

#endif /* __SYSTEM_NETWORK_RX_INTERNAL_LATENCY_H */
