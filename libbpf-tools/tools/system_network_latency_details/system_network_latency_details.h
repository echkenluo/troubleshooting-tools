// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_latency_details - Detailed system network latency tracing
// Shared types between BPF and userspace

#ifndef __SYSTEM_NETWORK_LATENCY_DETAILS_H
#define __SYSTEM_NETWORK_LATENCY_DETAILS_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16
#define MAX_STAGES 14
#define MAX_STACK_DEPTH 32

/* Stage definitions for TX path */
#define TX_STAGE_0    0   /* ip_queue_xmit / ip_send_skb */
#define TX_STAGE_1    1   /* internal_dev_xmit */
#define TX_STAGE_2    2   /* ovs_dp_process_packet */
#define TX_STAGE_3    3   /* ovs_dp_upcall */
#define TX_STAGE_4    4   /* ovs_flow_key_extract_userspace */
#define TX_STAGE_5    5   /* ovs_vport_send */
#define TX_STAGE_6    6   /* dev_queue_xmit */

/* Stage definitions for RX path */
#define RX_STAGE_0    7   /* netif_receive_skb */
#define RX_STAGE_1    8   /* netdev_frame_hook */
#define RX_STAGE_2    9   /* ovs_dp_process_packet */
#define RX_STAGE_3    10  /* ovs_dp_upcall */
#define RX_STAGE_4    11  /* ovs_flow_key_extract_userspace */
#define RX_STAGE_5    12  /* ovs_vport_send */
#define RX_STAGE_6    13  /* tcp_v4_rcv / udp_rcv */

/* Packet key for tracking */
struct packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 pad[3];
    __u32 seq;      /* TCP seq or UDP ip_id */
};

/* Flow data with timestamps for each stage */
struct flow_data {
    __u64 ts[MAX_STAGES];
    __u64 skb_ptr[MAX_STAGES];
    __s32 stack_id[MAX_STAGES];
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    __u8 tcp_flags;
    __u8 saw_start;
    __u8 saw_end;
    __u8 direction;  /* 1=tx, 2=rx */
};

/* Latency event output */
struct latency_event {
    struct packet_key key;
    struct flow_data data;
};

#endif /* __SYSTEM_NETWORK_LATENCY_DETAILS_H */
