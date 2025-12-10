// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_latency_summary - Network stack latency tracer
// Shared types between BPF and userspace

#ifndef __SYSTEM_NETWORK_LATENCY_SUMMARY_H
#define __SYSTEM_NETWORK_LATENCY_SUMMARY_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_STAGES      14
#define MAX_SLOTS       26

/* Stage definitions */
/* TX direction stages (System -> Physical) */
#define TX_STAGE_0      0   /* ip_queue_xmit (TCP) / ip_send_skb (UDP) */
#define TX_STAGE_1      1   /* internal_dev_xmit */
#define TX_STAGE_2      2   /* ovs_dp_process_packet */
#define TX_STAGE_3      3   /* ovs_dp_upcall */
#define TX_STAGE_4      4   /* ovs_flow_key_extract_userspace */
#define TX_STAGE_5      5   /* ovs_vport_send */
#define TX_STAGE_6      6   /* dev_queue_xmit (physical) */

/* RX direction stages (Physical -> System) */
#define RX_STAGE_0      7   /* __netif_receive_skb (physical) */
#define RX_STAGE_1      8   /* netdev_frame_hook */
#define RX_STAGE_2      9   /* ovs_dp_process_packet */
#define RX_STAGE_3      10  /* ovs_dp_upcall */
#define RX_STAGE_4      11  /* ovs_flow_key_extract_userspace */
#define RX_STAGE_5      12  /* ovs_vport_send */
#define RX_STAGE_6      13  /* tcp_v4_rcv/udp_rcv */

/* Direction constants */
#define DIRECTION_TX    1
#define DIRECTION_RX    2

/* Protocol constants */
#define PROTO_TCP       6
#define PROTO_UDP       17

/* Packet key for flow tracking */
struct packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 protocol;
    __u8 pad[3];
    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;
        } tcp;
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;
            __be16 udp_len;
            __be16 frag_off;
            __u8 pad[2];
        } udp;
    };
};

/* Flow tracking data */
struct flow_data {
    __u64 first_timestamp;
    __u64 last_timestamp;
    __u8 direction;
    __u8 last_stage;
    __u8 pad[6];
};

/* Stage pair key for histogram */
struct stage_pair_key {
    __u8 prev_stage;
    __u8 curr_stage;
    __u8 direction;
    __u8 pad;
};

/* Histogram structure for stage pair latencies */
struct stage_pair_hist {
    __u64 slots[MAX_SLOTS];
};

/* Simple histogram for total latency */
struct total_hist {
    __u64 slots[MAX_SLOTS];
};

/* Counter indices */
#define COUNTER_TOTAL       0
#define COUNTER_TX          1
#define COUNTER_RX          2
#define COUNTER_DROPPED     3
#define MAX_COUNTERS        4

/* Flow stage counter indices */
#define FSC_FIRST_TX        0
#define FSC_LAST_TX         1
#define FSC_FIRST_RX        2
#define FSC_LAST_RX         3
#define MAX_FSC             4

#endif /* __SYSTEM_NETWORK_LATENCY_SUMMARY_H */
