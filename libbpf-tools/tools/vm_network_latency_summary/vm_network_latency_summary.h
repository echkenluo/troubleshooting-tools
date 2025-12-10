// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_latency_summary - VM Network stack latency tracer
// Shared types between BPF and userspace

#ifndef __VM_NETWORK_LATENCY_SUMMARY_H
#define __VM_NETWORK_LATENCY_SUMMARY_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_STAGES      22
#define MAX_SLOTS       26

/* Stage definitions - VNET perspective */
/* VNET RX path (VM TX, packets from VM to external) */
#define STG_VNET_RX             1
#define STG_OVS_RX              2
#define STG_FLOW_EXTRACT_END_RX 3
#define STG_OVS_UPCALL_RX       4
#define STG_OVS_USERSPACE_RX    5
#define STG_CT_RX               6
#define STG_CT_OUT_RX           7
#define STG_QDISC_ENQ           8
#define STG_QDISC_DEQ           9
#define STG_TX_QUEUE            10
#define STG_TX_XMIT             11

/* VNET TX path (VM RX, packets from external to VM) */
#define STG_PHY_RX              12
#define STG_OVS_TX              13
#define STG_FLOW_EXTRACT_END_TX 14
#define STG_OVS_UPCALL_TX       15
#define STG_OVS_USERSPACE_TX    16
#define STG_CT_TX               17
#define STG_CT_OUT_TX           18
#define STG_VNET_QDISC_ENQ      19
#define STG_VNET_QDISC_DEQ      20
#define STG_VNET_TX             21

/* Direction constants */
#define DIRECTION_VNET_RX   1   /* VM TX - packets from VM to external */
#define DIRECTION_VNET_TX   2   /* VM RX - packets from external to VM */

/* Protocol constants */
#define PROTO_TCP       6
#define PROTO_UDP       17
#define PROTO_ICMP      1

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
        } udp;
        struct {
            __be16 id;
            __be16 seq;
            __u8 type;
            __u8 code;
            __u8 pad[2];
        } icmp;
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
#define COUNTER_VNET_RX     1
#define COUNTER_VNET_TX     2
#define COUNTER_DROPPED     3
#define MAX_COUNTERS        4

/* Flow stage counter indices */
#define FSC_FIRST_RX        0
#define FSC_LAST_RX         1
#define FSC_FIRST_TX        2
#define FSC_LAST_TX         3
#define MAX_FSC             4

#endif /* __VM_NETWORK_LATENCY_SUMMARY_H */
