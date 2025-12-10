// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_performance_metrics - VM Network performance metrics
// Shared types between BPF and userspace

#ifndef __VM_NETWORK_PERFORMANCE_METRICS_H
#define __VM_NETWORK_PERFORMANCE_METRICS_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_STAGES      22

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
#define DIR_VNET_RX     1       /* VM TX - packets from VM to external */
#define DIR_VNET_TX     2       /* VM RX - packets from external to VM */

/* Protocol constants */
#define PROTO_TCP       6
#define PROTO_UDP       17
#define PROTO_ICMP      1

/* Packet key for flow tracking */
struct packet_key {
    __be32 sip;
    __be32 dip;
    __u8 proto;
    __u8 pad[3];
    union {
        struct {
            __be16 source;
            __be16 dest;
            __be32 seq;
        } tcp;
        struct {
            __be16 source;
            __be16 dest;
            __be16 id;
            __be16 len;
        } udp;
        struct {
            __be16 id;
            __be16 sequence;
            __u8 type;
            __u8 code;
            __u8 pad[2];
        } icmp;
    };
};

/* Per-stage information */
struct stage_info {
    __u64 timestamp;
    __u64 skb_ptr;
    __u32 ifindex;
    char devname[IFNAMSIZ];
    __s16 queue_mapping;
    __u32 skb_hash;
    __u32 len;
    __u32 data_len;
    __u32 cpu;
    __u8 valid;
    __u8 pad[3];
};

/* Flow tracking data */
struct flow_data {
    struct stage_info stages[MAX_STAGES];
    __u32 first_pid;
    char first_comm[TASK_COMM_LEN];
    __u64 ct_start_time;
    __u32 ct_lookup_duration;
    __u64 qdisc_enq_time;
    __u32 qdisc_qlen;
    __u8 direction;
    __u8 stage_count;
    __u8 complete;
    __u8 pad;
    char first_ifname[IFNAMSIZ];
};

/* Performance event for ring buffer */
struct perf_event {
    __u64 pkt_id;
    struct packet_key key;
    struct flow_data flow;
    __u64 timestamp;
    __u32 cpu;
    __u32 ifindex;
    char devname[IFNAMSIZ];
    __u8 stage;
    __u8 event_type;
    __u8 pad[2];
};

#endif /* __VM_NETWORK_PERFORMANCE_METRICS_H */
