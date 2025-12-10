// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Common types shared between BPF programs and userspace

#ifndef __COMMON_TYPES_H
#define __COMMON_TYPES_H

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <stdint.h>
#include <stdbool.h>
#include <linux/types.h>
#endif

/* Common constants */
#define TASK_COMM_LEN       16
#define IFNAMSIZ            16
#define MAX_STACK_DEPTH     50
#define ETH_ALEN            6

/* Histogram bucket sizes */
#define HIST_SLOTS_SMALL    16   /* For small value ranges */
#define HIST_SLOTS_NORMAL   26   /* For general latency (ns to seconds) */
#define HIST_SLOTS_LARGE    64   /* For wide value ranges */

/* Direction constants */
#define DIRECTION_TX        1
#define DIRECTION_RX        2

/* Protocol constants */
#define PROTO_TCP           6
#define PROTO_UDP           17
#define PROTO_ICMP          1

/*
 * Network packet identification
 * Used for tracking packets through the network stack
 */
struct packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 protocol;
    __u8 pad[3];
    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;          /* TCP sequence number */
        } tcp;
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;        /* IP identification */
            __be16 udp_len;
        } udp;
    };
};

/*
 * Flow tracking data
 * Used for tracking packets through multiple stages
 */
struct flow_data {
    __u64 first_ts;              /* Timestamp of first stage */
    __u64 last_ts;               /* Timestamp of last stage */
    __u8 direction;              /* 1=tx, 2=rx */
    __u8 last_stage;             /* Last valid stage seen */
    __u8 pad[6];
};

/*
 * Simple histogram structure
 * Used for single distribution histograms
 */
struct hist {
    __u64 slots[HIST_SLOTS_NORMAL];
};

/*
 * Keyed histogram structure
 * Used for multi-dimensional histograms
 */
struct keyed_hist {
    __u64 slots[HIST_SLOTS_NORMAL];
};

/*
 * Stage pair key for adjacent latency tracking
 */
struct stage_pair_key {
    __u8 prev_stage;
    __u8 curr_stage;
    __u8 direction;
    __u8 pad;
};

/*
 * Packet drop event structure
 */
struct drop_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __s32 stack_id;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];

    /* Ethernet fields */
    __u8 eth_src[ETH_ALEN];
    __u8 eth_dst[ETH_ALEN];
    __u16 eth_type;

    /* VLAN fields */
    __u16 vlan_id;
    __u8 has_vlan;
    __u8 protocol_type;  /* 0=other, 1=ipv4, 2=ipv6, 3=arp */

    /* IPv4 fields */
    __u32 ipv4_saddr;
    __u32 ipv4_daddr;
    __u8 ipv4_protocol;
    __u8 ipv4_ttl;
    __u16 ipv4_id;
    __u16 ipv4_sport;
    __u16 ipv4_dport;

    /* SKB debug fields */
    __u32 skb_len;
};

/*
 * Latency event structure for detailed tracing
 */
struct latency_event {
    __u64 timestamp;
    __u64 latency_ns;
    __u32 pid;
    __u8 stage;
    __u8 direction;
    __u8 protocol;
    __u8 pad;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    char comm[TASK_COMM_LEN];
};

/*
 * ICMP RTT event structure
 */
struct icmp_rtt_event {
    __u64 timestamp;
    __u64 rtt_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 seq;
    __u16 id;
};

/*
 * Counters array indices
 */
enum counter_idx {
    COUNTER_TOTAL = 0,
    COUNTER_TX,
    COUNTER_RX,
    COUNTER_DROPPED,
    COUNTER_MAX
};

/*
 * Stage definitions for system network latency
 */
enum tx_stage {
    TX_STAGE_0 = 0,  /* ip_queue_xmit (TCP) / ip_send_skb (UDP) */
    TX_STAGE_1,      /* internal_dev_xmit */
    TX_STAGE_2,      /* ovs_dp_process_packet */
    TX_STAGE_3,      /* ovs_dp_upcall */
    TX_STAGE_4,      /* ovs_flow_key_extract_userspace */
    TX_STAGE_5,      /* ovs_vport_send */
    TX_STAGE_6,      /* dev_queue_xmit (physical) */
};

enum rx_stage {
    RX_STAGE_0 = 7,  /* __netif_receive_skb (physical) */
    RX_STAGE_1,      /* netdev_frame_hook */
    RX_STAGE_2,      /* ovs_dp_process_packet */
    RX_STAGE_3,      /* ovs_dp_upcall */
    RX_STAGE_4,      /* ovs_flow_key_extract_userspace */
    RX_STAGE_5,      /* ovs_vport_send */
    RX_STAGE_6,      /* tcp_v4_rcv/udp_rcv */
};

#define MAX_STAGES 14

#endif /* __COMMON_TYPES_H */
