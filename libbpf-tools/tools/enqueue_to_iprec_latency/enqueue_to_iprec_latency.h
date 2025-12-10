// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// enqueue_to_iprec_latency - RX latency measurement tool
// Shared types between BPF and userspace

#ifndef __ENQUEUE_TO_IPREC_LATENCY_H
#define __ENQUEUE_TO_IPREC_LATENCY_H

#define TASK_COMM_LEN   16
#define MAX_SLOTS       32

/* Stage definitions */
#define STAGE_ENQUEUE     1  /* enqueue_to_backlog */
#define STAGE_RECEIVE     2  /* __netif_receive_skb */
#define STAGE_IP_RCV      3  /* ip_rcv */

/* Packet key for flow tracking */
struct packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 pad[3];
    __u32 seq_or_id;  /* TCP seq or IP id for UDP */
};

/* Flow tracking data */
struct flow_data {
    __u64 enqueue_ts;      /* Timestamp at enqueue_to_backlog */
    __u64 receive_ts;      /* Timestamp at __netif_receive_skb */
    __u8 enqueue_cpu;      /* CPU at enqueue */
    __u8 receive_cpu;      /* CPU at receive */
    __u16 pad;
};

/* High latency event */
struct latency_event {
    __u64 ts_start;
    __u64 ts_end;
    __u64 latency_us;
    __u8 prev_stage;
    __u8 curr_stage;
    __u8 cpu_start;
    __u8 cpu_end;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

/* Histogram key */
struct hist_key {
    __u8 prev_stage;
    __u8 curr_stage;
    __u8 slot;
    __u8 pad;
};

/* Counter indices */
#define CNT_ENQUEUE         0
#define CNT_RECEIVE         1
#define CNT_IP_RCV          2
#define CNT_CROSS_CPU       3
#define CNT_PARSE_FAIL      4
#define CNT_FLOW_NOT_FOUND  5
#define CNT_MAX             6

#endif /* __ENQUEUE_TO_IPREC_LATENCY_H */
