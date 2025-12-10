// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// qdisc_latency_details - Qdisc latency tracking tool
// Shared types between BPF and userspace

#ifndef __QDISC_LATENCY_DETAILS_H
#define __QDISC_LATENCY_DETAILS_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16

/* Packet key for tracking */
struct packet_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u8 pad[3];
    __u32 seq_or_id;  /* TCP seq or IP ID */
};

/* Flow data for qdisc tracking */
struct flow_data {
    __u64 enqueue_time;
    char dev_name[IFNAMSIZ];
};

/* Qdisc latency event */
struct qdisc_event {
    __u64 timestamp;
    __u64 enqueue_time;
    __u64 dequeue_time;
    __u64 delay_ns;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u8 pad[3];
    char dev_name[IFNAMSIZ];
};

#endif /* __QDISC_LATENCY_DETAILS_H */
