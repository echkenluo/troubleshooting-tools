// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// qdisc_drop_trace - Queueing discipline drop tracer
// Shared types between BPF and userspace

#ifndef __QDISC_DROP_TRACE_H
#define __QDISC_DROP_TRACE_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16
#define MAX_STACK_DEPTH 32

/* Drop event from qdisc */
struct qdisc_drop_event {
    __u64 timestamp;
    __u32 pid;
    __u32 ifindex;
    __u32 qdisc_handle;
    __u32 skb_len;
    __u8 protocol;
    __u8 pad[3];
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __s32 stack_id;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
};

/* Stats key for aggregation */
struct qdisc_stats_key {
    __u32 ifindex;
    __u32 qdisc_handle;
};

/* Stats value */
struct qdisc_stats {
    __u64 drops;
    __u64 bytes;
    __u64 last_drop_ts;
};

#endif /* __QDISC_DROP_TRACE_H */
