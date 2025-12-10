// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kernel_drop_stack_stats_summary - Kernel packet drop statistics with stack traces
// Shared types between BPF and userspace

#ifndef __KERNEL_DROP_STACK_STATS_SUMMARY_H
#define __KERNEL_DROP_STACK_STATS_SUMMARY_H

#define MAX_STACK_DEPTH 32
#define TASK_COMM_LEN 16
#define IFNAMSIZ 16

/* Drop reasons from kernel */
enum drop_reason {
    DROP_REASON_NOT_SPECIFIED = 0,
    DROP_REASON_NO_SOCKET,
    DROP_REASON_PKT_TOO_SMALL,
    DROP_REASON_TCP_CSUM,
    DROP_REASON_SOCKET_FILTER,
    DROP_REASON_UDP_CSUM,
    DROP_REASON_NETFILTER_DROP,
    DROP_REASON_OTHERHOST,
    DROP_REASON_IP_CSUM,
    DROP_REASON_IP_INHDR,
    DROP_REASON_IP_RPFILTER,
    DROP_REASON_UNICAST_IN_L2_MULTICAST,
    DROP_REASON_MAX
};

/* Key for aggregating drops by stack */
struct drop_key {
    __u32 stack_id;
    __u32 drop_reason;
};

/* Event structure for detailed drop info */
struct drop_event {
    __u64 timestamp;
    __u32 pid;
    __u32 drop_reason;
    __u32 ifindex;
    __u32 protocol;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __s32 stack_id;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
};

/* Statistics per stack/reason combination */
struct drop_stats {
    __u64 count;
    __u64 bytes;
    __u64 last_timestamp;
};

/* Filter configuration */
struct filter_config {
    __be32 src_ip;
    __be32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 pad[3];
};

#endif /* __KERNEL_DROP_STACK_STATS_SUMMARY_H */
