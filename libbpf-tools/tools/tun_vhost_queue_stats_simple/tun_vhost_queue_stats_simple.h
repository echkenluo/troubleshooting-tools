// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_vhost_queue_stats_simple - Simple TUN to vhost-net queue statistics
// Shared types between BPF and userspace

#ifndef __TUN_VHOST_QUEUE_STATS_SIMPLE_H
#define __TUN_VHOST_QUEUE_STATS_SIMPLE_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_QUEUES      256

/* Histogram key structure */
struct hist_key {
    __u32 queue_index;
    char dev_name[IFNAMSIZ];
    __u64 slot;
};

/* Queue tracking key */
struct queue_key {
    __u64 sock_ptr;
    __u32 queue_index;
    char dev_name[IFNAMSIZ];
};

/* Per-queue index value key */
struct idx_value_key {
    __u32 queue_index;
    char dev_name[IFNAMSIZ];
};

/* NAPI status */
struct napi_status {
    __u8 napi_enabled;
    __u8 napi_frags_enabled;
    __u8 pad[6];
};

/* Simple queue stats */
struct simple_stats {
    __u64 xmit_count;
    __u64 signal_count;
    __u16 last_used_idx;
    __u16 pad[3];
};

#endif /* __TUN_VHOST_QUEUE_STATS_SIMPLE_H */
