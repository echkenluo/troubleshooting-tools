// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_vhost_queue_stats_full - Full TUN to vhost-net queue statistics
// Shared types between BPF and userspace

#ifndef __TUN_VHOST_QUEUE_STATS_FULL_H
#define __TUN_VHOST_QUEUE_STATS_FULL_H

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

/* Signal index frequency key */
struct idx_freq_key {
    __u64 sock_ptr;
    __u16 last_used_idx;
    __u16 pad;
};

/* Queue statistics summary */
struct queue_stats {
    __u64 xmit_count;
    __u64 handle_rx_count;
    __u64 recvmsg_count;
    __u64 signal_count;
    __u64 ring_depth_sum;
    __u32 ring_depth_max;
    __u32 pad;
};

#endif /* __TUN_VHOST_QUEUE_STATS_FULL_H */
