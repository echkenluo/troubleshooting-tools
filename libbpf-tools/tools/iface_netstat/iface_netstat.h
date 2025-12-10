// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// iface_netstat - Per-queue packet size distribution monitor
// Shared types between BPF and userspace

#ifndef __IFACE_NETSTAT_H
#define __IFACE_NETSTAT_H

#define IFNAMSIZ        16
#define MAX_QUEUE_NUM   1024

/* Queue data for packet statistics */
struct queue_data {
    __u64 total_pkt_len;
    __u32 num_pkt;
    __u32 size_64B;      /* [0, 64) bytes */
    __u32 size_512B;     /* [64, 512) bytes */
    __u32 size_2K;       /* [512, 2K) bytes */
    __u32 size_16K;      /* [2K, 16K) bytes */
    __u32 size_64K;      /* [16K, 64K) bytes */
};

#endif /* __IFACE_NETSTAT_H */
