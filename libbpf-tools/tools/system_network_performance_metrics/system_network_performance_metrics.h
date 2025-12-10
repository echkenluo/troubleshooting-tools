// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_performance_metrics - System network performance metrics
// Shared types between BPF and userspace

#ifndef __SYSTEM_NETWORK_PERFORMANCE_METRICS_H
#define __SYSTEM_NETWORK_PERFORMANCE_METRICS_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16

/* Metrics structure */
struct perf_metrics {
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_latency_sum;
    __u64 rx_latency_sum;
    __u64 tx_latency_min;
    __u64 tx_latency_max;
    __u64 rx_latency_min;
    __u64 rx_latency_max;
    __u64 drops;
    __u64 errors;
};

/* Per-interface metrics key */
struct if_metrics_key {
    __u32 ifindex;
};

/* Per-protocol metrics key */
struct proto_metrics_key {
    __u8 protocol;
    __u8 pad[3];
};

/* Histogram bucket */
struct hist_bucket {
    __u64 count;
};

#endif /* __SYSTEM_NETWORK_PERFORMANCE_METRICS_H */
