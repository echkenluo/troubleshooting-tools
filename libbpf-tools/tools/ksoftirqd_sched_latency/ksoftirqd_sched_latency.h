// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ksoftirqd_sched_latency - ksoftirqd scheduling latency measurement
// Shared types between BPF and userspace

#ifndef __KSOFTIRQD_SCHED_LATENCY_H
#define __KSOFTIRQD_SCHED_LATENCY_H

#define TASK_COMM_LEN   16
#define MAX_CPUS        256
#define MAX_SLOTS       32

/* Histogram key */
struct hist_key {
    __u32 cpu;
    __u32 slot;
};

#endif /* __KSOFTIRQD_SCHED_LATENCY_H */
