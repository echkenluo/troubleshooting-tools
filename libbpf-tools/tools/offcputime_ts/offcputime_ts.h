// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// offcputime_ts - Off-CPU time analysis with timeseries support
// Shared types between BPF and userspace

#ifndef __OFFCPUTIME_TS_H
#define __OFFCPUTIME_TS_H

#define TASK_COMM_LEN   16
#define MAX_STACK_DEPTH 128

/* Key for off-CPU time aggregation */
struct key_t {
    __u32 pid;
    __u32 tgid;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    char comm[TASK_COMM_LEN];
};

#endif /* __OFFCPUTIME_TS_H */
