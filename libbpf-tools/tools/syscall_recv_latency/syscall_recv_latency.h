// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// syscall_recv_latency - recv/read syscall latency measurement
// Shared types between BPF and userspace

#ifndef __SYSCALL_RECV_LATENCY_H
#define __SYSCALL_RECV_LATENCY_H

#define TASK_COMM_LEN   16
#define MAX_SLOTS       32

/* Recv context key */
struct recv_key {
    __u32 tid;
    __u8 syscall_type;
    __u8 pad[3];
};

/* Recv enter context */
struct recv_enter {
    __u64 ts;
    __u32 cpu;
    __s32 fd;
};

/* High latency event */
struct recv_event {
    __u64 ts_enter;
    __u64 ts_exit;
    __u64 latency_us;
    __u32 pid;
    __u32 tid;
    __u32 cpu_enter;
    __u32 cpu_exit;
    __s32 fd;
    __s64 bytes;
    char comm[TASK_COMM_LEN];
};

/* Syscall types */
#define SYSCALL_READ     0
#define SYSCALL_RECVFROM 1
#define SYSCALL_RECVMSG  2

/* Counter indices */
#define CNT_TOTAL_CALLS   0
#define CNT_TOTAL_BYTES   1
#define CNT_CPU_MIGRATE   2
#define CNT_ERRORS        3
#define CNT_ZERO_READS    4
#define CNT_MAX           5

#endif /* __SYSCALL_RECV_LATENCY_H */
