// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_queue_correlation - VHOST queue correlation monitor
// Shared types between BPF and userspace

#ifndef __VHOST_QUEUE_CORRELATION_H
#define __VHOST_QUEUE_CORRELATION_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_QUEUES      256

/* Event types */
#define EVENT_VHOST_SIGNAL  1
#define EVENT_VHOST_NOTIFY  2

/* Queue key structure */
struct queue_key {
    __u64 sock_ptr;
    __u32 queue_index;
    char dev_name[IFNAMSIZ];
};

/* Queue event structure */
struct queue_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];

    __u64 sock_ptr;
    __u32 queue_index;
    char dev_name[IFNAMSIZ];

    __u8 event_type;  /* 1=vhost_signal, 2=vhost_notify */
    __u8 pad[3];

    /* VQ state */
    __u64 vq_ptr;
    __u16 last_avail_idx;
    __u16 avail_idx;
    __u16 last_used_idx;
    __u16 used_flags;
    __u16 signalled_used;
    __u8 signalled_used_valid;
    __u8 log_used;
    __u64 log_addr;
    __u64 acked_features;
    __u64 acked_backend_features;

    /* vhost_notify specific */
    __s32 ret_val;
    __u8 has_event_idx_feature;
    __u8 guest_flags_valid;
    __u8 guest_event_valid;
    __u8 pad2;
    __u16 avail_flags;
    __u16 used_event_idx;
};

/* Device name union for efficient comparison */
union name_buf {
    char name[IFNAMSIZ];
    struct {
        __u64 hi;
        __u64 lo;
    } name_int;
};

#endif /* __VHOST_QUEUE_CORRELATION_H */
