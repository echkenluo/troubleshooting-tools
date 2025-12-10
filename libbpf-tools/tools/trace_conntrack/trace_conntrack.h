// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// trace_conntrack - Connection tracking event tracer
// Shared types between BPF and userspace

#ifndef __TRACE_CONNTRACK_H
#define __TRACE_CONNTRACK_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16

/* Conntrack states */
enum ct_state {
    CT_STATE_NONE = 0,
    CT_STATE_NEW,
    CT_STATE_ESTABLISHED,
    CT_STATE_RELATED,
    CT_STATE_INVALID,
    CT_STATE_UNTRACKED,
};

/* Conntrack event types */
enum ct_event_type {
    CT_EVENT_NEW = 1,
    CT_EVENT_DESTROY,
    CT_EVENT_UPDATE,
};

/* Conntrack event structure */
struct ct_event {
    __u64 timestamp;
    __u32 pid;
    __u32 event_type;
    __u32 ct_state;
    __u8 protocol;
    __u8 pad[3];
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __be32 reply_src_ip;
    __be32 reply_dst_ip;
    __be16 reply_src_port;
    __be16 reply_dst_port;
    __u32 mark;
    __u32 timeout;
    __u64 packets;
    __u64 bytes;
    char comm[TASK_COMM_LEN];
};

/* Stats key for connection tracking */
struct ct_stats_key {
    __u8 protocol;
    __u8 state;
    __u16 pad;
};

/* Stats value */
struct ct_stats {
    __u64 new_count;
    __u64 destroy_count;
    __u64 update_count;
};

#endif /* __TRACE_CONNTRACK_H */
