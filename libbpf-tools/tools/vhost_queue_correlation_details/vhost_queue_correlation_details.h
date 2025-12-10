// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_queue_correlation_details - VHOST-NET queue correlation monitor
// Shared types between BPF and userspace

#ifndef __VHOST_QUEUE_CORRELATION_DETAILS_H
#define __VHOST_QUEUE_CORRELATION_DETAILS_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_QUEUES      256

/* Event types */
#define EVENT_TUN_XMIT      1
#define EVENT_HANDLE_RX     2
#define EVENT_TUN_RECVMSG   3
#define EVENT_VHOST_SIGNAL  4
#define EVENT_VHOST_NOTIFY  5

/* Queue tracking key */
struct queue_key {
    __u64 sock_ptr;
    __u32 queue_index;
    char dev_name[IFNAMSIZ];
};

/* Queue correlation event */
struct queue_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];

    /* Queue identification */
    __u64 sock_ptr;
    __u32 queue_index;
    char dev_name[IFNAMSIZ];

    /* Event type */
    __u8 event_type;
    __u8 pad[3];

    /* Pointers */
    __u64 skb_ptr;
    __u64 tfile_ptr;
    __u64 vq_ptr;
    __u64 nvq_ptr;

    /* Packet info (from tun_xmit) */
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u8 pad2[3];

    /* PTR ring state */
    __u32 ptr_ring_size;
    __u32 producer;
    __u32 consumer_head;
    __u32 consumer_tail;
    __u32 ring_full;
    __u32 pad3;

    /* VHOST virtqueue state */
    __u16 last_avail_idx;
    __u16 avail_idx;
    __u16 last_used_idx;
    __u16 used_flags;
    __u16 signalled_used;
    __u8 signalled_used_valid;
    __u8 log_used;
    __u64 acked_features;

    /* vhost_notify specific */
    __s32 ret_val;
    __u8 has_event_idx_feature;
    __u8 guest_flags_valid;
    __u16 avail_flags;

    /* Busyloop timeouts */
    __s32 rx_busyloop_timeout;
    __s32 tx_busyloop_timeout;
};

#endif /* __VHOST_QUEUE_CORRELATION_DETAILS_H */
