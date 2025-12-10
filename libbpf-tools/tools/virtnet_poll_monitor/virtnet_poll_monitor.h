// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// virtnet_poll_monitor - Virtio-net RX monitor
// Shared types between BPF and userspace

#ifndef __VIRTNET_POLL_MONITOR_H
#define __VIRTNET_POLL_MONITOR_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16

/* Event types */
#define EVENT_POLL_ENTRY    0
#define EVENT_POLL_EXIT     1
#define EVENT_SKB_RECV_DONE 2

/* Event structure for virtnet_poll monitoring */
struct virtnet_poll_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];

    /* Device and queue info */
    char dev_name[IFNAMSIZ];
    __u32 queue_index;
    __u32 vq_index;

    /* Poll parameters */
    __u32 budget;
    __u32 processed;  /* For return probe */

    /* Pointers for debugging */
    __u64 napi_ptr;
    __u64 rq_ptr;
    __u64 vq_ptr;
    __u64 netdev_ptr;

    /* Event type: 0=entry, 1=exit, 2=skb_recv_done */
    __u8 event_type;
    __u8 pad[7];
};

/* Device filter structure */
struct device_filter {
    char name[IFNAMSIZ];
};

#endif /* __VIRTNET_POLL_MONITOR_H */
