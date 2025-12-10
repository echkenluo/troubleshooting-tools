// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_ring_monitor - TUN ptr_ring monitor
// Shared types between BPF and userspace

#ifndef __TUN_RING_MONITOR_H
#define __TUN_RING_MONITOR_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16

/* Event data for ptr_ring monitoring */
struct ring_event {
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];
    char dev_name[IFNAMSIZ];
    __u32 queue_mapping;
    __u32 ptr_ring_size;
    __u32 producer;
    __u32 consumer_head;
    __u32 consumer_tail;
    __u32 ring_full;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u8 pad[3];
    __u64 skb_addr;
    __u64 timestamp;
    __u64 queue_producer_ptr;
    __u32 tun_numqueues;
    __u32 queue_index;
};

#endif /* __TUN_RING_MONITOR_H */
