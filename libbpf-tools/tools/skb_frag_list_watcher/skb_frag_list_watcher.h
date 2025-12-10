// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// skb_frag_list_watcher - SKB frag_list change monitor
// Shared types between BPF and userspace

#ifndef __SKB_FRAG_LIST_WATCHER_H
#define __SKB_FRAG_LIST_WATCHER_H

#define TASK_COMM_LEN   16
#define FUNC_NAME_LEN   32

/* Event types */
#define EVENT_FRAG_LIST_CREATE    1
#define EVENT_FRAG_LIST_CLEAR     2
#define EVENT_FRAG_LIST_MODIFY    3
#define EVENT_FRAG_LIST_ACCESS    4
#define EVENT_GSO_INCONSISTENT    5

/* Event data structure */
struct frag_event {
    __u64 timestamp_ns;
    __u64 skb_addr;
    __u64 frag_list_before;
    __u64 frag_list_after;
    __u32 pid;
    __u32 cpu;
    __u16 gso_size;
    __u16 gso_segs;
    __u32 gso_type;
    __u8 nr_frags;
    __u8 event_type;
    __u8 cloned;
    __u8 pad;
    __u32 len;
    __u32 data_len;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    char func_name[FUNC_NAME_LEN];
    char comm[TASK_COMM_LEN];
    __s32 stack_id;
};

#endif /* __SKB_FRAG_LIST_WATCHER_H */
