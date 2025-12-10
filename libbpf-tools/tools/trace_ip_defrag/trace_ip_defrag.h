// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// trace_ip_defrag - IP fragmentation/defragmentation tracer
// Shared types between BPF and userspace

#ifndef __TRACE_IP_DEFRAG_H
#define __TRACE_IP_DEFRAG_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16

/* Fragment event types */
enum frag_event_type {
    FRAG_EVENT_RECV = 1,     /* Fragment received */
    FRAG_EVENT_COMPLETE,     /* Reassembly complete */
    FRAG_EVENT_TIMEOUT,      /* Reassembly timeout */
    FRAG_EVENT_DROP,         /* Fragment dropped */
};

/* Fragment event structure */
struct frag_event {
    __u64 timestamp;
    __u32 pid;
    __u32 event_type;
    __be32 src_ip;
    __be32 dst_ip;
    __u16 ip_id;
    __u16 frag_offset;
    __u16 total_len;
    __u16 data_len;
    __u8 protocol;
    __u8 more_frags;
    __u8 pad[2];
    __u32 ifindex;
    __s32 stack_id;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
};

/* Stats key for fragment tracking */
struct frag_stats_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u16 ip_id;
    __u16 pad;
};

/* Stats value */
struct frag_stats {
    __u64 fragments_recv;
    __u64 bytes_recv;
    __u64 reassembled;
    __u64 timeouts;
    __u64 drops;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
};

/* Global stats */
struct global_frag_stats {
    __u64 total_fragments;
    __u64 total_bytes;
    __u64 reassembled;
    __u64 timeouts;
    __u64 drops;
};

#endif /* __TRACE_IP_DEFRAG_H */
