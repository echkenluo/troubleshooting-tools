// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_pair_latency - VM pair latency measurement
// Shared types between BPF and userspace

#ifndef __VM_PAIR_LATENCY_H
#define __VM_PAIR_LATENCY_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_SLOTS       26

/* Protocol constants */
#define PROTO_UDP       17

/* Flow key for tracking */
struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

/* Latency event */
struct latency_event {
    struct flow_key key;
    __u64 latency_ns;
    __u64 timestamp;
    __u32 src_ifindex;
    __u32 dst_ifindex;
    char src_ifname[IFNAMSIZ];
    char dst_ifname[IFNAMSIZ];
};

/* Histogram structure */
struct hist {
    __u64 slots[MAX_SLOTS];
};

#endif /* __VM_PAIR_LATENCY_H */
