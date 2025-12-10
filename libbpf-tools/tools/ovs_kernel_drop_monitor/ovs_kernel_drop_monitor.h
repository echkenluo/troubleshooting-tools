// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_kernel_drop_monitor - OVS kernel module drop monitoring
// Shared types between BPF and userspace

#ifndef __OVS_KERNEL_DROP_MONITOR_H
#define __OVS_KERNEL_DROP_MONITOR_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16
#define MAX_STACK_DEPTH 32

/* OVS drop reasons */
enum ovs_drop_reason {
    OVS_DROP_UNKNOWN = 0,
    OVS_DROP_ACTION_ERROR,
    OVS_DROP_EXPLICIT,
    OVS_DROP_IP_TTL,
    OVS_DROP_FRAG,
    OVS_DROP_CONNTRACK,
    OVS_DROP_TUNNEL_ERROR,
    OVS_DROP_HEADROOM,
    OVS_DROP_MAX
};

/* OVS drop event */
struct ovs_drop_event {
    __u64 timestamp;
    __u32 pid;
    __u32 drop_reason;
    __u32 ifindex;
    __u32 dp_ifindex;
    __u8 protocol;
    __u8 pad[3];
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __s32 stack_id;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    char dp_name[IFNAMSIZ];
};

/* Stats key */
struct ovs_drop_key {
    __u32 drop_reason;
    __u32 stack_id;
};

/* Stats value */
struct ovs_drop_stats {
    __u64 count;
    __u64 bytes;
    __u64 last_timestamp;
};

#endif /* __OVS_KERNEL_DROP_MONITOR_H */
