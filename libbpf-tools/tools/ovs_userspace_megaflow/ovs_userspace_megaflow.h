// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_userspace_megaflow - OVS userspace megaflow tracker
// Shared types between BPF and userspace

#ifndef __OVS_USERSPACE_MEGAFLOW_H
#define __OVS_USERSPACE_MEGAFLOW_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16
#define ETH_ALEN 6

/* Upcall event structure */
struct upcall_event {
    __u64 timestamp;
    __u32 pid;
    __u32 portid;
    __u8 eth_dst[ETH_ALEN];
    __u8 eth_src[ETH_ALEN];
    __u16 eth_type;
    __u8 protocol;
    __u8 pad;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u32 skb_mark;
    __u32 ifindex;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
};

/* Flow new event structure - for ovs_flow_cmd_new */
struct flow_new_event {
    __u64 timestamp;
    __u32 pid;
    __u32 netlink_portid;
    __u32 skb_len;
    __u32 data_len;
    char comm[TASK_COMM_LEN];
};

/* Stats key for upcall tracking */
struct upcall_stats_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 protocol;
    __u8 pad[3];
};

/* Stats value */
struct upcall_stats {
    __u64 count;
    __u64 bytes;
    __u64 last_timestamp;
};

#endif /* __OVS_USERSPACE_MEGAFLOW_H */
