// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_icmp_rtt - ICMP RTT measurement for system network
// Shared types between BPF and userspace

#ifndef __SYSTEM_NETWORK_ICMP_RTT_H
#define __SYSTEM_NETWORK_ICMP_RTT_H

#define TASK_COMM_LEN 16
#define IFNAMSIZ 16
#define MAX_STAGES 14

/* ICMP packet key */
struct icmp_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u16 id;
    __u16 seq;
};

/* RTT flow data */
struct rtt_flow_data {
    __u64 ts[MAX_STAGES];
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    __u8 request_type;
    __u8 reply_type;
    __u8 saw_request_start;
    __u8 saw_request_end;
    __u8 saw_reply_start;
    __u8 saw_reply_end;
    __u8 pad[3];
};

/* RTT event output */
struct rtt_event {
    struct icmp_key key;
    struct rtt_flow_data data;
};

/* Histogram key */
struct hist_key {
    __u32 bucket;
};

#endif /* __SYSTEM_NETWORK_ICMP_RTT_H */
