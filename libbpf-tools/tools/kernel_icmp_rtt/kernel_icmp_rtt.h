// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kernel_icmp_rtt - ICMP RTT tracer for kernel network stack
// Shared types between BPF and userspace

#ifndef __KERNEL_ICMP_RTT_H
#define __KERNEL_ICMP_RTT_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_STAGES      6
#define MAX_STACK_DEPTH 50

/* Stage definitions */
/* Path 1 stages (Request path) */
#define PATH1_STAGE_0   0   /* TX: ip_local_out / RX: __netif_receive_skb */
#define PATH1_STAGE_1   1   /* TX: dev_queue_xmit / RX: ip_rcv */
#define PATH1_STAGE_2   2   /* (unused for TX) / RX: icmp_rcv */

/* Path 2 stages (Reply path) */
#define PATH2_STAGE_0   3   /* TX: __netif_receive_skb / RX: ip_local_out */
#define PATH2_STAGE_1   4   /* TX: ip_rcv / RX: ip_local_out */
#define PATH2_STAGE_2   5   /* TX: icmp_rcv / RX: dev_queue_xmit */

/* Direction constants */
#define DIRECTION_TX    0   /* Local pings remote */
#define DIRECTION_RX    1   /* Remote pings local */

/* ICMP types */
#define ICMP_ECHO       8
#define ICMP_ECHOREPLY  0

/* Packet key for flow tracking */
struct icmp_packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 proto;
    __u8 pad;
    __be16 id;
    __be16 seq;
    __u16 pad2;
};

/* Flow data structure */
struct icmp_flow_data {
    __u64 ts[MAX_STAGES];
    __s32 kstack_id[MAX_STAGES];

    __u32 p1_pid;
    char p1_comm[TASK_COMM_LEN];
    char p1_ifname[IFNAMSIZ];

    __u32 p2_pid;
    char p2_comm[TASK_COMM_LEN];
    char p2_ifname[IFNAMSIZ];

    __u8 request_type;
    __u8 reply_type;
    __u8 saw_path1_start;
    __u8 saw_path1_end;
    __u8 saw_path2_start;
    __u8 saw_path2_end;
    __u8 pad[2];
};

/* Event structure for userspace */
struct icmp_rtt_event {
    struct icmp_packet_key key;
    struct icmp_flow_data data;
};

#endif /* __KERNEL_ICMP_RTT_H */
