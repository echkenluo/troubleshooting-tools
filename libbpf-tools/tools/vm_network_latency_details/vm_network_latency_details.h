// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_latency_details - VM Network detailed latency tracer
// Shared types between BPF and userspace

#ifndef __VM_NETWORK_LATENCY_DETAILS_H
#define __VM_NETWORK_LATENCY_DETAILS_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define MAX_STAGES      14
#define MAX_STACK_DEPTH 32
#define MAX_SLOTS       26

/* RX direction stages (VM -> Physical) */
#define RX_STAGE_0      0   /* netif_receive_skb (vnet) */
#define RX_STAGE_1      1   /* netdev_frame_hook */
#define RX_STAGE_2      2   /* ovs_dp_process_packet */
#define RX_STAGE_3      3   /* ovs_dp_upcall */
#define RX_STAGE_4      4   /* ovs_flow_key_extract_userspace */
#define RX_STAGE_5      5   /* ovs_vport_send */
#define RX_STAGE_6      6   /* __dev_queue_xmit (physical) */

/* TX direction stages (Physical -> VM) */
#define TX_STAGE_0      7   /* __netif_receive_skb (physical) */
#define TX_STAGE_1      8   /* netdev_frame_hook */
#define TX_STAGE_2      9   /* ovs_dp_process_packet */
#define TX_STAGE_3      10  /* ovs_dp_upcall */
#define TX_STAGE_4      11  /* ovs_flow_key_extract_userspace */
#define TX_STAGE_5      12  /* ovs_vport_send */
#define TX_STAGE_6      13  /* tun_net_xmit (vnet) */

/* Direction constants */
#define DIRECTION_RX    2   /* VM -> Physical (rx from VM) */
#define DIRECTION_TX    1   /* Physical -> VM (tx to VM) */

/* Protocol constants */
#define PROTO_TCP       6
#define PROTO_UDP       17
#define PROTO_ICMP      1

/* Packet key for flow tracking */
struct packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 protocol;
    __u8 pad[3];
    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;
            __be16 payload_len;
            __be16 pad;
        } tcp;
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;
            __be16 frag_off;
        } udp;
        struct {
            __be16 id;
            __be16 seq;
            __u8 type;
            __u8 code;
            __u8 pad[2];
        } icmp;
    };
};

/* Flow tracking data */
struct flow_data {
    __u64 first_seen_ns;
    __u64 ts[MAX_STAGES];
    __u64 skb_ptr[MAX_STAGES];
    __s32 kstack_id[MAX_STAGES];
    __u32 tx_pid;
    char tx_comm[TASK_COMM_LEN];
    char tx_pnic_ifname[IFNAMSIZ];
    __u32 rx_pid;
    char rx_comm[TASK_COMM_LEN];
    char rx_vnet_ifname[IFNAMSIZ];
    __u8 tx_start;
    __u8 tx_end;
    __u8 rx_start;
    __u8 rx_end;
    __u8 direction;
    __u8 pad[3];
};

/* Latency event for ring buffer output */
struct latency_event {
    struct packet_key key;
    struct flow_data data;
    __u64 event_ts;
};

#endif /* __VM_NETWORK_LATENCY_DETAILS_H */
