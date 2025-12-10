// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// eth_drop - Network packet drop tracer
// Shared types between BPF and userspace

#ifndef __ETH_DROP_H
#define __ETH_DROP_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16
#define ETH_ALEN        6
#define MAX_STACK_DEPTH 50
#define PAYLOAD_LEN     32

/* Protocol type indicators */
#define PROTO_TYPE_OTHER    0
#define PROTO_TYPE_IPV4     1
#define PROTO_TYPE_IPV6     2
#define PROTO_TYPE_ARP      3
#define PROTO_TYPE_RARP     4

/* EtherType constants */
#define ETH_P_IP        0x0800
#define ETH_P_IPV6      0x86DD
#define ETH_P_ARP       0x0806
#define ETH_P_RARP      0x8035
#define ETH_P_8021Q     0x8100
#define ETH_P_LLDP      0x88CC
#define ETH_P_FLOW_CTRL 0x8808

/* L4 Protocol constants */
#define L4_PROTO_ALL    0
#define L4_PROTO_ICMP   1
#define L4_PROTO_TCP    6
#define L4_PROTO_UDP    17

/* Packet drop event structure */
struct drop_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __s32 stack_id;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];

    /* Ethernet fields */
    __u8 eth_src[ETH_ALEN];
    __u8 eth_dst[ETH_ALEN];
    __u16 eth_type;

    /* VLAN fields */
    __u16 vlan_id;
    __u16 vlan_priority;
    __u16 inner_protocol;
    __u8 has_vlan;

    /* Protocol type indicator */
    __u8 protocol_type;

    /* IPv4 fields */
    __u32 ipv4_saddr;
    __u32 ipv4_daddr;
    __u8 ipv4_protocol;
    __u8 ipv4_ttl;
    __u16 ipv4_id;
    __u16 ipv4_tot_len;
    __u8 ipv4_tos;
    __u8 pad1;
    __u16 ipv4_sport;
    __u16 ipv4_dport;

    /* IPv6 fields */
    __u8 ipv6_saddr[16];
    __u8 ipv6_daddr[16];
    __u8 ipv6_nexthdr;
    __u8 ipv6_hop_limit;
    __u16 ipv6_payload_len;

    /* ARP fields */
    __u16 arp_hrd;
    __u16 arp_pro;
    __u16 arp_op;
    __u8 arp_sha[ETH_ALEN];
    __u8 arp_sip[4];
    __u8 arp_tha[ETH_ALEN];
    __u8 arp_tip[4];

    /* Other protocol fields */
    __u16 other_ethertype;
    __u8 other_data[PAYLOAD_LEN];

    /* SKB debug fields */
    __u16 skb_mac_header;
    __u16 skb_network_header;
    __u16 skb_transport_header;
    __u32 skb_len;
    __u32 skb_data_len;

    /* Execution context */
    __u32 cpu_id;
    __u8 in_interrupt;
    __u8 pad2[3];
};

#endif /* __ETH_DROP_H */
