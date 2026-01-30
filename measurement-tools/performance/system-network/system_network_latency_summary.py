#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
System Network Latency Summary Tool

Measures total end-to-end latency and per-flow latency distribution through the
system network stack. Supports optional per-stage adjacent latency breakdown.

Default mode: Only total latency with per-flow statistics (minimal probes).
Stage mode (--stage-latency): Adds per-stage adjacent latency measurement.

Based on:
- system_network_latency_details.py: Stage definitions and probe points
- vm_network_latency_summary.py: Histogram aggregation architecture

Usage:
    sudo ./system_network_latency_summary.py --phy-interface enp94s0f0np0 \
                                --src-ip 70.0.0.33 --direction tx --interval 5
    sudo ./system_network_latency_summary.py --phy-interface enp94s0f0np0 \
                                --direction tx --stage-latency --sort-by p90 --top 20

"""

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)

from time import sleep, strftime, time as time_time
import argparse
import ctypes
import socket
import struct
import os
import sys
import datetime
import fcntl
import signal

# Global configuration
direction_filter = 1  # 1=tx (System->Physical), 2=rx (Physical->System)

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/flow.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

struct net;
struct inet_cork;

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP, 1=ICMP
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define DIRECTION_FILTER %d  // 1=tx, 2=rx
#define STAGE_LATENCY_MODE %d  // 0=total-only, 1=per-stage breakdown

// Stage definitions - from system_network_latency_details.py
// TX direction stages (System -> Physical)
#define TX_STAGE_0    0  // ip_queue_xmit (TCP) / ip_send_skb (UDP)
#define TX_STAGE_1    1  // internal_dev_xmit
#define TX_STAGE_2    2  // ovs_dp_process_packet
#define TX_STAGE_3    3  // ovs_dp_upcall
#define TX_STAGE_4    4  // ovs_flow_key_extract_userspace
#define TX_STAGE_5    5  // ovs_vport_send
#define TX_STAGE_6    6  // net_dev_xmit (physical)

// RX direction stages (Physical -> System)
#define RX_STAGE_0    7  // __netif_receive_skb (physical)
#define RX_STAGE_1    8  // netdev_frame_hook
#define RX_STAGE_2    9  // ovs_dp_process_packet
#define RX_STAGE_3    10 // ovs_dp_upcall
#define RX_STAGE_4    11 // ovs_flow_key_extract_userspace
#define RX_STAGE_5    12 // ovs_vport_send
#define RX_STAGE_6    13 // tcp_v4_rcv/udp_rcv/icmp_rcv (protocol specific)

#define MAX_STAGES               14
#define IFNAMSIZ                 16

// Packet key structure - same as system_network_latency_details.py
struct packet_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    u8 protocol;
    u8 pad[3];

    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;          // TCP sequence number
        } tcp;

        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;        // IP identification
            __be16 udp_len;
            __be16 frag_off;     // Fragment offset
        } udp;

        struct {
            __be16 id;
            __be16 sequence;
            u8 type;
            u8 code;
            u8 pad2[2];
        } icmp;
    };
};

// Flow tracking - minimal for summary mode
struct flow_data_t {
    u64 first_timestamp;               // Timestamp of first stage (for total latency)
    u64 last_timestamp;                // Timestamp of last stage
    u8 direction;                      // 1=tx, 2=rx
    u8 last_stage;                     // Last valid stage seen
    u8 pad[4];                         // Padding for alignment
};

// Stage pair key for histogram with latency bucket
struct stage_pair_key_t {
    u8 prev_stage;
    u8 curr_stage;
    u8 direction;
    u8 latency_bucket;  // log2 of latency in microseconds
};

// Per-flow aggregation key (5-tuple)
struct flow_key_t {
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    u8  protocol;
    u8  pad[3];
};

struct flow_bucket_key_t {
    struct flow_key_t flow;
    u8  latency_bucket;   // log2(us)
    u8  pad[3];
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);

#if STAGE_LATENCY_MODE
// BPF Histogram for adjacent stage latencies
BPF_HISTOGRAM(adjacent_latency_hist, struct stage_pair_key_t, 1024);
#endif

// BPF Histogram for total end-to-end latency
BPF_HISTOGRAM(total_latency_hist, u8, 256);

// BPF Histogram for per-flow total latency
BPF_HISTOGRAM(flow_total_hist, struct flow_bucket_key_t, 10240);

// Performance statistics
BPF_ARRAY(packet_counters, u64, 4);  // 0=total, 1=tx, 2=rx, 3=dropped
BPF_ARRAY(flow_stage_counters, u64, 4);  // 0=first_stage_tx, 1=last_stage_tx, 2=first_stage_rx, 3=last_stage_rx

// Helper function to check if an interface index matches our targets
static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }

    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }

    return (ifindex == TARGET_IFINDEX1 || ifindex == TARGET_IFINDEX2);
}

// Helper functions for packet parsing - from system_network_latency_details.py
static __always_inline int get_ip_header(struct sk_buff *skb, struct iphdr *ip, u8 stage_id) {
    unsigned char *head;
    u16 network_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        return -1;
    }

    if (bpf_probe_read_kernel(ip, sizeof(*ip), head + network_header_offset) < 0) {
        return -1;
    }

    return 0;
}

static __always_inline int get_transport_header(struct sk_buff *skb, void *hdr, u16 hdr_size, u8 stage_id) {
    unsigned char *head;
    u16 transport_header_offset;
    u16 network_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
        // Calculate transport header offset from IP header
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
            return -1;
        }
        u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5) return -1;
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    if (bpf_probe_read_kernel(hdr, hdr_size, head + transport_header_offset) < 0) {
        return -1;
    }

    return 0;
}

// TCP protocol parsing
static __always_inline int parse_tcp_key(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id
) {
    struct tcphdr tcp;
    if (get_transport_header(skb, &tcp, sizeof(tcp), stage_id) != 0) return 0;

    key->tcp.src_port = tcp.source;
    key->tcp.dst_port = tcp.dest;
    key->tcp.seq = tcp.seq;

    return 1;
}

// UDP protocol parsing
static __always_inline int parse_udp_key(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) != 0) return 0;

    key->udp.ip_id = ip.id;

    // Get fragmentation information
    struct udphdr udp = {};
    if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
        key->udp.src_port = udp.source;
        key->udp.dst_port = udp.dest;
        key->udp.udp_len = udp.len;
    } else {
        key->udp.src_port = 0;
        key->udp.dst_port = 0;
        key->udp.udp_len = 0;
    }

    return 1;
}

// Specialized parsing function for userspace SKB
static __always_inline int parse_packet_key_userspace(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id,
    u8 direction
) {
    if (skb == NULL) {
        return 0;
    }

    unsigned char *skb_head;
    if(bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0) {
        return 0;
    }
    if (!skb_head) {
        return 0;
    }

    unsigned long skb_data_ptr_val;
    if(bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 0;
    }

    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);
    unsigned int mac_offset = data_offset;

    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset) < 0) {
        return 0;
    }

    unsigned int net_offset = mac_offset + ETH_HLEN;
    __be16 h_proto = eth.h_proto;

    // Handle VLAN tags
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        net_offset += VLAN_HLEN;
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2) < 0) {
            return 0;
        }
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
             net_offset += VLAN_HLEN;
             if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + (2 * VLAN_HLEN) + 2) < 0) {
                 return 0;
             }
        }
    }

    if (h_proto != htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), skb_head + net_offset) < 0) {
        return 0;
    }

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    // Apply filters
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }

    // Apply IP filters
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
        return 0;
    }

    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) {
        return 0;
    }

    unsigned int trans_offset = net_offset + (ip_ihl * 4);

    // Parse transport layer
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + trans_offset) < 0) {
                return 0;
            }
            key->tcp.src_port = tcp.source;
            key->tcp.dst_port = tcp.dest;
            key->tcp.seq = tcp.seq;

            if (SRC_PORT_FILTER != 0 && key->tcp.src_port != htons(SRC_PORT_FILTER) && key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.src_port != htons(DST_PORT_FILTER) && key->tcp.dst_port != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            key->udp.ip_id = ip.id;

            u16 frag_off_flags = ntohs(ip.frag_off);
            u8 more_frag = (frag_off_flags & 0x2000) ? 1 : 0;
            u16 frag_offset = frag_off_flags & 0x1FFF;
            u8 is_fragment = (more_frag || frag_offset) ? 1 : 0;

            if (is_fragment) {
                key->udp.frag_off = frag_offset * 8;
                if (frag_offset == 0) {
                    struct udphdr udp;
                    if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) == 0) {
                        key->udp.src_port = udp.source;
                        key->udp.dst_port = udp.dest;
                    } else {
                        key->udp.src_port = 0;
                        key->udp.dst_port = 0;
                    }
                } else {
                    key->udp.src_port = 0;
                    key->udp.dst_port = 0;
                }
            } else {
                key->udp.frag_off = 0;
                struct udphdr udp;
                if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) < 0) {
                    return 0;
                }
                key->udp.src_port = udp.source;
                key->udp.dst_port = udp.dest;
            }

            if (!is_fragment || frag_offset == 0) {
                if (SRC_PORT_FILTER != 0 && key->udp.src_port != htons(SRC_PORT_FILTER) && key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                    return 0;
                }
                if (DST_PORT_FILTER != 0 && key->udp.src_port != htons(DST_PORT_FILTER) && key->udp.dst_port != htons(DST_PORT_FILTER)) {
                    return 0;
                }
            }

            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr icmp;
            if (bpf_probe_read_kernel(&icmp, sizeof(icmp), skb_head + trans_offset) < 0) {
                return 0;
            }
            key->icmp.id = icmp.un.echo.id;
            key->icmp.sequence = icmp.un.echo.sequence;
            key->icmp.type = icmp.type;
            key->icmp.code = icmp.code;
            break;
        }
        default:
            return 0;
    }

    return 1;
}

static __always_inline int parse_packet_key(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id,
    u8 direction
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) != 0) {
        return 0;
    }

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }

    // Apply IP filters
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
        return 0;
    }

    switch (ip.protocol) {
        case IPPROTO_TCP:
            if (!parse_tcp_key(skb, key, stage_id)) return 0;
            if (SRC_PORT_FILTER != 0 && key->tcp.src_port != htons(SRC_PORT_FILTER) && key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.src_port != htons(DST_PORT_FILTER) && key->tcp.dst_port != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        case IPPROTO_UDP:
            if (!parse_udp_key(skb, key, stage_id)) return 0;
            if (key->udp.frag_off == 0) {
                if (SRC_PORT_FILTER != 0 && key->udp.src_port != htons(SRC_PORT_FILTER) && key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                    return 0;
                }
                if (DST_PORT_FILTER != 0 && key->udp.src_port != htons(DST_PORT_FILTER) && key->udp.dst_port != htons(DST_PORT_FILTER)) {
                    return 0;
                }
            }
            break;
        case IPPROTO_ICMP: {
            struct icmphdr icmp;
            if (get_transport_header(skb, &icmp, sizeof(icmp), stage_id) != 0) return 0;
            key->icmp.id = icmp.un.echo.id;
            key->icmp.sequence = icmp.un.echo.sequence;
            key->icmp.type = icmp.type;
            key->icmp.code = icmp.code;
            break;
        }
        default:
            return 0;
    }

    return 1;
}

// TCP early stage parsing - from __ip_queue_xmit with sock parameter
static __always_inline int parse_packet_key_tcp_early(
    struct sk_buff *skb,
    struct sock *sk,
    struct packet_key_t *key,
    u8 stage_id
) {
    if (!sk) return 0;

    // Get from socket
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&key->src_ip, sizeof(key->src_ip), &inet->inet_saddr);
    bpf_probe_read_kernel(&key->dst_ip, sizeof(key->dst_ip), &inet->inet_daddr);
    bpf_probe_read_kernel(&key->tcp.src_port, sizeof(key->tcp.src_port), &inet->inet_sport);
    bpf_probe_read_kernel(&key->tcp.dst_port, sizeof(key->tcp.dst_port), &inet->inet_dport);

    key->protocol = IPPROTO_TCP;

    // Apply filters
    if (PROTOCOL_FILTER != 0 && key->protocol != PROTOCOL_FILTER) {
        return 0;
    }

    if (SRC_IP_FILTER != 0 && key->src_ip != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && key->dst_ip != DST_IP_FILTER) {
        return 0;
    }

    // Get TCP sequence number
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u32 tcp_snd_nxt = 0;
    u32 tcp_write_seq = 0;

    int snd_nxt_ret = bpf_probe_read_kernel(&tcp_snd_nxt, sizeof(tcp_snd_nxt), &tp->snd_nxt);
    int write_seq_ret = bpf_probe_read_kernel(&tcp_write_seq, sizeof(tcp_write_seq), &tp->write_seq);

    if (snd_nxt_ret >= 0 && tcp_snd_nxt != 0) {
        key->tcp.seq = htonl(tcp_snd_nxt);
    } else if (write_seq_ret >= 0 && tcp_write_seq != 0) {
        key->tcp.seq = htonl(tcp_write_seq);
    } else {
        // Fallback: try from SKB data
        unsigned char *data;
        if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) >= 0 && data) {
            struct iphdr ip;
            if (bpf_probe_read_kernel(&ip, sizeof(ip), data) >= 0) {
                u8 ip_ihl = (ip.ihl & 0x0F);
                if (ip_ihl >= 5) {
                    struct tcphdr tcp;
                    if (bpf_probe_read_kernel(&tcp, sizeof(tcp), data + (ip_ihl * 4)) >= 0) {
                        key->tcp.seq = tcp.seq;
                    }
                }
            }
        }
    }

    // Apply port filters
    if (SRC_PORT_FILTER != 0 && key->tcp.src_port != htons(SRC_PORT_FILTER) && key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
        return 0;
    }
    if (DST_PORT_FILTER != 0 && key->tcp.src_port != htons(DST_PORT_FILTER) && key->tcp.dst_port != htons(DST_PORT_FILTER)) {
        return 0;
    }

    return 1;
}

// Main event handling function - adjacent stage tracking only
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb, u8 stage_id, u8 direction) {
    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();

    // Parse packet key
    int parse_success = 0;
    if (stage_id == TX_STAGE_4 || stage_id == RX_STAGE_4) {
        parse_success = parse_packet_key_userspace(skb, &key, stage_id, direction);
    } else {
        parse_success = parse_packet_key(skb, &key, stage_id, direction);
    }

    if (!parse_success) {
        return;
    }

    // Check if this is the first stage for this direction
    bool is_first_stage = false;
    if ((direction == 1 && stage_id == TX_STAGE_0) ||
        (direction == 2 && stage_id == RX_STAGE_0)) {
        is_first_stage = true;
    }

    struct flow_data_t *flow_ptr;

    if (is_first_stage) {
        // Initialize new flow tracking
        struct flow_data_t zero = {};
        zero.direction = direction;
        zero.last_stage = stage_id;
        zero.last_timestamp = current_ts;
        zero.first_timestamp = current_ts;

        flow_sessions.delete(&key);
        flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);

        if (flow_ptr) {
            u32 idx = direction;
            u64 *counter = packet_counters.lookup(&idx);
            if (counter) (*counter)++;

            // Count first stage
            u32 first_stage_idx = (direction == 1) ? 0 : 2;
            u64 *first_counter = flow_stage_counters.lookup(&first_stage_idx);
            if (first_counter) (*first_counter)++;
        }
        return;
    } else {
        flow_ptr = flow_sessions.lookup(&key);
    }

    if (!flow_ptr) {
        flow_sessions.delete(&key);
        return;
    }

#if STAGE_LATENCY_MODE
    // Calculate and submit latency for adjacent stages
    if (flow_ptr->last_timestamp > 0 && flow_ptr->last_timestamp < current_ts) {
        u64 prev_ts = flow_ptr->last_timestamp;
        u64 latency_ns = current_ts - prev_ts;
        u64 latency_us = latency_ns / 1000;

        struct stage_pair_key_t pair_key = {};
        pair_key.prev_stage = flow_ptr->last_stage;
        pair_key.curr_stage = stage_id;
        pair_key.direction = direction;
        pair_key.latency_bucket = bpf_log2l(latency_us + 1);

        adjacent_latency_hist.increment(pair_key, 1);
    }

    // Update tracking for next stage
    flow_ptr->last_stage = stage_id;
    flow_ptr->last_timestamp = current_ts;
#endif

    // Check if this is the last stage
    bool is_last_stage = false;
    if ((direction == 1 && stage_id == TX_STAGE_6) ||
        (direction == 2 && stage_id == RX_STAGE_6)) {
        is_last_stage = true;

        // Calculate total latency from first to last stage
        if (flow_ptr->first_timestamp > 0 && current_ts > flow_ptr->first_timestamp) {
            u64 total_latency = current_ts - flow_ptr->first_timestamp;

            u64 latency_us = total_latency / 1000;
            if (latency_us > 0) {
                u8 log2_latency = bpf_log2l(latency_us);
                total_latency_hist.increment(log2_latency);

                // Per-flow total latency histogram
                struct flow_bucket_key_t fb_key = {};
                fb_key.flow.sip = key.src_ip;
                fb_key.flow.dip = key.dst_ip;
                fb_key.flow.protocol = key.protocol;
                if (key.protocol == IPPROTO_TCP) {
                    fb_key.flow.sport = key.tcp.src_port;
                    fb_key.flow.dport = key.tcp.dst_port;
                } else if (key.protocol == IPPROTO_UDP) {
                    fb_key.flow.sport = key.udp.src_port;
                    fb_key.flow.dport = key.udp.dst_port;
                } else if (key.protocol == IPPROTO_ICMP) {
                    fb_key.flow.sport = key.icmp.id;
                    fb_key.flow.dport = key.icmp.sequence;
                }
                fb_key.latency_bucket = log2_latency;
                flow_total_hist.increment(fb_key, 1);
            }
        }

        // Count last stage
        u32 last_stage_idx = (direction == 1) ? 1 : 3;
        u64 *last_counter = flow_stage_counters.lookup(&last_stage_idx);
        if (last_counter) (*last_counter)++;

        // Delete flow session
        flow_sessions.delete(&key);
    }
}

// TX Stage 0: TCP __ip_queue_xmit - with special parsing
static __always_inline void handle_stage_event_tcp_early(
    void *ctx,
    struct sock *sk,
    struct sk_buff *skb,
    u8 stage_id,
    u8 direction
) {
    struct packet_key_t key = {};
    if (!parse_packet_key_tcp_early(skb, sk, &key, stage_id)) {
        return;
    }

    u64 current_ts = bpf_ktime_get_ns();

    // Initialize flow (TX_STAGE_0 is first stage)
    struct flow_data_t zero = {};
    zero.direction = direction;
    zero.last_stage = stage_id;
    zero.last_timestamp = current_ts;
    zero.first_timestamp = current_ts;

    flow_sessions.delete(&key);
    struct flow_data_t *flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);

    if (flow_ptr) {
        u32 idx = direction;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;

        // Count first stage
        u32 first_stage_idx = (direction == 1) ? 0 : 2;
        u64 *first_counter = flow_stage_counters.lookup(&first_stage_idx);
        if (first_counter) (*first_counter)++;
    }
}

// ========== Probe Points - from system_network_latency_details.py ==========

// TX Stage 0: TCP __ip_queue_xmit
int kprobe____ip_queue_xmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, struct flowi *fl) {
    if (DIRECTION_FILTER == 2) return 0;  // rx only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_TCP) return 0;

    handle_stage_event_tcp_early(ctx, sk, skb, TX_STAGE_0, 1);
    return 0;
}

// TX Stage 0: UDP/ICMP ip_send_skb
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 2) return 0;  // rx only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_UDP && PROTOCOL_FILTER != IPPROTO_ICMP) return 0;

    handle_stage_event(ctx, skb, TX_STAGE_0, 1);
    return 0;
}

#if STAGE_LATENCY_MODE
// TX Stage 1: internal_dev_xmit
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 2) return 0;
    handle_stage_event(ctx, skb, TX_STAGE_1, 1);
    return 0;
}

// OVS processing stages (common for TX/RX)
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, TX_STAGE_2, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, RX_STAGE_2, 2);
    }
    return 0;
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, TX_STAGE_3, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, RX_STAGE_3, 2);
    }
    return 0;
}

int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) return 0;
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, TX_STAGE_4, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, RX_STAGE_4, 2);
    }
    return 0;
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, TX_STAGE_5, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, RX_STAGE_5, 2);
    }
    return 0;
}
#endif

// TX Stage 6: net_dev_xmit tracepoint
RAW_TRACEPOINT_PROBE(net_dev_xmit) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    if (!is_target_ifindex(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0;  // rx only
    handle_stage_event(ctx, skb, TX_STAGE_6, 1);
    return 0;
}

// RX Stage 0: netif_receive_skb tracepoint
TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    if (!is_target_ifindex(skb)) return 0;
    if (DIRECTION_FILTER == 1) return 0;  // tx only

    handle_stage_event(args, skb, RX_STAGE_0, 2);
    return 0;
}

#if STAGE_LATENCY_MODE
// RX Stage 1: netdev_frame_hook
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    struct sk_buff *skb = NULL;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || skb == NULL) {
        return 0;
    }

    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, RX_STAGE_1, 2);
    }
    return 0;
}
#endif

// RX Stage 6: tcp_v4_rcv
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 1) return 0;  // tx only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_TCP) return 0;
    handle_stage_event(ctx, skb, RX_STAGE_6, 2);
    return 0;
}

// RX Stage 6: __udp4_lib_rcv
int kprobe____udp4_lib_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct udp_table *udptable) {
    if (DIRECTION_FILTER == 1) return 0;  // tx only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_UDP) return 0;
    handle_stage_event(ctx, skb, RX_STAGE_6, 2);
    return 0;
}

// RX Stage 6: icmp_rcv
int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 1) return 0;  // tx only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_ICMP) return 0;
    handle_stage_event(ctx, skb, RX_STAGE_6, 2);
    return 0;
}

"""

# Constants
MAX_STAGES = 14

# Helper Functions
def get_if_index(devname):
    """Get the interface index for a device name"""
    SIOCGIFINDEX = 0x8933
    if len(devname.encode('ascii')) > 15:
        raise OSError("Interface name '%s' too long" % devname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('16s%dx' % (256-16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    except IOError as e:
        raise OSError("ioctl failed for interface '%s': %s" % (devname, e))
    finally:
        s.close()

def ip_to_hex(ip_str):
    """Convert IP string to network-ordered hex value"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def get_stage_name(stage_id):
    """Get human-readable stage name"""
    stage_names = {
        # TX path
        0: "TX_S0_ip_layer_entry",
        1: "TX_S1_internal_dev_xmit",
        2: "TX_S2_ovs_dp_process",
        3: "TX_S3_ovs_dp_upcall",
        4: "TX_S4_ovs_flow_key_extract",
        5: "TX_S5_ovs_vport_send",
        6: "TX_S6_net_dev_xmit",

        # RX path
        7: "RX_S0_netif_receive_skb",
        8: "RX_S1_netdev_frame_hook",
        9: "RX_S2_ovs_dp_process",
        10: "RX_S3_ovs_dp_upcall",
        11: "RX_S4_ovs_flow_key_extract",
        12: "RX_S5_ovs_vport_send",
        13: "RX_S6_tcp_v4_rcv/udp_rcv/icmp_rcv"
    }
    return stage_names.get(stage_id, "UNKNOWN_%d" % stage_id)

def format_protocol(proto):
    """Convert protocol number to name"""
    proto_names = {6: "TCP", 17: "UDP", 1: "ICMP"}
    return proto_names.get(proto, "PROTO_%d" % proto)

def bucket_range_str(bucket):
    """Convert log2 bucket to human-readable latency range string"""
    if bucket == 0:
        return "1us"
    low = 1 << (bucket - 1)
    high = (1 << bucket) - 1
    if low >= 1000000:
        return "%gs-%gs" % (low / 1000000.0, high / 1000000.0)
    elif low >= 1000:
        return "%g-%gms" % (low / 1000.0, high / 1000.0)
    return "%d-%dus" % (low, high)

def bucket_midpoint_us(bucket):
    """Approximate midpoint of a log2 bucket in microseconds"""
    if bucket == 0:
        return 0.5
    return 1.5 * (1 << (bucket - 1))

def compute_flow_stats(bucket_counts):
    """Compute statistics from a dict of {bucket: count}."""
    total = sum(bucket_counts.values())
    if total == 0:
        return None

    sorted_buckets = sorted(bucket_counts.items())
    min_bucket = sorted_buckets[0][0]
    max_bucket = sorted_buckets[-1][0]

    weighted_sum = sum(bucket_midpoint_us(b) * c for b, c in sorted_buckets)
    avg = weighted_sum / total

    percentiles = {"p50": 0.50, "p90": 0.90, "p99": 0.99}
    result = {"count": total, "avg": avg, "min_bucket": min_bucket, "max_bucket": max_bucket}

    cumulative = 0
    pct_keys = sorted(percentiles.keys(), key=lambda k: percentiles[k])
    pct_idx = 0
    for bucket, count in sorted_buckets:
        cumulative += count
        while pct_idx < len(pct_keys) and cumulative >= percentiles[pct_keys[pct_idx]] * total:
            result[pct_keys[pct_idx]] = bucket
            pct_idx += 1
    while pct_idx < len(pct_keys):
        result[pct_keys[pct_idx]] = max_bucket
        pct_idx += 1

    return result

def print_per_flow_stats(b, sort_by, top_n):
    """Read flow_total_hist and print per-flow latency statistics"""
    flow_hist = b["flow_total_hist"]

    flow_data = {}
    for k, v in flow_hist.items():
        fk = k.flow
        flow_tuple = (fk.sip, fk.dip, fk.sport, fk.dport, fk.protocol)
        bucket = k.latency_bucket
        count = v.value if hasattr(v, 'value') else int(v)
        if count <= 0:
            continue
        if flow_tuple not in flow_data:
            flow_data[flow_tuple] = {}
        flow_data[flow_tuple][bucket] = count

    if not flow_data:
        print("\n  No per-flow total latency data collected in this interval")
        return

    flow_stats = []
    for flow_tuple, buckets in flow_data.items():
        stats = compute_flow_stats(buckets)
        if stats:
            flow_stats.append((flow_tuple, stats, buckets))

    sort_key_map = {
        "count": lambda x: x[1]["count"],
        "avg":   lambda x: x[1]["avg"],
        "p90":   lambda x: x[1].get("p90", 0),
        "p99":   lambda x: x[1].get("p99", 0),
    }
    key_fn = sort_key_map.get(sort_by, sort_key_map["count"])
    flow_stats.sort(key=key_fn, reverse=True)

    shown = min(top_n, len(flow_stats))
    print("\nPer-Flow Total Latency Statistics (approx values from log2 histogram):")
    print("  Flows: %d, Sorted by: %s (desc), Showing top %d" % (len(flow_stats), sort_by, shown))

    for idx, (flow_tuple, stats, buckets) in enumerate(flow_stats[:shown]):
        sip, dip, sport, dport, proto = flow_tuple
        sip_str = format_ip(sip)
        dip_str = format_ip(dip)
        proto_str = format_protocol(proto)

        sport_h = socket.ntohs(sport)
        dport_h = socket.ntohs(dport)

        if proto == 1:  # ICMP: sport=id, dport=seq
            flow_label = "%s -> %s (%s id=%d seq=%d)" % (
                sip_str, dip_str, proto_str, sport_h, dport_h)
        else:
            flow_label = "%s:%d -> %s:%d (%s)" % (
                sip_str, sport_h, dip_str, dport_h, proto_str)

        avg_str = "%dus" % int(stats["avg"]) if stats["avg"] < 1000 else "%.1fms" % (stats["avg"] / 1000)
        p50_str = bucket_range_str(stats["p50"])
        p90_str = bucket_range_str(stats["p90"])
        p99_str = bucket_range_str(stats["p99"])
        min_str = bucket_range_str(stats["min_bucket"])
        max_str = bucket_range_str(stats["max_bucket"])

        print("\n  #%d  %s" % (idx + 1, flow_label))
        print("      Count: %-6d Avg~: %-8s P50~: %-12s P90~: %-12s P99~: %-12s Min: %-12s Max: %s" % (
            stats["count"], avg_str, p50_str, p90_str, p99_str, min_str, max_str))

        sorted_buckets = sorted(buckets.items())
        max_count = max(buckets.values())
        print("      Latency distribution:")
        for bucket, count in sorted_buckets:
            if count > 0:
                range_str = bucket_range_str(bucket)
                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                print("        %-12s: %6d |%-40s|" % (range_str, count, bar))

def _print_counters_and_total(b, sort_by, top_n):
    """Print packet counters, total latency histogram, and per-flow stats"""
    counters = b["packet_counters"]
    print("\nPacket Counters:")
    print("  TX packets: %d" % counters[1].value)
    print("  RX packets: %d" % counters[2].value)

    flow_counters = b["flow_stage_counters"]
    first_stage_tx = flow_counters[0].value
    last_stage_tx = flow_counters[1].value
    first_stage_rx = flow_counters[2].value
    last_stage_rx = flow_counters[3].value

    incomplete_tx_count = first_stage_tx - last_stage_tx
    incomplete_rx_count = first_stage_rx - last_stage_rx

    print("\nFlow Session Analysis:")
    if first_stage_tx > 0:
        print("  TX started: %d, completed: %d, incomplete: %d (%.2f%%)" % (
            first_stage_tx, last_stage_tx, incomplete_tx_count,
            100.0 * incomplete_tx_count / first_stage_tx if first_stage_tx > 0 else 0))
    if first_stage_rx > 0:
        print("  RX started: %d, completed: %d, incomplete: %d (%.2f%%)" % (
            first_stage_rx, last_stage_rx, incomplete_rx_count,
            100.0 * incomplete_rx_count / first_stage_rx if first_stage_rx > 0 else 0))

    total_active_flows = 0
    try:
        flow_sessions = b["flow_sessions"]
        total_active_flows = len(flow_sessions)
    except:
        total_active_flows = -1

    if total_active_flows >= 0:
        print("  Currently active flow sessions: %d" % total_active_flows)

    # Display total latency histogram
    print("\nTotal End-to-End Latency Distribution:")
    print("-" * 60)

    try:
        total_hist = b["total_latency_hist"]
        total_latency_data = {}

        for k, v in total_hist.items():
            bucket = k.value if hasattr(k, 'value') else int(k)
            count = v.value if hasattr(v, 'value') else int(v)
            if count > 0:
                total_latency_data[bucket] = count

        if total_latency_data:
            max_count = max(total_latency_data.values())

            for bucket in sorted(total_latency_data.keys()):
                count = total_latency_data[bucket]
                range_str = bucket_range_str(bucket)
                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                print("  %-12s: %6d |%-40s|" % (range_str, count, bar))
        else:
            print("  No total latency data collected in this interval")
    except Exception as e:
        print("  Error reading total latency histogram: %s" % str(e))

    # Per-flow total latency statistics
    try:
        print_per_flow_stats(b, sort_by, top_n)
    except Exception as e:
        print("  Error reading per-flow latency data: %s" % str(e))

    # Clear histograms for next interval
    try:
        b["total_latency_hist"].clear()
    except:
        pass
    try:
        b["flow_total_hist"].clear()
    except:
        pass

def print_histogram_summary(b, interval_start_time, sort_by="count", top_n=10, stage_latency=False):
    """Print histogram summary for the current interval"""
    current_time = datetime.datetime.now()
    print("\n" + "=" * 80)
    if stage_latency:
        print("[%s] Stage + Flow Latency Report (Interval: %.1fs)" % (
            current_time.strftime("%Y-%m-%d %H:%M:%S"),
            time_time() - interval_start_time
        ))
    else:
        print("[%s] Flow Latency Report (Interval: %.1fs)" % (
            current_time.strftime("%Y-%m-%d %H:%M:%S"),
            time_time() - interval_start_time
        ))
    print("=" * 80)

    if not stage_latency:
        _print_counters_and_total(b, sort_by, top_n)
        return

    # Get stage pair histogram data
    latency_hist = b["adjacent_latency_hist"]

    stage_pair_data = {}

    try:
        for k, v in latency_hist.items():
            pair_key = (k.prev_stage, k.curr_stage, k.direction)
            bucket = k.latency_bucket
            count = v.value if hasattr(v, 'value') else int(v)

            if pair_key not in stage_pair_data:
                stage_pair_data[pair_key] = {}
            stage_pair_data[pair_key][bucket] = count
    except Exception as e:
        print("Error reading histogram data:", str(e))
        return

    if not stage_pair_data:
        print("No adjacent stage data collected in this interval")
        return

    print("Found %d unique stage pairs" % len(stage_pair_data))

    sorted_pairs = sorted(stage_pair_data.keys(), key=lambda x: (x[2], x[0], x[1]))

    for direction in [1, 2]:
        dir_pairs = [p for p in sorted_pairs if p[2] == direction]
        if not dir_pairs:
            continue

        direction_str = "TX Direction (System -> Physical)" if direction == 1 else "RX Direction (Physical -> System)"
        print("\n%s:" % direction_str)
        print("-" * 60)

        for prev_stage, curr_stage, dir_val in dir_pairs:
            prev_name = get_stage_name(prev_stage)
            curr_name = get_stage_name(curr_stage)

            print("\n  %s -> %s:" % (prev_name, curr_name))

            buckets = stage_pair_data[(prev_stage, curr_stage, dir_val)]
            total_samples = sum(buckets.values())

            if total_samples == 0:
                print("    No samples")
                continue

            print("    Total samples: %d" % total_samples)
            print("    Latency distribution:")

            sorted_buckets = sorted(buckets.items())
            max_count = max(buckets.values())

            for bucket, count in sorted_buckets:
                if count > 0:
                    if bucket == 0:
                        range_str = "0-1us"
                    else:
                        low = 1 << (bucket - 1)
                        high = (1 << bucket) - 1
                        range_str = "%d-%dus" % (low, high)

                    bar_width = int(40 * count / max_count)
                    bar = "*" * bar_width

                    print("      %-12s: %6d |%-40s|" % (range_str, count, bar))

    _print_counters_and_total(b, sort_by, top_n)

    # Clear stage latency histogram for next interval
    latency_hist.clear()

def main():
    global direction_filter

    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="System Network Latency Summary Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor TCP TX traffic (total latency only, default):
    sudo %(prog)s --phy-interface enp94s0f0np0 --direction tx --protocol tcp --src-ip 70.0.0.33

  Monitor with per-stage latency breakdown:
    sudo %(prog)s --phy-interface enp94s0f0np0 --direction tx --protocol tcp --src-ip 70.0.0.33 --stage-latency

  Monitor all traffic with custom sort and top-N:
    sudo %(prog)s --phy-interface enp94s0f0np0 --direction tx --protocol all --interval 10 --sort-by p90 --top 20
"""
    )

    parser.add_argument('--phy-interface', type=str, required=True,
                        help='Physical interface to monitor (e.g., enp94s0f0np0)')
    parser.add_argument('--src-ip', type=str, required=False,
                        help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, required=False,
                        help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port filter (TCP/UDP)')
    parser.add_argument('--dst-port', type=int, required=False,
                        help='Destination port filter (TCP/UDP)')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'icmp', 'all'],
                        default='all', help='Protocol filter (default: all)')
    parser.add_argument('--direction', type=str, choices=['tx', 'rx'],
                        required=True, help='Direction filter: tx=System TX, rx=System RX')
    parser.add_argument('--interval', type=int, default=5,
                        help='Statistics output interval in seconds (default: 5)')
    parser.add_argument('--stage-latency', action='store_true',
                        help='Enable per-stage adjacent latency measurement (adds intermediate probes, higher overhead)')
    parser.add_argument('--top', type=int, default=10,
                        help='Number of top flows to display (default: 10)')
    parser.add_argument('--sort-by', type=str, choices=['count', 'avg', 'p90', 'p99'],
                        default='count', help='Sort per-flow stats by this metric (default: count)')

    args = parser.parse_args()

    # Convert parameters
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0

    protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'all': 0}
    protocol_filter = protocol_map[args.protocol]

    # Direction: 1=tx, 2=rx
    direction_map = {'tx': 1, 'rx': 2}
    direction_filter = direction_map[args.direction]

    stage_latency_mode = 1 if args.stage_latency else 0

    # Support multiple interfaces
    phy_interfaces = args.phy_interface.split(',')
    try:
        ifindex1 = get_if_index(phy_interfaces[0].strip())
        ifindex2 = get_if_index(phy_interfaces[1].strip()) if len(phy_interfaces) > 1 else ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    print("=== System Network Latency Summary Tool ===")
    print("Protocol filter: %s" % args.protocol.upper())
    print("Direction filter: %s (tx=System->Physical, rx=Physical->System)" % args.direction.upper())
    if args.src_ip:
        print("Source IP filter: %s" % args.src_ip)
    if args.dst_ip:
        print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("Physical interfaces: %s (ifindex %d, %d)" % (args.phy_interface, ifindex1, ifindex2))
    print("Statistics interval: %d seconds" % args.interval)
    if args.stage_latency:
        print("Mode: Stage + Flow latency (per-stage probes enabled)")
    else:
        print("Mode: Flow latency only (minimal probes)")
    print("Sort by: %s, Top: %d" % (args.sort_by, args.top))

    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, ifindex1, ifindex2, direction_filter,
            stage_latency_mode
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    print("\nCollecting latency data... Hit Ctrl-C to end.")
    print("Statistics will be displayed every %d seconds\n" % args.interval)

    # Setup signal handler for clean exit
    def signal_handler(sig, frame):
        print("\n\nFinal statistics:")
        print_histogram_summary(b, interval_start_time,
                                sort_by=args.sort_by, top_n=args.top,
                                stage_latency=args.stage_latency)
        print("\nExiting...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Main loop
    interval_start_time = time_time()

    try:
        while True:
            sleep(args.interval)
            print_histogram_summary(b, interval_start_time,
                                    sort_by=args.sort_by, top_n=args.top,
                                    stage_latency=args.stage_latency)
            interval_start_time = time_time()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
