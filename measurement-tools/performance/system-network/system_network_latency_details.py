#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
System Network TCP/UDP Latency Measurement Tool

This tool measures one-way network latency for system-level TCP/UDP traffic,
supporting packet-level tracking using protocol-specific unique identifiers.
It traces the complete network path from protocol stack through OVS to physical interfaces.

Based on:
- icmp_rtt_latency.py: probe point architecture and OVS path handling
- vm_network_latency.py: TCP/UDP packet identification and parsing logic

Usage:
    sudo ./system_tcp_udp_latency.py --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \
                                     --protocol tcp --direction tx \
                                     --phy-interface enp94s0f0np0
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

# Global variable for direction filter
direction_filter = 0  # 1=tx, 2=rx

# BPF Program - comprehensive implementation based on design document
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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

// IP fragment flags constants
#ifndef IP_MF
#define IP_MF 0x2000    // More Fragments flag
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF // Fragment offset mask
#endif

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define DIRECTION_FILTER %d  // 1=tx, 2=rx
#define LATENCY_THRESHOLD_NS %d  // Minimum latency threshold in nanoseconds

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
#define RX_STAGE_6    13 // tcp_v4_rcv/udp_rcv (protocol specific)

#define MAX_STAGES               14
#define IFNAMSIZ                 16
#define TASK_COMM_LEN            16

// Unified packet key structure supporting TCP/UDP protocols - from vm_network_latency.py
struct packet_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    u8 protocol;
    u8 pad[3];

    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;          // TCP sequence number (packet identifier)
        } tcp;

        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;        // IP identification
            __be16 udp_len;      // UDP length field
            __be16 frag_off;     // Fragment offset
        } udp;
    };

    u64 first_seen_ns;  // First capture timestamp (handle retransmissions)
};

// Structure to track TX/RX flow data and timestamps - based on icmp_rtt_latency.py
struct flow_data_t {
    u64 first_seen_ns;        // First capture timestamp (handle retransmissions)
    u64 ts[MAX_STAGES];
    u64 skb_ptr[MAX_STAGES];
    int kstack_id[MAX_STAGES];
    
    // Path1 info (TX for tx, RX for rx)
    u32 p1_pid;
    char p1_comm[TASK_COMM_LEN];
    char p1_ifname[IFNAMSIZ];
    
    // Path2 info (RX for tx, TX for rx)  
    u32 p2_pid;
    char p2_comm[TASK_COMM_LEN];
    char p2_ifname[IFNAMSIZ];
    
    // Protocol specific info
    u8 tcp_flags;
    u16 udp_len;
    
    // Flow state flags
    u8 saw_path1_start:1;
    u8 saw_path1_end:1;
    u8 saw_path2_start:1;
    u8 saw_path2_end:1;
};

// Structure for perf event output
struct event_data_t {
    struct packet_key_t key;
    struct flow_data_t data;
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch_map, struct event_data_t, 1);

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

// Helper functions for packet parsing - from vm_network_latency.py
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

// TCP protocol parsing - simplified and more robust
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

// UDP protocol parsing - from vm_network_latency.py
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

// Specialized parsing function for userspace SKB - from vm_network_latency.py
static __always_inline int parse_packet_key_userspace(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
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
    
    // Handle VLAN tags - exactly like icmp_rtt_latency.py
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

    // Apply IP filters - use exact matching for packet direction
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
            
            // Sequence number removed from key structure
            
            // Use same payload length bucketing as regular parsing
            u16 ip_len = ntohs(ip.tot_len);
            u16 ip_hdr_len = (ip.ihl & 0x0F) * 4;
            u16 tcp_hdr_len = (tcp.doff & 0x0F) * 4;
            if (tcp_hdr_len < 20) tcp_hdr_len = 20; // Minimum TCP header size
            
            u16 payload_len = 0;
            if (ip_len > ip_hdr_len + tcp_hdr_len) {
                payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
            }
            
            // Payload length removed from key structure
            
            if (SRC_PORT_FILTER != 0 && key->tcp.src_port != htons(SRC_PORT_FILTER) && key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.src_port != htons(DST_PORT_FILTER) && key->tcp.dst_port != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            // Set ip_id exactly like regular UDP parsing
            key->udp.ip_id = ip.id;
            
            // Fragment handling exactly like regular parsing
            u16 frag_off_flags = ntohs(ip.frag_off);
            u8 more_frag = (frag_off_flags & 0x2000) ? 1 : 0;  // More Fragments bit
            u16 frag_offset = frag_off_flags & 0x1FFF;          // Fragment offset (8-byte units)
            u8 is_fragment = (more_frag || frag_offset) ? 1 : 0;
            
            if (is_fragment) {
                key->udp.frag_off = frag_offset * 8;
                if (frag_offset == 0) {
                    // First fragment - parse UDP header
                    struct udphdr udp;
                    if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) == 0) {
                        key->udp.src_port = udp.source;
                        key->udp.dst_port = udp.dest;
                    } else {
                        key->udp.src_port = 0;
                        key->udp.dst_port = 0;
                    }
                } else {
                    // Subsequent fragments - no UDP header
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
            
            // Apply port filters only if not fragmented or is first fragment
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
        default:
            return 0;
    }
    
    return 1;
}

static __always_inline int parse_packet_key(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
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

    // Apply IP filters - use exact matching for packet direction
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
            if (key->udp.frag_off == 0) { // Only apply port filter for non-fragments or first fragment
                if (SRC_PORT_FILTER != 0 && key->udp.src_port != htons(SRC_PORT_FILTER) && key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                    return 0;
                }
                if (DST_PORT_FILTER != 0 && key->udp.src_port != htons(DST_PORT_FILTER) && key->udp.dst_port != htons(DST_PORT_FILTER)) {
                    return 0;
                }
            }
            break;
        default:
            return 0;
    }
    
    return 1;
}

// Event submission function
static __always_inline void submit_event(struct pt_regs *ctx, struct packet_key_t *key, struct flow_data_t *flow) {
    u32 map_key_zero = 0;
    struct event_data_t *event_data_ptr = event_scratch_map.lookup(&map_key_zero);
    if (!event_data_ptr) {
        return;
    }
    
    event_data_ptr->key = *key;
    if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow) != 0) {
        return;
    }
    
    events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
    // Note: PERF_SUBMIT events are tracked by the Python side, not here
}

// Common event handling function
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb, u8 stage_id) {
    
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, stage_id)) {
        return;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    
    struct flow_data_t *flow_ptr;
    
    // Flow creation for start stages
    if (stage_id == TX_STAGE_0 || stage_id == RX_STAGE_0) {
        struct flow_data_t zero = {};
        flow_sessions.delete(&key);
        flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);
        if (!flow_ptr) {
            return;
        }
        
        flow_ptr->first_seen_ns = current_ts;
        
        if (stage_id == TX_STAGE_0) {
            flow_ptr->p1_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p1_comm, sizeof(flow_ptr->p1_comm));
            flow_ptr->saw_path1_start = 1;
        } else if (stage_id == RX_STAGE_0) {
            flow_ptr->p2_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p2_comm, sizeof(flow_ptr->p2_comm));
            flow_ptr->saw_path2_start = 1;
        }
        
        // Record interface name
        struct net_device *dev;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            if (stage_id == TX_STAGE_0) {
                bpf_probe_read_kernel_str(flow_ptr->p1_ifname, IFNAMSIZ, dev->name);
            } else {
                bpf_probe_read_kernel_str(flow_ptr->p2_ifname, IFNAMSIZ, dev->name);
            }
        }
        
        // Record protocol specific info
        if (key.protocol == IPPROTO_TCP) {
            struct tcphdr tcp;
            if (get_transport_header(skb, &tcp, sizeof(tcp), stage_id) == 0) {
                flow_ptr->tcp_flags = tcp.rst << 2 | tcp.syn << 1 | tcp.fin;
            }
        } else if (key.protocol == IPPROTO_UDP) {
            struct udphdr udp;
            if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
                flow_ptr->udp_len = ntohs(udp.len);
            }
        }

    } else {
        flow_ptr = flow_sessions.lookup(&key);
        if (!flow_ptr) {
            return;
        }
    }
    
    
    // Update timestamp if not already recorded
    if (flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (u64)skb;
        flow_ptr->kstack_id[stage_id] = stack_id;
        
        // Mark end stages
        if (stage_id == TX_STAGE_6) {
            flow_ptr->saw_path1_end = 1;
        } else if (stage_id == RX_STAGE_6) {
            flow_ptr->saw_path2_end = 1;
        }
        
        flow_sessions.update(&key, flow_ptr);
    }
    
    // Check for complete paths and submit events
    bool path1_complete = (stage_id == TX_STAGE_6 && flow_ptr->saw_path1_start && flow_ptr->saw_path1_end);
    bool path2_complete = (stage_id == RX_STAGE_6 && flow_ptr->saw_path2_start && flow_ptr->saw_path2_end);

    if (path1_complete || path2_complete) {
        // Check latency threshold before submitting
        if (LATENCY_THRESHOLD_NS > 0) {
            u64 start_ts = 0;
            u64 end_ts = current_ts;

            // Find the first valid timestamp
            #pragma unroll
            for (int i = 0; i < MAX_STAGES; i++) {
                if (flow_ptr->ts[i] > 0) {
                    start_ts = flow_ptr->ts[i];
                    break;
                }
            }

            // Skip if latency below threshold
            if (start_ts == 0 || end_ts == 0 || (end_ts - start_ts) < LATENCY_THRESHOLD_NS) {
                flow_sessions.delete(&key);
                return;
            }
        }

        submit_event(ctx, &key, flow_ptr);
        flow_sessions.delete(&key);
    }
}

// Specialized event handling function for userspace SKB parsing
static __always_inline void handle_stage_event_userspace(void *ctx, struct sk_buff *skb, u8 stage_id) {
    
    struct packet_key_t key = {};
    if (!parse_packet_key_userspace(skb, &key, stage_id)) {
        return;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    
    struct flow_data_t *flow_ptr;
    
    flow_ptr = flow_sessions.lookup(&key);
    if (!flow_ptr) {
        return;
    }
    
    // Update flow data 
    if (flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (u64)skb;
        flow_ptr->kstack_id[stage_id] = stack_id;
        
        flow_sessions.update(&key, flow_ptr);
    }
}

// TX Direction Probes (System -> Physical) - based on design document


// Special packet key extraction for TCP at __ip_queue_xmit - must match standard format exactly
static __always_inline int parse_packet_key_tcp_early(
    struct sk_buff *skb,
    struct sock *sk,
    struct packet_key_t *key,
    u8 stage_id
) {

    if (!sk) return 0;

    // Get from socket - this is reliable at __ip_queue_xmit
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&key->src_ip, sizeof(key->src_ip), &inet->inet_saddr);
    bpf_probe_read_kernel(&key->dst_ip, sizeof(key->dst_ip), &inet->inet_daddr);
    bpf_probe_read_kernel(&key->tcp.src_port, sizeof(key->tcp.src_port), &inet->inet_sport);
    bpf_probe_read_kernel(&key->tcp.dst_port, sizeof(key->tcp.dst_port), &inet->inet_dport);

    key->protocol = IPPROTO_TCP;

    // Apply same filters as standard function
    if (PROTOCOL_FILTER != 0 && key->protocol != PROTOCOL_FILTER) {
        return 0;
    }

    // Apply IP filters - use exact matching for packet direction
    if (SRC_IP_FILTER != 0 && key->src_ip != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && key->dst_ip != DST_IP_FILTER) {
        return 0;
    }

    // Use tcp_sock method for reliable sequence number extraction
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u32 tcp_snd_nxt = 0;
    u32 tcp_write_seq = 0;

    // Try to read both values for reliability
    int snd_nxt_ret = bpf_probe_read_kernel(&tcp_snd_nxt, sizeof(tcp_snd_nxt), &tp->snd_nxt);
    int write_seq_ret = bpf_probe_read_kernel(&tcp_write_seq, sizeof(tcp_write_seq), &tp->write_seq);

    // Use snd_nxt if it's non-zero and read successfully
    if (snd_nxt_ret >= 0 && tcp_snd_nxt != 0) {
        key->tcp.seq = htonl(tcp_snd_nxt);
    } else if (write_seq_ret >= 0 && tcp_write_seq != 0) {
        // Fallback to write_seq if snd_nxt is 0 or failed
        key->tcp.seq = htonl(tcp_write_seq);
    } else {
        // Last resort: try to get from SKB data (might not be ready yet)
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

// TX Stage 0: TCP __ip_queue_xmit - TCP IP layer transmission entry point
int kprobe____ip_queue_xmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, struct flowi *fl) {

    if (DIRECTION_FILTER == 2) { // rx only
        return 0;
    }

    // TCP protocol filter
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_TCP) {
        return 0;
    }


    struct packet_key_t key = {};
    if (!parse_packet_key_tcp_early(skb, sk, &key, TX_STAGE_0)) {
        return 0;
    }

    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);

    // Create flow for TX_STAGE_0
    struct flow_data_t zero = {};
    flow_sessions.delete(&key);
    struct flow_data_t *flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);
    if (!flow_ptr) {
        return 0;
    }

    flow_ptr->first_seen_ns = current_ts;
    flow_ptr->p1_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&flow_ptr->p1_comm, sizeof(flow_ptr->p1_comm));
    flow_ptr->saw_path1_start = 1;

    // Record interface name
    struct net_device *dev;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
        bpf_probe_read_kernel_str(flow_ptr->p1_ifname, IFNAMSIZ, dev->name);
    }

    // Record TCP flags
    struct tcphdr tcp;
    unsigned char *data;
    if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) == 0 && data) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), data) == 0) {
            u8 ip_ihl = (ip.ihl & 0x0F);
            if (ip_ihl >= 5) {
                if (bpf_probe_read_kernel(&tcp, sizeof(tcp), data + (ip_ihl * 4)) == 0) {
                    flow_ptr->tcp_flags = tcp.rst << 2 | tcp.syn << 1 | tcp.fin;
                }
            }
        }
    }

    flow_ptr->ts[TX_STAGE_0] = current_ts;
    flow_ptr->skb_ptr[TX_STAGE_0] = (u64)skb;
    flow_ptr->kstack_id[TX_STAGE_0] = stack_id;

    flow_sessions.update(&key, flow_ptr);

    return 0;
}

// TX Stage 0: UDP ip_send_skb - UDP IP layer transmission entry point
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {

    if (DIRECTION_FILTER == 2) { // rx only
        return 0;
    }

    // UDP protocol filter
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_UDP) {
        return 0;
    }

    handle_stage_event(ctx, skb, TX_STAGE_0);
    return 0;
}

// TX Stage 1: internal_dev_xmit - Internal device transmission
int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 2) return 0; // rx only
    handle_stage_event(ctx, skb, TX_STAGE_1);
    return 0;
}


// OVS processing stages (common for TX/RX) - from icmp_rtt_latency.py
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (DIRECTION_FILTER != 2) { // tx
        handle_stage_event(ctx, skb, TX_STAGE_2);
    }
    if (DIRECTION_FILTER != 1) { // rx
        handle_stage_event(ctx, skb, RX_STAGE_2);
    }
    return 0;
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (DIRECTION_FILTER != 2) { // tx
        handle_stage_event(ctx, skb, TX_STAGE_3);
    }
    if (DIRECTION_FILTER != 1) { // rx
        handle_stage_event(ctx, skb, RX_STAGE_3);
    }
    return 0;
}

int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) return 0;
    if (DIRECTION_FILTER != 2) { // tx
        handle_stage_event_userspace(ctx, skb, TX_STAGE_4);
    }
    if (DIRECTION_FILTER != 1) { // rx
        handle_stage_event_userspace(ctx, skb, RX_STAGE_4);
    }
    return 0;
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    if (DIRECTION_FILTER != 2) { // tx
        handle_stage_event(ctx, skb, TX_STAGE_5);
    }
    if (DIRECTION_FILTER != 1) { // rx
        handle_stage_event(ctx, skb, RX_STAGE_5);
    }
    return 0;
}

// TX Stage 6: net_dev_xmit tracepoint - Physical interface transmission
RAW_TRACEPOINT_PROBE(net_dev_xmit) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    if (!is_target_ifindex(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0; // rx only
    handle_stage_event(ctx, skb, TX_STAGE_6);
    return 0;
}

// RX Direction Probes (Physical -> System)

// RX Stage 0: netif_receive_skb tracepoint - Physical interface reception
TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) {
        return 0;
    }


    if (!is_target_ifindex(skb)) {
        return 0;
    }

    if (DIRECTION_FILTER == 1) { // tx only
        return 0;
    }

    handle_stage_event(args, skb, RX_STAGE_0);
    return 0;
}

// RX Stage 1: netdev_frame_hook - Network frame processing hook
int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    struct sk_buff *skb = NULL;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || skb == NULL) {
        return 0;
    }
    
    if (DIRECTION_FILTER != 1) { // rx
        handle_stage_event(ctx, skb, RX_STAGE_1);
    }
    return 0;
}

// RX Stage 6: Protocol-specific reception - tcp_v4_rcv for TCP
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (DIRECTION_FILTER == 1) return 0; // tx only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_TCP) return 0;
    handle_stage_event(ctx, skb, RX_STAGE_6);
    return 0;
}

// RX Stage 6: Protocol-specific reception - udp_rcv for UDP  
int kprobe____udp4_lib_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct udp_table *udptable) {
    if (DIRECTION_FILTER == 1) return 0; // tx only
    if (PROTOCOL_FILTER != 0 && PROTOCOL_FILTER != IPPROTO_UDP) return 0;
    handle_stage_event(ctx, skb, RX_STAGE_6);
    return 0;
}

"""

# Constants
MAX_STAGES = 14
IFNAMSIZ = 16
TASK_COMM_LEN = 16

# Protocol-specific structures - from vm_network_latency.py
class TCPData(ctypes.Structure):
    _fields_ = [
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("payload_len", ctypes.c_uint16)
    ]

class UDPData(ctypes.Structure):
    _fields_ = [
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("ip_id", ctypes.c_uint16),
        ("udp_len", ctypes.c_uint16),
        ("frag_off", ctypes.c_uint16)
    ]

class ProtocolUnion(ctypes.Union):
    _fields_ = [
        ("tcp", TCPData),
        ("udp", UDPData)
    ]

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("protocol", ctypes.c_uint8),
        ("proto_data", ProtocolUnion),
        ("first_seen_ns", ctypes.c_uint64)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("first_seen_ns", ctypes.c_uint64),
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_STAGES),
        ("kstack_id", ctypes.c_int * MAX_STAGES),
        ("p1_pid", ctypes.c_uint32),
        ("p1_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p1_ifname", ctypes.c_char * IFNAMSIZ),
        ("p2_pid", ctypes.c_uint32),
        ("p2_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p2_ifname", ctypes.c_char * IFNAMSIZ),
        ("tcp_flags", ctypes.c_uint8),
        ("udp_len", ctypes.c_uint16),
        ("saw_path1_start", ctypes.c_uint8, 1),
        ("saw_path1_end", ctypes.c_uint8, 1),
        ("saw_path2_start", ctypes.c_uint8, 1),
        ("saw_path2_end", ctypes.c_uint8, 1)
    ]

class EventData(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("data", FlowData)
    ]

# Helper Functions - from icmp_rtt_latency.py
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

def format_latency(ts_start, ts_end):
    """Format latency value in microseconds"""
    if ts_start == 0 or ts_end == 0:
        return " N/A ".rjust(10)
    
    delta_ns = ts_end - ts_start
    delta_us = delta_ns / 1000.0
    return ("%.3f" % delta_us).rjust(10)

def print_path_latencies(flow, start_stage, end_stage, path_type):
    """Print latencies for TX or RX path, handling skipped stages intelligently"""
    
    # Find actual stages with non-zero timestamps
    active_stages = []
    for i in range(start_stage, end_stage + 1):
        if flow.ts[i] > 0:
            active_stages.append(i)
    
    if len(active_stages) < 2:
        print("  No latency data available")
        return
    
    # Print stage-to-stage latencies for consecutive active stages
    for i in range(len(active_stages) - 1):
        stage1 = active_stages[i]
        stage2 = active_stages[i + 1]
        latency = format_latency(flow.ts[stage1], flow.ts[stage2])
        print("  [%d->%d] %s -> %s: %s us" % (
            stage1, stage2, get_stage_name(stage1), get_stage_name(stage2), latency
        ))
    
    # Print total path latency
    if flow.ts[active_stages[0]] > 0 and flow.ts[active_stages[-1]] > 0:
        total_latency = format_latency(flow.ts[active_stages[0]], flow.ts[active_stages[-1]])
        print("  Total %s Latency: %s us" % (path_type, total_latency))

def get_stage_name(stage_id):
    """Get human-readable stage name"""
    stage_names = {
        0: "TX_S0_ip_layer_entry",       1: "TX_S1_internal_dev_xmit",
        2: "TX_S2_ovs_dp_process",        3: "TX_S3_ovs_dp_upcall",
        4: "TX_S4_ovs_flow_key_extract",  5: "TX_S5_ovs_vport_send",
        6: "TX_S6_net_dev_xmit",
        7: "RX_S0_netif_receive_skb",     8: "RX_S1_netdev_frame_hook",
        9: "RX_S2_ovs_dp_process",        10: "RX_S3_ovs_dp_upcall",
        11: "RX_S4_ovs_flow_key_extract", 12: "RX_S5_ovs_vport_send",
        13: "RX_S6_tcp_v4_rcv/udp_rcv"
    }
    return stage_names.get(stage_id, "Unknown_%d" % stage_id)

def print_event(cpu, data, size):
    """Print packet latency event"""
    global args
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    key = event.key
    flow = event.data
    
    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    protocol_names = {6: "TCP", 17: "UDP"}
    protocol_name = protocol_names.get(key.protocol, "Unknown")
    
    direction_str = "TX (System -> Remote)" if args.direction == "tx" else "RX (Remote -> System)"
    
    print("=== System Network %s Latency Trace: %s ===" % (protocol_name, time_str))
    print("Direction: %s" % direction_str)
    print("Flow: %s -> %s (%s)" % (
        format_ip(key.src_ip), format_ip(key.dst_ip), protocol_name
    ))
    
    if key.protocol == 6:  # TCP
        tcp_flags_str = ""
        if flow.tcp_flags & 0x01: tcp_flags_str += "FIN "
        if flow.tcp_flags & 0x02: tcp_flags_str += "SYN "
        if flow.tcp_flags & 0x04: tcp_flags_str += "RST "
        tcp_flags_str = tcp_flags_str.strip() if tcp_flags_str else "ACK"
        
        print("TCP Segment: %s:%d -> %s:%d (seq=%u, payload=%d bytes, flags=%s)" % (
            format_ip(key.src_ip), socket.ntohs(key.proto_data.tcp.src_port),
            format_ip(key.dst_ip), socket.ntohs(key.proto_data.tcp.dst_port),
            socket.ntohl(key.proto_data.tcp.seq), key.proto_data.tcp.payload_len,
            tcp_flags_str
        ))
    elif key.protocol == 17:  # UDP
        if key.proto_data.udp.frag_off > 0:
            print("UDP Fragment: %s:%d -> %s:%d (ip_id=%d, frag_offset=%d bytes, len=%d)" % (
                format_ip(key.src_ip), socket.ntohs(key.proto_data.udp.src_port),
                format_ip(key.dst_ip), socket.ntohs(key.proto_data.udp.dst_port),
                key.proto_data.udp.ip_id, key.proto_data.udp.frag_off, flow.udp_len
            ))
        else:
            print("UDP Packet: %s:%d -> %s:%d (ip_id=%d, len=%d bytes, no fragmentation)" % (
                format_ip(key.src_ip), socket.ntohs(key.proto_data.udp.src_port),
                format_ip(key.dst_ip), socket.ntohs(key.proto_data.udp.dst_port),
                key.proto_data.udp.ip_id, flow.udp_len
            ))
    
    # Show process info
    if flow.p1_pid > 0:
        print("TX Process: PID=%d COMM=%s IF=%s" % (
            flow.p1_pid, 
            flow.p1_comm.decode('utf-8', 'replace'),
            flow.p1_ifname.decode('utf-8', 'replace')
        ))
    if flow.p2_pid > 0:
        print("RX Process: PID=%d COMM=%s IF=%s" % (
            flow.p2_pid, 
            flow.p2_comm.decode('utf-8', 'replace'),
            flow.p2_ifname.decode('utf-8', 'replace')
        ))
    
    # Show TX path if direction is tx
    if direction_filter == 1:  # tx
        print("\nTX Path Latencies (us):")
        print_path_latencies(flow, 0, 6, "TX")
    
    # Show RX path if direction is rx
    if direction_filter == 2:  # rx
        print("\nRX Path Latencies (us):")
        print_path_latencies(flow, 7, 13, "RX")
    
    # Show total one-way latency for selected direction
    if (flow.ts[0] > 0 and flow.ts[13] > 0):  # TX start to RX end
        total_latency = format_latency(flow.ts[0], flow.ts[13])
        print("\nTotal One-Way Latency: %s us" % total_latency)
    elif (flow.ts[7] > 0 and flow.ts[6] > 0):  # RX start to TX end (for rx)
        total_latency = format_latency(flow.ts[7], flow.ts[6])
        print("\nTotal One-Way Latency: %s us" % total_latency)
    
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="System Network TCP/UDP Latency Measurement Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor TCP traffic (most reliable packet-level tracking):
    sudo %(prog)s --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \\
                  --protocol tcp --direction tx \\
                  --phy-interface enp94s0f0np0

  Monitor UDP traffic (including fragmentation handling):
    sudo %(prog)s --src-ip 70.0.0.33 --dst-port 53 \\
                  --protocol udp --direction rx \\
                  --phy-interface enp94s0f0np0

  Monitor specific TCP connection packet-level latency:
    sudo %(prog)s --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \\
                  --src-port 12345 --dst-port 80 \\
                  --protocol tcp --direction tx \\
                  --phy-interface enp94s0f0np0

  Monitor all TCP/UDP protocols:
    sudo %(prog)s --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \\
                  --protocol all \\
                  --phy-interface enp94s0f0np0

  Monitor flows with latency > 100us:
    sudo %(prog)s --src-ip 70.0.0.33 --dst-ip 70.0.0.34 \\
                  --protocol tcp --direction tx \\
                  --phy-interface enp94s0f0np0 \\
                  --latency-us 100
"""
    )
    
    parser.add_argument('--src-ip', type=str, required=False,
                        help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, required=False,
                        help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port filter (TCP/UDP)')
    parser.add_argument('--dst-port', type=int, required=False,
                        help='Destination port filter (TCP/UDP)')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'all'], 
                        default='all', help='Protocol filter (default: all)')
    parser.add_argument('--direction', type=str, choices=['tx', 'rx'],
                        required=True, help='Direction filter (tx or rx)')
    parser.add_argument('--phy-interface', type=str, required=True,
                        help='Physical interface to monitor (e.g., enp94s0f0np0)')
    parser.add_argument('--latency-us', type=float, default=0,
                        help='Minimum latency threshold in microseconds to report (default: 0, report all)')
    
    args = parser.parse_args()
    
    # Convert parameters
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0

    protocol_map = {'tcp': 6, 'udp': 17, 'all': 0}
    protocol_filter = protocol_map[args.protocol]

    direction_map = {'tx': 1, 'rx': 2}
    direction_filter = direction_map[args.direction]

    # Convert latency threshold from microseconds to nanoseconds
    latency_threshold_ns = int(args.latency_us * 1000)
    
    # Support multiple interfaces (split by comma)
    phy_interfaces = args.phy_interface.split(',')
    try:
        ifindex1 = get_if_index(phy_interfaces[0].strip())
        ifindex2 = get_if_index(phy_interfaces[1].strip()) if len(phy_interfaces) > 1 else ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)
    
    print("=== System Network TCP/UDP Latency Tracer ===")
    print("Protocol filter: %s" % args.protocol.upper())
    print("Direction filter: %s" % args.direction.upper())
    if args.src_ip:
        print("Source IP filter: %s" % args.src_ip)
    if args.dst_ip:
        print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("Physical interfaces: %s (ifindex %d, %d)" % (args.phy_interface, ifindex1, ifindex2))
    if latency_threshold_ns > 0:
        print("Latency threshold: >= %.3f us (only reporting flows exceeding this latency)" % args.latency_us)
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, ifindex1, ifindex2, direction_filter,
            latency_threshold_ns
        ))
        print("BPF program loaded successfully")

    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    b["events"].open_perf_buffer(print_event)

    print("\nTracing system network TCP/UDP latency... Hit Ctrl-C to end.")
    print("Generate some TCP/UDP traffic to see results...\n")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
    finally:
        print("Exiting.")
