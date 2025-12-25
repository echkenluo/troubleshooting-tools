#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
VM Network Adjacent Stage Latency Histogram Tool

Measures latency distribution between adjacent network stack stages using BPF_HISTOGRAM.
Only tracks latencies between consecutive processing stages in the actual packet path.

Usage:
    sudo ./vm_network_latency_adjacent_hist.py --vm-interface vnet37 --phy-interface enp94s0f0np0 \
                                --src-ip 192.168.76.198 --direction rx --interval 5

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
import re

def find_kernel_function(base_name):
    """
    Find actual kernel function name, handling GCC clone suffixes.
    GCC may generate optimized clones with suffixes like:
      .isra.N     - Inter-procedural Scalar Replacement of Aggregates
      .constprop.N - Constant Propagation
      .part.N     - Partial inlining
    Returns the actual symbol name or None if not found.
    """
    pattern = re.compile(
        r'^[0-9a-f]+\s+[tT]\s+(' + re.escape(base_name) +
        r'(?:\.(?:isra|constprop|part)\.\d+)*)(?:\s+\[\w+\])?$'
    )

    candidates = []
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                match = pattern.match(line.strip())
                if match:
                    candidates.append(match.group(1))
    except Exception:
        return None

    if not candidates:
        return None

    # Prefer exact match, then shortest suffix
    if base_name in candidates:
        return base_name

    return min(candidates, key=len)

# ctypes structure for stage pair key
class stage_pair_key_t(ctypes.Structure):
    _fields_ = [
        ("prev_stage", ctypes.c_uint8),
        ("curr_stage", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("latency_bucket", ctypes.c_uint8)
    ]

# Global configuration
direction_filter = 1  # 1=VM TX (packets leaving VM), 2=VM RX (packets entering VM)

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/flow.h>

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP, 1=ICMP
#define VM_IFINDEX %d
#define PHY_IFINDEX1 %d
#define PHY_IFINDEX2 %d
#define DIRECTION_FILTER %d  // 1=vnet_rx, 2=vnet_tx

// Stage definitions - vnet perspective
// VNET RX path (VM TX, packets from VM to external)
#define STG_VNET_RX         1
#define STG_OVS_RX          2
#define STG_FLOW_EXTRACT_END_RX  3
#define STG_OVS_UPCALL_RX   4
#define STG_OVS_USERSPACE_RX 5
#define STG_CT_RX           6
#define STG_CT_OUT_RX       7
#define STG_QDISC_ENQ       8
#define STG_QDISC_DEQ       9
#define STG_TX_QUEUE        10
#define STG_TX_XMIT         11

// VNET TX path (VM RX, packets from external to VM)
#define STG_PHY_RX          12
#define STG_OVS_TX          13
#define STG_FLOW_EXTRACT_END_TX  14
#define STG_OVS_UPCALL_TX   15
#define STG_OVS_USERSPACE_TX 16
#define STG_CT_TX           17
#define STG_CT_OUT_TX       18
#define STG_VNET_QDISC_ENQ  19
#define STG_VNET_QDISC_DEQ  20
#define STG_VNET_TX         21

#define MAX_STAGES          22
#define IFNAMSIZ            16

// Packet key structure for unique packet identification
struct packet_key_t {
    __be32 sip;
    __be32 dip;
    u8 proto;
    u8 pad[3];
    
    union {
        struct {
            __be16 source;
            __be16 dest;
            __be32 seq;
        } tcp;
        
        struct {
            __be16 source;
            __be16 dest;
            __be16 id;
            __be16 len;
        } udp;
        
        struct {
            __be16 id;
            __be16 sequence;
            u8 type;
            u8 code;
            u8 pad[2];
        } icmp;
    };
};

// Flow tracking - track both first and last stage timestamps for total latency
struct flow_data_t {
    u64 first_timestamp;               // Timestamp of first stage (for total latency)
    u64 last_timestamp;                // Timestamp of last stage  
    u8 direction;                      // 1=vnet_rx, 2=vnet_tx
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

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);

// BPF Histogram for adjacent stage latencies - with stage pair as key
// BPF_HISTOGRAM supports struct keys for creating separate histograms per key
BPF_HISTOGRAM(adjacent_latency_hist, struct stage_pair_key_t, 1024);

// BPF Histogram for total end-to-end latency - simple u8 key for direction
BPF_HISTOGRAM(total_latency_hist, u8, 256);

// Performance statistics
BPF_ARRAY(packet_counters, u64, 4);  // 0=total, 1=vnet_rx, 2=vnet_tx, 3=dropped
BPF_ARRAY(stage_pair_counters, u64, 32);  // Count of stage pairs seen
BPF_ARRAY(flow_stage_counters, u64, 4);  // 0=first_stage_rx, 1=last_stage_rx, 2=first_stage_tx, 3=last_stage_tx

// Helper functions
static __always_inline bool is_target_vm_interface(const struct sk_buff *skb) {
    if (VM_IFINDEX == 0) return false;
    
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    return (ifindex == VM_IFINDEX);
}

static __always_inline bool is_target_phy_interface(const struct sk_buff *skb) {
    if (PHY_IFINDEX1 == 0) return false;

    struct net_device *dev = NULL;
    int ifindex = 0;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }

    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }

    return (ifindex == PHY_IFINDEX1 || ifindex == PHY_IFINDEX2);
}

// Packet parsing functions
static __always_inline int get_ip_header(struct sk_buff *skb, struct iphdr *ip) {
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

static __always_inline int get_transport_header(struct sk_buff *skb, void *hdr, u16 hdr_size) {
    unsigned char *head;
    u16 transport_header_offset;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }
    
    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
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

static __always_inline int parse_packet_key(
    struct sk_buff *skb, 
    struct packet_key_t *key,
    u8 direction
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip) != 0) {
        return 0;
    }
    
    // Apply filters
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }
    
    // Direction-specific IP filtering
    if (direction == 1) { // vnet_rx: packets from VM
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    } else if (direction == 2) { // vnet_tx: packets to VM
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    }
    
    // Set canonical source/destination
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;
    
    // Parse transport layer
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (get_transport_header(skb, &tcp, sizeof(tcp)) != 0) return 0;
            
            key->tcp.source = tcp.source;
            key->tcp.dest = tcp.dest;
            key->tcp.seq = tcp.seq;
            
            if (SRC_PORT_FILTER != 0 && key->tcp.source != htons(SRC_PORT_FILTER) && key->tcp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.source != htons(DST_PORT_FILTER) && key->tcp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            key->udp.id = ip.id;
            
            struct udphdr udp;
            if (get_transport_header(skb, &udp, sizeof(udp)) == 0) {
                key->udp.source = udp.source;
                key->udp.dest = udp.dest;
                key->udp.len = udp.len;
            }
            
            if (SRC_PORT_FILTER != 0 && key->udp.source != htons(SRC_PORT_FILTER) && key->udp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->udp.source != htons(DST_PORT_FILTER) && key->udp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr icmp;
            if (get_transport_header(skb, &icmp, sizeof(icmp)) != 0) return 0;
            
            key->icmp.type = icmp.type;
            key->icmp.code = icmp.code;
            key->icmp.id = icmp.un.echo.id;
            key->icmp.sequence = icmp.un.echo.sequence;
            break;
        }
        default:
            return 0;
    }
    
    return 1;
}

// Specialized parsing function for userspace SKB
static __always_inline int parse_packet_key_userspace(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
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
    
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;
    
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
            
            key->tcp.source = tcp.source;
            key->tcp.dest = tcp.dest;
            key->tcp.seq = tcp.seq;
            
            if (SRC_PORT_FILTER != 0 && tcp.source != htons(SRC_PORT_FILTER) && tcp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && tcp.source != htons(DST_PORT_FILTER) && tcp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            key->udp.id = ip.id;
            
            struct udphdr udp;
            if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) < 0) {
                return 0;
            }
            key->udp.source = udp.source;
            key->udp.dest = udp.dest;
            
            if (SRC_PORT_FILTER != 0 && key->udp.source != htons(SRC_PORT_FILTER) && key->udp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->udp.source != htons(DST_PORT_FILTER) && key->udp.dest != htons(DST_PORT_FILTER)) {
                return 0;
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

// Main event handling function - adjacent stage tracking only
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb, u8 stage_id, u8 direction) {
    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();
    
    // Parse packet key
    int parse_success = 0;
    if (stage_id == STG_OVS_USERSPACE_RX || stage_id == STG_OVS_USERSPACE_TX) {
        parse_success = parse_packet_key_userspace(skb, &key, direction);
    } else {
        parse_success = parse_packet_key(skb, &key, direction);
    }
    
    if (!parse_success) {
        return;
    }
    
    // Check if this is the first stage for this direction
    bool is_first_stage = false;
    if ((direction == 1 && stage_id == STG_VNET_RX) ||
        (direction == 2 && stage_id == STG_PHY_RX)) {
        is_first_stage = true;
    }
    
    struct flow_data_t *flow_ptr;
    
    if (is_first_stage) {
        // Initialize new flow tracking
        struct flow_data_t zero = {};
        zero.direction = direction;
        zero.last_stage = 0;
        zero.last_timestamp = 0;
        zero.first_timestamp = current_ts;  // Record first stage timestamp
        
        flow_sessions.delete(&key);
        flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);
        
        if (flow_ptr) {
            u32 idx = direction;
            u64 *counter = packet_counters.lookup(&idx);
            if (counter) (*counter)++;
            
            // Count first stage
            u32 first_stage_idx = (direction == 1) ? 0 : 2;  // 0=first_stage_rx, 2=first_stage_tx
            u64 *first_counter = flow_stage_counters.lookup(&first_stage_idx);
            if (first_counter) (*first_counter)++;
        }
    } else {
        flow_ptr = flow_sessions.lookup(&key);
    }
    
    if (!flow_ptr) {
        flow_sessions.delete(&key);
        return;
    }
    
    // Calculate and submit latency for adjacent stages
    if (flow_ptr->last_stage > 0 && flow_ptr->last_timestamp > 0) {
        u64 prev_ts = flow_ptr->last_timestamp;
        
        if (current_ts > prev_ts) {
            u64 latency_ns = current_ts - prev_ts;
            u64 latency_us = latency_ns / 1000;
            
            // Create stage pair key with latency bucket
            struct stage_pair_key_t pair_key = {};
            pair_key.prev_stage = flow_ptr->last_stage;
            pair_key.curr_stage = stage_id;
            pair_key.direction = direction;
            pair_key.latency_bucket = bpf_log2l(latency_us + 1);
            
            // Update histogram
            adjacent_latency_hist.increment(pair_key, 1);
        }
    }
    
    // Update tracking for next stage
    flow_ptr->last_stage = stage_id;
    flow_ptr->last_timestamp = current_ts;
    
    // Check if this is the last stage
    bool is_last_stage = false;
    if ((direction == 1 && stage_id == STG_TX_XMIT) ||
        (direction == 2 && stage_id == STG_VNET_TX)) {
        is_last_stage = true;
        
        // Calculate total latency from first to last stage
        if (flow_ptr->first_timestamp > 0 && current_ts > flow_ptr->first_timestamp) {
            u64 total_latency = current_ts - flow_ptr->first_timestamp;
            
            // Convert to microseconds and calculate log2 bucket
            u64 latency_us = total_latency / 1000;
            if (latency_us > 0) {
                u8 log2_latency = bpf_log2l(latency_us);
                total_latency_hist.increment(log2_latency);
            }
        }
        
        // Count last stage
        u32 last_stage_idx = (direction == 1) ? 1 : 3;  // 1=last_stage_rx, 3=last_stage_tx
        u64 *last_counter = flow_stage_counters.lookup(&last_stage_idx);
        if (last_counter) (*last_counter)++;
        
        // Delete flow session
        flow_sessions.delete(&key);
    }
}

// Use tracepoint for both RX and TX direction
RAW_TRACEPOINT_PROBE(netif_receive_skb) {
    // Get skb from tracepoint args
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    // TX Direction: Physical interface receives packets for VM
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if RX-only mode
        handle_stage_event(ctx, skb, STG_PHY_RX, 2);
    }

    // RX Direction: VM interface sends packets to physical
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if TX-only mode
        handle_stage_event(ctx, skb, STG_VNET_RX, 1);
    }

    return 0;
}

int kprobe__ovs_vport_receive(struct pt_regs *ctx, void *vport, struct sk_buff *skb, void *tun_info) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, STG_OVS_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, STG_OVS_TX, 2);
    }
    return 0;
}

int kprobe__nf_conntrack_in(struct pt_regs *ctx, struct net *net, u_int8_t pf, unsigned int hooknum, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, STG_CT_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, STG_CT_TX, 2);
    }
    
    return 0;
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_TX, 2);
    }
    
    return 0;
}

int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {
        handle_stage_event(ctx, skb, STG_OVS_USERSPACE_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {
        handle_stage_event(ctx, skb, STG_OVS_USERSPACE_TX, 2);
    }
    
    return 0;
}

// Manual attach - function name varies by kernel/compiler (GCC clone suffixes)
int trace_ovs_ct_update_key(struct pt_regs *ctx, struct sk_buff *skb, void *info, void *key, bool post_ct, bool keep_nat_flags) {
    if (!skb) return 0;

    if (post_ct) {
        // Conntrack action phase
        if (DIRECTION_FILTER != 2) {
            handle_stage_event(ctx, skb, STG_CT_OUT_RX, 1);
        }
        if (DIRECTION_FILTER != 1) {
            handle_stage_event(ctx, skb, STG_CT_OUT_TX, 2);
        }
    } else {
        // Flow extract phase
        if (DIRECTION_FILTER != 2) {
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_RX, 1);
        }
        if (DIRECTION_FILTER != 1) {
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_TX, 2);
        }
    }

    return 0;
}

// Qdisc enqueue using tracepoint
RAW_TRACEPOINT_PROBE(net_dev_queue) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;
        handle_stage_event(ctx, skb, STG_QDISC_ENQ, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;
        handle_stage_event(ctx, skb, STG_VNET_QDISC_ENQ, 2);
    }
    
    return 0;
}

// Qdisc dequeue tracepoint 
RAW_TRACEPOINT_PROBE(qdisc_dequeue) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[3];
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;
        handle_stage_event(ctx, skb, STG_QDISC_DEQ, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;
        handle_stage_event(ctx, skb, STG_VNET_QDISC_DEQ, 2);
    }
    
    return 0;
}

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;
        handle_stage_event(ctx, skb, STG_TX_QUEUE, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;
        handle_stage_event(ctx, skb, STG_VNET_TX, 2);
    }
    
    return 0;
}

int kprobe__dev_queue_xmit_nit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !is_target_phy_interface(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0;
    
    handle_stage_event(ctx, skb, STG_TX_XMIT, 1);
    return 0;
}

"""

# Constants
MAX_STAGES = 22

# Stage pair key structure
class StagePairKey(ctypes.Structure):
    _fields_ = [
        ("prev_stage", ctypes.c_uint8),
        ("curr_stage", ctypes.c_uint8), 
        ("direction", ctypes.c_uint8),
        ("pad", ctypes.c_uint8)
    ]

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
        # VNET RX path (VM TX, packets from VM to external)
        1: "VNET_RX",
        2: "OVS_RX", 
        3: "FLOW_EXTRACT_END_RX",
        4: "OVS_UPCALL_RX",
        5: "OVS_USERSPACE_RX",
        6: "CT_RX",
        7: "CT_OUT_RX",
        8: "QDISC_ENQ",
        9: "QDISC_DEQ",
        10: "TX_QUEUE",
        11: "TX_XMIT",
        
        # VNET TX path (VM RX, packets from external to VM)
        12: "PHY_RX",
        13: "OVS_TX",
        14: "FLOW_EXTRACT_END_TX",
        15: "OVS_UPCALL_TX",
        16: "OVS_USERSPACE_TX",
        17: "CT_TX",
        18: "CT_OUT_TX",
        19: "VNET_QDISC_ENQ",
        20: "VNET_QDISC_DEQ",
        21: "VNET_TX"
    }
    return stage_names.get(stage_id, "UNKNOWN_%d" % stage_id)

def print_histogram_summary(b, interval_start_time):
    """Print histogram summary for the current interval"""
    current_time = datetime.datetime.now()
    print("\n" + "=" * 80)
    print("[%s] Adjacent Stage Latency Report (Interval: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        time_time() - interval_start_time
    ))
    print("=" * 80)
    
    # Get stage pair histogram data
    latency_hist = b["adjacent_latency_hist"]
    
    # Collect all stage pair data organized by (prev_stage, curr_stage, direction)
    stage_pair_data = {}  # Key: (prev_stage, curr_stage, direction), Value: {bucket: count}
    
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
    
    # Sort stage pairs by direction, then by stages
    sorted_pairs = sorted(stage_pair_data.keys(), key=lambda x: (x[2], x[0], x[1]))
    
    # Print by direction
    for direction in [1, 2]:
        dir_pairs = [p for p in sorted_pairs if p[2] == direction]
        if not dir_pairs:
            continue

        direction_str = "VM TX (VM->External)" if direction == 1 else "VM RX (External->VM)"
        print("\n%s:" % direction_str)
        print("-" * 60)
        
        for prev_stage, curr_stage, dir_val in dir_pairs:
            prev_name = get_stage_name(prev_stage)
            curr_name = get_stage_name(curr_stage)
            
            print("\n  %s -> %s:" % (prev_name, curr_name))
            
            # Get histogram data for this stage pair
            buckets = stage_pair_data[(prev_stage, curr_stage, dir_val)]
            total_samples = sum(buckets.values())
            
            if total_samples == 0:
                print("    No samples")
                continue
                
            print("    Total samples: %d" % total_samples)
            print("    Latency distribution:")
            
            # Sort buckets and display
            sorted_buckets = sorted(buckets.items())
            max_count = max(buckets.values())
            
            for bucket, count in sorted_buckets:
                if count > 0:
                    # Convert bucket to latency range (2^bucket to 2^(bucket+1) - 1)
                    if bucket == 0:
                        range_str = "0-1us"
                    else:
                        low = 1 << (bucket - 1)  # 2^(bucket-1)
                        high = (1 << bucket) - 1  # 2^bucket - 1
                        range_str = "%d-%dus" % (low, high)
                    
                    # Create simple bar graph
                    bar_width = int(40 * count / max_count)
                    bar = "*" * bar_width
                    
                    print("      %-12s: %6d |%-40s|" % (range_str, count, bar))
    
    # Print packet counters
    counters = b["packet_counters"]
    print("\nPacket Counters:")
    print("  VM TX packets: %d" % counters[1].value)
    print("  VM RX packets: %d" % counters[2].value)
    
    # Calculate incomplete flows using counter method
    flow_counters = b["flow_stage_counters"]
    
    first_stage_rx = flow_counters[0].value    # Count of flows that started (VNET_RX)
    last_stage_rx = flow_counters[1].value     # Count of flows that completed (TX_XMIT) 
    first_stage_tx = flow_counters[2].value    # Count of flows that started (PHY_RX)
    last_stage_tx = flow_counters[3].value     # Count of flows that completed (VNET_TX)
    
    incomplete_rx_count = first_stage_rx - last_stage_rx
    incomplete_tx_count = first_stage_tx - last_stage_tx
    
    print("\nFlow Session Analysis (Counter-based):")
    print("  VM TX started: %d, completed: %d, incomplete: %d" % (
        first_stage_rx, last_stage_rx, incomplete_rx_count))
    print("  VM RX started: %d, completed: %d, incomplete: %d" % (
        first_stage_tx, last_stage_tx, incomplete_tx_count))
    
    # Also try to check flow_sessions table for additional debug info
    total_active_flows = 0
    try:
        flow_sessions = b["flow_sessions"]
        total_active_flows = len(flow_sessions)
    except:
        total_active_flows = -1
    
    if total_active_flows >= 0:
        print("  Currently active flow sessions: %d" % total_active_flows)
    else:
        print("  Flow sessions table not accessible")
    
    # Display total latency histogram (end-to-end latency)
    print("\nTotal End-to-End Latency Distribution (First Stage -> Last Stage):")
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
                
                # Calculate latency range for this bucket
                if bucket == 0:
                    range_str = "1us"
                else:
                    low = 1 << (bucket - 1)  # 2^(bucket-1)
                    high = (1 << bucket) - 1  # 2^bucket - 1
                    range_str = "%d-%dus" % (low, high)
                
                # Create simple bar graph
                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                
                print("  %-12s: %6d |%-40s|" % (range_str, count, bar))
        else:
            print("  No total latency data collected in this interval")
    except Exception as e:
        print("  Error reading total latency histogram: %s" % str(e))
    
    
    # Clear histograms for next interval
    latency_hist.clear()
    try:
        total_hist = b["total_latency_hist"]
        total_hist.clear()
    except:
        pass

def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="VM Network Adjacent Stage Latency Histogram Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor VM TX traffic (packets leaving VM, e.g., 192.168.76.198 -> external):
    sudo %(prog)s --vm-interface vnet37 --phy-interface enp94s0f0np0 --direction tx --src-ip 192.168.76.198

  Monitor VM RX traffic (packets entering VM, e.g., external -> 192.168.76.198):
    sudo %(prog)s --vm-interface vnet37 --phy-interface enp94s0f0np0 --direction rx --dst-ip 192.168.76.198

  Monitor TCP SSH traffic to VM with 10 second intervals:
    sudo %(prog)s --vm-interface vnet37 --phy-interface enp94s0f0np0 --protocol tcp --dst-port 22 --direction rx --interval 10
"""
    )
    
    parser.add_argument('--vm-interface', type=str, required=True,
                        help='VM virtual interface to monitor (e.g., vnet37)')
    parser.add_argument('--phy-interface', type=str, required=True,
                        help='Physical interface(s) to monitor. Supports comma-separated list for bond members (e.g., enp94s0f0np0 or eth0,eth1)')
    parser.add_argument('--vm-ip', type=str, required=False,
                        help='VM IP address filter')
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
    parser.add_argument('--direction', type=str, choices=['rx', 'tx'],
                        required=True, help='Direction filter: tx=VM TX (packets leaving VM), rx=VM RX (packets entering VM)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Statistics output interval in seconds (default: 5)')
    parser.add_argument('--enable-ct', action='store_true',
                        help='Enable conntrack measurement (enabled by default)')
    
    args = parser.parse_args()
    
    # Convert parameters
    if args.vm_ip:
        src_ip_hex = ip_to_hex(args.vm_ip)
        dst_ip_hex = ip_to_hex(args.vm_ip)
    else:
        src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
        dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0
    
    protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'all': 0}
    protocol_filter = protocol_map[args.protocol]
    
    # Direction mapping from VM perspective:
    # tx = VM TX (packets leaving VM) = vnet RX path (direction=1)
    # rx = VM RX (packets entering VM) = vnet TX path (direction=2)
    direction_map = {'tx': 1, 'rx': 2}
    direction_filter = direction_map[args.direction]
    
    # Support multiple interfaces (split by comma)
    phy_interfaces = args.phy_interface.split(',')
    try:
        vm_ifindex = get_if_index(args.vm_interface)
        phy_ifindex1 = get_if_index(phy_interfaces[0].strip())
        phy_ifindex2 = get_if_index(phy_interfaces[1].strip()) if len(phy_interfaces) > 1 else phy_ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    print("=== VM Network Adjacent Stage Latency Histogram Tool ===")
    print("Protocol filter: %s" % args.protocol.upper())
    print("Direction filter: %s (tx=VM TX, rx=VM RX)" % args.direction.upper())
    if args.vm_ip:
        print("VM IP filter: %s" % args.vm_ip)
    elif args.src_ip or args.dst_ip:
        if args.src_ip:
            print("Source IP filter: %s" % args.src_ip)
        if args.dst_ip:
            print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("VM interface: %s (ifindex %d)" % (args.vm_interface, vm_ifindex))
    print("Physical interfaces: %s (ifindex %d, %d)" % (args.phy_interface, phy_ifindex1, phy_ifindex2))
    print("Statistics interval: %d seconds" % args.interval)
    print("Conntrack measurement: ENABLED")
    print("Mode: Adjacent stage latency tracking only")
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, vm_ifindex, phy_ifindex1, phy_ifindex2, direction_filter
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    # Manual attachment for ovs_ct_update_key (function name varies by kernel/compiler)
    # GCC may generate optimized clones: .isra.N, .constprop.N, .part.N
    ovs_ct_func = find_kernel_function("ovs_ct_update_key")
    if ovs_ct_func:
        try:
            b.attach_kprobe(event=ovs_ct_func, fn_name="trace_ovs_ct_update_key")
            print("Attached kprobe to %s" % ovs_ct_func)
        except Exception as e:
            print("Warning: Could not attach to %s: %s" % (ovs_ct_func, e))
            print("         CT flow tracking will be disabled")
    else:
        print("Warning: ovs_ct_update_key not found in kallsyms")
        print("         CT flow tracking will be disabled")
    
    print("\nCollecting adjacent stage latency data... Hit Ctrl-C to end.")
    print("Statistics will be displayed every %d seconds\n" % args.interval)
    
    # Setup signal handler for clean exit
    def signal_handler(sig, frame):
        print("\n\nFinal statistics:")
        print_histogram_summary(b, interval_start_time)
        print("\nExiting...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Main loop
    interval_start_time = time_time()
    
    try:
        while True:
            sleep(args.interval)
            print_histogram_summary(b, interval_start_time)
            interval_start_time = time_time()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()