#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
VM Network Performance Tracing Tool

Provides comprehensive VM network performance measurement with packet tracking
through the entire network stack. Uses LRU hash for packet identification
and tracks packets from first probe point through all stages.

Key features:
- Packet unique identification with LRU hash storage
- Direction based on vnet perspective (rx/tx)
- Qdisc enqueue/dequeue monitoring
- Complete packet path tracing

Usage:
    sudo ./vm_net_perf_trace.py --vm-interface vnet37 --phy-interface enp94s0f0np0 \
                                --src-ip 192.168.76.198 --direction rx

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

# Global configuration
direction_filter = 1  # 1=vnet_rx(vm_tx), 2=vnet_tx(vm_rx)

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
#define LATENCY_THRESHOLD_NS %d  // Minimum latency threshold in nanoseconds

// Stage definitions - vnet perspective (reordered to match temporal sequence)
// VNET RX path (VM TX, packets from VM to external)
#define STG_VNET_RX         1   // netif_receive_skb (vnet) - FIRST POINT
#define STG_OVS_RX          2   // ovs_vport_receive
#define STG_FLOW_EXTRACT_END_RX  3   // ovs_ct_update_key (flow extract phase) - before upcall
#define STG_OVS_UPCALL_RX   4   // ovs_dp_upcall - upcall starts
#define STG_OVS_USERSPACE_RX 5  // ovs_flow_key_extract_userspace - upcall processing
#define STG_CT_RX           6   // nf_conntrack_in
#define STG_CT_OUT_RX       7   // ovs_ct_update_key (conntrack action)
#define STG_QDISC_ENQ       8   // qdisc_enqueue (physical dev)
#define STG_QDISC_DEQ       9   // qdisc_dequeue (physical dev)
#define STG_TX_QUEUE        10  // dev_queue_xmit (physical dev)
#define STG_TX_XMIT         11  // dev_hard_start_xmit (physical dev) - LAST POINT

// VNET TX path (VM RX, packets from external to VM)
#define STG_PHY_RX          12  // netif_receive_skb (physical) - FIRST POINT
#define STG_OVS_TX          13  // ovs_vport_receive
#define STG_FLOW_EXTRACT_END_TX  14   // ovs_ct_update_key (flow extract phase) - before upcall
#define STG_OVS_UPCALL_TX   15  // ovs_dp_upcall - upcall starts
#define STG_OVS_USERSPACE_TX 16 // ovs_flow_key_extract_userspace - upcall processing
#define STG_CT_TX           17  // nf_conntrack_in
#define STG_CT_OUT_TX       18  // ovs_ct_update_key (conntrack action)
#define STG_VNET_QDISC_ENQ  19  // qdisc_enqueue (vnet dev)
#define STG_VNET_QDISC_DEQ  20  // qdisc_dequeue (vnet dev)
#define STG_VNET_TX         21  // dev_hard_start_xmit (vnet) - LAST POINT

#define MAX_STAGES          22
#define IFNAMSIZ            16
#define TASK_COMM_LEN       16

// Debug framework definitions

// Packet key structure for unique packet identification
struct packet_key_t {
    __be32 sip;         // Canonical source IP
    __be32 dip;         // Canonical destination IP
    u8 proto;           // Protocol type
    u8 pad[3];          // Alignment padding
    
    union {
        // TCP packet identification - using seq as primary identifier
        struct {
            __be16 source;        // Source port
            __be16 dest;          // Destination port
            __be32 seq;           // TCP sequence number (main identifier)
        } tcp;
        
        // UDP packet identification - using IP ID as identifier
        struct {
            __be16 source;        // Source port
            __be16 dest;          // Destination port
            __be16 id;            // IP identification (main identifier)
            __be16 len;           // UDP length
        } udp;
        
        // ICMP packet identification - using ID+seq as identifier
        struct {
            __be16 id;            // ICMP ID
            __be16 sequence;      // ICMP sequence number
            u8 type;              // ICMP type
            u8 code;              // ICMP code
            u8 pad[2];            // Padding
        } icmp;
    };
};

// Per-stage detailed information
struct stage_info_t {
    u64 timestamp;                // Timestamp for this stage
    u64 skb_ptr;                  // SKB pointer for this stage
    u32 ifindex;                  // Interface index
    char devname[IFNAMSIZ];       // Device name
    s16 queue_mapping;            // SKB queue mapping at this stage
    u32 skb_hash;                 // SKB hash at this stage
    u32 len;                      // Packet length at this stage
    u32 data_len;                 // SKB data length at this stage
    u32 cpu;                      // CPU at this stage
    u8 valid;                     // Whether this stage has valid data
};

// Flow tracking data structure
struct flow_data_t {
    struct stage_info_t stages[MAX_STAGES];  // Per-stage detailed info
    
    // Packet identification info (first stage)
    u32 first_pid;                // PID at first capture
    char first_comm[TASK_COMM_LEN]; // Process name at first capture
    
    // Conntrack timing
    u64 ct_start_time;            // When CT lookup started
    u32 ct_lookup_duration;       // CT lookup duration in nanoseconds
    
    // Qdisc timing
    u64 qdisc_enq_time;           // When packet was enqueued to qdisc
    u32 qdisc_qlen;               // Queue length at dequeue time
    
    // Direction and flow state
    u8 direction;                 // 1=vnet_rx, 2=vnet_tx
    u8 stage_count;               // Number of stages captured
    u8 complete;                  // Flow complete flag
    
    // Backward compatibility fields (deprecated, use stages[] instead)
    u64 ts[MAX_STAGES];           // Backward compatibility - timestamps
    u64 skb_ptr[MAX_STAGES];      // Backward compatibility - skb pointers
    s16 queue_mapping;            // Backward compatibility - initial queue mapping
    u32 skb_hash;                 // Backward compatibility - initial skb hash
    u32 len;                      // Backward compatibility - initial packet length
    u32 data_len;                 // Backward compatibility - initial data length
    char first_ifname[IFNAMSIZ];  // Backward compatibility - first interface name
};

// Event data structure for performance output
struct pkt_event {
    // Packet identification
    u64 pkt_id;                  // Packet unique ID (skb pointer)
    struct packet_key_t key;     // Packet identification key
    
    // Flow tracking data
    struct flow_data_t flow;     // Complete flow data
    
    // Current stage info
    u64 timestamp;               // Current event timestamp
    u32 cpu;                     // Current CPU ID
    u32 ifindex;                 // Current device ifindex
    char devname[16];            // Current device name
    u8 stage;                    // Current stage
    
    // Event type: 0=stage_event, 1=complete_flow
    u8 event_type;
};

// Maps for packet flow tracking - using LRU hash like icmp_rtt_latency.py
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);
BPF_ARRAY(event_scratch_map, struct pkt_event, 1);
BPF_PERCPU_ARRAY(flow_init_map, struct flow_data_t, 1);  // Per-cpu temp storage for initialization

// Performance statistics
BPF_ARRAY(probe_stats, u64, 32);          // Event counters for each probe point

// Events output
BPF_PERF_OUTPUT(events);

// Helper functions - reusing vm_network_latency.py proven logic
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

// Packet parsing functions - reusing vm_network_latency.py logic
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

static __always_inline int parse_packet_key(
    struct sk_buff *skb, 
    struct packet_key_t *key,
    u8 direction  // 1=vnet_rx, 2=vnet_tx
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip) != 0) {
        return 0;
    }
    
    // Apply filters first
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
    
    // Set canonical source/destination for consistent packet identification
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;
    
    // Parse transport layer based on protocol
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
            key->udp.id = ip.id;  // Use IP ID as main identifier
            
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

// Specialized parsing function for userspace SKB (used in ovs_flow_key_extract_userspace)
// Copied from vm_network_latency.py implementation
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
    
    // Parse transport layer - match the regular parsing exactly
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + trans_offset) < 0) {
                return 0;
            }
            
            // Use current packet_key_t structure field names
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
            // Set ip_id exactly like regular UDP parsing
            key->udp.id = ip.id;
            
            // Fragment handling exactly like regular parsing
            u16 frag_off_flags = ntohs(ip.frag_off);
            u8 more_frag = (frag_off_flags & 0x2000) ? 1 : 0;  // More Fragments bit
            u16 frag_offset = frag_off_flags & 0x1FFF;          // Fragment offset (8-byte units)
            u8 is_fragment = (more_frag || frag_offset) ? 1 : 0;
            
            if (is_fragment) {
                key->udp.len = frag_offset * 8;  // Store fragment offset in len field
                
                if (frag_offset == 0) {
                    // First fragment - parse UDP header
                    struct udphdr udp;
                    if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) == 0) {
                        key->udp.source = udp.source;
                        key->udp.dest = udp.dest;
                    } else {
                        key->udp.source = 0;
                        key->udp.dest = 0;
                    }
                } else {
                    // Subsequent fragments - no UDP header
                    key->udp.source = 0;
                    key->udp.dest = 0;
                }
            } else {
                key->udp.len = 0;  // No fragmentation
                struct udphdr udp;
                if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) < 0) {
                    return 0;
                }
                key->udp.source = udp.source;
                key->udp.dest = udp.dest;
            }
            
            // Apply port filters only if not fragmented or is first fragment
            if (!is_fragment || frag_offset == 0) {
                if (SRC_PORT_FILTER != 0 && key->udp.source != htons(SRC_PORT_FILTER) && key->udp.dest != htons(SRC_PORT_FILTER)) {
                    return 0;
                }
                if (DST_PORT_FILTER != 0 && key->udp.source != htons(DST_PORT_FILTER) && key->udp.dest != htons(DST_PORT_FILTER)) {
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

// Main event handling function - tracks packets through all stages
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb, u8 stage_id, u8 direction) {

    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();

    // Parse packet key for identification
    int parse_success = 0;
    // Use userspace parsing for OVS_USERSPACE stages, regular parsing for others
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
    if ((direction == 1 && stage_id == STG_VNET_RX) ||  // vnet RX path starts
        (direction == 2 && stage_id == STG_PHY_RX)) {    // vnet TX path starts
        is_first_stage = true;
    }

    struct flow_data_t *flow_ptr;

    if (is_first_stage) {
        // Initialize new flow tracking using per-cpu map
        flow_sessions.delete(&key);  // Clean any old entries
        
        u32 init_key = 0;
        struct flow_data_t *zero_ptr = flow_init_map.lookup(&init_key);
        if (!zero_ptr) {
            return;
        }
        
        // Manual initialization in per-cpu map to avoid stack overflow
        #pragma unroll
        for (int i = 0; i < MAX_STAGES; i++) {
            zero_ptr->stages[i].valid = 0;
            zero_ptr->stages[i].timestamp = 0;
            zero_ptr->stages[i].skb_ptr = 0;
            zero_ptr->ts[i] = 0;
            zero_ptr->skb_ptr[i] = 0;
        }
        zero_ptr->first_pid = 0;
        zero_ptr->ct_start_time = 0;
        zero_ptr->ct_lookup_duration = 0;
        zero_ptr->qdisc_enq_time = 0;
        zero_ptr->qdisc_qlen = 0;
        zero_ptr->direction = 0;
        zero_ptr->stage_count = 0;
        zero_ptr->complete = 0;
        
        flow_ptr = flow_sessions.lookup_or_try_init(&key, zero_ptr);
        if (flow_ptr) {
            // Initialize flow data
            flow_ptr->first_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->first_comm, sizeof(flow_ptr->first_comm));
            
            struct net_device *dev = NULL;
            if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
                bpf_probe_read_kernel_str(flow_ptr->first_ifname, IFNAMSIZ, dev->name);
            }
            
            flow_ptr->direction = direction;
            bpf_probe_read_kernel(&flow_ptr->queue_mapping, sizeof(flow_ptr->queue_mapping), &skb->queue_mapping);
            bpf_probe_read_kernel(&flow_ptr->skb_hash, sizeof(flow_ptr->skb_hash), &skb->hash);
            bpf_probe_read_kernel(&flow_ptr->len, sizeof(flow_ptr->len), &skb->len);
            bpf_probe_read_kernel(&flow_ptr->data_len, sizeof(flow_ptr->data_len), &skb->data_len);
        }
    } else {
        // Look up existing flow
        flow_ptr = flow_sessions.lookup(&key);
        if (flow_ptr) {
            // Check if flow direction matches current stage direction
            if (flow_ptr->direction != direction) {
                return;  // Direction mismatch, skip this stage
            }
        }
    }

    if (!flow_ptr) {
        return;
    }
    // Record detailed information for this stage
    if (stage_id < MAX_STAGES && !flow_ptr->stages[stage_id].valid) {
        struct stage_info_t *stage = &flow_ptr->stages[stage_id];
        
        stage->timestamp = current_ts;
        stage->skb_ptr = (u64)skb;
        stage->cpu = bpf_get_smp_processor_id();
        
        // Get current device info
        struct net_device *dev = NULL;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            bpf_probe_read_kernel(&stage->ifindex, sizeof(stage->ifindex), &dev->ifindex);
            bpf_probe_read_kernel_str(stage->devname, IFNAMSIZ, dev->name);
        }
        
        // Get current SKB info
        bpf_probe_read_kernel(&stage->queue_mapping, sizeof(stage->queue_mapping), &skb->queue_mapping);
        bpf_probe_read_kernel(&stage->skb_hash, sizeof(stage->skb_hash), &skb->hash);
        bpf_probe_read_kernel(&stage->len, sizeof(stage->len), &skb->len);
        bpf_probe_read_kernel(&stage->data_len, sizeof(stage->data_len), &skb->data_len);
        
        stage->valid = 1;
        flow_ptr->stage_count++;
        
        // Backward compatibility - still fill old fields
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (u64)skb;
    }
    
    // Handle special stages
    if (stage_id == STG_QDISC_ENQ || stage_id == STG_VNET_QDISC_ENQ) {
        flow_ptr->qdisc_enq_time = current_ts;
    }
    
    if (stage_id == STG_CT_RX || stage_id == STG_CT_TX) {
        flow_ptr->ct_start_time = current_ts;
    }
    
    if (stage_id == STG_CT_OUT_RX || stage_id == STG_CT_OUT_TX) {
        if (flow_ptr->ct_start_time > 0) {
            flow_ptr->ct_lookup_duration = (u32)(current_ts - flow_ptr->ct_start_time);
        }
    }
    
    flow_sessions.update(&key, flow_ptr);
    
    // Check if this is the last stage
    bool is_last_stage = false;
    if ((direction == 1 && stage_id == STG_TX_XMIT) ||   // vnet RX path ends
        (direction == 2 && stage_id == STG_VNET_TX)) {    // vnet TX path ends
        is_last_stage = true;
    }
    
    // Only submit event at the last stage
    if (is_last_stage) {
        // Check latency threshold before submitting
        if (LATENCY_THRESHOLD_NS > 0) {
            // Find first and last valid timestamps
            u64 first_ts = 0;
            u64 last_ts = current_ts;

            #pragma unroll
            for (int i = 0; i < MAX_STAGES; i++) {
                if (flow_ptr->stages[i].valid && flow_ptr->stages[i].timestamp > 0) {
                    first_ts = flow_ptr->stages[i].timestamp;
                    break;
                }
            }

            // Skip if latency below threshold
            if (first_ts == 0 || last_ts == 0 || (last_ts - first_ts) < LATENCY_THRESHOLD_NS) {
                flow_sessions.delete(&key);
                return;
            }
        }

        u32 map_key_zero = 0;
        struct pkt_event *event_ptr = event_scratch_map.lookup(&map_key_zero);
        if (!event_ptr) {
            return;
        }

        event_ptr->pkt_id = (u64)skb;
        event_ptr->key = key;
        event_ptr->timestamp = current_ts;
        event_ptr->cpu = bpf_get_smp_processor_id();
        event_ptr->stage = stage_id;
        event_ptr->event_type = 1;  // complete flow event

        // Get current device info
        struct net_device *dev = NULL;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            bpf_probe_read_kernel(&event_ptr->ifindex, sizeof(event_ptr->ifindex), &dev->ifindex);
            bpf_probe_read_kernel_str(event_ptr->devname, IFNAMSIZ, dev->name);
        }

        // Copy flow data and submit complete flow event
        if (bpf_probe_read_kernel(&event_ptr->flow, sizeof(event_ptr->flow), flow_ptr) == 0) {
            events.perf_submit(ctx, event_ptr, sizeof(*event_ptr));
        }

        // Clean up flow tracking
        flow_sessions.delete(&key);
    }
    
    // Update statistics
    u32 stat_idx = stage_id %% 32;
    u64 *counter = probe_stats.lookup(&stat_idx);
    if (counter) {
        (*counter)++;
    }
}

// Use tracepoint for both RX and TX direction - unified probe for first stage
RAW_TRACEPOINT_PROBE(netif_receive_skb) {
    // Get skb from tracepoint args
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    // TX Direction: Physical interface receives packets for VM
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 1) {
            return 0;  // Skip if vnet_rx only
        }
        handle_stage_event(ctx, skb, STG_PHY_RX, 2);  // direction=2 (vnet_tx)
    }

    // RX Direction: VM interface sends packets to physical
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 2) {
            return 0;  // Skip if vnet_tx only
        }
        handle_stage_event(ctx, skb, STG_VNET_RX, 1);  // direction=1 (vnet_rx)
    }

    return 0;
}

int kprobe__ovs_vport_receive(struct pt_regs *ctx, void *vport, struct sk_buff *skb, void *tun_info) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {  // vnet_rx or both
        handle_stage_event(ctx, skb, STG_OVS_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {  // vnet_tx or both
        handle_stage_event(ctx, skb, STG_OVS_TX, 2);
    }
    return 0;
}

int kprobe__nf_conntrack_in(struct pt_regs *ctx, struct net *net, u_int8_t pf, unsigned int hooknum, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {  // vnet_rx or both
        handle_stage_event(ctx, skb, STG_CT_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {  // vnet_tx or both
        handle_stage_event(ctx, skb, STG_CT_TX, 2);
    }
    
    return 0;
}

// OVS upcall probe point - captures flow table miss events
int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (!skb) return 0;
    
    // Upcall happens when flow table miss occurs
    if (DIRECTION_FILTER != 2) {  // vnet_rx or both
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {  // vnet_tx or both
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_TX, 2);
    }
    
    return 0;
}

// OVS userspace flow key extraction - captures upcall processing completion
int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) return 0;
    
    // Userspace key extraction happens during upcall processing
    if (DIRECTION_FILTER != 2) {  // vnet_rx or both
        handle_stage_event(ctx, skb, STG_OVS_USERSPACE_RX, 1);
    }
    if (DIRECTION_FILTER != 1) {  // vnet_tx or both
        handle_stage_event(ctx, skb, STG_OVS_USERSPACE_TX, 2);
    }
    
    return 0;
}

int kprobe__ovs_ct_update_key(struct pt_regs *ctx, struct sk_buff *skb, void *info, void *key, bool post_ct, bool keep_nat_flags) {
    
    if (!skb) return 0;
    
    // Distinguish between flow extract and conntrack action calls
    // post_ct=false indicates flow extract phase (ovs_ct_fill_key) - occurs BEFORE upcall
    // post_ct=true indicates conntrack action phase (__ovs_ct_lookup) - occurs AFTER upcall
    if (post_ct) {
        // Conntrack action phase - occurs after upcall processing
        if (DIRECTION_FILTER != 2) {  // vnet_rx or both
            handle_stage_event(ctx, skb, STG_CT_OUT_RX, 1);
        }
        if (DIRECTION_FILTER != 1) {  // vnet_tx or both
            handle_stage_event(ctx, skb, STG_CT_OUT_TX, 2);
        }
    } else {
        // Flow extract phase - occurs BEFORE upcall (when flow table miss detected)
        if (DIRECTION_FILTER != 2) {  // vnet_rx or both
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_RX, 1);
        }
        if (DIRECTION_FILTER != 1) {  // vnet_tx or both
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_TX, 2);
        }
    }
    
    return 0;
}

// Qdisc enqueue using tracepoint trace_net_dev_queue
RAW_TRACEPOINT_PROBE(net_dev_queue) {
    // args: struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
        handle_stage_event(ctx, skb, STG_QDISC_ENQ, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
        handle_stage_event(ctx, skb, STG_VNET_QDISC_ENQ, 2);
    }
    
    return 0;
}

// Qdisc dequeue tracepoint 
RAW_TRACEPOINT_PROBE(qdisc_dequeue) {
    // args: struct Qdisc *qdisc, const struct netdev_queue *txq, int packets, struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[3];
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
        handle_stage_event(ctx, skb, STG_QDISC_DEQ, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
        handle_stage_event(ctx, skb, STG_VNET_QDISC_DEQ, 2);
    }
    
    return 0;
}

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb) return 0;
    
    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
        handle_stage_event(ctx, skb, STG_TX_QUEUE, 1);
    }
    
    if (is_target_vm_interface(skb)) {
        if (DIRECTION_FILTER == 1) return 0;  // Skip if vnet_rx only
        handle_stage_event(ctx, skb, STG_VNET_TX, 2);  // Last stage for vnet_tx
    }
    
    return 0;
}

int kprobe__dev_queue_xmit_nit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !is_target_phy_interface(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0;  // Skip if vnet_tx only
    
    handle_stage_event(ctx, skb, STG_TX_XMIT, 1);  // Last stage for vnet_rx
    return 0;
}

"""

# Constants
MAX_STAGES = 22
IFNAMSIZ = 16
TASK_COMM_LEN = 16

# Event data structure - matching BPF structure
class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("proto", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("data", ctypes.c_uint8 * 8)  # Union data
    ]

# Per-stage information structure
class StageInfo(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("skb_ptr", ctypes.c_uint64),
        ("ifindex", ctypes.c_uint32),
        ("devname", ctypes.c_char * IFNAMSIZ),
        ("queue_mapping", ctypes.c_int16),
        ("skb_hash", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
        ("data_len", ctypes.c_uint32),
        ("cpu", ctypes.c_uint32),
        ("valid", ctypes.c_uint8)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("stages", StageInfo * MAX_STAGES),
        ("first_pid", ctypes.c_uint32),
        ("first_comm", ctypes.c_char * TASK_COMM_LEN),
        ("ct_start_time", ctypes.c_uint64),
        ("ct_lookup_duration", ctypes.c_uint32),
        ("qdisc_enq_time", ctypes.c_uint64),
        ("qdisc_qlen", ctypes.c_uint32),
        ("direction", ctypes.c_uint8),
        ("stage_count", ctypes.c_uint8),
        ("complete", ctypes.c_uint8),
        # Backward compatibility fields
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_STAGES),
        ("queue_mapping", ctypes.c_int16),
        ("skb_hash", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
        ("data_len", ctypes.c_uint32),
        ("first_ifname", ctypes.c_char * IFNAMSIZ)
    ]

class PktEvent(ctypes.Structure):
    _fields_ = [
        ("pkt_id", ctypes.c_uint64),
        ("key", PacketKey),
        ("flow", FlowData),
        ("timestamp", ctypes.c_uint64),
        ("cpu", ctypes.c_uint32),
        ("ifindex", ctypes.c_uint32),
        ("devname", ctypes.c_char * IFNAMSIZ),
        ("stage", ctypes.c_uint8),
        ("event_type", ctypes.c_uint8)
    ]

# Helper Functions - reusing vm_network_latency.py logic
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
    return stage_names.get(stage_id, "Unknown_%d" % stage_id)

def get_protocol_identifier(key, protocol):
    """Get protocol-specific packet identifier"""
    data = ctypes.string_at(ctypes.addressof(key.data), 8)
    
    if protocol == 6:  # TCP
        # TCP: source(2) + dest(2) + seq(4)
        source = struct.unpack("!H", data[0:2])[0]
        dest = struct.unpack("!H", data[2:4])[0]
        seq = struct.unpack("!I", data[4:8])[0]
        return "TCP %d->%d seq=%u" % (source, dest, seq)
    elif protocol == 17:  # UDP
        # UDP: source(2) + dest(2) + id(2) + len(2)
        source = struct.unpack("!H", data[0:2])[0]
        dest = struct.unpack("!H", data[2:4])[0]
        ip_id = struct.unpack("!H", data[4:6])[0]
        return "UDP %d->%d id=%u" % (source, dest, ip_id)
    elif protocol == 1:  # ICMP
        # ICMP: id(2) + seq(2) + type(1) + code(1)
        icmp_id = struct.unpack("!H", data[0:2])[0]
        seq = struct.unpack("!H", data[2:4])[0]
        icmp_type = data[4] if len(data) > 4 else 0
        return "ICMP id=%u seq=%u type=%u" % (icmp_id, seq, icmp_type)
    else:
        return "Proto%d" % protocol

def print_event(cpu, data, size):
    """Print performance event"""
    global args
    event = ctypes.cast(data, ctypes.POINTER(PktEvent)).contents
    
    # Now we only receive complete flow events (event_type=1)
    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    protocol_name = protocol_names.get(event.key.proto, "Proto%d" % event.key.proto)
    
    # Get protocol-specific packet identifier
    pkt_id = get_protocol_identifier(event.key, event.key.proto)
    
    # Get current timestamp for the flow complete line
    current_time = datetime.datetime.now()
    print("[%s] === FLOW COMPLETE: %d stages captured ===" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        event.flow.stage_count
    ))
    
    # Display 5-tuple information
    src_ip = format_ip(event.key.sip)
    dst_ip = format_ip(event.key.dip)
    print("FLOW: %s -> %s (%s)" % (src_ip, dst_ip, pkt_id))
    
    # Display detailed 5-tuple
    direction_str = "VNET_RX" if event.flow.direction == 1 else "VNET_TX"
    if event.key.proto == 6:  # TCP
        tcp_data = ctypes.string_at(ctypes.addressof(event.key.data), 8)
        src_port = struct.unpack("!H", tcp_data[0:2])[0] 
        dst_port = struct.unpack("!H", tcp_data[2:4])[0]
        seq = struct.unpack("!I", tcp_data[4:8])[0]
        print("5-TUPLE: %s:%d -> %s:%d TCP (seq=%u) DIR=%s" % (src_ip, src_port, dst_ip, dst_port, seq, direction_str))
    elif event.key.proto == 17:  # UDP
        udp_data = ctypes.string_at(ctypes.addressof(event.key.data), 8)
        src_port = struct.unpack("!H", udp_data[0:2])[0]
        dst_port = struct.unpack("!H", udp_data[2:4])[0]
        ip_id = struct.unpack("!H", udp_data[4:6])[0]
        print("5-TUPLE: %s:%d -> %s:%d UDP (id=%u) DIR=%s" % (src_ip, src_port, dst_ip, dst_port, ip_id, direction_str))
    elif event.key.proto == 1:  # ICMP
        icmp_data = ctypes.string_at(ctypes.addressof(event.key.data), 8)
        icmp_id = struct.unpack("!H", icmp_data[0:2])[0]
        seq = struct.unpack("!H", icmp_data[2:4])[0]
        icmp_type = icmp_data[4] if len(icmp_data) > 4 else 0
        print("5-TUPLE: %s -> %s ICMP (id=%u seq=%u type=%u) DIR=%s" % (src_ip, dst_ip, icmp_id, seq, icmp_type, direction_str))
    else:
        print("5-TUPLE: %s -> %s Proto%d DIR=%s" % (src_ip, dst_ip, event.key.proto, direction_str))
    
    # Collect valid stages using the new stages array
    stages = []
    for i in range(MAX_STAGES):
        if event.flow.stages[i].valid:
            stages.append((i, event.flow.stages[i]))
    
    # Sort by stage ID to maintain logical order (not by timestamp)
    stages.sort(key=lambda x: x[0])  # Sort by stage_id instead of timestamp
    
    # Print stages with detailed information from each stage
    prev_ts = None
    for idx, (stage_id, stage_info) in enumerate(stages):
        delta_str = ""
        if prev_ts is not None:
            delta_ns = stage_info.timestamp - prev_ts
            if delta_ns >= 0:
                delta_str = " (+%.3fus)" % (delta_ns / 1000.0)
            else:
                delta_str = " (%.3fus)" % (delta_ns / 1000.0)  # Negative values already have minus sign
        
        # Get exact device name from stage_info
        devname = stage_info.devname.decode('utf-8', 'replace').rstrip('\x00')
        
        print("  Stage %s: KTIME=%luns%s" % (
            get_stage_name(stage_id), 
            stage_info.timestamp, 
            delta_str
        ))
        
        # Print detailed stage information
        print("    SKB: ptr=0x%x len=%d data_len=%d queue_mapping=%d hash=0x%x" % (
            stage_info.skb_ptr, stage_info.len, stage_info.data_len, 
            stage_info.queue_mapping, stage_info.skb_hash
        ))
        
        print("    DEV: %s (ifindex=%d) CPU=%d" % (
            devname, stage_info.ifindex, stage_info.cpu
        ))
        
        prev_ts = stage_info.timestamp
        
    # Show total flow duration
    if len(stages) > 1:
        total_duration = stages[-1][1].timestamp - stages[0][1].timestamp
        print("  TOTAL DURATION: %.3fus" % (total_duration / 1000.0))
    
    # Show detailed packet information
    print("  PACKET: len=%d data_len=%d queue_mapping=%d skb_hash=0x%x" % (
        event.flow.len, event.flow.data_len, event.flow.queue_mapping, event.flow.skb_hash
    ))
    
    # Show process and interface information
    first_comm = event.flow.first_comm.decode('utf-8', 'replace').rstrip('\x00')
    first_ifname = event.flow.first_ifname.decode('utf-8', 'replace').rstrip('\x00')
    print("  PROCESS: pid=%d comm=%s first_dev=%s" % (
        event.flow.first_pid, first_comm, first_ifname
    ))
    
    # Show final stage device information
    final_dev = event.devname.decode('utf-8', 'replace').rstrip('\x00')
    print("  FINAL_STAGE: dev=%s(ifindex=%d) cpu=%d" % (
        final_dev, event.ifindex, event.cpu
    ))
    
    # Show metrics if available
    if event.flow.qdisc_enq_time > 0:
        for stage_id, stage_info in stages:
            if stage_id == 9 or stage_id == 20:  # QDISC_DEQ or VNET_QDISC_DEQ
                sojourn_time_ns = stage_info.timestamp - event.flow.qdisc_enq_time
                qdisc_type = "QDISC" if stage_id == 9 else "VNET_QDISC"
                print("  %s: sojourn=%.3fus qlen=%d" % (qdisc_type, sojourn_time_ns / 1000.0, event.flow.qdisc_qlen))
                break
    
    if event.flow.ct_lookup_duration > 0:
        print("  CT: lookup=%.3fus" % (event.flow.ct_lookup_duration / 1000.0))
        
    print("")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="VM Network Performance Tracing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor VM TX traffic (packets leaving VM):
    sudo %(prog)s --vm-interface vnet37 --phy-interface enp94s0f0np0 --direction tx --src-ip 192.168.76.198

  Monitor VM RX traffic (packets entering VM):
    sudo %(prog)s --vm-interface vnet37 --phy-interface enp94s0f0np0 --direction rx --dst-ip 192.168.76.198

  Monitor TCP SSH traffic to VM:
    sudo %(prog)s --vm-interface vnet37 --phy-interface enp94s0f0np0 --protocol tcp --dst-port 22 --direction rx

  Monitor VM TX flows with latency > 100us:
    sudo %(prog)s --vm-interface vnet37 --phy-interface enp94s0f0np0 --direction tx --src-ip 192.168.76.198 --latency-us 100
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
    parser.add_argument('--latency-us', type=float, default=0,
                        help='Minimum latency threshold in microseconds to report (default: 0, report all)')
    parser.add_argument('--enable-ct', action='store_true',
                        help='Enable conntrack measurement')
    parser.add_argument('--verbose', action='store_true',
                        help='Verbose output')
    
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

    direction_map = {'tx': 1, 'rx': 2}  # tx=VM_TX(VNET_RX path), rx=VM_RX(VNET_TX path)
    direction_filter = direction_map[args.direction]

    # Convert latency threshold from microseconds to nanoseconds
    latency_threshold_ns = int(args.latency_us * 1000)

    # Support multiple interfaces (split by comma)
    phy_interfaces = args.phy_interface.split(',')
    try:
        vm_ifindex = get_if_index(args.vm_interface)
        phy_ifindex1 = get_if_index(phy_interfaces[0].strip())
        phy_ifindex2 = get_if_index(phy_interfaces[1].strip()) if len(phy_interfaces) > 1 else phy_ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    print("=== VM Network Performance Tracer ===")
    print("Protocol filter: %s" % args.protocol.upper())
    print("Direction filter: %s (tx=VM_TX, rx=VM_RX)" % args.direction.upper())
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
    print("Conntrack measurement: %s" % ("ENABLED" if args.enable_ct else "DISABLED"))
    if latency_threshold_ns > 0:
        print("Latency threshold: >= %.3f us (only reporting flows exceeding this latency)" % args.latency_us)

    # Debug parameter values
    print("\nDebug: BPF parameters:")
    print("  src_ip_hex=0x%x, dst_ip_hex=0x%x" % (src_ip_hex, dst_ip_hex))
    print("  src_port=%d, dst_port=%d" % (src_port, dst_port))
    print("  protocol_filter=%d, vm_ifindex=%d, phy_ifindex1=%d, phy_ifindex2=%d, direction_filter=%d" %
          (protocol_filter, vm_ifindex, phy_ifindex1, phy_ifindex2, direction_filter))

    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, vm_ifindex, phy_ifindex1, phy_ifindex2, direction_filter,
            latency_threshold_ns
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        print("\nActual format string substitution:")
        print("Parameters passed: %d arguments" % len([src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_filter, vm_ifindex, phy_ifindex1, phy_ifindex2, direction_filter, latency_threshold_ns]))
        sys.exit(1)
    
    b["events"].open_perf_buffer(print_event)
    
    print("\nTracing VM network performance... Hit Ctrl-C to end.")
    print("Format: [YYYY-MM-DD HH:MM:SS.mmm] PKT_ID DIR STAGE DEV KTIME=ns")
    print("        FLOW: src -> dst (protocol_identifier)")
    print("        QUEUE/CT/QDISC metrics")
    print("        Complete flow summary at last stage with absolute kernel timestamps")
    print("")
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")

        print("\n=== Performance Statistics ===")
        
        print("Event counts by probe point:")
        probe_stats = b["probe_stats"]
        for i in range(32):
            count = probe_stats[i].value
            if count > 0:
                print("  Probe %d: %d events" % (i, count))
    finally:
        print("Exiting.")