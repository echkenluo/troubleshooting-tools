#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
System Network Performance Tracing Tool

Provides comprehensive system network performance measurement with packet tracking
through the entire network stack. Uses LRU hash for packet identification
and tracks packets from first probe point through all stages.

Key features:
- Packet unique identification with LRU hash storage
- Direction based on internal port perspective (tx/rx)
- Qdisc enqueue/dequeue monitoring for physical interface only
- Complete packet path tracing
- No qdisc for internal port

Usage:
    sudo ./system_net_perf_trace.py --internal-interface port-mgt --phy-interface enp94s0f0np0 \
                                    --src-ip 192.168.70.33 --direction tx

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
import re

# Global configuration
direction_filter = 0  # 0=both, 1=system_tx(local_to_uplink), 2=system_rx(uplink_to_local)

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
#include <net/inet_sock.h>
#include <net/tcp.h>

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP, 1=ICMP
#define INTERNAL_IFINDEX %d
#define PHY_IFINDEX1 %d
#define PHY_IFINDEX2 %d
#define DIRECTION_FILTER %d  // 0=both, 1=system_tx, 2=system_rx
#define LATENCY_THRESHOLD_NS %d  // Minimum total latency threshold in nanoseconds

// Stage definitions - internal port perspective
// TX direction probes (EXTENDED: socket -> network)
// REMOVED: STG_SOCK_SEND and STG_TCP_UDP_SEND - socket and protocol layer probes removed
#define STG_SOCK_SEND_SYSCALL 21  // sys_enter_sendto/sys_enter_send - syscall entry
#define STG_IP_QUEUE_XMIT    1   // __ip_queue_xmit - FIRST STAGE for TCP TX
#define STG_IP_OUTPUT        2   // ip_output - FIRST STAGE for ICMP TX
#define STG_OVS_TX           3   // ovs_vport_receive (internal port)
#define STG_FLOW_EXTRACT_TX  4   // ovs_ct_update_key (flow extract phase)
#define STG_CT_TX            5   // nf_conntrack_in
#define STG_CT_OUT_TX        6   // ovs_ct_update_key (conntrack action)
#define STG_PHY_QDISC_ENQ    7   // qdisc_enqueue (physical dev)
#define STG_PHY_QDISC_DEQ    8   // qdisc_dequeue (physical dev)
#define STG_PHY_TX           9   // dev_hard_start_xmit (physical) - LAST POINT

// RX direction probes (EXTENDED: network -> socket)
#define STG_PHY_RX           11  // netif_receive_skb (physical) - FIRST POINT
#define STG_OVS_RX           12  // ovs_vport_receive (from physical to internal)
#define STG_FLOW_EXTRACT_RX  13  // ovs_ct_update_key (flow extract phase)
#define STG_CT_RX            14  // nf_conntrack_in
#define STG_CT_OUT_RX        15  // ovs_ct_update_key (conntrack action)
#define STG_INTERNAL_DEV_RECV 16  // internal_dev_recv - internal port device receive
#define STG_INTERNAL_SOFTIRQ 17  // netif_receive_skb (internal port) - network RX end before protocol stack
#define STG_IP_RCV           18  // ip_rcv - IP receive
#define STG_TCP_UDP_RCV      19  // tcp_v4_rcv/udp_rcv - protocol layer recv - LAST POINT for RX
#define STG_ICMP_RCV         25  // icmp_rcv - ICMP receive - LAST POINT for ICMP RX
#define STG_IP_SEND_SKB      26  // ip_send_skb - FIRST POINT for UDP TX
// REMOVED: #define STG_SOCK_QUEUE       23  // sock_queue_rcv_skb - socket buffer queueing  
// REMOVED: #define STG_SOCK_RECV_SYSCALL 24 // sys_enter_recvfrom/sys_enter_recv - syscall entry
// REMOVED: #define STG_SOCK_RECV        20  // socket receive complete - LAST POINT

#define MAX_STAGES          27
#define IFNAMSIZ            16
#define TASK_COMM_LEN       16

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
    
    // Qdisc timing (physical interface only)
    u64 qdisc_enq_time;           // When packet was enqueued to qdisc
    u32 qdisc_qlen;               // Queue length at dequeue time
    
    // Direction and flow state
    u8 direction;                 // 1=system_tx, 2=system_rx
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

// Events output
BPF_PERF_OUTPUT(events);

// Helper functions - reusing vm_network_latency.py proven logic
static __always_inline bool is_target_internal_interface(const struct sk_buff *skb) {
    if (INTERNAL_IFINDEX == 0) return false;
    
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    return (ifindex == INTERNAL_IFINDEX);
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
    u8 direction  // 1=system_tx, 2=system_rx
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip) != 0) {
        return 0;
    }

    // Apply filters first
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }

    // Direction-specific IP filtering
    if (direction == 1) { // system_tx: packets from system (source should be system IP)
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    } else if (direction == 2) { // system_rx: packets to system (destination should be system IP)
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    } else {
        // For both directions, use OR logic (either source OR destination matches)
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
            return 0;
        }
        if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
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
            if (get_transport_header(skb, &icmp, sizeof(icmp)) != 0) {
                return 0;
            }

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

// TCP packet key parsing for early stage (__ip_queue_xmit) - with tcp_sock fix
static __always_inline int parse_packet_key_tcp_early(
    struct sk_buff *skb,
    struct sock *sk,
    struct packet_key_t *key,
    u8 stage_id
) {
    if (!sk) return 0;

    // Get from socket - this is reliable at __ip_queue_xmit
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&key->sip, sizeof(key->sip), &inet->inet_saddr);
    bpf_probe_read_kernel(&key->dip, sizeof(key->dip), &inet->inet_daddr);
    bpf_probe_read_kernel(&key->tcp.source, sizeof(key->tcp.source), &inet->inet_sport);
    bpf_probe_read_kernel(&key->tcp.dest, sizeof(key->tcp.dest), &inet->inet_dport);
    key->proto = IPPROTO_TCP;

    // Apply same filters as standard function
    if (PROTOCOL_FILTER != 0 && key->proto != PROTOCOL_FILTER) {
        return 0;
    }

    // Direction-specific IP filtering (direction 1 = system_tx)
    if (SRC_IP_FILTER != 0 && key->sip != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && key->dip != DST_IP_FILTER) {
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
        struct iphdr ip;
        if (get_ip_header(skb, &ip) == 0 && ip.protocol == IPPROTO_TCP) {
            struct tcphdr tcp;
            if (get_transport_header(skb, &tcp, sizeof(tcp)) == 0) {
                key->tcp.seq = tcp.seq;
            }
        }
    }

    // Apply port filters
    if (SRC_PORT_FILTER != 0 && key->tcp.source != htons(SRC_PORT_FILTER) && key->tcp.dest != htons(SRC_PORT_FILTER)) {
        return 0;
    }
    if (DST_PORT_FILTER != 0 && key->tcp.source != htons(DST_PORT_FILTER) && key->tcp.dest != htons(DST_PORT_FILTER)) {
        return 0;
    }

    return 1;
}

// REMOVED: build_tcp_tx_packet_key function - no longer needed without socket probes

// REMOVED: handle_tcp_tx_stage_event function - no longer needed without socket probes

// Main event handling function - tracks packets through all stages
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb, u8 stage_id, u8 direction) {
    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();

    // Parse packet key for identification
    if (!parse_packet_key(skb, &key, direction)) {
        return;
    }

    // Check if this is the first stage for this direction
    bool is_first_stage = false;
    if ((direction == 1 && stage_id == STG_IP_QUEUE_XMIT) || // TCP TX path starts with __ip_queue_xmit
        (direction == 1 && stage_id == STG_IP_OUTPUT) ||      // ICMP TX path starts with ip_output
        (direction == 1 && stage_id == STG_IP_SEND_SKB) ||    // UDP TX path starts with ip_send_skb
        (direction == 2 && stage_id == STG_PHY_RX)) {        // system RX path starts with physical RX
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
    if (stage_id == STG_PHY_QDISC_ENQ) {
        flow_ptr->qdisc_enq_time = current_ts;
    }
    
    if (stage_id == STG_CT_TX || stage_id == STG_CT_RX) {
        flow_ptr->ct_start_time = current_ts;
    }
    
    if (stage_id == STG_CT_OUT_TX || stage_id == STG_CT_OUT_RX) {
        if (flow_ptr->ct_start_time > 0) {
            flow_ptr->ct_lookup_duration = (u32)(current_ts - flow_ptr->ct_start_time);
        }
    }
    
    flow_sessions.update(&key, flow_ptr);
    
    // Check if this is the last stage
    bool is_last_stage = false;
    if ((direction == 1 && stage_id == STG_PHY_TX) ||        // system TX path ends at physical TX
        (direction == 2 && stage_id == STG_TCP_UDP_RCV) ||   // TCP/UDP RX ends at protocol layer recv
        (direction == 2 && stage_id == STG_ICMP_RCV)) {      // ICMP RX ends at icmp_rcv
        is_last_stage = true;
    }

    // Only submit event at the last stage
    if (is_last_stage) {
        // Check latency threshold before submitting
        if (LATENCY_THRESHOLD_NS > 0) {
            // Find first stage timestamp
            u64 first_ts = 0;
            #pragma unroll
            for (int i = 0; i < MAX_STAGES; i++) {
                if (flow_ptr->stages[i].valid && flow_ptr->stages[i].timestamp > 0) {
                    first_ts = flow_ptr->stages[i].timestamp;
                    break;
                }
            }

            // Check if total latency exceeds threshold
            if (first_ts == 0 || current_ts == 0 || (current_ts - first_ts) < LATENCY_THRESHOLD_NS) {
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
}

// Socket layer helper for packet tracking without skb - WITH DIRECTION-AWARE FILTERING
static __always_inline int handle_socket_event(struct sock *sk, u8 stage_id, u8 direction) {
    
    if ((direction == 1 && DIRECTION_FILTER == 2) ||    // TX but rx_only mode
        (direction == 2 && DIRECTION_FILTER == 1)) {    // RX but tx_only mode
        return 0;
    }
    
    if (!sk) {
        return 0;
    }
    
    // Extract connection info from socket for packet identification
    u16 family = 0;
    u32 sock_saddr = 0, sock_daddr = 0, sock_rcv_saddr = 0;
    u16 sock_sport = 0, sock_dport = 0, sock_num = 0;
    
    // Read socket family
    if (bpf_probe_read_kernel(&family, sizeof(family), &sk->sk_family) != 0) {
        return 0;
    }
    
    if (family != AF_INET) {
        return 0;  // Only handle IPv4
    }
    
    struct inet_sock *inet = inet_sk(sk);
    if (!inet) {
        return 0;
    }
    
    // Read all socket addresses to understand the connection
    if (bpf_probe_read_kernel(&sock_saddr, sizeof(sock_saddr), &inet->inet_saddr) != 0 ||
        bpf_probe_read_kernel(&sock_daddr, sizeof(sock_daddr), &inet->inet_daddr) != 0 ||
        bpf_probe_read_kernel(&sock_rcv_saddr, sizeof(sock_rcv_saddr), &inet->sk.__sk_common.skc_rcv_saddr) != 0 ||
        bpf_probe_read_kernel(&sock_sport, sizeof(sock_sport), &inet->inet_sport) != 0 ||
        bpf_probe_read_kernel(&sock_dport, sizeof(sock_dport), &inet->inet_dport) != 0 ||
        bpf_probe_read_kernel(&sock_num, sizeof(sock_num), &inet->sk.__sk_common.skc_num) != 0) {
        return 0;
    }
    
    // Apply DIRECTION-AWARE filtering based on RX/TX packet flow semantics
    bool match_found = false;
    
    if (direction == 1) { // TX direction (system sending): socket local -> remote
        // For TX: socket local addresses should match our filter constraints
        if (SRC_IP_FILTER != 0) {
            // Check if socket local address matches SRC_IP_FILTER
            if (sock_saddr == SRC_IP_FILTER || sock_rcv_saddr == SRC_IP_FILTER) {
                match_found = true;
            } else if (SRC_IP_FILTER != 0) {
                return 0;
            }
        }
        if (DST_IP_FILTER != 0) {
            // Check if socket remote address matches DST_IP_FILTER  
            if (sock_daddr == DST_IP_FILTER) {
                match_found = true;
            } else if (DST_IP_FILTER != 0) {
                return 0;
            }
        }
    } else if (direction == 2) { // RX direction (system receiving): remote -> socket local
        // For RX direction, socket address semantics:
        // - sock_daddr/sock_dport: remote endpoint (packet source)
        // - sock_rcv_saddr/sock_num: local bound endpoint (packet destination)
        
        if (SRC_IP_FILTER != 0) {
            // Packet source should match socket remote address (sock_daddr)
            if (sock_daddr == SRC_IP_FILTER) {
                match_found = true;
            } else {
                return 0;
            }
        }
        if (DST_IP_FILTER != 0) {
            // Packet destination should match socket local bound address (sock_rcv_saddr)
            if (sock_rcv_saddr == DST_IP_FILTER) {
                match_found = true;
            } else {
                return 0;
            }
        }
    }
    
    // If no filters specified, or if we found at least one match, allow the event
    if ((SRC_IP_FILTER == 0 && DST_IP_FILTER == 0) || match_found) {
        return 1; // Successfully processed with correct direction semantics
    }
    
    return 0;
}


// TX direction probes
// TCP first stage: __ip_queue_xmit - use tcp_sock for reliable packet key, handle directly
int kprobe____ip_queue_xmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, void *fl) {
    if (!skb || !sk) {
        return 0;
    }

    if (DIRECTION_FILTER == 2) {
        return 0;  // Skip if system_rx only
    }

    // Use tcp_sock-based parsing for reliable packet key extraction
    struct packet_key_t key = {};
    if (!parse_packet_key_tcp_early(skb, sk, &key, STG_IP_QUEUE_XMIT)) {
        return 0;
    }


    // Handle stage event directly without calling parse_packet_key again
    u64 current_ts = bpf_ktime_get_ns();
    u8 direction = 1; // TX direction

    // This is first stage for TCP TX

    // Initialize new flow tracking using per-cpu map
    flow_sessions.delete(&key);  // Clean any old entries

    u32 init_key = 0;
    struct flow_data_t *zero_ptr = flow_init_map.lookup(&init_key);
    if (!zero_ptr) {
        return 0;
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

    struct flow_data_t *flow_ptr = flow_sessions.lookup_or_try_init(&key, zero_ptr);
    if (!flow_ptr) {
        return 0;
    }

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


    // Record detailed information for this stage
    if (STG_IP_QUEUE_XMIT < MAX_STAGES && !flow_ptr->stages[STG_IP_QUEUE_XMIT].valid) {
        struct stage_info_t *stage = &flow_ptr->stages[STG_IP_QUEUE_XMIT];

        stage->timestamp = current_ts;
        stage->skb_ptr = (u64)skb;
        stage->cpu = bpf_get_smp_processor_id();

        // Get current device info
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
        flow_ptr->ts[STG_IP_QUEUE_XMIT] = current_ts;
        flow_ptr->skb_ptr[STG_IP_QUEUE_XMIT] = (u64)skb;
    }

    flow_sessions.update(&key, flow_ptr);


    return 0;
}

// REMOVED: ip_output probe - TCP uses __ip_queue_xmit, UDP/ICMP use ip_send_skb

int kprobe__ovs_vport_receive(struct pt_regs *ctx, void *vport, struct sk_buff *skb, void *tun_info) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {  // system_tx or both
        if (is_target_internal_interface(skb)) {
            handle_stage_event(ctx, skb, STG_OVS_TX, 1);
        }
    }
    if (DIRECTION_FILTER != 1) {  // system_rx or both
        handle_stage_event(ctx, skb, STG_OVS_RX, 2);
    }
    return 0;
}

int kprobe__nf_conntrack_in(struct pt_regs *ctx, struct net *net, u_int8_t pf, unsigned int hooknum, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER != 2) {  // system_tx or both
        handle_stage_event(ctx, skb, STG_CT_TX, 1);
    }
    if (DIRECTION_FILTER != 1) {  // system_rx or both
        handle_stage_event(ctx, skb, STG_CT_RX, 2);
    }
    
    return 0;
}

// Manual attach - function name varies by kernel/compiler optimization
int trace_ovs_ct_update_key(struct pt_regs *ctx, struct sk_buff *skb, void *info, void *key, bool post_ct, bool keep_nat_flags) {
    if (!skb) return 0;

    // Distinguish between flow extract and conntrack action calls
    // post_ct=false indicates flow extract phase (ovs_ct_fill_key)
    // post_ct=true indicates conntrack action phase (__ovs_ct_lookup)
    if (post_ct) {
        // Conntrack action phase
        if (DIRECTION_FILTER != 2) {  // system_tx or both
            handle_stage_event(ctx, skb, STG_CT_OUT_TX, 1);
        }
        if (DIRECTION_FILTER != 1) {  // system_rx or both
            handle_stage_event(ctx, skb, STG_CT_OUT_RX, 2);
        }
    } else {
        // Flow extract phase
        if (DIRECTION_FILTER != 2) {  // system_tx or both
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_TX, 1);
        }
        if (DIRECTION_FILTER != 1) {  // system_rx or both
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_RX, 2);
        }
    }

    return 0;
}

// Physical interface qdisc (only for system TX path)
RAW_TRACEPOINT_PROBE(net_dev_queue) {
    // args: struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb || !is_target_phy_interface(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0;  // Skip if system_rx only
    
    handle_stage_event(ctx, skb, STG_PHY_QDISC_ENQ, 1);
    return 0;
}

RAW_TRACEPOINT_PROBE(qdisc_dequeue) {
    // args: struct Qdisc *qdisc, const struct netdev_queue *txq, int packets, struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[3];
    if (!skb || !is_target_phy_interface(skb)) return 0;
    if (DIRECTION_FILTER == 2) return 0;  // Skip if system_rx only
    
    handle_stage_event(ctx, skb, STG_PHY_QDISC_DEQ, 1);
    return 0;
}

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb) return 0;

    if (is_target_phy_interface(skb)) {
        if (DIRECTION_FILTER == 2) {
            return 0;  // Skip if system_rx only
        }
        handle_stage_event(ctx, skb, STG_PHY_TX, 1);  // Last stage for system_tx
    }

    return 0;
}


// Unified netif_receive_skb tracepoint - both physical and internal ports pass through here
RAW_TRACEPOINT_PROBE(netif_receive_skb) {
    // args: struct sk_buff *skb
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    
    // Get interface information
    struct net_device *dev = NULL;
    int ifindex = 0;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) != 0 || dev == NULL) {
        return 0;
    }
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) != 0) {
        return 0;
    }
    
    // Route to appropriate stage based on interface type and direction
    if (ifindex == PHY_IFINDEX1 || ifindex == PHY_IFINDEX2) {
        // Physical interface

        if (DIRECTION_FILTER == 1) {
            return 0;  // Skip if system_tx only
        }

        handle_stage_event(ctx, skb, STG_PHY_RX, 2);  // Physical RX stage for system_rx

    } else if (ifindex == INTERNAL_IFINDEX) {
        // Internal port - this is the softirq processing stage (after internal_dev_recv)
        
        if (DIRECTION_FILTER == 1) {
            return 0;  // Skip if system_tx only
        }
        
        handle_stage_event(ctx, skb, STG_INTERNAL_SOFTIRQ, 2);  // Network RX end stage
        
    } else {
        // Other interfaces - filter out
    }
    
    return 0;
}

// Removed - now handled in unified netif_receive_skb tracepoint

// Internal port device receive - OVS sends to kernel via internal_dev_recv  
int kprobe__internal_dev_recv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER == 1) {
        return 0;  // Skip if system_tx only
    }
    
    // Verify this is our target internal interface
    if (is_target_internal_interface(skb)) {
        handle_stage_event(ctx, skb, STG_INTERNAL_DEV_RECV, 2);  // Internal device receive entry
    } else {
    }
    
    return 0;
}

int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER == 1) return 0;  // Skip if system_tx only
    handle_stage_event(ctx, skb, STG_IP_RCV, 2);
    return 0;
}

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }
    
    if (DIRECTION_FILTER == 1) {
        return 0;  // Skip if system_tx only
    }
    
    
    handle_stage_event(ctx, skb, STG_TCP_UDP_RCV, 2);
    return 0;
}

int kprobe__udp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb) return 0;
    
    if (DIRECTION_FILTER == 1) return 0;  // Skip if system_tx only
    handle_stage_event(ctx, skb, STG_TCP_UDP_RCV, 2);
    return 0;
}

// ICMP-specific probe points
int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }
    
    if (DIRECTION_FILTER == 1) {
        return 0;  // Skip if system_tx only
    }
    
    handle_stage_event(ctx, skb, STG_ICMP_RCV, 2);  // LAST STAGE for ICMP RX
    return 0;
}

// ip_send_skb - UDP TX entry point
// Manual attach - function signature varies by kernel version
int trace_ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }

    if (DIRECTION_FILTER == 2) {
        return 0;  // Skip if system_rx only
    }

    handle_stage_event(ctx, skb, STG_IP_SEND_SKB, 1);  // FIRST STAGE for UDP TX
    return 0;
}

// ip_output - IP output (ICMP TX entry point)
// ICMP echo reply on 5.10+ kernel uses this path
// Manual attach - function signature varies by kernel version
int trace_ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }

    if (DIRECTION_FILTER == 2) {
        return 0;  // Skip if system_rx only
    }

    handle_stage_event(ctx, skb, STG_IP_OUTPUT, 1);  // FIRST STAGE for ICMP TX
    return 0;
}

// REMOVED: kprobe__sock_queue_rcv_skb - this probe point rarely triggers and often fails parsing
// Instead we focus on the more reliable tcp_v4_rcv and tcp_recvmsg probe points


// REMOVED: tcp/udp_recvmsg probe points - RX path ends at tcp_v4_rcv/udp_rcv

// TX direction protocol layer probes - TCP transmit starts here
// REMOVED: __tcp_transmit_skb and udp_sendmsg probes - socket/protocol layer probes removed
// TX direction starts at __ip_queue_xmit (TCP), ip_output (ICMP), or ip_send_skb (UDP)
"""

# Constants  
MAX_STAGES = 27
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
        # TX path (Local->Uplink)
        21: "SOCK_SEND_SYSCALL",  # syscall entry
        1: "IP_QUEUE_XMIT",       # TCP first stage: __ip_queue_xmit
        2: "IP_OUTPUT",           # ICMP first stage: ip_output
        3: "OVS_TX",
        4: "FLOW_EXTRACT_TX", 
        5: "CT_TX",
        6: "CT_OUT_TX",
        7: "PHY_QDISC_ENQ",
        8: "PHY_QDISC_DEQ",
        9: "PHY_TX",              # End of TX path
        
        # 系统 RX 路径（Uplink→Local，外部到系统接收） - EXTENDED
        11: "PHY_RX",             # Start of RX path
        12: "OVS_RX",
        13: "FLOW_EXTRACT_RX",
        14: "CT_RX",
        15: "CT_OUT_RX",
        16: "INTERNAL_DEV_RECV",
        17: "NETRX_END", 
        18: "IP_RCV",             # IP layer processing
        19: "TCP_UDP_RCV",        # Protocol layer recv - END OF TCP/UDP RX PATH
        25: "ICMP_RCV",           # ICMP receive - END OF ICMP RX PATH
        26: "IP_SEND_SKB",        # ip_send_skb - START OF UDP TX PATH
        # REMOVED: 23: "SOCK_QUEUE" - socket buffer queueing probe removed
        24: "SOCK_RECV_SYSCALL",  # New: syscall entry  
        20: "SOCK_RECV"           # End of RX path
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
        # Python 2/3 compatibility: data[4] returns int in Py3, str in Py2
        if len(data) > 4:
            icmp_type = data[4] if isinstance(data[4], int) else ord(data[4])
        else:
            icmp_type = 0
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
    
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Millisecond precision
    print("=== FLOW COMPLETE: %d stages captured === %s" % (event.flow.stage_count, current_time))
    
    # Display 5-tuple information
    src_ip = format_ip(event.key.sip)
    dst_ip = format_ip(event.key.dip)
    print("FLOW: %s -> %s (%s)" % (src_ip, dst_ip, pkt_id))
    
    # Display detailed 5-tuple
    direction_str = "SYSTEM_TX" if event.flow.direction == 1 else "SYSTEM_RX"
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
        # Python 2/3 compatibility: icmp_data[4] returns int in Py3, str in Py2
        if len(icmp_data) > 4:
            icmp_type = icmp_data[4] if isinstance(icmp_data[4], int) else ord(icmp_data[4])
        else:
            icmp_type = 0
        print("5-TUPLE: %s -> %s ICMP (id=%u seq=%u type=%u) DIR=%s" % (src_ip, dst_ip, icmp_id, seq, icmp_type, direction_str))
    else:
        print("5-TUPLE: %s -> %s Proto%d DIR=%s" % (src_ip, dst_ip, event.key.proto, direction_str))
    
    # Collect valid stages using the new stages array
    stages = []
    for i in range(MAX_STAGES):
        if event.flow.stages[i].valid:
            stages.append((i, event.flow.stages[i]))
    
    # Sort by timestamp to ensure proper order
    stages.sort(key=lambda x: x[1].timestamp)
    
    # Print stages with detailed information from each stage
    prev_ts = None
    for idx, (stage_id, stage_info) in enumerate(stages):
        delta_str = ""
        if prev_ts is not None:
            delta_ns = stage_info.timestamp - prev_ts
            delta_str = " (+%.3fus)" % (delta_ns / 1000.0)
        
        # Get exact device name from stage_info
        devname = stage_info.devname.decode('utf-8', 'replace').rstrip('\x00')
        
        print("  Stage %s: (KTIME=%luns)%s" % (
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
            if stage_id == 8:  # PHY_QDISC_DEQ
                sojourn_time_ns = stage_info.timestamp - event.flow.qdisc_enq_time
                print("  PHY_QDISC: sojourn=%.3fus qlen=%d" % (sojourn_time_ns / 1000.0, event.flow.qdisc_qlen))
                break
    
    if event.flow.ct_lookup_duration > 0:
        print("  CT: lookup=%.3fus" % (event.flow.ct_lookup_duration / 1000.0))
        
    print("")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="System Network Performance Tracing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor system bidirectional traffic:
    sudo %(prog)s --internal-interface port-mgt --phy-interface enp94s0f0np0 --src-ip 192.168.70.33

  Monitor only system TX traffic (Local→Uplink):
    sudo %(prog)s --internal-interface port-mgt --phy-interface enp94s0f0np0 --direction tx --src-ip 192.168.70.33

  Monitor TCP SSH traffic:
    sudo %(prog)s --internal-interface port-mgt --phy-interface enp94s0f0np0 --protocol tcp --dst-port 22

  Monitor flows with latency > 100us:
    sudo %(prog)s --internal-interface port-mgt --phy-interface enp94s0f0np0 --src-ip 192.168.70.33 --latency-us 100
"""
    )
    
    parser.add_argument('--internal-interface', type=str, required=True,
                        help='Internal port interface to monitor (e.g., port-mgt)')
    parser.add_argument('--phy-interface', type=str, required=True,
                        help='Physical interface(s) to monitor. Supports comma-separated list for bond members (e.g., enp94s0f0np0 or eth0,eth1)')
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
    parser.add_argument('--direction', type=str, choices=['tx', 'rx', 'both'],
                        default='both', help='Direction filter: tx=SYSTEM_TX(Local→Uplink), rx=SYSTEM_RX(Uplink→Local) (default: both)')
    parser.add_argument('--latency-us', type=float, default=0,
                        help='Minimum total latency threshold in microseconds to report (default: 0, report all)')
    parser.add_argument('--enable-ct', action='store_true',
                        help='Enable conntrack measurement')
    parser.add_argument('--verbose', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    # Convert parameters
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0

    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0

    protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'all': 0}
    protocol_filter = protocol_map[args.protocol]

    direction_map = {'tx': 1, 'rx': 2, 'both': 0}
    direction_filter = direction_map[args.direction]

    # Convert latency threshold from microseconds to nanoseconds
    latency_threshold_ns = int(args.latency_us * 1000)
    
    # Support multiple interfaces (split by comma)
    phy_interfaces = args.phy_interface.split(',')
    try:
        internal_ifindex = get_if_index(args.internal_interface)
        phy_ifindex1 = get_if_index(phy_interfaces[0].strip())
        phy_ifindex2 = get_if_index(phy_interfaces[1].strip()) if len(phy_interfaces) > 1 else phy_ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    print("=== System Network Performance Tracer ===")
    print("Protocol filter: %s" % args.protocol.upper())
    print("Direction filter: %s (1=SYSTEM_TX/Local→Uplink, 2=SYSTEM_RX/Uplink→Local)" % args.direction.upper())
    if args.src_ip or args.dst_ip:
        if args.src_ip:
            print("Source IP filter: %s" % args.src_ip)
        if args.dst_ip:
            print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("Internal interface: %s (ifindex %d)" % (args.internal_interface, internal_ifindex))
    print("Physical interfaces: %s (ifindex %d, %d)" % (args.phy_interface, phy_ifindex1, phy_ifindex2))
    print("Conntrack measurement: %s" % ("ENABLED" if args.enable_ct else "DISABLED"))
    if latency_threshold_ns > 0:
        print("Latency threshold: >= %.3f us (only reporting flows exceeding this latency)" % args.latency_us)
    
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, internal_ifindex, phy_ifindex1, phy_ifindex2, direction_filter,
            latency_threshold_ns
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        print("\nActual format string substitution:")
        print("Parameters passed: %d arguments" % len([src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_filter, internal_ifindex, phy_ifindex1, phy_ifindex2, direction_filter, latency_threshold_ns]))
        sys.exit(1)

    # Manual attachment for ip_send_skb (UDP TX first stage)
    ip_send_skb_func = find_kernel_function("ip_send_skb")
    if ip_send_skb_func:
        try:
            b.attach_kprobe(event=ip_send_skb_func, fn_name="trace_ip_send_skb")
            print("Attached kprobe to %s" % ip_send_skb_func)
        except Exception as e:
            print("Warning: Could not attach to %s: %s" % (ip_send_skb_func, e))
            print("         UDP TX first stage will be disabled")
    else:
        print("Warning: ip_send_skb not found in kallsyms")
        print("         UDP TX first stage will be disabled")

    # Manual attachment for ip_output (ICMP TX first stage)
    # ICMP echo reply on 5.10+ kernel uses ip_output path
    ip_output_func = find_kernel_function("ip_output")
    if ip_output_func:
        try:
            b.attach_kprobe(event=ip_output_func, fn_name="trace_ip_output")
            print("Attached kprobe to %s" % ip_output_func)
        except Exception as e:
            print("Warning: Could not attach to %s: %s" % (ip_output_func, e))
            print("         ICMP TX first stage will be disabled")
    else:
        print("Warning: ip_output not found in kallsyms")
        print("         ICMP TX first stage will be disabled")

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
    
    b["events"].open_perf_buffer(print_event)
    
    print("\nTracing system network performance... Hit Ctrl-C to end.")
    print("Format: Complete flow summary at last stage with absolute kernel timestamps")
    print("        System TX: SOCK_SEND -> PHY_TX")
    print("        System RX: PHY_RX -> SOCK_RECV")
    print("        Note: Internal port has NO qdisc (unlike physical interface)")
    print("")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
    finally:
        print("Exiting.")