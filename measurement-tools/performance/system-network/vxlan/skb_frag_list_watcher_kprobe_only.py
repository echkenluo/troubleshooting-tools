#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SKB frag_list Watcher (Kprobe-only version)

This version uses ONLY kprobes (no kretprobes) to avoid polluting the kernel call stack,
allowing complete stack traces to be captured.

Tracks frag_list state changes between consecutive probe points instead of comparing
entry/return states. Each probe point:
1. Reads current frag_list state
2. Compares with last seen state (from previous probe point)
3. Detects and reports changes (CREATE/CLEAR/MODIFY/ACCESS/INCONSISTENT)
4. Updates last seen state

Target issue: skb_segment crash due to NULL frag_list with non-zero gso_size

Key monitoring points:
1. frag_list creation:
   - skb_gro_receive_list (GRO aggregation)

2. frag_list clearing:
   - skb_segment_list (fragment list segmentation)
   - pskb_expand_head (header expansion - may affect)

3. frag_list access and crash path (from actual crash stack):
   - napi_gro_receive (GRO entry)
   - ip_forward (forwarding path)
   - validate_xmit_skb (GSO validation checkpoint)
   - __skb_gso_segment (GSO segmentation entry)
   - skb_udp_tunnel_segment (UDP tunnel processing - KEY!)
   - inet_gso_segment (IP layer GSO)
   - tcp_gso_segment (TCP GSO)
   - skb_segment (crash point)

Usage:
    # Monitor all frag_list changes with stack traces
    sudo python skb_frag_list_watcher_kprobe_only.py --stack-trace

    # Filter by GSO packets only
    sudo python skb_frag_list_watcher_kprobe_only.py --gso-only --stack-trace

    # Filter by source IP and port
    sudo python skb_frag_list_watcher_kprobe_only.py --src-ip 10.132.114.11 --src-port 443 --stack-trace

    # Filter by destination IP and port
    sudo python skb_frag_list_watcher_kprobe_only.py --dst-ip 172.16.139.51 --dst-port 6443 --stack-trace

    # Monitor specific interface, exclude normal ACCESS events
    sudo python skb_frag_list_watcher_kprobe_only.py --interface ens11 --exclude-access --stack-trace

Output format:
    [TIMESTAMP] CPU EVENT COMM(PID) FUNC | SKB=addr | frag_list: prev -> current | gso_type=X gso_size=Y

Author: Automated tooling for kernel crash analysis
"""

from __future__ import print_function
import sys
import argparse
import ctypes
import socket
import struct
from datetime import datetime
import signal

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)

# Global flag for graceful exit
exiting = False

def signal_handler(sig, frame):
    global exiting
    exiting = True

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

// Configuration
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define GSO_ONLY_FILTER %d
#define TARGET_IFINDEX %d
#define ENABLE_STACK_TRACE %d
#define EXCLUDE_ACCESS_EVENTS %d

// skb_shared_info structure (from include/linux/skbuff.h for Linux 4.18.0-553.47.1.el8_10)
struct skb_shared_info_minimal {
    __u8 __unused;              // offset 0
    __u8 meta_len;              // offset 1
    __u8 nr_frags;              // offset 2
    __u8 tx_flags;              // offset 3
    unsigned short gso_size;    // offset 4
    unsigned short gso_segs;    // offset 6
    struct sk_buff *frag_list;  // offset 8 (8 bytes pointer on x86_64)
    char _pad[8];               // Padding for hwtstamps (ktime_t, 8 bytes)
    unsigned int gso_type;      // offset 24
};

// Last seen state for each SKB (probe-to-probe tracking)
struct skb_last_state_t {
    struct sk_buff *frag_list;
    u16 gso_size;
    u32 gso_type;
    u8 nr_frags;
    u32 data_len;
};

// Event types
#define EVENT_FRAG_LIST_CREATE    1
#define EVENT_FRAG_LIST_CLEAR     2
#define EVENT_FRAG_LIST_MODIFY    3
#define EVENT_FRAG_LIST_ACCESS    4
#define EVENT_GSO_INCONSISTENT    5  // Critical: frag_list NULL but gso_size > 0

// Event data structure
struct frag_list_event_t {
    u64 timestamp_ns;
    u64 skb_addr;
    u64 frag_list_prev;     // frag_list from previous probe point
    u64 frag_list_current;  // frag_list at current probe point

    u32 pid;
    u32 cpu;

    u16 gso_size;
    u16 gso_segs;
    u32 gso_type;

    u8 nr_frags;
    u8 event_type;
    u8 cloned;
    u8 slow_gro;

    u32 len;
    u32 data_len;

    // Outer header (for VXLAN: outer IP/UDP)
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;

    // VXLAN fields
    u8 is_vxlan;           // 1 if VXLAN packet, 0 otherwise
    u8 vxlan_flags;        // VXLAN flags
    u16 _pad;              // Padding for alignment
    u32 vxlan_vni;         // VXLAN Network Identifier (24-bit, stored as u32)

    // Inner header (for VXLAN: inner IP/TCP/UDP)
    u32 inner_src_ip;
    u32 inner_dst_ip;
    u16 inner_src_port;
    u16 inner_dst_port;

    char func_name[32];
    char comm[16];

    int stack_id;  // Stack trace ID (-1 if not collected)
};

// Maps
BPF_HASH(skb_last_state, u64, struct skb_last_state_t, 10240);  // Track last seen state
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 2048);

// Statistics
BPF_ARRAY(stats, u64, 8);
// 0: total_events, 1: create_events, 2: clear_events,
// 3: access_events, 4: inconsistent_state, 5: filtered_out

// Helper: Extract skb_shared_info from skb
static __always_inline struct skb_shared_info_minimal* get_shinfo(struct sk_buff *skb) {
    unsigned char *head;
    unsigned char *end;
    struct skb_shared_info_minimal *shinfo;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0) {
        return NULL;
    }

    u32 end_offset;
    if (bpf_probe_read_kernel(&end_offset, sizeof(end_offset), &skb->end) != 0) {
        return NULL;
    }

    shinfo = (struct skb_shared_info_minimal *)(head + end_offset);
    return shinfo;
}

// Helper: Check if packet matches filters
static __always_inline int should_trace_skb(struct sk_buff *skb) {
    // Check interface filter
    if (TARGET_IFINDEX != 0) {
        struct net_device *dev;
        int ifindex;

        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) != 0 || dev == NULL) {
            return 0;
        }

        if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) != 0) {
            return 0;
        }

        if (ifindex != TARGET_IFINDEX) {
            return 0;
        }
    }

    // Check GSO filter
    if (GSO_ONLY_FILTER) {
        struct skb_shared_info_minimal *shinfo = get_shinfo(skb);
        if (!shinfo) return 0;

        u16 gso_size;
        if (bpf_probe_read_kernel(&gso_size, sizeof(gso_size), &shinfo->gso_size) != 0) {
            return 0;
        }

        if (gso_size == 0) {
            return 0;
        }
    }

    // Check IP and port filters if needed
    if (SRC_IP_FILTER != 0 || DST_IP_FILTER != 0 || SRC_PORT_FILTER != 0 || DST_PORT_FILTER != 0) {
        unsigned char *head;
        u16 network_header;
        struct iphdr ip;

        if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0) {
            return 1; // Allow if cannot read IP
        }

        if (bpf_probe_read_kernel(&network_header, sizeof(network_header),
                                  &skb->network_header) != 0) {
            return 1;
        }

        if (network_header == (u16)~0U) {
            return 1;
        }

        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) != 0) {
            return 1;
        }

        // Check IP filters
        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }

        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }

        // Check port filters (only for TCP/UDP)
        if (SRC_PORT_FILTER != 0 || DST_PORT_FILTER != 0) {
            if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
                u16 transport_header;
                if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header),
                                          &skb->transport_header) != 0) {
                    return 1; // Allow if cannot read transport header
                }

                if (transport_header == (u16)~0U) {
                    return 1;
                }

                struct {
                    __be16 source;
                    __be16 dest;
                } ports;

                if (bpf_probe_read_kernel(&ports, sizeof(ports),
                                          head + transport_header) != 0) {
                    return 1; // Allow if cannot read ports
                }

                u16 src_port = bpf_ntohs(ports.source);
                u16 dst_port = bpf_ntohs(ports.dest);

                if (SRC_PORT_FILTER != 0 && src_port != SRC_PORT_FILTER) {
                    return 0;
                }

                if (DST_PORT_FILTER != 0 && dst_port != DST_PORT_FILTER) {
                    return 0;
                }
            }
        }
    }

    return 1;
}

// Helper: Fill event with packet info (with tunnel parsing)
static __always_inline void fill_event_info(struct pt_regs *ctx,
                                            struct frag_list_event_t *event,
                                            struct sk_buff *skb,
                                            struct skb_shared_info_minimal *shinfo) {
    // Basic info
    event->timestamp_ns = bpf_ktime_get_ns();
    event->skb_addr = (u64)skb;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // SKB lengths
    bpf_probe_read_kernel(&event->len, sizeof(event->len), &skb->len);
    bpf_probe_read_kernel(&event->data_len, sizeof(event->data_len), &skb->data_len);

    // SKB flags
    event->cloned = 0;
    event->slow_gro = 0;

    // GSO info from shinfo
    if (shinfo) {
        bpf_probe_read_kernel(&event->gso_size, sizeof(event->gso_size), &shinfo->gso_size);
        bpf_probe_read_kernel(&event->gso_segs, sizeof(event->gso_segs), &shinfo->gso_segs);
        bpf_probe_read_kernel(&event->gso_type, sizeof(event->gso_type), &shinfo->gso_type);
        bpf_probe_read_kernel(&event->nr_frags, sizeof(event->nr_frags), &shinfo->nr_frags);
    }

    // Initialize all fields
    event->src_ip = 0;
    event->dst_ip = 0;
    event->src_port = 0;
    event->dst_port = 0;
    event->is_vxlan = 0;
    event->vxlan_flags = 0;
    event->vxlan_vni = 0;
    event->inner_src_ip = 0;
    event->inner_dst_ip = 0;
    event->inner_src_port = 0;
    event->inner_dst_port = 0;

    // Extract packet headers
    unsigned char *head;
    u16 mac_header, network_header, transport_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0) {
        goto skip_packet_parsing;
    }

    if (bpf_probe_read_kernel(&mac_header, sizeof(mac_header), &skb->mac_header) != 0) {
        goto skip_packet_parsing;
    }

    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) != 0) {
        goto skip_packet_parsing;
    }

    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) != 0) {
        goto skip_packet_parsing;
    }

    // Parse outer IP header
    if (network_header == (u16)~0U) {
        goto skip_packet_parsing;
    }

    struct iphdr outer_ip;
    if (bpf_probe_read_kernel(&outer_ip, sizeof(outer_ip), head + network_header) != 0) {
        goto skip_packet_parsing;
    }

    event->src_ip = outer_ip.saddr;
    event->dst_ip = outer_ip.daddr;

    // Parse outer transport header
    if (transport_header != (u16)~0U) {
        if (outer_ip.protocol == IPPROTO_UDP) {
            // Read UDP header
            struct {
                __be16 source;
                __be16 dest;
                __be16 len;
                __be16 check;
            } udp_hdr;

            if (bpf_probe_read_kernel(&udp_hdr, sizeof(udp_hdr), head + transport_header) == 0) {
                event->src_port = bpf_ntohs(udp_hdr.source);
                event->dst_port = bpf_ntohs(udp_hdr.dest);

                // Check for VXLAN (UDP port 4789)
                if (event->dst_port == 4789 || event->src_port == 4789) {
                    // VXLAN header: flags(1) + reserved(3) + VNI(3) + reserved(1) = 8 bytes
                    struct {
                        u8 flags;
                        u8 reserved1[3];
                        u8 vni[3];
                        u8 reserved2;
                    } vxlan_hdr;

                    u16 vxlan_offset = transport_header + sizeof(udp_hdr);
                    if (bpf_probe_read_kernel(&vxlan_hdr, sizeof(vxlan_hdr), head + vxlan_offset) == 0) {
                        event->is_vxlan = 1;
                        event->vxlan_flags = vxlan_hdr.flags;
                        // Extract 24-bit VNI
                        event->vxlan_vni = (vxlan_hdr.vni[0] << 16) | (vxlan_hdr.vni[1] << 8) | vxlan_hdr.vni[2];

                        // Parse inner Ethernet header (skip 14 bytes: 6 dst MAC + 6 src MAC + 2 EtherType)
                        u16 inner_eth_offset = vxlan_offset + sizeof(vxlan_hdr);
                        struct ethhdr inner_eth;
                        if (bpf_probe_read_kernel(&inner_eth, sizeof(inner_eth), head + inner_eth_offset) == 0) {
                            u16 inner_eth_proto = bpf_ntohs(inner_eth.h_proto);

                            // Check if it's IPv4 (0x0800)
                            if (inner_eth_proto == 0x0800) {
                                u16 inner_ip_offset = inner_eth_offset + sizeof(inner_eth);
                                struct iphdr inner_ip;

                                if (bpf_probe_read_kernel(&inner_ip, sizeof(inner_ip), head + inner_ip_offset) == 0) {
                                    event->inner_src_ip = inner_ip.saddr;
                                    event->inner_dst_ip = inner_ip.daddr;

                                    // Parse inner TCP/UDP ports
                                    u16 inner_transport_offset = inner_ip_offset + (inner_ip.ihl * 4);
                                    if (inner_ip.protocol == IPPROTO_TCP || inner_ip.protocol == IPPROTO_UDP) {
                                        struct {
                                            __be16 source;
                                            __be16 dest;
                                        } inner_ports;

                                        if (bpf_probe_read_kernel(&inner_ports, sizeof(inner_ports),
                                                                  head + inner_transport_offset) == 0) {
                                            event->inner_src_port = bpf_ntohs(inner_ports.source);
                                            event->inner_dst_port = bpf_ntohs(inner_ports.dest);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else if (outer_ip.protocol == IPPROTO_TCP) {
            // Parse TCP ports
            struct {
                __be16 source;
                __be16 dest;
            } tcp_ports;

            if (bpf_probe_read_kernel(&tcp_ports, sizeof(tcp_ports), head + transport_header) == 0) {
                event->src_port = bpf_ntohs(tcp_ports.source);
                event->dst_port = bpf_ntohs(tcp_ports.dest);
            }
        } else if (outer_ip.protocol == IPPROTO_IPIP) {
            // IPIP encapsulation: inner IP follows outer IP directly
            u16 inner_ip_offset = network_header + (outer_ip.ihl * 4);
            struct iphdr inner_ip;

            if (bpf_probe_read_kernel(&inner_ip, sizeof(inner_ip), head + inner_ip_offset) == 0) {
                event->inner_src_ip = inner_ip.saddr;
                event->inner_dst_ip = inner_ip.daddr;

                // Parse inner TCP/UDP ports
                u16 inner_transport_offset = inner_ip_offset + (inner_ip.ihl * 4);
                if (inner_ip.protocol == IPPROTO_TCP || inner_ip.protocol == IPPROTO_UDP) {
                    struct {
                        __be16 source;
                        __be16 dest;
                    } inner_ports;

                    if (bpf_probe_read_kernel(&inner_ports, sizeof(inner_ports),
                                              head + inner_transport_offset) == 0) {
                        event->inner_src_port = bpf_ntohs(inner_ports.source);
                        event->inner_dst_port = bpf_ntohs(inner_ports.dest);
                    }
                }
            }
        }
    }

skip_packet_parsing:
    // Stack trace if enabled
    if (ENABLE_STACK_TRACE) {
        event->stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    } else {
        event->stack_id = -1;
    }
}

// Generic probe function - compares with last seen state
static __always_inline int trace_frag_list(struct pt_regs *ctx,
                                           struct sk_buff *skb,
                                           const char *func_name) {
    if (!should_trace_skb(skb)) {
        int key = 5;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
        return 0;
    }

    struct skb_shared_info_minimal *shinfo = get_shinfo(skb);
    if (!shinfo) {
        return 0;
    }

    u64 skb_addr = (u64)skb;

    // Read current state
    struct sk_buff *current_frag_list;
    u16 current_gso_size;
    u32 current_gso_type;
    u8 current_nr_frags;
    u32 current_data_len;

    bpf_probe_read_kernel(&current_frag_list, sizeof(current_frag_list), &shinfo->frag_list);
    bpf_probe_read_kernel(&current_gso_size, sizeof(current_gso_size), &shinfo->gso_size);
    bpf_probe_read_kernel(&current_gso_type, sizeof(current_gso_type), &shinfo->gso_type);
    bpf_probe_read_kernel(&current_nr_frags, sizeof(current_nr_frags), &shinfo->nr_frags);
    bpf_probe_read_kernel(&current_data_len, sizeof(current_data_len), &skb->data_len);

    // Look up last seen state
    struct skb_last_state_t *last_state = skb_last_state.lookup(&skb_addr);

    struct sk_buff *prev_frag_list = NULL;
    u16 prev_gso_size = 0;
    u32 prev_gso_type = 0;
    u8 prev_nr_frags = 0;
    u32 prev_data_len = 0;

    if (last_state) {
        prev_frag_list = last_state->frag_list;
        prev_gso_size = last_state->gso_size;
        prev_gso_type = last_state->gso_type;
        prev_nr_frags = last_state->nr_frags;
        prev_data_len = last_state->data_len;
    }

    // Determine event type based on frag_list change
    int event_type = EVENT_FRAG_LIST_ACCESS;
    int should_report = 0;

    if (prev_frag_list == NULL && current_frag_list != NULL) {
        event_type = EVENT_FRAG_LIST_CREATE;
        should_report = 1;
        int key = 1;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    } else if (prev_frag_list != NULL && current_frag_list == NULL) {
        event_type = EVENT_FRAG_LIST_CLEAR;
        should_report = 1;
        int key = 2;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    } else if (prev_frag_list != NULL && current_frag_list != NULL &&
               prev_frag_list != current_frag_list) {
        event_type = EVENT_FRAG_LIST_MODIFY;
        should_report = 1;
    } else {
        // ACCESS event - no change in frag_list pointer
        event_type = EVENT_FRAG_LIST_ACCESS;
        int key = 3;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }

    // Check for INCONSISTENT state (overrides event type)
    int inconsistent = 0;
    if (current_frag_list == NULL && current_gso_size > 0) {
        // Check if we have nr_frags or data_len
        if (current_nr_frags == 0 && current_data_len == 0) {
            inconsistent = 1;
            event_type = EVENT_GSO_INCONSISTENT;
            should_report = 1;
            int key = 4;
            u64 *val = stats.lookup(&key);
            if (val) (*val)++;
        }
    }

    // Filter ACCESS events if requested
    #if EXCLUDE_ACCESS_EVENTS
    if (event_type == EVENT_FRAG_LIST_ACCESS) {
        // Update last state before filtering out
        struct skb_last_state_t new_state = {};
        new_state.frag_list = current_frag_list;
        new_state.gso_size = current_gso_size;
        new_state.gso_type = current_gso_type;
        new_state.nr_frags = current_nr_frags;
        new_state.data_len = current_data_len;
        skb_last_state.update(&skb_addr, &new_state);
        return 0;
    }
    #endif

    // Report event if there's a change or inconsistent state
    if (should_report || inconsistent) {
        struct frag_list_event_t event = {};

        event.frag_list_prev = (u64)prev_frag_list;
        event.frag_list_current = (u64)current_frag_list;
        event.event_type = event_type;

        fill_event_info(ctx, &event, skb, shinfo);
        __builtin_strncpy(event.func_name, func_name, sizeof(event.func_name));

        events.perf_submit(ctx, &event, sizeof(event));

        int key = 0;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }

    // Update last seen state
    struct skb_last_state_t new_state = {};
    new_state.frag_list = current_frag_list;
    new_state.gso_size = current_gso_size;
    new_state.gso_type = current_gso_type;
    new_state.nr_frags = current_nr_frags;
    new_state.data_len = current_data_len;
    skb_last_state.update(&skb_addr, &new_state);

    return 0;
}

// ============================================================================
// Probe functions (kprobe only - no kretprobe)
// ============================================================================

// Probe: skb_gro_receive_list (creates frag_list)
int trace_skb_gro_receive_list(struct pt_regs *ctx, struct sk_buff *p, struct sk_buff *skb) {
    return trace_frag_list(ctx, p, "skb_gro_receive_list");
}

// Probe: skb_segment_list (clears frag_list)
int trace_skb_segment_list(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "skb_segment_list");
}

// Probe: pskb_expand_head (may affect frag_list)
int trace_pskb_expand_head(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "pskb_expand_head");
}

// Probe: netif_receive_skb_internal (early receive path - SKB fully parsed)
int trace_netif_receive_skb_internal(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "netif_receive_skb_internal");
}

// Probe: napi_gro_receive (GRO entry)
int trace_napi_gro_receive(struct pt_regs *ctx, struct napi_struct *napi, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "napi_gro_receive");
}

// Probe: ip_forward (forwarding path)
int trace_ip_forward(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "ip_forward");
}

// Probe: validate_xmit_skb (GSO validation checkpoint)
int trace_validate_xmit_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "validate_xmit_skb");
}

// Probe: __skb_gso_segment (GSO segmentation entry)
int trace___skb_gso_segment(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "__skb_gso_segment");
}

// Probe: skb_udp_tunnel_segment (UDP tunnel processing - KEY!)
int trace_skb_udp_tunnel_segment(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "skb_udp_tunnel_segment");
}

// Probe: inet_gso_segment (IP layer GSO)
int trace_inet_gso_segment(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "inet_gso_segment");
}

// Probe: tcp_gso_segment (TCP GSO)
int trace_tcp_gso_segment(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_frag_list(ctx, skb, "tcp_gso_segment");
}

// Probe: skb_segment (crash point - accesses frag_list)
int trace_skb_segment(struct pt_regs *ctx, struct sk_buff *head_skb) {
    return trace_frag_list(ctx, head_skb, "skb_segment");
}
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace sk_buff frag_list modifications (kprobe-only version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This version uses ONLY kprobes (no kretprobes) to preserve clean stack traces.
State changes are tracked between consecutive probe points.

Examples:
    # Monitor all frag_list changes with stack traces
    sudo python skb_frag_list_watcher_kprobe_only.py --stack-trace

    # Only GSO packets with stack traces
    sudo python skb_frag_list_watcher_kprobe_only.py --gso-only --stack-trace

    # Filter by source IP and port with stack traces
    sudo python skb_frag_list_watcher_kprobe_only.py --src-ip 10.132.114.11 --src-port 443 --stack-trace

    # Filter by destination IP and port
    sudo python skb_frag_list_watcher_kprobe_only.py --dst-ip 172.16.139.51 --dst-port 6443 --stack-trace

    # Exclude ACCESS events, show only state changes
    sudo python skb_frag_list_watcher_kprobe_only.py --exclude-access --stack-trace
        """
    )

    parser.add_argument("--src-ip", type=str, help="Filter by source IP address")
    parser.add_argument("--dst-ip", type=str, help="Filter by destination IP address")
    parser.add_argument("--src-port", type=int, help="Filter by source port (TCP/UDP only)")
    parser.add_argument("--dst-port", type=int, help="Filter by destination port (TCP/UDP only)")
    parser.add_argument("--gso-only", action="store_true",
                        help="Only trace GSO packets (gso_size > 0)")
    parser.add_argument("--interface", type=str, help="Filter by network interface")
    parser.add_argument("--exclude-access", action="store_true",
                        help="Exclude ACCESS events (keep only CRITICAL/CREATE/CLEAR/MODIFY)")
    parser.add_argument("--stack-trace", action="store_true",
                        help="Collect kernel stack traces (recommended for this version)")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output with all fields")

    return parser.parse_args()

def ip_to_int(ip_str):
    """Convert IP string to integer for comparison with kernel iphdr"""
    if not ip_str:
        return 0
    try:
        return struct.unpack("=I", socket.inet_aton(ip_str))[0]
    except:
        print("Error: Invalid IP address: %s" % ip_str)
        sys.exit(1)

def int_to_ip(ip_int):
    """Convert integer to IP string"""
    if ip_int == 0:
        return "0.0.0.0"
    return socket.inet_ntoa(struct.pack("=I", ip_int))

def get_ifindex(ifname):
    """Get interface index by name"""
    if not ifname:
        return 0

    import fcntl
    SIOCGIFINDEX = 0x8933

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifr = struct.pack('16sH', ifname.encode(), 0)
        result = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifr)
        ifindex = struct.unpack('16sH', result)[1]
        s.close()
        return ifindex
    except:
        print("Error: Cannot find interface: %s" % ifname)
        sys.exit(1)

def decode_gso_type(gso_type):
    """Decode GSO type flags based on Linux 4.18.0-553.47.1.el8_10"""
    flags = []
    if gso_type & (1 << 0):  flags.append("TCPV4")
    if gso_type & (1 << 1):  flags.append("DODGY")
    if gso_type & (1 << 2):  flags.append("TCP_ECN")
    if gso_type & (1 << 3):  flags.append("TCP_FIXEDID")
    if gso_type & (1 << 4):  flags.append("TCPV6")
    if gso_type & (1 << 5):  flags.append("FCOE")
    if gso_type & (1 << 6):  flags.append("GRE")
    if gso_type & (1 << 7):  flags.append("GRE_CSUM")
    if gso_type & (1 << 8):  flags.append("IPXIP4")
    if gso_type & (1 << 9):  flags.append("IPXIP6")
    if gso_type & (1 << 10): flags.append("UDP_TUNNEL")
    if gso_type & (1 << 11): flags.append("UDP_TUNNEL_CSUM")
    if gso_type & (1 << 12): flags.append("PARTIAL")
    if gso_type & (1 << 13): flags.append("TUNNEL_REMCSUM")
    if gso_type & (1 << 14): flags.append("SCTP")
    if gso_type & (1 << 15): flags.append("ESP")
    if gso_type & (1 << 16): flags.append("UDP")
    if gso_type & (1 << 17): flags.append("UDP_L4")
    if gso_type & (1 << 18): flags.append("FRAGLIST")

    return "|".join(flags) if flags else "NONE"

def main():
    args = parse_args()

    # Convert filters
    src_ip = ip_to_int(args.src_ip)
    dst_ip = ip_to_int(args.dst_ip)
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0
    gso_only = 1 if args.gso_only else 0
    ifindex = get_ifindex(args.interface)
    stack_trace = 1 if args.stack_trace else 0
    exclude_access = 1 if args.exclude_access else 0

    # Load BPF program
    bpf_code = bpf_text % (src_ip, dst_ip, src_port, dst_port, gso_only, ifindex, stack_trace, exclude_access)

    try:
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program:")
        print(str(e))
        sys.exit(1)

    # Attach probes (kprobe only - no kretprobe!)
    try:
        b.attach_kprobe(event="skb_gro_receive_list", fn_name="trace_skb_gro_receive_list")
        b.attach_kprobe(event="skb_segment_list", fn_name="trace_skb_segment_list")
        b.attach_kprobe(event="pskb_expand_head", fn_name="trace_pskb_expand_head")
        b.attach_kprobe(event="netif_receive_skb_internal", fn_name="trace_netif_receive_skb_internal")
        b.attach_kprobe(event="napi_gro_receive", fn_name="trace_napi_gro_receive")
        b.attach_kprobe(event="ip_forward", fn_name="trace_ip_forward")
        b.attach_kprobe(event="validate_xmit_skb", fn_name="trace_validate_xmit_skb")
        b.attach_kprobe(event="__skb_gso_segment", fn_name="trace___skb_gso_segment")
        b.attach_kprobe(event="skb_udp_tunnel_segment", fn_name="trace_skb_udp_tunnel_segment")
        b.attach_kprobe(event="inet_gso_segment", fn_name="trace_inet_gso_segment")
        b.attach_kprobe(event="tcp_gso_segment", fn_name="trace_tcp_gso_segment")
        b.attach_kprobe(event="skb_segment", fn_name="trace_skb_segment")

    except Exception as e:
        print("Error attaching probes:")
        print(str(e))
        print("\nMake sure the following kernel functions exist:")
        print("  - skb_gro_receive_list")
        print("  - skb_segment_list")
        print("  - pskb_expand_head")
        print("  - netif_receive_skb_internal")
        print("  - napi_gro_receive")
        print("  - ip_forward")
        print("  - validate_xmit_skb")
        print("  - __skb_gso_segment")
        print("  - skb_udp_tunnel_segment")
        print("  - inet_gso_segment")
        print("  - tcp_gso_segment")
        print("  - skb_segment")
        sys.exit(1)

    print("Successfully attached to 12 functions (kprobe-only, no kretprobe)")
    print("This version preserves clean stack traces for debugging")

    # Event data structure
    class FragListEvent(ctypes.Structure):
        _fields_ = [
            ("timestamp_ns", ctypes.c_uint64),
            ("skb_addr", ctypes.c_uint64),
            ("frag_list_prev", ctypes.c_uint64),
            ("frag_list_current", ctypes.c_uint64),
            ("pid", ctypes.c_uint32),
            ("cpu", ctypes.c_uint32),
            ("gso_size", ctypes.c_uint16),
            ("gso_segs", ctypes.c_uint16),
            ("gso_type", ctypes.c_uint32),
            ("nr_frags", ctypes.c_uint8),
            ("event_type", ctypes.c_uint8),
            ("cloned", ctypes.c_uint8),
            ("slow_gro", ctypes.c_uint8),
            ("len", ctypes.c_uint32),
            ("data_len", ctypes.c_uint32),
            # Outer header (for tunnels: outer IP/UDP)
            ("src_ip", ctypes.c_uint32),
            ("dst_ip", ctypes.c_uint32),
            ("src_port", ctypes.c_uint16),
            ("dst_port", ctypes.c_uint16),
            # VXLAN fields
            ("is_vxlan", ctypes.c_uint8),
            ("vxlan_flags", ctypes.c_uint8),
            ("_pad", ctypes.c_uint16),
            ("vxlan_vni", ctypes.c_uint32),
            # Inner header (for tunnels: inner IP/TCP/UDP)
            ("inner_src_ip", ctypes.c_uint32),
            ("inner_dst_ip", ctypes.c_uint32),
            ("inner_src_port", ctypes.c_uint16),
            ("inner_dst_port", ctypes.c_uint16),
            ("func_name", ctypes.c_char * 32),
            ("comm", ctypes.c_char * 16),
            ("stack_id", ctypes.c_int),
        ]

    # Event type names
    event_types = {
        1: "CREATE",
        2: "CLEAR",
        3: "MODIFY",
        4: "ACCESS",
        5: "INCONSISTENT",
    }

    # Print header
    print("Tracing sk_buff frag_list modifications (probe-to-probe)... Hit Ctrl-C to end.")
    print("")

    if args.verbose:
        print("%-18s %-3s %-12s %-16s %-7s %-24s | %-18s | %-20s | %-30s" %
              ("TIME", "CPU", "EVENT", "COMM", "PID", "FUNCTION", "SKB", "FRAG_LIST", "GSO_INFO"))
        print("-" * 190)
    else:
        print("%-18s %-3s %-12s %-20s | %-18s | %-12s" %
              ("TIME", "CPU", "EVENT", "FUNCTION", "SKB", "CHANGE"))
        print("-" * 100)

    # Event handler
    def print_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(FragListEvent)).contents

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        event_type = event_types.get(event.event_type, "UNKNOWN")

        # Format frag_list change (prev -> current)
        if event.frag_list_prev == 0 and event.frag_list_current != 0:
            change = "NULL -> 0x%x" % event.frag_list_current
        elif event.frag_list_prev != 0 and event.frag_list_current == 0:
            change = "0x%x -> NULL [!!]" % event.frag_list_prev
        elif event.frag_list_prev != event.frag_list_current:
            change = "0x%x -> 0x%x" % (event.frag_list_prev, event.frag_list_current)
        else:
            change = "0x%x (no change)" % event.frag_list_prev

        func_name = event.func_name.decode('utf-8', 'replace')
        comm = event.comm.decode('utf-8', 'replace')

        if args.verbose:
            # Determine severity marker
            marker = ""
            if event.event_type == 5:  # INCONSISTENT
                marker = " [CRITICAL]"
            elif event.event_type == 4 and event.frag_list_current == 0 and event.gso_size > 0:  # ACCESS
                marker = " [WARNING]"

            gso_info = "type=0x%x(%s) size=%d segs=%d" % (
                event.gso_type,
                decode_gso_type(event.gso_type),
                event.gso_size,
                event.gso_segs
            )

            print("%-18s %-3d %-12s %-16s %-7d %-24s | 0x%-16x | %-20s | %-30s%s" % (
                timestamp, event.cpu, event_type, comm, event.pid, func_name,
                event.skb_addr, change, gso_info, marker
            ))

            if event.src_ip != 0:
                print("  -> Flow: %s:%d -> %s:%d | len=%d data_len=%d nr_frags=%d cloned=%d gro=%d" % (
                    int_to_ip(event.src_ip), event.src_port,
                    int_to_ip(event.dst_ip), event.dst_port,
                    event.len, event.data_len, event.nr_frags,
                    event.cloned, event.slow_gro
                ))
        else:
            # Compact output
            marker = ""
            if event.event_type == 5:  # INCONSISTENT
                marker = " [CRITICAL]"
            elif event.frag_list_current == 0 and event.gso_size > 0:
                marker = " [WARNING]"

            print("%-18s %-3d %-12s %-20s | 0x%-16x | %s%s" % (
                timestamp, event.cpu, event_type, func_name,
                event.skb_addr, change, marker
            ))

        # Print stack trace if available
        if args.stack_trace and event.stack_id >= 0:
            print("    [STACK TRACE]")
            stack = list(b["stack_traces"].walk(event.stack_id))
            for addr in stack:
                sym = b.ksym(addr, show_offset=True)
                print("        %s" % sym.decode('utf-8', 'replace'))
            print("")

    b["events"].open_perf_buffer(print_event, page_cnt=256)

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Main loop
    print("")
    while not exiting:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break

    # Print statistics
    print("\n--- Statistics ---")
    stats = b.get_table("stats")
    print("Total events:       %d" % stats[ctypes.c_int(0)].value)
    print("  CREATE events:    %d" % stats[ctypes.c_int(1)].value)
    print("  CLEAR events:     %d" % stats[ctypes.c_int(2)].value)
    print("  ACCESS events:    %d" % stats[ctypes.c_int(3)].value)
    print("  INCONSISTENT:     %d" % stats[ctypes.c_int(4)].value)
    print("  Filtered out:     %d" % stats[ctypes.c_int(5)].value)

if __name__ == "__main__":
    main()
