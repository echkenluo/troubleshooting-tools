#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SKB frag_list Watcher

Traces all modifications to sk_buff->frag_list to identify where and when
frag_list is created, modified, or cleared. This is critical for debugging
GSO segmentation crashes caused by inconsistent frag_list state.

Target issue: skb_segment crash due to NULL frag_list with non-zero gso_size

Key monitoring points:
1. frag_list creation:
   - skb_gro_receive_list (GRO aggregation)

2. frag_list clearing:
   - skb_segment_list (fragment list segmentation)
   - __skb_linearize (linearization)
   - pskb_expand_head (header expansion - may affect)

3. frag_list access:
   - skb_segment (GSO segmentation - crash point)

Usage:
    # Monitor all frag_list changes
    sudo python skb_frag_list_watcher.py

    # Filter by GSO packets only
    sudo python skb_frag_list_watcher.py --gso-only

    # Filter by source IP
    sudo python skb_frag_list_watcher.py --src-ip 10.132.114.11

    # With stack trace for critical events
    sudo python skb_frag_list_watcher.py --stack-trace

    # Monitor specific interface
    sudo python skb_frag_list_watcher.py --interface ens11

Output format:
    [TIMESTAMP] CPU COMM(PID) FUNC | SKB=addr | frag_list: before -> after | gso_type=X gso_size=Y gso_segs=Z

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
#define GSO_ONLY_FILTER %d
#define TARGET_IFINDEX %d
#define ENABLE_STACK_TRACE %d
#define EXCLUDE_ACCESS_EVENTS %d

// skb_shared_info structure (from include/linux/skbuff.h for Linux 4.18.0-553.47.1.el8_10)
// Layout verified from include/linux/skbuff.h lines 519-541
struct skb_shared_info_minimal {
    __u8 __unused;              // offset 0
    __u8 meta_len;              // offset 1
    __u8 nr_frags;              // offset 2
    __u8 tx_flags;              // offset 3
    unsigned short gso_size;    // offset 4
    unsigned short gso_segs;    // offset 6
    struct sk_buff *frag_list;  // offset 8 (8 bytes pointer on x86_64)
    // offset 16: struct skb_shared_hwtstamps hwtstamps (contains ktime_t, 8 bytes)
    char _pad[8];               // Padding for hwtstamps
    unsigned int gso_type;      // offset 24
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
    u64 frag_list_before;
    u64 frag_list_after;

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

    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;

    char func_name[32];
    char comm[16];

    int stack_id;        // Return stack trace ID (-1 if not collected)
    int entry_stack_id;  // Entry stack trace ID (-1 if not available)
};

// Maps
BPF_HASH(skb_entry_state, u64, struct skb_shared_info_minimal, 10240);
BPF_HASH(skb_entry_stack, u64, int, 10240);  // Store entry stack_id for each SKB
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 2048);  // Increased from 1024

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

    // skb_shinfo = (struct skb_shared_info *)(skb->head + skb->end)
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

    // Check IP filters if needed
    if (SRC_IP_FILTER != 0 || DST_IP_FILTER != 0) {
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

        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }

        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    }

    return 1;
}

// Helper: Fill event with packet info
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

    // SKB flags (bit fields - hard to access directly, set to 0 for now)
    // These are not critical for frag_list debugging
    event->cloned = 0;
    event->slow_gro = 0;

    // GSO info from shinfo
    if (shinfo) {
        bpf_probe_read_kernel(&event->gso_size, sizeof(event->gso_size), &shinfo->gso_size);
        bpf_probe_read_kernel(&event->gso_segs, sizeof(event->gso_segs), &shinfo->gso_segs);
        bpf_probe_read_kernel(&event->gso_type, sizeof(event->gso_type), &shinfo->gso_type);
        bpf_probe_read_kernel(&event->nr_frags, sizeof(event->nr_frags), &shinfo->nr_frags);
    }

    // Extract IP addresses and ports
    unsigned char *head;
    u16 network_header;
    struct iphdr ip;

    event->src_ip = 0;
    event->dst_ip = 0;
    event->src_port = 0;
    event->dst_port = 0;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) == 0 &&
        bpf_probe_read_kernel(&network_header, sizeof(network_header),
                              &skb->network_header) == 0 &&
        network_header != (u16)~0U) {

        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
            event->src_ip = ip.saddr;
            event->dst_ip = ip.daddr;

            // Extract ports for TCP/UDP
            u16 transport_header;
            if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header),
                                      &skb->transport_header) == 0 &&
                transport_header != (u16)~0U) {

                if (ip.protocol == IPPROTO_TCP || ip.protocol == IPPROTO_UDP) {
                    struct {
                        __be16 source;
                        __be16 dest;
                    } ports;

                    if (bpf_probe_read_kernel(&ports, sizeof(ports),
                                              head + transport_header) == 0) {
                        event->src_port = bpf_ntohs(ports.source);
                        event->dst_port = bpf_ntohs(ports.dest);
                    }
                }
            }
        }
    }

    // Stack trace if enabled
    if (ENABLE_STACK_TRACE) {
        // Remove BPF_F_REUSE_STACKID to get complete stacks
        // Use BPF_F_FAST_STACK_CMP for better performance
        event->stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    } else {
        event->stack_id = -1;
    }
}

// Generic entry probe - save state
static __always_inline int trace_entry(struct pt_regs *ctx, struct sk_buff *skb) {
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

    // Read and save shinfo state
    struct skb_shared_info_minimal saved_state = {};
    bpf_probe_read_kernel(&saved_state, sizeof(saved_state), shinfo);

    u64 skb_addr = (u64)skb;
    skb_entry_state.update(&skb_addr, &saved_state);

    // Save entry stack trace if enabled
    if (ENABLE_STACK_TRACE) {
        int stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
        if (stack_id >= 0) {
            skb_entry_stack.update(&skb_addr, &stack_id);
        }
    }

    return 0;
}

// Generic return probe - check for changes
static __always_inline int trace_return(struct pt_regs *ctx,
                                        struct sk_buff *skb,
                                        const char *func_name,
                                        u8 event_type) {
    u64 skb_addr = (u64)skb;
    struct skb_shared_info_minimal *saved = skb_entry_state.lookup(&skb_addr);

    if (!saved) {
        return 0; // No entry state, likely filtered
    }

    struct skb_shared_info_minimal *current_shinfo = get_shinfo(skb);
    if (!current_shinfo) {
        skb_entry_state.delete(&skb_addr);
        return 0;
    }

    // Read current frag_list
    struct sk_buff *current_frag_list;
    struct sk_buff *saved_frag_list = saved->frag_list;

    bpf_probe_read_kernel(&current_frag_list, sizeof(current_frag_list),
                          &current_shinfo->frag_list);

    // Check if frag_list changed
    int changed = 0;
    if (current_frag_list != saved_frag_list) {
        changed = 1;
    }

    // Also check for inconsistent state
    u16 current_gso_size;
    u32 current_gso_type;
    bpf_probe_read_kernel(&current_gso_size, sizeof(current_gso_size),
                          &current_shinfo->gso_size);
    bpf_probe_read_kernel(&current_gso_type, sizeof(current_gso_type),
                          &current_shinfo->gso_type);

    int inconsistent = 0;
    // CRITICAL condition: gso_size > 0 means GSO packet, but no data to segment
    if (current_frag_list == NULL && current_gso_size > 0) {
        // Check if we have nr_frags or data_len
        u8 nr_frags;
        u32 data_len;
        bpf_probe_read_kernel(&nr_frags, sizeof(nr_frags), &current_shinfo->nr_frags);
        bpf_probe_read_kernel(&data_len, sizeof(data_len), &skb->data_len);

        if (nr_frags == 0 && data_len == 0) {
            inconsistent = 1;  // CRITICAL: gso_size > 0 but no segmentation data
        }
    }

    // Send event if changed or inconsistent
    if (changed || inconsistent) {
        struct frag_list_event_t event = {};

        event.frag_list_before = (u64)saved_frag_list;
        event.frag_list_after = (u64)current_frag_list;

        // Determine event type
        if (inconsistent) {
            event.event_type = EVENT_GSO_INCONSISTENT;
            int key = 4;
            u64 *val = stats.lookup(&key);
            if (val) (*val)++;
        } else if (saved_frag_list == NULL && current_frag_list != NULL) {
            event.event_type = EVENT_FRAG_LIST_CREATE;
            int key = 1;
            u64 *val = stats.lookup(&key);
            if (val) (*val)++;
        } else if (saved_frag_list != NULL && current_frag_list == NULL) {
            event.event_type = EVENT_FRAG_LIST_CLEAR;
            int key = 2;
            u64 *val = stats.lookup(&key);
            if (val) (*val)++;
        } else {
            event.event_type = event_type;
        }

        // Filter ACCESS events if requested
        #if EXCLUDE_ACCESS_EVENTS
        if (event.event_type == EVENT_FRAG_LIST_ACCESS) {
            int key = 5;
            u64 *val = stats.lookup(&key);
            if (val) (*val)++;
            skb_entry_state.delete(&skb_addr);
            skb_entry_stack.delete(&skb_addr);
            return 0;
        }
        #endif

        fill_event_info(ctx, &event, skb, current_shinfo);
        __builtin_strncpy(event.func_name, func_name, sizeof(event.func_name));

        // Get entry stack trace if available
        int *entry_stack_ptr = skb_entry_stack.lookup(&skb_addr);
        if (entry_stack_ptr) {
            event.entry_stack_id = *entry_stack_ptr;
        } else {
            event.entry_stack_id = -1;
        }

        events.perf_submit(ctx, &event, sizeof(event));

        int key = 0;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }

    skb_entry_state.delete(&skb_addr);
    skb_entry_stack.delete(&skb_addr);
    return 0;
}

// Probe: skb_gro_receive_list (creates frag_list)
int trace_skb_gro_receive_list_entry(struct pt_regs *ctx, struct sk_buff *p,
                                       struct sk_buff *skb) {
    return trace_entry(ctx, p);
}

int trace_skb_gro_receive_list_return(struct pt_regs *ctx) {
    struct sk_buff *p = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, p, "skb_gro_receive_list", EVENT_FRAG_LIST_CREATE);
}

// Probe: skb_segment_list (clears frag_list)
int trace_skb_segment_list_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_skb_segment_list_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "skb_segment_list", EVENT_FRAG_LIST_CLEAR);
}

// Probe: pskb_expand_head (may affect frag_list)
int trace_pskb_expand_head_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_pskb_expand_head_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "pskb_expand_head", EVENT_FRAG_LIST_MODIFY);
}

// ============================================================================
// Call-stack based probes (from crash trace)
// ============================================================================

// Probe: napi_gro_receive (GRO entry, may create frag_list)
int trace_napi_gro_receive_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_napi_gro_receive_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "napi_gro_receive", EVENT_FRAG_LIST_MODIFY);
}

// Probe: ip_forward (forwarding path, may modify SKB)
int trace_ip_forward_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_ip_forward_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "ip_forward", EVENT_FRAG_LIST_MODIFY);
}

// Probe: validate_xmit_skb (GSO validation checkpoint)
int trace_validate_xmit_skb_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_validate_xmit_skb_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "validate_xmit_skb", EVENT_FRAG_LIST_MODIFY);
}

// Probe: __skb_gso_segment (GSO segmentation entry)
int trace___skb_gso_segment_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace___skb_gso_segment_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "__skb_gso_segment", EVENT_FRAG_LIST_MODIFY);
}

// Probe: skb_udp_tunnel_segment (UDP tunnel processing - KEY!)
int trace_skb_udp_tunnel_segment_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_skb_udp_tunnel_segment_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "skb_udp_tunnel_segment", EVENT_FRAG_LIST_MODIFY);
}

// Probe: inet_gso_segment (IP layer GSO)
int trace_inet_gso_segment_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_inet_gso_segment_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "inet_gso_segment", EVENT_FRAG_LIST_MODIFY);
}

// Probe: tcp_gso_segment (TCP GSO, just before crash)
int trace_tcp_gso_segment_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_entry(ctx, skb);
}

int trace_tcp_gso_segment_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return trace_return(ctx, skb, "tcp_gso_segment", EVENT_FRAG_LIST_MODIFY);
}

// ============================================================================
// Original probes
// ============================================================================

// Probe: skb_segment (accesses frag_list - crash point)
int trace_skb_segment_entry(struct pt_regs *ctx, struct sk_buff *head_skb) {
    if (!should_trace_skb(head_skb)) {
        return 0;
    }

    struct skb_shared_info_minimal *shinfo = get_shinfo(head_skb);
    if (!shinfo) {
        return 0;
    }

    // Check for dangerous condition: frag_list access but NULL
    struct sk_buff *frag_list;
    bpf_probe_read_kernel(&frag_list, sizeof(frag_list), &shinfo->frag_list);

    u16 gso_size;
    u32 gso_type;
    bpf_probe_read_kernel(&gso_size, sizeof(gso_size), &shinfo->gso_size);
    bpf_probe_read_kernel(&gso_type, sizeof(gso_type), &shinfo->gso_type);

    // This is the exact condition that causes the crash
    if (frag_list == NULL && gso_size > 0) {
        #if EXCLUDE_ACCESS_EVENTS
        // Filter ACCESS events - only count in stats
        int key = 5;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
        return 0;
        #else
        struct frag_list_event_t event = {};

        event.frag_list_before = 0;
        event.frag_list_after = 0;
        event.event_type = EVENT_FRAG_LIST_ACCESS;

        fill_event_info(ctx, &event, head_skb, shinfo);
        __builtin_strncpy(event.func_name, "skb_segment", sizeof(event.func_name));

        // No entry stack for skb_segment since it's entry probe only
        event.entry_stack_id = -1;

        events.perf_submit(ctx, &event, sizeof(event));

        int key = 3;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
        #endif
    }

    return 0;
}
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace sk_buff frag_list modifications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Monitor all frag_list changes
    sudo python skb_frag_list_watcher.py

    # Only GSO packets
    sudo python skb_frag_list_watcher.py --gso-only

    # Filter by source IP
    sudo python skb_frag_list_watcher.py --src-ip 10.132.114.11

    # With stack traces
    sudo python skb_frag_list_watcher.py --stack-trace
        """
    )

    parser.add_argument("--src-ip", type=str, help="Filter by source IP address")
    parser.add_argument("--dst-ip", type=str, help="Filter by destination IP address")
    parser.add_argument("--gso-only", action="store_true",
                        help="Only trace GSO packets (gso_size > 0)")
    parser.add_argument("--interface", type=str, help="Filter by network interface")
    parser.add_argument("--exclude-access", action="store_true",
                        help="Exclude ACCESS events (keep only CRITICAL/CREATE/CLEAR/MODIFY)")
    parser.add_argument("--stack-trace", action="store_true",
                        help="Collect kernel stack traces (adds overhead)")
    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output with all fields")

    return parser.parse_args()

def ip_to_int(ip_str):
    """Convert IP string to integer for comparison with kernel iphdr

    inet_aton() returns network byte order (big-endian) bytes.
    We need to unpack it in native byte order to match how kernel iphdr.saddr/daddr
    is stored in memory on little-endian x86_64 machines.
    """
    if not ip_str:
        return 0
    try:
        # Use native byte order '=' to match kernel memory layout
        return struct.unpack("=I", socket.inet_aton(ip_str))[0]
    except:
        print("Error: Invalid IP address: %s" % ip_str)
        sys.exit(1)

def int_to_ip(ip_int):
    """Convert integer to IP string

    The IP is read from kernel iphdr.saddr/daddr which is in network byte order (big-endian).
    On little-endian x86_64, we need to use native byte order to pack it correctly.
    """
    if ip_int == 0:
        return "0.0.0.0"
    # Use native byte order '=' or '<' for little-endian, not network byte order '!'
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
    """Decode GSO type flags based on Linux 4.18.0-553.47.1.el8_10

    Reference: include/linux/skbuff.h lines 590-628
    """
    flags = []
    # Bits 0-18 based on target kernel definition
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
    gso_only = 1 if args.gso_only else 0
    ifindex = get_ifindex(args.interface)
    stack_trace = 1 if args.stack_trace else 0
    exclude_access = 1 if args.exclude_access else 0

    # Load BPF program
    bpf_code = bpf_text % (src_ip, dst_ip, gso_only, ifindex, stack_trace, exclude_access)

    try:
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program:")
        print(str(e))
        sys.exit(1)

    # Attach probes
    try:
        # skb_gro_receive_list
        b.attach_kprobe(event="skb_gro_receive_list",
                        fn_name="trace_skb_gro_receive_list_entry")
        b.attach_kretprobe(event="skb_gro_receive_list",
                           fn_name="trace_skb_gro_receive_list_return")

        # skb_segment_list
        b.attach_kprobe(event="skb_segment_list",
                        fn_name="trace_skb_segment_list_entry")
        b.attach_kretprobe(event="skb_segment_list",
                           fn_name="trace_skb_segment_list_return")

        # pskb_expand_head
        b.attach_kprobe(event="pskb_expand_head",
                        fn_name="trace_pskb_expand_head_entry")
        b.attach_kretprobe(event="pskb_expand_head",
                           fn_name="trace_pskb_expand_head_return")

        # skb_segment (access point)
        b.attach_kprobe(event="skb_segment",
                        fn_name="trace_skb_segment_entry")

        # === Call-stack based probes ===

        # napi_gro_receive (GRO entry)
        b.attach_kprobe(event="napi_gro_receive",
                        fn_name="trace_napi_gro_receive_entry")
        b.attach_kretprobe(event="napi_gro_receive",
                           fn_name="trace_napi_gro_receive_return")

        # ip_forward (forwarding path)
        b.attach_kprobe(event="ip_forward",
                        fn_name="trace_ip_forward_entry")
        b.attach_kretprobe(event="ip_forward",
                           fn_name="trace_ip_forward_return")

        # validate_xmit_skb (GSO validation)
        b.attach_kprobe(event="validate_xmit_skb",
                        fn_name="trace_validate_xmit_skb_entry")
        b.attach_kretprobe(event="validate_xmit_skb",
                           fn_name="trace_validate_xmit_skb_return")

        # __skb_gso_segment (GSO entry)
        b.attach_kprobe(event="__skb_gso_segment",
                        fn_name="trace___skb_gso_segment_entry")
        b.attach_kretprobe(event="__skb_gso_segment",
                           fn_name="trace___skb_gso_segment_return")

        # skb_udp_tunnel_segment (UDP tunnel - KEY!)
        b.attach_kprobe(event="skb_udp_tunnel_segment",
                        fn_name="trace_skb_udp_tunnel_segment_entry")
        b.attach_kretprobe(event="skb_udp_tunnel_segment",
                           fn_name="trace_skb_udp_tunnel_segment_return")

        # inet_gso_segment (IP layer GSO)
        b.attach_kprobe(event="inet_gso_segment",
                        fn_name="trace_inet_gso_segment_entry")
        b.attach_kretprobe(event="inet_gso_segment",
                           fn_name="trace_inet_gso_segment_return")

        # tcp_gso_segment (TCP GSO)
        b.attach_kprobe(event="tcp_gso_segment",
                        fn_name="trace_tcp_gso_segment_entry")
        b.attach_kretprobe(event="tcp_gso_segment",
                           fn_name="trace_tcp_gso_segment_return")

    except Exception as e:
        print("Error attaching probes:")
        print(str(e))
        print("\nMake sure the following kernel functions exist:")
        print("  - skb_gro_receive_list")
        print("  - skb_segment_list")
        print("  - pskb_expand_head")
        print("  - skb_segment")
        print("  - napi_gro_receive")
        print("  - ip_forward")
        print("  - validate_xmit_skb")
        print("  - __skb_gso_segment")
        print("  - skb_udp_tunnel_segment")
        print("  - inet_gso_segment")
        print("  - tcp_gso_segment")
        sys.exit(1)

    print("Successfully attached to 11 functions (including 7 call-stack probes)")

    # Event data structure
    class FragListEvent(ctypes.Structure):
        _fields_ = [
            ("timestamp_ns", ctypes.c_uint64),
            ("skb_addr", ctypes.c_uint64),
            ("frag_list_before", ctypes.c_uint64),
            ("frag_list_after", ctypes.c_uint64),
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
            ("src_ip", ctypes.c_uint32),
            ("dst_ip", ctypes.c_uint32),
            ("src_port", ctypes.c_uint16),
            ("dst_port", ctypes.c_uint16),
            ("func_name", ctypes.c_char * 32),
            ("comm", ctypes.c_char * 16),
            ("stack_id", ctypes.c_int),
            ("entry_stack_id", ctypes.c_int),
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
    print("Tracing sk_buff frag_list modifications... Hit Ctrl-C to end.")
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

        # Format frag_list change
        if event.frag_list_before == 0 and event.frag_list_after != 0:
            change = "NULL -> 0x%x" % event.frag_list_after
        elif event.frag_list_before != 0 and event.frag_list_after == 0:
            change = "0x%x -> NULL [!!]" % event.frag_list_before
        elif event.frag_list_before != event.frag_list_after:
            change = "0x%x -> 0x%x" % (event.frag_list_before, event.frag_list_after)
        else:
            change = "0x%x (no change)" % event.frag_list_before

        func_name = event.func_name.decode('utf-8', 'replace')
        comm = event.comm.decode('utf-8', 'replace')

        if args.verbose:
            # Determine severity marker
            marker = ""
            if event.event_type == 5:  # INCONSISTENT
                marker = " [CRITICAL]"
            elif event.event_type == 4 and event.frag_list_after == 0 and event.gso_size > 0:  # ACCESS
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
            elif event.frag_list_after == 0 and event.gso_size > 0:
                marker = " [WARNING]"

            print("%-18s %-3d %-12s %-20s | 0x%-16x | %s%s" % (
                timestamp, event.cpu, event_type, func_name,
                event.skb_addr, change, marker
            ))

        # Print stack trace if available
        if args.stack_trace:
            # Print entry stack trace (function entry point)
            if event.entry_stack_id >= 0:
                print("    [ENTRY STACK]")
                stack = list(b["stack_traces"].walk(event.entry_stack_id))
                for addr in stack:
                    sym = b.ksym(addr, show_offset=True)
                    print("        %s" % sym.decode('utf-8', 'replace'))
                print("")

            # Print return stack trace (function return point)
            if event.stack_id >= 0:
                print("    [RETURN STACK]")
                stack = list(b["stack_traces"].walk(event.stack_id))
                for addr in stack:
                    sym = b.ksym(addr, show_offset=True)
                    print("        %s" % sym.decode('utf-8', 'replace'))
                print("")

            # Show if no stacks available
            if event.entry_stack_id < 0 and event.stack_id < 0:
                print("    [No stack trace available]")
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
