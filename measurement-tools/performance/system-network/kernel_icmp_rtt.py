#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Simplified ICMP RTT tracer for kernel network stack only (no OVS)
# This tool traces ICMP packets through kernel protocol stack without OVS layer
#
# Usage examples:
#   TX mode (local ping remote):
#     sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                               --interface eth0 --direction tx
#
#   RX mode (remote ping local):
#     sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                               --interface eth0 --direction rx
#
#   With latency threshold:
#     sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                               --interface eth0 --latency-ms 10
#
#   Bond scenario (multiple slave interfaces):
#     sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                               --interface ens4f0,ens4f1 --direction tx
#
# Trace stages (minimal host-only, no ip_send_skb dependency):
# TX mode (local -> remote):
#   Path 1 (Request): ip_local_out -> net_dev_xmit
#   Path 2 (Reply):   __netif_receive_skb -> ip_rcv -> icmp_rcv
#
# RX mode (remote -> local):
#   Path 1 (Request): __netif_receive_skb -> ip_rcv -> icmp_rcv
#   Path 2 (Reply):   ip_local_out -> net_dev_xmit

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

# --- BPF Program ---
bpf_text = """
#define DEBUG_ENABLE %d

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/sched.h>
#include <linux/netdevice.h>

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define LATENCY_THRESHOLD_NS %d
#define TRACE_DIRECTION %d  // 0 for TX, 1 for RX

// Multi-interface support for bond scenarios
__IFACE_ARRAY__

// Stage definitions
// Path 1 stages: 0, 1 (TX path start/end without ip_send_skb dependency)
// Path 2 stages: 3, 4, 5
#define PATH1_STAGE_0    0
#define PATH1_STAGE_1    1
#define PATH1_STAGE_2    2  // reserved/unused
#define PATH2_STAGE_0    3
#define PATH2_STAGE_1    4
#define PATH2_STAGE_2    5

#define MAX_STAGES       6
#define IFNAMSIZ         16
#define TASK_COMM_LEN    16

// Debug code points (bcc-debug-framework)
#define CODE_PROBE_ENTRY         1
#define CODE_INTERFACE_FILTER    2
#define CODE_HANDLE_ENTRY        5
#define CODE_PARSE_ENTRY         6
#define CODE_PARSE_SUCCESS       7
#define CODE_PARSE_IP_FILTER     8
#define CODE_FLOW_CREATE        14
#define CODE_FLOW_LOOKUP        15
#define CODE_FLOW_FOUND         16
#define CODE_FLOW_NOT_FOUND     17
#define CODE_PERF_SUBMIT        19
#define CODE_PARSE_HDR_FAIL     20
#define CODE_PARSE_NOT_ICMP     21
#define CODE_PARSE_IP_MISMATCH  22
#define CODE_PARSE_ICMP_MISMATCH 23

// Debug helpers
BPF_HISTOGRAM(debug_stage_stats, u32);

static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    if (!DEBUG_ENABLE)
        return;
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stage_stats.increment(key);
}

// Packet key structure
struct packet_key_t {
    __be32 sip;
    __be32 dip;
    u8  proto;
    __be16 id;
    __be16 seq;
};

// Flow data structure
struct flow_data_t {
    u64 ts[MAX_STAGES];
    u64 skb_ptr[MAX_STAGES];
    int kstack_id[MAX_STAGES];

    u32 p1_pid;
    char p1_comm[TASK_COMM_LEN];
    char p1_ifname[IFNAMSIZ];

    u32 p2_pid;
    char p2_comm[TASK_COMM_LEN];
    char p2_ifname[IFNAMSIZ];

    u8 request_type;
    u8 reply_type;

    u8 saw_path1_start:1;
    u8 saw_path1_end:1;
    u8 saw_path2_start:1;
    u8 saw_path2_end:1;
};

// Event data structure
struct event_data_t {
    struct packet_key_t key;
    struct flow_data_t data;
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch_map, struct event_data_t, 1);

// Helper to check interface
static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    if (IFACE_COUNT == 0) {
        return true;  // No filter
    }

    struct net_device *dev = NULL;
    int ifindex = 0;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }

    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }

    // Check if ifindex matches any configured interface
    #pragma unroll
    for (int i = 0; i < IFACE_COUNT; i++) {
        if (target_ifindexes[i] == ifindex) {
            return true;
        }
    }
    return false;
}

// Parse packet key
// expect_echo_reply: 0 -> expect ICMP_ECHO, 1 -> ICMP_ECHOREPLY
// reverse_ips:       0 -> sip=SRC_IP_FILTER, dip=DST_IP_FILTER
//                    1 -> sip=DST_IP_FILTER, dip=SRC_IP_FILTER
static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key,
                                           u8 *icmp_type_out, int expect_echo_reply,
                                           int reverse_ips, u8 stage_id) {
    debug_inc(stage_id, CODE_PARSE_ENTRY);

    if (skb == NULL) {
        return 0;
    }

    unsigned char *head;
    u16 network_header_offset;
    u16 transport_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0) {
        debug_inc(stage_id, CODE_PARSE_HDR_FAIL);
        return 0;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 4096) {
        debug_inc(stage_id, CODE_PARSE_HDR_FAIL);
        return 0;
    }

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        debug_inc(stage_id, CODE_PARSE_HDR_FAIL);
        return 0;
    }

    if (ip.protocol != IPPROTO_ICMP) {
        debug_inc(stage_id, CODE_PARSE_NOT_ICMP);
        return 0;
    }

    __be32 expected_sip = reverse_ips ? DST_IP_FILTER : SRC_IP_FILTER;
    __be32 expected_dip = reverse_ips ? SRC_IP_FILTER : DST_IP_FILTER;
    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    if (!(actual_sip == expected_sip && actual_dip == expected_dip)) {
        debug_inc(stage_id, CODE_PARSE_IP_MISMATCH);
        return 0;
    }

    u8 expected_icmp_type_val = expect_echo_reply ? ICMP_ECHOREPLY : ICMP_ECHO;

    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) {
        debug_inc(stage_id, CODE_PARSE_HDR_FAIL);
        return 0;
    }

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U ||
        transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    struct icmphdr icmph;
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset) < 0) {
        debug_inc(stage_id, CODE_PARSE_HDR_FAIL);
        return 0;
    }

    if (icmph.type != expected_icmp_type_val) {
        debug_inc(stage_id, CODE_PARSE_ICMP_MISMATCH);
        return 0;
    }

    *icmp_type_out = icmph.type;
    key->sip = SRC_IP_FILTER;
    key->dip = DST_IP_FILTER;
    key->proto = ip.protocol;
    key->id = icmph.un.echo.id;
    key->seq = icmph.un.echo.sequence;

    debug_inc(stage_id, CODE_PARSE_SUCCESS);

    return 1;
}

// Handle event
// ctx can be either struct pt_regs* (kprobe) or tracepoint args (TRACEPOINT_PROBE)
static __always_inline void handle_event(void *ctx, struct sk_buff *skb,
                                         u64 current_stage_global_id,
                                         struct packet_key_t *parsed_packet_key,
                                         u8 actual_icmp_type) {
    debug_inc(current_stage_global_id, CODE_HANDLE_ENTRY);
    if (skb == NULL) {
        return;
    }

    // Check interface for first stage of each path
    if (current_stage_global_id == PATH2_STAGE_0 && TRACE_DIRECTION == 0) {  // TX mode reply
        if (!is_target_ifindex(skb)) {
            debug_inc(current_stage_global_id, CODE_INTERFACE_FILTER);
            return;
        }
    }
    if (current_stage_global_id == PATH1_STAGE_0 && TRACE_DIRECTION == 1) {  // RX mode request
        if (!is_target_ifindex(skb)) {
            return;
        }
    }
    if (current_stage_global_id == PATH1_STAGE_1 && TRACE_DIRECTION == 0) {  // TX mode request final
        if (!is_target_ifindex(skb)) {
            return;
        }
    }
    if (current_stage_global_id == PATH2_STAGE_2 && TRACE_DIRECTION == 1) {  // RX mode reply final
        if (!is_target_ifindex(skb)) {
            return;
        }
    }

    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);

    struct flow_data_t *flow_ptr;

    if (current_stage_global_id == PATH1_STAGE_0) {
        struct flow_data_t zero = {};
        debug_inc(current_stage_global_id, CODE_FLOW_CREATE);
        flow_ptr = flow_sessions.lookup_or_try_init(parsed_packet_key, &zero);
    } else {
        debug_inc(current_stage_global_id, CODE_FLOW_LOOKUP);
        flow_ptr = flow_sessions.lookup(parsed_packet_key);
    }

    if (!flow_ptr) {
        debug_inc(current_stage_global_id, CODE_FLOW_NOT_FOUND);
        return;
    }
    debug_inc(current_stage_global_id, CODE_FLOW_FOUND);

    if (flow_ptr->ts[current_stage_global_id] == 0) {
        flow_ptr->ts[current_stage_global_id] = current_ts;
        flow_ptr->skb_ptr[current_stage_global_id] = (u64)skb;
        flow_ptr->kstack_id[current_stage_global_id] = stack_id;

        struct net_device *dev;
        char if_name_buffer[IFNAMSIZ];
        __builtin_memset(if_name_buffer, 0, IFNAMSIZ);

        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            bpf_probe_read_kernel_str(if_name_buffer, IFNAMSIZ, dev->name);
        } else {
            char unk[] = "unknown";
            bpf_probe_read_kernel_str(if_name_buffer, sizeof(unk), unk);
        }

        if (current_stage_global_id == PATH1_STAGE_0) {
            flow_ptr->p1_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p1_comm, sizeof(flow_ptr->p1_comm));
            bpf_probe_read_kernel_str(flow_ptr->p1_ifname, IFNAMSIZ, if_name_buffer);
            flow_ptr->request_type = actual_icmp_type;
            flow_ptr->saw_path1_start = 1;
        }

        if ((TRACE_DIRECTION == 0 && current_stage_global_id == PATH1_STAGE_1) ||
            (TRACE_DIRECTION == 1 && current_stage_global_id == PATH1_STAGE_2)) {
            flow_ptr->saw_path1_end = 1;
        }

        if (current_stage_global_id == PATH2_STAGE_0 || current_stage_global_id == PATH2_STAGE_1) {
            flow_ptr->p2_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p2_comm, sizeof(flow_ptr->p2_comm));
            bpf_probe_read_kernel_str(flow_ptr->p2_ifname, IFNAMSIZ, if_name_buffer);
            flow_ptr->reply_type = actual_icmp_type;
            flow_ptr->saw_path2_start = 1;
        }

        if (current_stage_global_id == PATH2_STAGE_2) {
            flow_ptr->saw_path2_end = 1;
        }

        flow_sessions.update(parsed_packet_key, flow_ptr);
    }

    // Submit event when complete
    if (current_stage_global_id == PATH2_STAGE_2 &&
        flow_ptr->saw_path1_start && flow_ptr->saw_path1_end &&
        flow_ptr->saw_path2_start && flow_ptr->saw_path2_end) {

        u64 rtt_start_ts = flow_ptr->ts[PATH1_STAGE_0];
        u64 rtt_end_ts = flow_ptr->ts[PATH2_STAGE_2];

        if (LATENCY_THRESHOLD_NS > 0) {
            if (rtt_start_ts == 0 || rtt_end_ts == 0 ||
                (rtt_end_ts - rtt_start_ts) < LATENCY_THRESHOLD_NS) {
                return;
            }
        }

        u32 map_key_zero = 0;
        struct event_data_t *event_data_ptr = event_scratch_map.lookup(&map_key_zero);
        if (!event_data_ptr) {
            return;
        }

        event_data_ptr->key = *parsed_packet_key;

        if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow_ptr) != 0) {
            flow_sessions.delete(parsed_packet_key);
            return;
        }

        debug_inc(current_stage_global_id, CODE_PERF_SUBMIT);
        events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));
        flow_sessions.delete(parsed_packet_key);
    }
}

// Probe: ip_local_out (kernel 4.18 and some 5.x)
int kprobe__ip_local_out(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    debug_inc(TRACE_DIRECTION == 0 ? PATH1_STAGE_0 : PATH2_STAGE_1, CODE_PROBE_ENTRY);

    if (TRACE_DIRECTION == 0) {  // TX: request path (local -> remote ECHO)
        if (parse_packet_key(skb, &key, &icmp_type, 0, 0, PATH1_STAGE_0)) {
            handle_event(ctx, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    } else {  // RX: reply path
        if (parse_packet_key(skb, &key, &icmp_type, 1, 0, PATH2_STAGE_1)) {
            handle_event(ctx, skb, PATH2_STAGE_1, &key, icmp_type);
        }
    }
    return 0;
}

// Probe: __ip_local_out (kernel 5.10+ where ip_local_out may be bypassed)
// Some kernel builds call __ip_local_out directly from ip_push_pending_frames
int kprobe____ip_local_out(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    debug_inc(TRACE_DIRECTION == 0 ? PATH1_STAGE_0 : PATH2_STAGE_1, CODE_PROBE_ENTRY);

    if (TRACE_DIRECTION == 0) {  // TX: request path (local -> remote ECHO)
        if (parse_packet_key(skb, &key, &icmp_type, 0, 0, PATH1_STAGE_0)) {
            handle_event(ctx, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    } else {  // RX: reply path
        if (parse_packet_key(skb, &key, &icmp_type, 1, 0, PATH2_STAGE_1)) {
            handle_event(ctx, skb, PATH2_STAGE_1, &key, icmp_type);
        }
    }
    return 0;
}

// Tracepoint: net_dev_xmit
RAW_TRACEPOINT_PROBE(net_dev_xmit) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    struct packet_key_t key = {};
    u8 icmp_type = 0;

    debug_inc(TRACE_DIRECTION == 0 ? PATH1_STAGE_1 : PATH2_STAGE_2, CODE_PROBE_ENTRY);

    if (TRACE_DIRECTION == 0) {  // TX: request path
        if (parse_packet_key(skb, &key, &icmp_type, 0, 0, PATH1_STAGE_1)) {
            handle_event(ctx, skb, PATH1_STAGE_1, &key, icmp_type);
        }
    } else {  // RX: reply path
        if (parse_packet_key(skb, &key, &icmp_type, 1, 0, PATH2_STAGE_2)) {
            handle_event(ctx, skb, PATH2_STAGE_2, &key, icmp_type);
        }
    }
    return 0;
}

// Probe: netif_receive_skb
// Using tracepoint for better compatibility
// NOTE: TRACEPOINT_PROBE macro already includes return type - do NOT add 'int' prefix
//       In tracepoint context, use 'args' instead of 'ctx'
//
// Fallback for old kernels without this tracepoint:
// Replace with: int kprobe____netif_receive_skb_core(struct pt_regs *ctx, struct sk_buff *skb) {
//
TRACEPOINT_PROBE(net, netif_receive_skb) {
    debug_inc(TRACE_DIRECTION == 0 ? PATH2_STAGE_0 : PATH1_STAGE_0, CODE_PROBE_ENTRY);

    // Get skb from tracepoint arguments
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {  // TX: reply path (incoming echo-reply)
        if (parse_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_0)) {
            handle_event(args, skb, PATH2_STAGE_0, &key, icmp_type);
        }
    } else {  // RX: request path (source is remote, dest is local)
        if (parse_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_0)) {
            handle_event(args, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    }
    return 0;
}

// Some kernels use netif_receive_skb_entry tracepoint; attach as fallback
TRACEPOINT_PROBE(net, netif_receive_skb_entry) {
    debug_inc(TRACE_DIRECTION == 0 ? PATH2_STAGE_0 : PATH1_STAGE_0, CODE_PROBE_ENTRY);

    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {  // TX: reply path (incoming echo-reply)
        if (parse_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_0)) {
            handle_event(args, skb, PATH2_STAGE_0, &key, icmp_type);
        }
    } else {  // RX: request path
        // RX request (incoming echo)
        if (parse_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_0)) {
            handle_event(args, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    }
    return 0;
}

// Older kernels may miss the tracepoint; fallback kprobe
int kprobe____netif_receive_skb_core(struct pt_regs *ctx, struct sk_buff *skb) {
    debug_inc(TRACE_DIRECTION == 0 ? PATH2_STAGE_0 : PATH1_STAGE_0, CODE_PROBE_ENTRY);

    if (!skb) return 0;

    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {  // TX: reply path (incoming echo-reply)
        if (parse_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_0)) {
            handle_event(ctx, skb, PATH2_STAGE_0, &key, icmp_type);
        }
    } else {  // RX: request path
        if (parse_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_0)) {
            handle_event(ctx, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    }
    return 0;
}

// Probe: ip_rcv
// Kernel 4.18 signature: int ip_rcv(struct sk_buff *skb, struct net_device *dev,
//                                    struct packet_type *pt, struct net_device *orig_dev)
int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb,
                   struct net_device *dev, struct packet_type *pt,
                   struct net_device *orig_dev) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    debug_inc(TRACE_DIRECTION == 0 ? PATH2_STAGE_1 : PATH1_STAGE_1, CODE_PROBE_ENTRY);

    if (TRACE_DIRECTION == 0) {  // TX: reply path (incoming echo-reply)
        if (parse_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_1)) {
            handle_event(ctx, skb, PATH2_STAGE_1, &key, icmp_type);
        }
    } else {  // RX: request path
        if (parse_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_1)) {
            handle_event(ctx, skb, PATH1_STAGE_1, &key, icmp_type);
        }
    }
    return 0;
}

// Probe: icmp_rcv
int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    debug_inc(TRACE_DIRECTION == 0 ? PATH2_STAGE_2 : PATH1_STAGE_2, CODE_PROBE_ENTRY);

    if (TRACE_DIRECTION == 0) {  // TX: reply path (incoming echo-reply)
        if (parse_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_2)) {
            handle_event(ctx, skb, PATH2_STAGE_2, &key, icmp_type);
        }
    } else {  // RX: request path
        if (parse_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_2)) {
            handle_event(ctx, skb, PATH1_STAGE_2, &key, icmp_type);
        }
    }
    return 0;
}
"""

# Constants
MAX_STAGES = 6
IFNAMSIZ = 16
TASK_COMM_LEN = 16

class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("proto", ctypes.c_uint8),
        ("id", ctypes.c_uint16),
        ("seq", ctypes.c_uint16)
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_STAGES),
        ("kstack_id", ctypes.c_int * MAX_STAGES),
        ("p1_pid", ctypes.c_uint32),
        ("p1_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p1_ifname", ctypes.c_char * IFNAMSIZ),
        ("p2_pid", ctypes.c_uint32),
        ("p2_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p2_ifname", ctypes.c_char * IFNAMSIZ),
        ("request_type", ctypes.c_uint8),
        ("reply_type", ctypes.c_uint8),
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

# Debug decoding helpers
DEBUG_STAGE_NAMES = {
    0: "P1:S0",
    1: "P1:S1",
    2: "P1:S2",
    3: "P2:S0",
    4: "P2:S1",
    5: "P2:S2",
}

DEBUG_CODE_NAMES = {
    1: "PROBE_ENTRY",
    2: "INTERFACE_FILTER",
    5: "HANDLE_ENTRY",
    6: "PARSE_ENTRY",
    7: "PARSE_SUCCESS",
    8: "IP_FILTER",
    14: "FLOW_CREATE",
    15: "FLOW_LOOKUP",
    16: "FLOW_FOUND",
    17: "FLOW_NOT_FOUND",
    19: "PERF_SUBMIT",
    20: "PARSE_HDR_FAIL",
    21: "PARSE_NOT_ICMP",
    22: "PARSE_IP_MISMATCH",
    23: "PARSE_ICMP_MISMATCH",
}

# Helper functions
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
        return " N/A ".rjust(7)
    delta_ns = ts_end - ts_start
    delta_us = delta_ns / 1000.0
    return ("%.3f" % delta_us).rjust(7)

def get_stage_name(stage_id, direction):
    """Get stage name based on direction"""
    if direction == "tx":
        stage_names = {
            0: "P1:S0 (ip_local_out)",
            1: "P1:S1 (net_dev_xmit)",
            2: "P1:S2 (unused)",
            3: "P2:S0 (__netif_receive_skb)",
            4: "P2:S1 (ip_rcv)",
            5: "P2:S2 (icmp_rcv)"
        }
    else:  # rx
        stage_names = {
            0: "P1:S0 (__netif_receive_skb)",
            1: "P1:S1 (ip_rcv)",
            2: "P1:S2 (icmp_rcv)",
            3: "P2:S0 (unused)",
            4: "P2:S1 (ip_local_out)",
            5: "P2:S2 (net_dev_xmit)"
        }
    return stage_names.get(stage_id, "Unknown")

def print_latency_segment(start_idx, end_idx, flow_data, direction_str):
    """Print a latency segment"""
    latency = format_latency(flow_data.ts[start_idx], flow_data.ts[end_idx])
    start_name = get_stage_name(start_idx, direction_str)
    end_name = get_stage_name(end_idx, direction_str)

    print("  [%d->%d] %-40s -> %-40s: %s us" % (
        start_idx, end_idx, start_name, end_name, latency
    ))

def print_kernel_stack(stage_idx, stack_id, direction):
    """Print kernel stack trace for a stage"""
    global args, b
    stage_name = get_stage_name(stage_idx, direction)
    print("  Stage %d (%s):" % (stage_idx, stage_name))

    if stack_id <= 0:
        print("    <No stack trace: id=%d>" % stack_id)
        return

    try:
        stack_table = b.get_table("stack_traces")
        resolved_one = False
        for addr in stack_table.walk(stack_id):
            sym = b.ksym(addr, show_offset=True)
            print("    %s" % sym)
            resolved_one = True

        if not resolved_one:
            print("    <No symbols for stack id %d>" % stack_id)
    except Exception as e:
        print("    <Error: %s>" % e)

def print_debug_statistics(bpf_obj):
    """Print debug histogram statistics (bcc-debug-framework)"""
    try:
        debug_map = bpf_obj.get_table("debug_stage_stats")
    except Exception:
        print("No debug statistics available")
        return

    entries = []
    for k, v in debug_map.items():
        count = v.value if hasattr(v, 'value') else int(v)
        if count == 0:
            continue
        stage_id = k.value >> 8
        code_point = k.value & 0xFF
        stage_name = DEBUG_STAGE_NAMES.get(stage_id, "STAGE_%d" % stage_id)
        code_name = DEBUG_CODE_NAMES.get(code_point, "CODE_%d" % code_point)
        entries.append((stage_id, code_point, stage_name, code_name, count))

    if not entries:
        print("No debug counters recorded")
        return

    print("\n" + "=" * 80)
    print("Debug Counters (stage_id.code_point -> count)")
    print("=" * 80)
    for _, _, stage_name, code_name, count in sorted(entries):
        print("  %-10s %-15s : %d" % (stage_name, code_name, count))

def print_event(cpu, data, size):
    global args, b
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    key = event.key
    flow = event.data

    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    trace_dir_str = "TX (Local -> Remote)" if args.direction == "tx" else "RX (Remote -> Local)"

    print("=" * 80)
    print("=== ICMP RTT Trace: %s (%s) ===" % (time_str, trace_dir_str))
    # Session shows ping initiator -> ping target (user's --src-ip -> --dst-ip)
    print("Session: %s -> %s (ID: %d, Seq: %d)" % (
        args.src_ip,
        args.dst_ip,
        socket.ntohs(key.id),
        socket.ntohs(key.seq)
    ))

    if args.direction == "tx":
        # TX: local sends request to remote, receives reply from remote
        path1_desc = "Path 1 (Request: TX to %s)" % args.dst_ip
        path2_desc = "Path 2 (Reply:   RX from %s)" % args.dst_ip
    else:
        # RX: receive request from remote (src_ip), send reply to remote (src_ip)
        path1_desc = "Path 1 (Request: RX from %s)" % args.src_ip
        path2_desc = "Path 2 (Reply:   TX to %s)" % args.src_ip

    print("%-45s: PID=%-6d COMM=%-12s IF=%-10s ICMP_Type=%d" % (
        path1_desc,
        flow.p1_pid,
        flow.p1_comm.decode('utf-8', 'replace'),
        flow.p1_ifname.decode('utf-8', 'replace'),
        flow.request_type
    ))

    print("%-45s: PID=%-6d COMM=%-12s IF=%-10s ICMP_Type=%d" % (
        path2_desc,
        flow.p2_pid,
        flow.p2_comm.decode('utf-8', 'replace'),
        flow.p2_ifname.decode('utf-8', 'replace'),
        flow.reply_type
    ))

    print("\nSKB Pointers:")
    for i in range(MAX_STAGES):
        if flow.skb_ptr[i] != 0:
            stage_name = get_stage_name(i, args.direction)
            print("  Stage %d (%-40s): 0x%x" % (i, stage_name, flow.skb_ptr[i]))

    print("\nPath 1 Latencies (us):")
    print_latency_segment(0, 1, flow, args.direction)
    if args.direction == "rx":
        print_latency_segment(1, 2, flow, args.direction)
        if flow.ts[0] > 0 and flow.ts[2] > 0:
            path1_total = format_latency(flow.ts[0], flow.ts[2])
            print("  Total Path 1: %s us" % path1_total)
    else:
        if flow.ts[0] > 0 and flow.ts[1] > 0:
            path1_total = format_latency(flow.ts[0], flow.ts[1])
            print("  Total Path 1: %s us" % path1_total)

    print("\nPath 2 Latencies (us):")
    if args.direction == "tx":
        print_latency_segment(3, 4, flow, args.direction)
        print_latency_segment(4, 5, flow, args.direction)
        if flow.ts[3] > 0 and flow.ts[5] > 0:
            path2_total = format_latency(flow.ts[3], flow.ts[5])
            print("  Total Path 2: %s us" % path2_total)
    else:
        print_latency_segment(4, 5, flow, args.direction)
        if flow.ts[4] > 0 and flow.ts[5] > 0:
            path2_total = format_latency(flow.ts[4], flow.ts[5])
            print("  Total Path 2: %s us" % path2_total)

    if flow.ts[0] > 0 and flow.ts[5] > 0:
        rtt = format_latency(flow.ts[0], flow.ts[5])
        print("\nTotal RTT (Path1 Start to Path2 End): %s us" % rtt)

        if args.direction == "tx" and flow.ts[1] > 0 and flow.ts[3] > 0:
            inter_path_latency = format_latency(flow.ts[1], flow.ts[3])
            print("Inter-Path Latency (P1 end -> P2 start): %s us" % inter_path_latency)
        if args.direction == "rx" and flow.ts[2] > 0 and flow.ts[4] > 0:
            inter_path_latency = format_latency(flow.ts[2], flow.ts[4])
            print("Inter-Path Latency (P1 end -> P2 start): %s us" % inter_path_latency)

    if not args.disable_kernel_stacks:
        print("\nKernel Stack Traces:")
        for i in range(MAX_STAGES):
            if flow.ts[i] != 0:
                print_kernel_stack(i, flow.kstack_id[i], args.direction)

    print("=" * 80 + "\n")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Trace ICMP RTT through kernel network stack (no OVS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  TX mode (local ping remote):
    sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                              --interface eth0 --direction tx

  RX mode (remote ping local):
    sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                              --interface eth0 --direction rx

  With latency threshold:
    sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                              --interface eth0 --latency-ms 10

  Bond scenario (monitor multiple slave interfaces):
    sudo ./kernel_icmp_rtt.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
                              --interface ens4f0,ens4f1 --direction tx
"""
    )

    parser.add_argument('--src-ip', type=str, required=True,
                      help='Source IP of ping session (who sends echo request)')
    parser.add_argument('--dst-ip', type=str, required=True,
                      help='Destination IP of ping session (who receives echo request)')
    parser.add_argument('--interface', type=str, required=False, default=None,
                      help='Network interface(s) to monitor, comma-separated for bond scenarios (e.g., "ens4f0,ens4f1"). Optional, monitors all if not specified.')
    parser.add_argument('--latency-ms', type=float, default=0,
                      help='Minimum RTT latency threshold in ms (default: 0, report all)')
    parser.add_argument('--direction', type=str, choices=["tx", "rx"], default="tx",
                      help='Direction: "tx" (local pings remote) or "rx" (remote pings local)')
    parser.add_argument('--disable-kernel-stacks', action='store_true', default=False,
                      help='Disable kernel stack trace output')
    parser.add_argument('--debug', action='store_true', default=False,
                      help='Enable verbose BPF debug trace output (trace_pipe)')

    args = parser.parse_args()

    direction_val = 0 if args.direction == "tx" else 1
    debug_enable_val = 1 if args.debug else 0

    # Parse interface(s) - support comma-separated list for bond scenarios
    iface_indices = []
    iface_names = []
    if args.interface:
        iface_list = [iface.strip() for iface in args.interface.split(',')]
        for iface in iface_list:
            try:
                idx = get_if_index(iface)
                iface_indices.append(idx)
                iface_names.append(iface)
            except OSError as e:
                print("Error getting interface index for '%s': %s" % (iface, e))
                sys.exit(1)

    # In TX mode: src-ip is local, dst-ip is remote (user sends ping)
    # In RX mode: src-ip is remote, dst-ip is local (user receives ping)
    # BPF code always expects: SRC_IP_FILTER = local IP, DST_IP_FILTER = remote IP
    # So we swap the values internally for RX mode
    if args.direction == "tx":
        local_ip = args.src_ip
        remote_ip = args.dst_ip
    else:  # rx mode
        local_ip = args.dst_ip
        remote_ip = args.src_ip

    src_ip_hex_val = ip_to_hex(local_ip)
    dst_ip_hex_val = ip_to_hex(remote_ip)
    latency_threshold_ns_val = int(args.latency_ms * 1000000)

    print("=== Kernel ICMP RTT Tracer ===")
    print("Trace Direction: %s" % args.direction.upper())
    print("Ping Session: %s -> %s" % (args.src_ip, args.dst_ip))
    print("Local IP: %s (0x%x)" % (local_ip, socket.ntohl(src_ip_hex_val)))
    print("Remote IP: %s (0x%x)" % (remote_ip, socket.ntohl(dst_ip_hex_val)))

    if iface_indices:
        iface_info = ', '.join("%s(ifindex=%d)" % (n, i) for n, i in zip(iface_names, iface_indices))
        print("Monitoring interface(s): %s" % iface_info)
    else:
        print("Monitoring all interfaces")

    if latency_threshold_ns_val > 0:
        print("Reporting only RTT >= %.3f ms" % args.latency_ms)

    if args.debug:
        print("Debug counters enabled (bcc-debug-framework); will print on exit")

    # Generate interface array code for BPF
    if iface_indices:
        iface_array_code = """
#define IFACE_COUNT %d
static const int target_ifindexes[IFACE_COUNT] = {%s};
""" % (len(iface_indices), ', '.join(str(i) for i in iface_indices))
    else:
        iface_array_code = """
#define IFACE_COUNT 0
// No interface filter - all interfaces monitored
"""

    try:
        # Substitute interface array code first (string replace)
        bpf_program = bpf_text.replace("__IFACE_ARRAY__", iface_array_code)
        # Then substitute other parameters
        b = BPF(text=bpf_program % (
            debug_enable_val,
            src_ip_hex_val,
            dst_ip_hex_val,
            latency_threshold_ns_val,
            direction_val
        ))
        print("\nBPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Verify probe attachment
    print("\nVerifying probe attachments:")
    probe_functions = [
        "ip_local_out",
        "__ip_local_out",
        "ip_rcv",
        "icmp_rcv"
    ]

    for func in probe_functions:
        # Try to check if function exists in kernel
        try:
            with open("/proc/kallsyms", "r") as f:
                if any(func in line for line in f):
                    print("  [OK] %s found in kallsyms" % func)
                else:
                    print("  [WARN] %s NOT found in kallsyms - probe may fail!" % func)
        except:
            pass

    # Check tracepoint
    import glob
    tp_path = "/sys/kernel/debug/tracing/events/net/netif_receive_skb"
    if os.path.exists(tp_path):
        print("  [OK] netif_receive_skb tracepoint exists")
    else:
        print("  [WARN] netif_receive_skb tracepoint NOT found!")
        # Try alternative
        tp_alt = "/sys/kernel/debug/tracing/events/net/netif_rx"
        if os.path.exists(tp_alt):
            print("  [INFO] Found alternative: netif_rx tracepoint")

    tp_xmit = "/sys/kernel/debug/tracing/events/net/net_dev_xmit"
    if os.path.exists(tp_xmit):
        print("  [OK] net_dev_xmit tracepoint exists")
    else:
        print("  [WARN] net_dev_xmit tracepoint NOT found!")

    b["events"].open_perf_buffer(print_event)

    print("\nTracing ICMP RTT (src=%s, dst=%s, dir=%s) ... Hit Ctrl-C to end." %
          (args.src_ip, args.dst_ip, args.direction))

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
    finally:
        if args.debug:
            print_debug_statistics(b)
        print("Exiting.")
