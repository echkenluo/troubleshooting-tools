#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OVS Multicast Action Trace Tool
# Traces OVS datapath action execution for IPv6 multicast packets
# to debug why multicast only reaches one of multiple output ports.
#
# Usage: sudo python ovs_mcast_action_trace.py --dst-ip ff05::1
#
# Key probe points:
# 1. ovs_dp_process_packet - Entry point for packet processing
# 2. do_output - Per-port output action
# 3. ovs_fragment - IPv6 fragmentation
# 4. ovs_vport_send - Final packet send

from __future__ import print_function
import argparse
import ctypes
import socket
import struct
import sys

try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Error: Neither 'bcc' nor 'bpfcc' module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)

# BPF program
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/openvswitch.h>

#define MAX_IFNAME_LEN 16
#define IPV6_ADDR_LEN 16

// Event types
#define EVENT_PROCESS_PKT   1
#define EVENT_EXECUTE_ACTS  2
#define EVENT_DO_OUTPUT     3
#define EVENT_FRAGMENT      4
#define EVENT_VPORT_SEND    5
#define EVENT_VPORT_DROP    6

struct event_t {
    u64 ts_ns;
    u32 pid;
    u32 cpu;
    u8 event_type;
    u8 ipv6_dst[IPV6_ADDR_LEN];
    char in_ifname[MAX_IFNAME_LEN];
    char out_ifname[MAX_IFNAME_LEN];
    u32 skb_len;
    u32 skb_hash;
    u16 mru;
    u16 out_port;
    u16 mtu;
    u8 is_clone;
    u8 action_count;
};

BPF_PERF_OUTPUT(events);

// Helper to check if destination is our target multicast address
static inline int match_ipv6_dst(struct sk_buff *skb, u8 *target_dst) {
    void *data = (void *)(long)skb->data;
    struct ipv6hdr *ip6h;
    u16 network_offset;

    // Get network header offset
    network_offset = skb->network_header;
    if (network_offset == 0) {
        return 0;
    }

    ip6h = (struct ipv6hdr *)(skb->head + network_offset);

    // Compare destination address
    #pragma unroll
    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        u8 addr_byte = 0;
        bpf_probe_read_kernel(&addr_byte, 1, &ip6h->daddr.s6_addr[i]);
        if (addr_byte != target_dst[i]) {
            return 0;
        }
    }
    return 1;
}

// Get interface name from net_device
static inline void get_ifname(struct net_device *dev, char *ifname) {
    if (dev) {
        bpf_probe_read_kernel_str(ifname, MAX_IFNAME_LEN, dev->name);
    } else {
        ifname[0] = '-';
        ifname[1] = '\0';
    }
}

// Target IPv6 multicast address (set by userspace)
BPF_ARRAY(target_ipv6_dst, u8, IPV6_ADDR_LEN);

// Track per-packet processing
BPF_HASH(pkt_tracking, u64, u8);

// Probe: ovs_dp_process_packet
// Entry point for OVS datapath packet processing
int kprobe__ovs_dp_process_packet(struct pt_regs *ctx,
                                   struct sk_buff *skb,
                                   struct sw_flow_key *key) {
    struct event_t event = {};
    u8 target_dst[IPV6_ADDR_LEN] = {};

    // Get target IPv6 address
    #pragma unroll
    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        u8 *val = target_ipv6_dst.lookup(&i);
        if (val) target_dst[i] = *val;
    }

    // Check if this is our target packet
    if (!match_ipv6_dst(skb, target_dst)) {
        return 0;
    }

    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.cpu = bpf_get_smp_processor_id();
    event.event_type = EVENT_PROCESS_PKT;

    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);
    bpf_probe_read_kernel(&event.skb_hash, sizeof(event.skb_hash), &skb->hash);

    // Get input interface
    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    get_ifname(dev, event.in_ifname);

    // Copy IPv6 dst
    bpf_probe_read_kernel(event.ipv6_dst, IPV6_ADDR_LEN, target_dst);

    // Track this packet
    u64 skb_addr = (u64)skb;
    u8 tracked = 1;
    pkt_tracking.update(&skb_addr, &tracked);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: do_output
// Called for each OUTPUT action
int kprobe__do_output(struct pt_regs *ctx,
                      struct datapath *dp,
                      struct sk_buff *skb,
                      int out_port,
                      struct sw_flow_key *key) {
    u64 skb_addr = (u64)skb;
    u8 *tracked = pkt_tracking.lookup(&skb_addr);

    // Also check if this is a clone of a tracked packet
    struct sk_buff *orig_skb = NULL;
    // Note: skb clones share the same data, we track by checking ipv6 dst

    struct event_t event = {};
    u8 target_dst[IPV6_ADDR_LEN] = {};

    #pragma unroll
    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        u8 *val = target_ipv6_dst.lookup(&i);
        if (val) target_dst[i] = *val;
    }

    if (!match_ipv6_dst(skb, target_dst)) {
        return 0;
    }

    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.cpu = bpf_get_smp_processor_id();
    event.event_type = EVENT_DO_OUTPUT;
    event.out_port = out_port;

    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);
    bpf_probe_read_kernel(&event.skb_hash, sizeof(event.skb_hash), &skb->hash);

    // Get mru from OVS_CB
    // OVS_CB is at skb->cb, mru offset depends on kernel version
    // struct ovs_skb_cb { struct vport *input_vport; u16 mru; u16 cutlen; ... }
    u16 mru = 0;
    bpf_probe_read_kernel(&mru, sizeof(mru), &skb->cb[sizeof(void *)]);
    event.mru = mru;

    // Check if this is a clone
    u8 cloned = 0;
    bpf_probe_read_kernel(&cloned, sizeof(cloned), &skb->cloned);
    event.is_clone = cloned;

    bpf_probe_read_kernel(event.ipv6_dst, IPV6_ADDR_LEN, target_dst);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: ovs_fragment
// Called when packet needs fragmentation
int kprobe__ovs_fragment(struct pt_regs *ctx,
                         struct net *net,
                         struct vport *vport,
                         struct sk_buff *skb,
                         u16 mru,
                         struct sw_flow_key *key) {
    struct event_t event = {};
    u8 target_dst[IPV6_ADDR_LEN] = {};

    #pragma unroll
    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        u8 *val = target_ipv6_dst.lookup(&i);
        if (val) target_dst[i] = *val;
    }

    if (!match_ipv6_dst(skb, target_dst)) {
        return 0;
    }

    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.cpu = bpf_get_smp_processor_id();
    event.event_type = EVENT_FRAGMENT;
    event.mru = mru;

    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);

    // Get vport device name
    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &vport->dev);
    get_ifname(dev, event.out_ifname);

    if (dev) {
        bpf_probe_read_kernel(&event.mtu, sizeof(event.mtu), &dev->mtu);
    }

    bpf_probe_read_kernel(event.ipv6_dst, IPV6_ADDR_LEN, target_dst);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: ovs_vport_send
// Final send to output port
int kprobe__ovs_vport_send(struct pt_regs *ctx,
                           struct vport *vport,
                           struct sk_buff *skb,
                           u8 mac_proto) {
    struct event_t event = {};
    u8 target_dst[IPV6_ADDR_LEN] = {};

    #pragma unroll
    for (int i = 0; i < IPV6_ADDR_LEN; i++) {
        u8 *val = target_ipv6_dst.lookup(&i);
        if (val) target_dst[i] = *val;
    }

    if (!match_ipv6_dst(skb, target_dst)) {
        return 0;
    }

    event.ts_ns = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.cpu = bpf_get_smp_processor_id();
    event.event_type = EVENT_VPORT_SEND;

    bpf_probe_read_kernel(&event.skb_len, sizeof(event.skb_len), &skb->len);

    // Get output interface
    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &vport->dev);
    get_ifname(dev, event.out_ifname);

    if (dev) {
        bpf_probe_read_kernel(&event.mtu, sizeof(event.mtu), &dev->mtu);
    }

    bpf_probe_read_kernel(event.ipv6_dst, IPV6_ADDR_LEN, target_dst);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: kfree_skb in ovs_vport_send (drop path)
// Detect when packets are dropped due to MTU
int kretprobe__ovs_vport_send(struct pt_regs *ctx) {
    // This is called after ovs_vport_send returns
    // We can detect drops by checking if the packet was actually sent
    return 0;
}
"""

# Event types
EVENT_PROCESS_PKT = 1
EVENT_EXECUTE_ACTS = 2
EVENT_DO_OUTPUT = 3
EVENT_FRAGMENT = 4
EVENT_VPORT_SEND = 5
EVENT_VPORT_DROP = 6

EVENT_NAMES = {
    EVENT_PROCESS_PKT: "PROCESS_PKT",
    EVENT_EXECUTE_ACTS: "EXECUTE_ACTS",
    EVENT_DO_OUTPUT: "DO_OUTPUT",
    EVENT_FRAGMENT: "FRAGMENT",
    EVENT_VPORT_SEND: "VPORT_SEND",
    EVENT_VPORT_DROP: "VPORT_DROP",
}

def ipv6_to_bytes(ipv6_str):
    """Convert IPv6 string to bytes"""
    return socket.inet_pton(socket.AF_INET6, ipv6_str)

def bytes_to_ipv6(addr_bytes):
    """Convert bytes to IPv6 string"""
    return socket.inet_ntop(socket.AF_INET6, bytes(addr_bytes))

def print_event(cpu, data, size):
    """Print event callback"""
    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    ts_s = event.ts_ns / 1e9
    event_name = EVENT_NAMES.get(event.event_type, "UNKNOWN")
    ipv6_dst = bytes_to_ipv6(event.ipv6_dst)

    in_if = event.in_ifname.decode('utf-8', errors='replace').rstrip('\x00')
    out_if = event.out_ifname.decode('utf-8', errors='replace').rstrip('\x00')

    clone_str = "clone" if event.is_clone else "orig"

    if event.event_type == EVENT_PROCESS_PKT:
        print("[%.6f] CPU%-2d %-12s in=%-10s dst=%s len=%d hash=0x%x" % (
            ts_s, event.cpu, event_name, in_if, ipv6_dst,
            event.skb_len, event.skb_hash))
    elif event.event_type == EVENT_DO_OUTPUT:
        print("[%.6f] CPU%-2d %-12s port=%-4d len=%d mru=%d %s" % (
            ts_s, event.cpu, event_name, event.out_port,
            event.skb_len, event.mru, clone_str))
    elif event.event_type == EVENT_FRAGMENT:
        print("[%.6f] CPU%-2d %-12s out=%-10s len=%d mru=%d mtu=%d" % (
            ts_s, event.cpu, event_name, out_if,
            event.skb_len, event.mru, event.mtu))
    elif event.event_type == EVENT_VPORT_SEND:
        print("[%.6f] CPU%-2d %-12s out=%-10s len=%d mtu=%d" % (
            ts_s, event.cpu, event_name, out_if,
            event.skb_len, event.mtu))
    else:
        print("[%.6f] CPU%-2d %-12s len=%d" % (
            ts_s, event.cpu, event_name, event.skb_len))

class Event(ctypes.Structure):
    _fields_ = [
        ("ts_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("cpu", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("ipv6_dst", ctypes.c_uint8 * 16),
        ("in_ifname", ctypes.c_char * 16),
        ("out_ifname", ctypes.c_char * 16),
        ("skb_len", ctypes.c_uint32),
        ("skb_hash", ctypes.c_uint32),
        ("mru", ctypes.c_uint16),
        ("out_port", ctypes.c_uint16),
        ("mtu", ctypes.c_uint16),
        ("is_clone", ctypes.c_uint8),
        ("action_count", ctypes.c_uint8),
    ]

def main():
    parser = argparse.ArgumentParser(
        description="Trace OVS multicast action execution")
    parser.add_argument("--dst-ip", required=True,
                        help="IPv6 multicast destination address to trace")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug output")
    args = parser.parse_args()

    # Validate IPv6 address
    try:
        dst_bytes = ipv6_to_bytes(args.dst_ip)
    except socket.error:
        print("Error: Invalid IPv6 address: %s" % args.dst_ip)
        return 1

    print("OVS Multicast Action Trace")
    print("Tracing packets to: %s" % args.dst_ip)
    print("-" * 70)

    # Compile BPF program
    if args.debug:
        print("Compiling BPF program...")

    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print("Error compiling BPF program: %s" % e)
        print("Note: This tool requires OVS kernel module symbols")
        return 1

    # Set target IPv6 address
    target_map = b.get_table("target_ipv6_dst")
    for i, byte in enumerate(dst_bytes):
        target_map[ctypes.c_int(i)] = ctypes.c_uint8(byte)

    # Open perf buffer
    b["events"].open_perf_buffer(print_event)

    print("Listening for packets... (Ctrl+C to stop)")
    print("")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nStopping...")

    return 0

if __name__ == "__main__":
    exit(main())
