#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
OVS queue_userspace_packet Return Value Tracer

Traces the return value of queue_userspace_packet function to diagnose
upcall failures in OVS datapath.

Usage:
    sudo python queue_userspace_packet_retval.py
    sudo python queue_userspace_packet_retval.py --src-ip 192.168.1.100
    sudo python queue_userspace_packet_retval.py --filter-error
"""

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

import argparse
import sys
import os
from time import strftime
import errno
import socket
import struct

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

#define SRC_IP_FILTER __SRC_IP_FILTER__
#define DST_IP_FILTER __DST_IP_FILTER__
#define PROTOCOL_FILTER __PROTOCOL_FILTER__

struct call_info_t {
    u32 saddr;
    u32 daddr;
    u8 protocol;
    u8 matched;
};

struct event_t {
    u64 timestamp;
    u32 pid;
    int retval;
    u32 saddr;
    u32 daddr;
    u8 protocol;
    char comm[16];
};

// Map to pass data from kprobe entry to kretprobe exit (key: pid_tgid)
BPF_HASH(call_map, u64, struct call_info_t);

BPF_PERF_OUTPUT(events);

// Statistics counters
BPF_ARRAY(stats, u64, 16);

#define STAT_TOTAL      0
#define STAT_SUCCESS    1
#define STAT_ENODEV     2
#define STAT_ENOMEM     3
#define STAT_EFBIG      4
#define STAT_EINVAL     5
#define STAT_EMSGSIZE   6
#define STAT_ENOBUFS    7
#define STAT_ENOTCONN   8
#define STAT_ECONNREFUSED 9
#define STAT_OTHER      10

static __always_inline void update_stat(int idx) {
    u64 *val = stats.lookup(&idx);
    if (val) {
        (*val)++;
    }
}

static __always_inline int parse_skb_ip(struct sk_buff *skb, struct call_info_t *info) {
    struct iphdr ip;
    unsigned char *head;
    u16 network_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return 0;
    if (bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0)
        return 0;

    if (network_header_offset == (u16)~0U || network_header_offset > 2048)
        return 0;

    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0)
        return 0;

    // Check IP version
    if ((ip.version != 4) || (ip.ihl < 5))
        return 0;

    info->saddr = ip.saddr;
    info->daddr = ip.daddr;
    info->protocol = ip.protocol;

    // Apply protocol filter
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER)
        return 0;

    // Apply IP filters (strict match)
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER)
        return 0;
    if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER)
        return 0;

    info->matched = 1;
    return 1;
}

// Entry probe: save skb info to map
int trace_queue_userspace_packet_entry(struct pt_regs *ctx,
    void *dp, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct call_info_t info = {};

    parse_skb_ip(skb, &info);

    call_map.update(&pid_tgid, &info);
    return 0;
}

// Exit probe: get return value and correlate with entry data
int trace_queue_userspace_packet_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int retval = PT_REGS_RC(ctx);

    struct call_info_t *info = call_map.lookup(&pid_tgid);
    if (!info) {
        return 0;
    }

    // Only process if filter matched (or no filter)
    if (!info->matched) {
        call_map.delete(&pid_tgid);
        return 0;
    }

    struct event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.retval = retval;
    event.saddr = info->saddr;
    event.daddr = info->daddr;
    event.protocol = info->protocol;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Update statistics
    int idx = STAT_TOTAL;
    update_stat(idx);

    if (retval == 0) {
        idx = STAT_SUCCESS;
    } else if (retval == -19) {  // -ENODEV
        idx = STAT_ENODEV;
    } else if (retval == -12) {  // -ENOMEM
        idx = STAT_ENOMEM;
    } else if (retval == -27) {  // -EFBIG
        idx = STAT_EFBIG;
    } else if (retval == -22) {  // -EINVAL
        idx = STAT_EINVAL;
    } else if (retval == -90) {  // -EMSGSIZE
        idx = STAT_EMSGSIZE;
    } else if (retval == -105) { // -ENOBUFS
        idx = STAT_ENOBUFS;
    } else if (retval == -107) { // -ENOTCONN
        idx = STAT_ENOTCONN;
    } else if (retval == -111) { // -ECONNREFUSED
        idx = STAT_ECONNREFUSED;
    } else {
        idx = STAT_OTHER;
    }
    update_stat(idx);

    events.perf_submit(ctx, &event, sizeof(event));

    call_map.delete(&pid_tgid);
    return 0;
}
"""

ERRNO_MAP = {
    0: "SUCCESS",
    -errno.ENODEV: "ENODEV",
    -errno.ENOMEM: "ENOMEM",
    -errno.EFBIG: "EFBIG",
    -errno.EINVAL: "EINVAL",
    -errno.EMSGSIZE: "EMSGSIZE",
    -errno.ENOBUFS: "ENOBUFS",
    -errno.ENOTCONN: "ENOTCONN",
    -errno.ECONNREFUSED: "ECONNREFUSED",
}

PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def ip_to_int(ip_str):
    """Convert IP address string to integer (host byte order for BPF comparison)"""
    if not ip_str:
        return 0
    try:
        # Use native byte order to match how kernel stores IP in u32
        return struct.unpack("I", socket.inet_aton(ip_str))[0]
    except socket.error:
        print("Error: Invalid IP address: %s" % ip_str)
        sys.exit(1)

def int_to_ip(ip_int):
    """Convert integer to IP address string (from host byte order)"""
    if ip_int == 0:
        return "0.0.0.0"
    # IP stored as-is from kernel (network byte order in struct),
    # but read as host u32, so use native byte order here
    return socket.inet_ntoa(struct.pack("I", ip_int))

def proto_to_str(proto):
    """Convert protocol number to string"""
    return PROTO_MAP.get(proto, str(proto))

def get_error_name(retval):
    """Convert return value to error name"""
    if retval in ERRNO_MAP:
        return ERRNO_MAP[retval]
    if retval < 0:
        return "ERR(%d)" % retval
    return "OK(%d)" % retval

def print_event(cpu, data, size, filter_error=False):
    """Print event callback"""
    import ctypes

    class Event(ctypes.Structure):
        _fields_ = [
            ("timestamp", ctypes.c_ulonglong),
            ("pid", ctypes.c_uint),
            ("retval", ctypes.c_int),
            ("saddr", ctypes.c_uint),
            ("daddr", ctypes.c_uint),
            ("protocol", ctypes.c_ubyte),
            ("comm", ctypes.c_char * 16),
        ]

    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    if filter_error and event.retval == 0:
        return

    error_name = get_error_name(event.retval)
    comm = event.comm.decode('utf-8', 'replace')
    saddr = int_to_ip(event.saddr)
    daddr = int_to_ip(event.daddr)
    proto = proto_to_str(event.protocol)

    print("[%s] %-15s -> %-15s %-4s PID:%-6d RET:%-4d (%s)" % (
        strftime("%H:%M:%S"),
        saddr,
        daddr,
        proto,
        event.pid,
        event.retval,
        error_name
    ))

def print_stats(b):
    """Print statistics summary"""
    stats = b["stats"]

    print("\n" + "=" * 70)
    print("Statistics Summary")
    print("=" * 70)

    stat_names = [
        (0, "Total calls"),
        (1, "Success (0)"),
        (2, "ENODEV (-19)"),
        (3, "ENOMEM (-12)"),
        (4, "EFBIG (-27)"),
        (5, "EINVAL (-22)"),
        (6, "EMSGSIZE (-90)"),
        (7, "ENOBUFS (-105)"),
        (8, "ENOTCONN (-107)"),
        (9, "ECONNREFUSED (-111)"),
        (10, "Other errors"),
    ]

    total = stats[0].value

    for idx, name in stat_names:
        val = stats[idx].value
        if val > 0 or idx == 0:
            if idx == 0:
                print("  %-25s: %d" % (name, val))
            else:
                pct = (val * 100.0 / total) if total > 0 else 0
                print("  %-25s: %d (%.1f%%)" % (name, val, pct))

    print("=" * 70)

def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Trace queue_userspace_packet return values",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Return value meanings:
  0           Success - upcall sent to userspace
  -ENODEV     Datapath interface index not found
  -ENOMEM     Memory allocation failed
  -EFBIG      SKB too large
  -EINVAL     genlmsg_put failed
  -EMSGSIZE   Netlink message too large
  -ENOBUFS    Netlink buffer full
  -ENOTCONN   Netlink socket not connected (no ovs-vswitchd?)
  -ECONNREFUSED  Connection refused

Examples:
  %(prog)s                              # Trace all calls
  %(prog)s --src-ip 192.168.1.100       # Filter by IP address
  %(prog)s --protocol icmp              # Filter ICMP only
  %(prog)s --filter-error               # Only show errors
"""
    )

    parser.add_argument('--src-ip', '-s', type=str, default=None,
                        help='Filter by source IP address (strict match)')
    parser.add_argument('--dst-ip', '-d', type=str, default=None,
                        help='Filter by destination IP address (strict match)')
    parser.add_argument('--protocol', '-p', type=str, default=None,
                        choices=['tcp', 'udp', 'icmp'],
                        help='Filter by protocol (tcp, udp, icmp)')
    parser.add_argument('--filter-error', '-e', action='store_true',
                        help='Only show error returns (retval != 0)')

    args = parser.parse_args()

    # Convert filters to integers
    src_ip_filter = ip_to_int(args.src_ip) if args.src_ip else 0
    dst_ip_filter = ip_to_int(args.dst_ip) if args.dst_ip else 0

    proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
    proto_filter = proto_map.get(args.protocol, 0) if args.protocol else 0

    # Replace placeholders in BPF code
    bpf_code = bpf_text.replace('__SRC_IP_FILTER__', str(src_ip_filter))
    bpf_code = bpf_code.replace('__DST_IP_FILTER__', str(dst_ip_filter))
    bpf_code = bpf_code.replace('__PROTOCOL_FILTER__', str(proto_filter))

    print("=== OVS queue_userspace_packet Return Value Tracer ===")
    print("Tracing queue_userspace_packet returns...")
    if args.src_ip:
        print("  Filter src-ip: %s" % args.src_ip)
    if args.dst_ip:
        print("  Filter dst-ip: %s" % args.dst_ip)
    if args.protocol:
        print("  Filter protocol: %s" % args.protocol)
    if args.filter_error:
        print("  Filter: Only showing errors (retval != 0)")
    print("Hit Ctrl-C to end.\n")

    # Load BPF program
    try:
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    # Attach probes
    func_name = "queue_userspace_packet"
    try:
        b.attach_kprobe(event=func_name, fn_name="trace_queue_userspace_packet_entry")
        b.attach_kretprobe(event=func_name, fn_name="trace_queue_userspace_packet_return")
        print("Attached kprobe/kretprobe to %s" % func_name)
    except Exception as e:
        print("Error: Cannot attach to %s: %s" % (func_name, e))
        print("Make sure openvswitch kernel module is loaded")
        sys.exit(1)

    print("\n%-10s %-17s %-17s %-4s %-10s %-6s %s" % (
        "TIME", "SRC", "DST", "PROT", "PID", "RET", "ERROR"))
    print("-" * 80)

    def event_callback(cpu, data, size):
        print_event(cpu, data, size, args.filter_error)

    b["events"].open_perf_buffer(event_callback)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    finally:
        print_stats(b)
        print("\nExiting...")

if __name__ == "__main__":
    main()
