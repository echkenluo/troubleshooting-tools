#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from socket import inet_ntop, AF_INET, inet_aton
from struct import pack, unpack
from time import strftime
import argparse
import sys

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
import ctypes as ct

def safe_str(obj):
    """Safely convert bytes or str to str for cross-platform compatibility"""
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')
    return str(obj)

def format_ip_address(ip_bytes):
    """Format IPv4 address from bytes"""
    return inet_ntop(AF_INET, pack("I", ip_bytes))

# Command line argument parsing
parser = argparse.ArgumentParser(
    description='Trace __dev_queue_xmit, dev_hard_start_xmit, erspan_xmit and fq_codel_enqueue for packet drop analysis'
)
parser.add_argument('--interface', type=str, help='Network interface filter (e.g., erspan_sys)')
parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('--interval', type=int, default=10, help='Statistics reporting interval in seconds')
parser.add_argument('--drops-only', action='store_true', help='Show only dropped packets (return code != 0)')
parser.add_argument('--summary', action='store_true', help='Show only summary statistics, no individual events')

args = parser.parse_args()

interface_filter = args.interface if args.interface else ""

print("Qdisc Drop Trace Monitor")
if interface_filter:
    print("Interface filter: {}".format(interface_filter))
print("Verbose mode: {}".format('ON' if args.verbose else 'OFF'))
print("Drops only mode: {}".format('ON' if args.drops_only else 'OFF'))
print("Summary only mode: {}".format('ON' if args.summary else 'OFF'))
print("Stats interval: {} seconds".format(args.interval))
print("-" * 80)

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <linux/netdevice.h>
#include <net/sch_generic.h>
#include <net/gen_stats.h>

#define IFNAMSIZ 16
#define TASK_COMM_LEN 16

// Interface name filtering structure
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

BPF_ARRAY(interface_map, union name_buf, 1);

// Statistics structures using histogram for better efficiency
BPF_HISTOGRAM(dev_xmit_hist, u32);
BPF_HISTOGRAM(dev_hard_start_xmit_hist, u32);
BPF_HISTOGRAM(erspan_xmit_hist, u32);
BPF_HISTOGRAM(fq_codel_hist, u32);

// Entry count statistics using histogram for high efficiency
BPF_HISTOGRAM(dev_xmit_entry_hist, u32);
BPF_HISTOGRAM(dev_hard_start_xmit_entry_hist, u32);
BPF_HISTOGRAM(erspan_xmit_entry_hist, u32);
BPF_HISTOGRAM(fq_codel_entry_hist, u32);

// No correlation map needed - we'll filter at entry and skip return events that can't get interface names

// Event data structure for __dev_queue_xmit
struct dev_xmit_event_t {
    u64 timestamp;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u32 skb_len;
    u32 ret_code;
    u32 src_ip;
    u32 dst_ip;
    u16 protocol;
    u8 event_type; // 0 = entry, 1 = return
};

// Event data structure for dev_hard_start_xmit
struct dev_hard_start_xmit_event_t {
    u64 timestamp;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u32 skb_len;
    u32 ret_code;
    u32 src_ip;
    u32 dst_ip;
    u16 protocol;
    u8 event_type; // 0 = entry, 1 = return
    u16 txq_queue_id;
};

// Event data structure for erspan_xmit
struct erspan_xmit_event_t {
    u64 timestamp;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u32 skb_len;
    u32 ret_code;
    u32 src_ip;
    u32 dst_ip;
    u16 protocol;
    u8 event_type; // 0 = entry, 1 = return
};

// Event data structure for fq_codel_enqueue
struct fq_codel_event_t {
    u64 timestamp;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u32 skb_len;
    u32 ret_code;
    u32 src_ip;
    u32 dst_ip;
    u16 protocol;
    u8 event_type; // 0 = entry, 1 = return
    
    // fq_codel specific fields
    u32 qdisc_flags;
    u32 qlen;
    u32 backlog;
    u32 drops;
    u32 requeues;
    u32 overlimits;
};

BPF_PERF_OUTPUT(dev_xmit_events);
BPF_PERF_OUTPUT(dev_hard_start_xmit_events);
BPF_PERF_OUTPUT(erspan_xmit_events);
BPF_PERF_OUTPUT(fq_codel_events);

// Configuration
#define INTERFACE_FILTER_ENABLED %d
#define SUMMARY_MODE_ENABLED %d

// Helper function to filter interface in kernel space (based on iface_netstat.c)
static inline bool interface_filter(struct sk_buff *skb, char *ifname_out) {
    if (!INTERFACE_FILTER_ENABLED) {
        // Still get device name for output even when no filtering
        struct net_device *dev;
        if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
            bpf_probe_read_str(ifname_out, IFNAMSIZ, dev->name);
        }
        return true;  // No interface filtering
    }
    
    // Get device name from skb (following iface_netstat.c pattern)
    union name_buf real_devname;
    struct net_device *dev;
    bpf_probe_read(&dev, sizeof(skb->dev), ((char *)skb + offsetof(struct sk_buff, dev)));
    bpf_probe_read(&real_devname, IFNAMSIZ, dev->name);
    
    // Copy device name for output
    #pragma unroll
    for (int i = 0; i < IFNAMSIZ; i++) {
        ifname_out[i] = real_devname.name[i];
        if (real_devname.name[i] == 0) break;
    }
    
    int key = 0;
    union name_buf *leaf = interface_map.lookup(&key);
    if (!leaf) {
        return false;
    }
    
    // Use the same comparison logic as iface_netstat.c
    if ((leaf->name_int).hi != real_devname.name_int.hi || 
        (leaf->name_int).lo != real_devname.name_int.lo) {
        return false;
    }
    
    return true;
}

// Helper to extract IP info from skb
static inline void extract_ip_info(struct sk_buff *skb, u32 *src_ip, u32 *dst_ip, u16 *protocol) {
    *src_ip = 0;
    *dst_ip = 0;
    *protocol = 0;
    
    struct ethhdr *eth;
    struct iphdr *ip;
    
    // Try to get ethernet header
    unsigned char *head;
    u16 mac_header;
    
    if (bpf_probe_read(&head, sizeof(head), &skb->head) != 0 || !head) {
        return;
    }
    
    if (bpf_probe_read(&mac_header, sizeof(mac_header), &skb->mac_header) != 0) {
        return;
    }
    
    if (mac_header == (u16)~0U) {
        return;
    }
    
    eth = (struct ethhdr *)(head + mac_header);
    struct ethhdr eth_hdr;
    if (bpf_probe_read(&eth_hdr, sizeof(eth_hdr), eth) != 0) {
        return;
    }
    
    *protocol = __builtin_bswap16(eth_hdr.h_proto);
    
    if (*protocol == 0x0800) { // IPv4
        ip = (struct iphdr *)((char *)eth + 14);
        struct iphdr ip_hdr;
        if (bpf_probe_read(&ip_hdr, sizeof(ip_hdr), ip) == 0) {
            *src_ip = ip_hdr.saddr;
            *dst_ip = ip_hdr.daddr;
        }
    }
}

// Helper to get interface name (simplified since we now get it in interface_filter)
static inline void get_ifname(struct sk_buff *skb, char *ifname) {
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_str(ifname, IFNAMSIZ, dev->name);
    }
}

// Probe for __dev_queue_xmit entry
int trace_dev_queue_xmit_entry(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (skb == NULL) return 0;
    
    struct dev_xmit_event_t data = {};
    
    // Apply interface filter and get device name
    if (!interface_filter(skb, data.ifname)) {
        return 0;
    }
    
    // Increment entry count histogram for filtered successful entries
    dev_xmit_entry_hist.increment(1);
    
    data.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 0; // entry
    
    // No need to store call info since filtering is done at entry
    
    // Get SKB info
    u32 skb_len;
    if (bpf_probe_read(&skb_len, sizeof(skb_len), &skb->len) == 0) {
        data.skb_len = skb_len;
    }
    
    // Extract network info
    extract_ip_info(skb, &data.src_ip, &data.dst_ip, &data.protocol);
    
    // Only submit events if not in summary mode
    if (!SUMMARY_MODE_ENABLED) {
        dev_xmit_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Probe for __dev_queue_xmit return
int trace_dev_queue_xmit_return(struct pt_regs *ctx) {
    u32 ret_code = PT_REGS_RC(ctx);
    
    // Update histogram statistics only - much more efficient than submitting events
    dev_xmit_hist.increment(ret_code);
    
    return 0;
}

// Probe for fq_codel_enqueue entry
int trace_fq_codel_enqueue_entry(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct Qdisc *sch = (struct Qdisc *)PT_REGS_PARM2(ctx);
    
    if (skb == NULL || sch == NULL) return 0;
    
    struct fq_codel_event_t data = {};
    
    // Apply interface filter and get device name
    if (!interface_filter(skb, data.ifname)) {
        return 0;
    }
    
    // Increment entry count histogram for filtered successful entries
    fq_codel_entry_hist.increment(1);
    
    data.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 0; // entry
    
    // Get SKB info
    u32 skb_len;
    if (bpf_probe_read(&skb_len, sizeof(skb_len), &skb->len) == 0) {
        data.skb_len = skb_len;
    }
    
    // Extract network info
    extract_ip_info(skb, &data.src_ip, &data.dst_ip, &data.protocol);
    
    // Get qdisc information
    u32 flags;
    if (bpf_probe_read(&flags, sizeof(flags), &sch->flags) == 0) {
        data.qdisc_flags = flags;
    }
    
    // Get qdisc statistics
    struct gnet_stats_queue qstats;
    if (bpf_probe_read(&qstats, sizeof(qstats), &sch->qstats) == 0) {
        data.qlen = qstats.qlen;
        data.backlog = qstats.backlog;
        data.drops = qstats.drops;
        data.requeues = qstats.requeues;
        data.overlimits = qstats.overlimits;
    }
    
    // Only submit events if not in summary mode
    if (!SUMMARY_MODE_ENABLED) {
        fq_codel_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Probe for fq_codel_enqueue return
int trace_fq_codel_enqueue_return(struct pt_regs *ctx) {
    u32 ret_code = PT_REGS_RC(ctx);
    
    // Update histogram statistics only - much more efficient than submitting events
    fq_codel_hist.increment(ret_code);
    
    return 0;
}

// Probe for dev_hard_start_xmit entry
int trace_dev_hard_start_xmit_entry(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct netdev_queue *txq = (struct netdev_queue *)PT_REGS_PARM2(ctx);
    if (skb == NULL) return 0;
    
    struct dev_hard_start_xmit_event_t data = {};
    
    // Apply interface filter and get device name
    if (!interface_filter(skb, data.ifname)) {
        return 0;
    }
    
    // Increment entry count histogram for filtered successful entries
    dev_hard_start_xmit_entry_hist.increment(1);
    
    data.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 0; // entry
    
    // Get SKB info
    u32 skb_len;
    if (bpf_probe_read(&skb_len, sizeof(skb_len), &skb->len) == 0) {
        data.skb_len = skb_len;
    }
    
    // Get queue_mapping from skb instead of txq
    u16 queue_mapping;
    if (bpf_probe_read(&queue_mapping, sizeof(queue_mapping), &skb->queue_mapping) == 0) {
        data.txq_queue_id = queue_mapping;
    }
    
    // Extract network info
    extract_ip_info(skb, &data.src_ip, &data.dst_ip, &data.protocol);
    
    // Only submit events if not in summary mode
    if (!SUMMARY_MODE_ENABLED) {
        dev_hard_start_xmit_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Probe for dev_hard_start_xmit return
int trace_dev_hard_start_xmit_return(struct pt_regs *ctx) {
    u32 ret_code = PT_REGS_RC(ctx);
    
    // Update histogram statistics only - much more efficient than submitting events
    dev_hard_start_xmit_hist.increment(ret_code);
    
    return 0;
}

// Probe for erspan_xmit entry
int trace_erspan_xmit_entry(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (skb == NULL) return 0;
    
    struct erspan_xmit_event_t data = {};
    
    // Apply interface filter and get device name
    if (!interface_filter(skb, data.ifname)) {
        return 0;
    }
    
    // Increment entry count histogram for filtered successful entries
    erspan_xmit_entry_hist.increment(1);
    
    data.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.event_type = 0; // entry
    
    // Get SKB info
    u32 skb_len;
    if (bpf_probe_read(&skb_len, sizeof(skb_len), &skb->len) == 0) {
        data.skb_len = skb_len;
    }
    
    // Extract network info
    extract_ip_info(skb, &data.src_ip, &data.dst_ip, &data.protocol);
    
    // Only submit events if not in summary mode
    if (!SUMMARY_MODE_ENABLED) {
        erspan_xmit_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// Probe for erspan_xmit return
int trace_erspan_xmit_return(struct pt_regs *ctx) {
    u32 ret_code = PT_REGS_RC(ctx);
    
    // Update histogram statistics only - much more efficient than submitting events
    erspan_xmit_hist.increment(ret_code);
    
    return 0;
}
"""

# Format the BPF program with our constants
interface_filter_enabled = 1 if interface_filter else 0
summary_mode_enabled = 1 if args.summary else 0

b = BPF(text=bpf_text % (interface_filter_enabled, summary_mode_enabled))

if interface_filter:
    # Create interface name buffer structure
    class InterfaceName(ct.Structure):
        _fields_ = [("name", ct.c_char * 16)]
    
    interface_map = b.get_table("interface_map")
    target_name = InterfaceName()
    # Python 2/3 compatible string encoding
    if sys.version_info[0] == 2:
        # Python 2
        try:
            if isinstance(interface_filter, unicode):
                target_name.name = interface_filter.encode('utf-8')
            else:
                target_name.name = str(interface_filter)
        except NameError:
            target_name.name = str(interface_filter)
    else:
        # Python 3
        if isinstance(interface_filter, str):
            target_name.name = interface_filter.encode('utf-8')
        else:
            target_name.name = str(interface_filter).encode('utf-8')
    interface_map[0] = target_name

# Attach probes with optional function support
attached_probes = []

def attach_probe_pair(event, entry_fn, return_fn):
    """Attach kprobe/kretprobe pair, return True if successful"""
    try:
        b.attach_kprobe(event=event, fn_name=entry_fn)
        b.attach_kretprobe(event=event, fn_name=return_fn)
        attached_probes.append(event)
        return True
    except Exception as e:
        print("Warning: {} not available on this kernel, skipping".format(event))
        return False

# Core probes (should exist on all kernels)
attach_probe_pair("__dev_queue_xmit", "trace_dev_queue_xmit_entry", "trace_dev_queue_xmit_return")
attach_probe_pair("dev_hard_start_xmit", "trace_dev_hard_start_xmit_entry", "trace_dev_hard_start_xmit_return")

# Optional probes (may not exist on all kernels)
erspan_attached = attach_probe_pair("erspan_xmit", "trace_erspan_xmit_entry", "trace_erspan_xmit_return")
fq_codel_attached = attach_probe_pair("fq_codel_enqueue", "trace_fq_codel_enqueue_entry", "trace_fq_codel_enqueue_return")

print("Attached probes: {}".format(", ".join(attached_probes)))

# Define ctypes structures
class DevXmitEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("ifname", ct.c_char * 16),
        ("skb_len", ct.c_uint32),
        ("ret_code", ct.c_uint32),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("protocol", ct.c_uint16),
        ("event_type", ct.c_uint8),
    ]

class DevHardStartXmitEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("ifname", ct.c_char * 16),
        ("skb_len", ct.c_uint32),
        ("ret_code", ct.c_uint32),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("protocol", ct.c_uint16),
        ("event_type", ct.c_uint8),
        ("txq_queue_id", ct.c_uint16),
    ]

class ErspanXmitEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("ifname", ct.c_char * 16),
        ("skb_len", ct.c_uint32),
        ("ret_code", ct.c_uint32),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("protocol", ct.c_uint16),
        ("event_type", ct.c_uint8),
    ]

class FqCodelEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("ifname", ct.c_char * 16),
        ("skb_len", ct.c_uint32),
        ("ret_code", ct.c_uint32),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("protocol", ct.c_uint16),
        ("event_type", ct.c_uint8),
        ("qdisc_flags", ct.c_uint32),
        ("qlen", ct.c_uint32),
        ("backlog", ct.c_uint32),
        ("drops", ct.c_uint32),
        ("requeues", ct.c_uint32),
        ("overlimits", ct.c_uint32),
    ]

# Event handlers
def print_dev_xmit_event(cpu, data, size):
    """Print __dev_queue_xmit event"""
    event = ct.cast(data, ct.POINTER(DevXmitEvent)).contents
    
    # Skip if summary mode is enabled
    if args.summary:
        return
    
    # Skip if drops-only mode and this is a success
    if args.drops_only and event.ret_code == 0:
        return
    
    timestamp = strftime("%H:%M:%S")
    event_type_str = "ENTRY" if event.event_type == 0 else "RETURN"
    
    # Only entry events are submitted now, no return events
    if not args.drops_only:  # Only show entry if not in drops-only mode
        print("[{}] __dev_queue_xmit {} - DEV: {} PID: {} COMM: {} LEN: {}".format(
            timestamp, event_type_str, safe_str(event.ifname), event.pid, safe_str(event.comm), event.skb_len))
        
        if event.src_ip != 0 and event.dst_ip != 0:
            print("  IP: {} -> {} PROTO: 0x{:04x}".format(
                format_ip_address(event.src_ip), format_ip_address(event.dst_ip), event.protocol))

def print_dev_hard_start_xmit_event(cpu, data, size):
    """Print dev_hard_start_xmit event"""
    event = ct.cast(data, ct.POINTER(DevHardStartXmitEvent)).contents
    
    # Skip if summary mode is enabled
    if args.summary:
        return
    
    # Skip if drops-only mode and this is a success
    if args.drops_only and event.ret_code == 0:
        return
    
    timestamp = strftime("%H:%M:%S")
    event_type_str = "ENTRY" if event.event_type == 0 else "RETURN"
    
    # Only entry events are submitted now, no return events
    if not args.drops_only:  # Only show entry if not in drops-only mode
        print("[{}] dev_hard_start_xmit {} - DEV: {} PID: {} COMM: {} LEN: {} TXQ: {}".format(
            timestamp, event_type_str, safe_str(event.ifname), event.pid, safe_str(event.comm), event.skb_len, event.txq_queue_id))
        
        if event.src_ip != 0 and event.dst_ip != 0:
            print("  IP: {} -> {} PROTO: 0x{:04x}".format(
                format_ip_address(event.src_ip), format_ip_address(event.dst_ip), event.protocol))

def print_erspan_xmit_event(cpu, data, size):
    """Print erspan_xmit event"""
    event = ct.cast(data, ct.POINTER(ErspanXmitEvent)).contents
    
    # Skip if summary mode is enabled
    if args.summary:
        return
    
    # Skip if drops-only mode and this is a success
    if args.drops_only and event.ret_code == 0:
        return
    
    timestamp = strftime("%H:%M:%S")
    event_type_str = "ENTRY" if event.event_type == 0 else "RETURN"
    
    # Only entry events are submitted now, no return events
    if not args.drops_only:  # Only show entry if not in drops-only mode
        print("[{}] erspan_xmit {} - DEV: {} PID: {} COMM: {} LEN: {}".format(
            timestamp, event_type_str, safe_str(event.ifname), event.pid, safe_str(event.comm), event.skb_len))
        
        if event.src_ip != 0 and event.dst_ip != 0:
            print("  IP: {} -> {} PROTO: 0x{:04x}".format(
                format_ip_address(event.src_ip), format_ip_address(event.dst_ip), event.protocol))

def print_fq_codel_event(cpu, data, size):
    """Print fq_codel_enqueue event"""
    event = ct.cast(data, ct.POINTER(FqCodelEvent)).contents
    
    # Skip if summary mode is enabled
    if args.summary:
        return
    
    # Skip if drops-only mode and this is a success
    if args.drops_only and event.ret_code == 0:
        return
    
    timestamp = strftime("%H:%M:%S")
    event_type_str = "ENTRY" if event.event_type == 0 else "RETURN"
    
    # Only entry events are submitted now, no return events
    if not args.drops_only:  # Only show entry if not in drops-only mode
        print("[{}] fq_codel_enqueue {} - DEV: {} PID: {} COMM: {} LEN: {}".format(
            timestamp, event_type_str, safe_str(event.ifname), event.pid, safe_str(event.comm), event.skb_len))
        
        if event.src_ip != 0 and event.dst_ip != 0:
            print("  IP: {} -> {} PROTO: 0x{:04x}".format(
                format_ip_address(event.src_ip), format_ip_address(event.dst_ip), event.protocol))
        
        print("  QDISC FLAGS: 0x{:08x} QLEN: {} BACKLOG: {} DROPS: {} REQUEUES: {} OVERLIMITS: {}".format(
            event.qdisc_flags, event.qlen, event.backlog, event.drops, event.requeues, event.overlimits))

# Register callbacks
b["dev_xmit_events"].open_perf_buffer(print_dev_xmit_event)
b["dev_hard_start_xmit_events"].open_perf_buffer(print_dev_hard_start_xmit_event)
if erspan_attached:
    b["erspan_xmit_events"].open_perf_buffer(print_erspan_xmit_event)
if fq_codel_attached:
    b["fq_codel_events"].open_perf_buffer(print_fq_codel_event)

# Previous statistics for delta calculation
prev_dev_xmit_stats = {}
prev_dev_hard_start_xmit_stats = {}
prev_erspan_xmit_stats = {}
prev_fq_codel_stats = {}

# Previous entry statistics for delta calculation
prev_dev_xmit_entry_stats = {}
prev_dev_hard_start_xmit_entry_stats = {}
prev_erspan_xmit_entry_stats = {}
prev_fq_codel_entry_stats = {}

# Statistics reporting function
def print_statistics():
    """Print return code and entry count statistics from histograms (delta values)"""
    global prev_dev_xmit_stats, prev_dev_hard_start_xmit_stats, prev_erspan_xmit_stats, prev_fq_codel_stats
    global prev_dev_xmit_entry_stats, prev_dev_hard_start_xmit_entry_stats, prev_erspan_xmit_entry_stats, prev_fq_codel_entry_stats
    
    print("\n" + "=" * 70)
    print("STATISTICS SUMMARY (per interval)")
    print("=" * 70)
    
    # Print __dev_queue_xmit statistics
    print("__dev_queue_xmit return codes:")
    dev_xmit_hist = b.get_table("dev_xmit_hist")
    current_dev_xmit = {}
    
    for k, v in dev_xmit_hist.items():
        current_dev_xmit[k.value] = v.value
        prev_count = prev_dev_xmit_stats.get(k.value, 0)
        delta = v.value - prev_count
        
        ret_meaning = {
            0: "NET_XMIT_SUCCESS", 
            1: "NET_XMIT_DROP", 
            2: "NET_XMIT_CN",
            3: "NET_XMIT_POLICED"
        }.get(k.value, "UNKNOWN")
        
        if delta > 0:
            print("  {}: {} ({})".format(k.value, delta, ret_meaning))
    
    prev_dev_xmit_stats = current_dev_xmit
    
    # Print dev_hard_start_xmit statistics
    print("dev_hard_start_xmit return codes:")
    dev_hard_start_xmit_hist = b.get_table("dev_hard_start_xmit_hist")
    current_dev_hard_start_xmit = {}
    
    for k, v in dev_hard_start_xmit_hist.items():
        current_dev_hard_start_xmit[k.value] = v.value
        prev_count = prev_dev_hard_start_xmit_stats.get(k.value, 0)
        delta = v.value - prev_count
        
        ret_meaning = {
            0: "NET_XMIT_SUCCESS", 
            1: "NET_XMIT_DROP", 
            2: "NET_XMIT_CN",
            3: "NET_XMIT_POLICED"
        }.get(k.value, "UNKNOWN")
        
        if delta > 0:
            print("  {}: {} ({})".format(k.value, delta, ret_meaning))
    
    prev_dev_hard_start_xmit_stats = current_dev_hard_start_xmit
    
    # Print erspan_xmit statistics (only if probe attached)
    if erspan_attached:
        print("erspan_xmit return codes:")
        erspan_xmit_hist = b.get_table("erspan_xmit_hist")
        current_erspan_xmit = {}

        for k, v in erspan_xmit_hist.items():
            current_erspan_xmit[k.value] = v.value
            prev_count = prev_erspan_xmit_stats.get(k.value, 0)
            delta = v.value - prev_count

            ret_meaning = {
                0: "NET_XMIT_SUCCESS",
                1: "NET_XMIT_DROP",
                2: "NET_XMIT_CN",
                3: "NET_XMIT_POLICED"
            }.get(k.value, "UNKNOWN")

            if delta > 0:
                print("  {}: {} ({})".format(k.value, delta, ret_meaning))

        prev_erspan_xmit_stats = current_erspan_xmit

    # Print fq_codel_enqueue statistics (only if probe attached)
    if fq_codel_attached:
        print("fq_codel_enqueue return codes:")
        fq_codel_hist = b.get_table("fq_codel_hist")
        current_fq_codel = {}

        for k, v in fq_codel_hist.items():
            current_fq_codel[k.value] = v.value
            prev_count = prev_fq_codel_stats.get(k.value, 0)
            delta = v.value - prev_count

            ret_meaning = {
                0: "NET_XMIT_SUCCESS",
                1: "NET_XMIT_DROP",
                2: "NET_XMIT_CN",
                3: "NET_XMIT_POLICED"
            }.get(k.value, "UNKNOWN")

            if delta > 0:
                print("  {}: {} ({})".format(k.value, delta, ret_meaning))

        prev_fq_codel_stats = current_fq_codel
    
    # Print entry count statistics
    print("\nEntry count statistics (filtered entries):")
    
    # __dev_queue_xmit entries
    dev_xmit_entry_hist = b.get_table("dev_xmit_entry_hist")
    current_dev_xmit_entry = {}
    dev_xmit_entry_total = 0
    for k, v in dev_xmit_entry_hist.items():
        current_dev_xmit_entry[k.value] = v.value
        prev_count = prev_dev_xmit_entry_stats.get(k.value, 0)
        delta = v.value - prev_count
        dev_xmit_entry_total += delta
    prev_dev_xmit_entry_stats = current_dev_xmit_entry
    if dev_xmit_entry_total > 0:
        print("  __dev_queue_xmit entries: {}".format(dev_xmit_entry_total))
    
    # dev_hard_start_xmit entries
    dev_hard_start_xmit_entry_hist = b.get_table("dev_hard_start_xmit_entry_hist")
    current_dev_hard_start_xmit_entry = {}
    dev_hard_start_xmit_entry_total = 0
    for k, v in dev_hard_start_xmit_entry_hist.items():
        current_dev_hard_start_xmit_entry[k.value] = v.value
        prev_count = prev_dev_hard_start_xmit_entry_stats.get(k.value, 0)
        delta = v.value - prev_count
        dev_hard_start_xmit_entry_total += delta
    prev_dev_hard_start_xmit_entry_stats = current_dev_hard_start_xmit_entry
    if dev_hard_start_xmit_entry_total > 0:
        print("  dev_hard_start_xmit entries: {}".format(dev_hard_start_xmit_entry_total))
    
    # erspan_xmit entries (only if probe attached)
    if erspan_attached:
        erspan_xmit_entry_hist = b.get_table("erspan_xmit_entry_hist")
        current_erspan_xmit_entry = {}
        erspan_xmit_entry_total = 0
        for k, v in erspan_xmit_entry_hist.items():
            current_erspan_xmit_entry[k.value] = v.value
            prev_count = prev_erspan_xmit_entry_stats.get(k.value, 0)
            delta = v.value - prev_count
            erspan_xmit_entry_total += delta
        prev_erspan_xmit_entry_stats = current_erspan_xmit_entry
        if erspan_xmit_entry_total > 0:
            print("  erspan_xmit entries: {}".format(erspan_xmit_entry_total))

    # fq_codel_enqueue entries (only if probe attached)
    if fq_codel_attached:
        fq_codel_entry_hist = b.get_table("fq_codel_entry_hist")
        current_fq_codel_entry = {}
        fq_codel_entry_total = 0
        for k, v in fq_codel_entry_hist.items():
            current_fq_codel_entry[k.value] = v.value
            prev_count = prev_fq_codel_entry_stats.get(k.value, 0)
            delta = v.value - prev_count
            fq_codel_entry_total += delta
        prev_fq_codel_entry_stats = current_fq_codel_entry
        if fq_codel_entry_total > 0:
            print("  fq_codel_enqueue entries: {}".format(fq_codel_entry_total))
    
    print("=" * 70)

print("Starting qdisc drop monitoring... Press Ctrl+C to stop")

# Main event loop
import time
last_stats_time = time.time()

try:
    while True:
        b.perf_buffer_poll(timeout=1000)  # 1 second timeout
        
        # Print statistics periodically
        current_time = time.time()
        if current_time - last_stats_time >= args.interval:
            print_statistics()
            last_stats_time = current_time
            
except KeyboardInterrupt:
    print("\nStopping qdisc drop monitoring...")
    print_statistics()
    sys.exit(0)