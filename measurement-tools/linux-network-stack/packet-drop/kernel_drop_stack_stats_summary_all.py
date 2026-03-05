#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
kfree_skb Stack Statistics with Five-Tuple Histogram - Track kernel packet drop locations with five-tuple granularity

This BCC program tracks kfree_skb calls and collects stack trace statistics
using BPF histograms with five-tuple + device name as the key to identify
where packets are being dropped in the kernel with detailed flow information.

Usage: sudo python3 kernel_drop_stack_stats_fivetuple.py [-i INTERVAL] [-d DURATION] [-t TOP] [-n DEV] [--src IP] [--dst IP] [--src-port PORT] [--dst-port PORT] [--l4-protocol PROTO] [--max-entries NUM]
       -i INTERVAL: reporting interval in seconds (default: 10)
                    Statistics are cleared at each interval (shows delta per interval)
       -d DURATION: total duration in seconds (default: unlimited)
       -t TOP: number of top stacks to show (default: 5)
       -n DEV: filter by device name (e.g., eth0, br-int)
       --src IP: filter by source IP address
       --dst IP: filter by destination IP address
       --src-port PORT: filter by source port (TCP/UDP)
       --dst-port PORT: filter by destination port (TCP/UDP)
       --l4-protocol PROTO: filter by L4 protocol (tcp/udp/icmp/all, default: all)
       --max-entries NUM: maximum histogram entries (default: 10240)
       --group-by: grouping mode (stack/fivetuple/all, default: all)

Examples:
  sudo python3 kernel_drop_stack_stats_summary_all.py -i 5 -d 60 -n eth0
  sudo python3 kernel_drop_stack_stats_summary_all.py -t 10 -n br-int --src 192.168.1.10 --dst-port 80
  sudo python3 kernel_drop_stack_stats_summary_all.py --l4-protocol tcp --src-port 22 --group-by fivetuple

"""

from __future__ import print_function
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

import signal
import sys
import argparse
from ctypes import *
from time import sleep, strftime, time
from socket import inet_aton, inet_ntoa
from struct import unpack, pack

# BPF program
bpf_text = """
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/netdevice.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/if_ether.h>

#if IFNAMSIZ != 16
#error "IFNAMSIZ != 16 is not supported"
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

// Use custom VLAN header structure to avoid conflicts
struct custom_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// Configuration constants for five-tuple filtering
#define SRC_IP 0x%x
#define DST_IP 0x%x
#define SRC_PORT %d
#define DST_PORT %d
#define L4_PROTOCOL %d
#define MAX_ENTRIES %d

union name_buf{
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    }name_int;
};

// Five-tuple structure
struct five_tuple {
    u32 saddr;    // Source IP
    u32 daddr;    // Destination IP
    u16 sport;    // Source port
    u16 dport;    // Destination port
    u8  protocol; // L4 protocol (TCP/UDP/ICMP)
    u8  _pad[3];  // Padding for alignment
};

// Enhanced histogram key combining stack_id, device name, and five-tuple
struct hist_key {
    int stack_id;
    char devname[IFNAMSIZ];
    struct five_tuple tuple;
};

// Simplified key for stack-only grouping
struct stack_key {
    int stack_id;
    char devname[IFNAMSIZ];
};

// Simplified key for five-tuple-only grouping
struct tuple_key {
    char devname[IFNAMSIZ];
    struct five_tuple tuple;
};

BPF_STACK_TRACE(stack_traces, 1024);
BPF_HISTOGRAM(drop_hist, struct hist_key, MAX_ENTRIES);     // Main histogram for stack+device+fivetuple
BPF_HISTOGRAM(stack_hist, struct stack_key, MAX_ENTRIES);   // Histogram grouped by stack only
BPF_HISTOGRAM(tuple_hist, struct tuple_key, MAX_ENTRIES);   // Histogram grouped by five-tuple only
BPF_HISTOGRAM(failed_hist, union name_buf);                 // Histogram for failed stack traces
BPF_ARRAY(name_map, union name_buf, 1);

static inline int name_filter(struct sk_buff* skb){
    // Check if filtering is enabled
    int key = 0;
    union name_buf *leaf = name_map.lookup(&key);
    if (!leaf) {
        return 1; // No filter set, allow all
    }

    // Check if filter name is empty (all zeros)
    if (leaf->name_int.hi == 0 && leaf->name_int.lo == 0) {
        return 1; // Empty filter, allow all
    }

    // Get device name from skb
    union name_buf real_devname;
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) != 0 || !dev) {
        return 0;
    }
    if (bpf_probe_read(&real_devname, IFNAMSIZ, dev->name) != 0) {
        return 0;
    }

    // Compare device names
    if ((leaf->name_int).hi != real_devname.name_int.hi ||
        (leaf->name_int).lo != real_devname.name_int.lo) {
        return 0;
    }

    return 1;
}

static inline int extract_five_tuple(struct sk_buff* skb, struct five_tuple *tuple) {
    // Initialize tuple
    tuple->saddr = 0;
    tuple->daddr = 0;
    tuple->sport = 0;
    tuple->dport = 0;
    tuple->protocol = 0;

    // Try to get ethernet header using skb_mac_header if available
    unsigned char *mac_header_ptr = NULL;
    u16 mac_header;
    if (bpf_probe_read(&mac_header, sizeof(mac_header), &skb->mac_header) == 0) {
        if (mac_header != (u16)~0U) {
            // mac_header is valid, use it
            unsigned char *skb_head;
            if (bpf_probe_read(&skb_head, sizeof(skb_head), &skb->head) == 0 && skb_head) {
                mac_header_ptr = skb_head + mac_header;
            }
        }
    }

    // If mac_header approach failed, try using skb->data approach
    if (mac_header_ptr == NULL) {
        unsigned char *skb_data;
        if (bpf_probe_read(&skb_data, sizeof(skb_data), &skb->data) == 0 && skb_data) {
            mac_header_ptr = skb_data;
        }
    }

    if (mac_header_ptr == NULL) {
        return 0; // Can't find ethernet header
    }

    // Read Ethernet header
    struct ethhdr eth;
    if (bpf_probe_read(&eth, sizeof(eth), mac_header_ptr) < 0) {
        return 0;
    }

    u16 eth_type = ntohs(eth.h_proto);
    unsigned char *network_header_ptr = mac_header_ptr + ETH_HLEN;
    u16 real_protocol = eth_type;

    // Handle VLAN - check if ethertype indicates VLAN
    if (eth_type == ETH_P_8021Q) {
        // This is a VLAN packet
        struct custom_vlan_hdr vlan;
        if (bpf_probe_read(&vlan, sizeof(vlan), network_header_ptr) == 0) {
            real_protocol = ntohs(vlan.h_vlan_encapsulated_proto);
            network_header_ptr += 4; // Skip VLAN header

            // Check for double VLAN (QinQ)
            if (real_protocol == ETH_P_8021Q) {
                struct custom_vlan_hdr inner_vlan;
                if (bpf_probe_read(&inner_vlan, sizeof(inner_vlan), network_header_ptr) == 0) {
                    real_protocol = ntohs(inner_vlan.h_vlan_encapsulated_proto);
                    network_header_ptr += 4; // Skip inner VLAN header
                }
            }
        }
    }

    // Only process IPv4 packets
    if (real_protocol != ETH_P_IP) {
        return 0; // Not IPv4
    }

    // Parse IPv4 header
    struct iphdr iph;
    if (bpf_probe_read(&iph, sizeof(iph), network_header_ptr) < 0) {
        return 0;
    }

    // Extract IP addresses and protocol
    tuple->saddr = iph.saddr;
    tuple->daddr = iph.daddr;
    tuple->protocol = iph.protocol;

    // Extract ports for TCP/UDP
    if (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) {
        u8 ip_ihl = iph.ihl & 0x0F;
        unsigned char *transport_header_ptr = network_header_ptr + (ip_ihl * 4);

        if (iph.protocol == IPPROTO_TCP) {
            struct tcphdr tcph;
            if (bpf_probe_read(&tcph, sizeof(tcph), transport_header_ptr) == 0) {
                tuple->sport = ntohs(tcph.source);
                tuple->dport = ntohs(tcph.dest);
            }
        } else if (iph.protocol == IPPROTO_UDP) {
            struct udphdr udph;
            if (bpf_probe_read(&udph, sizeof(udph), transport_header_ptr) == 0) {
                tuple->sport = ntohs(udph.source);
                tuple->dport = ntohs(udph.dest);
            }
        }
    }

    return 1;
}

static inline int five_tuple_filter(struct five_tuple *tuple) {
    // If no five-tuple filters are set, allow all
    if (SRC_IP == 0 && DST_IP == 0 && SRC_PORT == 0 && DST_PORT == 0 && L4_PROTOCOL == 0) {
        return 1;
    }

    // Check L4 protocol filter
    if (L4_PROTOCOL != 0 && tuple->protocol != L4_PROTOCOL) {
        return 0;
    }

    // Check IP address filters
    if ((SRC_IP != 0 && tuple->saddr != SRC_IP) ||
        (DST_IP != 0 && tuple->daddr != DST_IP)) {
        return 0;
    }

    // Check port filters
    if ((SRC_PORT != 0 && tuple->sport != SRC_PORT) ||
        (DST_PORT != 0 && tuple->dport != DST_PORT)) {
        return 0;
    }

    return 1;
}

int trace_kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    // Apply device name filter
    if (!name_filter(skb)) {
        return 0;
    }

    // Get device name
    union name_buf devname = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) != 0 || !dev) {
        return 0;
    }
    if (bpf_probe_read(&devname, IFNAMSIZ, dev->name) != 0) {
        return 0;
    }

    // Extract five-tuple
    struct five_tuple tuple = {};
    extract_five_tuple(skb, &tuple);

    // Apply five-tuple filter
    if (!five_tuple_filter(&tuple)) {
        return 0;
    }

    // Get stack trace
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    if (stack_id >= 0) {
        // Success: increment histograms

        // 1. Full histogram (stack + device + five-tuple)
        struct hist_key key = {};
        key.stack_id = stack_id;
        #pragma unroll
        for (int i = 0; i < IFNAMSIZ; i++) {
            key.devname[i] = devname.name[i];
        }
        key.tuple = tuple;
        drop_hist.increment(key);

        // 2. Stack-only histogram
        struct stack_key skey = {};
        skey.stack_id = stack_id;
        #pragma unroll
        for (int i = 0; i < IFNAMSIZ; i++) {
            skey.devname[i] = devname.name[i];
        }
        stack_hist.increment(skey);

        // 3. Five-tuple-only histogram
        struct tuple_key tkey = {};
        #pragma unroll
        for (int i = 0; i < IFNAMSIZ; i++) {
            tkey.devname[i] = devname.name[i];
        }
        tkey.tuple = tuple;
        tuple_hist.increment(tkey);
    } else {
        // Failed: increment failed histogram by device
        failed_hist.increment(devname);
    }

    return 0;
}
"""

# Signal handler for graceful exit
exiting = False

def signal_handler(signal, frame):
    global exiting
    exiting = True

def format_five_tuple(tuple_data):
    """Format five-tuple information for display"""
    protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

    src_ip = inet_ntoa(pack('I', tuple_data.saddr))
    dst_ip = inet_ntoa(pack('I', tuple_data.daddr))
    protocol = protocol_map.get(tuple_data.protocol, str(tuple_data.protocol))

    if tuple_data.protocol in [6, 17]:  # TCP or UDP
        return "%s:%d -> %s:%d (%s)" % (src_ip, tuple_data.sport,
                                         dst_ip, tuple_data.dport, protocol)
    else:
        return "%s -> %s (%s)" % (src_ip, dst_ip, protocol)

def print_histogram_stats(b, top_n=5, group_by='all'):
    """Print current histogram statistics"""
    failed_hist = b["failed_hist"]
    stack_traces = b["stack_traces"]

    # Print failed stacks if any
    if len(failed_hist) > 0:
        print("\n  Stack trace failures by device:")
        for devname, count in failed_hist.items():
            devname_str = devname.name.decode('utf-8', 'replace').rstrip('\x00') if isinstance(devname.name, bytes) else str(devname.name).rstrip('\x00')
            print("    %s: %d failed" % (devname_str, count.value))

    if group_by == 'stack':
        # Group by stack only
        stack_hist = b["stack_hist"]
        if len(stack_hist) == 0:
            print("  No stack traces collected.")
            return

        sorted_hist = sorted(stack_hist.items(), key=lambda x: x[1].value, reverse=True)
        print("  Found %d unique stacks, showing top %d:" % (len(sorted_hist), min(top_n, len(sorted_hist))))

        for i, (key, count) in enumerate(sorted_hist[:top_n]):
            devname_str = key.devname.decode('utf-8', 'replace').rstrip('\x00') if isinstance(key.devname, bytes) else str(key.devname).rstrip('\x00')
            print("\n  #%d Count: %d calls [device: %s] [stack_id: %d]" %
                  (i+1, count.value, devname_str, key.stack_id))
            print("  Stack trace:")

            try:
                stack = list(stack_traces.walk(key.stack_id))
                print("    Stack depth: %d frames" % len(stack))
                for j, addr in enumerate(stack[:5]):  # Show top 5 frames
                    sym = b.sym(addr, -1, show_module=True, show_offset=True)
                    sym_str = sym.decode('utf-8', 'replace') if isinstance(sym, bytes) else str(sym)
                    print("    %s" % sym_str)
                if len(stack) > 5:
                    print("    ... (%d more frames)" % (len(stack) - 5))
            except Exception as e:
                print("    [Error reading stack: %s]" % e)

    elif group_by == 'fivetuple':
        # Group by five-tuple only
        tuple_hist = b["tuple_hist"]
        if len(tuple_hist) == 0:
            print("  No five-tuple data collected.")
            return

        sorted_hist = sorted(tuple_hist.items(), key=lambda x: x[1].value, reverse=True)
        print("  Found %d unique five-tuples, showing top %d:" % (len(sorted_hist), min(top_n, len(sorted_hist))))

        for i, (key, count) in enumerate(sorted_hist[:top_n]):
            devname_str = key.devname.decode('utf-8', 'replace').rstrip('\x00') if isinstance(key.devname, bytes) else str(key.devname).rstrip('\x00')
            tuple_str = format_five_tuple(key.tuple)
            print("\n  #%d Count: %d calls [device: %s]" % (i+1, count.value, devname_str))
            print("     Flow: %s" % tuple_str)

    else:  # group_by == 'all'
        # Full detail with stack + five-tuple
        drop_hist = b["drop_hist"]
        if len(drop_hist) == 0:
            print("  No data collected.")
            return

        sorted_hist = sorted(drop_hist.items(), key=lambda x: x[1].value, reverse=True)
        print("  Found %d unique stack+flow combinations, showing top %d:" % (len(sorted_hist), min(top_n, len(sorted_hist))))

        for i, (key, count) in enumerate(sorted_hist[:top_n]):
            devname_str = key.devname.decode('utf-8', 'replace').rstrip('\x00') if isinstance(key.devname, bytes) else str(key.devname).rstrip('\x00')
            tuple_str = format_five_tuple(key.tuple)
            print("\n  #%d Count: %d calls [device: %s] [stack_id: %d]" %
                  (i+1, count.value, devname_str, key.stack_id))
            print("     Flow: %s" % tuple_str)
            print("  Stack trace:")

            try:
                stack = list(stack_traces.walk(key.stack_id))
                print("    Stack depth: %d frames" % len(stack))
                for j, addr in enumerate(stack[:5]):  # Show top 5 frames
                    sym = b.sym(addr, -1, show_module=True, show_offset=True)
                    sym_str = sym.decode('utf-8', 'replace') if isinstance(sym, bytes) else str(sym)
                    print("    %s" % sym_str)
                if len(stack) > 5:
                    print("    ... (%d more frames)" % (len(stack) - 5))
            except Exception as e:
                print("    [Error reading stack: %s]" % e)

def ip_to_hex(ip):
    """Convert IP address to hex format"""
    try:
        return unpack("I", inet_aton(ip))[0]
    except:
        return 0

def main():
    global exiting

    # Parse arguments
    parser = argparse.ArgumentParser(description="Track kfree_skb call stack statistics with five-tuple granularity")
    parser.add_argument("-i", "--interval", type=int, default=10,
                        help="reporting interval in seconds (default: 10)")
    parser.add_argument("-d", "--duration", type=int, default=0,
                        help="total duration in seconds (default: unlimited)")
    parser.add_argument("-t", "--top", type=int, default=5,
                        help="number of top stacks to show (default: 5)")
    parser.add_argument("-n", "--name", type=str, default="",
                        help="filter by device name (e.g., eth0, br-int)")
    parser.add_argument("--src-ip", type=str, help="source IP address filter")
    parser.add_argument("--dst-ip", type=str, help="destination IP address filter")
    parser.add_argument("--src-port", type=int, help="source port filter (TCP/UDP)")
    parser.add_argument("--dst-port", type=int, help="destination port filter (TCP/UDP)")
    parser.add_argument("--l4-protocol", type=str, choices=['all', 'icmp', 'tcp', 'udp'],
                        default='all', help="L4 protocol filter (TCP/UDP/ICMP)")
    parser.add_argument("--max-entries", type=int, default=10240,
                        help="maximum histogram entries (default: 10240)")
    parser.add_argument("--group-by", type=str, choices=['all', 'stack', 'fivetuple'],
                        default='all', help="grouping mode (default: all)")
    args = parser.parse_args()

    # Process five-tuple arguments
    l4_protocol_map = {'all': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}
    l4_protocol = l4_protocol_map.get(args.l4_protocol, 0)
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0

    # Install signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Build filter info string
    filters = []
    if args.name:
        filters.append("device: %s" % args.name)
    if args.src_ip:
        filters.append("src IP: %s" % args.src_ip)
    if args.dst_ip:
        filters.append("dst IP: %s" % args.dst_ip)
    if args.src_port:
        filters.append("src port: %d" % args.src_port)
    if args.dst_port:
        filters.append("dst port: %d" % args.dst_port)
    if args.l4_protocol != 'all':
        filters.append("protocol: %s" % args.l4_protocol.upper())

    filter_info = " (filters: %s)" % ", ".join(filters) if filters else " (no filters)"
    print("Tracing kfree_skb calls with five-tuple histograms, %ds intervals...%s" % (args.interval, filter_info))
    print("Max histogram entries: %d, Grouping by: %s" % (args.max_entries, args.group_by))
    if args.duration > 0:
        print("Duration: %ds, Press Ctrl+C to stop early" % args.duration)
    else:
        print("Press Ctrl+C to stop")
    print("="*60)

    # Initialize BPF with five-tuple parameters
    b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex, src_port, dst_port, l4_protocol, args.max_entries))
    b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")

    # Set device name filter if specified
    if args.name:
        if len(args.name) > 15:  # IFNAMSIZ-1
            print("Device name too long (max 15 chars)")
            return

        # Define ctypes structure for device name
        class Devname(Structure):
            _fields_ = [('name', c_char * 16)]  # IFNAMSIZ

        devname_map = b['name_map']
        _name = Devname()
        _name.name = args.name.encode('utf-8')
        devname_map[0] = _name
        print("Filtering by device: %s" % args.name)
    else:
        print("No device filter - monitoring all interfaces")

    # Initialize timing
    start_time = time()
    cycle = 0

    try:
        while not exiting:
            sleep(args.interval)
            cycle += 1

            # Check duration limit
            if args.duration > 0 and (time() - start_time) >= args.duration:
                break

            # Calculate total drops based on grouping mode
            if args.group_by == 'stack':
                hist = b["stack_hist"]
            elif args.group_by == 'fivetuple':
                hist = b["tuple_hist"]
            else:
                hist = b["drop_hist"]

            total_drops = sum(count.value for count in hist.values())

            # Print periodic statistics
            current_time = strftime("%Y-%m-%d %H:%M:%S")
            print("\n[%s] Cycle %d - Interval drops: %d [showing top %d, grouped by: %s]" %
                  (current_time, cycle, total_drops, args.top, args.group_by))
            print("-" * 60)

            # Print histogram statistics
            print_histogram_stats(b, args.top, args.group_by)
            print("=" * 60)

            # Clear histograms for next interval
            if args.group_by == 'stack':
                b["stack_hist"].clear()
            elif args.group_by == 'fivetuple':
                b["tuple_hist"].clear()
            else:
                b["drop_hist"].clear()
                b["stack_hist"].clear()
                b["tuple_hist"].clear()
            b["failed_hist"].clear()

    except KeyboardInterrupt:
        exiting = True

    # Print final statistics (last interval)
    print("\n" + "="*60)
    print("%s kfree_skb Call Stack Statistics - Final Interval Summary" % strftime("%Y-%m-%d %H:%M:%S"))
    print("="*60)

    # Get final interval totals (before clearing)
    drop_hist = b["drop_hist"]
    failed_hist = b["failed_hist"]

    total_drops = sum(count.value for count in drop_hist.values())
    total_failed = sum(count.value for count in failed_hist.values())

    print("Last interval packet drops: %d" % total_drops)
    if total_failed > 0:
        print("Last interval failed stack traces: %d (%.1f%%)\n" %
              (total_failed, 100.0 * total_failed / (total_drops + total_failed)))

    if total_drops == 0:
        print("No packet drops in last interval.")
        return

    print("Top call stacks and flows in last interval:")
    print("-" * 40)

    # Sort histogram by count (descending)
    sorted_hist = sorted(drop_hist.items(), key=lambda x: x[1].value, reverse=True)

    for key, count in sorted_hist[:args.top * 2]:  # Show more in final summary
        devname_str = key.devname.decode('utf-8', 'replace').rstrip('\x00')
        tuple_str = format_five_tuple(key.tuple)
        print("\nCount: %d calls (%.1f%%) [device: %s] [stack_id: %d]" %
              (count.value, 100.0 * count.value / total_drops, devname_str, key.stack_id))
        print("Flow: %s" % tuple_str)
        print("Stack trace:")

        try:
            stack_traces = b["stack_traces"]
            stack = stack_traces.walk(key.stack_id)
            for addr in stack:
                sym = b.sym(addr, -1, show_module=True, show_offset=True)
                sym_str = sym.decode('utf-8', 'replace') if isinstance(sym, bytes) else str(sym)
                print("  %s" % sym_str)
        except Exception as e:
            print("  [Error reading stack: %s]" % e)

        print("-" * 40)

    print("\nTracing completed.")

if __name__ == "__main__":
    main()