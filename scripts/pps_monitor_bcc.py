#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PPS Monitor with Protocol Classification (BCC Version)

Monitor network interface PPS using eBPF tracepoint, classify packets by
protocol (L2: IP/ARP, L4: TCP/UDP/ICMP), and optionally trigger tcpdump
capture when total PPS exceeds threshold.

Usage:
    sudo python -u pps_monitor_bcc.py --nic enp24s0f0np0 --interval 1
    sudo python -u pps_monitor_bcc.py --nic eth0 --interval 1 --enable-capture \
        --threshold 10000 --duration 3 --capture-time 10
"""

from __future__ import print_function, division

import argparse
import ctypes
import os
import signal
import subprocess
import sys
import time
from collections import deque
from datetime import datetime

try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF


# BPF program
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bcc/proto.h>

// Protocol category enum
enum pkt_category {
    CAT_IP_TCP = 0,
    CAT_IP_UDP,
    CAT_IP_ICMP,
    CAT_IP_OTHER,
    CAT_ARP,
    CAT_L2_OTHER,
    CAT_MAX
};

// Per-CPU counter array for each category
BPF_PERCPU_ARRAY(pkt_counts, u64, CAT_MAX);

// Target interface index (0 means all interfaces)
BPF_ARRAY(target_ifindex, u32, 1);

TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    u32 zero = 0;
    u32 *tgt_idx = target_ifindex.lookup(&zero);

    // Get interface index
    struct net_device *dev;
    u32 ifindex = 0;
    bpf_probe_read(&dev, sizeof(dev), &skb->dev);
    if (dev) {
        bpf_probe_read(&ifindex, sizeof(ifindex), &dev->ifindex);
    }

    // Filter by interface if specified
    if (tgt_idx && *tgt_idx != 0 && ifindex != *tgt_idx) {
        return 0;
    }

    // Get L2 protocol (in network byte order)
    __be16 protocol;
    bpf_probe_read(&protocol, sizeof(protocol), &skb->protocol);
    u16 eth_proto = ntohs(protocol);

    u32 category;

    if (eth_proto == ETH_P_IP) {
        // Parse IP header to get L4 protocol
        unsigned char *head;
        u16 network_header;
        bpf_probe_read(&head, sizeof(head), &skb->head);
        bpf_probe_read(&network_header, sizeof(network_header), &skb->network_header);

        struct iphdr iph;
        bpf_probe_read(&iph, sizeof(iph), head + network_header);

        switch (iph.protocol) {
            case IPPROTO_TCP:
                category = CAT_IP_TCP;
                break;
            case IPPROTO_UDP:
                category = CAT_IP_UDP;
                break;
            case IPPROTO_ICMP:
                category = CAT_IP_ICMP;
                break;
            default:
                category = CAT_IP_OTHER;
                break;
        }
    } else if (eth_proto == ETH_P_ARP) {
        category = CAT_ARP;
    } else {
        category = CAT_L2_OTHER;
    }

    u64 *count = pkt_counts.lookup(&category);
    if (count) {
        (*count)++;
    }

    return 0;
}
"""

# Category names for display
CATEGORY_NAMES = [
    "TCP",
    "UDP",
    "ICMP",
    "IP-Other",
    "ARP",
    "L2-Other"
]

CAT_MAX = 6

# Global state
running = True
capture_processes = []


def flush_print(msg):
    """Print with immediate flush"""
    print(msg)
    sys.stdout.flush()


def signal_handler(sig, frame):
    """Handle interrupt signals"""
    global running, capture_processes
    flush_print("\n[INFO] Received signal %d, stopping..." % sig)
    running = False

    for proc in capture_processes:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='BCC-based PPS monitor with protocol classification',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Monitor PPS on single NIC:
    sudo python %(prog)s --nic eth0 --interval 1

  Enable capture when threshold exceeded:
    sudo python %(prog)s --nic eth0 --enable-capture --threshold 5000

  Custom capture settings:
    sudo python %(prog)s --nic eth0 --enable-capture --threshold 5000 \\
        --duration 3 --capture-time 30 --max-captures 2
        ''')

    parser.add_argument('--nic', required=True,
                        help='NIC to monitor')
    parser.add_argument('--interval', type=int, default=1,
                        help='Monitoring interval in seconds (default: 1)')

    # Capture options (disabled by default)
    parser.add_argument('--enable-capture', action='store_true',
                        help='Enable packet capture when threshold exceeded')
    parser.add_argument('--threshold', type=int, default=10000,
                        help='PPS threshold to trigger capture (default: 10000)')
    parser.add_argument('--duration', type=int, default=3,
                        help='Consecutive intervals exceeding threshold (default: 3)')
    parser.add_argument('--capture-time', type=int, default=10,
                        help='Capture duration in seconds (default: 10)')
    parser.add_argument('--capture-count', type=int, default=0,
                        help='Max packets to capture (0=no limit, default: 0)')
    parser.add_argument('--max-captures', type=int, default=1,
                        help='Maximum capture sessions (default: 1)')
    parser.add_argument('--output-dir', default='/tmp/pps_captures',
                        help='Directory for capture files (default: /tmp/pps_captures)')
    parser.add_argument('--snaplen', type=int, default=128,
                        help='Capture snaplen bytes per packet (default: 128)')

    return parser.parse_args()


def get_ifindex(nic):
    """Get interface index for the given NIC name"""
    try:
        with open('/sys/class/net/%s/ifindex' % nic, 'r') as f:
            return int(f.read().strip())
    except IOError:
        return None


def ensure_output_dir(output_dir):
    """Create output directory if needed"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        flush_print("[INFO] Created output directory: %s" % output_dir)


def start_tcpdump(nic, output_dir, capture_time, capture_count, snaplen, capture_num):
    """Start tcpdump capture"""
    global capture_processes
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(output_dir,
                           'capture_%s_%s_%d.pcap' % (nic, timestamp, capture_num))

    cmd = ['sudo', 'timeout', str(capture_time),
           'tcpdump', '-i', nic, '-s', str(snaplen), '-w', filename]

    if capture_count > 0:
        cmd.extend(['-c', str(capture_count)])

    flush_print("[CAPTURE] Starting tcpdump on %s -> %s" % (nic, filename))

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        capture_processes.append(proc)
        return proc
    except Exception as e:
        flush_print("[ERROR] Failed to start tcpdump: %s" % str(e))
        return None


def main():
    global running

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_args()

    # Validate NIC
    ifindex = get_ifindex(args.nic)
    if ifindex is None:
        flush_print("[ERROR] Interface %s not found" % args.nic)
        return 1

    # Initialize BPF
    flush_print("[INFO] Loading BPF program...")
    try:
        b = BPF(text=BPF_PROGRAM)
    except Exception as e:
        flush_print("[ERROR] Failed to load BPF: %s" % str(e))
        return 1

    # Set target interface
    target_ifindex = b.get_table("target_ifindex")
    target_ifindex[ctypes.c_int(0)] = ctypes.c_uint(ifindex)

    pkt_counts = b.get_table("pkt_counts")

    # State for capture trigger
    pps_history = deque(maxlen=args.duration)
    capture_count = 0
    capturing = False
    capture_end_time = 0

    if args.enable_capture:
        ensure_output_dir(args.output_dir)

    # Print header
    flush_print("=" * 90)
    flush_print("PPS Monitor with Protocol Classification (BCC)")
    flush_print("=" * 90)
    flush_print("NIC:          %s (ifindex=%d)" % (args.nic, ifindex))
    flush_print("Interval:     %d seconds" % args.interval)
    if args.enable_capture:
        flush_print("Capture:      ENABLED")
        flush_print("Threshold:    %d pps" % args.threshold)
        flush_print("Duration:     %d intervals" % args.duration)
        flush_print("Capture time: %d seconds" % args.capture_time)
        flush_print("Max captures: %d" % args.max_captures)
        flush_print("Output dir:   %s" % args.output_dir)
    else:
        flush_print("Capture:      DISABLED (use --enable-capture to enable)")
    flush_print("=" * 90)
    flush_print("")

    # Column header
    header = "%-10s %12s %12s %12s %12s %12s %12s %12s" % (
        "Time", "Total", "TCP", "UDP", "ICMP", "IP-Other", "ARP", "L2-Other")
    flush_print(header)
    flush_print("-" * 90)

    # Previous counts for delta calculation
    prev_counts = [0] * CAT_MAX

    try:
        while running:
            time.sleep(args.interval)

            if not running:
                break

            current_time = datetime.now().strftime('%H:%M:%S')

            # Read current counts (sum across all CPUs)
            curr_counts = [0] * CAT_MAX
            for i in range(CAT_MAX):
                try:
                    vals = pkt_counts[ctypes.c_int(i)]
                    total = sum(vals)
                    curr_counts[i] = total
                except (KeyError, IndexError):
                    curr_counts[i] = 0

            # Calculate delta (packets in this interval)
            delta_counts = [curr_counts[i] - prev_counts[i] for i in range(CAT_MAX)]
            prev_counts = curr_counts[:]

            # Calculate PPS
            pps = [d / args.interval for d in delta_counts]
            total_pps = sum(pps)

            # Format output
            line = "%-10s %12.0f %12.0f %12.0f %12.0f %12.0f %12.0f %12.0f" % (
                current_time, total_pps, pps[0], pps[1], pps[2], pps[3], pps[4], pps[5])
            flush_print(line)

            # Capture logic (if enabled)
            if args.enable_capture:
                # Check if capturing is done
                if capturing and time.time() >= capture_end_time:
                    capturing = False
                    flush_print("[INFO] Capture session %d completed" % capture_count)

                # Update history and check trigger
                pps_history.append(total_pps)

                if not capturing and capture_count < args.max_captures:
                    if len(pps_history) >= args.duration:
                        if all(p >= args.threshold for p in pps_history):
                            capture_count += 1
                            capturing = True
                            capture_end_time = time.time() + args.capture_time

                            flush_print("")
                            flush_print("=" * 90)
                            flush_print("[TRIGGER] PPS exceeded %d for %d intervals!" %
                                        (args.threshold, args.duration))
                            flush_print("[TRIGGER] Starting capture session %d/%d" %
                                        (capture_count, args.max_captures))
                            flush_print("=" * 90)
                            flush_print("")

                            start_tcpdump(args.nic, args.output_dir,
                                         args.capture_time, args.capture_count,
                                         args.snaplen, capture_count)

                            pps_history.clear()

    except KeyboardInterrupt:
        pass

    # Cleanup
    flush_print("\n[INFO] Stopping monitor...")

    if capturing:
        flush_print("[INFO] Waiting for capture to complete...")
        time.sleep(max(0, capture_end_time - time.time()) + 2)

    # Summary
    flush_print("")
    flush_print("=" * 90)
    flush_print("Summary")
    flush_print("=" * 90)

    if args.enable_capture:
        flush_print("Total captures triggered: %d" % capture_count)
        if os.path.exists(args.output_dir):
            files = [f for f in os.listdir(args.output_dir) if f.endswith('.pcap')]
            if files:
                flush_print("Capture files:")
                for f in sorted(files):
                    filepath = os.path.join(args.output_dir, f)
                    size = os.path.getsize(filepath)
                    flush_print("  - %s (%d bytes)" % (f, size))

    flush_print("=" * 90)
    return 0


if __name__ == '__main__':
    sys.exit(main())
