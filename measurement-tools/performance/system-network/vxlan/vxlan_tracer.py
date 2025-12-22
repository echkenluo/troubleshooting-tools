#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VXLAN Tracer - Simple VXLAN Encap/Decap Monitor

Traces VXLAN encapsulation (xmit) and decapsulation (rcv) operations,
capturing packet metadata and optional call stacks.

Key trace points:
- vxlan_xmit: VXLAN packet encapsulation on TX
- vxlan_rcv: VXLAN packet decapsulation on RX

Captured information:
- Packet: src/dst IP, protocol, length
- SKB metadata: gso_type, gso_size, data_len
- VXLAN: VNI, flags, UDP ports
- Optional: kernel call stack

Usage:
    # Basic tracing
    sudo python3 vxlan_tracer.py

    # With call stacks
    sudo python3 vxlan_tracer.py --stack

    # Filter by VNI
    sudo python3 vxlan_tracer.py --vni 100

    # Filter by IP
    sudo python3 vxlan_tracer.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2

    # Only show encap or decap
    sudo python3 vxlan_tracer.py --direction tx   # or rx

Author: Network Troubleshooting Tools
"""

from __future__ import print_function
import sys
import argparse
import ctypes
import socket
import struct
import signal
from datetime import datetime

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

# Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

// Configuration
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define VNI_FILTER %d
#define CAPTURE_STACK %d

// VXLAN header (simplified)
struct vxlanhdr_simple {
    __be32 vx_flags;
    __be32 vx_vni;
};

// skb_shared_info minimal
struct skb_shared_info_min {
    __u8 __unused;
    __u8 meta_len;
    __u8 nr_frags;
    __u8 tx_flags;
    unsigned short gso_size;
    unsigned short gso_segs;
    struct sk_buff *frag_list;
    unsigned int gso_type;
};

// Event structure
struct vxlan_event_t {
    u64 timestamp_ns;
    u64 skb_addr;

    // Packet info
    u32 src_ip;
    u32 dst_ip;
    u32 inner_src_ip;
    u32 inner_dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 direction;  // 0=RX, 1=TX

    // SKB metadata
    u32 len;
    u32 data_len;
    u32 gso_type;
    u16 gso_size;
    u16 gso_segs;
    u64 frag_list;  // skb_shared_info->frag_list pointer

    // VXLAN metadata
    u32 vni;
    u32 vx_flags;

    // Context
    u32 pid;
    u32 cpu;
    char comm[16];
    char dev_name[16];

    // Stack trace ID
    int stack_id;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(stats, u32, u64, 4);
// stats[0]=rx_count, stats[1]=tx_count, stats[2]=rx_bytes, stats[3]=tx_bytes

#if CAPTURE_STACK
BPF_STACK_TRACE(stacks, 1024);
#endif

// Helper: Get skb_shared_info
static __always_inline struct skb_shared_info_min* get_shinfo(struct sk_buff *skb) {
    unsigned char *head;
    u32 end_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0) {
        return NULL;
    }

    if (bpf_probe_read_kernel(&end_offset, sizeof(end_offset), &skb->end) != 0) {
        return NULL;
    }

    return (struct skb_shared_info_min *)(head + end_offset);
}

// Helper: Extract inner IP from VXLAN packet
static __always_inline void extract_inner_ip(struct sk_buff *skb,
                                              struct vxlan_event_t *event) {
    unsigned char *data;
    u32 data_len;

    if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) != 0) {
        return;
    }

    if (bpf_probe_read_kernel(&data_len, sizeof(data_len), &skb->len) != 0) {
        return;
    }

    // VXLAN header is 8 bytes, then inner Ethernet
    if (data_len < 8 + 14 + 20) {  // VXLAN + ETH + IP
        return;
    }

    struct vxlanhdr_simple vxh;
    if (bpf_probe_read_kernel(&vxh, sizeof(vxh), data) == 0) {
        event->vx_flags = bpf_ntohl(vxh.vx_flags);
        event->vni = bpf_ntohl(vxh.vx_vni) >> 8;  // VNI is in upper 24 bits
    }

    // Skip VXLAN header (8) + Ethernet header (14)
    struct iphdr inner_ip;
    if (bpf_probe_read_kernel(&inner_ip, sizeof(inner_ip), data + 8 + 14) == 0) {
        if (inner_ip.version == 4) {
            event->inner_src_ip = inner_ip.saddr;
            event->inner_dst_ip = inner_ip.daddr;
        }
    }
}

// Trace vxlan_xmit (TX/Encap)
int trace_vxlan_xmit(struct pt_regs *ctx, struct sk_buff *skb,
                     struct net_device *dev) {
    struct vxlan_event_t event = {};

    // Basic info
    event.timestamp_ns = bpf_ktime_get_ns();
    event.skb_addr = (u64)skb;
    event.direction = 1;  // TX
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Device name
    if (dev) {
        bpf_probe_read_kernel_str(&event.dev_name, sizeof(event.dev_name),
                                  &dev->name);
    }

    // SKB length
    bpf_probe_read_kernel(&event.len, sizeof(event.len), &skb->len);
    bpf_probe_read_kernel(&event.data_len, sizeof(event.data_len), &skb->data_len);

    // GSO info
    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (shinfo) {
        bpf_probe_read_kernel(&event.gso_type, sizeof(event.gso_type),
                              &shinfo->gso_type);
        bpf_probe_read_kernel(&event.gso_size, sizeof(event.gso_size),
                              &shinfo->gso_size);
        bpf_probe_read_kernel(&event.gso_segs, sizeof(event.gso_segs),
                              &shinfo->gso_segs);

        // Read frag_list pointer
        struct sk_buff *frag_list_ptr;
        if (bpf_probe_read_kernel(&frag_list_ptr, sizeof(frag_list_ptr),
                                  &shinfo->frag_list) == 0) {
            event.frag_list = (u64)frag_list_ptr;
        }
    }

    // Get inner packet IP (pre-encapsulation)
    unsigned char *head;
    u16 network_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) == 0 &&
        bpf_probe_read_kernel(&network_header, sizeof(network_header),
                              &skb->network_header) == 0 &&
        network_header != (u16)~0U) {

        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
            event.inner_src_ip = ip.saddr;
            event.inner_dst_ip = ip.daddr;
            event.protocol = ip.protocol;

            // Apply inner IP filter
            if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
                return 0;
            }
            if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
                return 0;
            }
        }
    }

#if CAPTURE_STACK
    event.stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID);
#else
    event.stack_id = -1;
#endif

    // Submit event
    events.perf_submit(ctx, &event, sizeof(event));

    // Update stats
    u32 key = 1;  // TX count
    u64 *val = stats.lookup(&key);
    if (val) {
        (*val)++;
    }

    key = 3;  // TX bytes
    val = stats.lookup(&key);
    if (val) {
        (*val) += event.len;
    }

    return 0;
}

// Trace vxlan_rcv (RX/Decap)
int trace_vxlan_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct vxlan_event_t event = {};

    // Basic info
    event.timestamp_ns = bpf_ktime_get_ns();
    event.skb_addr = (u64)skb;
    event.direction = 0;  // RX
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Device name
    struct net_device *dev;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_kernel_str(&event.dev_name, sizeof(event.dev_name),
                                  &dev->name);
    }

    // SKB length
    bpf_probe_read_kernel(&event.len, sizeof(event.len), &skb->len);
    bpf_probe_read_kernel(&event.data_len, sizeof(event.data_len), &skb->data_len);

    // GSO info
    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (shinfo) {
        bpf_probe_read_kernel(&event.gso_type, sizeof(event.gso_type),
                              &shinfo->gso_type);
        bpf_probe_read_kernel(&event.gso_size, sizeof(event.gso_size),
                              &shinfo->gso_size);
        bpf_probe_read_kernel(&event.gso_segs, sizeof(event.gso_segs),
                              &shinfo->gso_segs);

        // Read frag_list pointer
        struct sk_buff *frag_list_ptr;
        if (bpf_probe_read_kernel(&frag_list_ptr, sizeof(frag_list_ptr),
                                  &shinfo->frag_list) == 0) {
            event.frag_list = (u64)frag_list_ptr;
        }
    }

    // Get outer IP header
    unsigned char *head;
    u16 network_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) == 0 &&
        bpf_probe_read_kernel(&network_header, sizeof(network_header),
                              &skb->network_header) == 0 &&
        network_header != (u16)~0U) {

        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
            event.src_ip = ip.saddr;
            event.dst_ip = ip.daddr;
            event.protocol = ip.protocol;

            // Get UDP header for VXLAN ports
            if (ip.protocol == IPPROTO_UDP) {
                u16 transport_header;
                if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header),
                                          &skb->transport_header) == 0 &&
                    transport_header != (u16)~0U) {

                    struct udphdr udp;
                    if (bpf_probe_read_kernel(&udp, sizeof(udp),
                                              head + transport_header) == 0) {
                        event.src_port = bpf_ntohs(udp.source);
                        event.dst_port = bpf_ntohs(udp.dest);
                    }
                }
            }
        }
    }

    // Extract VXLAN header and inner IP
    extract_inner_ip(skb, &event);

    // Apply VNI filter
    if (VNI_FILTER != 0 && event.vni != VNI_FILTER) {
        return 0;
    }

    // Apply inner IP filter
    if (SRC_IP_FILTER != 0 && event.inner_src_ip != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && event.inner_dst_ip != DST_IP_FILTER) {
        return 0;
    }

#if CAPTURE_STACK
    event.stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID);
#else
    event.stack_id = -1;
#endif

    // Submit event
    events.perf_submit(ctx, &event, sizeof(event));

    // Update stats
    u32 key = 0;  // RX count
    u64 *val = stats.lookup(&key);
    if (val) {
        (*val)++;
    }

    key = 2;  // RX bytes
    val = stats.lookup(&key);
    if (val) {
        (*val) += event.len;
    }

    return 0;
}
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace VXLAN encapsulation/decapsulation",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("--src-ip", type=str, help="Filter by inner source IP")
    parser.add_argument("--dst-ip", type=str, help="Filter by inner destination IP")
    parser.add_argument("--vni", type=int, help="Filter by VNI (only for RX)")
    parser.add_argument("--direction", type=str, choices=['tx', 'rx'],
                        help="Only show TX (encap) or RX (decap)")
    parser.add_argument("--stack", action="store_true",
                        help="Capture kernel stack traces")

    return parser.parse_args()

def ip_to_int(ip_str):
    if not ip_str:
        return 0
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except:
        print(Colors.FAIL + "Invalid IP address: %s" % ip_str + Colors.ENDC)
        sys.exit(1)

def int_to_ip(ip_int):
    if ip_int == 0:
        return "0.0.0.0"
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def decode_gso_type(gso_type):
    flags = []
    if gso_type & (1 << 0): flags.append("DODGY")
    if gso_type & (1 << 1): flags.append("UDP_TUNNEL")
    if gso_type & (1 << 2): flags.append("UDP_TUNNEL_CSUM")
    if gso_type & (1 << 3): flags.append("PARTIAL")
    if gso_type & (1 << 16): flags.append("TCPV4")
    if gso_type & (1 << 17): flags.append("TCPV6")
    if gso_type & (1 << 23): flags.append("UDP_L4")
    if gso_type & (1 << 24): flags.append("FRAGLIST")

    return "|".join(flags) if flags else "NONE"

def main():
    args = parse_args()

    print(Colors.BOLD + Colors.HEADER + "=" * 80 + Colors.ENDC)
    print(Colors.BOLD + Colors.HEADER + "VXLAN Tracer - Encap/Decap Monitor" + Colors.ENDC)
    print(Colors.BOLD + Colors.HEADER + "=" * 80 + Colors.ENDC)

    # Check if VXLAN module is loaded
    try:
        with open('/proc/modules', 'r') as f:
            modules = f.read()
            if 'vxlan' not in modules:
                print(Colors.WARNING + "\nWarning: VXLAN module not loaded!")
                print("No VXLAN traffic will be captured.")
                print("To load: sudo modprobe vxlan" + Colors.ENDC)
                print("\nContinuing anyway (will wait for module to be loaded)...\n")
    except:
        pass

    # Prepare filters
    src_ip = ip_to_int(args.src_ip)
    dst_ip = ip_to_int(args.dst_ip)
    vni = args.vni if args.vni else 0
    capture_stack = 1 if args.stack else 0

    # Load BPF
    bpf_code = bpf_text % (src_ip, dst_ip, vni, capture_stack)

    try:
        b = BPF(text=bpf_code)
    except Exception as e:
        print(Colors.FAIL + "Failed to load BPF program:" + Colors.ENDC)
        print(str(e))
        sys.exit(1)

    # Attach probes
    print("Attaching probes...")

    try:
        b.attach_kprobe(event="vxlan_xmit", fn_name="trace_vxlan_xmit")
        print(Colors.OKGREEN + "[+] Attached to vxlan_xmit (TX/Encap)" + Colors.ENDC)
    except Exception as e:
        print(Colors.WARNING + "[!] Could not attach to vxlan_xmit: %s" % str(e) + Colors.ENDC)
        print("    VXLAN TX events will not be captured.")

    try:
        b.attach_kprobe(event="vxlan_rcv", fn_name="trace_vxlan_rcv")
        print(Colors.OKGREEN + "[+] Attached to vxlan_rcv (RX/Decap)" + Colors.ENDC)
    except Exception as e:
        print(Colors.WARNING + "[!] Could not attach to vxlan_rcv: %s" % str(e) + Colors.ENDC)
        print("    VXLAN RX events will not be captured.")

    # Event structure
    class VxlanEvent(ctypes.Structure):
        _fields_ = [
            ("timestamp_ns", ctypes.c_uint64),
            ("skb_addr", ctypes.c_uint64),
            ("src_ip", ctypes.c_uint32),
            ("dst_ip", ctypes.c_uint32),
            ("inner_src_ip", ctypes.c_uint32),
            ("inner_dst_ip", ctypes.c_uint32),
            ("src_port", ctypes.c_uint16),
            ("dst_port", ctypes.c_uint16),
            ("protocol", ctypes.c_uint8),
            ("direction", ctypes.c_uint8),
            ("len", ctypes.c_uint32),
            ("data_len", ctypes.c_uint32),
            ("gso_type", ctypes.c_uint32),
            ("gso_size", ctypes.c_uint16),
            ("gso_segs", ctypes.c_uint16),
            ("frag_list", ctypes.c_uint64),
            ("vni", ctypes.c_uint32),
            ("vx_flags", ctypes.c_uint32),
            ("pid", ctypes.c_uint32),
            ("cpu", ctypes.c_uint32),
            ("comm", ctypes.c_char * 16),
            ("dev_name", ctypes.c_char * 16),
            ("stack_id", ctypes.c_int),
        ]

    # Print header
    print("\nTracing VXLAN traffic... Hit Ctrl-C to end.\n")

    if args.direction:
        print("Direction filter: %s" % args.direction.upper())
    if args.src_ip or args.dst_ip:
        print("IP filter: %s -> %s" %
              (args.src_ip or "any", args.dst_ip or "any"))
    if args.vni:
        print("VNI filter: %d" % args.vni)

    print()
    print("%-18s %-3s %-6s %-15s %-15s %-8s | %s" %
          ("TIME", "CPU", "DIR", "INNER_SRC", "INNER_DST", "VNI", "SKB_INFO"))
    print("-" * 120)

    # Event handler
    def print_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(VxlanEvent)).contents

        # Direction filter
        if args.direction:
            if args.direction == 'tx' and event.direction != 1:
                return
            if args.direction == 'rx' and event.direction != 0:
                return

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        direction = "TX" if event.direction == 1 else "RX"
        dev_name = event.dev_name.decode('utf-8', 'replace')

        # Direction color
        dir_color = Colors.OKGREEN if event.direction == 1 else Colors.OKCYAN
        direction_str = dir_color + direction + Colors.ENDC

        # Format IPs
        if event.direction == 1:  # TX
            inner_src = int_to_ip(event.inner_src_ip)
            inner_dst = int_to_ip(event.inner_dst_ip)
            vni_str = "N/A"
        else:  # RX
            inner_src = int_to_ip(event.inner_src_ip)
            inner_dst = int_to_ip(event.inner_dst_ip)
            vni_str = str(event.vni) if event.vni > 0 else "N/A"

        # SKB info
        skb_info = "len=%d" % event.len
        if event.gso_type != 0:
            skb_info += " gso=%s(%d)" % (decode_gso_type(event.gso_type),
                                         event.gso_size)

        print("%-18s %-3d %-6s %-15s %-15s %-8s | %s" %
              (timestamp, event.cpu, direction_str, inner_src, inner_dst,
               vni_str, skb_info))

        # Additional details
        details = []
        if event.direction == 0 and event.src_ip != 0:  # RX outer IP
            details.append("outer=%s:%d->%s:%d" %
                          (int_to_ip(event.src_ip), event.src_port,
                           int_to_ip(event.dst_ip), event.dst_port))
        if dev_name:
            details.append("dev=%s" % dev_name)
        if event.data_len > 0:
            details.append("data_len=%d" % event.data_len)
        if event.frag_list != 0:
            details.append("frag_list=0x%x" % event.frag_list)

        if details:
            print("  " + " ".join(details))

        # Print stack trace
        if args.stack and event.stack_id >= 0:
            stack = list(b["stacks"].walk(event.stack_id))
            for addr in stack:
                sym = b.ksym(addr, show_module=True, show_offset=True)
                print("    %s" % sym.decode('utf-8', 'replace'))
            print()

    b["events"].open_perf_buffer(print_event, page_cnt=256)

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Main loop
    while not exiting:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break

    # Print statistics
    print("\n" + "=" * 80)
    print("Statistics:")
    stats = b.get_table("stats")
    rx_count = stats[ctypes.c_uint(0)].value if ctypes.c_uint(0) in stats else 0
    tx_count = stats[ctypes.c_uint(1)].value if ctypes.c_uint(1) in stats else 0
    rx_bytes = stats[ctypes.c_uint(2)].value if ctypes.c_uint(2) in stats else 0
    tx_bytes = stats[ctypes.c_uint(3)].value if ctypes.c_uint(3) in stats else 0

    print("  RX (decap): %d packets, %d bytes" % (rx_count, rx_bytes))
    print("  TX (encap): %d packets, %d bytes" % (tx_count, tx_bytes))

if __name__ == "__main__":
    main()
