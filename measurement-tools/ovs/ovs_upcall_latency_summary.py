#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
OVS Upcall Latency Histogram Tool

Measures latency distribution between OVS upcall and userspace processing using BPF_HISTOGRAM.
Only tracks the delay between ovs_dp_upcall and ovs_flow_key_extract_userspace.

Usage:
    sudo ./ovs_upcall_latency_histogram.py --src-ip 192.168.76.198 --proto tcp --interval 5

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
import signal

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

// User-defined filters  
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP, 1=ICMP

// Packet key structure for unique packet identification
struct packet_key_t {
    __be32 sip;
    __be32 dip;
    u8 proto;
    u8 pad[3];
    
    union {
        struct {
            __be16 source;
            __be16 dest;
            __be32 seq;
        } tcp;
        
        struct {
            __be16 source;
            __be16 dest;
            __be16 id;
            __be16 len;
        } udp;
        
        struct {
            __be16 id;
            __be16 sequence;
            u8 type;
            u8 code;
            u8 pad[2];
        } icmp;
    };
};

// Upcall session tracking
struct upcall_data_t {
    u64 upcall_timestamp;
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct upcall_data_t, upcall_sessions, 10240);

// BPF Histogram for upcall latencies - simple u8 key for latency bucket
BPF_HISTOGRAM(upcall_latency_hist, u8, 64);

// Performance statistics
BPF_ARRAY(packet_counters, u64, 4);  // 0=total_upcalls, 1=completed_upcalls, 2=timeouts, 3=errors

// Packet parsing function
static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key) {
    struct iphdr ip;
    unsigned char *head;
    u16 network_header_offset;
    
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return 0;
    }
    
    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        return 0;
    }
    
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        return 0;
    }
    
    // Apply protocol filter
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }
    
    // Apply IP filters
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
        return 0;
    }
    
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;
    
    // Parse transport layer based on protocol
    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) return 0;
    
    u16 transport_header_offset = network_header_offset + (ip_ihl * 4);
    
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header_offset) < 0) {
                return 0;
            }
            
            key->tcp.source = tcp.source;
            key->tcp.dest = tcp.dest;
            key->tcp.seq = tcp.seq;
            
            if (SRC_PORT_FILTER != 0 && tcp.source != htons(SRC_PORT_FILTER) && tcp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && tcp.source != htons(DST_PORT_FILTER) && tcp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            key->udp.id = ip.id;
            
            struct udphdr udp;
            if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header_offset) < 0) {
                return 0;
            }
            key->udp.source = udp.source;
            key->udp.dest = udp.dest;
            key->udp.len = udp.len;
            
            if (SRC_PORT_FILTER != 0 && udp.source != htons(SRC_PORT_FILTER) && udp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && udp.source != htons(DST_PORT_FILTER) && udp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_ICMP: {
            struct icmphdr icmp;
            if (bpf_probe_read_kernel(&icmp, sizeof(icmp), head + transport_header_offset) < 0) {
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

// Specialized parsing function for userspace SKB
static __always_inline int parse_packet_key_userspace(struct sk_buff *skb, struct packet_key_t *key) {
    if (skb == NULL) {
        return 0;
    }

    unsigned char *skb_head;
    if(bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0) {
        return 0;
    }
    if (!skb_head) {
        return 0;
    }
    
    unsigned long skb_data_ptr_val; 
    if(bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 0;
    }
    
    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);
    unsigned int mac_offset = data_offset; 
    
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset) < 0) {
        return 0;
    }
    
    unsigned int net_offset = mac_offset + ETH_HLEN;
    __be16 h_proto = eth.h_proto;
    
    // Handle VLAN tags
    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        net_offset += VLAN_HLEN; 
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2) < 0) { 
            return 0;
        }
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
             net_offset += VLAN_HLEN;
             if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + (2 * VLAN_HLEN) + 2) < 0) {
                 return 0;
             }
        }
    }
    
    if (h_proto != htons(ETH_P_IP)) {
        return 0;
    }
    
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), skb_head + net_offset) < 0) {
        return 0;
    }
    
    // Apply protocol filter
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }
    
    // Apply IP filters
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER && ip.daddr != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.saddr != DST_IP_FILTER && ip.daddr != DST_IP_FILTER) {
        return 0;
    }
    
    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;

    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {  
        return 0;
    }

    unsigned int trans_offset = net_offset + (ip_ihl * 4);
    
    // Parse transport layer
    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + trans_offset) < 0) {
                return 0;
            }
            
            key->tcp.source = tcp.source;
            key->tcp.dest = tcp.dest;
            key->tcp.seq = tcp.seq;
            
            if (SRC_PORT_FILTER != 0 && tcp.source != htons(SRC_PORT_FILTER) && tcp.dest != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && tcp.source != htons(DST_PORT_FILTER) && tcp.dest != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            key->udp.id = ip.id;

            struct udphdr udp;
            if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) < 0) {
                return 0;
            }
            key->udp.source = udp.source;
            key->udp.dest = udp.dest;
            key->udp.len = udp.len;

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
            if (bpf_probe_read_kernel(&icmp, sizeof(icmp), skb_head + trans_offset) < 0) {
                return 0;
            }
            
            key->icmp.id = icmp.un.echo.id;
            key->icmp.sequence = icmp.un.echo.sequence;
            key->icmp.type = icmp.type;
            key->icmp.code = icmp.code;
            break;
        }
        default:
            return 0;
    }
    
    return 1;
}

// Probe 1: OVS upcall start
int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (!skb) return 0;
    
    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key)) {
        return 0;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    
    // Record upcall start time
    struct upcall_data_t upcall_data = {};
    upcall_data.upcall_timestamp = current_ts;
    
    upcall_sessions.update(&key, &upcall_data);
    
    // Count total upcalls
    u32 idx = 0;
    u64 *upcall_counter = packet_counters.lookup(&idx);
    if (upcall_counter) (*upcall_counter)++;
    
    return 0;
}

// Probe 2: OVS userspace processing 
int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) return 0;
    
    struct packet_key_t key = {};
    if (!parse_packet_key_userspace(skb, &key)) {
        return 0;
    }
    
    // Look up upcall session
    struct upcall_data_t *upcall_ptr = upcall_sessions.lookup(&key);
    if (!upcall_ptr) {
        upcall_sessions.delete(&key);
        return 0;
    }
    
    u64 current_ts = bpf_ktime_get_ns();
    
    if (current_ts > upcall_ptr->upcall_timestamp) {
        u64 latency_ns = current_ts - upcall_ptr->upcall_timestamp;
        u64 latency_us = latency_ns / 1000;
        
        // Calculate log2 bucket for histogram
        u8 log2_latency = 0;
        if (latency_us > 0) {
            log2_latency = bpf_log2l(latency_us);
            // Cap at 63 to avoid array bounds
            if (log2_latency > 63) log2_latency = 63;
        }
        
        // Update histogram
        upcall_latency_hist.increment(log2_latency);
        
        // Count completed upcalls
        u32 idx = 1;
        u64 *complete_counter = packet_counters.lookup(&idx);
        if (complete_counter) (*complete_counter)++;
    }
    
    // Clean up session
    upcall_sessions.delete(&key);
    return 0;
}
"""

# Helper Functions
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

def print_histogram_summary(b, interval_start_time):
    """Print upcall latency histogram summary for the current interval"""
    current_time = datetime.datetime.now()
    print("\n" + "=" * 80)
    print("[%s] OVS Upcall Latency Report (Interval: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        time_time() - interval_start_time
    ))
    print("=" * 80)
    
    # Get histogram data
    latency_hist = b["upcall_latency_hist"]
    
    # Collect histogram data
    latency_data = {}
    
    try:
        for k, v in latency_hist.items():
            bucket = k.value if hasattr(k, 'value') else int(k)
            count = v.value if hasattr(v, 'value') else int(v)
            if count > 0:
                latency_data[bucket] = count
    except Exception as e:
        print("Error reading histogram data:", str(e))
        return
    
    # Print statistics
    counters = b["packet_counters"]
    total_upcalls = counters[0].value
    completed_upcalls = counters[1].value
    
    print("Upcall Statistics:")
    print("  Total upcalls: %d" % total_upcalls)
    print("  Completed upcalls: %d" % completed_upcalls)
    if total_upcalls > 0:
        completion_rate = (completed_upcalls * 100.0) / total_upcalls
        print("  Completion rate: %.1f%%" % completion_rate)
        print("  Lost/timeout upcalls: %d" % (total_upcalls - completed_upcalls))
    
    # Display histogram
    if latency_data:
        print("\nUpcall Latency Distribution:")
        print("-" * 60)
        
        # Calculate statistics
        total_samples = sum(latency_data.values())
        max_count = max(latency_data.values())
        
        print("  Total samples: %d" % total_samples)
        print("  Latency histogram:")
        
        for bucket in sorted(latency_data.keys()):
            count = latency_data[bucket]
            
            # Calculate latency range for this bucket
            if bucket == 0:
                range_str = "0-1us"
            else:
                low = 1 << (bucket - 1)  # 2^(bucket-1)
                high = (1 << bucket) - 1  # 2^bucket - 1
                if high >= 1000000:  # >= 1s
                    range_str = "%.1f-%.1fs" % (low/1000000.0, high/1000000.0)
                elif high >= 1000:  # >= 1ms
                    range_str = "%.1f-%.1fms" % (low/1000.0, high/1000.0)
                else:
                    range_str = "%d-%dus" % (low, high)
            
            # Create simple bar graph
            bar_width = int(40 * count / max_count)
            bar = "*" * bar_width
            
            print("    %-15s: %6d |%-40s|" % (range_str, count, bar))
    else:
        print("\nNo upcall latency data collected in this interval")
    
    # Check active sessions
    try:
        active_sessions = len(b["upcall_sessions"])
        print("\nActive upcall sessions: %d" % active_sessions)
    except:
        print("\nActive upcall sessions: N/A")
    
    # Clear histogram for next interval
    latency_hist.clear()

def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="OVS Upcall Latency Histogram Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor all upcall latency:
    sudo %(prog)s --interval 5
    
  Monitor TCP upcalls from specific IP:
    sudo %(prog)s --src-ip 192.168.76.198 --proto tcp
    
  Monitor SSH traffic upcalls:
    sudo %(prog)s --proto tcp --dst-port 22 --interval 10
"""
    )
    
    parser.add_argument('--src-ip', type=str, required=False,
                        help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, required=False,
                        help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port filter (TCP/UDP)')
    parser.add_argument('--dst-port', type=int, required=False,
                        help='Destination port filter (TCP/UDP)')
    parser.add_argument('--protocol', '--proto', type=str, choices=['tcp', 'udp', 'icmp', 'all'],
                        default='all', help='Protocol filter (default: all)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Statistics output interval in seconds (default: 5)')
    
    args = parser.parse_args()
    
    # Convert parameters
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0
    
    protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'all': 0}
    protocol_filter = protocol_map[args.protocol]
    
    print("=== OVS Upcall Latency Histogram Tool ===")
    print("Protocol filter: %s" % args.protocol.upper())
    if args.src_ip:
        print("Source IP filter: %s" % args.src_ip)
    if args.dst_ip:
        print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("Statistics interval: %d seconds" % args.interval)
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_filter
        ))
        print("BPF program loaded successfully")
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)
    
    print("\nCollecting OVS upcall latency data... Hit Ctrl-C to end.")
    print("Statistics will be displayed every %d seconds\n" % args.interval)
    
    # Setup signal handler for clean exit
    def signal_handler(sig, frame):
        print("\n\nFinal statistics:")
        print_histogram_summary(b, interval_start_time)
        print("\nExiting...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Main loop
    interval_start_time = time_time()
    
    try:
        while True:
            sleep(args.interval)
            print_histogram_summary(b, interval_start_time)
            interval_start_time = time_time()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()