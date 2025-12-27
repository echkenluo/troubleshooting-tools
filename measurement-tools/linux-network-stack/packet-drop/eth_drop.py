#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from socket import inet_ntop, AF_INET, AF_INET6, inet_aton, htonl
from struct import pack, unpack
from time import strftime
import socket
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

# Protocol mapping for EtherType values
PROTOCOL_MAP = {
    'arp': 0x0806,
    'rarp': 0x8035,
    'ipv4': 0x0800,
    'ipv6': 0x86DD,
    'lldp': 0x88CC,
    'flow_control': 0x8808,
    'other': 0xFFFF  # Special value for other protocols
}

# Normal patterns for filtering out expected drops
normal_patterns = {
    'icmp_rcv': ['icmp_rcv'],
    'tcp_v4_rcv': ['tcp_v4_rcv', 'tcp_v4_do_rcv'],
    'skb_release_data': ['skb_release_data', '__kfree_skb', 'tcp_recvmsg'],
    'sk_stream_kill_queues': ['sk_stream_kill_queues']
}

def safe_str(obj):
    """Safely convert bytes or str to str for cross-platform compatibility"""
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='ignore')
    return str(obj)

def is_normal_kfree_pattern(stack_trace):
    """Filter out normal/expected kfree patterns"""
    if not stack_trace or len(stack_trace) < 2:
        return False
    
    # Convert all stack trace items to strings safely
    stack_trace_str = [safe_str(item) for item in stack_trace]
    
    # Stack trace is ordered from innermost (0) to outermost (-1)
    first_func = stack_trace_str[0]
    if 'kfree_skb' not in first_func:
        return False
    
    if len(stack_trace_str) >= 2:
        second_func = stack_trace_str[1]
        for pattern_name, pattern_funcs in normal_patterns.items():
            if any(func in second_func for func in pattern_funcs):
                return True
    
    return False

def ip_to_hex(ip):
    """Convert IPv4 address to hex format"""
    return unpack("I", inet_aton(ip))[0]

def ipv6_to_u64_pair(ip):
    """Convert IPv6 address to two 64-bit integers for BPF comparison.
    Use little-endian to match how x86 CPU interprets memory read by bpf_probe_read."""
    packed = socket.inet_pton(AF_INET6, ip)
    high = unpack("<Q", packed[:8])[0]
    low = unpack("<Q", packed[8:])[0]
    return high, low

def is_ipv6(ip):
    """Check if IP address is IPv6"""
    return ':' in ip

def parse_protocol_filter(protocol_str):
    """Parse protocol filter argument"""
    if protocol_str in PROTOCOL_MAP:
        return PROTOCOL_MAP[protocol_str]
    elif protocol_str.startswith('0x'):
        try:
            return int(protocol_str, 16)
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid hex protocol: {}".format(protocol_str))
    else:
        raise argparse.ArgumentTypeError("Unknown protocol: {}".format(protocol_str))

# Command line argument parsing
parser = argparse.ArgumentParser(
    description='Enhanced network packet drop tracing with protocol filtering and VLAN support (ARM compatible)'
)
parser.add_argument('--type', type=str, default='all',
                    help='Protocol type filter (arp|rarp|ipv4|ipv6|lldp|flow_control|other|0xXXXX|all)')
parser.add_argument('--l4-protocol', type=str, choices=['all', 'icmp', 'tcp', 'udp'], default='all', help='L4 Protocol filter (TCP/UDP/ICMP)')
parser.add_argument('--src-ip', type=str, help='Source IP address filter')
parser.add_argument('--dst-ip', type=str, help='Destination IP address filter')
parser.add_argument('--src-port', type=int, help='Source port filter (TCP/UDP)')
parser.add_argument('--dst-port', type=int, help='Destination port filter (TCP/UDP)')
parser.add_argument('--vlan-id', type=int, help='VLAN ID filter')
parser.add_argument('--interface', type=str, help='Network interface filter')
parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
parser.add_argument('--no-stack-trace', action='store_true', help='Disable stack trace output')
parser.add_argument('--disable-normal-filter', action='store_true', default=False,
                    help='Disable filtering of normal kfree patterns (default: filter enabled)')

args = parser.parse_args()

# Process arguments
l4_protocol_map = {'all': 0, 'icmp': 1, 'tcp': 6, 'udp': 17}
l4_protocol = l4_protocol_map.get(args.l4_protocol, 0)

# Detect IPv4 vs IPv6 for source and destination
src_ip_is_v6 = args.src_ip and is_ipv6(args.src_ip)
dst_ip_is_v6 = args.dst_ip and is_ipv6(args.dst_ip)

# IPv4 filter values
src_ip = "0.0.0.0"
dst_ip = "0.0.0.0"
# IPv6 filter values (high, low pairs)
src_ipv6_hi, src_ipv6_lo = 0, 0
dst_ipv6_hi, dst_ipv6_lo = 0, 0

if args.src_ip:
    if src_ip_is_v6:
        src_ipv6_hi, src_ipv6_lo = ipv6_to_u64_pair(args.src_ip)
    else:
        src_ip = args.src_ip

if args.dst_ip:
    if dst_ip_is_v6:
        dst_ipv6_hi, dst_ipv6_lo = ipv6_to_u64_pair(args.dst_ip)
    else:
        dst_ip = args.dst_ip

src_port = args.src_port if args.src_port else 0
dst_port = args.dst_port if args.dst_port else 0
vlan_filter = args.vlan_id if args.vlan_id else 0
interface_filter = args.interface if args.interface else ""

if args.type == 'all':
    protocol_filter = 0  # No filtering
else:
    protocol_filter = parse_protocol_filter(args.type)

print("Enhanced Ethernet Packet Drop Monitor (ARM Compatible)")
print("Protocol filter: {} (0x{:04x})".format(args.type, protocol_filter))
print("L4 Protocol filter: {}".format(args.l4_protocol))
if args.src_ip:
    print("Source IP: {} ({})".format(args.src_ip, "IPv6" if src_ip_is_v6 else "IPv4"))
else:
    print("Source IP: any")
if args.dst_ip:
    print("Destination IP: {} ({})".format(args.dst_ip, "IPv6" if dst_ip_is_v6 else "IPv4"))
else:
    print("Destination IP: any")
if src_port or dst_port:
    print("Source port: {}, Destination port: {}".format(src_port, dst_port))
if vlan_filter:
    print("VLAN ID filter: {}".format(vlan_filter))
if interface_filter:
    print("Interface filter: {}".format(interface_filter))
print("Verbose mode: {}".format('ON' if args.verbose else 'OFF'))
print("Stack trace: {}".format('OFF' if args.no_stack_trace else 'ON'))
print("Normal pattern filter: {}".format('OFF' if args.disable_normal_filter else 'ON'))
print("-" * 80)

src_ip_hex = ip_to_hex(src_ip)
dst_ip_hex = ip_to_hex(dst_ip)

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_arp.h>

#define IFNAMSIZ 16
#define TASK_COMM_LEN 16
#define ETH_ALEN 6

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88CC
#endif

// VLAN header structure
struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// ARP header structure
struct arphdr_custom {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8 ar_hln;
    __u8 ar_pln;
    __be16 ar_op;
    __u8 ar_sha[ETH_ALEN];
    __u8 ar_sip[4];
    __u8 ar_tha[ETH_ALEN];
    __u8 ar_tip[4];
};

BPF_STACK_TRACE(stack_traces, 10240);

// Interface name filtering structure
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

BPF_ARRAY(interface_map, union name_buf, 1);

// Configuration constants
#define SRC_IP 0x%x
#define DST_IP 0x%x
#define SRC_PORT %d
#define DST_PORT %d
#define PROTOCOL_FILTER 0x%x
#define L4_PROTOCOL %d
#define VLAN_FILTER %d
#define INTERFACE_FILTER_ENABLED %d

// IPv6 filter constants (128-bit as two 64-bit values)
#define SRC_IPV6_HI 0x%xULL
#define SRC_IPV6_LO 0x%xULL
#define DST_IPV6_HI 0x%xULL
#define DST_IPV6_LO 0x%xULL

// Simplified packet data structure without union
struct packet_data_t {
    u64 timestamp;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u32 stack_id;
    
    // Ethernet fields
    u8 eth_src[ETH_ALEN];
    u8 eth_dst[ETH_ALEN];
    u16 eth_type;
    
    // VLAN fields
    u16 vlan_id;
    u16 vlan_priority;
    u16 inner_protocol;
    u8 has_vlan;
    
    // Protocol type indicator
    u8 protocol_type;  // 0=other, 1=ipv4, 2=ipv6, 3=arp, 4=rarp
    
    // IPv4 fields
    u32 ipv4_saddr;
    u32 ipv4_daddr;
    u8 ipv4_protocol;
    u16 ipv4_sport;
    u16 ipv4_dport;
    u8 ipv4_ttl;
    u16 ipv4_id;
    u16 ipv4_tot_len;
    u8 ipv4_tos;
    
    // IPv6 fields
    u8 ipv6_saddr[16];
    u8 ipv6_daddr[16];
    u8 ipv6_nexthdr;
    u8 ipv6_hop_limit;
    u16 ipv6_payload_len;
    u16 ipv6_sport;
    u16 ipv6_dport;
    
    // ARP fields
    u16 arp_hrd;
    u16 arp_pro;
    u16 arp_op;
    u8 arp_sha[ETH_ALEN];
    u8 arp_sip[4];
    u8 arp_tha[ETH_ALEN];
    u8 arp_tip[4];
    
    // Other protocol fields
    u16 other_ethertype;
    u8 other_data[32];
    
    // Debug fields to understand packet structure
    u16 skb_mac_header;
    u16 skb_network_header;
    u16 skb_transport_header;
    u32 skb_len;
    u32 skb_data_len;
    
    // Execution context debug fields
    u32 cpu_id;
    u32 tgid;
    u8 in_interrupt;
};

BPF_PERF_OUTPUT(packet_drops);

// Helper function to check if packet should be captured
static inline bool should_capture_packet(u16 protocol, u16 filter_protocol) {
    if (filter_protocol == 0) return true;  // Capture all
    if (filter_protocol == 0xFFFF) {
        // "other" protocols - not IP, ARP, RARP, IPv6, LLDP, Flow Control
        return !(protocol == ETH_P_IP || protocol == ETH_P_ARP || 
                protocol == ETH_P_RARP || protocol == ETH_P_IPV6 ||
                protocol == 0x88CC || protocol == 0x8808);
    }
    return protocol == filter_protocol;
}

// Helper function to filter interface in kernel space
static inline bool interface_filter(struct sk_buff *skb) {
    if (!INTERFACE_FILTER_ENABLED) {
        return true;  // No interface filtering
    }
    
    // Get device name from skb
    union name_buf real_devname = {};
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) != 0 || !dev) {
        return false;
    }
    if (bpf_probe_read(&real_devname, IFNAMSIZ, dev->name) != 0) {
        return false;
    }
    
    int key = 0;
    union name_buf *target_name = interface_map.lookup(&key);
    if (!target_name) {
        return false;
    }
    
    // Fast comparison using 128-bit integers
    if (target_name->name_int.hi != real_devname.name_int.hi || 
        target_name->name_int.lo != real_devname.name_int.lo) {
        return false;
    }
    
    return true;
}

int trace_kfree_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (skb == NULL) return 0;
    
    // Apply interface filter first (most efficient)
    if (!interface_filter(skb)) {
        return 0;
    }
    
    // Initialize packet data
    struct packet_data_t data = {};
    data.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid & 0xFFFFFFFF;
    data.tgid = pid_tgid >> 32;
    data.stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Get execution context information
    data.cpu_id = bpf_get_smp_processor_id();
    data.in_interrupt = (bpf_get_current_task() == 0) ? 1 : 0;
    
    // Get interface name
    struct net_device *dev;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_str(data.ifname, IFNAMSIZ, dev->name);
    }
    
    // Get SKB metadata for debugging
    u16 mac_header, network_header, transport_header;
    u32 skb_len, skb_data_len;
    
    if (bpf_probe_read(&mac_header, sizeof(mac_header), &skb->mac_header) == 0) {
        data.skb_mac_header = mac_header;
    }
    if (bpf_probe_read(&network_header, sizeof(network_header), &skb->network_header) == 0) {
        data.skb_network_header = network_header;
    }
    if (bpf_probe_read(&transport_header, sizeof(transport_header), &skb->transport_header) == 0) {
        data.skb_transport_header = transport_header;
    }
    if (bpf_probe_read(&skb_len, sizeof(skb_len), &skb->len) == 0) {
        data.skb_len = skb_len;
    }
    if (bpf_probe_read(&skb_data_len, sizeof(skb_data_len), &skb->data_len) == 0) {
        data.skb_data_len = skb_data_len;
    }
    
    // Try to get ethernet header using skb_mac_header if available
    unsigned char *mac_header_ptr = NULL;
    if (mac_header != (u16)~0U) {
        // mac_header is valid, use it
        unsigned char *skb_head;
        if (bpf_probe_read(&skb_head, sizeof(skb_head), &skb->head) == 0 && skb_head) {
            mac_header_ptr = skb_head + mac_header;
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
        // Can't find ethernet header, skip this packet
        return 0;
    }
    
    // Read Ethernet header
    struct ethhdr eth;
    if (bpf_probe_read(&eth, sizeof(eth), mac_header_ptr) < 0) {
        return 0;
    }
    
    data.eth_type = ntohs(eth.h_proto);
    
    // Copy MAC addresses
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        data.eth_src[i] = eth.h_source[i];
        data.eth_dst[i] = eth.h_dest[i];
    }
    
    // Handle VLAN - check if ethertype indicates VLAN
    unsigned char *network_header_ptr = mac_header_ptr + ETH_HLEN;
    u16 real_protocol = data.eth_type;
    
    if (data.eth_type == ETH_P_8021Q) {
        // This is a VLAN packet
        struct vlan_hdr vlan;
        if (bpf_probe_read(&vlan, sizeof(vlan), network_header_ptr) == 0) {
            u16 tci = ntohs(vlan.h_vlan_TCI);
            data.vlan_id = tci & 0x0FFF;
            data.vlan_priority = (tci >> 13) & 0x07;
            data.inner_protocol = ntohs(vlan.h_vlan_encapsulated_proto);
            data.has_vlan = 1;
            real_protocol = data.inner_protocol;
            network_header_ptr += 4; // Skip VLAN header
            
            // Check for double VLAN (QinQ)
            if (real_protocol == ETH_P_8021Q) {
                struct vlan_hdr inner_vlan;
                if (bpf_probe_read(&inner_vlan, sizeof(inner_vlan), network_header_ptr) == 0) {
                    // Update with inner VLAN info, keep outer VLAN in main fields
                    real_protocol = ntohs(inner_vlan.h_vlan_encapsulated_proto);
                    network_header_ptr += 4; // Skip inner VLAN header
                }
            }
        }
    }
    
    // Apply protocol filter
    if (!should_capture_packet(real_protocol, PROTOCOL_FILTER)) {
        return 0;
    }
    
    // Apply VLAN filter
    if (VLAN_FILTER > 0 && data.vlan_id != VLAN_FILTER) {
        return 0;
    }
    
    // Parse protocol-specific data based on real protocol
    if (real_protocol == ETH_P_IP) {
        data.protocol_type = 1;  // IPv4
        struct iphdr iph;
        if (bpf_probe_read(&iph, sizeof(iph), network_header_ptr) == 0) {
            data.ipv4_saddr = iph.saddr;
            data.ipv4_daddr = iph.daddr;
            data.ipv4_protocol = iph.protocol;

            // Check L4 protocol filter
            if (L4_PROTOCOL != 0 && data.ipv4_protocol != L4_PROTOCOL) {
                return 0;
            }
            data.ipv4_ttl = iph.ttl;
            data.ipv4_id = ntohs(iph.id);
            data.ipv4_tot_len = ntohs(iph.tot_len);
            data.ipv4_tos = iph.tos;
            
            // Check IP address filters
            if ((SRC_IP != 0 && data.ipv4_saddr != SRC_IP) ||
                (DST_IP != 0 && data.ipv4_daddr != DST_IP)) {
                return 0;
            }
            
            // Parse TCP/UDP ports
            if (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) {
                u8 ip_ihl = iph.ihl & 0x0F;
                unsigned char *transport_header_ptr = network_header_ptr + (ip_ihl * 4);
                
                if (iph.protocol == IPPROTO_TCP) {
                    struct tcphdr tcph;
                    if (bpf_probe_read(&tcph, sizeof(tcph), transport_header_ptr) == 0) {
                        data.ipv4_sport = ntohs(tcph.source);
                        data.ipv4_dport = ntohs(tcph.dest);
                    }
                } else {
                    struct udphdr udph;
                    if (bpf_probe_read(&udph, sizeof(udph), transport_header_ptr) == 0) {
                        data.ipv4_sport = ntohs(udph.source);
                        data.ipv4_dport = ntohs(udph.dest);
                    }
                }
                
                // Check port filters
                if ((SRC_PORT != 0 && data.ipv4_sport != SRC_PORT) ||
                    (DST_PORT != 0 && data.ipv4_dport != DST_PORT)) {
                    return 0;
                }
            }
        }
    } else if (real_protocol == ETH_P_IPV6) {
        data.protocol_type = 2;  // IPv6
        struct ipv6hdr ip6h;
        if (bpf_probe_read(&ip6h, sizeof(ip6h), network_header_ptr) == 0) {
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                data.ipv6_saddr[i] = ip6h.saddr.in6_u.u6_addr8[i];
                data.ipv6_daddr[i] = ip6h.daddr.in6_u.u6_addr8[i];
            }
            data.ipv6_nexthdr = ip6h.nexthdr;
            data.ipv6_hop_limit = ip6h.hop_limit;
            data.ipv6_payload_len = ntohs(ip6h.payload_len);

            // Check L4 protocol filter for IPv6
            if (L4_PROTOCOL != 0 && ip6h.nexthdr != L4_PROTOCOL) {
                return 0;
            }

            // Check IPv6 address filters (ip6h is already on stack, access directly)
            if (SRC_IPV6_HI != 0 || SRC_IPV6_LO != 0) {
                u64 *saddr_ptr = (u64 *)&ip6h.saddr;
                if (saddr_ptr[0] != SRC_IPV6_HI || saddr_ptr[1] != SRC_IPV6_LO) {
                    return 0;
                }
            }
            if (DST_IPV6_HI != 0 || DST_IPV6_LO != 0) {
                u64 *daddr_ptr = (u64 *)&ip6h.daddr;
                if (daddr_ptr[0] != DST_IPV6_HI || daddr_ptr[1] != DST_IPV6_LO) {
                    return 0;
                }
            }

            // Parse TCP/UDP ports for IPv6
            if (ip6h.nexthdr == IPPROTO_TCP || ip6h.nexthdr == IPPROTO_UDP) {
                unsigned char *transport_ptr = network_header_ptr + sizeof(struct ipv6hdr);

                if (ip6h.nexthdr == IPPROTO_TCP) {
                    struct tcphdr tcph;
                    if (bpf_probe_read(&tcph, sizeof(tcph), transport_ptr) == 0) {
                        data.ipv6_sport = ntohs(tcph.source);
                        data.ipv6_dport = ntohs(tcph.dest);
                    }
                } else {
                    struct udphdr udph;
                    if (bpf_probe_read(&udph, sizeof(udph), transport_ptr) == 0) {
                        data.ipv6_sport = ntohs(udph.source);
                        data.ipv6_dport = ntohs(udph.dest);
                    }
                }

                // Check port filters
                if ((SRC_PORT != 0 && data.ipv6_sport != SRC_PORT) ||
                    (DST_PORT != 0 && data.ipv6_dport != DST_PORT)) {
                    return 0;
                }
            }
        }
    } else if (real_protocol == ETH_P_ARP) {
        data.protocol_type = 3;  // ARP
        struct arphdr_custom arph;
        if (bpf_probe_read(&arph, sizeof(arph), network_header_ptr) == 0) {
            data.arp_hrd = ntohs(arph.ar_hrd);
            data.arp_pro = ntohs(arph.ar_pro);
            data.arp_op = ntohs(arph.ar_op);
            
            #pragma unroll
            for (int i = 0; i < ETH_ALEN; i++) {
                data.arp_sha[i] = arph.ar_sha[i];
                data.arp_tha[i] = arph.ar_tha[i];
            }
            
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                data.arp_sip[i] = arph.ar_sip[i];
                data.arp_tip[i] = arph.ar_tip[i];
            }
        }
    } else if (real_protocol == ETH_P_RARP) {
        data.protocol_type = 4;  // RARP
        struct arphdr_custom rarph;
        if (bpf_probe_read(&rarph, sizeof(rarph), network_header_ptr) == 0) {
            data.arp_hrd = ntohs(rarph.ar_hrd);
            data.arp_pro = ntohs(rarph.ar_pro);
            data.arp_op = ntohs(rarph.ar_op);
            
            #pragma unroll
            for (int i = 0; i < ETH_ALEN; i++) {
                data.arp_sha[i] = rarph.ar_sha[i];
                data.arp_tha[i] = rarph.ar_tha[i];
            }
            
            #pragma unroll
            for (int i = 0; i < 4; i++) {
                data.arp_sip[i] = rarph.ar_sip[i];
                data.arp_tip[i] = rarph.ar_tip[i];
            }
        }
    } else {
        data.protocol_type = 0;  // Other
        data.other_ethertype = real_protocol;
        
        // Read first 32 bytes of payload
        if (bpf_probe_read(&data.other_data, sizeof(data.other_data), network_header_ptr) < 0) {
            // If we can't read payload, just zero it
            #pragma unroll
            for (int i = 0; i < 32; i++) {
                data.other_data[i] = 0;
            }
        }
    }
    
    packet_drops.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Format the BPF program with our constants
interface_filter_enabled = 1 if interface_filter else 0

b = BPF(text=bpf_text % (
    src_ip_hex, dst_ip_hex, src_port, dst_port,
    protocol_filter, l4_protocol, vlan_filter, interface_filter_enabled,
    src_ipv6_hi, src_ipv6_lo, dst_ipv6_hi, dst_ipv6_lo
))

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

# Attach the kprobe
b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")

# No debug code needed

# Define ctypes structure for packet data
class PacketData(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("ifname", ct.c_char * 16),
        ("stack_id", ct.c_int32),
        
        # Ethernet fields
        ("eth_src", ct.c_uint8 * 6),
        ("eth_dst", ct.c_uint8 * 6),
        ("eth_type", ct.c_uint16),
        
        # VLAN fields
        ("vlan_id", ct.c_uint16),
        ("vlan_priority", ct.c_uint16),
        ("inner_protocol", ct.c_uint16),
        ("has_vlan", ct.c_uint8),
        
        # Protocol type
        ("protocol_type", ct.c_uint8),
        
        # IPv4 fields
        ("ipv4_saddr", ct.c_uint32),
        ("ipv4_daddr", ct.c_uint32),
        ("ipv4_protocol", ct.c_uint8),
        ("ipv4_sport", ct.c_uint16),
        ("ipv4_dport", ct.c_uint16),
        ("ipv4_ttl", ct.c_uint8),
        ("ipv4_id", ct.c_uint16),
        ("ipv4_tot_len", ct.c_uint16),
        ("ipv4_tos", ct.c_uint8),
        
        # IPv6 fields
        ("ipv6_saddr", ct.c_uint8 * 16),
        ("ipv6_daddr", ct.c_uint8 * 16),
        ("ipv6_nexthdr", ct.c_uint8),
        ("ipv6_hop_limit", ct.c_uint8),
        ("ipv6_payload_len", ct.c_uint16),
        ("ipv6_sport", ct.c_uint16),
        ("ipv6_dport", ct.c_uint16),
        
        # ARP fields
        ("arp_hrd", ct.c_uint16),
        ("arp_pro", ct.c_uint16),
        ("arp_op", ct.c_uint16),
        ("arp_sha", ct.c_uint8 * 6),
        ("arp_sip", ct.c_uint8 * 4),
        ("arp_tha", ct.c_uint8 * 6),
        ("arp_tip", ct.c_uint8 * 4),
        
        # Other protocol fields
        ("other_ethertype", ct.c_uint16),
        ("other_data", ct.c_uint8 * 32),
        
        # Debug fields
        ("skb_mac_header", ct.c_uint16),
        ("skb_network_header", ct.c_uint16),
        ("skb_transport_header", ct.c_uint16),
        ("skb_len", ct.c_uint32),
        ("skb_data_len", ct.c_uint32),
        
        # Execution context debug fields
        ("cpu_id", ct.c_uint32),
        ("tgid", ct.c_uint32),
        ("in_interrupt", ct.c_uint8),
    ]

def format_mac_address(mac_bytes):
    """Format MAC address from bytes"""
    return ":".join(["%02x" % b for b in mac_bytes])

def format_ip_address(ip_bytes):
    """Format IPv4 address from bytes"""
    return inet_ntop(AF_INET, pack("I", ip_bytes))

def format_ipv6_address(ip_bytes):
    """Format IPv6 address from bytes"""
    return inet_ntop(AF_INET6, bytes(ip_bytes))

def print_packet_event(cpu, data, size):
    """Print packet drop event"""
    global b
    event = ct.cast(data, ct.POINTER(PacketData)).contents
    
    # Skip normal patterns if not verbose
    if not args.disable_normal_filter and event.stack_id > 0:
        try:
            stack_trace = []
            stack_table = b.get_table("stack_traces")
            resolved_addrs = False
            for addr in stack_table.walk(event.stack_id):
                sym = b.ksym(addr, show_offset=True)
                # Convert to string safely for ARM compatibility
                stack_trace.append(safe_str(sym))
                resolved_addrs = True
            
            if resolved_addrs and is_normal_kfree_pattern(stack_trace):
                return
        except (KeyError, TypeError):
            # Handle both missing stack traces and type conversion errors
            # Don't skip the event if we can't check the pattern
            pass
    
    # Print timestamp and basic info
    timestamp = strftime("%H:%M:%S")
    print("[{}] PID: {} TGID: {} COMM: {} CPU: {}".format(
        timestamp, event.pid, event.tgid, safe_str(event.comm), event.cpu_id))
    
    # Print debug info if verbose
    if args.verbose:
        print("Debug Info:")
        print("  SKB Length: {} bytes, Data Length: {} bytes".format(event.skb_len, event.skb_data_len))
        print("  MAC Header Offset: {}, Network Header Offset: {}, Transport Header Offset: {}".format(
            event.skb_mac_header, event.skb_network_header, event.skb_transport_header))
        print("  Execution Context: CPU={}, PID={}, TGID={}, COMM={}".format(
            event.cpu_id, event.pid, event.tgid, safe_str(event.comm)))
        print("  Interrupt Context: in_interrupt={}".format(event.in_interrupt))
    
    # Print VLAN info if present
    vlan_prefix = ""
    if event.has_vlan:
        vlan_prefix = "[VLAN {}] ".format(event.vlan_id)
        print("VLAN ID: {}, Priority: {}, Inner Protocol: 0x{:04x}".format(
            event.vlan_id, event.vlan_priority, event.inner_protocol))
    
    # Print Ethernet header
    print("Ethernet Header:")
    print("  Source MAC: {}".format(format_mac_address(event.eth_src)))
    print("  Dest MAC:   {}".format(format_mac_address(event.eth_dst)))
    print("  EtherType:  0x{:04x}".format(event.eth_type))
    
    # Print protocol-specific information
    if event.protocol_type == 1:  # IPv4
        print("{}IPv4 PACKET".format(vlan_prefix))
        print("IPv4 Header:")
        print("  Version:    4")
        print("  ToS:        0x{:02x}".format(event.ipv4_tos))
        print("  Length:     {}".format(event.ipv4_tot_len))
        print("  ID:         0x{:04x}".format(event.ipv4_id))
        print("  TTL:        {}".format(event.ipv4_ttl))
        print("  Protocol:   {}".format(event.ipv4_protocol))
        print("  Source IP:  {}".format(format_ip_address(event.ipv4_saddr)))
        print("  Dest IP:    {}".format(format_ip_address(event.ipv4_daddr)))
        
        if event.ipv4_protocol in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
            proto_name = "TCP" if event.ipv4_protocol == socket.IPPROTO_TCP else "UDP"
            print("  {} Ports: {} -> {}".format(proto_name, event.ipv4_sport, event.ipv4_dport))
            
    elif event.protocol_type == 2:  # IPv6
        print("{}IPv6 PACKET".format(vlan_prefix))
        print("IPv6 Header:")
        print("  Version:     6")
        print("  Payload Len: {}".format(event.ipv6_payload_len))
        print("  Next Header: {}".format(event.ipv6_nexthdr))
        print("  Hop Limit:   {}".format(event.ipv6_hop_limit))
        print("  Source IP:   {}".format(format_ipv6_address(event.ipv6_saddr)))
        print("  Dest IP:     {}".format(format_ipv6_address(event.ipv6_daddr)))

        if event.ipv6_nexthdr in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
            proto_name = "TCP" if event.ipv6_nexthdr == socket.IPPROTO_TCP else "UDP"
            print("  {} Ports: {} -> {}".format(proto_name, event.ipv6_sport, event.ipv6_dport))
        
    elif event.protocol_type == 3:  # ARP
        print("{}ARP PACKET".format(vlan_prefix))
        print("ARP Header:")
        print("  Hardware Type: 0x{:04x}".format(event.arp_hrd))
        print("  Protocol Type: 0x{:04x}".format(event.arp_pro))
        op_str = {1: "Request", 2: "Reply"}.get(event.arp_op, "Unknown({})".format(event.arp_op))
        print("  Operation:     {}".format(op_str))
        print("  Sender MAC:    {}".format(format_mac_address(event.arp_sha)))
        print("  Sender IP:     {}".format(format_ip_address(unpack('I', bytes(bytearray(event.arp_sip)))[0])))
        print("  Target MAC:    {}".format(format_mac_address(event.arp_tha)))
        print("  Target IP:     {}".format(format_ip_address(unpack('I', bytes(bytearray(event.arp_tip)))[0])))
        
    elif event.protocol_type == 4:  # RARP
        print("{}RARP PACKET".format(vlan_prefix))
        print("RARP Header:")
        print("  Hardware Type: 0x{:04x}".format(event.arp_hrd))
        print("  Protocol Type: 0x{:04x}".format(event.arp_pro))
        op_str = {3: "Request", 4: "Reply"}.get(event.arp_op, "Unknown({})".format(event.arp_op))
        print("  Operation:     {}".format(op_str))
        print("  Sender MAC:    {}".format(format_mac_address(event.arp_sha)))
        print("  Sender IP:     {}".format(format_ip_address(unpack('I', bytes(bytearray(event.arp_sip)))[0])))
        print("  Target MAC:    {}".format(format_mac_address(event.arp_tha)))
        print("  Target IP:     {}".format(format_ip_address(unpack('I', bytes(bytearray(event.arp_tip)))[0])))
        
    else:  # Other protocols
        print("{}OTHER PROTOCOL".format(vlan_prefix))
        print("  EtherType: 0x{:04x}".format(event.other_ethertype))
        if args.verbose:
            print("  Payload (first 32 bytes): {}".format(' '.join(['%02x' % b for b in event.other_data])))
    
    # Print interface
    print("Interface: {}".format(safe_str(event.ifname)))
    
    # Print stack trace if enabled
    if not args.no_stack_trace:
        if event.stack_id <= 0:
            # Negative or zero stack_id means error or no stack trace
            print("Stack trace:")
            if event.stack_id == 0:
                print("  <No stack trace available>")
            elif event.stack_id == -14:
                print("  <Stack trace unavailable in current context (EFAULT)>")
            else:
                print("  <BPF get_stackid failed with error code: {}>".format(event.stack_id))
        else:
            print("Stack trace:")
            try:
                stack_table = b.get_table("stack_traces")
                resolved_symbols = False
                for addr in stack_table.walk(event.stack_id):
                    sym = b.ksym(addr, show_offset=True)
                    print("  {}".format(safe_str(sym)))
                    resolved_symbols = True
                
                if not resolved_symbols:
                    print("  <Stack trace walk for ID {} yielded no symbols>".format(event.stack_id))
                    
            except KeyError:
                print("  <stack_traces table not found>")
            except Exception as e:
                print("  <Error retrieving stack trace: {}>".format(e))
    
    print("-" * 80)

# Register the callback
b["packet_drops"].open_perf_buffer(print_packet_event)

print("Starting packet drop monitoring... Press Ctrl+C to stop")

# Main event loop
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopping packet drop monitoring...")
    sys.exit(0)
