#!/usr/bin/python2
# -*- coding: utf-8 -*-

from bcc import BPF
#from bpfcc import BPF
from socket import inet_ntop, AF_INET, inet_aton, htonl
from struct import pack, unpack
from time import strftime
import socket
import argparse
import ctypes as ct

# Devname structure for device filtering (same as tun_ring_monitor.py)
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

normal_patterns = {
    'icmp_rcv': ['icmp_rcv'],
    'tcp_v4_rcv': ['tcp_v4_rcv'],
    'skb_release_data': ['skb_release_data', '__kfree_skb', 'tcp_recvmsg']
}

def is_normal_kfree_pattern(stack_trace):
    if not stack_trace or len(stack_trace) < 2:
        return False
    
    last_func = stack_trace[-1]
    if 'kfree_skb' not in last_func:
        return False
    
    if len(stack_trace) >= 2:
        second_last_func = stack_trace[-2]
        for pattern_name, pattern_funcs in normal_patterns.items():
            if any(func in second_last_func for func in pattern_funcs):
                return True
    
    return False

def ip_to_hex(ip):
    return htonl(unpack("!I", inet_aton(ip))[0])

parser = argparse.ArgumentParser(description='Tracing network packets for specific IP addresses and ports')
parser.add_argument('--src', type=str, help='Source IP address to tracing (in dotted decimal notation)')
parser.add_argument('--dst', type=str, help='Destination IP address to tracing (in dotted decimal notation)')
parser.add_argument('--protocol', type=str, choices=['all', 'icmp', 'tcp', 'udp', 'arp', 'rarp', 'other'], default='all', help='Protocol to tracing')
parser.add_argument('--src-port', type=int, help='Source port to tracing (for TCP/UDP)')
parser.add_argument('--dst-port', type=int, help='Destination port to tracing (for TCP/UDP)')
parser.add_argument('--dev', type=str, help='Device name to filter (e.g., eth0, vnet12)')
args = parser.parse_args()

src_ip = args.src if args.src else "0.0.0.0"
dst_ip = args.dst if args.dst else "0.0.0.0"
src_port = args.src_port if args.src_port else 0
dst_port = args.dst_port if args.dst_port else 0

print("Monitoring source IP: {}".format(src_ip))
print("Monitoring destination IP: {}".format(dst_ip))
print("Protocol: {}".format(args.protocol))
if args.protocol in ['tcp', 'udp']:
    print("Source port: {}".format(src_port))
    print("Destination port: {}".format(dst_port))
if args.dev:
    print("Device filter: {}".format(args.dev))
else:
    print("Device filter: All devices")

src_ip_hex = ip_to_hex(src_ip)
dst_ip_hex = ip_to_hex(dst_ip)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_arp.h>

#define IFNAMSIZ 16
#define TASK_COMM_LEN 16

// Device name union for efficient comparison (from tun_ring_monitor.py)
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100   // 802.1Q VLAN protocol
#endif

// VLAN header structure
struct vlan_hdr {
    __be16 h_vlan_TCI;     // Tag Control Information
    __be16 h_vlan_encapsulated_proto; // Inner protocol
};

BPF_HASH(ipv4_count, u32, u64);
BPF_STACK_TRACE(stack_traces, 8192);  
BPF_ARRAY(name_map, union name_buf, 1);  // Device filter
#define SRC_IP 0x%x
#define DST_IP 0x%x
#define SRC_PORT %d
#define DST_PORT %d
#define PROTOCOL %d
#define FILTER_ARP %d
#define FILTER_RARP %d

// Device filter logic (from tun_ring_monitor.py)
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname;
    bpf_probe_read_kernel_str(real_devname.name, IFNAMSIZ, dev->name);

    int key=0;
    union name_buf *leaf = name_map.lookup(&key);
    if(!leaf){
        return 1;  // No filter set - accept all devices
    }
    if(leaf->name_int.hi == 0 && leaf->name_int.lo == 0){
        return 1;  // Empty filter - accept all devices
    }
    if(leaf->name_int.hi != real_devname.name_int.hi || leaf->name_int.lo != real_devname.name_int.lo){
        return 0;  // Device name doesn't match
    }

    return 1;  // Device name matches
}

struct dropped_skb_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    u32 raw_stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
    // ARP/RARP specific fields
    u16 eth_protocol;  // ETH_P_IP, ETH_P_ARP, ETH_P_RARP
    u16 arp_op;        // ARP operation code
    u32 arp_sip;       // ARP source IP
    u32 arp_tip;       // ARP target IP
    u8 eth_sha[6];     // Ethernet source hardware address
    u8 eth_tha[6];     // Ethernet target hardware address
    // VLAN specific fields
    u16 vlan_id;       // VLAN ID (12 bits)
    u16 vlan_priority; // VLAN priority (3 bits)
    u16 inner_protocol; // Inner protocol type for VLAN packets
};
BPF_PERF_OUTPUT(kfree_drops);

struct netif_receive_data_t {
    u32 pid;
    u64 ts;
    u16 eth_protocol;  // Original protocol (may be VLAN)
    u8 eth_sha[6];     // source hardware address
    u8 eth_tha[6];     // target hardware address
    u8 pfmemalloc;     // pfmemalloc parameter value
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
    // VLAN specific fields
    u16 vlan_id;       // VLAN ID (12 bits)
    u16 vlan_priority; // VLAN priority (3 bits)
    u16 inner_protocol; // Inner protocol type for VLAN packets
};
BPF_PERF_OUTPUT(netif_receive_events);

int trace_kfree_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (skb == NULL)
        return 0;

    // Get device and apply device filter first
    struct net_device *dev;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (!name_filter(dev)) {
        return 0;  // Device doesn't match filter, skip
    }

    // Advanced SKB parsing similar to icmp_rtt_latency.py and netif_receive_skb_core
    unsigned char *skb_head;
    if (bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0) {
        return 0;
    }
    if (!skb_head) {
        return 0;
    }
    
    unsigned long skb_data_ptr_val; 
    if (bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 0;
    }
    
    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);
    unsigned int mac_offset = data_offset; 
    
    // Read ethernet header from correct offset
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset) < 0) {
        return 0;
    }
    
    unsigned int net_offset = mac_offset + ETH_HLEN;
    __be16 h_proto = eth.h_proto;
    
    // Handle VLAN tags (single or double tagged)
    if (h_proto == htons(ETH_P_8021Q)) {
        net_offset += 4; // VLAN_HLEN = 4
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2) < 0) { 
            return 0;
        }
        // Check for double VLAN (QinQ)
        if (h_proto == htons(ETH_P_8021Q)) {
             net_offset += 4; // Another VLAN tag
             if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 6) < 0) {
                 return 0;
             }
        }
    }
    
    u16 protocol = h_proto;  // Real inner protocol after VLAN processing
    
    // Step 1: Determine the real protocol type (handle VLAN encapsulation)
    u16 real_protocol = protocol;  // This is already the inner protocol
    u16 vlan_id = 0;
    u16 vlan_priority = 0;
    bool is_vlan = false;
    
    if (eth.h_proto == htons(ETH_P_8021Q)) {
        // This is a VLAN packet, extract VLAN info
        is_vlan = true;
        struct vlan_hdr vlan;
        if (bpf_probe_read_kernel(&vlan, sizeof(vlan), skb_head + mac_offset + ETH_HLEN) < 0) {
            return 0;
        }
        
        // Extract VLAN ID and priority
        u16 tci = ntohs(vlan.h_vlan_TCI);
        vlan_id = tci & 0x0FFF;  // Lower 12 bits
        vlan_priority = (tci >> 13) & 0x07;  // Upper 3 bits
        
        real_protocol = vlan.h_vlan_encapsulated_proto;  // Inner protocol
    }
    
    // Step 2: Protocol filtering based on real protocol type
    if (FILTER_ARP == 1) {
        // Only ARP packets
        if (real_protocol != htons(ETH_P_ARP))
            return 0;
    } else if (FILTER_RARP == 1) {
        // Only RARP packets
        if (real_protocol != htons(ETH_P_RARP))
            return 0;
    } else {
        // Protocol filtering logic
        if (PROTOCOL != 0) {
            // If user specified a specific protocol, only capture that
            if (PROTOCOL == 0xFFFF) {
                // User wants "other" protocols - capture anything that is NOT IP, ARP, or RARP
                if (real_protocol == htons(ETH_P_IP) || real_protocol == htons(ETH_P_ARP) || real_protocol == htons(ETH_P_RARP))
                    return 0;
            } else if (real_protocol == htons(ETH_P_IP)) {
                // Continue with IP processing
            } else if (real_protocol == htons(ETH_P_ARP) || real_protocol == htons(ETH_P_RARP)) {
                // Continue with ARP/RARP processing  
            } else {
                // For other protocols, only capture if user wants "other"
                return 0;
            }
        }
        // If PROTOCOL == 0 (all), we capture everything including "other" protocols
    }

    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    struct dropped_skb_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.eth_protocol = ntohs(eth.h_proto);  // Original ethernet protocol (may be VLAN)
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.raw_stack_id = data.stack_id; 
    if (data.stack_id < 0) {
        data.stack_id = -data.stack_id; 
    }
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Set VLAN fields
    data.vlan_id = vlan_id;
    data.vlan_priority = vlan_priority;
    data.inner_protocol = is_vlan ? ntohs(real_protocol) : 0;

    // Copy MAC addresses from ethernet header
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        data.eth_sha[i] = eth.h_source[i];
        data.eth_tha[i] = eth.h_dest[i];
    }

    // Step 3: Process based on real protocol type
    if (real_protocol == htons(ETH_P_IP)) {
        // Handle IP packets (may be VLAN-encapsulated)
        struct iphdr iph;
        if (bpf_probe_read_kernel(&iph, sizeof(iph), skb_head + net_offset) < 0) {
            return 0;
        }
        data.saddr = iph.saddr;
        data.daddr = iph.daddr;
        data.protocol = iph.protocol;

        // Check IP addresses
        if ((SRC_IP == 0 || data.saddr == SRC_IP) && (DST_IP == 0 || data.daddr == DST_IP)) {
            // Check protocol (only for IP protocols, not ARP/RARP)
            if (PROTOCOL == 0 || (PROTOCOL < 256 && iph.protocol == PROTOCOL)) {
                if (iph.protocol == IPPROTO_ICMP) {
                    struct icmphdr icmph;
                    u8 ip_ihl = iph.ihl & 0x0F;
                    unsigned int trans_offset = net_offset + (ip_ihl * 4);
                    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), skb_head + trans_offset) < 0) {
                        return 0;
                    }
                    data.icmp_type = icmph.type;
                    data.icmp_code = icmph.code;
                    kfree_drops.perf_submit(ctx, &data, sizeof(data));
                } else if (iph.protocol == IPPROTO_TCP) {
                    struct tcphdr tcph;
                    u8 ip_ihl = iph.ihl & 0x0F;
                    unsigned int trans_offset = net_offset + (ip_ihl * 4);
                    if (bpf_probe_read_kernel(&tcph, sizeof(tcph), skb_head + trans_offset) < 0) {
                        return 0;
                    }
                    data.sport = ntohs(tcph.source);
                    data.dport = ntohs(tcph.dest);
                    if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                        kfree_drops.perf_submit(ctx, &data, sizeof(data));
                    }
                } else if (iph.protocol == IPPROTO_UDP) {
                    struct udphdr udph;
                    u8 ip_ihl = iph.ihl & 0x0F;
                    unsigned int trans_offset = net_offset + (ip_ihl * 4);
                    if (bpf_probe_read_kernel(&udph, sizeof(udph), skb_head + trans_offset) < 0) {
                        return 0;
                    }
                    data.sport = ntohs(udph.source);
                    data.dport = ntohs(udph.dest);
                    if ((SRC_PORT == 0 || data.sport == SRC_PORT) && (DST_PORT == 0 || data.dport == DST_PORT)) {
                        kfree_drops.perf_submit(ctx, &data, sizeof(data));
                    }
                } else {
                    // For other IP protocols, submit without port information
                    kfree_drops.perf_submit(ctx, &data, sizeof(data));
                }
            }
        }
    } else if (real_protocol == htons(ETH_P_ARP) || real_protocol == htons(ETH_P_RARP)) {
        // Handle ARP/RARP packets (may be VLAN-encapsulated)
        
        // Set dummy values for IP addresses
        data.saddr = 0;
        data.daddr = 0;
        data.arp_sip = 0;
        data.arp_tip = 0;
        data.arp_op = (real_protocol == htons(ETH_P_ARP)) ? 1 : 3;
        
        kfree_drops.perf_submit(ctx, &data, sizeof(data));
    } else {
        // Handle other protocol types
        
        // Set dummy values for IP addresses
        data.saddr = 0;
        data.daddr = 0;
        data.arp_sip = 0;
        data.arp_tip = 0;
        data.arp_op = 0;
        data.protocol = 0;
        
        kfree_drops.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

int trace____netif_receive_skb_core(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    bool pfmemalloc = (bool)PT_REGS_PARM2(ctx);
    
    if (skb == NULL)
        return 0;

    // Get device and apply device filter first
    struct net_device *dev;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (!name_filter(dev)) {
        return 0;  // Device doesn't match filter, skip
    }

    // Advanced SKB parsing similar to icmp_rtt_latency.py
    unsigned char *skb_head;
    if (bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0) {
        return 0;
    }
    if (!skb_head) {
        return 0;
    }
    
    unsigned long skb_data_ptr_val; 
    if (bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 0;
    }
    
    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);
    unsigned int mac_offset = data_offset; 
    
    // Read ethernet header from correct offset
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + mac_offset) < 0) {
        return 0;
    }
    
    unsigned int net_offset = mac_offset + ETH_HLEN;
    __be16 h_proto = eth.h_proto;
    
    // Handle VLAN tags (single or double tagged)
    if (h_proto == htons(ETH_P_8021Q)) {
        net_offset += 4; // VLAN_HLEN = 4
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 2) < 0) { 
            return 0;
        }
        // Check for double VLAN (QinQ)
        if (h_proto == htons(ETH_P_8021Q)) {
             net_offset += 4; // Another VLAN tag
             if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + mac_offset + ETH_HLEN + 6) < 0) {
                 return 0;
             }
        }
    }
    
    u16 protocol = h_proto;  // Real inner protocol after VLAN processing
    
    // Step 1: Determine the real protocol type (handle VLAN encapsulation)
    u16 real_protocol = protocol;  // This is already the inner protocol
    u16 vlan_id = 0;
    u16 vlan_priority = 0;
    bool is_vlan = false;
    
    if (eth.h_proto == htons(ETH_P_8021Q)) {
        // This is a VLAN packet, extract VLAN info
        is_vlan = true;
        struct vlan_hdr vlan;
        if (bpf_probe_read_kernel(&vlan, sizeof(vlan), skb_head + mac_offset + ETH_HLEN) < 0) {
            return 0;
        }
        
        // Extract VLAN ID and priority
        u16 tci = ntohs(vlan.h_vlan_TCI);
        vlan_id = tci & 0x0FFF;  // Lower 12 bits
        vlan_priority = (tci >> 13) & 0x07;  // Upper 3 bits
        
        real_protocol = vlan.h_vlan_encapsulated_proto;  // Inner protocol
    }
    
    // Step 2: Protocol filtering based on real protocol type (same as kfree_skb)
    if (FILTER_ARP == 1) {
        // Only ARP packets
        if (real_protocol != htons(ETH_P_ARP))
            return 0;
    } else if (FILTER_RARP == 1) {
        // Only RARP packets
        if (real_protocol != htons(ETH_P_RARP))
            return 0;
    } else {
        // Protocol filtering logic
        if (PROTOCOL != 0) {
            // If user specified a specific protocol, only capture that
            if (PROTOCOL == 0xFFFF) {
                // User wants "other" protocols - capture anything that is NOT IP, ARP, or RARP
                if (real_protocol == htons(ETH_P_IP) || real_protocol == htons(ETH_P_ARP) || real_protocol == htons(ETH_P_RARP))
                    return 0;
            } else if (real_protocol == htons(ETH_P_IP)) {
                // Continue with IP processing
            } else if (real_protocol == htons(ETH_P_ARP) || real_protocol == htons(ETH_P_RARP)) {
                // Continue with ARP/RARP processing  
            } else {
                // For other protocols, only capture if user wants "other"
                return 0;
            }
        }
        // If PROTOCOL == 0 (all), we capture everything including "other" protocols
    }

    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    struct netif_receive_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.eth_protocol = ntohs(eth.h_proto);  // Original ethernet protocol (may be VLAN)
    data.pfmemalloc = pfmemalloc ? 1 : 0;
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), ifname);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Set VLAN fields
    data.vlan_id = vlan_id;
    data.vlan_priority = vlan_priority;
    data.inner_protocol = is_vlan ? ntohs(real_protocol) : 0;

    // Copy MAC addresses from ethernet header
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        data.eth_sha[i] = eth.h_source[i];
        data.eth_tha[i] = eth.h_dest[i];
    }

    // Step 3: Process based on real protocol type (same as kfree_skb)
    bool should_submit = false;
    
    if (real_protocol == htons(ETH_P_IP)) {
        // Handle IP packets (may be VLAN-encapsulated) - need IP address filtering
        struct iphdr iph;
        if (bpf_probe_read_kernel(&iph, sizeof(iph), skb_head + net_offset) < 0) {
            return 0;
        }
        
        // Check IP addresses (same logic as kfree_skb)
        if ((SRC_IP == 0 || iph.saddr == SRC_IP) && (DST_IP == 0 || iph.daddr == DST_IP)) {
            // Check protocol (only for IP protocols, not ARP/RARP)
            if (PROTOCOL == 0 || (PROTOCOL < 256 && iph.protocol == PROTOCOL)) {
                should_submit = true;
            }
        }
    } else if (real_protocol == htons(ETH_P_ARP) || real_protocol == htons(ETH_P_RARP)) {
        // Handle ARP/RARP packets (may be VLAN-encapsulated) - always submit if filter matches
        should_submit = true;
    } else {
        // Handle other protocol types - always submit if filter matches
        should_submit = true;
    }

    if (should_submit) {
        netif_receive_events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}

"""
#b = BPF(text=bpf_text)
protocol_map = {'all': 0, 'icmp': socket.IPPROTO_ICMP, 'tcp': socket.IPPROTO_TCP, 'udp': socket.IPPROTO_UDP, 'arp': 0x0806, 'rarp': 0x8035, 'other': 0xFFFF}

# Set protocol filtering flags
if args.protocol == 'arp':
    protocol_num = 0  # Not used for ARP
    filter_arp = 1
    filter_rarp = 0
elif args.protocol == 'rarp':
    protocol_num = 0  # Not used for RARP
    filter_arp = 0
    filter_rarp = 1
elif args.protocol == 'other':
    protocol_num = 0xFFFF  # Special value to indicate "other" protocols
    filter_arp = 0
    filter_rarp = 0
elif args.protocol in protocol_map:
    protocol_num = protocol_map[args.protocol]
    filter_arp = 0
    filter_rarp = 0
else:
    protocol_num = 0
    filter_arp = 0
    filter_rarp = 0

b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_num, filter_arp, filter_rarp))
# if use xxx.c as bpf program which is not embeded in python code as text. 
#EBPF_FILE = "multi-probe.c"
#b = BPF(src_file = EBPF_FILE)

b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")
b.attach_kprobe(event="__netif_receive_skb_core", fn_name="trace____netif_receive_skb_core")

# Set device filter (from tun_ring_monitor.py approach)
devname_map = b["name_map"]
_name = Devname()
if args.dev:
    _name.name = args.dev.encode()
    devname_map[0] = _name
else:
    # Set empty filter to accept all devices
    _name.name = b""
    devname_map[0] = _name

def print_basic_skb_data(cpu, data, size, perf_event=""):
    global b
    event = b[perf_event].event(data)
    
    # Determine if this is a VLAN packet and get the real protocol
    is_vlan = (event.eth_protocol == 0x8100)
    real_protocol = event.inner_protocol if is_vlan else event.eth_protocol
    
    # Add VLAN prefix if applicable
    vlan_prefix = ""
    if is_vlan:
        vlan_prefix = "[VLAN %d] " % event.vlan_id
    
    # Process based on real protocol type
    if real_protocol == 0x0800:  # ETH_P_IP (IPv4)
        protocol_str = {socket.IPPROTO_ICMP: "ICMP", socket.IPPROTO_TCP: "TCP", socket.IPPROTO_UDP: "UDP"}.get(event.protocol, str(event.protocol))
        print("%-9s %-6d %-12s %s%s -> %s Protocol: %-4s" % (
            strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), vlan_prefix,
            inet_ntop(AF_INET, pack("I", event.saddr)),
            inet_ntop(AF_INET, pack("I", event.daddr)),
            protocol_str))
        
        if event.protocol == socket.IPPROTO_ICMP:
            print("ICMP Type: %-2d Code: %-2d" % (event.icmp_type, event.icmp_code))
        elif event.protocol in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
            print("Source Port: %-5d Destination Port: %-5d" % (event.sport, event.dport))
            
    elif real_protocol == 0x0806:  # ETH_P_ARP
        print("%-9s %-6d %-12s %sARP PACKET" % (
            strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), vlan_prefix))
        
        # Print MAC addresses from ethernet header
        src_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_sha[:6]])
        dst_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_tha[:6]])
        print("Source MAC: %-17s Destination MAC: %-17s" % (src_mac, dst_mac))
        
    elif real_protocol == 0x8035:  # ETH_P_RARP
        print("%-9s %-6d %-12s %sRARP PACKET" % (
            strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), vlan_prefix))
        
        # Print MAC addresses from ethernet header
        src_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_sha[:6]])
        dst_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_sha[:6]])
        print("Source MAC: %-17s Destination MAC: %-17s" % (src_mac, dst_mac))
    else:
        # Handle other protocol types
        if is_vlan:
            # This should not happen with our new logic, but handle just in case
            inner_protocol_str = "0x%04x" % real_protocol
            print("%-9s %-6d %-12s VLAN PACKET (VLAN ID: %d, Priority: %d, Inner: %s)" % (
                strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), 
                event.vlan_id, event.vlan_priority, inner_protocol_str))
        else:
            # Non-VLAN other protocols
            print("%-9s %-6d %-12s OTHER PROTOCOL (EtherType: 0x%04x)" % (
                strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), event.eth_protocol))
        
        # Print MAC addresses from ethernet header
        src_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_sha[:6]])
        dst_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_tha[:6]])
        print("Source MAC: %-17s Destination MAC: %-17s" % (src_mac, dst_mac))
    
    # Add VLAN details if applicable
    if is_vlan:
        print("VLAN ID: %-4d Priority: %-1d" % (event.vlan_id, event.vlan_priority))
    
    print("Device: %-16s" % event.ifname.decode('utf-8'))
    print("Stack ID: %d, Raw Stack ID: %d" % (event.stack_id, event.raw_stack_id))
    
    #for addr in b.get_table("stack_traces").walk(event.stack_id):
    #    sym = b.ksym(addr, show_offset=True)
    #    print("\t%s" % sym)
    if event.stack_id > 0:
        try:
            for addr in b.get_table("stack_traces").walk(event.stack_id):
                sym = b.ksym(addr, show_offset=True)
                print("\t%s" % sym)
        except KeyError:
            print("\tFailed to retrieve stack trace (ID: %d)" % event.stack_id)
    else:
        print("\tFailed to capture stack trace (Error code: %d)" % event.stack_id)

    print("")



def print_kfree_drop_event(cpu, data, size):
    global b
    event = b["kfree_drops"].event(data)
    
    if event.stack_id > 0:
        try:
            stack_trace = []
            for addr in b.get_table("stack_traces").walk(event.stack_id):
                sym = b.ksym(addr, show_offset=True)
                stack_trace.append(sym)
            
            if is_normal_kfree_pattern(stack_trace):
                return
        except KeyError:
            pass
    
    print_basic_skb_data(cpu, data, size, perf_event="kfree_drops")

def print_netif_receive_event(cpu, data, size):
    global b
    event = b["netif_receive_events"].event(data)
    
    # Determine if this is a VLAN packet and get the real protocol
    is_vlan = (event.eth_protocol == 0x8100)
    real_protocol = event.inner_protocol if is_vlan else event.eth_protocol
    
    # Add VLAN prefix if applicable
    vlan_prefix = ""
    if is_vlan:
        vlan_prefix = "[VLAN %d] " % event.vlan_id
    
    # Process based on real protocol type
    if real_protocol == 0x0800:  # ETH_P_IP (IPv4)
        print("%-9s %-6d %-12s %sIP RECEIVE (pfmemalloc=%d)" % (
            strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), 
            vlan_prefix, event.pfmemalloc))
    elif real_protocol == 0x0806:  # ETH_P_ARP
        print("%-9s %-6d %-12s %sARP RECEIVE (pfmemalloc=%d)" % (
            strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), 
            vlan_prefix, event.pfmemalloc))
    elif real_protocol == 0x8035:  # ETH_P_RARP
        print("%-9s %-6d %-12s %sRARP RECEIVE (pfmemalloc=%d)" % (
            strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), 
            vlan_prefix, event.pfmemalloc))
    else:
        # Handle other protocol types
        print("%-9s %-6d %-12s %sOTHER RECEIVE (EtherType: 0x%04x, pfmemalloc=%d)" % (
            strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8'), 
            vlan_prefix, real_protocol, event.pfmemalloc))
    
    # Print MAC addresses from ethernet header
    src_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_sha[:6]])
    dst_mac = ":".join(["%02x" % mac_byte for mac_byte in event.eth_tha[:6]])
    print("Source MAC: %-17s Destination MAC: %-17s" % (src_mac, dst_mac))
    
    # Add VLAN details if applicable
    if is_vlan:
        print("VLAN ID: %-4d Priority: %-1d" % (event.vlan_id, event.vlan_priority))
    
    print("Device: %-16s" % event.ifname.decode('utf-8'))
    print("")

b["kfree_drops"].open_perf_buffer(print_kfree_drop_event)
b["netif_receive_events"].open_perf_buffer(print_netif_receive_event)


while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
