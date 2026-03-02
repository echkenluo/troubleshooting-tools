#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
OVS Userspace Megaflow Tracker 
Parse Netlink messages completely in userspace with configurable filtering
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
import ctypes as ct
from socket import inet_ntop, inet_pton, AF_INET
from struct import pack, unpack
import struct
from time import strftime
import sys
import argparse

DEBUG_MODE = False

# Filter configuration structure
class FilterConfig:
    def __init__(self):
        self.eth_src = None
        self.eth_dst = None
        self.eth_type = None
        self.ip_src = None
        self.ip_dst = None
        self.ip_proto = None
        self.l4_src_port = None
        self.l4_dst_port = None
        self.enabled = False

FILTER_CONFIG = FilterConfig()

def mac_str_to_bytes(mac_str):
    return [int(x, 16) for x in mac_str.split(':')]

def ip_str_to_int(ip_str):
    """Convert IP string to integer"""
    return unpack('>I', inet_ntop(AF_INET, ip_str))[0] if ip_str else 0

bpf_text = """
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/sock.h>
#include <net/genetlink.h>

// Define ETH_ALEN if not defined
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct upcall_event_t {
    u64 kernel_timestamp;
    u32 pid;
    u32 portid;
    char comm[16];
    
    u8 eth_dst[6];
    u8 eth_src[6];
    u16 eth_type;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 ip_proto;
    u8 _pad1;
    u32 skb_mark;
    
    char dev_name[16];
    u32 parse_status;
};

struct flow_cmd_new_event_t {
    u64 kernel_timestamp;
    u32 pid;
    char comm[16];
    u32 netlink_portid;
    
    u32 skb_len;
    u32 data_len;
    u8 nlmsg_data[2048];
};

BPF_PERF_OUTPUT(upcall_events);
BPF_PERF_OUTPUT(flow_cmd_new_events);

static __always_inline int parse_eth_header(struct sk_buff *skb, struct upcall_event_t *event) {
    unsigned char *skb_head;
    if (bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0 || !skb_head) {
        return 1;
    }
    
    unsigned long skb_data_ptr_val; 
    if (bpf_probe_read_kernel(&skb_data_ptr_val, sizeof(skb_data_ptr_val), &skb->data) < 0) {
        return 1;
    }
    
    unsigned int data_offset = (unsigned int)(skb_data_ptr_val - (unsigned long)skb_head);
    unsigned int ip_offset = data_offset + sizeof(struct ethhdr);
    
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + data_offset) < 0) {
        return 1;
    }
    
    __builtin_memcpy(event->eth_dst, eth.h_dest, ETH_ALEN);
    __builtin_memcpy(event->eth_src, eth.h_source, ETH_ALEN);
    event->eth_type = ntohs(eth.h_proto);
    
    event->src_ip = 0;
    event->dst_ip = 0;
    event->src_port = 0;
    event->dst_port = 0;
    event->ip_proto = 0;
    
    // Handle VLAN tagged packets
    if (event->eth_type == 0x8100 || event->eth_type == 0x88a8) {
        struct vlan_hdr vlan;
        if (bpf_probe_read_kernel(&vlan, sizeof(vlan), skb_head + ip_offset) == 0) {
            // Update eth_type to the encapsulated protocol
            event->eth_type = ntohs(vlan.h_vlan_encapsulated_proto);
            ip_offset += sizeof(struct vlan_hdr);
        }
    }
    
    // Parse IP header if present
    if (event->eth_type == 0x0800) {
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), skb_head + ip_offset) == 0) {
            event->src_ip = ntohl(ip.saddr);
            event->dst_ip = ntohl(ip.daddr);
            event->ip_proto = ip.protocol;
            
            // Parse L4 ports if TCP or UDP
            if (ip.protocol == 6) {  // TCP
                struct tcphdr tcp;
                if (bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + ip_offset + (ip.ihl * 4)) == 0) {
                    event->src_port = ntohs(tcp.source);
                    event->dst_port = ntohs(tcp.dest);
                }
            } else if (ip.protocol == 17) {  // UDP
                struct udphdr udp;
                if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + ip_offset + (ip.ihl * 4)) == 0) {
                    event->src_port = ntohs(udp.source);
                    event->dst_port = ntohs(udp.dest);
                }
            }
        }
    }
    
    return 0;
}

int trace_ovs_dp_upcall(struct pt_regs *ctx)
{
    struct datapath *dp = (struct datapath *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    void *key_ptr = (void *)PT_REGS_PARM3(ctx);
    void *upcall_info = (void *)PT_REGS_PARM4(ctx);
    
    if (!key_ptr || !skb) {
        return 0;
    }
    
    struct upcall_event_t event;
    __builtin_memset(&event, 0, sizeof(event));
    
    event.kernel_timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.portid = 0;
    
    if (upcall_info) {
        bpf_probe_read_kernel(&event.portid, sizeof(u32), upcall_info);
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    event.parse_status = parse_eth_header(skb, &event);
    
    bpf_probe_read_kernel(&event.skb_mark, sizeof(u32), &skb->mark);
    
    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev) {
        bpf_probe_read_kernel_str(&event.dev_name, sizeof(event.dev_name), &dev->name);
    }
    
    upcall_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

BPF_PERCPU_ARRAY(flow_event_buf, struct flow_cmd_new_event_t, 1);

int trace_ovs_flow_cmd_new(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct genl_info *info = (struct genl_info *)PT_REGS_PARM2(ctx);
    
    if (!skb || !info) {
        return 0;
    }
    
    u32 key = 0;
    struct flow_cmd_new_event_t *event = flow_event_buf.lookup(&key);
    if (!event) {
        return 0;
    }
    
    event->kernel_timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->netlink_portid = 0;
    event->skb_len = 0;
    event->data_len = 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_probe_read_kernel(&event->netlink_portid, sizeof(event->netlink_portid), &info->snd_portid);
    
    bpf_probe_read_kernel(&event->skb_len, sizeof(event->skb_len), &skb->len);
    
    unsigned char *skb_data = NULL;
    if (bpf_probe_read_kernel(&skb_data, sizeof(skb_data), &skb->data) == 0 && skb_data) {
        u32 copy_len = event->skb_len > 2048 ? 2048 : event->skb_len;
        event->data_len = copy_len;
        
        if (copy_len > 0 && copy_len <= 2048) {
            bpf_probe_read_kernel(event->nlmsg_data, copy_len, skb_data);
        }
    }
    
    flow_cmd_new_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
"""

class UpcallEvent(ct.Structure):
    _fields_ = [
        ("kernel_timestamp", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("portid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("eth_dst", ct.c_ubyte * 6),
        ("eth_src", ct.c_ubyte * 6),
        ("eth_type", ct.c_uint16),
        ("src_ip", ct.c_uint32),
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
        ("ip_proto", ct.c_uint8),
        ("_pad1", ct.c_uint8),
        ("skb_mark", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("parse_status", ct.c_uint32),
    ]

class FlowCmdNewEvent(ct.Structure):
    _fields_ = [
        ("kernel_timestamp", ct.c_ulonglong),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("netlink_portid", ct.c_uint32),
        ("skb_len", ct.c_uint32),
        ("data_len", ct.c_uint32),
        ("nlmsg_data", ct.c_ubyte * 2048),
    ]

stats = {'upcalls': 0, 'flows': 0, 'filtered_upcalls': 0, 'filtered_flows': 0}

# Netlink parsing constants (reference dpif_nl_exec_monitor.py)
OVS_FLOW_ATTR_UNSPEC = 0
OVS_FLOW_ATTR_KEY = 1
OVS_FLOW_ATTR_ACTIONS = 2
OVS_FLOW_ATTR_STATS = 3
OVS_FLOW_ATTR_TCP_FLAGS = 4
OVS_FLOW_ATTR_USED = 5
OVS_FLOW_ATTR_CLEAR = 6
OVS_FLOW_ATTR_MASK = 7
OVS_FLOW_ATTR_PROBE = 8
OVS_FLOW_ATTR_UFID = 9
OVS_FLOW_ATTR_UFID_FLAGS = 10
OVS_FLOW_ATTR_PAD = 11

OVS_KEY_ATTR_UNSPEC = 0
OVS_KEY_ATTR_ENCAP = 1
OVS_KEY_ATTR_PRIORITY = 2
OVS_KEY_ATTR_IN_PORT = 3
OVS_KEY_ATTR_ETHERNET = 4
OVS_KEY_ATTR_VLAN = 5
OVS_KEY_ATTR_ETHERTYPE = 6
OVS_KEY_ATTR_IPV4 = 7
OVS_KEY_ATTR_IPV6 = 8
OVS_KEY_ATTR_TCP = 9
OVS_KEY_ATTR_UDP = 10
OVS_KEY_ATTR_ICMP = 11
OVS_KEY_ATTR_ICMPV6 = 12
OVS_KEY_ATTR_ARP = 13
OVS_KEY_ATTR_ND = 14
OVS_KEY_ATTR_SKB_MARK = 15
OVS_KEY_ATTR_TUNNEL = 16
OVS_KEY_ATTR_SCTP = 17
OVS_KEY_ATTR_TCP_FLAGS = 18
OVS_KEY_ATTR_DP_HASH = 19
OVS_KEY_ATTR_RECIRC_ID = 20

# OVS Action constants
OVS_ACTION_ATTR_UNSPEC = 0
OVS_ACTION_ATTR_OUTPUT = 1
OVS_ACTION_ATTR_USERSPACE = 2
OVS_ACTION_ATTR_SET = 3
OVS_ACTION_ATTR_PUSH_VLAN = 4
OVS_ACTION_ATTR_POP_VLAN = 5
OVS_ACTION_ATTR_SAMPLE = 6
OVS_ACTION_ATTR_RECIRC = 7
OVS_ACTION_ATTR_HASH = 8
OVS_ACTION_ATTR_PUSH_MPLS = 9
OVS_ACTION_ATTR_POP_MPLS = 10
OVS_ACTION_ATTR_SET_MASKED = 11
OVS_ACTION_ATTR_CT = 12
OVS_ACTION_ATTR_TRUNC = 13
OVS_ACTION_ATTR_PUSH_ETH = 14
OVS_ACTION_ATTR_POP_ETH = 15
OVS_ACTION_ATTR_CT_CLEAR = 16
OVS_ACTION_ATTR_PUSH_NSH = 17
OVS_ACTION_ATTR_POP_NSH = 18
OVS_ACTION_ATTR_METER = 19
OVS_ACTION_ATTR_CLONE = 20
OVS_ACTION_ATTR_CHECK_PKT_LEN = 21
OVS_ACTION_ATTR_ADD_MPLS = 22
OVS_ACTION_ATTR_DEC_TTL = 23

# Userspace action sub-attributes
OVS_USERSPACE_ATTR_UNSPEC = 0
OVS_USERSPACE_ATTR_PID = 1
OVS_USERSPACE_ATTR_USERDATA = 2
OVS_USERSPACE_ATTR_EGRESS_TUN_PORT = 3
OVS_USERSPACE_ATTR_ACTIONS = 4

def mac_bytes_to_str(mac_bytes):
    return ':'.join(['%02x' % (ord(b) if isinstance(b, str) else b) for b in mac_bytes])

def ip_to_str(ip):
    return inet_ntop(AF_INET, pack('I', ip))

def format_kernel_timestamp(ns_timestamp):
    """Display raw kernel timestamp (nanoseconds) directly"""
    return str(ns_timestamp)

def decode_nlm_tlvs(data, offset):
    """Parse Netlink TLV structure (reference dpif_nl_exec_monitor.py)"""
    tlvs = {}
    
    while offset + 4 <= len(data):
        if offset + 4 > len(data):
            break
        
        try:
            length_bytes = data[offset:offset+2]
            type_bytes = data[offset+2:offset+4]
            
            if len(length_bytes) < 2 or len(type_bytes) < 2:
                break
                
            length = unpack('<H', length_bytes)[0]
            attr_type = unpack('<H', type_bytes)[0]
        except (struct.error, IndexError):
            break
        
        if length < 4 or offset + length > len(data):
            break
            
        attr_data = data[offset+4:offset+length]
        tlvs[attr_type] = attr_data
        
        offset += ((length + 3) // 4) * 4
        
    return tlvs

def parse_ovs_key_ethernet(data):
    """Parse OVS_KEY_ATTR_ETHERNET"""
    if len(data) < 12:
        return None
    
    try:
        eth_src = data[0:6]
        eth_dst = data[6:12]
        result = {
            'eth_src': mac_bytes_to_str(eth_src),
            'eth_dst': mac_bytes_to_str(eth_dst)
        }
        return result
    except Exception as e:
        return None

def parse_ovs_key_ipv4(data):
    """Parse OVS_KEY_ATTR_IPV4"""
    if len(data) < 12:
        return None
        
    return {
        'src_ip': inet_ntop(AF_INET, data[0:4]),
        'dst_ip': inet_ntop(AF_INET, data[4:8]),
        'proto': unpack('B', data[8:9])[0],
        'tos': unpack('B', data[9:10])[0],
        'ttl': unpack('B', data[10:11])[0],
        'frag': unpack('B', data[11:12])[0]
    }

def parse_ovs_key_tcp(data):
    """Parse OVS_KEY_ATTR_TCP"""
    if len(data) < 4:
        return None
        
    src_port = unpack('>H', data[0:2])[0]
    dst_port = unpack('>H', data[2:4])[0]
    
    return {
        'src_port': src_port,
        'dst_port': dst_port
    }

def parse_ovs_key_udp(data):
    """Parse OVS_KEY_ATTR_UDP"""
    if len(data) < 4:
        return None
        
    src_port = unpack('>H', data[0:2])[0]
    dst_port = unpack('>H', data[2:4])[0]
    
    return {
        'src_port': src_port,
        'dst_port': dst_port
    }

def parse_ovs_key_attributes(key_data):
    """Parse OVS key attributes"""
    try:
        key_attrs = decode_nlm_tlvs(key_data, 0)
        result = {}
        
        for attr_type, attr_data in key_attrs.items():
            try:
                
                if attr_type == OVS_KEY_ATTR_RECIRC_ID:
                    if len(attr_data) >= 4:
                        result['recirc_id'] = unpack('<I', attr_data[0:4])[0]
                elif attr_type == OVS_KEY_ATTR_SKB_MARK:
                    if len(attr_data) >= 4:
                        result['skb_mark'] = unpack('<I', attr_data[0:4])[0]
                elif attr_type == OVS_KEY_ATTR_IN_PORT:
                    if len(attr_data) >= 4:
                        result['in_port'] = unpack('<I', attr_data[0:4])[0]
                elif attr_type == OVS_KEY_ATTR_ETHERNET:
                    eth = parse_ovs_key_ethernet(attr_data)
                    if eth:
                        result['ethernet'] = eth
                elif attr_type == OVS_KEY_ATTR_ETHERTYPE:
                    if len(attr_data) >= 2:
                        result['eth_type'] = unpack('>H', attr_data[0:2])[0]
                elif attr_type == OVS_KEY_ATTR_IPV4:
                    ipv4 = parse_ovs_key_ipv4(attr_data)
                    if ipv4:
                        result['ipv4'] = ipv4
                elif attr_type == OVS_KEY_ATTR_TCP:
                    tcp = parse_ovs_key_tcp(attr_data)
                    if tcp:
                        result['tcp'] = tcp
                elif attr_type == OVS_KEY_ATTR_UDP:
                    udp = parse_ovs_key_udp(attr_data)
                    if udp:
                        result['udp'] = udp
            except Exception as e:
                continue
        
        return result
    except Exception as e:
        return {}

def parse_ovs_userspace_action(data):
    """Parse userspace action details"""
    result = {}
    userspace_attrs = decode_nlm_tlvs(data, 0)
    
    for attr_type, attr_data in userspace_attrs.items():
        if attr_type == OVS_USERSPACE_ATTR_PID:
            if len(attr_data) >= 4:
                result['pid'] = unpack('<I', attr_data[0:4])[0]
        elif attr_type == OVS_USERSPACE_ATTR_USERDATA:
            result['userdata_len'] = len(attr_data)
    
    return result

def parse_ovs_actions(actions_data):
    """Parse OVS actions"""
    try:
        actions = []
        action_attrs = decode_nlm_tlvs(actions_data, 0)
        
        for action_type, action_data in action_attrs.items():
            try:
                if action_type == OVS_ACTION_ATTR_OUTPUT:
                    if len(action_data) >= 4:
                        port = unpack('<I', action_data[0:4])[0]
                        actions.append({'type': 'OUTPUT', 'port': port})
                elif action_type == OVS_ACTION_ATTR_USERSPACE:
                    userspace_info = parse_ovs_userspace_action(action_data)
                    actions.append({'type': 'USERSPACE', 'info': userspace_info})
                elif action_type == OVS_ACTION_ATTR_RECIRC:
                    if len(action_data) >= 4:
                        recirc_id = unpack('<I', action_data[0:4])[0]
                        actions.append({'type': 'RECIRC', 'recirc_id': recirc_id})
                elif action_type == OVS_ACTION_ATTR_SET:
                    set_attrs = parse_ovs_key_attributes(action_data)
                    actions.append({'type': 'SET', 'attrs': set_attrs})
                elif action_type == OVS_ACTION_ATTR_SET_MASKED:
                    actions.append({'type': 'SET_MASKED', 'data_len': len(action_data)})
                elif action_type == OVS_ACTION_ATTR_PUSH_VLAN:
                    if len(action_data) >= 4:
                        tci = unpack('>H', action_data[2:4])[0]
                        actions.append({'type': 'PUSH_VLAN', 'tci': tci})
                elif action_type == OVS_ACTION_ATTR_POP_VLAN:
                    actions.append({'type': 'POP_VLAN'})
                elif action_type == OVS_ACTION_ATTR_SAMPLE:
                    actions.append({'type': 'SAMPLE', 'data_len': len(action_data)})
                elif action_type == OVS_ACTION_ATTR_CT:
                    actions.append({'type': 'CT', 'data_len': len(action_data)})
                elif action_type == OVS_ACTION_ATTR_TRUNC:
                    if len(action_data) >= 4:
                        max_len = unpack('<I', action_data[0:4])[0]
                        actions.append({'type': 'TRUNC', 'max_len': max_len})
                else:
                    actions.append({'type': 'UNKNOWN_%d' % action_type, 'data_len': len(action_data)})
            except Exception as e:
                continue
        
        return actions
    except Exception as e:
        return []

def parse_netlink_flow_message(nlmsg_data, data_len):
    """Parse complete Netlink flow message"""
    result = {
        'key': None,
        'mask': None,
        'actions': None,
        'parse_ok': False
    }
    
    if data_len < 16:
        result['parse_error'] = 'Data too short: %d bytes' % data_len
        return result
    
    try:
        if hasattr(nlmsg_data, '__getitem__'):
            data_bytes = b''.join([chr(b) if isinstance(b, int) else b for b in nlmsg_data[:data_len]])
        else:
            data_bytes = nlmsg_data[:data_len]
        
        if len(data_bytes) < 16:
            result['parse_error'] = 'Insufficient data for Netlink header'
            return result
            
        nl_len = unpack('<I', data_bytes[0:4])[0]
        
        offset = 24
        
        if offset >= len(data_bytes):
            result['parse_error'] = 'Offset %d >= data length %d' % (offset, len(data_bytes))
            return result
        
        flow_attrs = decode_nlm_tlvs(data_bytes, offset)
        
        if not flow_attrs:
            result['parse_error'] = 'No flow attributes found'
            return result
        
        for attr_type, attr_data in flow_attrs.items():
            if attr_type == OVS_FLOW_ATTR_KEY:
                result['key'] = parse_ovs_key_attributes(attr_data)
            elif attr_type == OVS_FLOW_ATTR_MASK:
                result['mask'] = parse_ovs_key_attributes(attr_data)
            elif attr_type == OVS_FLOW_ATTR_ACTIONS:
                result['actions'] = parse_ovs_actions(attr_data)
        
        result['parse_ok'] = True
        
    except Exception as e:
        result['parse_error'] = 'Exception: %s' % str(e)
    
    return result

def matches_filter_upcall(event):
    """Check if upcall event matches filter conditions"""
    if not FILTER_CONFIG.enabled:
        return True
        
    if event.parse_status != 0:
        return False
    
    if FILTER_CONFIG.eth_src:
        current_mac = mac_bytes_to_str(event.eth_src)
        if current_mac != FILTER_CONFIG.eth_src:
            return False
    
    if FILTER_CONFIG.eth_dst:
        current_mac = mac_bytes_to_str(event.eth_dst)
        if current_mac != FILTER_CONFIG.eth_dst:
            return False
    
    if FILTER_CONFIG.eth_type is not None:
        if event.eth_type != FILTER_CONFIG.eth_type:
            return False
    
    if FILTER_CONFIG.ip_src is not None:
        if event.src_ip != FILTER_CONFIG.ip_src:
            return False
    
    if FILTER_CONFIG.ip_dst is not None:
        if event.dst_ip != FILTER_CONFIG.ip_dst:
            return False
    
    if FILTER_CONFIG.ip_proto is not None:
        if event.ip_proto != FILTER_CONFIG.ip_proto:
            return False
    
    if FILTER_CONFIG.l4_src_port is not None:
        if event.src_port != FILTER_CONFIG.l4_src_port:
            return False
    
    if FILTER_CONFIG.l4_dst_port is not None:
        if event.dst_port != FILTER_CONFIG.l4_dst_port:
            return False
    
    return True

def matches_filter_flow(parsed_flow, debug_info=None):
    """Check if parsed flow matches filter conditions"""
    if debug_info is None:
        debug_info = {}
    
    if not FILTER_CONFIG.enabled:
        return True
        
    if not parsed_flow['parse_ok'] or not parsed_flow['key']:
        debug_info['reason'] = 'parse_failed_or_no_key'
        return False
    
    key = parsed_flow['key']
    
    if FILTER_CONFIG.eth_src:
        if 'ethernet' not in key:
            debug_info['reason'] = 'no_ethernet_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        current_mac = key['ethernet']['eth_src']
        if current_mac != FILTER_CONFIG.eth_src:
            debug_info['reason'] = 'eth_src_mismatch'
            debug_info['expected'] = FILTER_CONFIG.eth_src
            debug_info['actual'] = current_mac
            return False
    
    if FILTER_CONFIG.eth_dst:
        if 'ethernet' not in key:
            debug_info['reason'] = 'no_ethernet_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        current_mac = key['ethernet']['eth_dst']
        if current_mac != FILTER_CONFIG.eth_dst:
            debug_info['reason'] = 'eth_dst_mismatch'
            debug_info['expected'] = FILTER_CONFIG.eth_dst
            debug_info['actual'] = current_mac
            return False
    
    if FILTER_CONFIG.eth_type is not None:
        if 'eth_type' not in key:
            debug_info['reason'] = 'no_eth_type_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        current_type = key['eth_type']
        if current_type != FILTER_CONFIG.eth_type:
            debug_info['reason'] = 'eth_type_mismatch'
            debug_info['expected'] = '0x%04x' % FILTER_CONFIG.eth_type
            debug_info['actual'] = '0x%04x' % current_type
            return False
    
    if FILTER_CONFIG.ip_src is not None:
        if 'ipv4' not in key:
            debug_info['reason'] = 'no_ipv4_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        current_ip = key['ipv4']['src_ip']
        expected_ip = inet_ntop(AF_INET, pack('>I', FILTER_CONFIG.ip_src))
        if current_ip != expected_ip:
            debug_info['reason'] = 'ip_src_mismatch'
            debug_info['expected'] = expected_ip
            debug_info['actual'] = current_ip
            return False
    
    if FILTER_CONFIG.ip_dst is not None:
        if 'ipv4' not in key:
            debug_info['reason'] = 'no_ipv4_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        current_ip = key['ipv4']['dst_ip']
        expected_ip = inet_ntop(AF_INET, pack('>I', FILTER_CONFIG.ip_dst))
        if current_ip != expected_ip:
            debug_info['reason'] = 'ip_dst_mismatch'
            debug_info['expected'] = expected_ip
            debug_info['actual'] = current_ip
            return False
    
    if FILTER_CONFIG.ip_proto is not None:
        if 'ipv4' not in key:
            debug_info['reason'] = 'no_ipv4_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        current_proto = key['ipv4']['proto']
        if current_proto != FILTER_CONFIG.ip_proto:
            debug_info['reason'] = 'ip_proto_mismatch'
            debug_info['expected'] = FILTER_CONFIG.ip_proto
            debug_info['actual'] = current_proto
            return False
    
    if FILTER_CONFIG.l4_src_port is not None:
        port_found = False
        current_port = None
        if 'tcp' in key:
            current_port = key['tcp']['src_port']
            port_found = True
        elif 'udp' in key:
            current_port = key['udp']['src_port']
            port_found = True
        
        if not port_found:
            debug_info['reason'] = 'no_l4_port_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        
        if current_port != FILTER_CONFIG.l4_src_port:
            debug_info['reason'] = 'l4_src_port_mismatch'
            debug_info['expected'] = FILTER_CONFIG.l4_src_port
            debug_info['actual'] = current_port
            return False
    
    if FILTER_CONFIG.l4_dst_port is not None:
        port_found = False
        current_port = None
        if 'tcp' in key:
            current_port = key['tcp']['dst_port']
            port_found = True
        elif 'udp' in key:
            current_port = key['udp']['dst_port']
            port_found = True
        
        if not port_found:
            debug_info['reason'] = 'no_l4_port_field'
            debug_info['available_fields'] = list(key.keys())
            return False
        
        if current_port != FILTER_CONFIG.l4_dst_port:
            debug_info['reason'] = 'l4_dst_port_mismatch'
            debug_info['expected'] = FILTER_CONFIG.l4_dst_port
            debug_info['actual'] = current_port
            return False
    
    debug_info['reason'] = 'match'
    return True

def handle_upcall_event(cpu, data, size):
    global stats
    event = ct.cast(data, ct.POINTER(UpcallEvent)).contents
    stats['upcalls'] += 1
    
    matches_filter = matches_filter_upcall(event)
    
    if not matches_filter and not DEBUG_MODE:
        return
    
    if matches_filter:
        stats['filtered_upcalls'] += 1
    
    title = "UPCALL EVENT"
    if matches_filter:
        title += " (filtered)"
    elif DEBUG_MODE:
        title += " (debug - no match)"
    
    print("\\n=== %s ===" % title)
    print("Time: %s (kernel: %s)" % (strftime('%H:%M:%S'), format_kernel_timestamp(event.kernel_timestamp)))
    print("Process: %s (PID: %d)" % (event.comm.decode('utf-8', 'replace'), event.pid))
    print("PortID: %u, Device: %s" % (event.portid, event.dev_name.decode('utf-8', 'replace')))
    print("SKB Mark: 0x%x" % event.skb_mark)
    print("SKB Eth: %s -> %s, type=0x%04x" % (
        mac_bytes_to_str(event.eth_src), mac_bytes_to_str(event.eth_dst), event.eth_type))
    
    # Show IP and port information if available
    if event.eth_type == 0x0800 and (event.src_ip != 0 or event.dst_ip != 0):
        src_ip_str = inet_ntop(AF_INET, pack('>I', event.src_ip)) if event.src_ip != 0 else "0.0.0.0"
        dst_ip_str = inet_ntop(AF_INET, pack('>I', event.dst_ip)) if event.dst_ip != 0 else "0.0.0.0"
        proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(event.ip_proto, str(event.ip_proto)) if event.ip_proto != 0 else "UNKNOWN"
        
        if event.src_port != 0 or event.dst_port != 0:
            print("SKB IP: %s:%d -> %s:%d (%s)" % (
                src_ip_str, event.src_port, dst_ip_str, event.dst_port, proto_name))
        else:
            print("SKB IP: %s -> %s (%s)" % (src_ip_str, dst_ip_str, proto_name))
    elif event.eth_type == 0x0806:
        print("SKB ARP: Request/Reply packet (no IP/port info)")
    elif event.eth_type == 0x8100:
        print("SKB VLAN: Tagged packet (VLAN parsing not implemented)")
    
    # Debug mode: show all parsed fields
    if DEBUG_MODE:
        print("Debug Fields:")
        print("  Parse Status: %d" % event.parse_status)
        print("  Ethernet Type: 0x%04x (%s)" % (event.eth_type, 
            {0x0800: "IPv4", 0x0806: "ARP", 0x8100: "VLAN", 0x86dd: "IPv6"}.get(event.eth_type, "Unknown")))
        
        # Only show IP fields for IPv4 packets
        if event.eth_type == 0x0800:
            print("  IP Protocol: %d" % event.ip_proto)
            print("  Source IP: %s (0x%08x)" % (inet_ntop(AF_INET, pack('>I', event.src_ip)) if event.src_ip != 0 else "0.0.0.0", event.src_ip))
            print("  Dest IP: %s (0x%08x)" % (inet_ntop(AF_INET, pack('>I', event.dst_ip)) if event.dst_ip != 0 else "0.0.0.0", event.dst_ip))
            print("  Source Port: %d" % event.src_port)
            print("  Dest Port: %d" % event.dst_port)
        
        if not matches_filter:
            print("  Filter Status: Does not match filter conditions")
    
    print("="*50)

def handle_flow_cmd_new_event(cpu, data, size):
    global stats
    event = ct.cast(data, ct.POINTER(FlowCmdNewEvent)).contents
    stats['flows'] += 1
    
    parsed_flow = parse_netlink_flow_message(event.nlmsg_data, event.data_len)
    
    debug_info = {}
    matches_filter = matches_filter_flow(parsed_flow, debug_info)
    
    if not matches_filter and not DEBUG_MODE:
        return
    
    if matches_filter:
        stats['filtered_flows'] += 1
    
    title = "FLOW CMD NEW EVENT"
    if matches_filter:
        title += " (filtered)"
    elif DEBUG_MODE:
        title += " (debug - no match)"
    
    print("\\n=== %s ===" % title)
    print("Time: %s (kernel: %s)" % (strftime('%H:%M:%S'), format_kernel_timestamp(event.kernel_timestamp)))
    print("Process: %s (PID: %d)" % (event.comm.decode('utf-8', 'replace'), event.pid))
    print("Netlink PortID: %u" % event.netlink_portid)
    print("SKB: len=%u, data_len=%u" % (event.skb_len, event.data_len))
    
    if DEBUG_MODE and 'parse_error' in parsed_flow:
        print("Detailed parsing error: %s" % parsed_flow['parse_error'])
        print("Data length: %d, first 16 bytes: %s" % (
            event.data_len, 
            ' '.join(['%02x' % b for b in event.nlmsg_data[:min(16, event.data_len)]])
        ))
    
    if parsed_flow['parse_ok'] and parsed_flow['key']:
        key = parsed_flow['key']
        
        # Show summary of key packet information
        summary_parts = []
        if 'ethernet' in key:
            eth = key['ethernet']
            summary_parts.append("Eth: %s -> %s" % (eth['eth_src'], eth['eth_dst']))
        
        if 'ipv4' in key:
            ipv4 = key['ipv4']
            proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ipv4['proto'], str(ipv4['proto']))
            
            if 'tcp' in key or 'udp' in key:
                port_key = 'tcp' if 'tcp' in key else 'udp'
                summary_parts.append("%s:%d -> %s:%d (%s)" % (
                    ipv4['src_ip'], key[port_key]['src_port'],
                    ipv4['dst_ip'], key[port_key]['dst_port'], proto_name))
            else:
                summary_parts.append("%s -> %s (%s)" % (ipv4['src_ip'], ipv4['dst_ip'], proto_name))
        
        if summary_parts:
            print("Packet: %s" % ", ".join(summary_parts))
        
        if DEBUG_MODE:
            print("Debug - Parsed Key fields: %s" % ', '.join(key.keys()))
        
        if 'recirc_id' in key or 'in_port' in key or 'skb_mark' in key:
            mark_val = key.get('skb_mark', 0)
            mark_str = hex(mark_val)[2:] if isinstance(mark_val, int) else str(mark_val)
            print("Key: recirc_id=%s, in_port=%s, mark=0x%s" % (
                key.get('recirc_id', 'N/A'),
                key.get('in_port', 'N/A'),
                mark_str))
        
        if 'ethernet' in key:
            eth = key['ethernet']
            eth_type = key.get('eth_type', 0)
            print("Key Eth: %s -> %s, type=0x%04x" % (
                eth['eth_src'], eth['eth_dst'], eth_type))
        else:
            eth_type = key.get('eth_type', 0)
            if eth_type != 0:
                print("Key Eth: type=0x%04x (no ethernet field)" % eth_type)
            else:
                print("Key Eth: no ethernet info")
        
        if 'ipv4' in key:
            ipv4 = key['ipv4']
            proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ipv4['proto'], str(ipv4['proto']))
            
            ports_info = ""
            if 'tcp' in key:
                ports_info = ":%d -> :%d" % (key['tcp']['src_port'], key['tcp']['dst_port'])
            elif 'udp' in key:
                ports_info = ":%d -> :%d" % (key['udp']['src_port'], key['udp']['dst_port'])
            
            print("Key IP: %s%s %s%s (%s)" % (
                ipv4['src_ip'], ports_info.split(' -> ')[0] if ports_info else '',
                ipv4['dst_ip'], ports_info.split(' -> ')[1] if ports_info else '',
                proto_name))
        
        if parsed_flow['mask']:
            mask = parsed_flow['mask']
            if 'ethernet' in mask:
                print("Mask Eth: %s -> %s" % (
                    mask['ethernet']['eth_src'], mask['ethernet']['eth_dst']))
        
        if parsed_flow['actions']:
            actions_str = []
            for action in parsed_flow['actions']:
                if action['type'] == 'OUTPUT':
                    actions_str.append("output:%d" % action['port'])
                elif action['type'] == 'USERSPACE':
                    info = action['info']
                    pid_str = "pid=%d" % info['pid'] if 'pid' in info else ""
                    actions_str.append("userspace(%s)" % pid_str)
                elif action['type'] == 'RECIRC':
                    actions_str.append("recirc(%d)" % action['recirc_id'])
                elif action['type'] == 'SET':
                    set_fields = []
                    attrs = action['attrs']
                    if 'ethernet' in attrs:
                        set_fields.append("eth")
                    if 'ipv4' in attrs:
                        set_fields.append("ipv4")
                    actions_str.append("set(%s)" % ','.join(set_fields))
                elif action['type'] == 'PUSH_VLAN':
                    vid = action['tci'] & 0xFFF
                    actions_str.append("push_vlan(vid=%d)" % vid)
                elif action['type'] == 'POP_VLAN':
                    actions_str.append("pop_vlan")
                elif action['type'] == 'CT':
                    actions_str.append("ct")
                elif action['type'] == 'TRUNC':
                    actions_str.append("trunc(%d)" % action['max_len'])
                else:
                    actions_str.append(action['type'].lower())
            
            print("Actions: %s" % ', '.join(actions_str))
        
        print("Netlink: has_key=yes, has_mask=%s, has_actions=%s" % (
            "yes" if parsed_flow['mask'] else "no",
            "yes" if parsed_flow['actions'] else "no"))
    else:
        print("Warning: Netlink message parsing failed")
        if 'parse_error' in parsed_flow:
            print("Error: %s" % parsed_flow['parse_error'])
    
    if DEBUG_MODE and not matches_filter:
        print("Warning: Does not match filter conditions")
        if debug_info:
            reason = debug_info.get('reason', 'unknown')
            print("    Reason: %s" % reason)
            if 'available_fields' in debug_info:
                print("    Available fields: %s" % ', '.join(debug_info['available_fields']))
            if 'expected' in debug_info and 'actual' in debug_info:
                print("    Expected: %s, Actual: %s" % (debug_info['expected'], debug_info['actual']))
    
    print("="*50)

def print_debug_summary():
    """Print debug summary information"""
    print("\\n" + "="*60)
    print("=== Statistics Summary ===")
    
    print("\\nStatistics:")
    print("   Total upcalls: %d" % stats['upcalls'])
    print("   Filtered upcalls: %d" % stats['filtered_upcalls'])
    print("   Total flows: %d" % stats['flows'])
    print("   Filtered flows: %d" % stats['filtered_flows'])
    
    if stats['upcalls'] > 0:
        upcall_filter_rate = (stats['filtered_upcalls'] * 100.0) / stats['upcalls']
        print("   Upcall filter rate: %.2f%%" % upcall_filter_rate)
    
    if stats['flows'] > 0:
        flow_filter_rate = (stats['filtered_flows'] * 100.0) / stats['flows']
        print("   Flow filter rate: %.2f%%" % flow_filter_rate)
    
    print("="*60)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='OVS Userspace Megaflow Tracker with configurable filtering')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode (show all events)')
    parser.add_argument('--eth-src', type=str, help='Filter by ethernet source MAC (e.g., aa:bb:cc:dd:ee:ff)')
    parser.add_argument('--eth-dst', type=str, help='Filter by ethernet destination MAC (e.g., aa:bb:cc:dd:ee:ff)')
    parser.add_argument('--eth-type', type=str, help='Filter by ethernet type (e.g., 0x0800 for IPv4)')
    parser.add_argument('--src-ip', '--ip-src', type=str, help='Filter by IP source address (e.g., 192.168.1.1)')
    parser.add_argument('--dst-ip', '--ip-dst', type=str, help='Filter by IP destination address (e.g., 192.168.1.1)')
    parser.add_argument('--ip-proto', type=int, help='Filter by IP protocol (e.g., 6 for TCP, 17 for UDP)')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'icmp', 'all'], help='Filter by protocol (tcp, udp, icmp, all)')
    parser.add_argument('--l4-src-port', type=int, help='Filter by L4 source port (e.g., 80, 443)')
    parser.add_argument('--l4-dst-port', type=int, help='Filter by L4 destination port (e.g., 80, 443)')
    
    return parser.parse_args()

def configure_filters(args):
    """Configure filter settings based on arguments"""
    global DEBUG_MODE, FILTER_CONFIG
    
    DEBUG_MODE = args.debug
    
    FILTER_CONFIG.eth_src = args.eth_src
    FILTER_CONFIG.eth_dst = args.eth_dst
    FILTER_CONFIG.eth_type = int(args.eth_type, 0) if args.eth_type else None
    FILTER_CONFIG.ip_src = unpack('>I', inet_pton(AF_INET, args.src_ip))[0] if args.src_ip else None
    FILTER_CONFIG.ip_dst = unpack('>I', inet_pton(AF_INET, args.dst_ip))[0] if args.dst_ip else None
    # Handle protocol conversion from string to numeric
    if args.protocol:
        protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'all': None}
        FILTER_CONFIG.ip_proto = protocol_map.get(args.protocol.lower())
    else:
        FILTER_CONFIG.ip_proto = args.ip_proto
    FILTER_CONFIG.l4_src_port = args.l4_src_port
    FILTER_CONFIG.l4_dst_port = args.l4_dst_port
    
    # Enable filtering if any filter is set
    FILTER_CONFIG.enabled = any([
        FILTER_CONFIG.eth_src, FILTER_CONFIG.eth_dst, FILTER_CONFIG.eth_type,
        FILTER_CONFIG.ip_src, FILTER_CONFIG.ip_dst, FILTER_CONFIG.ip_proto,
        FILTER_CONFIG.l4_src_port, FILTER_CONFIG.l4_dst_port
    ])

def print_filter_config():
    """Print current filter configuration"""
    print("OVS Megaflow Tracker V8")
    
    if FILTER_CONFIG.enabled:
        print("Filter Configuration:")
        if FILTER_CONFIG.eth_src:
            print("  Ethernet Source: %s" % FILTER_CONFIG.eth_src)
        if FILTER_CONFIG.eth_dst:
            print("  Ethernet Destination: %s" % FILTER_CONFIG.eth_dst)
        if FILTER_CONFIG.eth_type is not None:
            print("  Ethernet Type: 0x%04x" % FILTER_CONFIG.eth_type)
        if FILTER_CONFIG.ip_src is not None:
            print("  IP Source: %s" % inet_ntop(AF_INET, pack('>I', FILTER_CONFIG.ip_src)))
        if FILTER_CONFIG.ip_dst is not None:
            print("  IP Destination: %s" % inet_ntop(AF_INET, pack('>I', FILTER_CONFIG.ip_dst)))
        if FILTER_CONFIG.ip_proto is not None:
            proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(FILTER_CONFIG.ip_proto, str(FILTER_CONFIG.ip_proto))
            print("  IP Protocol: %s (%d)" % (proto_name, FILTER_CONFIG.ip_proto))
        if FILTER_CONFIG.l4_src_port is not None:
            print("  L4 Source Port: %d" % FILTER_CONFIG.l4_src_port)
        if FILTER_CONFIG.l4_dst_port is not None:
            print("  L4 Destination Port: %d" % FILTER_CONFIG.l4_dst_port)
    else:
        print("No filters configured - showing all events")
    
    if DEBUG_MODE:
        print("Debug mode: showing all events (including non-matching)")
    elif FILTER_CONFIG.enabled:
        print("Filter mode: only showing matching events")
    
    print("")

def main():
    args = parse_arguments()
    configure_filters(args)
    print_filter_config()
    
    b = BPF(text=bpf_text)
    
    try:
        b.attach_kprobe(event="ovs_dp_upcall", fn_name="trace_ovs_dp_upcall")
        print("Attached to ovs_dp_upcall")
        
        try:
            b.attach_kprobe(event="ovs_flow_cmd_new", fn_name="trace_ovs_flow_cmd_new")
            print("Attached to ovs_flow_cmd_new")
        except Exception as e:
            print("Warning: Cannot attach to ovs_flow_cmd_new: %s" % str(e))
            
    except Exception as e:
        print("Error: %s" % str(e))
        sys.exit(1)
    
    b["upcall_events"].open_perf_buffer(handle_upcall_event, page_cnt=256)
    b["flow_cmd_new_events"].open_perf_buffer(handle_flow_cmd_new_event, page_cnt=256)
    
    print("\\n Starting monitoring...\\n")
    
    try:
        while True:
            b.perf_buffer_poll()
                
    except KeyboardInterrupt:
        print("\\nUser interrupted...")
    finally:
        print_debug_summary()

if __name__ == "__main__":
    main()