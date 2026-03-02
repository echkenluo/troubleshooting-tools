#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
import argparse
import sys
import socket
import struct
from datetime import datetime
import time
import json
import os
import subprocess

def get_boot_time():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])

        return time.time() - uptime_seconds
    except Exception as e:
        sys.stderr.write("WARNING: Unable to get boot time: %s\n" % e)
        return time.time()

def kernel_ns_to_datetime(ns):
    seconds_since_boot = float(ns) / 1e9
    absolute_time = BOOT_TIME + seconds_since_boot
    return datetime.fromtimestamp(absolute_time)

BOOT_TIME = get_boot_time()

def check_kernel_function_exists(func_name):
    """Check if a kernel function exists using /proc/kallsyms or bpftrace"""
    # Method 1: Try to check /proc/kallsyms
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                if func_name in line:
                    return True
    except:
        pass

    # Method 2: Try using bpftrace if available
    try:
        result = subprocess.run(['bpftrace', '-l', 'kprobe:' + func_name],
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and func_name in result.stdout:
            return True
    except:
        pass

    # Method 3: Try to attach and see if it fails (handled by caller)
    return None  # Unknown, let the caller try

def get_kernel_version():
    """Get kernel version tuple (major, minor, patch)"""
    try:
        import platform
        version_str = platform.release()
        # Extract version numbers (e.g., "5.4.0-150-generic" -> (5, 4, 0))
        parts = version_str.split('-')[0].split('.')
        return tuple(int(p) for p in parts[:3])
    except:
        return (0, 0, 0)

def ip_to_int(ip_str):
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        return socket.htonl(struct.unpack("!I", packed_ip)[0])
    except socket.error:
        sys.stderr.write("ERROR: Invalid IP address format '%s'\n" % ip_str)
        sys.exit(1)

PROTO_MAP = {
    'all': 0,
    'icmp': socket.IPPROTO_ICMP,
    'tcp': socket.IPPROTO_TCP,
    'udp': socket.IPPROTO_UDP,
}

parser = argparse.ArgumentParser(
    description="Trace skb->_nfct pointer value, filtering by network properties (adaptive kernel version).",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--src-ip', type=str, help='Filter by source IP address')
parser.add_argument('--dst-ip', type=str, help='Filter by destination IP address')
parser.add_argument('--protocol', type=str, choices=PROTO_MAP.keys(), default='all', help='Filter by protocol (tcp, udp, icmp, all)')
parser.add_argument('--src-port', type=int, default=0, help='Filter by source port (TCP/UDP only)')
parser.add_argument('--dst-port', type=int, default=0, help='Filter by destination port (TCP/UDP only)')
parser.add_argument('--rel-time', action='store_true', help='Display relative seconds instead of absolute timestamps')
parser.add_argument('--filters-file', type=str, help='JSON file containing multiple filter rules')
parser.add_argument('--stack', type=lambda x: (str(x).lower() == 'true'), default=True, help='Display kernel stack traces (true/false, default: true)')
args = parser.parse_args()

# Detect available TCP packet functions
kernel_version = get_kernel_version()
print("Detected kernel version: %d.%d.%d" % kernel_version)

# Determine which TCP functions are available
tcp_packet_func = None
tcp_error_func = None
use_tcp_return_probe = False

# Check for newer kernel (5.4+) functions first
if kernel_version >= (5, 4, 0) or check_kernel_function_exists('nf_conntrack_tcp_packet'):
    tcp_packet_func = 'nf_conntrack_tcp_packet'
    print("Using nf_conntrack_tcp_packet (kernel 5.4+ style)")
    # Note: tcp_error doesn't exist in newer kernels
elif check_kernel_function_exists('tcp_packet'):
    tcp_packet_func = 'tcp_packet'
    use_tcp_return_probe = True
    print("Using tcp_packet (kernel 4.19- style)")
    if check_kernel_function_exists('tcp_error'):
        tcp_error_func = 'tcp_error'
        print("tcp_error function found")

if not tcp_packet_func:
    print("WARNING: No suitable TCP packet tracking function found")
    print("Will continue without TCP-specific probes")

filter_rules = []
if args.filters_file:
    try:
        with open(args.filters_file, 'r') as f:
            filter_data = json.load(f)

            if isinstance(filter_data, list):
                for rule in filter_data:
                    filter_rule = {
                        'src_ip': ip_to_int(rule.get('src_ip')),
                        'dst_ip': ip_to_int(rule.get('dst_ip')),
                        'proto': PROTO_MAP.get(rule.get('protocol', 'all'), 0),
                        'src_port': int(rule.get('src_port', 0)),
                        'dst_port': int(rule.get('dst_port', 0))
                    }
                    filter_rules.append(filter_rule)

                    print("Added filter rule: %s" % rule)
    except Exception as e:
        sys.stderr.write("ERROR: Failed to load filter rules from %s: %s\n" % (args.filters_file, e))
        sys.exit(1)

    if not filter_rules:
        sys.stderr.write("WARNING: No filter rules found in %s\n" % args.filters_file)
else:
    src_ip_filter = ip_to_int(args.src_ip)
    dst_ip_filter = ip_to_int(args.dst_ip)
    proto_filter = PROTO_MAP[args.protocol]
    src_port_filter = args.src_port
    dst_port_filter = args.dst_port

    if src_ip_filter != 0 or dst_ip_filter != 0 or proto_filter != 0 or src_port_filter != 0 or dst_port_filter != 0:
        filter_rules.append({
            'src_ip': src_ip_filter,
            'dst_ip': dst_ip_filter,
            'proto': proto_filter,
            'src_port': src_port_filter,
            'dst_port': dst_port_filter
        })

    print("--- Filters ---")
    print("Src IP: %s (Host Order Int: 0x%x)" % (args.src_ip if args.src_ip else "Any", src_ip_filter))
    print("Dst IP: %s (Host Order Int: 0x%x)" % (args.dst_ip if args.dst_ip else "Any", dst_ip_filter))
    print("Protocol: %s (%d)" % (args.protocol, proto_filter))
    if proto_filter in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
        print("Src Port: %s (Host Order)" % (src_port_filter if src_port_filter else "Any"))
        print("Dst Port: %s (Host Order)" % (dst_port_filter if dst_port_filter else "Any"))
    print("---------------")

print("For multiple connection filters, create a JSON file with this structure:")
print('''
[
    {
        "src_ip": "10.200.0.243",
        "dst_ip": "10.200.0.245",
        "protocol": "tcp",
        "src_port": 9900,
        "dst_port": 0
    },
    {
        "src_ip": "10.200.0.245",
        "dst_ip": "10.200.0.243",
        "protocol": "tcp",
        "src_port": 0,
        "dst_port": 9900
    }
]
''')
print("And use it with: --filters-file /path/to/filters.json")
print("---------------")

MAX_FILTER_RULES = 10

filter_array = []
if len(filter_rules) > 0:
    rule = filter_rules[0]
    filter_array.append((rule['src_ip'], rule['dst_ip'], rule['proto'], rule['src_port'], rule['dst_port']))
    if len(filter_rules) > 1:
        print("WARNING: Only the first filter rule will be used in this version")
else:
    filter_array.append((0, 0, 0, 0, 0))

for i in range(MAX_FILTER_RULES - len(filter_array)):
    filter_array.append((0, 0, 0, 0, 0))

num_filters = 1 if len(filter_rules) > 0 else 0

if len(filter_rules) > 0:
    rule = filter_rules[0]
    src_ip = rule['src_ip']
    dst_ip = rule['dst_ip']
    proto = rule['proto']
    src_port = rule['src_port']
    dst_port = rule['dst_port']
    has_filter = 1
    if len(filter_rules) > 1:
        print("WARNING: Only the first filter rule will be used in this version")
else:
    src_ip = 0
    dst_ip = 0
    proto = 0
    src_port = 0
    dst_port = 0
    has_filter = 0

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/inet_connection_sock.h>
#include <linux/netfilter/nf_conntrack_zones_common.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <net/sock.h>

#define HAS_FILTER %d
#define FILTER_SRC_IP %sU
#define FILTER_DST_IP %sU
#define FILTER_PROTO %d
#define FILTER_SRC_PORT %d
#define FILTER_DST_PORT %d

struct skb_ct_info {
    u64 nfct_ptr;
    u32 ctinfo;
    u64 ct_status;
    u64 ct_label[2];
    u16 zone_id;
    u8  zone_dir;
};

struct ovs_ct_info {
    u8  commit_flag;
    u16 zone_id;
    u8  zone_dir;
    u64 nfct_ptr;
};

struct data_t {
    u64 timestamp_ns;
    int stack_id;
    u32 probe_id;
    char comm[TASK_COMM_LEN];

    u32 saddr;
    u32 daddr;
    u8 ip_proto;
    u16 sport;
    u16 dport;
    u16 ip_id;
    u32 tcp_seq;
    u32 tcp_ack;
    u8  tcp_state;
    u8  tcp_flags;

    u32 ifindex;
    char devname[16];

    s64 retval;

    struct skb_ct_info skb_ct;
    struct ovs_ct_info ovs_ct;
};

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 10240);

struct filter_decision_t {
    bool should_trace;
};
BPF_HASH(entry_filter_decision, u64, struct filter_decision_t, 10240);

enum probe_ids {
    PROBE_ID_NF_CONNTRACK_IN = 1,
    PROBE_ID_OVS_CT_LOOKUP   = 2,
    PROBE_ID_OVS_CT_UPDATE   = 3,
    PROBE_ID_NF_REFRESH_ACCT = 4,
    PROBE_ID_TCP_PACKET = 6,
    PROBE_ID_TCP_PACKET_RET = 7,
    PROBE_ID_TCP_ERROR = 8,
    PROBE_ID_OVS_CT_EXECUTE = 9,
};

static __always_inline int parse_skb_fields(struct sk_buff *skb, struct data_t *data) {
    if (skb == NULL) return 0;

    unsigned char *head;
    u16 network_header;
    u16 transport_header;

    // Extract device info from skb->dev
    struct net_device *dev = NULL;
    data->ifindex = 0;
    __builtin_memset(&data->devname, 0, sizeof(data->devname));

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
        // Read ifindex
        bpf_probe_read_kernel(&data->ifindex, sizeof(data->ifindex), &dev->ifindex);

        // Read device name
        char devname[16];
        if (bpf_probe_read_kernel_str(&devname, sizeof(devname), dev->name) > 0) {
            __builtin_memcpy(&data->devname, devname, sizeof(devname));
        }
    }

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0) return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0) return 0;
    if (network_header == (u16)~0U) return 0;

    void *ip_header_address = head + network_header;
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), ip_header_address) < 0) {
        return 0;
    }

    data->saddr = iph.saddr;
    data->daddr = iph.daddr;
    data->ip_proto = iph.protocol;
    data->tcp_state = 0xFF;
    data->tcp_flags = 0;

    // Extract IP ID
    data->ip_id = bpf_ntohs(iph.id);

    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0) {
       data->sport = 0;
       data->dport = 0;
       data->tcp_seq = 0;
       data->tcp_ack = 0;
       return 1;
    }
    if (transport_header == (u16)~0U) {
       data->sport = 0;
       data->dport = 0;
       data->tcp_seq = 0;
       data->tcp_ack = 0;
       return 1;
    }

    void *transport_header_address = head + transport_header;

    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), transport_header_address) == 0) {
            data->sport = bpf_ntohs(tcph.source);
            data->dport = bpf_ntohs(tcph.dest);

            // Extract TCP sequence and ACK numbers
            data->tcp_seq = bpf_ntohl(tcph.seq);
            data->tcp_ack = bpf_ntohl(tcph.ack_seq);

            data->tcp_flags = 0;
            __u16 tcp_flags_field = 0;
            bpf_probe_read_kernel(&tcp_flags_field, sizeof(tcp_flags_field), ((char *)&tcph) + 12);

#if defined(__LITTLE_ENDIAN_BITFIELD)
            data->tcp_flags |= ((tcp_flags_field >> 8) & 0xFF);
#elif defined(__BIG_ENDIAN_BITFIELD)
            data->tcp_flags |= (tcp_flags_field & 0xFF);
#else
            data->tcp_flags |= ((tcp_flags_field >> 8) & 0xFF);
#endif

            struct sock *sk = NULL;
            if (bpf_probe_read_kernel(&sk, sizeof(sk), &skb->sk) == 0 && sk != NULL) {
                u8 tcp_state = 0;
                void *state_addr = (void *)&sk->__sk_common.skc_state;
                if (bpf_probe_read_kernel(&tcp_state, sizeof(tcp_state), state_addr) == 0) {
                    data->tcp_state = tcp_state;
                }
            }
        } else {
            data->sport = 0;
            data->dport = 0;
            data->tcp_seq = 0;
            data->tcp_ack = 0;
        }
    } else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), transport_header_address) == 0) {
            data->sport = bpf_ntohs(udph.source);
            data->dport = bpf_ntohs(udph.dest);
        } else {
            data->sport = 0;
            data->dport = 0;
        }
        data->tcp_seq = 0;
        data->tcp_ack = 0;
    } else {
        data->sport = 0;
        data->dport = 0;
        data->tcp_seq = 0;
        data->tcp_ack = 0;
    }

    return 1;
}

// Define the shared ovs_conntrack_info structure
struct ovs_conntrack_info {
    void *helper;
    struct {
        u16 id;
#ifdef CONFIG_NF_CONNTRACK_ZONE_DIRECTIONS
        u8 dir;
#else
        u8 __pad_dir;
#endif
    } zone;
    struct nf_conn *ct;
    u8 bitfields;
};

// Shared function to parse ovs_conntrack_info
static inline void parse_ovs_conntrack_info(const struct ovs_conntrack_info *info, struct data_t *data) {
    if (info == NULL) {
        data->ovs_ct.commit_flag = (u8)-1;
        data->ovs_ct.zone_id = (u16)-1;
        data->ovs_ct.zone_dir = (u8)-1;
        data->ovs_ct.nfct_ptr = (u64)-1;
        return;
    }

    // Parse commit flag
    u8 tmp_commit = 0xff;
    if (bpf_probe_read_kernel(&tmp_commit, sizeof(tmp_commit), &info->bitfields) == 0) {
        data->ovs_ct.commit_flag = tmp_commit & 0x01;
    } else {
        data->ovs_ct.commit_flag = (u8)-2;
    }

    // Parse zone ID
    u16 tmp_zone_id = 0xffff;
    if (bpf_probe_read_kernel(&tmp_zone_id, sizeof(tmp_zone_id), &info->zone.id) == 0) {
        data->ovs_ct.zone_id = tmp_zone_id;
    } else {
        data->ovs_ct.zone_id = (u16)-2;
    }

    // Parse zone direction
#ifdef CONFIG_NF_CONNTRACK_ZONE_DIRECTIONS
    u8 tmp_zone_dir = 0xff;
    if (bpf_probe_read_kernel(&tmp_zone_dir, sizeof(tmp_zone_dir), &info->zone.dir) == 0) {
        data->ovs_ct.zone_dir = tmp_zone_dir;
    } else {
        data->ovs_ct.zone_dir = (u8)-2;
    }
#else
    data->ovs_ct.zone_dir = (u8)-3;
#endif

    // Parse nfct pointer
    u64 tmp_nfct_ptr = (u64)-1;
    if (bpf_probe_read_kernel(&tmp_nfct_ptr, sizeof(tmp_nfct_ptr), &info->ct) == 0) {
        data->ovs_ct.nfct_ptr = tmp_nfct_ptr;
    } else {
        data->ovs_ct.nfct_ptr = (u64)-2;
    }
}

static inline void init_ovs_fields(struct data_t *data) {
    data->ovs_ct.commit_flag = (u8)-1;
    data->ovs_ct.zone_id = (u16)-1;
    data->ovs_ct.zone_dir = (u8)-1;
    data->ovs_ct.nfct_ptr = (u64)-1;
}

static inline int process_ret_event(struct pt_regs *ctx, u32 probe_id) {
    struct data_t data = {};
    data.timestamp_ns = bpf_ktime_get_ns();
    data.probe_id = probe_id;
    data.retval = (s32)PT_REGS_RC(ctx);
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.skb_ct.nfct_ptr = 0;
    data.saddr = 0;
    data.daddr = 0;
    data.ip_proto = 0;
    data.sport = 0;
    data.dport = 0;
    data.tcp_state = 0xFF;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// Parse nf_conn fields (for tcp_packet and tcp_error probes)
static inline void parse_nf_conn_fields(struct nf_conn *ct, struct data_t *data) {
    if (ct == NULL) {
        return;
    }

    // Parse nf_conn->zone using the proper structure from the header file
    struct nf_conntrack_zone zone;

    if (bpf_probe_read_kernel(&zone, sizeof(zone), &ct->zone) == 0) {
        //bpf_trace_printk("zone.id: %%d, zone.dir: %%d\\n", zone.id, zone.dir);
        // You can access zone.flags if needed in the future
        u16 tmp_zone_id = 0xffff;
        if (bpf_probe_read_kernel(&tmp_zone_id, sizeof(tmp_zone_id), &zone.id) == 0) {
            data->skb_ct.zone_id = tmp_zone_id;
        } else {
            data->skb_ct.zone_id = (u16)-2;
        }

        // Parse zone direction
#ifdef CONFIG_NF_CONNTRACK_ZONE_DIRECTIONS
        u8 tmp_zone_dir = 0xff;
        if (bpf_probe_read_kernel(&tmp_zone_dir, sizeof(tmp_zone_dir), &zone.dir) == 0) {
            data->skb_ct.zone_dir = tmp_zone_dir;
        } else {
            data->skb_ct.zone_dir = (u8)-2;
        }
#else
        data->skb_ct.zone_dir = (u8)-3;
#endif
    } else {
        data->skb_ct.zone_id = (u16)-2;
        data->skb_ct.zone_dir = (u8)-2;
    }

    // Read ct_status
    if (bpf_probe_read_kernel(&data->skb_ct.ct_status, sizeof(data->skb_ct.ct_status), &ct->status) < 0) {
        data->skb_ct.ct_status = (u64)-5; // Indicate failed to read ct->status
    }

    // Read ct_label - initialize to invalid
    data->skb_ct.ct_label[0] = 0xFFFFFFFFFFFFFFFF;
    data->skb_ct.ct_label[1] = 0xFFFFFFFFFFFFFFFF;

    // Try to access the label extension
    struct nf_ct_ext *ext;
    if (bpf_probe_read_kernel(&ext, sizeof(ext), &ct->ext) == 0 && ext != NULL) {
        // Check if labels extension exists (ID 7 = NF_CT_EXT_LABELS)
        u8 offset;
        if (bpf_probe_read_kernel(&offset, sizeof(offset), &ext->offset[7]) == 0 && offset != 0) {
            // Calculate address of the label data
            void *label_addr = (void *)ext + offset;

            // Read the label data (16 bytes / 128 bits)
            bpf_probe_read_kernel(&data->skb_ct.ct_label, sizeof(data->skb_ct.ct_label), label_addr);
        }
    }
}

static inline int extract_conntrack_info(struct pt_regs *ctx, struct sk_buff *skb, struct data_t *data) {
    u64 skb_nfct_val = 0;

    // Extract nfct information
    bpf_probe_read_kernel(&skb_nfct_val, sizeof(skb_nfct_val), &skb->_nfct);
    data->skb_ct.nfct_ptr = skb_nfct_val;
    data->skb_ct.ctinfo = (u32)(skb_nfct_val & NFCT_INFOMASK);

    // Initialize ct_label to invalid values
    data->skb_ct.ct_label[0] = 0xFFFFFFFFFFFFFFFF;
    data->skb_ct.ct_label[1] = 0xFFFFFFFFFFFFFFFF;

    if (skb_nfct_val != 0) {
        struct nf_conn *tmpl_bpf = (struct nf_conn *)(skb_nfct_val & NFCT_PTRMASK);
        if (tmpl_bpf != NULL) {
            // Call parse_nf_conn_fields to handle all nf_conn related data processing
            parse_nf_conn_fields(tmpl_bpf, data);
        } else {
            data->skb_ct.ct_status = (u64)-3;
        }
    } else {
        data->skb_ct.ct_status = (u64)-4;
    }

    // Setup common fields
    data->timestamp_ns = bpf_ktime_get_ns();
    data->stack_id = stack_traces.get_stackid(ctx, 0);
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    data->retval = -999;

    return 1;
}

// Shared function to extract packet information and apply filters
static inline int prepare_data_and_check_filters(struct pt_regs *ctx, struct sk_buff *skb, struct data_t *data) {
    if (skb == NULL) {
        return 0;
    }

    // Initialize data fields
    data->skb_ct.ct_status = (u64)-1;
    data->skb_ct.ctinfo = (u32)-1;
    init_ovs_fields(data);

    // Parse SKB fields
    if (!parse_skb_fields(skb, data)) {
        return 0;
    }

    // No filter means trace everything
    if (HAS_FILTER == 0) {
        return extract_conntrack_info(ctx, skb, data);
    }

    // Skip empty filter (all zeros)
    if (FILTER_SRC_IP == 0 && FILTER_DST_IP == 0 && FILTER_PROTO == 0 &&
        FILTER_SRC_PORT == 0 && FILTER_DST_PORT == 0) {
        return extract_conntrack_info(ctx, skb, data);
    }

    // Try direct match first
    bool direct_match = true;

    // Check source IP if specified
    if (FILTER_SRC_IP != 0 && data->saddr != FILTER_SRC_IP) {
        direct_match = false;
    }

    // Check destination IP if specified
    if (direct_match && FILTER_DST_IP != 0 && data->daddr != FILTER_DST_IP) {
        direct_match = false;
    }

    // Check protocol if specified
    if (direct_match && FILTER_PROTO != 0 && data->ip_proto != FILTER_PROTO) {
        direct_match = false;
    }

    // Check ports for TCP/UDP
    if (direct_match && (data->ip_proto == IPPROTO_TCP || data->ip_proto == IPPROTO_UDP)) {
        // Check source port if specified
        if (FILTER_SRC_PORT != 0 && data->sport != FILTER_SRC_PORT) {
            direct_match = false;
        }

        // Check destination port if specified
        if (direct_match && FILTER_DST_PORT != 0 && data->dport != FILTER_DST_PORT) {
            direct_match = false;
        }
    }

    // If direct match succeeds
    if (direct_match) {
        return extract_conntrack_info(ctx, skb, data);
    }

    // Try reverse match for connection tracking
    bool reverse_match = true;

    // Swap src/dst for reverse check
    if (FILTER_DST_IP != 0 && data->saddr != FILTER_DST_IP) {
        reverse_match = false;
    }

    if (reverse_match && FILTER_SRC_IP != 0 && data->daddr != FILTER_SRC_IP) {
        reverse_match = false;
    }

    // Protocol stays the same
    if (reverse_match && FILTER_PROTO != 0 && data->ip_proto != FILTER_PROTO) {
        reverse_match = false;
    }

    // Swap ports for reverse check
    if (reverse_match && (data->ip_proto == IPPROTO_TCP || data->ip_proto == IPPROTO_UDP)) {
        // Check destination port against src_port
        if (FILTER_SRC_PORT != 0 && data->dport != FILTER_SRC_PORT) {
            reverse_match = false;
        }

        // Check source port against dst_port
        if (reverse_match && FILTER_DST_PORT != 0 && data->sport != FILTER_DST_PORT) {
            reverse_match = false;
        }
    }

    // If reverse match succeeds
    if (reverse_match) {
        return extract_conntrack_info(ctx, skb, data);
    }

    // No match
    return 0;
}

static inline int check_filters_and_submit_entry(struct pt_regs *ctx, struct sk_buff *skb, u32 probe_id) {
    struct data_t data = {};

    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }

    data.probe_id = probe_id;
    events.perf_submit(ctx, &data, sizeof(data));
    return 1;
}

int trace_ovs_ct_lookup(struct pt_regs *ctx, void *net, void *key, void *info_ptr, struct sk_buff *skb) {
    struct data_t data = {};

    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }

    // Parse ovs_conntrack_info from this probe
    const struct ovs_conntrack_info *info = (const struct ovs_conntrack_info *)info_ptr;
    parse_ovs_conntrack_info(info, &data);

    data.probe_id = PROBE_ID_OVS_CT_LOOKUP;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_ovs_ct_update_key(struct pt_regs *ctx, struct sk_buff *skb, const struct ovs_conntrack_info *info_ptr, void *key, bool post_ct, bool keep_nat_flags) {
    struct data_t data = {};

    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }

    // Parse ovs_conntrack_info from this probe
    parse_ovs_conntrack_info(info_ptr, &data);

    data.probe_id = PROBE_ID_OVS_CT_UPDATE;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_ovs_ct_execute(struct pt_regs *ctx, void *net, struct sk_buff *skb, void *key, const void *info_ptr) {
    struct data_t data = {};

    if (!prepare_data_and_check_filters(ctx, skb, &data)) {
        return 0;
    }

    // Parse ovs_conntrack_info from this probe
    const struct ovs_conntrack_info *info = (const struct ovs_conntrack_info *)info_ptr;
    parse_ovs_conntrack_info(info, &data);

    data.probe_id = PROBE_ID_OVS_CT_EXECUTE;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_nf_conntrack_in(struct pt_regs *ctx, void *net, u8 pf, u32 hooknum, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_NF_CONNTRACK_IN);
    return 0;
}


int trace_nf_ct_refresh_acct(struct pt_regs *ctx, void *ct_ptr, int ctinfo, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_NF_REFRESH_ACCT);
    return 0;
}

// Generic TCP packet handler that can work with both function signatures
int trace_tcp_packet_generic(struct pt_regs *ctx, void *arg0, void *arg1, void *arg2) {
    struct sk_buff *skb = NULL;

    // For tcp_packet: (struct nf_conn *ct, struct sk_buff *skb, ...)
    // For nf_conntrack_tcp_packet: (struct nf_conn *ct, struct sk_buff *skb, unsigned int dataoff, ...)
    // In both cases, skb is the second argument
    skb = (struct sk_buff *)arg1;

    if (check_filters_and_submit_entry(ctx, skb, PROBE_ID_TCP_PACKET) == 0) {
        return 0;
    }

    // Set filter decision for return probe (only for older kernels)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct filter_decision_t decision = {.should_trace = true};
    entry_filter_decision.update(&pid_tgid, &decision);

    return 0;
}

int trace_tcp_packet_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct filter_decision_t *decision = entry_filter_decision.lookup(&pid_tgid);

    if (decision && decision->should_trace) {
        process_ret_event(ctx, PROBE_ID_TCP_PACKET_RET);
    }
    entry_filter_decision.delete(&pid_tgid);
    return 0;
}

int trace_tcp_error(struct pt_regs *ctx, void *net, struct nf_conn *tmpl, struct sk_buff *skb) {
    check_filters_and_submit_entry(ctx, skb, PROBE_ID_TCP_ERROR);

    return 0;
}
"""

probe_names = {
    1: "nf_conntrack_in",
    2: "__ovs_ct_lookup",
    3: "ovs_ct_update_key",
    4: "__nf_ct_refresh_acct",
    6: "tcp_packet",
    7: "tcp_packet_ret",
    8: "tcp_error",
    9: "ovs_ct_execute",
}

# Rest of the Python code remains the same...
class SkbCtInfo(ct.Structure):
    _fields_ = [
        ("nfct_ptr", ct.c_ulonglong),
        ("ctinfo", ct.c_uint32),
        ("ct_status", ct.c_ulonglong),
        ("ct_label", ct.c_ulonglong * 2),
        ("zone_id", ct.c_uint16),
        ("zone_dir", ct.c_uint8),
    ]

class OvsCtInfo(ct.Structure):
    _fields_ = [
        ("commit_flag", ct.c_uint8),
        ("zone_id", ct.c_uint16),
        ("zone_dir", ct.c_uint8),
        ("nfct_ptr", ct.c_ulonglong),
    ]

class Data(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("stack_id", ct.c_int),
        ("probe_id", ct.c_uint),
        ("comm", ct.c_char * 16),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("ip_proto", ct.c_uint8),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("ip_id", ct.c_uint16),
        ("tcp_seq", ct.c_uint32),
        ("tcp_ack", ct.c_uint32),
        ("tcp_state", ct.c_uint8),
        ("tcp_flags", ct.c_uint8),
        ("ifindex", ct.c_uint32),
        ("devname", ct.c_char * 16),
        ("retval", ct.c_longlong),
        ("skb_ct", SkbCtInfo),
        ("ovs_ct", OvsCtInfo),
    ]

bpf_text_final = bpf_text % (has_filter, hex(src_ip), hex(dst_ip), proto, src_port, dst_port)

cflags = []
try:
    # Pass cflags during BPF object initialization
    b = BPF(text=bpf_text_final, cflags=cflags)
except Exception as e:
    sys.stderr.write("ERROR: Failed to compile or load BPF program: %s\n" % e)
    sys.stderr.write("Ensure kernel headers are installed and accessible (e.g., /lib/modules/$(uname -r)/build).\n")
    sys.exit(1)

def attach_probe(event_name, fn_name):
    try:
        b.attach_kprobe(event=event_name, fn_name=fn_name)
        print("Attached kprobe to %s" % event_name)
        return True
    except Exception as e:
        sys.stderr.write("WARN: Failed to attach kprobe to %s: %s\n" % (event_name, e))
        sys.stderr.write("      Check if the function exists in your kernel version and modules (e.g., nf_conntrack, openvswitch) are loaded.\n")
        return False

def attach_kretprobe(event_name, fn_name):
    try:
        b.attach_kretprobe(event=event_name, fn_name=fn_name)
        print("Attached kretprobe to %s" % event_name)
        return True
    except Exception as e:
        sys.stderr.write("WARN: Failed to attach kretprobe to %s: %s\n" % (event_name, e))
        sys.stderr.write("      Check if the function exists in your kernel version.\n")
        return False

# Attach basic probes
attach_probe("nf_conntrack_in", "trace_nf_conntrack_in")
attach_probe("__ovs_ct_lookup", "trace_ovs_ct_lookup")
attach_probe("ovs_ct_update_key", "trace_ovs_ct_update_key")
attach_probe("__nf_ct_refresh_acct", "trace_nf_ct_refresh_acct")
attach_probe("ovs_ct_execute", "trace_ovs_ct_execute")

# Adaptive TCP packet probe attachment
if tcp_packet_func:
    # Use the generic handler for both function types
    if attach_probe(tcp_packet_func, "trace_tcp_packet_generic"):
        # Update probe_names dynamically
        probe_names[6] = tcp_packet_func

        # Only attach return probe for older kernels with tcp_packet
        if use_tcp_return_probe:
            attach_kretprobe(tcp_packet_func, "trace_tcp_packet_ret")

# Attach tcp_error if it exists (older kernels only)
if tcp_error_func:
    attach_probe(tcp_error_func, "trace_tcp_error")

print("\nTracing skb->_nfct pointer changes (filtered)... Press Ctrl-C to stop.")

start_ts = 0
start_time = time.time()  # Record wall clock time when we start

def format_ip(addr):
    packed_ip = struct.pack("I", addr)
    try:
        return socket.inet_ntop(socket.AF_INET, packed_ip)
    except ValueError:
        return "Invalid IP Addr"
    except Exception as e:
        sys.stderr.write("Error formatting IP 0x%x: %s\n" % (addr, e))
        return "Format Error"

def format_timestamp(event, rel_time=False):
    global start_ts
    if start_ts == 0:
        start_ts = event.timestamp_ns

    time_s = float(event.timestamp_ns - start_ts) / 1e9

    if rel_time:
        return "TIME(s): %-9.4f" % time_s
    else:
        time_str = kernel_ns_to_datetime(event.timestamp_ns).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return "DATETIME: %s" % time_str

def format_basic_info(event):
    comm = event.comm.decode('utf-8', 'replace')
    probe_name = probe_names.get(event.probe_id, "Unknown Probe (%d)" % event.probe_id)

    dev_info = ""
    if event.retval == -999 and event.ifindex != 0:
        dev_name = event.devname.decode('utf-8', 'replace').strip('\x00')
        if dev_name:
            dev_info = "DEV: %s[%d]" % (dev_name, event.ifindex)
        else:
            dev_info = "DEV: ifidx=%d" % event.ifindex

    if dev_info:
        return "COMM: %-16s FUNC: %-25s %s" % (comm, probe_name, dev_info)
    else:
        return "COMM: %-16s FUNC: %-25s" % (comm, probe_name)

def format_packet_info(event):
    if event.retval != -999 or event.saddr == 0:
        return "PKTINFO: (Pkt N/A)"

    saddr_str = format_ip(event.saddr)
    daddr_str = format_ip(event.daddr)
    proto_str = {socket.IPPROTO_ICMP: "ICMP", socket.IPPROTO_TCP: "TCP", socket.IPPROTO_UDP: "UDP"}.get(event.ip_proto, str(event.ip_proto))

    pkt_id_info = "IP_ID:0x%x" % event.ip_id

    flags_str = ""
    if event.ip_proto == socket.IPPROTO_TCP:
        tcp_flags = event.tcp_flags
        flags = []
        if tcp_flags & 0x01: flags.append("FIN")
        if tcp_flags & 0x02: flags.append("SYN")
        if tcp_flags & 0x04: flags.append("RST")
        if tcp_flags & 0x08: flags.append("PSH")
        if tcp_flags & 0x10: flags.append("ACK")
        if tcp_flags & 0x20: flags.append("URG")
        if tcp_flags & 0x40: flags.append("ECE")
        if tcp_flags & 0x80: flags.append("CWR")

        if flags:
            flags_str = " FLAGS:[%s]" % "|".join(flags)
        else:
            flags_str = " FLAGS:[]"

    tcp_state_str = ""
    if event.ip_proto == socket.IPPROTO_TCP:
        tcp_state_map = {
            1: "TCP_ESTABLISHED",
            2: "TCP_SYN_SENT",
            3: "TCP_SYN_RECV",
            4: "TCP_FIN_WAIT1",
            5: "TCP_FIN_WAIT2",
            6: "TCP_TIME_WAIT",
            7: "TCP_CLOSE",
            8: "TCP_CLOSE_WAIT",
            9: "TCP_LAST_ACK",
            10: "TCP_LISTEN",
            11: "TCP_CLOSING",
            12: "TCP_NEW_SYN_RECV",
        }
        tcp_state_str = tcp_state_map.get(event.tcp_state, "UNKNOWN_STATE(%d)" % event.tcp_state)

        pkt_id_info += " SEQ:%u ACK:%u" % (event.tcp_seq, event.tcp_ack)

    if event.ip_proto in [socket.IPPROTO_TCP, socket.IPPROTO_UDP] and event.sport != 0:
        pkt_info = "PKTINFO: %s:%d -> %s:%d (%s) %s%s" % (
            saddr_str, event.sport, daddr_str, event.dport, proto_str, pkt_id_info, flags_str)
        if tcp_state_str:
            pkt_info += " [%s]" % tcp_state_str
    else:
        pkt_info = "PKTINFO: %s -> %s (%s) %s%s" % (
            saddr_str, daddr_str, proto_str, pkt_id_info, flags_str)
        if tcp_state_str:
            pkt_info += " [%s]" % tcp_state_str

    return pkt_info

def format_return_info(event):
    if event.retval != -999:
        return "RET: %d" % event.retval
    return ""

def format_ovs_ct_info(event):
    ovs_nfct_str = "OvsConInfoNFCT:0x%x" % event.ovs_ct.nfct_ptr
    if event.ovs_ct.nfct_ptr == (ct.c_ulonglong(-1).value):
        ovs_nfct_str = "OvsConInfoNFCT:N/A(Init)"
    elif event.ovs_ct.nfct_ptr == (ct.c_ulonglong(-2).value):
        ovs_nfct_str = "OvsConInfoNFCT:N/A(ReadFail)"

    ovs_commit_str = "OvsCommit:%d" % event.ovs_ct.commit_flag
    if event.ovs_ct.commit_flag == (ct.c_uint8(-1).value):
        ovs_commit_str = "OvsCommit:N/A(Init)"
    elif event.ovs_ct.commit_flag == (ct.c_uint8(-2).value):
        ovs_commit_str = "OvsCommit:N/A(ReadFail)"

    ovs_zone_id_str = "OvsZoneID:%d" % event.ovs_ct.zone_id
    if event.ovs_ct.zone_id == (ct.c_uint16(-1).value):
        ovs_zone_id_str = "OvsZoneID:N/A(Init)"
    elif event.ovs_ct.zone_id == (ct.c_uint16(-2).value):
        ovs_zone_id_str = "OvsZoneID:N/A(ReadFail)"
    else:
        ovs_zone_id_str = "OvsZoneID:%d" % event.ovs_ct.zone_id

    if event.ovs_ct.zone_dir == 0:
        ovs_zone_dir_str = "OvsZoneDir:0(OrigDst)"
    elif event.ovs_ct.zone_dir == 1:
        ovs_zone_dir_str = "OvsZoneDir:1(ReplySrc)"
    elif event.ovs_ct.zone_dir == (ct.c_uint8(-1).value):
        ovs_zone_dir_str = "OvsZoneDir:N/A(Init)"
    elif event.ovs_ct.zone_dir == (ct.c_uint8(-2).value):
        ovs_zone_dir_str = "OvsZoneDir:N/A(ReadFail)"
    elif event.ovs_ct.zone_dir == (ct.c_uint8(-3).value):
        ovs_zone_dir_str = "OvsZoneDir:N/A(NoCfg)"
    else:
        ovs_zone_dir_str = "OvsZoneDir:%d" % event.ovs_ct.zone_dir

    return "OVS_CT_INFO: " + " ".join([ovs_nfct_str, ovs_commit_str, ovs_zone_id_str, ovs_zone_dir_str])

def format_skb_ct_info(event):
    parts = []

    IPS_TEMPLATE_BIT = 11
    status_val = event.skb_ct.ct_status

    if status_val == (ct.c_ulonglong(-1).value):
        status_info = "CT_STATUS:N/A(Init/NULL)"
    elif status_val == (ct.c_ulonglong(-2).value):
        status_info = "CT_STATUS:N/A(ReadFail)"
    elif status_val == (ct.c_ulonglong(-3).value):
        status_info = "CT_STATUS:N/A(MaskedPtrNULL)"
    elif status_val == (ct.c_ulonglong(-4).value):
        status_info = "CT_STATUS:N/A(_nfct=0)"
    else:
        status_info = "CT_STATUS:0x%x" % status_val
        if status_val & (1 << IPS_TEMPLATE_BIT):
            status_info += "(TEMPLATE)"
        else:
            status_info += "(NOT_TEMPLATE)"

    parts.append(status_info)

    ctinfo_val = event.skb_ct.ctinfo
    ctinfo_map = {
        0: "IP_CT_ESTABLISHED",
        1: "IP_CT_RELATED",
        2: "IP_CT_NEW",
        3: "IP_CT_ESTABLISHED_REPLY",
        5: "IP_CT_RELATED_REPLY",
        7: "IP_CT_UNTRACKED",
    }

    if ctinfo_val == (ct.c_uint32(-1).value):
        ctinfo_str = "CTINFO:N/A"
    else:
        state_str = ctinfo_map.get(ctinfo_val, "UNKNOWN_VALUE")
        ctinfo_str = "CTINFO:%d(%s)" % (ctinfo_val, state_str)

    parts.append(ctinfo_str)

    skb_nfct_str = "NFCT_PTR:0x%x" % event.skb_ct.nfct_ptr
    if event.skb_ct.nfct_ptr == 0:
        skb_nfct_str = "NFCT_PTR:NULL"

    parts.append(skb_nfct_str)

    if event.skb_ct.zone_id == 0:
        skb_zone_id_str = "SKBZoneID:0(KernelDefaultZone)"
    elif event.skb_ct.zone_id == (ct.c_uint16(-1).value):
        skb_zone_id_str = "SKBZoneID:N/A(Init)"
    elif event.skb_ct.zone_id == (ct.c_uint16(-2).value):
        skb_zone_id_str = "SKBZoneID:N/A(ReadFail)"
    else:
        skb_zone_id_str = "SKBZoneID:%d" % event.skb_ct.zone_id

    parts.append(skb_zone_id_str)

    if event.skb_ct.zone_dir == 0:
        skb_zone_dir_str = "SKBZoneDir:0(OrigDst)"
    elif event.skb_ct.zone_dir == 1:
        skb_zone_dir_str = "SKBZoneDir:1(ReplySrc)"
    elif event.skb_ct.zone_dir == (ct.c_uint8(-1).value):
        skb_zone_dir_str = "SKBZoneDir:N/A(Init)"
    elif event.skb_ct.zone_dir == (ct.c_uint8(-2).value):
        skb_zone_dir_str = "SKBZoneDir:N/A(ReadFail)"
    elif event.skb_ct.zone_dir == (ct.c_uint8(-3).value):
        skb_zone_dir_str = "SKBZoneDir:N/A(NoCfg)"
    else:
        skb_zone_dir_str = "SKBZoneDir:%d" % event.skb_ct.zone_dir

    parts.append(skb_zone_dir_str)

    label_val0 = event.skb_ct.ct_label[0]
    label_val1 = event.skb_ct.ct_label[1]
    if label_val0 == 0xFFFFFFFFFFFFFFFF and label_val1 == 0xFFFFFFFFFFFFFFFF:
        label_info = "CT_LABEL:N/A"
    else:
        label_info = "CT_LABEL:0x%016x%016x" % (label_val0, label_val1)

    parts.append(label_info)

    return "SKB_CT_INFO: " + " ".join(parts)

def format_stack_trace(event):
    if not args.stack or event.stack_id < 0:
        if args.stack:
            return ["[Kernel Stack Trace Error: %d]" % event.stack_id]
        return []

    try:
        stack_trace = list(b.get_table("stack_traces").walk(event.stack_id))
        return [b.ksym(addr, show_offset=True) for addr in stack_trace]
    except KeyError:
        return ["[WARN: Stack ID %d not found in stack_traces table]" % event.stack_id]
    except Exception as e:
        return ["[WARN: Error walking/resolving stack trace for stack_id %d: %s]" % (event.stack_id, e)]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    timestamp_info = format_timestamp(event, args.rel_time)
    basic_info = format_basic_info(event)
    packet_info = format_packet_info(event)
    return_info = format_return_info(event)
    ovs_ct_info = format_ovs_ct_info(event)
    skb_ct_info = format_skb_ct_info(event)

    basic_info_parts = [
        timestamp_info,
        basic_info,
    ]

    print(" ".join(basic_info_parts))
    print(packet_info)

    if return_info:
        print(return_info)

    print(ovs_ct_info)
    print(skb_ct_info)

    stack_lines = format_stack_trace(event)
    for line in stack_lines:
        print("  %s" % line)

    print("-" * 80)

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching probes and exiting...")
        sys.exit(0)
    except Exception as e:
        sys.stderr.write("ERROR during perf buffer polling: %s\n" % e)
        sys.exit(1)