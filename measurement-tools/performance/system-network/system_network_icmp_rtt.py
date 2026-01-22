#!/usr/bin/env python
# -*- coding: utf-8 -*-

# curl -fLO http://192.168.17.20/tmp/bpftools/x86_64/bcc-0.21.0-1.el7.x86_64.rpm
# curl -fLO http://192.168.17.20/tmp/bpftools/noarch/python-bcc-0.21.0-1.el7.noarch.rpm 
# rpm -ivh bcc-0.21.0-1.el7.x86_64.rpm python-bcc-0.21.0-1.el7.noarch.rpm --force 

# ./icmp_rtt_latency.py --help
# usage: icmp_rtt_latency.py [-h] --src-ip SRC_IP --dst-ip DST_IP --phy-iface1
#                            PHY_IFACE1 [--phy-iface2 PHY_IFACE2]
#                            [--latency-ms LATENCY_MS]
#                            [--direction {tx,rx}]
#                            [--disable-kernel-stacks]

# Trace full round-trip ICMP latency through the Linux network stack and OVS.

# optional arguments:
#   -h, --help            show this help message and exit
#   --src-ip SRC_IP       Primary IP of the host where this script runs. This IP
#                         is used as SRC_IP_FILTER in BPF. For "outgoing" trace,
#                         this is the ICMP request source. For "incoming" trace,
#                         this is the local IP that receives the request and
#                         sends the reply.
#   --dst-ip DST_IP       Secondary IP involved in the trace. This IP is used as
#                         DST_IP_FILTER in BPF. For "outgoing" trace, this is
#                         the ICMP request destination. For "incoming" trace,
#                         this is the remote IP sending the request.
#   --phy-iface1 PHY_IFACE1
#                         First physical interface to monitor (e.g., for
#                         net_dev_xmit on request path, or __netif_receive_skb
#                         on reply path).
#   --phy-iface2 PHY_IFACE2
#                         Second physical interface to monitor. If not provided,
#                         phy-iface1 will be used for both checks (effectively
#                         monitoring a single interface).
#   --latency-ms LATENCY_MS
#                         Minimum round-trip latency threshold in ms to report
#                         (default: 0, report all).
#   --direction {tx,rx}
#                         Direction of ICMP trace: "tx" (local host pings
#                         remote) or "rx" (remote host pings local).
#                         Default: tx.
#   --disable-kernel-stacks
#                         Disable printing of kernel stack traces for each
#                         stage.

# Examples:
#   TX ping from 192.168.1.10 to 192.168.1.20, interfaces eth0, eth1:
#     sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20                                --phy-iface1 eth0 --phy-iface2 eth1 --direction tx

#   RX ping to 192.168.1.10 from 192.168.1.20, interfaces eth0, eth1:
#     sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20                                --phy-iface1 eth0 --phy-iface2 eth1 --direction rx
#                                 (Note: src-ip is still the local IP being traced)
# 
# This tool traces the complete round-trip latency of ICMP packets:
# - TX path: Application -> Protocol Stack -> OVS Internal Port -> OVS Kernel Module -> Physical NIC -> External
# - RX path: External -> Physical NIC -> OVS Kernel Module -> OVS Internal Port -> Protocol Stack -> Application
#
# It identifies matching ICMP request/reply pairs and reports segment latencies for both paths.
# Supports "tx" (local host initiates ping) and "rx" (remote host initiates ping to local host) traces.
#
#    sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                               --phy-iface1 eth0 --phy-iface2 eth1 \
#                               [--latency-ms 10] [--direction tx]
#
#    sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#                               --phy-iface1 eth0 --phy-iface2 eth1 \
#                               [--latency-ms 2] [--direction rx]
#    


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
import fcntl # Needed for ioctl

# --- BPF Program ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define LATENCY_THRESHOLD_NS %d
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d
#define TRACE_DIRECTION %d // 0 for TX (default), 1 for RX

// Define stages for Path 1 (e.g., TX Request for TX, RX Request for RX)
#define PATH1_STAGE_0    0
#define PATH1_STAGE_1    1
#define PATH1_STAGE_2    2
#define PATH1_STAGE_3    3
#define PATH1_STAGE_4    4
#define PATH1_STAGE_5    5
#define PATH1_STAGE_6    6

// Define stages for Path 2 (e.g., RX Reply for TX, TX Reply for RX)
#define PATH2_STAGE_0    7
#define PATH2_STAGE_1    8
#define PATH2_STAGE_2    9
#define PATH2_STAGE_3    10
#define PATH2_STAGE_4    11
#define PATH2_STAGE_5    12
#define PATH2_STAGE_6    13

#define MAX_STAGES               14
#define IFNAMSIZ                 16

#define TASK_COMM_LEN            16


// Packet key structure to uniquely identify and match ICMP request/reply pairs
// Note: sip and dip in this key will be canonical (SRC_IP_FILTER, DST_IP_FILTER)
struct packet_key_t {
    __be32 sip; // Canonical source IP for the trace
    __be32 dip; // Canonical destination IP for the trace
    u8  proto;
    __be16 id;
    __be16 seq;
};

// Structure to track TX/RX flow data and timestamps
struct flow_data_t {
    u64 ts[MAX_STAGES];
    u64 skb_ptr[MAX_STAGES];
    int kstack_id[MAX_STAGES];
    
    // Tracking info for Path 1 (TX for TX, RX for RX)
    u32 p1_pid; // PID associated with start of Path 1
    char p1_comm[TASK_COMM_LEN]; // Comm for Path 1
    char p1_ifname[IFNAMSIZ]; // Interface for Path 1 start

    // Tracking info for Path 2 (RX for TX, TX for RX)
    u32 p2_pid; // PID associated with start of Path 2
    char p2_comm[TASK_COMM_LEN]; // Comm for Path 2
    char p2_ifname[IFNAMSIZ]; // Interface for Path 2 start
        
    // ICMP type info
    u8 request_type; // ICMP type of the request packet (Path 1)
    u8 reply_type;   // ICMP type of the reply packet (Path 2)
    
    // Flags for path tracking
    u8 saw_path1_start:1;
    u8 saw_path1_end:1;
    u8 saw_path2_start:1;
    u8 saw_path2_end:1;
};

// Structure for perf event output
struct event_data_t {
    struct packet_key_t key;
    struct flow_data_t data;
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);
BPF_STACK_TRACE(stack_traces, 10240);
BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(event_scratch_map, struct event_data_t, 1);

// Helper function to check if an interface index matches our targets
static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;
    
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }
    
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }
    
    return (ifindex == TARGET_IFINDEX1 || ifindex == TARGET_IFINDEX2);
}

// Function to manually parse SKB data coming from userspace (different structure)
static __always_inline int parse_packet_key_userspace(struct sk_buff *skb, struct packet_key_t *key,
                                                     u8 *icmp_type_out, int path_is_primary) {
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
    
    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    u8 expected_icmp_type_val;

    if (path_is_primary) { 
        if (!(actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER)) {
        return 0;
    }
        expected_icmp_type_val = ICMP_ECHO;
    } else { 
        if (!(actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER)) {
        return 0;
    }
        expected_icmp_type_val = ICMP_ECHOREPLY;
    }
    
    if (ip.protocol != IPPROTO_ICMP) {
        return 0;
    }

    u8 ip_ihl = ip.ihl & 0x0F;  
    if (ip_ihl < 5) {  
        return 0;
    }

    // Calculate transport offset based on net_offset and ip_ihl
    unsigned int trans_offset = net_offset + (ip_ihl * 4);
    //bpf_trace_printk("ParseUserPktKey: Stg=4, actual_sip=%%x, actual_dip=%%x", actual_sip, actual_dip);
    //bpf_trace_printk("ParseUserPktKey: Stg=4, mac_offset=%%d, net_hdr_off=%%d, trans_hdr_off=%%d", mac_offset, net_offset, trans_offset);
    
    struct icmphdr icmph;
    // Use skb_head (local alias for skb->head) and locally calculated trans_offset
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), skb_head + trans_offset) < 0) {
        //bpf_trace_printk("ParseUserPktKey: Stg=4, probe_read_kernel trasport header failed");
        return 0;
    }

    if (icmph.type != expected_icmp_type_val) {
        //bpf_trace_printk("ParseUserPktKey: Stg=4, icmp_type mismatch, expected=%%d, actual=%%d", expected_icmp_type_val, icmph.type);
        return 0;
    }
    //bpf_trace_printk("ParseUserPktKey: Stg=4, icmp_type=%%d, icmp_seq=%%d, icmp_id=%%d", icmph.type, icmph.un.echo.sequence, icmph.un.echo.id);

    *icmp_type_out = icmph.type;
    key->sip = SRC_IP_FILTER; 
    key->dip = DST_IP_FILTER;
    key->proto = ip.protocol; 
    key->id = icmph.un.echo.id;
    key->seq = icmph.un.echo.sequence;

    return 1;
}

static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key_t *key,
                                           u8 *icmp_type_out, int path_is_primary, u8 stage_id) {
    if (stage_id == PATH1_STAGE_4 || stage_id == PATH2_STAGE_4) {
         return parse_packet_key_userspace(skb, key, icmp_type_out, path_is_primary);
    }

    if (skb == NULL) {
        return 0;
    }

    unsigned char *head;
    u16 network_header_offset;
    u16 transport_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0) {
        return 0;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 2048 ) {
        return 0;
    }

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        return 0;
    }

    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    u8 expected_icmp_type_val;

    if (ip.protocol != IPPROTO_ICMP) {
        return 0;
    }

    if (path_is_primary) {
        if (!(actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER)) {
            return 0;
        }
        expected_icmp_type_val = ICMP_ECHO;
    } else {
        if (!(actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER)) {
            return 0;
        }
        expected_icmp_type_val = ICMP_ECHOREPLY;
    }

    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) {
        return 0;
    }

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    struct icmphdr icmph;
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset) < 0) {
        return 0;
    }

    if (icmph.type != expected_icmp_type_val) {
        return 0;
    }

    *icmp_type_out = icmph.type;
    key->sip = SRC_IP_FILTER;
    key->dip = DST_IP_FILTER;
    key->proto = ip.protocol;
    key->id = icmph.un.echo.id;
    key->seq = icmph.un.echo.sequence;

    return 1;
}

static __always_inline void handle_event(struct pt_regs *ctx, struct sk_buff *skb,
                                         u64 current_stage_global_id, struct packet_key_t *parsed_packet_key, u8 actual_icmp_type) {
    if (skb == NULL) {
        return;
    }

    if (TRACE_DIRECTION == 0 && current_stage_global_id == PATH2_STAGE_0) {
        if (!is_target_ifindex(skb)){
            return;
        }
    }
    if (TRACE_DIRECTION == 1 && current_stage_global_id == PATH1_STAGE_0) {
         if (!is_target_ifindex(skb)){
            return;
        }
    }

    u64 current_ts = bpf_ktime_get_ns();
    int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);

    struct flow_data_t *flow_ptr;

    if (current_stage_global_id == PATH1_STAGE_0) {
        struct flow_data_t zero = {};
        flow_sessions.delete(parsed_packet_key);
        flow_ptr = flow_sessions.lookup_or_try_init(parsed_packet_key, &zero);
    } else {
        flow_ptr = flow_sessions.lookup(parsed_packet_key);
    }

    if (!flow_ptr) {
        return;
    }

    if (flow_ptr->ts[current_stage_global_id] == 0) {
        flow_ptr->ts[current_stage_global_id] = current_ts;
        flow_ptr->skb_ptr[current_stage_global_id] = (u64)skb;
        flow_ptr->kstack_id[current_stage_global_id] = stack_id;

        struct net_device *dev;
        char if_name_buffer[IFNAMSIZ];
        __builtin_memset(if_name_buffer, 0, IFNAMSIZ);

        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev != NULL) {
            bpf_probe_read_kernel_str(if_name_buffer, IFNAMSIZ, dev->name);
        } else {
            char unk[] = "unknown";
            bpf_probe_read_kernel_str(if_name_buffer, sizeof(unk), unk); 
        }

        if (current_stage_global_id == PATH1_STAGE_0) { 
            flow_ptr->p1_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p1_comm, sizeof(flow_ptr->p1_comm));
            bpf_probe_read_kernel_str(flow_ptr->p1_ifname, IFNAMSIZ, if_name_buffer);
            flow_ptr->request_type = actual_icmp_type;
            flow_ptr->saw_path1_start = 1;
        }

        if (current_stage_global_id == PATH1_STAGE_6) { 
            flow_ptr->saw_path1_end = 1;
        }

        if (current_stage_global_id == PATH2_STAGE_0) { 
            flow_ptr->p2_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p2_comm, sizeof(flow_ptr->p2_comm));
            bpf_probe_read_kernel_str(flow_ptr->p2_ifname, IFNAMSIZ, if_name_buffer);
            flow_ptr->reply_type = actual_icmp_type;
            flow_ptr->saw_path2_start = 1;
        }
        if (current_stage_global_id == PATH2_STAGE_6) { 
            flow_ptr->saw_path2_end = 1;
        }

        flow_sessions.update(parsed_packet_key, flow_ptr);
    } 

    u64 rtt_start_ts = 0;
    u64 rtt_end_ts = 0;


    if (current_stage_global_id == PATH2_STAGE_6 &&
        flow_ptr->saw_path1_start && flow_ptr->saw_path1_end &&
        flow_ptr->saw_path2_start && flow_ptr->saw_path2_end) {
        rtt_start_ts = flow_ptr->ts[PATH1_STAGE_0]; 
        rtt_end_ts = flow_ptr->ts[PATH2_STAGE_6];   

        if (LATENCY_THRESHOLD_NS > 0) {
            if (rtt_start_ts == 0 || rtt_end_ts == 0 || (rtt_end_ts - rtt_start_ts) < LATENCY_THRESHOLD_NS) {
                //bpf_trace_printk("HdlEvt: Latency below threshold. Stg=%%d", current_stage_global_id);
                return; 
            }
        }
        
        u32 map_key_zero = 0;
        struct event_data_t *event_data_ptr = event_scratch_map.lookup(&map_key_zero);
        if (!event_data_ptr) {
            return;
        }

        event_data_ptr->key = *parsed_packet_key;

        if (bpf_probe_read_kernel(&event_data_ptr->data, sizeof(event_data_ptr->data), flow_ptr) != 0) {
            flow_sessions.delete(parsed_packet_key);
            return;
        }

        events.perf_submit(ctx, event_data_ptr, sizeof(*event_data_ptr));

        flow_sessions.delete(parsed_packet_key);
    }
}

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {
        if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_0)) {
            handle_event(ctx, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    } else {
        if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_0)) {
            handle_event(ctx, skb, PATH2_STAGE_0, &key, icmp_type);
        }
    }
    return 0;
}

int kprobe__internal_dev_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {
        if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_1)) {
            handle_event(ctx, skb, PATH1_STAGE_1, &key, icmp_type);
        }
    } else {
        if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_1)) {
            handle_event(ctx, skb, PATH2_STAGE_1, &key, icmp_type);
        }
    }
    return 0;
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {
        if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_0)) {
            handle_event(args, skb, PATH2_STAGE_0, &key, icmp_type);
        }
    } else {
        if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_0)) {
            handle_event(args, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    }
    return 0;
}

int kprobe__netdev_frame_hook(struct pt_regs *ctx, struct sk_buff **pskb) {
    struct sk_buff *skb = NULL;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || skb == NULL) {
        return 0;
    }

    struct packet_key_t key_parsed = {};
    u8 icmp_type_parsed = 0;

    if (TRACE_DIRECTION == 0) {
        if (parse_packet_key(skb, &key_parsed, &icmp_type_parsed, 0, PATH2_STAGE_1)) {
            handle_event(ctx, skb, PATH2_STAGE_1, &key_parsed, icmp_type_parsed);
        }
    } else {
        if (parse_packet_key(skb, &key_parsed, &icmp_type_parsed, 1, PATH1_STAGE_1)) {
            handle_event(ctx, skb, PATH1_STAGE_1, &key_parsed, icmp_type_parsed);
        }
    }
    return 0;
}

int kprobe__ovs_dp_process_packet(struct pt_regs *ctx, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_2)) {
        handle_event(ctx, skb, PATH1_STAGE_2, &key, icmp_type);
    }
    key = (struct packet_key_t){}; icmp_type = 0;
    if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_2)) {
        handle_event(ctx, skb, PATH2_STAGE_2, &key, icmp_type);
    }

    return 0;
}

int kprobe__ovs_dp_upcall(struct pt_regs *ctx, void *dp, const struct sk_buff *skb_const) {
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_3)) {
        handle_event(ctx, skb, PATH1_STAGE_3, &key, icmp_type);
    }

    key = (struct packet_key_t){}; icmp_type = 0;
    if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_3)) {
        handle_event(ctx, skb, PATH2_STAGE_3, &key, icmp_type);
    }
    return 0;
}

int kprobe__ovs_flow_key_extract_userspace(struct pt_regs *ctx, struct net *net, const struct nlattr *attr, struct sk_buff *skb) {
    if (!skb) {
        return 0;
    }
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_4)) {
        handle_event(ctx, skb, PATH1_STAGE_4, &key, icmp_type);
    }

    key = (struct packet_key_t){}; icmp_type = 0;
    if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_4)) {
        handle_event(ctx, skb, PATH2_STAGE_4, &key, icmp_type);
    }
    return 0;
}

int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_5)) {
        handle_event(ctx, skb, PATH1_STAGE_5, &key, icmp_type);
    }

    key = (struct packet_key_t){}; icmp_type = 0;
    if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_5)) {
        handle_event(ctx, skb, PATH2_STAGE_5, &key, icmp_type);
    }
    return 0;
}

RAW_TRACEPOINT_PROBE(net_dev_xmit) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) {
        return 0;
    }
    if (!is_target_ifindex(skb)) {
        return 0;
    }

    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {
        if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_6)) {
            handle_event(ctx, skb, PATH1_STAGE_6, &key, icmp_type);
        }
    } else {
        if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_6)) {
            handle_event(ctx, skb, PATH2_STAGE_6, &key, icmp_type);
        }
    }
    return 0;
}

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct packet_key_t key = {};
    u8 icmp_type = 0;

    if (TRACE_DIRECTION == 0) {
        if (parse_packet_key(skb, &key, &icmp_type, 0, PATH2_STAGE_6)) {
            handle_event(ctx, skb, PATH2_STAGE_6, &key, icmp_type);
        }
    } else {
        if (parse_packet_key(skb, &key, &icmp_type, 1, PATH1_STAGE_6)) {
            handle_event(ctx, skb, PATH1_STAGE_6, &key, icmp_type);
        }
    }
    return 0;
}
"""

# Constants
MAX_STAGES = 14
IFNAMSIZ = 16
TASK_COMM_LEN = 16
class PacketKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32), 
        ("dip", ctypes.c_uint32), 
        ("proto", ctypes.c_uint8),
        ("id", ctypes.c_uint16),  
        ("seq", ctypes.c_uint16)  
    ]

class FlowData(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("skb_ptr", ctypes.c_uint64 * MAX_STAGES),
        ("kstack_id", ctypes.c_int * MAX_STAGES),
        ("p1_pid", ctypes.c_uint32),
        ("p1_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p1_ifname", ctypes.c_char * IFNAMSIZ),
        ("p2_pid", ctypes.c_uint32),
        ("p2_comm", ctypes.c_char * TASK_COMM_LEN),
        ("p2_ifname", ctypes.c_char * IFNAMSIZ),
        ("request_type", ctypes.c_uint8),
        ("reply_type", ctypes.c_uint8),
        ("saw_path1_start", ctypes.c_uint8, 1), 
        ("saw_path1_end", ctypes.c_uint8, 1),
        ("saw_path2_start", ctypes.c_uint8, 1),
        ("saw_path2_end", ctypes.c_uint8, 1)
    ]

class EventData(ctypes.Structure):
    _fields_ = [
        ("key", PacketKey),
        ("data", FlowData)
    ]


# --- Helper Functions ---
def get_if_index(devname):
    """Get the interface index for a device name"""
    SIOCGIFINDEX = 0x8933
    if len(devname.encode('ascii')) > 15:
        raise OSError("Interface name '%s' too long" % devname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('16s%dx' % (256-16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        idx = struct.unpack('I', res[16:20])[0]
        return idx
    except IOError as e:
        raise OSError("ioctl failed for interface '%s': %s" % (devname, e))
    finally:
        s.close()

def ip_to_hex(ip_str):
    """Convert IP string to network-ordered hex value"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int) # BPF expects network byte order for filters
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))


def format_latency(ts_start, ts_end):
    """Format latency value in microseconds"""
    if ts_start == 0 or ts_end == 0: # Only return N/A if one of the timestamps is actually zero
        return " N/A ".rjust(7)
    
    # Calculate delta, which can be negative if ts_end < ts_start
    delta_ns = ts_end - ts_start
    delta_us = delta_ns / 1000.0
    return ("%.3f" % delta_us).rjust(7)


def get_detailed_stage_name(stage_id, direction):
    """Returns a detailed stage name including the BPF probe point based on direction."""
    
    base_names = {
        0: "P1:S0_INIT", 1: "P1:S1_STACK_PROC", 2: "P1:S2_OVS_DP_PROC",
        3: "P1:S3_OVS_UPCALL", 4: "P1:S4_OVS_KEYEXT", 5: "P1:S5_OVS_VPORT_SND",
        6: "P1:S6_FINAL",
        7: "P2:S0_INIT", 8: "P2:S1_STACK_PROC", 9: "P2:S2_OVS_DP_PROC",
        10: "P2:S3_OVS_UPCALL", 11: "P2:S4_OVS_KEYEXT", 12: "P2:S5_OVS_VPORT_SND",
        13: "P2:S6_FINAL"
    }
    
    probe_map_tx = {
        0: "ip_output",       1: "internal_dev_xmit",  2: "ovs_dp_process_packet",
        3: "ovs_dp_upcall",     4: "ovs_flow_key_extract_userspace", 5: "ovs_vport_send",
        6: "net_dev_xmit",
        7: "__netif_receive_skb", 8: "netdev_frame_hook",  9: "ovs_dp_process_packet",
        10: "ovs_dp_upcall",    11: "ovs_flow_key_extract_userspace",12: "ovs_vport_send",
        13: "icmp_rcv"
    }

    probe_map_rx = {
        0: "__netif_receive_skb", 1: "netdev_frame_hook",  2: "ovs_dp_process_packet",
        3: "ovs_dp_upcall",     4: "ovs_flow_key_extract_userspace", 5: "ovs_vport_send",
        6: "icmp_rcv",
        7: "ip_output",       8: "internal_dev_xmit",  9: "ovs_dp_process_packet",
        10: "ovs_dp_upcall",    11: "ovs_flow_key_extract_userspace",12: "ovs_vport_send",
        13: "net_dev_xmit"
    }

    base_name = base_names.get(stage_id, "Unknown Stage")
    probe_name = ""

    if direction == "tx":
        probe_name = probe_map_tx.get(stage_id, "N/A")
    elif direction == "rx":
        probe_name = probe_map_rx.get(stage_id, "N/A")
    else: # Should not happen
        probe_name = "N/A"
        
    return "%s (%s)" % (base_name, probe_name)

def _print_latency_segment(start_idx, end_idx, flow_data, direction_str, label_suffix=""):
    """Helper function to print a single latency segment."""
    latency = format_latency(flow_data.ts[start_idx], flow_data.ts[end_idx])
    start_name = get_detailed_stage_name(start_idx, direction_str)
    end_name = get_detailed_stage_name(end_idx, direction_str)
    effective_label_suffix = " " + label_suffix if label_suffix else ""
    
    idx_part_str = "  [%2d->%-2d]" % (start_idx, end_idx) # Results in like "  [ 0->1 ]", "  [12->13]"
    stages_desc_str = "%s -> %s" % (start_name, end_name)
    
    stages_desc_padded_width = 105 
    
    print("%s %-*s: %s us%s" % (
        idx_part_str, 
        stages_desc_padded_width, 
        stages_desc_str, 
        latency, 
        effective_label_suffix
    ))

def _print_kernel_stack_trace_for_stage(stage_idx, stack_id):
    """Helper function to print a single kernel stack trace."""
    global args, b
    stage_name = get_detailed_stage_name(stage_idx, args.direction)
    print("  Stage %d (%s):" % (stage_idx, stage_name))

    if stack_id <= 0:
        print("    <BPF 'get_stackid' call failed or returned no stack: id=%d>" % stack_id)
        return

    try:
        if not b:
            print("    <BPF object 'b' is not available for stack traces>")
            return

        stack_table = b.get_table("stack_traces")
        resolved_one = False
        for addr in stack_table.walk(stack_id):
            sym = b.ksym(addr, show_offset=True)
            print("    %s" % sym)
            resolved_one = True
        
        if not resolved_one:
            print("    <Stack trace walk for id %d yielded no symbols>" % stack_id)

    except KeyError:
        print("    <'stack_traces' table not found in BPF object. Kernel may lack CONFIG_BPF_STACK_TRACE.>")
        if b and hasattr(b, 'tables'):
            print("    Available tables: %s" % list(b.tables.keys()))
        else:
            print("    BPF object 'b' or 'b.tables' not available to list tables.")
    except Exception as e:
        print("    <Python error during stack trace resolution for id %d: %s>" % (stack_id, e))

def print_all_kernel_stack_traces(flow_data):
    """Prints kernel stack traces for all relevant stages in the flow."""
    print("\nKernel Stack Traces (Path1: 0-6, Path2: 7-13):")
    for i in range(MAX_STAGES):
        if flow_data.ts[i] != 0: # Only print for stages that have a timestamp
            _print_kernel_stack_trace_for_stage(i, flow_data.kstack_id[i])

def print_event(cpu, data, size):
    global args 
    event = ctypes.cast(data, ctypes.POINTER(EventData)).contents
    key = event.key
    flow = event.data
    
    now = datetime.datetime.now()
    time_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    trace_dir_str = "TX (Local -> Remote)" if args.direction == "tx" else "RX (Remote -> Local)"
    
    print("=== ICMP RTT Trace: %s (%s) ===" % (time_str, trace_dir_str))
    print("Session: %s (%s) -> %s (%s) (ID: %d, Seq: %d)" % (
        args.src_ip if args.direction == "tx" else args.dst_ip,
        format_ip(key.sip),
        args.dst_ip if args.direction == "tx" else args.src_ip,
        format_ip(key.dip),   
        socket.ntohs(key.id), 
        socket.ntohs(key.seq)
    ))
    
    path1_desc_detail = ""
    path2_desc_detail = ""
    path_desc_padding_width = 45 # Define padding for path description

    if args.direction == "rx":
        path1_desc_detail = "Path 1 (Request: RX from %s)" % args.src_ip
        path2_desc_detail = "Path 2 (Reply:   TX to %s)" % args.src_ip
    else:
        path1_desc_detail = "Path 1 (Request: TX to %s)" % args.dst_ip
        path2_desc_detail = "Path 2 (Reply:   RX from %s)" % args.dst_ip

    print("%-*s: PID=%-6d COMM=%-12s IF=%-10s ICMP_Type=%d" % (
        path_desc_padding_width,
        path1_desc_detail,
        flow.p1_pid, 
        flow.p1_comm.decode('utf-8', 'replace'),
        flow.p1_ifname.decode('utf-8', 'replace'),
        flow.request_type
    ))
    
    print("%-*s: PID=%-6d COMM=%-12s IF=%-10s ICMP_Type=%d" % (
        path_desc_padding_width,
        path2_desc_detail,
        flow.p2_pid, 
        flow.p2_comm.decode('utf-8', 'replace'),
        flow.p2_ifname.decode('utf-8', 'replace'),
        flow.reply_type
    ))
        
    print("\nSKB Pointers (Path1: 0-6, Path2: 7-13):")
    stage_name_padding_width = 45 # Define padding for stage name in SKB pointer lines
    for i in range(MAX_STAGES):
        if flow.skb_ptr[i] != 0:
            stage_name_str = get_detailed_stage_name(i, args.direction)
            print("  Stage %2d (%-*s): 0x%x" % (
                i, stage_name_padding_width, stage_name_str, flow.skb_ptr[i]
            ))
    
    print("\nPath 1 Latencies (us):")
    # Always print 0->1 and 1->2 if timestamps exist (format_latency handles N/A if not)
    _print_latency_segment(0, 1, flow, args.direction)
    _print_latency_segment(1, 2, flow, args.direction)

    # OVS Kernel Path vs OVS Upcall Path for Path 1
    has_s2_p1 = flow.ts[2] > 0
    has_s3_p1 = flow.ts[3] > 0 # OVS Upcall
    has_s4_p1 = flow.ts[4] > 0 # OVS Key Extract
    has_s5_p1 = flow.ts[5] > 0 # OVS Vport Send

    if has_s2_p1 and has_s3_p1: # From OVS DP to OVS Upcall
        _print_latency_segment(2, 3, flow, args.direction)

    if has_s3_p1 and has_s4_p1 and has_s5_p1: # Full upcall path: S3 -> S4 -> S5
        _print_latency_segment(3, 4, flow, args.direction) # OVS Upcall -> OVS KeyExt
        _print_latency_segment(4, 5, flow, args.direction) # OVS KeyExt -> OVS VportSnd
    elif has_s3_p1 and not has_s4_p1 and has_s5_p1: # Upcall happened, S4 missing, but S3 and S5 present
        _print_latency_segment(3, 5, flow, args.direction, label_suffix="(S4 N/A)")
    elif has_s2_p1 and not has_s3_p1 and not has_s4_p1 and has_s5_p1: # Kernel path, no upcall (S3 & S4 are zero)
        _print_latency_segment(2, 5, flow, args.direction, label_suffix="(OVS No Upcall)")
    # Cases where S5 might be missing if S3 or S4 are hit are implicitly handled
    # as _print_latency_segment will show N/A for the segment if an endpoint is missing.

    _print_latency_segment(5, 6, flow, args.direction)

    if flow.ts[0] > 0 and flow.ts[6] > 0:
        path1_total = format_latency(flow.ts[0], flow.ts[6])
        print("  Total Path 1: %s us" % path1_total)
    
    print("\nPath 2 Latencies (us):")
    _print_latency_segment(7, 8, flow, args.direction)
    _print_latency_segment(8, 9, flow, args.direction)

    # OVS Kernel Path vs OVS Upcall Path for Path 2
    has_s9_p2 = flow.ts[9] > 0
    has_s10_p2 = flow.ts[10] > 0 # OVS Upcall
    has_s11_p2 = flow.ts[11] > 0 # OVS Key Extract
    has_s12_p2 = flow.ts[12] > 0 # OVS Vport Send

    if has_s9_p2 and has_s10_p2: # From OVS DP to OVS Upcall
        _print_latency_segment(9, 10, flow, args.direction)

    if has_s10_p2 and has_s11_p2 and has_s12_p2: # Full upcall path: S10 -> S11 -> S12
        _print_latency_segment(10, 11, flow, args.direction)
        _print_latency_segment(11, 12, flow, args.direction)
    elif has_s10_p2 and not has_s11_p2 and has_s12_p2: # Upcall happened, S11 missing, but S10 and S12 present
        _print_latency_segment(10, 12, flow, args.direction, label_suffix="(S11 N/A)")
    elif has_s9_p2 and not has_s10_p2 and not has_s11_p2 and has_s12_p2: # Kernel path, no upcall (S10 & S11 are zero)
        _print_latency_segment(9, 12, flow, args.direction, label_suffix="(OVS No Upcall)")

    _print_latency_segment(12, 13, flow, args.direction)

    if flow.ts[7] > 0 and flow.ts[13] > 0:
        path2_total = format_latency(flow.ts[7], flow.ts[13])
        print("  Total Path 2: %s us" % path2_total)
    
    if flow.ts[0] > 0 and flow.ts[13] > 0:
        rtt = format_latency(flow.ts[0], flow.ts[13])
        print("\nTotal RTT (Path1 Start to Path2 End): %s us" % rtt)
        
        if flow.ts[6] > 0 and flow.ts[7] > 0:
            inter_path_latency = format_latency(flow.ts[6], flow.ts[7])
            print("Inter-Path Latency (P1 end -> P2 start): %s us" % inter_path_latency)
    
    if not args.disable_kernel_stacks:
        print_all_kernel_stack_traces(flow)
    
    print("\n" + "="*50 + "\n")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Trace full round-trip ICMP latency through the Linux network stack and OVS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  TX ping from 192.168.1.10 to 192.168.1.20, interfaces eth0, eth1:
    sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                               --phy-iface1 eth0 --phy-iface2 eth1 --direction tx

  RX ping to 192.168.1.10 from 192.168.1.20, interfaces eth0, eth1:
    sudo ./icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                               --phy-iface1 eth0 --phy-iface2 eth1 --direction rx
                                (Note: src-ip is still the local IP being traced)
"""
    )
    
    parser.add_argument('--src-ip', type=str, required=True, 
                      help='Primary IP of the host where this script runs. This IP is used as SRC_IP_FILTER in BPF. For "tx" trace, this is the ICMP request source. For "rx" trace, this is the local IP that receives the request and sends the reply.')
    parser.add_argument('--dst-ip', type=str, required=True,
                      help='Secondary IP involved in the trace. This IP is used as DST_IP_FILTER in BPF. For "tx" trace, this is the ICMP request destination. For "rx" trace, this is the remote IP sending the request.')
    parser.add_argument('--phy-interface', type=str, required=True,
                      help='Physical interface(s) to monitor. Supports comma-separated list for bond members (e.g., enp94s0f0np0 or eth0,eth1)')
    parser.add_argument('--latency-ms', type=float, default=0,
                      help='Minimum round-trip latency threshold in ms to report (default: 0, report all).')
    parser.add_argument('--direction', type=str, choices=["tx", "rx"], default="tx",
                      help='Direction of ICMP trace: "tx" (local host pings remote) or "rx" (remote host pings local). Default: tx.')
    parser.add_argument('--disable-kernel-stacks', action='store_true', default=False,
                      help='Disable printing of kernel stack traces for each stage.')
    
    args = parser.parse_args()
    
    direction_val = 0 if args.direction == "tx" else 1

    # Support multiple interfaces (split by comma)
    phy_interfaces = args.phy_interface.split(',')
    try:
        ifindex1 = get_if_index(phy_interfaces[0].strip())
        ifindex2 = get_if_index(phy_interfaces[1].strip()) if len(phy_interfaces) > 1 else ifindex1
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    src_ip_hex_val = ip_to_hex(args.src_ip)
    dst_ip_hex_val = ip_to_hex(args.dst_ip)

    latency_threshold_ns_val = int(args.latency_ms * 1000000)

    print("=== ICMP Round-Trip Latency Tracer ===")
    print("Trace Direction: %s" % args.direction.upper())
    print("SRC_IP_FILTER (Configured Local IP): %s (0x%x)" % (args.src_ip, socket.ntohl(src_ip_hex_val)))
    print("DST_IP_FILTER (Configured Remote IP): %s (0x%x)" % (args.dst_ip, socket.ntohl(dst_ip_hex_val)))
    print("Physical interfaces: %s (ifindex %d, %d)" % (args.phy_interface, ifindex1, ifindex2))
    
    if latency_threshold_ns_val > 0:
        print("Reporting only round trips with latency >= %.3f ms" % args.latency_ms)
    
    try:
        b = BPF(text=bpf_text % (
            src_ip_hex_val, 
            dst_ip_hex_val, 
            latency_threshold_ns_val,
            ifindex1, 
            ifindex2,
            direction_val  
        ))
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        print("\nEnsure all kprobe function names in the BPF C code are correct for your kernel version.")
        sys.exit(1)
        
    probe_functions = [
        ("ip_output", "kprobe__ip_output"),
        ("internal_dev_xmit", "kprobe__internal_dev_xmit"),
        ("netdev_frame_hook", "kprobe__netdev_frame_hook"),
        ("ovs_dp_process_packet", "kprobe__ovs_dp_process_packet"),
        ("ovs_dp_upcall", "kprobe__ovs_dp_upcall"),
        ("ovs_flow_key_extract_userspace", "kprobe__ovs_flow_key_extract_userspace"),
        ("ovs_vport_send", "kprobe__ovs_vport_send"),
        ("net_dev_xmit", "raw_tracepoint__net_dev_xmit"),
        ("icmp_rcv", "kprobe__icmp_rcv")
    ]

    b["events"].open_perf_buffer(print_event) 
    
    print("\nTracing ICMP RTT for src_ip=%s, dst_ip=%s, direction=%s ... Hit Ctrl-C to end." % (args.src_ip, args.dst_ip, args.direction))
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
        print("Exiting.") 
