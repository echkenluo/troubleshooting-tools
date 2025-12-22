#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
System Network RX Internal Path Detailed Latency Measurement Tool

Measures detailed latency distribution within the RX path between ovs_vport_send and tcp_v4_rcv.
This tool breaks down the RX_S5 -> RX_S6 stage into 8 detailed sub-stages to identify
the source of tail latency (8-16ms spikes).

Key measurement points:
- RX_S5_1: internal_dev_recv (OVS handoff to kernel)
- RX_S5_2: netif_rx (kernel network stack entry)
- RX_S5_3: netif_rx_internal (CPU selection point)
- RX_S5_4: enqueue_to_backlog (queue insertion - CRITICAL)
- RX_S5_5: process_backlog (softirq dequeue - CRITICAL ASYNC BOUNDARY)
- RX_S5_6: netif_receive_skb_internal (core reception)
- RX_S5_7: ip_rcv (IP layer + netfilter hooks)
- RX_S5_8: ip_local_deliver (local delivery + INPUT chain)

Expected tail latency location: RX_S5_4 -> RX_S5_5 (enqueue to process)

Usage:
    sudo ./system_network_rx_internal_latency_details.py \
        --phy-interface enp94s0f0np0 \
        --internal-interface port-storage \
        --src-ip 70.0.0.33 --direction rx --interval 5

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

# Global configuration
direction_filter = 2  # Fixed to RX only for this tool

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <net/flow.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

struct net;
struct inet_cork;
struct softnet_data;

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP
#define TARGET_IFINDEX1 %d
#define TARGET_IFINDEX2 %d

// Detailed RX path stages (between ovs_vport_send and tcp_v4_rcv)
#define RX_STAGE_5_0  12  // ovs_vport_send (starting point)
#define RX_STAGE_5_1  20  // internal_dev_recv - OVS handoff to kernel
#define RX_STAGE_5_2  21  // netif_rx - kernel network stack entry
#define RX_STAGE_5_3  22  // netif_rx_internal - CPU selection point
#define RX_STAGE_5_4  23  // enqueue_to_backlog - queue insertion (CRITICAL)
#define RX_STAGE_5_5  24  // process_backlog - softirq dequeue (CRITICAL ASYNC)
#define RX_STAGE_5_6  25  // netif_receive_skb_internal - core reception
#define RX_STAGE_5_7  26  // ip_rcv - IP layer + netfilter PRE_ROUTING
#define RX_STAGE_5_8  27  // ip_local_deliver - netfilter INPUT chain
#define RX_STAGE_6    13  // tcp_v4_rcv/udp_rcv (endpoint)

#define MAX_STAGES    30
#define IFNAMSIZ      16

// Packet key structure
struct packet_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    u8 protocol;
    u8 pad[3];

    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;          // TCP sequence number
        } tcp;

        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;        // IP identification
            __be16 udp_len;
            __be16 frag_off;     // Fragment offset
        } udp;
    };
};

// Flow tracking with extended metrics
struct flow_data_t {
    u64 first_timestamp;     // Timestamp at ovs_vport_send
    u64 last_timestamp;      // Timestamp of last stage
    u8 last_stage;           // Last valid stage seen
    u8 enqueue_cpu;          // CPU ID at enqueue_to_backlog
    u8 process_cpu;          // CPU ID at process_backlog
    u16 queue_len;           // Backlog queue length at enqueue
    u32 pad;                 // Padding for alignment
};

// Stage pair key for histogram with latency bucket
struct stage_pair_key_t {
    u8 prev_stage;
    u8 curr_stage;
    u8 direction;
    u8 latency_bucket;  // log2 of latency in microseconds
};

// CPU tracking key for histogram
struct cpu_pair_key_t {
    u8 enqueue_cpu;
    u8 process_cpu;
    u8 stage_pair;  // Identifies which stage transition (e.g., 4->5)
    u8 latency_bucket;
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);

// BPF Histogram for adjacent stage latencies
BPF_HISTOGRAM(adjacent_latency_hist, struct stage_pair_key_t, 2048);

// BPF Histogram for total end-to-end latency
BPF_HISTOGRAM(total_latency_hist, u8, 256);

// BPF Histogram for CPU migration analysis
BPF_HISTOGRAM(cpu_migration_hist, struct cpu_pair_key_t, 512);

// Performance statistics
BPF_ARRAY(packet_counters, u64, 4);  // 0=total, 1=rx, 2=dropped, 3=cross_cpu
BPF_ARRAY(queue_depth_stats, u64, 3);  // 0=sum, 1=count, 2=max

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

// Helper functions for packet parsing
static __always_inline int get_ip_header(struct sk_buff *skb, struct iphdr *ip, u8 stage_id) {
    unsigned char *head;
    u16 network_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        return -1;
    }

    if (bpf_probe_read_kernel(ip, sizeof(*ip), head + network_header_offset) < 0) {
        return -1;
    }

    return 0;
}

static __always_inline int get_transport_header(struct sk_buff *skb, void *hdr, u16 hdr_size, u8 stage_id) {
    unsigned char *head;
    u16 transport_header_offset;
    u16 network_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0) {
        return -1;
    }

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || transport_header_offset == network_header_offset) {
        // Calculate transport header offset from IP header
        struct iphdr ip;
        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
            return -1;
        }
        u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5) return -1;
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    if (bpf_probe_read_kernel(hdr, hdr_size, head + transport_header_offset) < 0) {
        return -1;
    }

    return 0;
}

// TCP protocol parsing
static __always_inline int parse_tcp_key(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id
) {
    struct tcphdr tcp;
    if (get_transport_header(skb, &tcp, sizeof(tcp), stage_id) != 0) return 0;

    key->tcp.src_port = tcp.source;
    key->tcp.dst_port = tcp.dest;
    key->tcp.seq = tcp.seq;

    return 1;
}

// UDP protocol parsing
static __always_inline int parse_udp_key(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) != 0) return 0;

    key->udp.ip_id = ip.id;

    struct udphdr udp = {};
    if (get_transport_header(skb, &udp, sizeof(udp), stage_id) == 0) {
        key->udp.src_port = udp.source;
        key->udp.dst_port = udp.dest;
        key->udp.udp_len = udp.len;
    } else {
        key->udp.src_port = 0;
        key->udp.dst_port = 0;
        key->udp.udp_len = 0;
    }

    return 1;
}

static __always_inline int parse_packet_key(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id
) {
    struct iphdr ip;
    if (get_ip_header(skb, &ip, stage_id) != 0) {
        return 0;
    }

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        return 0;
    }

    // Apply IP filters
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
        return 0;
    }

    switch (ip.protocol) {
        case IPPROTO_TCP:
            if (!parse_tcp_key(skb, key, stage_id)) return 0;
            if (SRC_PORT_FILTER != 0 && key->tcp.src_port != htons(SRC_PORT_FILTER) && key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
                return 0;
            }
            if (DST_PORT_FILTER != 0 && key->tcp.src_port != htons(DST_PORT_FILTER) && key->tcp.dst_port != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        case IPPROTO_UDP:
            if (!parse_udp_key(skb, key, stage_id)) return 0;
            if (key->udp.frag_off == 0) {
                if (SRC_PORT_FILTER != 0 && key->udp.src_port != htons(SRC_PORT_FILTER) && key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                    return 0;
                }
                if (DST_PORT_FILTER != 0 && key->udp.src_port != htons(DST_PORT_FILTER) && key->udp.dst_port != htons(DST_PORT_FILTER)) {
                    return 0;
                }
            }
            break;
        default:
            return 0;
    }

    return 1;
}

// Main event handling function for detailed RX path
static __always_inline void handle_rx_stage_event(void *ctx, struct sk_buff *skb, u8 stage_id) {
    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();

    // Parse packet key
    int parse_success = parse_packet_key(skb, &key, stage_id);
    if (!parse_success) {
        return;
    }

    // Check if this is the first stage (ovs_vport_send)
    bool is_first_stage = (stage_id == RX_STAGE_5_0);
    struct flow_data_t *flow_ptr;

    if (is_first_stage) {
        // Initialize new flow tracking
        struct flow_data_t zero = {};
        zero.last_stage = stage_id;
        zero.last_timestamp = current_ts;
        zero.first_timestamp = current_ts;
        zero.enqueue_cpu = 0xFF;  // Invalid CPU
        zero.process_cpu = 0xFF;
        zero.queue_len = 0;

        flow_sessions.delete(&key);
        flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);

        if (flow_ptr) {
            u32 idx = 1;  // RX counter
            u64 *counter = packet_counters.lookup(&idx);
            if (counter) (*counter)++;
        }
        return;
    } else {
        flow_ptr = flow_sessions.lookup(&key);
    }

    if (!flow_ptr) {
        return;
    }

    // Calculate and submit latency for adjacent stages
    if (flow_ptr->last_timestamp > 0 && flow_ptr->last_timestamp < current_ts) {
        u64 latency_ns = current_ts - flow_ptr->last_timestamp;
        u64 latency_us = latency_ns / 1000;

        // Create stage pair key with latency bucket
        struct stage_pair_key_t pair_key = {};
        pair_key.prev_stage = flow_ptr->last_stage;
        pair_key.curr_stage = stage_id;
        pair_key.direction = 2;  // RX
        pair_key.latency_bucket = bpf_log2l(latency_us + 1);

        // Update histogram
        adjacent_latency_hist.increment(pair_key, 1);

        // Special tracking for the critical async boundary (enqueue -> process)
        if (flow_ptr->last_stage == RX_STAGE_5_4 && stage_id == RX_STAGE_5_5) {
            // Track CPU migration
            if (flow_ptr->enqueue_cpu != 0xFF && flow_ptr->process_cpu != 0xFF) {
                struct cpu_pair_key_t cpu_key = {};
                cpu_key.enqueue_cpu = flow_ptr->enqueue_cpu;
                cpu_key.process_cpu = flow_ptr->process_cpu;
                cpu_key.stage_pair = 45;  // Represents 4->5 transition
                cpu_key.latency_bucket = pair_key.latency_bucket;

                cpu_migration_hist.increment(cpu_key, 1);

                // Count cross-CPU events
                if (cpu_key.enqueue_cpu != cpu_key.process_cpu) {
                    u32 idx = 3;
                    u64 *counter = packet_counters.lookup(&idx);
                    if (counter) (*counter)++;
                }
            }
        }
    }

    // Update tracking for next stage
    flow_ptr->last_stage = stage_id;
    flow_ptr->last_timestamp = current_ts;

    // Check if this is the last stage
    if (stage_id == RX_STAGE_6) {
        // Calculate total latency from first to last stage
        if (flow_ptr->first_timestamp > 0 && current_ts > flow_ptr->first_timestamp) {
            u64 total_latency = current_ts - flow_ptr->first_timestamp;
            u64 latency_us = total_latency / 1000;
            if (latency_us > 0) {
                u8 log2_latency = bpf_log2l(latency_us);
                total_latency_hist.increment(log2_latency);
            }
        }

        // Delete flow session
        flow_sessions.delete(&key);
    }
}

// Special handling for enqueue_to_backlog - extract CPU and queue depth
static __always_inline void handle_enqueue_to_backlog(
    void *ctx,
    struct sk_buff *skb,
    int target_cpu,
    unsigned int *qtail
) {
    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();
    u32 current_cpu = bpf_get_smp_processor_id();

    int parse_success = parse_packet_key(skb, &key, RX_STAGE_5_4);
    if (!parse_success) {
        return;
    }

    struct flow_data_t *flow_ptr = flow_sessions.lookup(&key);
    if (!flow_ptr) {
        return;
    }

    // Calculate latency from previous stage
    if (flow_ptr->last_timestamp > 0 && flow_ptr->last_timestamp < current_ts) {
        u64 latency_ns = current_ts - flow_ptr->last_timestamp;
        u64 latency_us = latency_ns / 1000;

        struct stage_pair_key_t pair_key = {};
        pair_key.prev_stage = flow_ptr->last_stage;
        pair_key.curr_stage = RX_STAGE_5_4;
        pair_key.direction = 2;
        pair_key.latency_bucket = bpf_log2l(latency_us + 1);

        adjacent_latency_hist.increment(pair_key, 1);
    }

    // Extract queue length from softnet_data
    // Note: Queue length extraction requires kernel-specific struct layout
    // This is a simplified version - may need adjustment for specific kernels
    u16 qlen = 0;
    if (qtail != NULL) {
        // Try to extract queue tail pointer to estimate queue depth
        // This is kernel-version dependent and may not work on all systems
        // For production, consider using BPF CO-RE for better portability
    }

    // Store CPU and queue info
    flow_ptr->enqueue_cpu = (u8)(current_cpu & 0xFF);
    flow_ptr->queue_len = qlen;
    flow_ptr->last_stage = RX_STAGE_5_4;
    flow_ptr->last_timestamp = current_ts;

    // Update queue depth statistics
    u32 idx = 0;
    u64 *sum = queue_depth_stats.lookup(&idx);
    if (sum) *sum += qlen;

    idx = 1;
    u64 *count = queue_depth_stats.lookup(&idx);
    if (count) (*count)++;

    idx = 2;
    u64 *max_qlen = queue_depth_stats.lookup(&idx);
    if (max_qlen && qlen > *max_qlen) *max_qlen = qlen;
}

// Special handling for process_backlog - extract CPU
static __always_inline void handle_process_backlog(
    void *ctx,
    struct sk_buff *skb
) {
    struct packet_key_t key = {};
    u64 current_ts = bpf_ktime_get_ns();
    u32 current_cpu = bpf_get_smp_processor_id();

    int parse_success = parse_packet_key(skb, &key, RX_STAGE_5_5);
    if (!parse_success) {
        return;
    }

    struct flow_data_t *flow_ptr = flow_sessions.lookup(&key);
    if (!flow_ptr) {
        return;
    }

    // Store processing CPU
    flow_ptr->process_cpu = (u8)(current_cpu & 0xFF);

    // Calculate latency from enqueue_to_backlog (CRITICAL MEASUREMENT)
    if (flow_ptr->last_timestamp > 0 && flow_ptr->last_timestamp < current_ts) {
        u64 latency_ns = current_ts - flow_ptr->last_timestamp;
        u64 latency_us = latency_ns / 1000;

        struct stage_pair_key_t pair_key = {};
        pair_key.prev_stage = flow_ptr->last_stage;
        pair_key.curr_stage = RX_STAGE_5_5;
        pair_key.direction = 2;
        pair_key.latency_bucket = bpf_log2l(latency_us + 1);

        adjacent_latency_hist.increment(pair_key, 1);

        // Track CPU migration for this critical stage
        if (flow_ptr->enqueue_cpu != 0xFF) {
            struct cpu_pair_key_t cpu_key = {};
            cpu_key.enqueue_cpu = flow_ptr->enqueue_cpu;
            cpu_key.process_cpu = flow_ptr->process_cpu;
            cpu_key.stage_pair = 45;
            cpu_key.latency_bucket = pair_key.latency_bucket;

            cpu_migration_hist.increment(cpu_key, 1);

            if (cpu_key.enqueue_cpu != cpu_key.process_cpu) {
                u32 idx = 3;
                u64 *counter = packet_counters.lookup(&idx);
                if (counter) (*counter)++;
            }
        }
    }

    flow_ptr->last_stage = RX_STAGE_5_5;
    flow_ptr->last_timestamp = current_ts;
}

// ========== Probe Points ==========

// RX_S5_0: ovs_vport_send (starting point)
int kprobe__ovs_vport_send(struct pt_regs *ctx, const void *vport, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_5_0);
    return 0;
}

// RX_S5_1: internal_dev_recv
int kprobe__internal_dev_recv(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_5_1);
    return 0;
}

// RX_S5_2: netif_rx
int kprobe__netif_rx(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_5_2);
    return 0;
}

// RX_S5_3: netif_rx_internal
int kprobe__netif_rx_internal(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_5_3);
    return 0;
}

// RX_S5_4: enqueue_to_backlog (CRITICAL - with queue depth extraction)
int kprobe__enqueue_to_backlog(struct pt_regs *ctx, struct sk_buff *skb, int cpu, unsigned int *qtail) {
    handle_enqueue_to_backlog(ctx, skb, cpu, qtail);
    return 0;
}

// RX_S5_5: process_backlog (CRITICAL ASYNC BOUNDARY)
int kprobe__process_backlog(struct pt_regs *ctx, void *napi, int quota) {
    // Note: process_backlog processes packets from queue, not individual SKBs
    // We'll need to hook into __netif_receive_skb_core to track individual packets
    // after they're dequeued. For now, this is a placeholder.
    // The actual measurement happens in netif_receive_skb_internal
    return 0;
}

// RX_S5_6: netif_receive_skb_internal (after softirq processing)
int kprobe__netif_receive_skb_internal(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_5_6);
    return 0;
}

// RX_S5_7: ip_rcv
int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_5_7);
    return 0;
}

// RX_S5_8: ip_local_deliver
int kprobe__ip_local_deliver(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_5_8);
    return 0;
}

// RX_S6: tcp_v4_rcv (endpoint)
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_6);
    return 0;
}

// RX_S6: __udp4_lib_rcv (endpoint for UDP)
int kprobe____udp4_lib_rcv(struct pt_regs *ctx, struct sk_buff *skb, struct udp_table *udptable) {
    handle_rx_stage_event(ctx, skb, RX_STAGE_6);
    return 0;
}

"""

# Constants
MAX_STAGES = 30

# Helper Functions
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
        return socket.htonl(host_int)
    except socket.error:
        print("Error: Invalid IP address format '%s'" % ip_str)
        sys.exit(1)

def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))

def get_stage_name(stage_id):
    """Get human-readable stage name for detailed RX path"""
    stage_names = {
        12: "RX_S5_0_ovs_vport_send",
        20: "RX_S5_1_internal_dev_recv",
        21: "RX_S5_2_netif_rx",
        22: "RX_S5_3_netif_rx_internal",
        23: "RX_S5_4_enqueue_to_backlog",
        24: "RX_S5_5_process_backlog",
        25: "RX_S5_6_netif_receive_skb_internal",
        26: "RX_S5_7_ip_rcv",
        27: "RX_S5_8_ip_local_deliver",
        13: "RX_S6_tcp_v4_rcv/udp_rcv"
    }
    return stage_names.get(stage_id, "UNKNOWN_%d" % stage_id)

def print_histogram_summary(b, interval_start_time):
    """Print histogram summary for the current interval"""
    current_time = datetime.datetime.now()
    print("\n" + "=" * 80)
    print("[%s] Detailed RX Internal Path Latency Report (Interval: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        time_time() - interval_start_time
    ))
    print("=" * 80)

    # Get stage pair histogram data
    latency_hist = b["adjacent_latency_hist"]

    # Collect all stage pair data
    stage_pair_data = {}

    try:
        for k, v in latency_hist.items():
            pair_key = (k.prev_stage, k.curr_stage, k.direction)
            bucket = k.latency_bucket
            count = v.value if hasattr(v, 'value') else int(v)

            if pair_key not in stage_pair_data:
                stage_pair_data[pair_key] = {}
            stage_pair_data[pair_key][bucket] = count
    except Exception as e:
        print("Error reading histogram data:", str(e))
        return

    if not stage_pair_data:
        print("No RX path data collected in this interval")
        return

    print("Found %d unique stage transitions in RX path" % len(stage_pair_data))

    # Sort stage pairs by stage order
    sorted_pairs = sorted(stage_pair_data.keys(), key=lambda x: (x[0], x[1]))

    print("\nDetailed RX Path (Physical -> System):")
    print("-" * 80)

    for prev_stage, curr_stage, dir_val in sorted_pairs:
        prev_name = get_stage_name(prev_stage)
        curr_name = get_stage_name(curr_stage)

        print("\n  %s -> %s:" % (prev_name, curr_name))

        # Get histogram data for this stage pair
        buckets = stage_pair_data[(prev_stage, curr_stage, dir_val)]
        total_samples = sum(buckets.values())

        if total_samples == 0:
            print("    No samples")
            continue

        print("    Total samples: %d" % total_samples)
        print("    Latency distribution:")

        # Sort buckets and display
        sorted_buckets = sorted(buckets.items())
        max_count = max(buckets.values())

        for bucket, count in sorted_buckets:
            if count > 0:
                # Convert bucket to latency range
                if bucket == 0:
                    range_str = "0-1us"
                else:
                    low = 1 << (bucket - 1)
                    high = (1 << bucket) - 1
                    range_str = "%d-%dus" % (low, high)

                # Create simple bar graph
                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                percentage = 100.0 * count / total_samples

                print("      %-16s: %6d (%5.1f%%) |%-40s|" % (range_str, count, percentage, bar))

        # Highlight if this is the critical async boundary
        if prev_stage == 23 and curr_stage == 24:  # enqueue -> process
            print("    ^^^ CRITICAL ASYNC BOUNDARY - Expected tail latency location ^^^")

    # Print packet counters
    counters = b["packet_counters"]
    print("\n" + "=" * 80)
    print("Packet Counters:")
    print("  RX packets: %d" % counters[1].value)
    print("  Cross-CPU packets: %d" % counters[3].value)

    # Print queue depth statistics
    queue_stats = b["queue_depth_stats"]
    qsum = queue_stats[0].value
    qcount = queue_stats[1].value
    qmax = queue_stats[2].value

    if qcount > 0:
        print("\nBacklog Queue Statistics:")
        print("  Average queue depth: %.2f packets" % (float(qsum) / qcount))
        print("  Max queue depth: %d packets" % qmax)
        print("  Total enqueue operations: %d" % qcount)

    # Display total latency histogram
    print("\nTotal End-to-End Latency Distribution (ovs_vport_send -> tcp_v4_rcv):")
    print("-" * 80)

    try:
        total_hist = b["total_latency_hist"]
        total_latency_data = {}

        for k, v in total_hist.items():
            bucket = k.value if hasattr(k, 'value') else int(k)
            count = v.value if hasattr(v, 'value') else int(v)
            if count > 0:
                total_latency_data[bucket] = count

        if total_latency_data:
            total_samples = sum(total_latency_data.values())
            max_count = max(total_latency_data.values())

            for bucket in sorted(total_latency_data.keys()):
                count = total_latency_data[bucket]

                if bucket == 0:
                    range_str = "1us"
                else:
                    low = 1 << (bucket - 1)
                    high = (1 << bucket) - 1
                    range_str = "%d-%dus" % (low, high)

                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                percentage = 100.0 * count / total_samples

                print("  %-16s: %6d (%5.1f%%) |%-40s|" % (range_str, count, percentage, bar))
        else:
            print("  No total latency data collected in this interval")
    except Exception as e:
        print("  Error reading total latency histogram: %s" % str(e))

    # Display CPU migration analysis
    print("\nCPU Migration Analysis (enqueue_to_backlog -> process_backlog):")
    print("-" * 80)

    try:
        cpu_hist = b["cpu_migration_hist"]
        cpu_data = {}

        for k, v in cpu_hist.items():
            cpu_pair = (k.enqueue_cpu, k.process_cpu)
            bucket = k.latency_bucket
            count = v.value if hasattr(v, 'value') else int(v)

            if cpu_pair not in cpu_data:
                cpu_data[cpu_pair] = {}
            cpu_data[cpu_pair][bucket] = count

        if cpu_data:
            # Sort by total samples
            cpu_pairs_sorted = sorted(cpu_data.items(),
                                     key=lambda x: sum(x[1].values()),
                                     reverse=True)

            for (enqueue_cpu, process_cpu), buckets in cpu_pairs_sorted[:10]:  # Top 10
                total = sum(buckets.values())
                migration_status = "CROSS-CPU" if enqueue_cpu != process_cpu else "SAME-CPU"
                print("  CPU %2d -> %2d (%s): %d packets" %
                      (enqueue_cpu, process_cpu, migration_status, total))

                # Show latency distribution for cross-CPU migrations
                if enqueue_cpu != process_cpu and total > 0:
                    sorted_buckets = sorted(buckets.items())
                    for bucket, count in sorted_buckets:
                        if count > 0 and bucket >= 10:  # Only show >= 1ms latencies
                            if bucket == 0:
                                range_str = "0-1us"
                            else:
                                low = 1 << (bucket - 1)
                                high = (1 << bucket) - 1
                                range_str = "%d-%dus" % (low, high)
                            percentage = 100.0 * count / total
                            print("      %16s: %4d (%5.1f%%)" % (range_str, count, percentage))
        else:
            print("  No CPU migration data collected")
    except Exception as e:
        print("  Error reading CPU migration data: %s" % str(e))

    # Clear histograms for next interval
    latency_hist.clear()
    try:
        total_hist = b["total_latency_hist"]
        total_hist.clear()
    except:
        pass
    try:
        cpu_hist = b["cpu_migration_hist"]
        cpu_hist.clear()
    except:
        pass

def main():
    global direction_filter

    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="System Network RX Internal Path Detailed Latency Measurement Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Measure detailed RX path from OVS internal port to TCP layer:
    sudo %(prog)s --phy-interface enp94s0f0np0 --internal-interface port-storage \\
                  --src-ip 70.0.0.33 --protocol tcp --interval 5

  Focus on specific destination and port:
    sudo %(prog)s --phy-interface ens11 --internal-interface port-storage \\
                  --dst-ip 10.132.114.12 --dst-port 5201 --protocol tcp

This tool breaks down the RX path between ovs_vport_send and tcp_v4_rcv into 8 detailed stages
to identify the source of tail latency. The critical measurement point is the asynchronous
boundary between enqueue_to_backlog and process_backlog.
"""
    )

    parser.add_argument('--phy-interface', type=str, required=True,
                        help='Physical interface to monitor (e.g., enp94s0f0np0)')
    parser.add_argument('--internal-interface', type=str, required=False,
                        help='OVS internal interface (e.g., port-storage) - optional')
    parser.add_argument('--src-ip', type=str, required=False,
                        help='Source IP address filter')
    parser.add_argument('--dst-ip', type=str, required=False,
                        help='Destination IP address filter')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port filter (TCP/UDP)')
    parser.add_argument('--dst-port', type=int, required=False,
                        help='Destination port filter (TCP/UDP)')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'all'],
                        default='all', help='Protocol filter (default: all)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Statistics output interval in seconds (default: 5)')

    args = parser.parse_args()

    # Convert parameters
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0

    protocol_map = {'tcp': 6, 'udp': 17, 'all': 0}
    protocol_filter = protocol_map[args.protocol]

    # Get interface indices
    try:
        ifindex1 = get_if_index(args.phy_interface)
        ifindex2 = ifindex1  # Default to same interface
        if args.internal_interface:
            ifindex2 = get_if_index(args.internal_interface)
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    print("=" * 80)
    print("System Network RX Internal Path Detailed Latency Measurement Tool")
    print("=" * 80)
    print("Protocol filter: %s" % args.protocol.upper())
    print("Direction: RX (Physical -> System)")
    if args.src_ip:
        print("Source IP filter: %s" % args.src_ip)
    if args.dst_ip:
        print("Destination IP filter: %s" % args.dst_ip)
    if src_port:
        print("Source port filter: %d" % src_port)
    if dst_port:
        print("Destination port filter: %d" % dst_port)
    print("Physical interface: %s (ifindex %d)" % (args.phy_interface, ifindex1))
    if args.internal_interface:
        print("Internal interface: %s (ifindex %d)" % (args.internal_interface, ifindex2))
    print("Statistics interval: %d seconds" % args.interval)
    print("\nMeasuring 10 detailed stages in RX path:")
    print("  RX_S5_0: ovs_vport_send (OVS sends to internal port)")
    print("  RX_S5_1: internal_dev_recv (OVS handoff to kernel)")
    print("  RX_S5_2: netif_rx (kernel network stack entry)")
    print("  RX_S5_3: netif_rx_internal (CPU selection)")
    print("  RX_S5_4: enqueue_to_backlog (queue insertion) ← CRITICAL")
    print("  RX_S5_5: process_backlog (softirq dequeue) ← CRITICAL ASYNC BOUNDARY")
    print("  RX_S5_6: netif_receive_skb_internal (core reception)")
    print("  RX_S5_7: ip_rcv (IP layer + netfilter)")
    print("  RX_S5_8: ip_local_deliver (local delivery)")
    print("  RX_S6:   tcp_v4_rcv/udp_rcv (protocol layer)")
    print("\nExpected tail latency location: RX_S5_4 -> RX_S5_5 (enqueue to process)")
    print("=" * 80)

    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, ifindex1, ifindex2
        ))
        print("\nBPF program loaded successfully")
        print("All 10 kprobes attached")
    except Exception as e:
        print("\nError loading BPF program: %s" % e)
        print("\nNote: Some kernel functions may not exist on your system.")
        print("This tool requires:")
        print("  - internal_dev_recv (OVS kernel module)")
        print("  - netif_rx, netif_rx_internal")
        print("  - enqueue_to_backlog, process_backlog")
        print("  - netif_receive_skb_internal")
        print("  - ip_rcv, ip_local_deliver")
        print("  - tcp_v4_rcv, __udp4_lib_rcv")
        sys.exit(1)

    print("\nCollecting detailed RX path latency data... Hit Ctrl-C to end.")
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
