#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Focused RX Latency Measurement: enqueue_to_backlog → ip_rcv

Measures the critical async boundary latency in the Linux kernel RX path
on a SINGLE specified interface.

Measurement points:
- Stage 1: enqueue_to_backlog - Packet queued to per-CPU backlog
- Stage 2: __netif_receive_skb - Packet dequeued and processed (CRITICAL)
- Stage 3: ip_rcv - IP layer entry

Includes comprehensive debugging framework to diagnose missing probe hits.

Usage:
    # Monitor physical NIC
    sudo ./enqueue_to_iprec_latency.py \
        --interface enp24s0f0np0 \
        --src-ip 70.0.0.32 --dst-ip 70.0.0.31 \
        --dst-port 2181 --protocol tcp --interval 1

    # Monitor OVS internal port
    sudo ./enqueue_to_iprec_latency.py \
        --interface br-int \
        --dst-ip 70.0.0.31 --protocol tcp --interval 1

Debug mode:
    sudo ./enqueue_to_iprec_latency.py --interface enp24s0f0np0 --debug
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

from time import sleep, time as time_time
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

// Compatibility fixes for older BCC versions (0.15.0) with newer kernels (5.10+)
// BCC 0.15.0 doesn't define these enums that kernel 5.10+ expects
// Must be defined BEFORE including headers that use them
#ifndef BPF_SK_LOOKUP
#define BPF_SK_LOOKUP 36
#endif

#ifndef BPF_CGROUP_INET_SOCK_RELEASE
#define BPF_CGROUP_INET_SOCK_RELEASE 34
#endif

#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <net/inet_sock.h>

// User-defined filters
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d
#define PROTOCOL_FILTER %d  // 0=all, 6=TCP, 17=UDP
#define TARGET_IFINDEX %d
#define HIGH_LATENCY_THRESHOLD_US %d
#define ENABLE_HIGH_LATENCY_EVENTS %d

// Stage definitions
#define STAGE_ENQUEUE     1  // enqueue_to_backlog
#define STAGE_RECEIVE     2  // __netif_receive_skb
#define STAGE_IP_RCV      3  // ip_rcv

// Debug code points (following bcc-debug-framework.md)
#define CODE_PROBE_ENTRY           1
#define CODE_HANDLE_ENTRY          5
#define CODE_PARSE_ENTRY           6
#define CODE_PARSE_SUCCESS         7
#define CODE_PARSE_IP_FILTER       8
#define CODE_PARSE_PROTO_FILTER    9
#define CODE_PARSE_PORT_FILTER    10
#define CODE_FLOW_CREATE          14
#define CODE_FLOW_LOOKUP          15
#define CODE_FLOW_FOUND           16
#define CODE_FLOW_NOT_FOUND       17
#define CODE_LATENCY_SUBMIT       19

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
            __be32 seq;
        } tcp;

        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;
            __be16 udp_len;
        } udp;
    };
};

// Flow tracking
struct flow_data_t {
    u64 enqueue_ts;      // Timestamp at enqueue_to_backlog
    u64 receive_ts;      // Timestamp at __netif_receive_skb
    u8 enqueue_cpu;      // CPU at enqueue
    u8 receive_cpu;      // CPU at receive
    u16 queue_len;       // Queue length at enqueue
};

// Stage pair key for histogram
struct stage_pair_key_t {
    u8 prev_stage;
    u8 curr_stage;
    u8 latency_bucket;  // log2 of latency in microseconds
};

// High latency event data for userspace
struct latency_event_t {
    u64 ts_start;        // Timestamp at start stage
    u64 ts_end;          // Timestamp at end stage
    u64 latency_us;      // Latency in microseconds
    u8 prev_stage;       // Previous stage ID
    u8 curr_stage;       // Current stage ID
    u8 cpu_start;        // CPU at start stage
    u8 cpu_end;          // CPU at end stage
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8 protocol;
    s64 bytes;           // Bytes (for ip_rcv stage)
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);

// BPF Histogram for stage latencies
BPF_HISTOGRAM(stage_latency_hist, struct stage_pair_key_t, 2048);

// Debug statistics (stage_id << 8 | code_point)
BPF_HISTOGRAM(debug_stage_stats, u32);

// Packet counters
BPF_ARRAY(packet_counters, u64, 10);
// 0=enqueue, 1=receive, 2=ip_rcv, 3=cross_cpu, 4=parse_fail, 5=flow_not_found

// Queue depth statistics
BPF_ARRAY(queue_depth_stats, u64, 3);  // 0=sum, 1=count, 2=max

// Perf event output for high latency events
BPF_PERF_OUTPUT(latency_events);

// Debug helper
static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stage_stats.increment(key);
}

// Helper to check interface
static __always_inline bool is_target_ifindex(const struct sk_buff *skb) {
    struct net_device *dev = NULL;
    int ifindex = 0;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || dev == NULL) {
        return false;
    }

    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0) {
        return false;
    }

    return (ifindex == TARGET_IFINDEX);
}

// Packet parsing
static __always_inline int parse_packet_key(
    struct sk_buff *skb,
    struct packet_key_t *key,
    u8 stage_id
) {
    debug_inc(stage_id, CODE_PARSE_ENTRY);

    struct iphdr ip;
    unsigned char *head;
    u16 network_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset),
                             &skb->network_header) < 0) {
        return 0;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        return 0;
    }

    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        return 0;
    }

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    // Protocol filter
    if (PROTOCOL_FILTER != 0 && ip.protocol != PROTOCOL_FILTER) {
        debug_inc(stage_id, CODE_PARSE_PROTO_FILTER);
        return 0;
    }

    // IP filters
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
        debug_inc(stage_id, CODE_PARSE_IP_FILTER);
        return 0;
    }

    // Transport header parsing
    u16 transport_header_offset;
    if (bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset),
                             &skb->transport_header) < 0) {
        return 0;
    }

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U) {
        u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5) return 0;
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    switch (ip.protocol) {
        case IPPROTO_TCP: {
            struct tcphdr tcp;
            if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header_offset) < 0) {
                return 0;
            }
            key->tcp.src_port = tcp.source;
            key->tcp.dst_port = tcp.dest;
            key->tcp.seq = tcp.seq;

            if (SRC_PORT_FILTER != 0 &&
                key->tcp.src_port != htons(SRC_PORT_FILTER) &&
                key->tcp.dst_port != htons(SRC_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            if (DST_PORT_FILTER != 0 &&
                key->tcp.src_port != htons(DST_PORT_FILTER) &&
                key->tcp.dst_port != htons(DST_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr udp;
            if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header_offset) < 0) {
                return 0;
            }
            key->udp.src_port = udp.source;
            key->udp.dst_port = udp.dest;
            key->udp.ip_id = ip.id;
            key->udp.udp_len = udp.len;

            if (SRC_PORT_FILTER != 0 &&
                key->udp.src_port != htons(SRC_PORT_FILTER) &&
                key->udp.dst_port != htons(SRC_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            if (DST_PORT_FILTER != 0 &&
                key->udp.src_port != htons(DST_PORT_FILTER) &&
                key->udp.dst_port != htons(DST_PORT_FILTER)) {
                debug_inc(stage_id, CODE_PARSE_PORT_FILTER);
                return 0;
            }
            break;
        }
        default:
            return 0;
    }

    debug_inc(stage_id, CODE_PARSE_SUCCESS);
    return 1;
}

// Stage 1: enqueue_to_backlog
int kprobe__enqueue_to_backlog(struct pt_regs *ctx, struct sk_buff *skb, int cpu, unsigned int *qtail) {
    debug_inc(STAGE_ENQUEUE, CODE_PROBE_ENTRY);

    // Check interface
    if (!is_target_ifindex(skb)) {
        return 0;
    }

    debug_inc(STAGE_ENQUEUE, CODE_HANDLE_ENTRY);

    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, STAGE_ENQUEUE)) {
        u32 idx = 4;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
        return 0;
    }

    u64 current_ts = bpf_ktime_get_ns();
    u32 current_cpu = bpf_get_smp_processor_id();

    // Create flow entry
    struct flow_data_t zero = {};
    zero.enqueue_ts = current_ts;
    zero.enqueue_cpu = (u8)(current_cpu & 0xFF);
    zero.queue_len = 0;  // TODO: extract actual queue length
    zero.receive_ts = 0;
    zero.receive_cpu = 0xFF;

    flow_sessions.delete(&key);
    struct flow_data_t *flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);

    if (flow_ptr) {
        debug_inc(STAGE_ENQUEUE, CODE_FLOW_CREATE);

        u32 idx = 0;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;

        // Update queue depth stats
        idx = 0;
        u64 *sum = queue_depth_stats.lookup(&idx);
        if (sum) *sum += flow_ptr->queue_len;

        idx = 1;
        u64 *count = queue_depth_stats.lookup(&idx);
        if (count) (*count)++;
    }

    return 0;
}

// Stage 2: netif_receive_skb via raw tracepoint (CRITICAL ASYNC BOUNDARY)
RAW_TRACEPOINT_PROBE(netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    debug_inc(STAGE_RECEIVE, CODE_PROBE_ENTRY);

    // Check interface
    if (!is_target_ifindex(skb)) {
        return 0;
    }

    debug_inc(STAGE_RECEIVE, CODE_HANDLE_ENTRY);

    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, STAGE_RECEIVE)) {
        u32 idx = 4;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
        return 0;
    }

    u64 current_ts = bpf_ktime_get_ns();
    u32 current_cpu = bpf_get_smp_processor_id();

    debug_inc(STAGE_RECEIVE, CODE_FLOW_LOOKUP);
    struct flow_data_t *flow_ptr = flow_sessions.lookup(&key);

    if (!flow_ptr) {
        debug_inc(STAGE_RECEIVE, CODE_FLOW_NOT_FOUND);
        u32 idx = 5;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
        return 0;
    }

    debug_inc(STAGE_RECEIVE, CODE_FLOW_FOUND);

    // Calculate latency from enqueue
    if (flow_ptr->enqueue_ts > 0 && current_ts > flow_ptr->enqueue_ts) {
        u64 latency_ns = current_ts - flow_ptr->enqueue_ts;
        u64 latency_us = latency_ns / 1000;

        struct stage_pair_key_t pair_key = {};
        pair_key.prev_stage = STAGE_ENQUEUE;
        pair_key.curr_stage = STAGE_RECEIVE;
        pair_key.latency_bucket = bpf_log2l(latency_us + 1);

        stage_latency_hist.increment(pair_key);
        debug_inc(STAGE_RECEIVE, CODE_LATENCY_SUBMIT);

        // Submit high latency event (CRITICAL ASYNC BOUNDARY)
        #if ENABLE_HIGH_LATENCY_EVENTS
        if (latency_us > HIGH_LATENCY_THRESHOLD_US) {
            struct latency_event_t event = {};
            event.ts_start = flow_ptr->enqueue_ts;
            event.ts_end = current_ts;
            event.latency_us = latency_us;
            event.prev_stage = STAGE_ENQUEUE;
            event.curr_stage = STAGE_RECEIVE;
            event.cpu_start = flow_ptr->enqueue_cpu;
            event.cpu_end = (u8)(current_cpu & 0xFF);
            event.src_ip = key.src_ip;
            event.dst_ip = key.dst_ip;
            event.protocol = key.protocol;
            if (key.protocol == IPPROTO_TCP) {
                event.src_port = key.tcp.src_port;
                event.dst_port = key.tcp.dst_port;
            } else if (key.protocol == IPPROTO_UDP) {
                event.src_port = key.udp.src_port;
                event.dst_port = key.udp.dst_port;
            }
            event.bytes = 0;
            latency_events.perf_submit(ctx, &event, sizeof(event));
        }
        #endif

        // Check CPU migration
        if (flow_ptr->enqueue_cpu != (u8)(current_cpu & 0xFF)) {
            u32 idx = 3;
            u64 *counter = packet_counters.lookup(&idx);
            if (counter) (*counter)++;
        }
    }

    // Update flow
    flow_ptr->receive_ts = current_ts;
    flow_ptr->receive_cpu = (u8)(current_cpu & 0xFF);

    u32 idx = 1;
    u64 *counter = packet_counters.lookup(&idx);
    if (counter) (*counter)++;

    return 0;
}

// Stage 3: ip_rcv
int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    debug_inc(STAGE_IP_RCV, CODE_PROBE_ENTRY);

    // Check interface
    if (!is_target_ifindex(skb)) {
        return 0;
    }

    debug_inc(STAGE_IP_RCV, CODE_HANDLE_ENTRY);

    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, STAGE_IP_RCV)) {
        u32 idx = 4;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
        return 0;
    }

    u64 current_ts = bpf_ktime_get_ns();

    debug_inc(STAGE_IP_RCV, CODE_FLOW_LOOKUP);
    struct flow_data_t *flow_ptr = flow_sessions.lookup(&key);

    if (!flow_ptr) {
        debug_inc(STAGE_IP_RCV, CODE_FLOW_NOT_FOUND);
        u32 idx = 5;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
        return 0;
    }

    debug_inc(STAGE_IP_RCV, CODE_FLOW_FOUND);

    // Calculate latency from receive
    if (flow_ptr->receive_ts > 0 && current_ts > flow_ptr->receive_ts) {
        u64 latency_ns = current_ts - flow_ptr->receive_ts;
        u64 latency_us = latency_ns / 1000;

        struct stage_pair_key_t pair_key = {};
        pair_key.prev_stage = STAGE_RECEIVE;
        pair_key.curr_stage = STAGE_IP_RCV;
        pair_key.latency_bucket = bpf_log2l(latency_us + 1);

        stage_latency_hist.increment(pair_key);
        debug_inc(STAGE_IP_RCV, CODE_LATENCY_SUBMIT);

        // Submit high latency event
        #if ENABLE_HIGH_LATENCY_EVENTS
        if (latency_us > HIGH_LATENCY_THRESHOLD_US) {
            struct latency_event_t event = {};
            event.ts_start = flow_ptr->receive_ts;
            event.ts_end = current_ts;
            event.latency_us = latency_us;
            event.prev_stage = STAGE_RECEIVE;
            event.curr_stage = STAGE_IP_RCV;
            event.cpu_start = flow_ptr->receive_cpu;
            event.cpu_end = bpf_get_smp_processor_id();
            event.src_ip = key.src_ip;
            event.dst_ip = key.dst_ip;
            event.protocol = key.protocol;
            if (key.protocol == IPPROTO_TCP) {
                event.src_port = key.tcp.src_port;
                event.dst_port = key.tcp.dst_port;
            } else if (key.protocol == IPPROTO_UDP) {
                event.src_port = key.udp.src_port;
                event.dst_port = key.udp.dst_port;
            }
            event.bytes = 0;
            latency_events.perf_submit(ctx, &event, sizeof(event));
        }
        #endif
    }

    u32 idx = 2;
    u64 *counter = packet_counters.lookup(&idx);
    if (counter) (*counter)++;

    // Clean up flow
    flow_sessions.delete(&key);

    return 0;
}
"""

# Cumulative statistics (from start to end)
cumulative_stats = {
    'stage_pair_data': {},  # {(prev_stage, curr_stage): {bucket: count}}
    'packet_counters': [0] * 10,
    'queue_depth_sum': 0,
    'queue_depth_count': 0
}

# Global event counter for high latency events
high_latency_event_count = 0


class LatencyEvent(ctypes.Structure):
    """Mirror of struct latency_event_t emitted by the BPF program."""
    _fields_ = [
        ("ts_start", ctypes.c_uint64),
        ("ts_end", ctypes.c_uint64),
        ("latency_us", ctypes.c_uint64),
        ("prev_stage", ctypes.c_uint8),
        ("curr_stage", ctypes.c_uint8),
        ("cpu_start", ctypes.c_uint8),
        ("cpu_end", ctypes.c_uint8),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 7),  # Align to 8-byte boundary for bytes field
        ("bytes", ctypes.c_int64),
    ]

def print_high_latency_event(cpu, data, size):
    """Callback for high latency events"""
    global high_latency_event_count

    if size < ctypes.sizeof(LatencyEvent):
        print("Received truncated latency event (size=%d, expected=%d)" % (size, ctypes.sizeof(LatencyEvent)))
        return

    high_latency_event_count += 1
    event = ctypes.cast(data, ctypes.POINTER(LatencyEvent)).contents

    print("\n" + "=" * 80)
    print("HIGH LATENCY EVENT #%d" % high_latency_event_count)
    print("=" * 80)
    print("Timestamp: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"))
    print("\nLatency: %.3f us (%.6f ms)" % (event.latency_us, event.latency_us / 1000.0))

    print("\nStage Transition:")
    prev_name = get_stage_name(event.prev_stage)
    curr_name = get_stage_name(event.curr_stage)
    print("  %s -> %s" % (prev_name, curr_name))

    if event.prev_stage == 1 and event.curr_stage == 2:
        print("  ^^^ CRITICAL ASYNC BOUNDARY (enqueue → receive) ^^^")

    print("\nCPU Information:")
    print("  Start CPU: %d" % event.cpu_start)
    print("  End CPU: %d" % event.cpu_end)
    if event.cpu_start != event.cpu_end:
        print("  ^^^ CPU MIGRATION DETECTED ^^^")

    print("\nPacket Information:")
    # Convert network byte order to host byte order for display
    src_ip = socket.inet_ntoa(struct.pack('!I', socket.ntohl(event.src_ip)))
    dst_ip = socket.inet_ntoa(struct.pack('!I', socket.ntohl(event.dst_ip)))
    print("  Source IP: %s" % src_ip)
    print("  Dest IP: %s" % dst_ip)

    if event.protocol == 6:
        print("  Protocol: TCP")
        print("  Source Port: %d" % socket.ntohs(event.src_port))
        print("  Dest Port: %d" % socket.ntohs(event.dst_port))
    elif event.protocol == 17:
        print("  Protocol: UDP")
        print("  Source Port: %d" % socket.ntohs(event.src_port))
        print("  Dest Port: %d" % socket.ntohs(event.dst_port))
    else:
        print("  Protocol: %d" % event.protocol)

    print("=" * 80)

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

def get_stage_name(stage_id):
    """Get human-readable stage name"""
    stage_names = {
        1: "STAGE1_enqueue_to_backlog",
        2: "STAGE2___netif_receive_skb",
        3: "STAGE3_ip_rcv"
    }
    return stage_names.get(stage_id, "UNKNOWN_%d" % stage_id)

def get_code_name(code_point):
    """Get human-readable code point name"""
    code_names = {
        1: "PROBE_ENTRY",
        5: "HANDLE_ENTRY",
        6: "PARSE_ENTRY",
        7: "PARSE_SUCCESS",
        8: "IP_FILTER",
        9: "PROTO_FILTER",
        10: "PORT_FILTER",
        14: "FLOW_CREATE",
        15: "FLOW_LOOKUP",
        16: "FLOW_FOUND",
        17: "FLOW_NOT_FOUND",
        19: "LATENCY_SUBMIT"
    }
    return code_names.get(code_point, "CODE_%d" % code_point)

def print_debug_statistics(b):
    """Print debug statistics following bcc-debug-framework.md"""
    print("\n" + "=" * 80)
    print("DEBUG STATISTICS (Stage Execution Flow)")
    print("=" * 80)

    stage_stats = b["debug_stage_stats"]
    debug_data = {}

    for k, v in stage_stats.items():
        if v.value > 0:
            stage_id = k.value >> 8
            code_point = k.value & 0xFF
            if stage_id not in debug_data:
                debug_data[stage_id] = {}
            debug_data[stage_id][code_point] = v.value

    for stage_id in sorted(debug_data.keys()):
        stage_name = get_stage_name(stage_id)
        print("\n%s:" % stage_name)

        for code_point in sorted(debug_data[stage_id].keys()):
            code_name = get_code_name(code_point)
            count = debug_data[stage_id][code_point]
            print("  %-25s: %d" % (code_name, count))

def print_histogram_summary(b, interval_start_time, show_debug, update_cumulative=True, enable_high_latency=False):
    """Print histogram summary for the current interval"""
    global cumulative_stats, high_latency_event_count

    current_time = datetime.datetime.now()
    print("\n" + "=" * 80)
    print("[%s] Enqueue → IP_RCV Latency Report (Interval: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        time_time() - interval_start_time
    ))
    print("=" * 80)

    # Get stage pair histogram data
    latency_hist = b["stage_latency_hist"]
    stage_pair_data = {}

    try:
        for k, v in latency_hist.items():
            pair_key = (k.prev_stage, k.curr_stage)
            bucket = k.latency_bucket
            count = v.value if hasattr(v, 'value') else int(v)

            if pair_key not in stage_pair_data:
                stage_pair_data[pair_key] = {}
            stage_pair_data[pair_key][bucket] = count

            # Update cumulative histogram
            if update_cumulative:
                if pair_key not in cumulative_stats['stage_pair_data']:
                    cumulative_stats['stage_pair_data'][pair_key] = {}
                cumulative_stats['stage_pair_data'][pair_key][bucket] = \
                    cumulative_stats['stage_pair_data'][pair_key].get(bucket, 0) + count
    except Exception as e:
        print("Error reading histogram data:", str(e))
        return

    if not stage_pair_data:
        print("No latency data collected in this interval")
        if show_debug:
            print_debug_statistics(b)
        return

    print("\nLatency Measurements:")
    print("-" * 80)

    for (prev_stage, curr_stage) in sorted(stage_pair_data.keys()):
        prev_name = get_stage_name(prev_stage)
        curr_name = get_stage_name(curr_stage)

        print("\n  %s -> %s:" % (prev_name, curr_name))

        buckets = stage_pair_data[(prev_stage, curr_stage)]
        total_samples = sum(buckets.values())

        if total_samples == 0:
            print("    No samples")
            continue

        print("    Total samples: %d" % total_samples)
        print("    Latency distribution:")

        sorted_buckets = sorted(buckets.items())
        max_count = max(buckets.values())

        for bucket, count in sorted_buckets:
            if count > 0:
                if bucket == 0:
                    range_str = "0-1us"
                else:
                    low = 1 << (bucket - 1)
                    high = (1 << bucket) - 1
                    range_str = "%d-%dus" % (low, high)

                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                percentage = 100.0 * count / total_samples

                print("      %-16s: %6d (%5.1f%%) |%-40s|" % (range_str, count, percentage, bar))

        # Highlight critical segment
        if prev_stage == 1 and curr_stage == 2:
            print("    ^^^ CRITICAL ASYNC BOUNDARY (enqueue → receive) ^^^")

    # Print packet counters
    counters = b["packet_counters"]
    print("\n" + "=" * 80)
    print("Packet Counters (Interval):")
    enq = counters[0].value
    rec = counters[1].value
    ipl = counters[2].value
    mig = counters[3].value
    prs = counters[4].value
    flf = counters[5].value

    # Update cumulative counters
    if update_cumulative:
        cumulative_stats['packet_counters'][0] += enq
        cumulative_stats['packet_counters'][1] += rec
        cumulative_stats['packet_counters'][2] += ipl
        cumulative_stats['packet_counters'][3] += mig
        cumulative_stats['packet_counters'][4] += prs
        cumulative_stats['packet_counters'][5] += flf

    print("  Enqueued packets:        %d" % enq)
    print("  Received packets:        %d" % rec)
    print("  IP layer packets:        %d" % ipl)
    print("  Cross-CPU migrations:    %d" % mig)
    print("  Parse failures:          %d" % prs)
    print("  Flow lookup failures:    %d" % flf)

    # Queue depth statistics
    queue_stats = b["queue_depth_stats"]
    qsum = queue_stats[0].value
    qcount = queue_stats[1].value

    # Update cumulative queue stats
    if update_cumulative:
        cumulative_stats['queue_depth_sum'] += qsum
        cumulative_stats['queue_depth_count'] += qcount

    if qcount > 0:
        print("\nBacklog Queue Statistics:")
        print("  Average queue depth: %.2f packets" % (float(qsum) / qcount))
        print("  Total enqueue operations: %d" % qcount)

    # Debug statistics
    if show_debug:
        print_debug_statistics(b)

    # Show high latency event count if enabled
    if enable_high_latency:
        print("\nHigh Latency Events: %d" % high_latency_event_count)
        print("=" * 80)

    # Clear histograms for next interval
    latency_hist.clear()

def print_cumulative_summary(program_start_time, show_debug, enable_high_latency=False):
    """Print cumulative statistics from start to end"""
    global cumulative_stats, high_latency_event_count

    current_time = datetime.datetime.now()
    total_duration = time_time() - program_start_time

    print("\n" + "=" * 80)
    print("[%s] CUMULATIVE Enqueue → IP_RCV Latency Report (Total Duration: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        total_duration
    ))
    print("=" * 80)

    stage_pair_data = cumulative_stats['stage_pair_data']

    if not stage_pair_data:
        print("No cumulative latency data collected")
        return

    print("\nLatency Measurements (Cumulative):")
    print("-" * 80)

    for (prev_stage, curr_stage) in sorted(stage_pair_data.keys()):
        prev_name = get_stage_name(prev_stage)
        curr_name = get_stage_name(curr_stage)

        print("\n  %s -> %s:" % (prev_name, curr_name))

        buckets = stage_pair_data[(prev_stage, curr_stage)]
        total_samples = sum(buckets.values())

        if total_samples == 0:
            print("    No samples")
            continue

        print("    Total samples: %d" % total_samples)
        print("    Latency distribution:")

        sorted_buckets = sorted(buckets.items())
        max_count = max(buckets.values())

        for bucket, count in sorted_buckets:
            if count > 0:
                if bucket == 0:
                    range_str = "0-1us"
                else:
                    low = 1 << (bucket - 1)
                    high = (1 << bucket) - 1
                    range_str = "%d-%dus" % (low, high)

                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                percentage = 100.0 * count / total_samples

                print("      %-16s: %6d (%5.1f%%) |%-40s|" % (range_str, count, percentage, bar))

        # Highlight critical segment
        if prev_stage == 1 and curr_stage == 2:
            print("    ^^^ CRITICAL ASYNC BOUNDARY (enqueue → receive) ^^^")

    # Print cumulative packet counters
    print("\n" + "=" * 80)
    print("Packet Counters (Cumulative):")
    print("  Enqueued packets:        %d" % cumulative_stats['packet_counters'][0])
    print("  Received packets:        %d" % cumulative_stats['packet_counters'][1])
    print("  IP layer packets:        %d" % cumulative_stats['packet_counters'][2])
    print("  Cross-CPU migrations:    %d" % cumulative_stats['packet_counters'][3])
    print("  Parse failures:          %d" % cumulative_stats['packet_counters'][4])
    print("  Flow lookup failures:    %d" % cumulative_stats['packet_counters'][5])

    # Cumulative queue depth statistics
    qsum = cumulative_stats['queue_depth_sum']
    qcount = cumulative_stats['queue_depth_count']

    if qcount > 0:
        print("\nBacklog Queue Statistics (Cumulative):")
        print("  Average queue depth: %.2f packets" % (float(qsum) / qcount))
        print("  Total enqueue operations: %d" % qcount)

    # Show cumulative high latency event count if enabled
    if enable_high_latency:
        print("\nTotal High Latency Events: %d" % high_latency_event_count)

    print("=" * 80)

def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Focused RX Latency: enqueue_to_backlog → ip_rcv",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Measure physical NIC RX latency:
    sudo %(prog)s --interface enp24s0f0np0 \\
                  --src-ip 70.0.0.32 --dst-ip 70.0.0.31 \\
                  --dst-port 2181 --protocol tcp --interval 1

  Measure OVS internal port RX latency:
    sudo %(prog)s --interface br-int \\
                  --dst-ip 70.0.0.31 --protocol tcp --interval 1

  Enable debug mode to diagnose missing probe hits:
    sudo %(prog)s --interface enp24s0f0np0 \\
                  --src-ip 70.0.0.32 --dst-ip 70.0.0.31 \\
                  --dst-port 2181 --protocol tcp --debug

This tool measures 3 critical stages on a SINGLE interface:
  1. enqueue_to_backlog - Queue insertion
  2. __netif_receive_skb - Softirq processing (CRITICAL ASYNC POINT)
  3. ip_rcv - IP layer entry

The latency between stage 1 and 2 reveals softirq scheduling delays,
CPU migration overhead, and queue contention issues.

NOTE: This tool monitors packets on the specified interface only.
In OVS environments, packets traverse multiple interfaces:
  - Physical NIC (e.g., enp24s0f0np0): Hardware → Kernel
  - OVS internal port (e.g., br-int): OVS → Protocol stack
Use separate runs to measure each interface independently.
"""
    )

    parser.add_argument('--interface', type=str, required=True,
                        help='Target interface to monitor (e.g., enp24s0f0np0 or br-int)')
    parser.add_argument('--src-ip', type=str, required=False,
                        help='Source IP filter')
    parser.add_argument('--dst-ip', type=str, required=False,
                        help='Destination IP filter')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port filter')
    parser.add_argument('--dst-port', type=int, required=False,
                        help='Destination port filter')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'all'],
                        default='all', help='Protocol filter (default: all)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Statistics interval in seconds (default: 5)')
    parser.add_argument('--duration', type=int, default=0,
                        help='Total execution time in seconds (default: 0 = run indefinitely)')
    parser.add_argument('--threshold', type=int, metavar='MICROSECONDS',
                        help='Enable high-latency event tracking with threshold in microseconds (e.g., 100 for 100us). '
                             'When specified, individual packets with latency exceeding this threshold will be reported in real-time. '
                             'If not specified, only summary histogram is collected (default behavior).')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug statistics output')

    args = parser.parse_args()

    # Convert parameters
    src_ip_hex = ip_to_hex(args.src_ip) if args.src_ip else 0
    dst_ip_hex = ip_to_hex(args.dst_ip) if args.dst_ip else 0
    src_port = args.src_port if args.src_port else 0
    dst_port = args.dst_port if args.dst_port else 0

    protocol_map = {'tcp': 6, 'udp': 17, 'all': 0}
    protocol_filter = protocol_map[args.protocol]

    # Get interface index
    try:
        target_ifindex = get_if_index(args.interface)
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    print("=" * 80)
    print("Focused RX Latency Measurement: enqueue_to_backlog → ip_rcv")
    print("=" * 80)
    print("Target interface: %s (ifindex %d)" % (args.interface, target_ifindex))
    print("Protocol filter: %s" % args.protocol.upper())
    if args.src_ip:
        print("Source IP: %s" % args.src_ip)
    if args.dst_ip:
        print("Destination IP: %s" % args.dst_ip)
    if src_port:
        print("Source port: %d" % src_port)
    if dst_port:
        print("Destination port: %d" % dst_port)
    print("Statistics interval: %d seconds" % args.interval)
    if args.duration > 0:
        print("Total duration: %d seconds" % args.duration)
    else:
        print("Total duration: Unlimited (run until Ctrl-C)")

    # High latency event tracking configuration
    high_latency_threshold = 0
    enable_high_latency = 0
    if args.threshold:
        high_latency_threshold = args.threshold
        enable_high_latency = 1
        print("High-latency event tracking: ENABLED (threshold: %d us = %.3f ms)" %
              (high_latency_threshold, high_latency_threshold / 1000.0))
    else:
        print("High-latency event tracking: DISABLED (only histogram summary)")

    if args.debug:
        print("Debug mode: ENABLED")
    print("\nMeasuring 3 critical stages:")
    print("  1. enqueue_to_backlog  - Queue insertion")
    print("  2. __netif_receive_skb - Softirq processing (ASYNC BOUNDARY)")
    print("  3. ip_rcv              - IP layer entry")
    print("=" * 80)

    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, target_ifindex,
            high_latency_threshold, enable_high_latency
        ))
        print("\nBPF program loaded successfully")
        print("Probes attached:")
        print("  - kprobe__enqueue_to_backlog")
        print("  - raw_tracepoint:netif_receive_skb")
        print("  - kprobe__ip_rcv")
    except Exception as e:
        print("\nError loading BPF program: %s" % e)
        sys.exit(1)

    print("\nCollecting latency data... Hit Ctrl-C to end.")
    print("Statistics will be displayed every %d seconds\n" % args.interval)

    # Open perf buffer for high latency events (only if enabled)
    if enable_high_latency:
        b["latency_events"].open_perf_buffer(print_high_latency_event)

    # Setup signal handler
    program_start_time = time_time()

    def signal_handler(sig, frame):
        print("\n\nFinal interval statistics:")
        print_histogram_summary(b, interval_start_time, args.debug, update_cumulative=False, enable_high_latency=enable_high_latency)
        print("\n")
        print_cumulative_summary(program_start_time, args.debug, enable_high_latency=enable_high_latency)
        print("\nExiting...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Main loop
    interval_start_time = time_time()

    try:
        while True:
            # Poll perf buffer (only if enabled)
            if enable_high_latency:
                b.perf_buffer_poll(timeout=100)
            else:
                sleep(0.1)

            # Check if duration limit exceeded
            if args.duration > 0 and (time_time() - program_start_time) >= args.duration:
                print("\n\nDuration limit reached (%d seconds)" % args.duration)
                print("\nFinal interval statistics:")
                print_histogram_summary(b, interval_start_time, args.debug, update_cumulative=False, enable_high_latency=enable_high_latency)
                print("\n")
                print_cumulative_summary(program_start_time, args.debug, enable_high_latency=enable_high_latency)
                break

            # Check if interval elapsed
            if time_time() - interval_start_time >= args.interval:
                print_histogram_summary(b, interval_start_time, args.debug, update_cumulative=True, enable_high_latency=enable_high_latency)
                interval_start_time = time_time()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        print("\nFinal interval statistics:")
        print_histogram_summary(b, interval_start_time, args.debug, update_cumulative=False, enable_high_latency=enable_high_latency)
        print("\n")
        print_cumulative_summary(program_start_time, args.debug, enable_high_latency=enable_high_latency)

if __name__ == "__main__":
    main()
