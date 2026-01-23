#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Threshold-Based RX Latency Analysis: enqueue_to_backlog → __netif_receive_skb

Captures stack traces and metadata when latency exceeds specified threshold
on a SINGLE specified interface. Focused on diagnosing high-latency events
in the critical async boundary.

Measurement points:
- Stage 1: enqueue_to_backlog - Packet queued to per-CPU backlog
- Stage 2: __netif_receive_skb - Packet dequeued and processed

When latency between these two stages exceeds the threshold, the tool captures:
- Complete kernel stack trace
- CPU information (enqueue CPU, receive CPU)
- Timestamp information
- Queue depth at enqueue time
- Latency value

Usage:
    # Monitor physical NIC
    sudo ./enqueue_to_iprec_latency_threshold.py \
        --interface enp24s0f0np0 \
        --src-ip 70.0.0.32 --dst-ip 70.0.0.31 \
        --dst-port 2181 --protocol tcp \
        --threshold-us 1000

    # Monitor OVS internal port with 5ms threshold
    sudo ./enqueue_to_iprec_latency_threshold.py \
        --interface br-int \
        --threshold-us 5000
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
#define THRESHOLD_US %d

// Stage definitions
#define STAGE_ENQUEUE     1  // enqueue_to_backlog
#define STAGE_RECEIVE     2  // __netif_receive_skb

// Packet key structure (for flow correlation)
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

// Flow tracking data
struct flow_data_t {
    u64 enqueue_ts;      // Timestamp at enqueue_to_backlog
    u8 enqueue_cpu;      // CPU at enqueue
    u16 queue_len;       // Queue length at enqueue
    u8 pad[5];
};

// Event data structure for threshold breaches
struct latency_event_t {
    u64 enqueue_ts;      // Timestamp at enqueue
    u64 receive_ts;      // Timestamp at receive
    u64 latency_us;      // Latency in microseconds
    u8 enqueue_cpu;      // CPU at enqueue
    u8 receive_cpu;      // CPU at receive
    u16 queue_len;       // Queue length at enqueue
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 pad[3];
    int kernel_stack_id; // Kernel stack trace ID
};

// Maps
BPF_TABLE("lru_hash", struct packet_key_t, struct flow_data_t, flow_sessions, 10240);

// Stack trace map
BPF_STACK_TRACE(stack_traces, 1024);

// Perf event output for threshold breaches
BPF_PERF_OUTPUT(latency_events);

// Counters
BPF_ARRAY(packet_counters, u64, 10);
// 0=enqueue, 1=receive, 2=threshold_breach, 3=below_threshold, 4=parse_fail, 5=flow_not_found

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
        return 0;
    }

    // IP filters
    if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
        return 0;
    }
    if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
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
                return 0;
            }
            if (DST_PORT_FILTER != 0 &&
                key->tcp.src_port != htons(DST_PORT_FILTER) &&
                key->tcp.dst_port != htons(DST_PORT_FILTER)) {
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
                return 0;
            }
            if (DST_PORT_FILTER != 0 &&
                key->udp.src_port != htons(DST_PORT_FILTER) &&
                key->udp.dst_port != htons(DST_PORT_FILTER)) {
                return 0;
            }
            break;
        }
        default:
            return 0;
    }

    return 1;
}

// Stage 1: enqueue_to_backlog
int kprobe__enqueue_to_backlog(struct pt_regs *ctx, struct sk_buff *skb, int cpu, unsigned int *qtail) {
    // Check interface
    if (!is_target_ifindex(skb)) {
        return 0;
    }

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

    flow_sessions.delete(&key);
    struct flow_data_t *flow_ptr = flow_sessions.lookup_or_try_init(&key, &zero);

    if (flow_ptr) {
        u32 idx = 0;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
    }

    return 0;
}

// Stage 2: netif_receive_skb (via raw tracepoint)
RAW_TRACEPOINT_PROBE(netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    // Check interface
    if (!is_target_ifindex(skb)) {
        return 0;
    }

    struct packet_key_t key = {};
    if (!parse_packet_key(skb, &key, STAGE_RECEIVE)) {
        u32 idx = 4;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
        return 0;
    }

    u64 current_ts = bpf_ktime_get_ns();
    u32 current_cpu = bpf_get_smp_processor_id();

    struct flow_data_t *flow_ptr = flow_sessions.lookup(&key);

    if (!flow_ptr) {
        u32 idx = 5;
        u64 *counter = packet_counters.lookup(&idx);
        if (counter) (*counter)++;
        return 0;
    }

    // Calculate latency
    if (flow_ptr->enqueue_ts > 0 && current_ts > flow_ptr->enqueue_ts) {
        u64 latency_ns = current_ts - flow_ptr->enqueue_ts;
        u64 latency_us = latency_ns / 1000;

        // Check threshold
        if (latency_us >= THRESHOLD_US) {
            // Threshold breach - capture stack trace and metadata
            struct latency_event_t event = {};
            event.enqueue_ts = flow_ptr->enqueue_ts;
            event.receive_ts = current_ts;
            event.latency_us = latency_us;
            event.enqueue_cpu = flow_ptr->enqueue_cpu;
            event.receive_cpu = (u8)(current_cpu & 0xFF);
            event.queue_len = flow_ptr->queue_len;

            // Extract flow info
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

            // Capture kernel stack trace
            event.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);

            // Submit event
            latency_events.perf_submit(ctx, &event, sizeof(event));

            u32 idx = 2;
            u64 *counter = packet_counters.lookup(&idx);
            if (counter) (*counter)++;
        } else {
            // Below threshold - just count and return
            u32 idx = 3;
            u64 *counter = packet_counters.lookup(&idx);
            if (counter) (*counter)++;
        }
    }

    u32 idx = 1;
    u64 *counter = packet_counters.lookup(&idx);
    if (counter) (*counter)++;

    // Clean up flow
    flow_sessions.delete(&key);

    return 0;
}
"""

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

def format_ip(ip_int):
    """Convert integer IP to string"""
    return socket.inet_ntoa(struct.pack("I", ip_int))

def format_port(port_be):
    """Convert network byte order port to host order"""
    return socket.ntohs(port_be)

def get_protocol_name(proto):
    """Get protocol name"""
    if proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    else:
        return "PROTO_%d" % proto

# Global event counter
event_count = 0

def print_event(cpu, data, size):
    """Callback for latency events"""
    global event_count, b

    event_count += 1
    event = b["latency_events"].event(data)

    print("\n" + "=" * 80)
    print("HIGH LATENCY EVENT #%d" % event_count)
    print("=" * 80)
    print("Timestamp: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"))
    print("\nLatency: %.3f ms (threshold: %.3f ms)" % (
        event.latency_us / 1000.0,
        args.threshold_us / 1000.0
    ))

    print("\nFlow Information:")
    print("  Protocol: %s" % get_protocol_name(event.protocol))
    print("  Source: %s:%d" % (format_ip(event.src_ip), format_port(event.src_port)))
    print("  Destination: %s:%d" % (format_ip(event.dst_ip), format_port(event.dst_port)))

    print("\nCPU Information:")
    print("  Enqueue CPU: %d" % event.enqueue_cpu)
    print("  Receive CPU: %d" % event.receive_cpu)
    if event.enqueue_cpu != event.receive_cpu:
        print("  ^^^ CROSS-CPU MIGRATION DETECTED ^^^")

    print("\nTiming Information:")
    print("  Enqueue timestamp: %d ns" % event.enqueue_ts)
    print("  Receive timestamp: %d ns" % event.receive_ts)
    print("  Queue depth: %d packets" % event.queue_len)

    # Print stack trace
    if event.kernel_stack_id >= 0:
        print("\nKernel Stack Trace:")
        stack_traces = b.get_table("stack_traces")
        stack = list(stack_traces.walk(event.kernel_stack_id))
        for addr in stack:
            sym = b.ksym(addr, show_module=True, show_offset=True).decode('utf-8', 'replace')
            print("  %s" % sym)
    else:
        print("\nKernel Stack Trace: [unavailable]")

    print("=" * 80)

def print_summary(b):
    """Print summary statistics"""
    counters = b["packet_counters"]

    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print("Packet Counters:")
    print("  Enqueued packets:        %d" % counters[0].value)
    print("  Received packets:        %d" % counters[1].value)
    print("  Threshold breaches:      %d" % counters[2].value)
    print("  Below threshold:         %d" % counters[3].value)
    print("  Parse failures:          %d" % counters[4].value)
    print("  Flow lookup failures:    %d" % counters[5].value)
    print("\nTotal events captured:     %d" % event_count)

    if counters[1].value > 0:
        breach_rate = 100.0 * counters[2].value / counters[1].value
        print("Threshold breach rate:     %.2f%%" % breach_rate)

    print("=" * 80)

def main():
    global args, b

    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Threshold-Based RX Latency Analysis: enqueue_to_backlog → __netif_receive_skb",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor physical NIC with 1ms threshold:
    sudo %(prog)s --interface enp24s0f0np0 \\
                  --src-ip 70.0.0.32 --dst-ip 70.0.0.31 \\
                  --dst-port 2181 --protocol tcp \\
                  --threshold-us 1000

  Monitor OVS internal port with 5ms threshold:
    sudo %(prog)s --interface br-int \\
                  --dst-ip 70.0.0.31 --protocol tcp \\
                  --threshold-us 5000

  Capture all traffic with latency >= 5ms:
    sudo %(prog)s --interface enp24s0f0np0 \\
                  --threshold-us 5000

When latency exceeds the threshold, the tool captures:
- Complete kernel stack trace
- CPU information (enqueue CPU, receive CPU, migration detection)
- Timestamp information
- Flow information (IP, port, protocol)
- Queue depth at enqueue

This helps diagnose root causes of high latency events.

NOTE: This tool monitors packets on the specified interface only.
In OVS environments, use separate runs to monitor physical NIC vs internal port.
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
    parser.add_argument('--threshold-us', type=int, default=1000,
                        help='Latency threshold in microseconds (default: 1000us = 1ms)')

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
    print("Threshold-Based RX Latency Analysis")
    print("=" * 80)
    print("Target interface: %s (ifindex %d)" % (args.interface, target_ifindex))
    print("Latency threshold: %.3f ms (%d us)" % (
        args.threshold_us / 1000.0, args.threshold_us
    ))
    print("Protocol filter: %s" % args.protocol.upper())
    if args.src_ip:
        print("Source IP: %s" % args.src_ip)
    if args.dst_ip:
        print("Destination IP: %s" % args.dst_ip)
    if src_port:
        print("Source port: %d" % src_port)
    if dst_port:
        print("Destination port: %d" % dst_port)
    print("\nMeasurement points:")
    print("  1. enqueue_to_backlog  - Queue insertion")
    print("  2. __netif_receive_skb - Softirq processing")
    print("\nCapture on threshold breach:")
    print("  - Kernel stack trace")
    print("  - CPU information (enqueue CPU, receive CPU)")
    print("  - Flow information (IP, port, protocol)")
    print("  - Timing and queue depth")
    print("=" * 80)

    try:
        b = BPF(text=bpf_text % (
            src_ip_hex, dst_ip_hex, src_port, dst_port,
            protocol_filter, target_ifindex, args.threshold_us
        ))
        print("\nBPF program loaded successfully")
        print("Probes attached:")
        print("  - kprobe__enqueue_to_backlog")
        print("  - raw_tracepoint:netif_receive_skb")
    except Exception as e:
        print("\nError loading BPF program: %s" % e)
        sys.exit(1)

    print("\nWaiting for high latency events... Hit Ctrl-C to end.\n")

    # Open perf buffer
    b["latency_events"].open_perf_buffer(print_event)

    # Setup signal handler
    def signal_handler(sig, frame):
        print("\n\nFinal summary:")
        print_summary(b)
        print("\nExiting...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Main loop
    try:
        while True:
            b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        print_summary(b)

if __name__ == "__main__":
    main()
