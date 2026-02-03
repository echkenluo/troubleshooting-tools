#!/usr/bin/env python
# -*- coding: utf-8 -*-

# System Network TCP Path Tracer - Detect TCP drops between phy NIC and protocol stack
#
# For system network (host-endpoint) scenarios where the host is a TCP endpoint.
# Monitors packets at physical interface and protocol stack endpoints to detect
# internal drops in the OVS + protocol stack path.
#
# Usage:
#   sudo ./system_tcp_path_tracer.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#       --phy-iface enp24s0f0np0 [--timeout-ms 1000]
#
#   # Default mode is stats (periodic summary). Use --verbose for per-packet output.
#   sudo ./system_tcp_path_tracer.py --src-ip 192.168.70.32 --dst-ip 192.168.70.31 \
#       --phy-iface enp24s0f0np0 --stats-interval 5
#
# Stages (4 stages, bidirectional):
#   Inbound (forward):
#     [0] RX @ phy interface         (netif_receive_skb)
#     [1] Delivered to tcp_v4_rcv     (tcp_v4_rcv)
#   Outbound (reply):
#     [2] Sent by protocol stack      (__ip_queue_xmit)
#     [3] TX @ phy interface          (net_dev_xmit)
#
# Drop detection:
#   - Has 0, missing 1: Inbound packet dropped internally
#   - Has 2, missing 3: Outbound packet dropped between __ip_queue_xmit and NIC TX

try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        sys.exit(1)

import argparse
import ctypes
import socket
import struct
import fcntl
import sys
import os
import datetime
import time
from collections import OrderedDict

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <net/flow.h>

struct net;
struct flowi;

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x

#define MAX_IFACES 8
__IFACE_ARRAYS__
__PORT_FILTER__

#define STAGE_FWD_RX     0  // Inbound RX at phy interface
#define STAGE_FWD_STACK  1  // Inbound delivered to tcp_v4_rcv
#define STAGE_REP_STACK  2  // Outbound sent by protocol stack (__ip_queue_xmit)
#define STAGE_REP_TX     3  // Outbound TX at phy interface
#define MAX_STAGES       4

#define DIR_FORWARD  0  // src -> dst (inbound to local)
#define DIR_REPLY    1  // dst -> src (outbound from local)

#define STATS_MODE __STATS_MODE__
#define LATENCY_BUCKETS 21

struct stats_t {
    u64 entry_packets;
    u64 exit_packets;
    u64 new_flows;
    u64 complete_flows;
    u64 latency_hist[LATENCY_BUCKETS];
    u64 total_latency_ns;
    u64 min_latency_ns;
    u64 max_latency_ns;
};

BPF_PERCPU_ARRAY(stats_map, struct stats_t, 2);  // 0=inbound, 1=outbound

static __always_inline u32 latency_bucket(u64 latency_ns) {
    u64 latency_us = latency_ns / 1000;
    if (latency_us == 0) return 0;
    if (latency_us < 2) return 0;
    if (latency_us < 4) return 1;
    if (latency_us < 8) return 2;
    if (latency_us < 16) return 3;
    if (latency_us < 32) return 4;
    if (latency_us < 64) return 5;
    if (latency_us < 128) return 6;
    if (latency_us < 256) return 7;
    if (latency_us < 512) return 8;
    if (latency_us < 1024) return 9;
    if (latency_us < 2048) return 10;
    if (latency_us < 4096) return 11;
    if (latency_us < 8192) return 12;
    if (latency_us < 16384) return 13;
    if (latency_us < 32768) return 14;
    if (latency_us < 65536) return 15;
    if (latency_us < 131072) return 16;
    if (latency_us < 262144) return 17;
    if (latency_us < 524288) return 18;
    if (latency_us < 1048576) return 19;
    return 20;
}

struct tcp_flow_key {
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    __be32 seq;
    u8 direction;
    u8 pad[3];
};

struct event_t {
    struct tcp_flow_key key;
    u64 ts[MAX_STAGES];
    __be16 sport;
    __be16 dport;
    u8 stage;
    u8 direction;
    u8 pad[2];
    u32 payload_len;
    char ifname[16];
};

BPF_TABLE("lru_hash", struct tcp_flow_key, struct event_t, flow_map, 10240);
BPF_PERF_OUTPUT(events);

static __always_inline int is_phy_iface(int ifindex) {
    #pragma unroll
    for (int i = 0; i < PHY_IFACE_COUNT; i++) {
        if (phy_ifindexes[i] == ifindex)
            return 1;
    }
    return 0;
}

// Returns: 1=forward (src->dst), 2=reply (dst->src), 0=not matched
static __always_inline int parse_tcp_skb(struct sk_buff *skb,
    struct tcp_flow_key *key, __be16 *sport_out, __be16 *dport_out,
    u32 *payload_out)
{
    unsigned char *head;
    u16 network_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return 0;
    if (bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset),
            &skb->network_header) < 0)
        return 0;
    if (network_header_offset == (u16)~0U || network_header_offset > 2048)
        return 0;

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0)
        return 0;
    if (ip.protocol != IPPROTO_TCP)
        return 0;

    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    int is_forward = 0;
    int is_reply = 0;

    if (actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER)
        is_forward = 1;
    else if (actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER)
        is_reply = 1;
    else
        return 0;

    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5)
        return 0;

    u16 transport_header_offset;
    if (bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset),
            &skb->transport_header) < 0)
        return 0;
    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U ||
        transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    struct tcphdr tcp;
    if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header_offset) < 0)
        return 0;

    __be16 actual_sport = tcp.source;
    __be16 actual_dport = tcp.dest;

#ifdef PORT_FILTER_ENABLED
    __be16 filter_port = htons(PORT_FILTER_VALUE);
    if (is_forward && actual_dport != filter_port)
        return 0;
    if (is_reply && actual_sport != filter_port)
        return 0;
#endif

    *sport_out = actual_sport;
    *dport_out = actual_dport;

    u16 ip_total = ntohs(ip.tot_len);
    u8 tcp_doff = tcp.doff & 0x0F;
    u32 hdr_len = (ip_ihl * 4) + (tcp_doff * 4);
    *payload_out = (ip_total > hdr_len) ? ip_total - hdr_len : 0;

    // Canonical key: always normalize to SRC_IP_FILTER as sip
    key->sip = SRC_IP_FILTER;
    key->dip = DST_IP_FILTER;
    if (is_forward) {
        key->sport = actual_sport;
        key->dport = actual_dport;
        key->direction = DIR_FORWARD;
    } else {
        key->sport = actual_dport;
        key->dport = actual_sport;
        key->direction = DIR_REPLY;
    }
    key->seq = tcp.seq;

    return is_forward ? 1 : 2;
}

// Parse TCP connection info from socket at __ip_queue_xmit
// Returns 2 for outbound (reply), 0 otherwise
static __always_inline int parse_tcp_sock(struct sock *sk, struct sk_buff *skb,
    struct tcp_flow_key *key, __be16 *sport_out, __be16 *dport_out, u32 *seq_out)
{
    if (!sk) return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    __be32 saddr = 0, daddr = 0;
    __be16 src_port = 0, dst_port = 0;

    bpf_probe_read_kernel(&saddr, sizeof(saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&src_port, sizeof(src_port), &inet->inet_sport);
    bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &inet->inet_dport);

    // Filter by IP: outbound is dst->src (local host sending to remote)
    int is_reply = 0;
    if (saddr == DST_IP_FILTER && daddr == SRC_IP_FILTER)
        is_reply = 1;
    else
        return 0;

#ifdef PORT_FILTER_ENABLED
    __be16 filter_port = htons(PORT_FILTER_VALUE);
    if (src_port != filter_port)
        return 0;
#endif

    // Read seq from tcp_sock
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u32 snd_nxt = 0;
    u32 write_seq = 0;
    int snd_nxt_ret = bpf_probe_read_kernel(&snd_nxt, sizeof(snd_nxt), &tp->snd_nxt);
    int write_seq_ret = bpf_probe_read_kernel(&write_seq, sizeof(write_seq), &tp->write_seq);

    u32 seq = 0;
    if (snd_nxt_ret >= 0 && snd_nxt != 0)
        seq = snd_nxt;
    else if (write_seq_ret >= 0 && write_seq != 0)
        seq = write_seq;

    // Canonical key: always SRC_IP_FILTER -> DST_IP_FILTER
    key->sip = SRC_IP_FILTER;
    key->dip = DST_IP_FILTER;
    key->sport = dst_port;  // Swap for canonical (remote port)
    key->dport = src_port;  // Local port
    key->seq = htonl(seq);
    key->direction = DIR_REPLY;

    *sport_out = src_port;
    *dport_out = dst_port;
    *seq_out = seq;

    return 2;  // Outbound/reply
}

static __always_inline void record_stage(void *ctx, struct tcp_flow_key *key,
    u8 stage, u8 direction, __be16 sport, __be16 dport, u32 payload_len,
    const char *ifname)
{
    u64 ts = bpf_ktime_get_ns();

    // Stats direction: 0=inbound (forward), 1=outbound (reply)
    u32 stats_idx = (direction == DIR_FORWARD) ? 0 : 1;
    struct stats_t *stats = stats_map.lookup(&stats_idx);

    struct event_t *flow = flow_map.lookup(key);

    if (!flow) {
        // Only start new flow at appropriate entry stages
        if (stage != STAGE_FWD_RX && stage != STAGE_REP_STACK)
            return;

        if (stats) {
            __sync_fetch_and_add(&stats->new_flows, 1);
            __sync_fetch_and_add(&stats->entry_packets, 1);
        }

        struct event_t new_flow = {};
        new_flow.key = *key;
        new_flow.ts[stage] = ts;
        new_flow.sport = sport;
        new_flow.dport = dport;
        new_flow.stage = stage;
        new_flow.direction = direction;
        new_flow.payload_len = payload_len;
        if (ifname)
            bpf_probe_read_kernel_str(new_flow.ifname, sizeof(new_flow.ifname), ifname);
        flow_map.update(key, &new_flow);

#if !STATS_MODE
        events.perf_submit(ctx, &new_flow, sizeof(new_flow));
#endif
        return;
    }

    if (flow->ts[stage] != 0)
        return;

    flow->ts[stage] = ts;
    flow->stage = stage;
    flow->direction = direction;
    if (ifname)
        bpf_probe_read_kernel_str(flow->ifname, sizeof(flow->ifname), ifname);

    // Check if this is a terminal stage (flow complete)
    u8 is_terminal = (stage == STAGE_FWD_STACK || stage == STAGE_REP_TX);

    if (is_terminal && stats) {
        __sync_fetch_and_add(&stats->complete_flows, 1);
        __sync_fetch_and_add(&stats->exit_packets, 1);

        // Calculate latency
        u64 start_ts = 0;
        if (direction == DIR_FORWARD)
            start_ts = flow->ts[STAGE_FWD_RX];
        else
            start_ts = flow->ts[STAGE_REP_STACK];

        if (start_ts > 0) {
            u64 latency = ts - start_ts;
            __sync_fetch_and_add(&stats->total_latency_ns, latency);

            u32 bucket = latency_bucket(latency);
            __sync_fetch_and_add(&stats->latency_hist[bucket], 1);

            if (stats->min_latency_ns == 0 || latency < stats->min_latency_ns)
                stats->min_latency_ns = latency;
            if (latency > stats->max_latency_ns)
                stats->max_latency_ns = latency;
        }
    } else if (!is_terminal && stats) {
        __sync_fetch_and_add(&stats->entry_packets, 1);
    }

#if !STATS_MODE
    flow_map.update(key, flow);
    events.perf_submit(ctx, flow, sizeof(*flow));
    if (is_terminal)
        flow_map.delete(key);
#else
    if (is_terminal)
        flow_map.delete(key);
    else
        flow_map.update(key, flow);
#endif
}

// Stage 0: Inbound RX at phy interface (netif_receive_skb)
TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;
    if (!is_phy_iface(ifindex))
        return 0;

    struct tcp_flow_key key = {};
    __be16 sport = 0, dport = 0;
    u32 payload = 0;
    int pkt_type = parse_tcp_skb(skb, &key, &sport, &dport, &payload);

    if (pkt_type != 1)  // Only inbound at phy RX
        return 0;

    record_stage(args, &key, STAGE_FWD_RX, DIR_FORWARD, sport, dport, payload, dev->name);
    return 0;
}

// Stage 1: Inbound delivered to protocol stack (tcp_v4_rcv)
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct tcp_flow_key key = {};
    __be16 sport = 0, dport = 0;
    u32 payload = 0;
    int pkt_type = parse_tcp_skb(skb, &key, &sport, &dport, &payload);

    if (pkt_type != 1)  // Only inbound
        return 0;

    record_stage(ctx, &key, STAGE_FWD_STACK, DIR_FORWARD, sport, dport, payload, NULL);
    return 0;
}

// Stage 2: Outbound sent by protocol stack (__ip_queue_xmit)
// At this probe point, IP header is not yet populated. Read from socket.
int kprobe____ip_queue_xmit(struct pt_regs *ctx, struct sock *sk,
    struct sk_buff *skb, struct flowi *fl)
{
    if (!sk) return 0;

    struct tcp_flow_key key = {};
    __be16 sport = 0, dport = 0;
    u32 seq = 0;
    int pkt_type = parse_tcp_sock(sk, skb, &key, &sport, &dport, &seq);

    if (pkt_type != 2)  // Only outbound
        return 0;

    record_stage(ctx, &key, STAGE_REP_STACK, DIR_REPLY, sport, dport, 0, NULL);
    return 0;
}

// Stage 3: Outbound TX at physical NIC (net_dev_xmit)
RAW_TRACEPOINT_PROBE(net_dev_xmit) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;
    if (!is_phy_iface(ifindex))
        return 0;

    struct tcp_flow_key key = {};
    __be16 sport = 0, dport = 0;
    u32 payload = 0;
    int pkt_type = parse_tcp_skb(skb, &key, &sport, &dport, &payload);

    if (pkt_type != 2)  // Only outbound
        return 0;

    record_stage(ctx, &key, STAGE_REP_TX, DIR_REPLY, sport, dport, payload, dev->name);
    return 0;
}
"""

MAX_STAGES = 4
STAGE_NAMES_FWD = ["InRX@phy", "InRcv@stack"]
STAGE_NAMES_REP = ["OutSnd@stack", "OutTX@phy"]
STAGE_NAMES = STAGE_NAMES_FWD + STAGE_NAMES_REP
DIR_FORWARD = 0
DIR_REPLY = 1
LATENCY_BUCKETS = 21
BUCKET_LABELS = [
    "0-1us", "1-2us", "2-4us", "4-8us", "8-16us",
    "16-32us", "32-64us", "64-128us", "128-256us", "256-512us",
    "512us-1ms", "1-2ms", "2-4ms", "4-8ms", "8-16ms",
    "16-32ms", "32-64ms", "64-128ms", "128-256ms", "256-512ms",
    ">512ms"
]


class TcpFlowKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("seq", ctypes.c_uint32),
        ("direction", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("key", TcpFlowKey),
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("stage", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 2),
        ("payload_len", ctypes.c_uint32),
        ("ifname", ctypes.c_char * 16),
    ]


class Stats(ctypes.Structure):
    _fields_ = [
        ("entry_packets", ctypes.c_uint64),
        ("exit_packets", ctypes.c_uint64),
        ("new_flows", ctypes.c_uint64),
        ("complete_flows", ctypes.c_uint64),
        ("latency_hist", ctypes.c_uint64 * LATENCY_BUCKETS),
        ("total_latency_ns", ctypes.c_uint64),
        ("min_latency_ns", ctypes.c_uint64),
        ("max_latency_ns", ctypes.c_uint64),
    ]


def get_if_index(devname):
    SIOCGIFINDEX = 0x8933
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('16s%dx' % (256 - 16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        return struct.unpack('I', res[16:20])[0]
    finally:
        s.close()


def ip_to_hex(ip_str):
    packed_ip = socket.inet_aton(ip_str)
    host_int = struct.unpack("!I", packed_ip)[0]
    return socket.htonl(host_int)


def format_ip(addr):
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))


class FlowTracker:
    def __init__(self, timeout_ms, phy_iface):
        self.flows = OrderedDict()
        self.timeout_ms = timeout_ms
        self.phy_iface = phy_iface
        self.stats = {
            "total_fwd": 0,
            "total_rep": 0,
            "complete_fwd": 0,
            "complete_rep": 0,
            "fwd_internal_drop": 0,
            "rep_internal_drop": 0,
        }

    def _make_key(self, event):
        return (event.key.sip, event.key.dip,
                socket.ntohs(event.key.sport), socket.ntohs(event.key.dport),
                socket.ntohl(event.key.seq), event.key.direction)

    def update(self, event):
        key = self._make_key(event)
        ts_array = [event.ts[i] for i in range(MAX_STAGES)]
        stage = event.stage
        direction = event.key.direction

        if key not in self.flows:
            if stage != 0 and stage != 2:
                return None
            self.flows[key] = {
                "ts": ts_array,
                "first_seen": time.time(),
                "reported": False,
                "direction": direction,
                "sport": socket.ntohs(event.sport),
                "dport": socket.ntohs(event.dport),
                "payload_len": event.payload_len,
            }
            if direction == 0:
                self.stats["total_fwd"] += 1
            else:
                self.stats["total_rep"] += 1
            return ("new", key, ts_array, direction)

        flow = self.flows[key]
        for i in range(MAX_STAGES):
            if ts_array[i] != 0 and flow["ts"][i] == 0:
                flow["ts"][i] = ts_array[i]

        is_complete = False
        if direction == 0 and stage == 1 and not flow["reported"]:
            is_complete = True
        elif direction == 1 and stage == 3 and not flow["reported"]:
            is_complete = True

        if is_complete:
            flow["reported"] = True
            if direction == 0:
                self.stats["complete_fwd"] += 1
            else:
                self.stats["complete_rep"] += 1
            return ("complete", key, flow["ts"], direction)

        return ("update", key, flow["ts"], direction)

    def check_timeouts(self):
        now = time.time()
        expired = []

        for key, flow in list(self.flows.items()):
            if flow["reported"]:
                expired.append(key)
                continue

            age_ms = (now - flow["first_seen"]) * 1000
            if age_ms < self.timeout_ms:
                continue

            drop_type = self._detect_drop(flow["ts"], flow["direction"])
            if drop_type:
                self._report_drop(key, flow, drop_type)
            expired.append(key)

        for key in expired:
            del self.flows[key]

    def _detect_drop(self, ts, direction):
        if direction == 0:
            if ts[0] and not ts[1]:
                return "fwd_internal"
        else:
            if ts[2] and not ts[3]:
                return "rep_internal"
        return None

    def _report_drop(self, key, flow, drop_type):
        sip, dip, sport, dport, seq, direction = key
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        dir_str = "Inbound" if direction == 0 else "Outbound"

        print("\n=== TCP Drop Detected (%s): %s ===" % (dir_str, now))
        print("Flow: %s:%d -> %s:%d Seq=%u" % (
            format_ip(sip), sport, format_ip(dip), dport, seq))

        if direction == 0:
            stages = [(0, STAGE_NAMES[0]), (1, STAGE_NAMES[1])]
        else:
            stages = [(2, STAGE_NAMES[2]), (3, STAGE_NAMES[3])]

        for i, name in stages:
            status = "recorded" if flow["ts"][i] != 0 else "MISSING"
            print("  [%d] %s: %s" % (i, name, status))

        if drop_type == "fwd_internal":
            print("\nDrop: Inbound packet dropped INTERNALLY (between phy NIC and tcp_v4_rcv)")
            self.stats["fwd_internal_drop"] += 1
        elif drop_type == "rep_internal":
            print("\nDrop: Outbound packet dropped INTERNALLY (between __ip_queue_xmit and phy NIC TX)")
            self.stats["rep_internal_drop"] += 1

    def print_stats(self):
        print("\n=== TCP System Path Statistics ===")
        print("Inbound:  total=%d, complete=%d, internal_drop=%d" % (
            self.stats["total_fwd"], self.stats["complete_fwd"],
            self.stats["fwd_internal_drop"]))
        print("Outbound: total=%d, complete=%d, internal_drop=%d" % (
            self.stats["total_rep"], self.stats["complete_rep"],
            self.stats["rep_internal_drop"]))


class BPFMapScanner:
    def __init__(self, bpf, timeout_ns):
        self.bpf = bpf
        self.timeout_ns = timeout_ns
        self.pending_flows = {}
        self.internal_drop_count_fwd = 0
        self.internal_drop_count_rep = 0

    def scan_for_drops(self):
        now = time.time()
        timeout_sec = self.timeout_ns / 1e9
        flow_map = self.bpf["flow_map"]
        keys_to_delete = []

        for key, event in flow_map.items():
            key_tuple = (key.sip, key.dip, key.sport, key.dport,
                         key.seq, key.direction)

            direction = key.direction
            if direction == DIR_FORWARD:
                has_entry = event.ts[0] != 0
                has_exit = event.ts[1] != 0
            else:
                has_entry = event.ts[2] != 0
                has_exit = event.ts[3] != 0

            if has_entry and not has_exit:
                if key_tuple not in self.pending_flows:
                    self.pending_flows[key_tuple] = now
                else:
                    age = now - self.pending_flows[key_tuple]
                    if age > timeout_sec:
                        if direction == DIR_FORWARD:
                            self.internal_drop_count_fwd += 1
                        else:
                            self.internal_drop_count_rep += 1
                        keys_to_delete.append(key)
                        del self.pending_flows[key_tuple]
            elif has_entry and has_exit:
                if key_tuple in self.pending_flows:
                    del self.pending_flows[key_tuple]

        for key in keys_to_delete:
            try:
                del flow_map[key]
            except:
                pass

        current_keys = set()
        for key, _ in flow_map.items():
            current_keys.add((key.sip, key.dip, key.sport, key.dport,
                              key.seq, key.direction))

        stale_keys = [k for k in self.pending_flows if k not in current_keys]
        for k in stale_keys:
            del self.pending_flows[k]


def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Detect TCP drops between physical NIC and protocol stack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default stats mode - periodic summary output
  sudo ./system_tcp_path_tracer.py --src-ip 192.168.70.32 --dst-ip 192.168.70.31 \\
      --phy-iface enp24s0f0np0

  # Stats mode with custom interval
  sudo ./system_tcp_path_tracer.py --src-ip 192.168.70.32 --dst-ip 192.168.70.31 \\
      --phy-iface enp24s0f0np0 --stats-interval 5

  # Verbose per-packet mode
  sudo ./system_tcp_path_tracer.py --src-ip 192.168.70.32 --dst-ip 192.168.70.31 \\
      --phy-iface enp24s0f0np0 --verbose

  # Filter by port
  sudo ./system_tcp_path_tracer.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --phy-iface ens4f0 --port 22 --timeout-ms 2000 --verbose

Stages:
  Inbound (forward):
    [0] InRX@phy       - Inbound received at physical interface
    [1] InRcv@stack    - Inbound delivered to tcp_v4_rcv
  Outbound (reply):
    [2] OutSnd@stack   - Outbound sent by protocol stack (__ip_queue_xmit)
    [3] OutTX@phy      - Outbound transmitted at physical interface
""")

    parser.add_argument('--src-ip', type=str, required=True,
                        help='Source IP (remote peer)')
    parser.add_argument('--dst-ip', type=str, required=True,
                        help='Destination IP (local host)')
    parser.add_argument('--phy-iface', type=str, required=True,
                        help='Physical interface(s), comma-separated for bond')
    parser.add_argument('--port', type=int, default=0,
                        help='Filter by local service port (default: all)')
    parser.add_argument('--timeout-ms', type=int, default=1000,
                        help='Timeout in ms for drop detection (default: 1000)')
    parser.add_argument('--verbose', action='store_true',
                        help='Per-packet output mode (disables default stats mode)')
    parser.add_argument('--stats-interval', type=int, default=10,
                        help='Stats output interval in seconds (default: 10)')

    args = parser.parse_args()

    # Default is stats mode; --verbose disables it
    stats_mode = not args.verbose

    phy_ifaces = [s.strip() for s in args.phy_iface.split(',')]
    phy_ifindexes = []
    try:
        for iface in phy_ifaces:
            phy_ifindexes.append((iface, get_if_index(iface)))
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    src_ip_hex = ip_to_hex(args.src_ip)
    dst_ip_hex = ip_to_hex(args.dst_ip)

    phy_indices = [idx for _, idx in phy_ifindexes]
    iface_arrays = """
#define PHY_IFACE_COUNT %d
static const int phy_ifindexes[PHY_IFACE_COUNT] = {%s};
""" % (len(phy_indices), ', '.join(str(i) for i in phy_indices))

    if args.port > 0:
        port_filter = """
#define PORT_FILTER_ENABLED 1
#define PORT_FILTER_VALUE %d
""" % args.port
    else:
        port_filter = ""

    print("=== System TCP Path Tracer ===")
    print("Source IP (remote): %s" % args.src_ip)
    print("Destination IP (local): %s" % args.dst_ip)
    print("Physical interface(s): %s" % ', '.join(
        "%s(ifindex=%d)" % (n, i) for n, i in phy_ifindexes))
    if args.port > 0:
        print("Port filter: %d" % args.port)
    print("Timeout: %d ms" % args.timeout_ms)
    if stats_mode:
        print("Mode: Stats (interval=%ds)" % args.stats_interval)
    else:
        print("Mode: Verbose")
    print("")
    print("Inbound:  phy RX -> tcp_v4_rcv")
    print("Outbound: __ip_queue_xmit -> phy TX")
    print("  [0] Inbound RX at %s" % args.phy_iface)
    print("  [1] Inbound delivered to tcp_v4_rcv")
    print("  [2] Outbound sent by __ip_queue_xmit")
    print("  [3] Outbound TX at %s" % args.phy_iface)
    print("")

    try:
        bpf_code = bpf_text % (src_ip_hex, dst_ip_hex)
        bpf_code = bpf_code.replace("__IFACE_ARRAYS__", iface_arrays)
        bpf_code = bpf_code.replace("__PORT_FILTER__", port_filter)
        stats_mode_val = "1" if stats_mode else "0"
        bpf_code = bpf_code.replace("__STATS_MODE__", stats_mode_val)
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    tracker = FlowTracker(args.timeout_ms, args.phy_iface)

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        result = tracker.update(event)

        if args.verbose and result:
            action, key, ts, direction = result
            sip, dip, sport, dport, seq, dirn = key
            dir_str = "FWD" if direction == 0 else "REP"
            if direction == 0:
                ts_str = " ".join(["%s:%s" % (STAGE_NAMES[i],
                    "Y" if ts[i] != 0 else "-") for i in range(2)])
            else:
                ts_str = " ".join(["%s:%s" % (STAGE_NAMES[i],
                    "Y" if ts[i] != 0 else "-") for i in range(2, 4)])
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print("%s [%s] %s %s:%d->%s:%d Seq=%u %s" % (
                now_str, action, dir_str, format_ip(sip), sport,
                format_ip(dip), dport, seq, ts_str))
            if action == "complete":
                if direction == 0 and ts[0] and ts[1]:
                    lat = (ts[1] - ts[0]) / 1000.0
                    print("  Latency(us): InPath=%.1f" % lat)
                elif direction == 1 and ts[2] and ts[3]:
                    lat = (ts[3] - ts[2]) / 1000.0
                    print("  Latency(us): OutPath=%.1f" % lat)
                print("-" * 80)

    # Stats mode helper functions
    def aggregate_percpu_stats(direction):
        stats_map = b["stats_map"]
        totals = {
            "entry_packets": 0, "exit_packets": 0, "new_flows": 0,
            "complete_flows": 0, "total_latency_ns": 0,
            "min_latency_ns": 0, "max_latency_ns": 0,
            "latency_hist": [0] * LATENCY_BUCKETS
        }
        try:
            cpu_stats = stats_map[direction]
            for s in cpu_stats:
                totals["entry_packets"] += s.entry_packets
                totals["exit_packets"] += s.exit_packets
                totals["new_flows"] += s.new_flows
                totals["complete_flows"] += s.complete_flows
                totals["total_latency_ns"] += s.total_latency_ns
                if s.min_latency_ns > 0:
                    if totals["min_latency_ns"] == 0 or s.min_latency_ns < totals["min_latency_ns"]:
                        totals["min_latency_ns"] = s.min_latency_ns
                if s.max_latency_ns > totals["max_latency_ns"]:
                    totals["max_latency_ns"] = s.max_latency_ns
                for i in range(LATENCY_BUCKETS):
                    totals["latency_hist"][i] += s.latency_hist[i]
        except:
            pass
        return totals

    def calculate_percentile(hist, percentile):
        total = sum(hist)
        if total == 0:
            return 0
        target = total * percentile / 100.0
        cumsum = 0
        for i, count in enumerate(hist):
            cumsum += count
            if cumsum >= target:
                return (1 << i) if i > 0 else 1
        return (1 << (LATENCY_BUCKETS - 1))

    def print_histogram(hist, indent="  "):
        max_count = max(hist) if hist else 0
        if max_count == 0:
            print("%s(no data)" % indent)
            return
        bar_width = 40
        for i, count in enumerate(hist):
            if count > 0:
                bar_len = int(count * bar_width / max_count)
                bar = "*" * bar_len
                print("%s%12s: %8d |%s" % (indent, BUCKET_LABELS[i], count, bar))

    def print_stats_summary(stats_fwd, stats_rep, prev_fwd, prev_rep,
                            interval_start, interval_end, drops_fwd, drops_rep):
        delta_fwd = {}
        delta_rep = {}
        for key in ["entry_packets", "exit_packets", "new_flows", "complete_flows"]:
            delta_fwd[key] = stats_fwd[key] - prev_fwd.get(key, 0)
            delta_rep[key] = stats_rep[key] - prev_rep.get(key, 0)

        start_str = datetime.datetime.fromtimestamp(interval_start).strftime("%H:%M:%S")
        end_str = datetime.datetime.fromtimestamp(interval_end).strftime("%H:%M:%S")

        print("\n" + "=" * 70)
        print("=== System TCP Stats [%s - %s] ===" % (start_str, end_str))
        print("=" * 70)

        print("Inbound:   Entry=%d  Complete=%d  InternalDrop=%d" % (
            delta_fwd["entry_packets"], delta_fwd["complete_flows"], drops_fwd))
        print("Outbound:  Entry=%d  Complete=%d  InternalDrop=%d" % (
            delta_rep["entry_packets"], delta_rep["complete_flows"], drops_rep))

        if stats_fwd["complete_flows"] > 0:
            avg_lat = stats_fwd["total_latency_ns"] / stats_fwd["complete_flows"] / 1000.0
            min_lat = stats_fwd["min_latency_ns"] / 1000.0
            max_lat = stats_fwd["max_latency_ns"] / 1000.0
            p50 = calculate_percentile(stats_fwd["latency_hist"], 50)
            p99 = calculate_percentile(stats_fwd["latency_hist"], 99)
            print("\nInbound Latency(us): Min=%.1f  Avg=%.1f  Max=%.1f  P50=%d  P99=%d" % (
                min_lat, avg_lat, max_lat, p50, p99))
            print("Inbound Latency Histogram:")
            print_histogram(stats_fwd["latency_hist"])

        if stats_rep["complete_flows"] > 0:
            avg_lat = stats_rep["total_latency_ns"] / stats_rep["complete_flows"] / 1000.0
            min_lat = stats_rep["min_latency_ns"] / 1000.0
            max_lat = stats_rep["max_latency_ns"] / 1000.0
            p50 = calculate_percentile(stats_rep["latency_hist"], 50)
            p99 = calculate_percentile(stats_rep["latency_hist"], 99)
            print("\nOutbound Latency(us): Min=%.1f  Avg=%.1f  Max=%.1f  P50=%d  P99=%d" % (
                min_lat, avg_lat, max_lat, p50, p99))
            print("Outbound Latency Histogram:")
            print_histogram(stats_rep["latency_hist"])

        print("")

    b["events"].open_perf_buffer(handle_event)
    print("Tracing... Hit Ctrl-C to end.\n")

    if stats_mode:
        scanner = BPFMapScanner(b, args.timeout_ms * 1000000)
        scan_interval = args.timeout_ms / 1000.0
        prev_stats_fwd = {}
        prev_stats_rep = {}
        prev_drops_fwd = 0
        prev_drops_rep = 0
        interval_start = time.time()
        try:
            while True:
                time.sleep(scan_interval)
                now = time.time()
                scanner.scan_for_drops()

                if now - interval_start >= args.stats_interval:
                    stats_fwd = aggregate_percpu_stats(DIR_FORWARD)
                    stats_rep = aggregate_percpu_stats(DIR_REPLY)
                    drops_fwd = scanner.internal_drop_count_fwd - prev_drops_fwd
                    drops_rep = scanner.internal_drop_count_rep - prev_drops_rep
                    print_stats_summary(stats_fwd, stats_rep, prev_stats_fwd, prev_stats_rep,
                                        interval_start, now, drops_fwd, drops_rep)
                    prev_stats_fwd = stats_fwd.copy()
                    prev_stats_rep = stats_rep.copy()
                    prev_drops_fwd = scanner.internal_drop_count_fwd
                    prev_drops_rep = scanner.internal_drop_count_rep
                    interval_start = now
        except KeyboardInterrupt:
            print("\nDetaching...")
            stats_fwd = aggregate_percpu_stats(DIR_FORWARD)
            stats_rep = aggregate_percpu_stats(DIR_REPLY)
            drops_fwd = scanner.internal_drop_count_fwd - prev_drops_fwd
            drops_rep = scanner.internal_drop_count_rep - prev_drops_rep
            print_stats_summary(stats_fwd, stats_rep, prev_stats_fwd, prev_stats_rep,
                                interval_start, time.time(), drops_fwd, drops_rep)
            print("Total Internal Drops: Inbound=%d  Outbound=%d" % (
                scanner.internal_drop_count_fwd, scanner.internal_drop_count_rep))
    else:
        # Verbose mode main loop
        try:
            last_check = time.time()
            while True:
                b.perf_buffer_poll(timeout=100)
                now = time.time()
                if now - last_check >= 1.0:
                    tracker.check_timeouts()
                    last_check = now
        except KeyboardInterrupt:
            print("\nDetaching...")
            tracker.check_timeouts()
            tracker.print_stats()


if __name__ == "__main__":
    main()
