#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TCP Path Tracer - Trace TCP packets through network path for boundary detection
#
# This tool monitors TCP packets at two network interfaces to trace
# packet flow and detect drops in the forwarding path. It tracks both
# forward (request) and reply directions for complete visibility.
#
# Usage:
#   sudo ./tcp_path_tracer.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#       --rx-iface eth0 --tx-iface eth1 [--timeout-ms 1000]
#
# Packet identification:
#   - Uses TCP sequence number as unique identifier
#   - Assumes TSO/GRO enabled (no IP fragmentation for TCP)

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

# Force unbuffered stdout
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d

#define MAX_IFACES 8
__IFACE_ARRAYS__

#define STAGE_RX      0
#define STAGE_TX      1
#define MAX_STAGES    2

#define DIR_FORWARD   0
#define DIR_REPLY     1

#define STATS_MODE __STATS_MODE__
#define LATENCY_BUCKETS 21

// Debug framework
#define DEBUG_MODE __DEBUG_MODE__
#if DEBUG_MODE
BPF_HISTOGRAM(debug_stats, u32);
static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stats.increment(key);
}
#else
#define debug_inc(stage, code) do {} while(0)
#endif

// Stage IDs
#define STAGE_RX_PROBE      0
#define STAGE_TX_PROBE      1
#define STAGE_PARSE         2

// Code points
#define CODE_PROBE_ENTRY        1
#define CODE_IFACE_CHECK        2
#define CODE_IFACE_MATCH        3
#define CODE_PARSE_ENTRY        4
#define CODE_PARSE_IP_OK        5
#define CODE_PARSE_TCP_OK       6
#define CODE_PARSE_FORWARD      7
#define CODE_PARSE_REPLY        8
#define CODE_PARSE_NO_MATCH     9
#define CODE_PARSE_PORT_FILTER 10
#define CODE_GROUP_NEW         11
#define CODE_GROUP_UPDATE      12
#define CODE_GROUP_COMPLETE    13
#define CODE_PERF_SUBMIT       14

struct stats_t {
    u64 rx_packets;
    u64 tx_packets;
    u64 rx_groups;
    u64 complete_groups;
    u64 latency_hist[LATENCY_BUCKETS];
    u64 total_latency_ns;
    u64 min_latency_ns;
    u64 max_latency_ns;
};

BPF_PERCPU_ARRAY(stats_map, struct stats_t, 2);

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

static __always_inline int is_rx_iface(int ifindex) {
    #pragma unroll
    for (int i = 0; i < RX_IFACE_COUNT; i++) {
        if (rx_ifindexes[i] == ifindex)
            return 1;
    }
    return 0;
}

static __always_inline int is_tx_iface(int ifindex) {
    #pragma unroll
    for (int i = 0; i < TX_IFACE_COUNT; i++) {
        if (tx_ifindexes[i] == ifindex)
            return 1;
    }
    return 0;
}

struct tcp_group_key {
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    __be32 seq;
    u8 direction;
    u8 pad[3];
};

struct event_t {
    struct tcp_group_key key;
    u64 ts[MAX_STAGES];
    __be16 sport;
    __be16 dport;
    u8 stage;
    u8 direction;
    u8 pad[2];
    u32 payload_len;
    char ifname[16];
};

BPF_TABLE("lru_hash", struct tcp_group_key, struct event_t, group_map, 10240);
BPF_PERF_OUTPUT(events);

static __always_inline int parse_tcp_packet(struct sk_buff *skb,
    struct tcp_group_key *key, __be16 *sport_out, __be16 *dport_out,
    u32 *payload_out, u8 *direction_out)
{
    debug_inc(STAGE_PARSE, CODE_PARSE_ENTRY);
    unsigned char *head;
    u16 network_header_offset;
    u16 transport_header_offset;

    if (bpf_probe_read(&head, sizeof(head), &skb->head) < 0)
        return 0;
    if (bpf_probe_read(&network_header_offset, sizeof(network_header_offset),
            &skb->network_header) < 0)
        return 0;
    if (network_header_offset == (u16)~0U || network_header_offset > 2048)
        return 0;

    struct iphdr ip;
    if (bpf_probe_read(&ip, sizeof(ip), head + network_header_offset) < 0)
        return 0;

    if (ip.protocol != IPPROTO_TCP)
        return 0;
    debug_inc(STAGE_PARSE, CODE_PARSE_TCP_OK);

    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;

    int is_forward = (actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER);
    int is_reply = (actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER);

    if (!is_forward && !is_reply) {
        debug_inc(STAGE_PARSE, CODE_PARSE_NO_MATCH);
        return 0;
    }

    if (is_forward)
        debug_inc(STAGE_PARSE, CODE_PARSE_FORWARD);
    else
        debug_inc(STAGE_PARSE, CODE_PARSE_REPLY);

    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5)
        return 0;

    if (bpf_probe_read(&transport_header_offset, sizeof(transport_header_offset),
            &skb->transport_header) < 0)
        return 0;

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U ||
        transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    struct tcphdr tcp;
    if (bpf_probe_read(&tcp, sizeof(tcp), head + transport_header_offset) < 0)
        return 0;

    __be16 actual_sport = tcp.source;
    __be16 actual_dport = tcp.dest;
    __be32 seq = tcp.seq;

    if (is_forward) {
        if (SRC_PORT_FILTER != 0 && ntohs(actual_sport) != SRC_PORT_FILTER)
            return 0;
        if (DST_PORT_FILTER != 0 && ntohs(actual_dport) != DST_PORT_FILTER)
            return 0;
    } else {
        if (SRC_PORT_FILTER != 0 && ntohs(actual_dport) != SRC_PORT_FILTER)
            return 0;
        if (DST_PORT_FILTER != 0 && ntohs(actual_sport) != DST_PORT_FILTER)
            return 0;
    }

    *sport_out = actual_sport;
    *dport_out = actual_dport;

    u16 ip_len = ntohs(ip.tot_len);
    u16 ip_hdr_len = ip_ihl * 4;
    u8 tcp_doff = tcp.doff & 0x0F;
    u16 tcp_hdr_len = tcp_doff * 4;
    if (ip_len > ip_hdr_len + tcp_hdr_len) {
        *payload_out = ip_len - ip_hdr_len - tcp_hdr_len;
    } else {
        *payload_out = 0;
    }

    if (is_forward) {
        key->sip = actual_sip;
        key->dip = actual_dip;
        key->sport = actual_sport;
        key->dport = actual_dport;
        key->direction = DIR_FORWARD;
        *direction_out = DIR_FORWARD;
    } else {
        key->sip = actual_dip;
        key->dip = actual_sip;
        key->sport = actual_dport;
        key->dport = actual_sport;
        key->direction = DIR_REPLY;
        *direction_out = DIR_REPLY;
    }
    key->seq = seq;

    return is_forward ? 1 : 2;
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    debug_inc(STAGE_RX_PROBE, CODE_PROBE_ENTRY);
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    debug_inc(STAGE_RX_PROBE, CODE_IFACE_CHECK);
    if (!is_rx_iface(ifindex))
        return 0;
    debug_inc(STAGE_RX_PROBE, CODE_IFACE_MATCH);

    struct tcp_group_key key = {};
    __be16 sport = 0, dport = 0;
    u32 payload = 0;
    u8 direction = 0;

    int match = parse_tcp_packet(skb, &key, &sport, &dport, &payload, &direction);
    if (!match)
        return 0;

    u64 ts = bpf_ktime_get_ns();

    u32 stats_key = direction;
    struct stats_t *stats = stats_map.lookup(&stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
    }

    struct event_t *group = group_map.lookup(&key);

    if (!group) {
        struct event_t evt = {};
        evt.key = key;
        evt.ts[STAGE_RX] = ts;
        evt.sport = sport;
        evt.dport = dport;
        evt.stage = STAGE_RX;
        evt.direction = direction;
        evt.payload_len = payload;
        bpf_probe_read_str(evt.ifname, sizeof(evt.ifname), dev->name);
        group_map.update(&key, &evt);

        if (stats) {
            __sync_fetch_and_add(&stats->rx_groups, 1);
        }

#if !STATS_MODE
        events.perf_submit(args, &evt, sizeof(evt));
#endif
        return 0;
    }

    if (group->ts[STAGE_RX] == 0) {
        group->ts[STAGE_RX] = ts;
    }
    group->stage = STAGE_RX;
    bpf_probe_read_str(group->ifname, sizeof(group->ifname), dev->name);
    group_map.update(&key, group);

#if !STATS_MODE
    events.perf_submit(args, group, sizeof(*group));
#endif

    return 0;
}

RAW_TRACEPOINT_PROBE(net_dev_xmit) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb)
        return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    if (!is_tx_iface(ifindex))
        return 0;

    struct tcp_group_key key = {};
    __be16 sport = 0, dport = 0;
    u32 payload = 0;
    u8 direction = 0;

    int match = parse_tcp_packet(skb, &key, &sport, &dport, &payload, &direction);
    if (!match)
        return 0;

    u64 ts = bpf_ktime_get_ns();

    u32 stats_key = direction;
    struct stats_t *stats = stats_map.lookup(&stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->tx_packets, 1);
    }

    struct event_t *group = group_map.lookup(&key);

    if (!group) {
        struct event_t evt = {};
        evt.key = key;
        evt.ts[STAGE_TX] = ts;
        evt.sport = sport;
        evt.dport = dport;
        evt.stage = STAGE_TX;
        evt.direction = direction;
        evt.payload_len = payload;
        bpf_probe_read_str(evt.ifname, sizeof(evt.ifname), dev->name);
        group_map.update(&key, &evt);

#if !STATS_MODE
        events.perf_submit(ctx, &evt, sizeof(evt));
#endif
        return 0;
    }

    if (group->ts[STAGE_TX] == 0) {
        group->ts[STAGE_TX] = ts;
    }
    group->stage = STAGE_TX;
    bpf_probe_read_str(group->ifname, sizeof(group->ifname), dev->name);

    u8 is_complete = (group->ts[STAGE_RX] != 0);

    if (is_complete && stats) {
        u64 latency = ts - group->ts[STAGE_RX];
        __sync_fetch_and_add(&stats->complete_groups, 1);
        __sync_fetch_and_add(&stats->total_latency_ns, latency);

        u32 bucket = latency_bucket(latency);
        __sync_fetch_and_add(&stats->latency_hist[bucket], 1);

        if (stats->min_latency_ns == 0 || latency < stats->min_latency_ns) {
            stats->min_latency_ns = latency;
        }
        if (latency > stats->max_latency_ns) {
            stats->max_latency_ns = latency;
        }
    }

#if !STATS_MODE
    group_map.update(&key, group);
    events.perf_submit(ctx, group, sizeof(*group));
    if (is_complete) {
        group_map.delete(&key);
    }
#else
    if (is_complete) {
        group_map.delete(&key);
    } else {
        group_map.update(&key, group);
    }
#endif

    return 0;
}
"""

MAX_STAGES = 2
STAGE_NAMES = ["RX", "TX"]
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


class Event(ctypes.Structure):
    class Key(ctypes.Structure):
        _fields_ = [
            ("sip", ctypes.c_uint32),
            ("dip", ctypes.c_uint32),
            ("sport", ctypes.c_uint16),
            ("dport", ctypes.c_uint16),
            ("seq", ctypes.c_uint32),
            ("direction", ctypes.c_uint8),
            ("pad", ctypes.c_uint8 * 3),
        ]

    _fields_ = [
        ("key", Key),
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("stage", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 2),
        ("payload_len", ctypes.c_uint32),
        ("ifname", ctypes.c_char * 16),
    ]


def ip_to_hex(ip_str):
    """Convert IP string to hex value matching kernel iphdr read format"""
    packed_ip = socket.inet_aton(ip_str)
    host_int = struct.unpack("!I", packed_ip)[0]
    return socket.htonl(host_int)


def format_ip(ip_int):
    """Convert hex IP back to dotted string"""
    net_int = socket.htonl(ip_int)
    return socket.inet_ntoa(struct.pack("!I", net_int))


def get_if_index(ifname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack('256s', ifname.encode()[:15])
        res = fcntl.ioctl(sock.fileno(), 0x8933, ifr)
        return struct.unpack('i', res[16:20])[0]
    finally:
        sock.close()


def validate_ip(ip_str):
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        for p in parts:
            if not 0 <= int(p) <= 255:
                return False
        return True
    except:
        return False


def validate_interfaces(iface_list):
    if not iface_list:
        return False, "empty list"
    if len(iface_list) > 8:
        return False, "max 8 interfaces"
    return True, None


class GroupTracker:
    def __init__(self, timeout_ms, rx_iface, tx_iface, port_filter=None):
        self.groups = OrderedDict()
        self.timeout_ns = timeout_ms * 1000000
        self.rx_iface = rx_iface
        self.tx_iface = tx_iface
        self.port_filter = port_filter
        self.stats = {
            "total_groups_fwd": 0, "total_groups_rep": 0,
            "complete_groups_fwd": 0, "complete_groups_rep": 0,
            "internal_drop_fwd": 0, "internal_drop_rep": 0,
        }

    def update(self, event):
        key = (event.key.sip, event.key.dip, event.key.sport,
               event.key.dport, event.key.seq, event.key.direction)
        ts_array = list(event.ts)
        sport = socket.ntohs(event.sport)
        dport = socket.ntohs(event.dport)
        direction = event.direction

        if key not in self.groups:
            self.groups[key] = {
                "ts": ts_array,
                "first_seen": time.time(),
                "reported": False,
                "sport": sport,
                "dport": dport,
                "direction": direction,
                "payload_len": event.payload_len,
            }
            if direction == DIR_FORWARD:
                self.stats["total_groups_fwd"] += 1
            else:
                self.stats["total_groups_rep"] += 1
            return ("new", key, self.groups[key])

        group = self.groups[key]
        for i in range(MAX_STAGES):
            if ts_array[i] != 0 and group["ts"][i] == 0:
                group["ts"][i] = ts_array[i]

        group["payload_len"] = max(group["payload_len"], event.payload_len)
        is_complete = (group["ts"][0] != 0 and group["ts"][1] != 0)

        if is_complete and not group["reported"]:
            group["reported"] = True
            if direction == DIR_FORWARD:
                self.stats["complete_groups_fwd"] += 1
            else:
                self.stats["complete_groups_rep"] += 1
            return ("complete", key, group)

        return ("update", key, group)

    def check_timeouts(self):
        now = time.time()
        expired = []

        for key, group in list(self.groups.items()):
            if group["reported"]:
                expired.append(key)
                continue

            age_sec = now - group["first_seen"]
            if age_sec * 1000 < self.timeout_ns / 1000000:
                continue

            drop_type = self._detect_drop(group)
            if drop_type:
                self._report_drop(key, group, drop_type)
            expired.append(key)

        for key in expired:
            del self.groups[key]

    def _detect_drop(self, group):
        has_rx = group["ts"][0] != 0
        has_tx = group["ts"][1] != 0
        if has_rx and not has_tx:
            return "internal"
        return None

    def _report_drop(self, key, group, drop_type):
        sip, dip, sport, dport, seq, direction = key
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        dir_str = "FWD" if direction == DIR_FORWARD else "REP"

        print("\n=== TCP Drop Detected [%s]: %s ===" % (dir_str, now))
        print("Flow: %s:%d -> %s:%d seq=%u" % (
            format_ip(sip), sport, format_ip(dip), dport, seq))

        stage_info = []
        for i, name in enumerate(STAGE_NAMES):
            if group["ts"][i] != 0:
                stage_info.append("  [%d] %s: recorded" % (i, name))
            else:
                stage_info.append("  [%d] %s: MISSING" % (i, name))
        print("\n".join(stage_info))

        if drop_type == "internal":
            print("\nDrop Location: Dropped INTERNALLY")
            print("  Received at %s but NOT sent from %s" % (
                self.rx_iface, self.tx_iface))
            if direction == DIR_FORWARD:
                self.stats["internal_drop_fwd"] += 1
            else:
                self.stats["internal_drop_rep"] += 1

    def print_stats(self):
        print("\n=== TCP Group Statistics ===")
        print("Forward (src->dst):")
        print("  Total groups: %d" % self.stats["total_groups_fwd"])
        print("  Complete: %d" % self.stats["complete_groups_fwd"])
        print("  Internal drops: %d" % self.stats["internal_drop_fwd"])
        print("Reply (dst->src):")
        print("  Total groups: %d" % self.stats["total_groups_rep"])
        print("  Complete: %d" % self.stats["complete_groups_rep"])
        print("  Internal drops: %d" % self.stats["internal_drop_rep"])


def print_debug_stats(b):
    stage_names = {
        0: "RX_PROBE",
        1: "TX_PROBE",
        2: "PARSE",
    }
    code_names = {
        1: "PROBE_ENTRY",
        2: "IFACE_CHECK",
        3: "IFACE_MATCH",
        4: "PARSE_ENTRY",
        5: "PARSE_IP_OK",
        6: "PARSE_TCP_OK",
        7: "PARSE_FORWARD",
        8: "PARSE_REPLY",
        9: "PARSE_NO_MATCH",
        10: "PARSE_PORT_FILTER",
        11: "GROUP_NEW",
        12: "GROUP_UPDATE",
        13: "GROUP_COMPLETE",
        14: "PERF_SUBMIT",
    }
    print("\n=== Debug Statistics ===")
    try:
        debug_stats = b["debug_stats"]
        for k, v in sorted(debug_stats.items(), key=lambda x: x[0].value):
            if v.value > 0:
                stage_id = k.value >> 8
                code_point = k.value & 0xFF
                stage_name = stage_names.get(stage_id, "STAGE_%d" % stage_id)
                code_name = code_names.get(code_point, "CODE_%d" % code_point)
                print("  %s.%s: %d" % (stage_name, code_name, v.value))
    except KeyError:
        print("  (debug mode not enabled)")


class BPFMapScanner:
    def __init__(self, bpf, timeout_ns):
        self.bpf = bpf
        self.timeout_ns = timeout_ns
        self.pending_groups = {}
        self.internal_drop_count_fwd = 0
        self.internal_drop_count_rep = 0

    def scan_for_drops(self):
        now = time.time()
        timeout_sec = self.timeout_ns / 1e9
        group_map = self.bpf["group_map"]
        keys_to_delete = []

        for key, event in group_map.items():
            key_tuple = (key.sip, key.dip, key.sport, key.dport,
                        key.seq, key.direction)

            has_rx = event.ts[0] != 0
            has_tx = event.ts[1] != 0

            if has_rx and not has_tx:
                if key_tuple not in self.pending_groups:
                    self.pending_groups[key_tuple] = now
                else:
                    age = now - self.pending_groups[key_tuple]
                    if age > timeout_sec:
                        if key.direction == DIR_FORWARD:
                            self.internal_drop_count_fwd += 1
                        else:
                            self.internal_drop_count_rep += 1
                        keys_to_delete.append(key)
                        del self.pending_groups[key_tuple]
            elif has_rx and has_tx:
                if key_tuple in self.pending_groups:
                    del self.pending_groups[key_tuple]

        for key in keys_to_delete:
            try:
                del group_map[key]
            except:
                pass

        current_keys = set()
        for key, _ in group_map.items():
            current_keys.add((key.sip, key.dip, key.sport, key.dport,
                            key.seq, key.direction))

        stale_keys = [k for k in self.pending_groups if k not in current_keys]
        for k in stale_keys:
            del self.pending_groups[k]


def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Trace TCP packets between two interfaces (bidirectional)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor TCP between vnet35 (RX) and enp24s0f0np0 (TX)
  sudo ./tcp_path_tracer.py --src-ip 192.168.77.83 --dst-ip 192.168.76.244 \\
      --rx-iface vnet35 --tx-iface enp24s0f0np0

  # With port filtering
  sudo ./tcp_path_tracer.py --src-ip 192.168.77.83 --dst-ip 192.168.76.244 \\
      --rx-iface vnet35 --tx-iface enp24s0f0np0 --dst-port 5201

  # Stats mode
  sudo ./tcp_path_tracer.py --src-ip 192.168.77.83 --dst-ip 192.168.76.244 \\
      --rx-iface vnet35 --tx-iface enp24s0f0np0 --dst-port 5201 \\
      --stats-mode --stats-interval 10
""")

    parser.add_argument('--src-ip', type=str, required=True,
                        help='Source IP (forward direction)')
    parser.add_argument('--dst-ip', type=str, required=True,
                        help='Destination IP (forward direction)')
    parser.add_argument('--rx-iface', type=str, required=True,
                        help='RX interface(s), comma-separated')
    parser.add_argument('--tx-iface', type=str, required=True,
                        help='TX interface(s), comma-separated')
    parser.add_argument('--src-port', type=int, default=0,
                        help='Filter by source port')
    parser.add_argument('--dst-port', type=int, default=0,
                        help='Filter by destination port')
    parser.add_argument('--timeout-ms', type=int, default=1000,
                        help='Timeout for drop detection (default: 1000ms)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print all packets')
    parser.add_argument('--stats-mode', action='store_true',
                        help='Stats mode: periodic summary')
    parser.add_argument('--stats-interval', type=int, default=10,
                        help='Stats interval in seconds (default: 10)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug statistics')

    args = parser.parse_args()

    if args.verbose and args.stats_mode:
        print("Error: --verbose and --stats-mode are mutually exclusive")
        sys.exit(1)

    if not validate_ip(args.src_ip):
        print("Error: Invalid source IP: %s" % args.src_ip)
        sys.exit(1)
    if not validate_ip(args.dst_ip):
        print("Error: Invalid destination IP: %s" % args.dst_ip)
        sys.exit(1)

    rx_ifaces = [s.strip() for s in args.rx_iface.split(',')]
    tx_ifaces = [s.strip() for s in args.tx_iface.split(',')]

    valid, err = validate_interfaces(rx_ifaces)
    if not valid:
        print("Error: Invalid RX interface list: %s" % err)
        sys.exit(1)
    valid, err = validate_interfaces(tx_ifaces)
    if not valid:
        print("Error: Invalid TX interface list: %s" % err)
        sys.exit(1)

    rx_ifindexes = []
    tx_ifindexes = []

    try:
        for iface in rx_ifaces:
            rx_ifindexes.append((iface, get_if_index(iface)))
        for iface in tx_ifaces:
            tx_ifindexes.append((iface, get_if_index(iface)))
    except OSError as e:
        print("Error getting interface index: %s" % e)
        sys.exit(1)

    src_ip_hex = ip_to_hex(args.src_ip)
    dst_ip_hex = ip_to_hex(args.dst_ip)

    rx_indices = [idx for _, idx in rx_ifindexes]
    tx_indices = [idx for _, idx in tx_ifindexes]

    iface_arrays = """
#define RX_IFACE_COUNT %d
#define TX_IFACE_COUNT %d
static const int rx_ifindexes[RX_IFACE_COUNT] = {%s};
static const int tx_ifindexes[TX_IFACE_COUNT] = {%s};
""" % (len(rx_indices), len(tx_indices),
       ', '.join(str(i) for i in rx_indices),
       ', '.join(str(i) for i in tx_indices))

    print("=== TCP Path Tracer ===")
    print("Source IP: %s" % args.src_ip)
    print("Destination IP: %s" % args.dst_ip)
    if args.src_port:
        print("Source Port Filter: %d" % args.src_port)
    if args.dst_port:
        print("Destination Port Filter: %d" % args.dst_port)
    print("RX Interface(s): %s" % ', '.join("%s(ifindex=%d)" % (n, i) for n, i in rx_ifindexes))
    print("TX Interface(s): %s" % ', '.join("%s(ifindex=%d)" % (n, i) for n, i in tx_ifindexes))
    print("Timeout: %d ms" % args.timeout_ms)
    if args.stats_mode:
        print("Mode: Stats (interval=%ds)" % args.stats_interval)
    elif args.verbose:
        print("Mode: Verbose")
    else:
        print("Mode: Default (drops only)")
    print("")
    print("Tracking bidirectional flow:")
    print("  Forward: %s -> %s" % (args.src_ip, args.dst_ip))
    print("  Reply:   %s -> %s" % (args.dst_ip, args.src_ip))
    print("")

    try:
        bpf_code = bpf_text % (src_ip_hex, dst_ip_hex, args.src_port, args.dst_port)
        bpf_code = bpf_code.replace("__IFACE_ARRAYS__", iface_arrays)
        stats_mode_val = "1" if args.stats_mode else "0"
        bpf_code = bpf_code.replace("__STATS_MODE__", stats_mode_val)
        debug_mode_val = "1" if args.debug else "0"
        bpf_code = bpf_code.replace("__DEBUG_MODE__", debug_mode_val)
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    port_filter = args.src_port or args.dst_port
    tracker = GroupTracker(args.timeout_ms, args.rx_iface, args.tx_iface, port_filter)

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        result = tracker.update(event)

        if args.verbose and result:
            action, key, group = result
            sip, dip, sport, dport, seq, direction = key
            dir_str = "FWD" if direction == DIR_FORWARD else "REP"
            ts_str = " ".join(["%s:%s" % (STAGE_NAMES[i],
                "Y" if group["ts"][i] != 0 else "-") for i in range(MAX_STAGES)])
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            port_str = " Port=%d->%d" % (group["sport"], group["dport"])
            payload_str = " Len=%d" % group["payload_len"] if group["payload_len"] else ""
            bpf_ts_rx = group["ts"][0] / 1000 if group["ts"][0] else 0
            bpf_ts_tx = group["ts"][1] / 1000 if group["ts"][1] else 0
            bpf_ts_str = " BPF_TS(us): RX=%.0f TX=%.0f" % (bpf_ts_rx, bpf_ts_tx) if bpf_ts_rx or bpf_ts_tx else ""
            print("%s [%s][%s] seq=%u%s%s%s %s" % (
                now_str, dir_str, action, seq, port_str, payload_str, bpf_ts_str, ts_str))
            if action == "complete":
                lat_internal = (group["ts"][1] - group["ts"][0]) / 1000.0 if group["ts"][0] and group["ts"][1] else 0
                print("  Latency(us): Internal=%.1f" % lat_internal)
                print("-" * 80)

    def aggregate_percpu_stats(direction):
        stats_map = b["stats_map"]
        totals = {
            "rx_packets": 0, "tx_packets": 0, "rx_groups": 0,
            "complete_groups": 0, "total_latency_ns": 0,
            "min_latency_ns": 0, "max_latency_ns": 0,
            "latency_hist": [0] * LATENCY_BUCKETS
        }
        try:
            cpu_stats = stats_map[direction]
            for s in cpu_stats:
                totals["rx_packets"] += s.rx_packets
                totals["tx_packets"] += s.tx_packets
                totals["rx_groups"] += s.rx_groups
                totals["complete_groups"] += s.complete_groups
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
        for key in ["rx_packets", "tx_packets", "rx_groups", "complete_groups"]:
            delta_fwd[key] = stats_fwd[key] - prev_fwd.get(key, 0)
            delta_rep[key] = stats_rep[key] - prev_rep.get(key, 0)

        start_str = datetime.datetime.fromtimestamp(interval_start).strftime("%H:%M:%S")
        end_str = datetime.datetime.fromtimestamp(interval_end).strftime("%H:%M:%S")

        print("\n" + "=" * 70)
        print("=== TCP Stats [%s - %s] ===" % (start_str, end_str))
        print("=" * 70)

        print("\nForward (%s -> %s):" % (args.src_ip, args.dst_ip))
        print("  Packets:   RX=%d  TX=%d" % (delta_fwd["rx_packets"], delta_fwd["tx_packets"]))
        print("  Groups:    New=%d  Complete=%d  InternalDrop=%d" % (
            delta_fwd["rx_groups"], delta_fwd["complete_groups"], drops_fwd))
        if stats_fwd["complete_groups"] > 0:
            avg_lat = stats_fwd["total_latency_ns"] / stats_fwd["complete_groups"] / 1000.0
            min_lat = stats_fwd["min_latency_ns"] / 1000.0
            max_lat = stats_fwd["max_latency_ns"] / 1000.0
            p50 = calculate_percentile(stats_fwd["latency_hist"], 50)
            p99 = calculate_percentile(stats_fwd["latency_hist"], 99)
            print("  Latency(us): Min=%.1f  Avg=%.1f  Max=%.1f  P50=%d  P99=%d" % (
                min_lat, avg_lat, max_lat, p50, p99))

        print("\nReply (%s -> %s):" % (args.dst_ip, args.src_ip))
        print("  Packets:   RX=%d  TX=%d" % (delta_rep["rx_packets"], delta_rep["tx_packets"]))
        print("  Groups:    New=%d  Complete=%d  InternalDrop=%d" % (
            delta_rep["rx_groups"], delta_rep["complete_groups"], drops_rep))
        if stats_rep["complete_groups"] > 0:
            avg_lat = stats_rep["total_latency_ns"] / stats_rep["complete_groups"] / 1000.0
            min_lat = stats_rep["min_latency_ns"] / 1000.0
            max_lat = stats_rep["max_latency_ns"] / 1000.0
            p50 = calculate_percentile(stats_rep["latency_hist"], 50)
            p99 = calculate_percentile(stats_rep["latency_hist"], 99)
            print("  Latency(us): Min=%.1f  Avg=%.1f  Max=%.1f  P50=%d  P99=%d" % (
                min_lat, avg_lat, max_lat, p50, p99))

        print("\nLatency Histogram (Forward):")
        print_histogram(stats_fwd["latency_hist"])
        print("\nLatency Histogram (Reply):")
        print_histogram(stats_rep["latency_hist"])
        print("")

    b["events"].open_perf_buffer(handle_event)

    print("Tracing... Hit Ctrl-C to end.\n")

    if args.stats_mode:
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
            print("Total Internal Drops: Forward=%d  Reply=%d" % (
                scanner.internal_drop_count_fwd, scanner.internal_drop_count_rep))
            if args.debug:
                print_debug_stats(b)
    else:
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
            if args.debug:
                print_debug_stats(b)


if __name__ == "__main__":
    main()
