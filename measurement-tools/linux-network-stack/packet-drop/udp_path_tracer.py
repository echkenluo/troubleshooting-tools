#!/usr/bin/env python
# -*- coding: utf-8 -*-

# UDP Path Tracer - Trace UDP packets through network path for boundary detection
#
# This tool monitors UDP packets at two network interfaces to trace
# packet flow and detect drops in the forwarding path. It uses fragment
# group tracking to handle IP fragmentation scenarios.
#
# Usage:
#   sudo ./udp_path_tracer.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#       --rx-iface eth0 --tx-iface eth1 [--timeout-ms 1000]
#
#   # With port filtering:
#   sudo ./udp_path_tracer.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
#       --rx-iface ens4f0 --tx-iface vnet0 --dst-port 53
#
# Flow tracking (single direction):
#   [0] RX at rx-iface - packet/fragment received
#   [1] TX at tx-iface - packet/fragment sent
#
# Fragment group tracking:
#   - Groups fragments by IP ID (same ID = same datagram)
#   - Tracks first fragment (offset=0, has UDP header)
#   - Tracks last fragment (MF=0)
#   - Reports drops at group level
#
# Drop detection:
#   - Has RX, missing TX: Dropped internally
#   - Partial fragments: Some fragments dropped
#
# Note: UDP is connectionless - deploy on both src and dst hosts
# and merge results offline for end-to-end view.

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

# Force unbuffered stdout for background execution
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define SRC_PORT_FILTER %d
#define DST_PORT_FILTER %d

// Multi-interface support
#define MAX_IFACES 8
__IFACE_ARRAYS__

// Stages for single direction tracking
#define STAGE_RX      0  // Packet received at rx-iface
#define STAGE_TX      1  // Packet sent from tx-iface
#define MAX_STAGES    2

// Stats mode control (replaced at load time)
#define STATS_MODE __STATS_MODE__

// Latency histogram buckets (log2 scale, 0-20)
// 0: 0-1us, 1: 1-2us, 2: 2-4us, ..., 20: >512ms
#define LATENCY_BUCKETS 21

// Stats structure for aggregated metrics
struct stats_t {
    u64 rx_packets;       // Total packets at RX
    u64 tx_packets;       // Total packets at TX
    u64 rx_groups;        // New groups created at RX
    u64 complete_groups;  // Groups with both RX and TX
    u64 latency_hist[LATENCY_BUCKETS];
    u64 total_latency_ns;
    u64 min_latency_ns;
    u64 max_latency_ns;
};

BPF_PERCPU_ARRAY(stats_map, struct stats_t, 1);

// Calculate log2 bucket for latency histogram (manually unrolled for BPF verifier)
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

// IP fragment flags
#define IP_MF_FLAG    0x2000  // More Fragments flag
#define IP_OFFSET_MASK 0x1FFF // Fragment offset mask

// Check if ifindex matches any RX interface
static __always_inline int is_rx_iface(int ifindex) {
    #pragma unroll
    for (int i = 0; i < RX_IFACE_COUNT; i++) {
        if (rx_ifindexes[i] == ifindex)
            return 1;
    }
    return 0;
}

// Check if ifindex matches any TX interface
static __always_inline int is_tx_iface(int ifindex) {
    #pragma unroll
    for (int i = 0; i < TX_IFACE_COUNT; i++) {
        if (tx_ifindexes[i] == ifindex)
            return 1;
    }
    return 0;
}

// UDP fragment group key - identifies a UDP datagram (possibly fragmented)
// Includes ports to reduce IP ID collision risk
struct udp_group_key {
    __be32 sip;           // Source IP
    __be32 dip;           // Destination IP
    __be16 ip_id;         // IP identification (links all fragments)
    __be16 sport;         // Source port (0 if unknown)
    __be16 dport;         // Destination port (0 if unknown)
    __be16 pad;
};

// Secondary key for port lookup (used by non-first fragments)
struct udp_port_lookup_key {
    __be32 sip;
    __be32 dip;
    __be16 ip_id;
    __be16 pad;
};

// Port info for lookup
struct udp_port_info {
    __be16 sport;
    __be16 dport;
    u64 timestamp;        // For expiration
};

// Event data sent to userspace
// Note: Avoid bitfields for kernel 4.19 BPF verifier compatibility
struct event_t {
    struct udp_group_key key;
    u64 ts[MAX_STAGES];

    // Fragment tracking
    u8 frag_count_rx;     // Fragments seen at RX stage
    u8 frag_count_tx;     // Fragments seen at TX stage
    u8 has_first_frag;    // Have we seen offset=0?
    u8 has_last_frag;     // Have we seen MF=0?
    u8 is_fragmented;     // Is this a fragmented datagram?
    u8 reserved;

    // Port info (from first fragment only)
    __be16 sport;
    __be16 dport;

    // Stage info
    u8 stage;
    u8 pad2;

    // Total payload tracked
    u32 total_payload;

    char ifname[16];
};

BPF_TABLE("lru_hash", struct udp_group_key, struct event_t, group_map, 10240);
BPF_TABLE("lru_hash", struct udp_port_lookup_key, struct udp_port_info, port_map, 10240);
BPF_PERF_OUTPUT(events);

// Parse UDP packet info and fill key
// Returns: 1=matched, 0=not matched
// Key fields are filled, ports are stored in evt fields
static __always_inline int parse_udp_packet(struct sk_buff *skb,
    struct udp_group_key *key, u8 *has_first_frag, u8 *has_last_frag,
    u8 *is_fragmented, __be16 *sport_out, __be16 *dport_out, u32 *payload_out)
{
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

    if (ip.protocol != IPPROTO_UDP)
        return 0;

    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;

    // Only track forward direction (src->dst)
    if (actual_sip != SRC_IP_FILTER || actual_dip != DST_IP_FILTER)
        return 0;

    // Check fragmentation
    u16 frag_off_raw = ntohs(ip.frag_off);
    u8 more_frag = (frag_off_raw & IP_MF_FLAG) ? 1 : 0;
    u16 frag_offset = (frag_off_raw & IP_OFFSET_MASK) * 8;

    *is_fragmented = (more_frag || frag_offset) ? 1 : 0;
    *has_first_frag = 0;
    *has_last_frag = 0;
    *sport_out = 0;
    *dport_out = 0;
    *payload_out = 0;

    // Ports for key - may be filled from first fragment or lookup
    __be16 key_sport = 0;
    __be16 key_dport = 0;

    // Port lookup key for secondary map
    struct udp_port_lookup_key port_key = {};
    port_key.sip = actual_sip;
    port_key.dip = actual_dip;
    port_key.ip_id = ip.id;
    port_key.pad = 0;

    // Track first fragment (offset=0)
    if (frag_offset == 0) {
        *has_first_frag = 1;

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

        struct udphdr udp;
        if (bpf_probe_read(&udp, sizeof(udp), head + transport_header_offset) < 0)
            return 0;

        *sport_out = udp.source;
        *dport_out = udp.dest;
        key_sport = udp.source;
        key_dport = udp.dest;

        // Store ports in lookup map for subsequent non-first fragments
        struct udp_port_info pinfo = {};
        pinfo.sport = udp.source;
        pinfo.dport = udp.dest;
        pinfo.timestamp = bpf_ktime_get_ns();
        port_map.update(&port_key, &pinfo);

        // Apply port filters
        if (SRC_PORT_FILTER != 0 && ntohs(udp.source) != SRC_PORT_FILTER)
            return 0;
        if (DST_PORT_FILTER != 0 && ntohs(udp.dest) != DST_PORT_FILTER)
            return 0;
    } else {
        // Non-first fragment - lookup ports
        struct udp_port_info *pinfo = port_map.lookup(&port_key);
        if (pinfo) {
            *sport_out = pinfo->sport;
            *dport_out = pinfo->dport;
            key_sport = pinfo->sport;
            key_dport = pinfo->dport;
        }
    }

    // Track last fragment
    if (!more_frag) {
        *has_last_frag = 1;
    }

    // Calculate payload
    u16 ip_len = ntohs(ip.tot_len);
    u8 ip_ihl = ip.ihl & 0x0F;
    u16 ip_hdr_len = ip_ihl * 4;
    if (ip_len > ip_hdr_len) {
        u32 pl = ip_len - ip_hdr_len;
        if (frag_offset == 0 && pl > 8) {
            pl -= 8;  // Subtract UDP header
        }
        *payload_out = pl;
    }

    // Fill key - all fields at once for verifier
    key->sip = actual_sip;
    key->dip = actual_dip;
    key->ip_id = ip.id;
    key->sport = key_sport;
    key->dport = key_dport;
    key->pad = 0;

    return 1;
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    if (!is_rx_iface(ifindex))
        return 0;

    struct udp_group_key key = {};
    u8 has_first_frag = 0, has_last_frag = 0, is_frag = 0;
    __be16 sport = 0, dport = 0;
    u32 payload = 0;

    if (!parse_udp_packet(skb, &key, &has_first_frag, &has_last_frag,
                          &is_frag, &sport, &dport, &payload))
        return 0;

    u64 ts = bpf_ktime_get_ns();

    // Update stats (always, regardless of mode)
    u32 stats_key = 0;
    struct stats_t *stats = stats_map.lookup(&stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->rx_packets, 1);
    }

    struct event_t *group = group_map.lookup(&key);

    if (!group) {
        // New group
        struct event_t evt = {};
        evt.key = key;
        evt.ts[STAGE_RX] = ts;
        evt.frag_count_rx = 1;
        evt.has_first_frag = has_first_frag;
        evt.has_last_frag = has_last_frag;
        evt.is_fragmented = is_frag;
        evt.sport = sport;
        evt.dport = dport;
        evt.total_payload = payload;
        evt.stage = STAGE_RX;
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

    // Update existing group
    if (group->ts[STAGE_RX] == 0) {
        group->ts[STAGE_RX] = ts;
    }
    group->frag_count_rx++;
    group->stage = STAGE_RX;

    // Merge fragment flags
    if (has_first_frag) {
        group->has_first_frag = 1;
        if (sport != 0) {
            group->sport = sport;
            group->dport = dport;
        }
    }
    if (has_last_frag) {
        group->has_last_frag = 1;
    }
    if (is_frag) {
        group->is_fragmented = 1;
    }
    group->total_payload += payload;

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

    struct udp_group_key key = {};
    u8 has_first_frag = 0, has_last_frag = 0, is_frag = 0;
    __be16 sport = 0, dport = 0;
    u32 payload = 0;

    if (!parse_udp_packet(skb, &key, &has_first_frag, &has_last_frag,
                          &is_frag, &sport, &dport, &payload))
        return 0;

    u64 ts = bpf_ktime_get_ns();

    // Update stats (always, regardless of mode)
    u32 stats_key = 0;
    struct stats_t *stats = stats_map.lookup(&stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->tx_packets, 1);
    }

    struct event_t *group = group_map.lookup(&key);

    if (!group) {
        // TX without RX - shouldn't happen normally, but track anyway
        struct event_t evt = {};
        evt.key = key;
        evt.ts[STAGE_TX] = ts;
        evt.frag_count_tx = 1;
        evt.has_first_frag = has_first_frag;
        evt.has_last_frag = has_last_frag;
        evt.is_fragmented = is_frag;
        evt.sport = sport;
        evt.dport = dport;
        evt.total_payload = payload;
        evt.stage = STAGE_TX;
        bpf_probe_read_str(evt.ifname, sizeof(evt.ifname), dev->name);
        group_map.update(&key, &evt);

#if !STATS_MODE
        events.perf_submit(ctx, &evt, sizeof(evt));
#endif
        return 0;
    }

    // Update existing group
    if (group->ts[STAGE_TX] == 0) {
        group->ts[STAGE_TX] = ts;
    }
    group->frag_count_tx++;
    group->stage = STAGE_TX;

    // Merge fragment flags
    if (has_first_frag) {
        group->has_first_frag = 1;
        if (sport != 0) {
            group->sport = sport;
            group->dport = dport;
        }
    }
    if (has_last_frag) {
        group->has_last_frag = 1;
    }
    if (is_frag) {
        group->is_fragmented = 1;
    }

    bpf_probe_read_str(group->ifname, sizeof(group->ifname), dev->name);

    // Check if complete: for non-fragmented, just need RX+TX; for fragmented, need all frags
    u8 is_complete = 0;
    if (group->ts[STAGE_RX] != 0) {
        if (!group->is_fragmented) {
            // Non-fragmented: complete as soon as we have TX
            is_complete = 1;
        } else {
            // Fragmented: need first+last frag and matching counts
            is_complete = (group->has_first_frag && group->has_last_frag &&
                          group->frag_count_rx == group->frag_count_tx);
        }
    }

    if (is_complete && stats) {
        u64 latency = ts - group->ts[STAGE_RX];
        __sync_fetch_and_add(&stats->complete_groups, 1);
        __sync_fetch_and_add(&stats->total_latency_ns, latency);

        // Update histogram
        u32 bucket = latency_bucket(latency);
        __sync_fetch_and_add(&stats->latency_hist[bucket], 1);

        // Update min/max (approximate, race possible but acceptable)
        if (stats->min_latency_ns == 0 || latency < stats->min_latency_ns) {
            stats->min_latency_ns = latency;
        }
        if (latency > stats->max_latency_ns) {
            stats->max_latency_ns = latency;
        }
    }

#if !STATS_MODE
    // In verbose mode, update map first for perf_submit, then delete
    group_map.update(&key, group);
    events.perf_submit(ctx, group, sizeof(*group));
    if (is_complete) {
        group_map.delete(&key);
    }
#else
    // In stats mode, delete immediately if complete, otherwise update
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
LATENCY_BUCKETS = 21

# Histogram bucket labels (log2 scale)
BUCKET_LABELS = [
    "0-1us", "1-2us", "2-4us", "4-8us", "8-16us",
    "16-32us", "32-64us", "64-128us", "128-256us", "256-512us",
    "512us-1ms", "1-2ms", "2-4ms", "4-8ms", "8-16ms",
    "16-32ms", "32-64ms", "64-128ms", "128-256ms", "256-512ms",
    ">512ms"
]


class Stats(ctypes.Structure):
    _fields_ = [
        ("rx_packets", ctypes.c_uint64),
        ("tx_packets", ctypes.c_uint64),
        ("rx_groups", ctypes.c_uint64),
        ("complete_groups", ctypes.c_uint64),
        ("latency_hist", ctypes.c_uint64 * LATENCY_BUCKETS),
        ("total_latency_ns", ctypes.c_uint64),
        ("min_latency_ns", ctypes.c_uint64),
        ("max_latency_ns", ctypes.c_uint64),
    ]


class UdpGroupKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("ip_id", ctypes.c_uint16),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("pad", ctypes.c_uint16),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("key", UdpGroupKey),
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("frag_count_rx", ctypes.c_uint8),
        ("frag_count_tx", ctypes.c_uint8),
        ("has_first_frag", ctypes.c_uint8),
        ("has_last_frag", ctypes.c_uint8),
        ("is_fragmented", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("stage", ctypes.c_uint8),
        ("pad2", ctypes.c_uint8),
        ("total_payload", ctypes.c_uint32),
        ("ifname", ctypes.c_char * 16),
    ]


def get_if_index(devname):
    """Get the interface index for a device name"""
    SIOCGIFINDEX = 0x8933
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    buf = struct.pack('16s%dx' % (256 - 16), devname.encode('ascii'))
    try:
        res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, buf)
        return struct.unpack('I', res[16:20])[0]
    finally:
        s.close()


def validate_ip(ip_str):
    """Validate IP address format"""
    try:
        socket.inet_aton(ip_str)
        return True
    except socket.error:
        return False


def ip_to_hex(ip_str):
    """Convert IP string to network-ordered hex value"""
    packed_ip = socket.inet_aton(ip_str)
    host_int = struct.unpack("!I", packed_ip)[0]
    return socket.htonl(host_int)


def validate_interfaces(ifaces, max_count=8):
    """Validate interface list"""
    if not ifaces:
        return False, "Interface list is empty"
    if len(ifaces) > max_count:
        return False, "Too many interfaces (max %d)" % max_count
    for iface in ifaces:
        if not iface or not iface.strip():
            return False, "Empty interface name"
    return True, None


def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))


class GroupTracker:
    """Track UDP fragment groups and detect drops"""

    def __init__(self, timeout_ms, rx_iface, tx_iface, port_filter):
        self.groups = OrderedDict()
        self.timeout_ns = timeout_ms * 1000000
        self.rx_iface = rx_iface
        self.tx_iface = tx_iface
        self.port_filter = port_filter
        self.stats = {
            "total_groups": 0,
            "complete_groups": 0,
            "internal_drop": 0,
            "partial_frag_drop": 0,
        }

    def _make_key(self, event):
        return (event.key.sip, event.key.dip, socket.ntohs(event.key.ip_id),
                socket.ntohs(event.key.sport), socket.ntohs(event.key.dport))

    def update(self, event):
        key = self._make_key(event)
        ts_array = [event.ts[i] for i in range(MAX_STAGES)]
        stage = event.stage

        sport = socket.ntohs(event.sport) if event.sport else 0
        dport = socket.ntohs(event.dport) if event.dport else 0

        if key not in self.groups:
            self.groups[key] = {
                "ts": ts_array,
                "first_seen": time.time(),
                "reported": False,
                "frag_count_rx": event.frag_count_rx,
                "frag_count_tx": event.frag_count_tx,
                "has_first_frag": event.has_first_frag,
                "has_last_frag": event.has_last_frag,
                "is_fragmented": event.is_fragmented,
                "sport": sport,
                "dport": dport,
                "total_payload": event.total_payload,
            }
            self.stats["total_groups"] += 1
            return ("new", key, self.groups[key])

        group = self.groups[key]

        # Update timestamps
        for i in range(MAX_STAGES):
            if ts_array[i] != 0 and group["ts"][i] == 0:
                group["ts"][i] = ts_array[i]

        # Update fragment counts
        group["frag_count_rx"] = max(group["frag_count_rx"], event.frag_count_rx)
        group["frag_count_tx"] = max(group["frag_count_tx"], event.frag_count_tx)

        # Update fragment flags
        if event.has_first_frag:
            group["has_first_frag"] = True
            if sport:
                group["sport"] = sport
                group["dport"] = dport
        if event.has_last_frag:
            group["has_last_frag"] = True
        if event.is_fragmented:
            group["is_fragmented"] = True

        group["total_payload"] = max(group["total_payload"], event.total_payload)

        # Check completion
        is_complete = (group["ts"][0] != 0 and group["ts"][1] != 0 and
                      group["has_first_frag"] and group["has_last_frag"] and
                      group["frag_count_rx"] == group["frag_count_tx"])

        if is_complete and not group["reported"]:
            group["reported"] = True
            self.stats["complete_groups"] += 1
            return ("complete", key, group)

        return ("update", key, group)

    def check_timeouts(self):
        """Check for timed-out groups and report drops"""
        now = time.time()
        expired = []

        for key, group in list(self.groups.items()):
            if group["reported"]:
                expired.append(key)
                continue

            age_sec = now - group["first_seen"]
            if age_sec * 1000 < self.timeout_ns / 1000000:
                continue

            # Apply port filter in userspace for groups that have port info
            if self.port_filter and group["sport"] and group["dport"]:
                if self.port_filter not in (group["sport"], group["dport"]):
                    expired.append(key)
                    continue

            drop_type = self._detect_drop(group)
            if drop_type:
                self._report_drop(key, group, drop_type)
            expired.append(key)

        for key in expired:
            del self.groups[key]

    def _detect_drop(self, group):
        """Detect drop type based on group state"""
        has_rx = group["ts"][0] != 0
        has_tx = group["ts"][1] != 0
        rx_count = group["frag_count_rx"]
        tx_count = group["frag_count_tx"]

        if has_rx and not has_tx:
            return "internal"
        if has_rx and has_tx and rx_count != tx_count:
            return "partial_frag"
        if has_rx and has_tx and not (group["has_first_frag"] and group["has_last_frag"]):
            return "partial_frag"
        return None

    def _report_drop(self, key, group, drop_type):
        """Report a detected drop"""
        sip, dip, ip_id, sport, dport = key
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        print("\n=== UDP Drop Detected: %s ===" % now)
        port_info = ""
        if sport and dport:
            port_info = " (Port: %d->%d)" % (sport, dport)
        elif group["sport"] and group["dport"]:
            port_info = " (Port: %d->%d)" % (group["sport"], group["dport"])
        print("Group: %s -> %s IP_ID=%d%s" % (
            format_ip(sip), format_ip(dip), ip_id, port_info))

        if group["is_fragmented"]:
            print("Fragmented: Yes (RX frags=%d, TX frags=%d)" % (
                group["frag_count_rx"], group["frag_count_tx"]))
            print("First fragment: %s, Last fragment: %s" % (
                "Yes" if group["has_first_frag"] else "No",
                "Yes" if group["has_last_frag"] else "No"))
        else:
            print("Fragmented: No")

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
            self.stats["internal_drop"] += 1
        elif drop_type == "partial_frag":
            print("\nDrop Location: PARTIAL FRAGMENT DROP")
            print("  Some fragments dropped between %s and %s" % (
                self.rx_iface, self.tx_iface))
            print("  RX fragments: %d, TX fragments: %d" % (
                group["frag_count_rx"], group["frag_count_tx"]))
            self.stats["partial_frag_drop"] += 1

    def print_stats(self):
        """Print statistics summary"""
        print("\n=== UDP Group Statistics ===")
        print("Total groups tracked: %d" % self.stats["total_groups"])
        print("Complete groups: %d" % self.stats["complete_groups"])
        print("Internal drops: %d" % self.stats["internal_drop"])
        print("Partial fragment drops: %d" % self.stats["partial_frag_drop"])


class BPFMapScanner:
    """Scan BPF group_map to detect internal drops in stats mode"""

    def __init__(self, bpf, timeout_ns):
        self.bpf = bpf
        self.timeout_ns = timeout_ns
        self.pending_groups = {}  # key -> first_seen_time (Python time)
        self.internal_drop_count = 0

    def scan_for_drops(self):
        """Scan BPF group_map and detect internal drops"""
        now = time.time()
        timeout_sec = self.timeout_ns / 1e9
        group_map = self.bpf["group_map"]
        drops_detected = 0
        keys_to_delete = []

        for key, event in group_map.items():
            # Create a hashable key tuple
            key_tuple = (key.sip, key.dip, key.ip_id, key.sport, key.dport)

            has_rx = event.ts[0] != 0
            has_tx = event.ts[1] != 0

            if has_rx and not has_tx:
                # RX seen, TX not seen - potential drop
                if key_tuple not in self.pending_groups:
                    # First time seeing this incomplete entry
                    self.pending_groups[key_tuple] = now
                else:
                    # Check if timeout exceeded
                    age = now - self.pending_groups[key_tuple]
                    if age > timeout_sec:
                        drops_detected += 1
                        self.internal_drop_count += 1
                        keys_to_delete.append(key)
                        del self.pending_groups[key_tuple]
            elif has_rx and has_tx:
                # Complete - remove from pending if exists
                if key_tuple in self.pending_groups:
                    del self.pending_groups[key_tuple]

        # Delete timed-out entries from BPF map
        for key in keys_to_delete:
            try:
                del group_map[key]
            except:
                pass

        # Clean up stale pending entries (entries that disappeared from BPF map)
        current_keys = set()
        for key, _ in group_map.items():
            current_keys.add((key.sip, key.dip, key.ip_id, key.sport, key.dport))

        stale_keys = [k for k in self.pending_groups if k not in current_keys]
        for k in stale_keys:
            del self.pending_groups[k]

        return drops_detected


def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Detect UDP packet drops between two interfaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor UDP between eth0 (RX) and eth1 (TX)
  sudo ./udp_drop_detector.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
      --rx-iface eth0 --tx-iface eth1

  # With port filtering (e.g., DNS traffic)
  sudo ./udp_drop_detector.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --rx-iface ens1f0 --tx-iface ens1f1 --dst-port 53

  # For bond interfaces, specify all slaves
  sudo ./udp_drop_detector.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --rx-iface ens4f0,ens4f1 --tx-iface vnet0

Flow stages (single direction):
  [0] RX: Packet/fragment received at rx-iface
  [1] TX: Packet/fragment sent from tx-iface

Fragment group tracking:
  - Fragments are grouped by IP ID (same ID = same datagram)
  - First fragment (offset=0) contains UDP header with ports
  - Last fragment (MF=0) marks group completion
  - Drop detection at group level, not individual fragment

Note: UDP is connectionless. For bidirectional monitoring,
run separate instances with swapped src-ip/dst-ip.
""")

    parser.add_argument('--src-ip', type=str, required=True,
                        help='Source IP of UDP packets')
    parser.add_argument('--dst-ip', type=str, required=True,
                        help='Destination IP of UDP packets')
    parser.add_argument('--rx-iface', type=str, required=True,
                        help='Interface(s) where packets are received (comma-separated)')
    parser.add_argument('--tx-iface', type=str, required=True,
                        help='Interface(s) where packets are sent (comma-separated)')
    parser.add_argument('--src-port', type=int, default=0,
                        help='Filter by source port (optional)')
    parser.add_argument('--dst-port', type=int, default=0,
                        help='Filter by destination port (optional)')
    parser.add_argument('--timeout-ms', type=int, default=1000,
                        help='Timeout in ms to wait for complete group (default: 1000)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print all group events (mutually exclusive with --stats-mode)')
    parser.add_argument('--stats-mode', action='store_true',
                        help='Stats mode: periodic summary instead of per-packet output')
    parser.add_argument('--stats-interval', type=int, default=10,
                        help='Stats output interval in seconds (default: 10)')

    args = parser.parse_args()

    # Validate mode options
    if args.verbose and args.stats_mode:
        print("Error: --verbose and --stats-mode are mutually exclusive")
        sys.exit(1)

    # Validate IP addresses
    if not validate_ip(args.src_ip):
        print("Error: Invalid source IP address: %s" % args.src_ip)
        sys.exit(1)
    if not validate_ip(args.dst_ip):
        print("Error: Invalid destination IP address: %s" % args.dst_ip)
        sys.exit(1)

    # Parse comma-separated interface lists
    rx_ifaces = [s.strip() for s in args.rx_iface.split(',')]
    tx_ifaces = [s.strip() for s in args.tx_iface.split(',')]

    # Validate interface lists
    valid, err = validate_interfaces(rx_ifaces)
    if not valid:
        print("Error: Invalid RX interface list: %s" % err)
        sys.exit(1)
    valid, err = validate_interfaces(tx_ifaces)
    if not valid:
        print("Error: Invalid TX interface list: %s" % err)
        sys.exit(1)

    # Get interface indices
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

    # Generate BPF interface arrays
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

    print("=== UDP Drop Detector ===")
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
    print("Flow path (single direction %s -> %s):" % (args.src_ip, args.dst_ip))
    print("  [0] RX at %s" % args.rx_iface)
    print("  [1] TX at %s" % args.tx_iface)
    print("")

    try:
        bpf_code = bpf_text % (src_ip_hex, dst_ip_hex, args.src_port, args.dst_port)
        bpf_code = bpf_code.replace("__IFACE_ARRAYS__", iface_arrays)
        # Set stats mode
        stats_mode_val = "1" if args.stats_mode else "0"
        bpf_code = bpf_code.replace("__STATS_MODE__", stats_mode_val)
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
            sip, dip, ip_id, sport, dport = key
            ts_str = " ".join(["%s:%s" % (STAGE_NAMES[i],
                "Y" if group["ts"][i] != 0 else "-") for i in range(MAX_STAGES)])
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            port_str = ""
            if sport and dport:
                port_str = " Port=%d->%d" % (sport, dport)
            elif group["sport"] and group["dport"]:
                port_str = " Port=%d->%d" % (group["sport"], group["dport"])
            frag_str = ""
            if group["is_fragmented"]:
                frag_str = " Frags(rx=%d,tx=%d)" % (
                    group["frag_count_rx"], group["frag_count_tx"])
            # BPF timestamps (nanoseconds since boot, show in microseconds)
            bpf_ts_rx = group["ts"][0] / 1000 if group["ts"][0] else 0
            bpf_ts_tx = group["ts"][1] / 1000 if group["ts"][1] else 0
            bpf_ts_str = " BPF_TS(us): RX=%.0f TX=%.0f" % (bpf_ts_rx, bpf_ts_tx) if bpf_ts_rx or bpf_ts_tx else ""
            # Payload length
            payload_str = " Len=%d" % group["total_payload"] if group["total_payload"] else ""
            print("%s [%s] IP_ID=%d%s%s%s%s %s" % (
                now_str, action, ip_id, port_str, payload_str, frag_str, bpf_ts_str, ts_str))
            if action == "complete":
                lat_internal = (group["ts"][1] - group["ts"][0]) / 1000.0 if group["ts"][0] and group["ts"][1] else 0
                print("  Latency(us): Internal=%.1f" % lat_internal)
                print("-" * 80)

    # Stats mode helper functions
    def aggregate_percpu_stats():
        """Aggregate per-CPU stats into single values"""
        stats_map = b["stats_map"]
        totals = {
            "rx_packets": 0, "tx_packets": 0, "rx_groups": 0,
            "complete_groups": 0, "total_latency_ns": 0,
            "min_latency_ns": 0, "max_latency_ns": 0,
            "latency_hist": [0] * LATENCY_BUCKETS
        }
        for cpu_stats in stats_map.values():
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
        return totals

    def calculate_percentile(hist, percentile):
        """Calculate percentile from histogram"""
        total = sum(hist)
        if total == 0:
            return 0
        target = total * percentile / 100.0
        cumsum = 0
        for i, count in enumerate(hist):
            cumsum += count
            if cumsum >= target:
                # Return upper bound of bucket in us
                return (1 << i) if i > 0 else 1
        return (1 << (LATENCY_BUCKETS - 1))

    def print_histogram(hist):
        """Print latency histogram"""
        max_count = max(hist) if hist else 0
        if max_count == 0:
            print("  (no data)")
            return
        bar_width = 40
        for i, count in enumerate(hist):
            if count > 0:
                bar_len = int(count * bar_width / max_count)
                bar = "*" * bar_len
                print("  %12s: %8d |%s" % (BUCKET_LABELS[i], count, bar))

    def print_stats_summary(stats, prev_stats, interval_start, interval_end, internal_drops=None):
        """Print stats summary for interval"""
        # Calculate deltas
        delta = {}
        for key in ["rx_packets", "tx_packets", "rx_groups", "complete_groups"]:
            delta[key] = stats[key] - prev_stats.get(key, 0)

        # Use provided internal_drops or calculate from tracker
        if internal_drops is None:
            internal_drops = tracker.stats.get("internal_drop", 0) - prev_stats.get("internal_drop_tracker", 0)

        start_str = datetime.datetime.fromtimestamp(interval_start).strftime("%H:%M:%S")
        end_str = datetime.datetime.fromtimestamp(interval_end).strftime("%H:%M:%S")

        print("\n" + "=" * 70)
        print("=== UDP Stats [%s - %s] ===" % (start_str, end_str))
        print("=" * 70)
        print("Packets:   RX=%d  TX=%d" % (delta["rx_packets"], delta["tx_packets"]))
        print("Groups:    New=%d  Complete=%d  InternalDrop=%d" % (
            delta["rx_groups"], delta["complete_groups"], internal_drops))

        # Latency stats
        if stats["complete_groups"] > 0:
            avg_lat = stats["total_latency_ns"] / stats["complete_groups"] / 1000.0
            min_lat = stats["min_latency_ns"] / 1000.0
            max_lat = stats["max_latency_ns"] / 1000.0
            p50 = calculate_percentile(stats["latency_hist"], 50)
            p99 = calculate_percentile(stats["latency_hist"], 99)
            print("Latency(us): Min=%.1f  Avg=%.1f  Max=%.1f  P50=%d  P99=%d" % (
                min_lat, avg_lat, max_lat, p50, p99))

        print("\nLatency Histogram:")
        print_histogram(stats["latency_hist"])
        print("")

    b["events"].open_perf_buffer(handle_event)

    print("Tracing... Hit Ctrl-C to end.\n")

    if args.stats_mode:
        # Stats mode main loop - use BPFMapScanner instead of GroupTracker
        scanner = BPFMapScanner(b, args.timeout_ms * 1000000)
        scan_interval = args.timeout_ms / 1000.0  # scan interval = timeout
        prev_stats = {}
        prev_internal_drops = 0
        interval_start = time.time()
        try:
            while True:
                time.sleep(scan_interval)
                now = time.time()
                # Scan BPF map for internal drops
                scanner.scan_for_drops()

                if now - interval_start >= args.stats_interval:
                    stats = aggregate_percpu_stats()
                    current_internal_drops = scanner.internal_drop_count
                    interval_drops = current_internal_drops - prev_internal_drops
                    stats["internal_drops_interval"] = interval_drops
                    print_stats_summary(stats, prev_stats, interval_start, now, interval_drops)
                    prev_stats = stats.copy()
                    prev_internal_drops = current_internal_drops
                    interval_start = now
        except KeyboardInterrupt:
            print("\nDetaching...")
            # Final stats
            stats = aggregate_percpu_stats()
            stats["internal_drops_interval"] = scanner.internal_drop_count - prev_internal_drops
            print_stats_summary(stats, prev_stats, interval_start, time.time(),
                              scanner.internal_drop_count - prev_internal_drops)
            print("Total Internal Drops: %d" % scanner.internal_drop_count)
    else:
        # Verbose/default mode main loop
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
