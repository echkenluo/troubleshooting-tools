#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TCP Path Tracer - Trace TCP packets through network path for boundary detection
#
# This tool monitors TCP packets at two network interfaces to trace
# packet flow and detect drops in the forwarding path. It tracks
# bidirectional flows using TCP sequence numbers for packet identification.
#
# Usage:
#   sudo ./tcp_path_tracer.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#       --rx-iface eth0 --tx-iface eth1 [--timeout-ms 1000]
#
#   # With port filtering:
#   sudo ./tcp_path_tracer.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
#       --rx-iface ens4f0 --tx-iface vnet0 --src-port 22
#
# Flow tracking:
#   1. Request RX at rx-iface (src->dst)
#   2. Request TX at tx-iface (src->dst)
#   3. Reply RX at tx-iface (dst->src)
#   4. Reply TX at rx-iface (dst->src)
#
# Drop detection:
#   - Has 1, missing 2: Request dropped internally
#   - Has 2, missing 3: External drop (network/peer issue)
#   - Has 3, missing 4: Reply dropped internally
#
# Packet identification:
#   TCP packets are uniquely identified by:
#   {src_ip, dst_ip, src_port, dst_port, expected_ack, payload_len}
#   where expected_ack = seq + payload_len for Request
#   and ack_seq for Reply (matches Request's expected_ack)

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

// Multi-interface support: up to 8 interfaces per direction
#define MAX_IFACES 8
__IFACE_ARRAYS__

#define STAGE_REQ_RX  0  // Request received at rx-iface (src->dst)
#define STAGE_REQ_TX  1  // Request sent from tx-iface (src->dst)
#define STAGE_REP_RX  2  // Reply received at tx-iface (dst->src)
#define STAGE_REP_TX  3  // Reply sent from rx-iface (dst->src)
#define MAX_STAGES    4

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

// TCP flow key - uniquely identifies a TCP packet
// Uses expected_ack for Request/Reply matching:
// - Request: expected_ack = seq + payload_len
// - Reply: lookup using ack_seq (matches Request's expected_ack)
struct tcp_flow_key {
    __be32 sip;           // Source IP (canonical: always SRC_IP_FILTER)
    __be32 dip;           // Destination IP (canonical: always DST_IP_FILTER)
    __be16 sport;         // Source port (canonical order)
    __be16 dport;         // Destination port (canonical order)
    __be32 expected_ack;  // Request: seq+payload_len, Reply: ack_seq
    __be16 payload_len;   // Payload length (for statistics)
    __be16 pad;           // Padding for alignment
};

// Event data sent to userspace
struct event_t {
    struct tcp_flow_key key;
    u64 ts[MAX_STAGES];
    u8 stage;             // Which stage triggered this event
    u8 tcp_flags;         // TCP flags (SYN, ACK, FIN, RST, etc.)
    char ifname[16];
};

BPF_TABLE("lru_hash", struct tcp_flow_key, struct event_t, flow_map, 10240);
BPF_PERF_OUTPUT(events);

// Parse TCP packet and fill flow key
// Returns: 1=request(src->dst), 2=reply(dst->src), 0=not matched
// Uses expected_ack for matching: Request stores seq+payload_len, Reply uses ack_seq
static __always_inline int parse_tcp_packet(struct sk_buff *skb,
    struct tcp_flow_key *key, u8 *tcp_flags_out)
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

    if (ip.protocol != IPPROTO_TCP)
        return 0;

    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    int is_request = 0;
    int is_reply = 0;

    // Check if this is a request (src->dst) or reply (dst->src)
    if (actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER) {
        is_request = 1;
    } else if (actual_sip == DST_IP_FILTER && actual_dip == SRC_IP_FILTER) {
        is_reply = 1;
    } else {
        return 0;
    }

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

    // Extract TCP flags
    *tcp_flags_out = ((u8 *)&tcp)[13];  // Flags byte in TCP header

    // Apply port filters if specified
    __be16 actual_sport = tcp.source;
    __be16 actual_dport = tcp.dest;

    if (is_request) {
        if (SRC_PORT_FILTER != 0 && ntohs(actual_sport) != SRC_PORT_FILTER)
            return 0;
        if (DST_PORT_FILTER != 0 && ntohs(actual_dport) != DST_PORT_FILTER)
            return 0;
    } else {
        // For replies, ports are swapped
        if (SRC_PORT_FILTER != 0 && ntohs(actual_dport) != SRC_PORT_FILTER)
            return 0;
        if (DST_PORT_FILTER != 0 && ntohs(actual_sport) != DST_PORT_FILTER)
            return 0;
    }

    // Calculate payload length
    u16 ip_len = ntohs(ip.tot_len);
    u16 ip_hdr_len = ip_ihl * 4;
    u8 tcp_doff = (tcp.doff >> 4) & 0x0F;
    if (tcp_doff == 0) tcp_doff = tcp.doff & 0x0F;
    u16 tcp_hdr_len = tcp_doff * 4;
    if (tcp_hdr_len < 20) tcp_hdr_len = 20;
    u16 payload_len = 0;
    if (ip_len > ip_hdr_len + tcp_hdr_len) {
        payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
    }

    // Use canonical key (always SRC_IP_FILTER, DST_IP_FILTER order)
    key->sip = SRC_IP_FILTER;
    key->dip = DST_IP_FILTER;

    if (is_request) {
        key->sport = actual_sport;
        key->dport = actual_dport;
        // Request: expected_ack = seq + payload_len + SYN/FIN adjustment
        // SYN and FIN flags each consume one sequence number
        u32 seq_host = ntohl(tcp.seq);
        u32 expected_ack = seq_host + payload_len;
        if (*tcp_flags_out & 0x02) expected_ack += 1;  // SYN consumes 1 seq
        if (*tcp_flags_out & 0x01) expected_ack += 1;  // FIN consumes 1 seq
        key->expected_ack = htonl(expected_ack);
        key->payload_len = htons(payload_len);
    } else {
        // Reply: store ports in canonical order (src->dst perspective)
        key->sport = actual_dport;  // Original source port
        key->dport = actual_sport;  // Original dest port
        // Reply: use ack_seq to match Request's expected_ack
        key->expected_ack = tcp.ack_seq;
        key->payload_len = htons(payload_len);
    }

    key->pad = 0;

    return is_request ? 1 : 2;
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

    struct tcp_flow_key key = {};
    u8 tcp_flags = 0;
    int pkt_type = parse_tcp_packet(skb, &key, &tcp_flags);

    if (pkt_type == 0)
        return 0;

    u8 stage;
    if (pkt_type == 1 && is_rx_iface(ifindex)) {
        stage = STAGE_REQ_RX;
    } else if (pkt_type == 2 && is_tx_iface(ifindex)) {
        stage = STAGE_REP_RX;
    } else {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    struct event_t *flow = flow_map.lookup(&key);

    if (!flow) {
        if (stage != STAGE_REQ_RX)
            return 0;

        struct event_t new_flow = {};
        new_flow.key = key;
        new_flow.ts[stage] = ts;
        new_flow.stage = stage;
        new_flow.tcp_flags = tcp_flags;
        bpf_probe_read_str(new_flow.ifname, sizeof(new_flow.ifname), dev->name);
        flow_map.update(&key, &new_flow);
        events.perf_submit(args, &new_flow, sizeof(new_flow));
        return 0;
    }

    if (flow->ts[stage] != 0)
        return 0;

    flow->ts[stage] = ts;
    flow->stage = stage;
    flow->tcp_flags = tcp_flags;
    bpf_probe_read_str(flow->ifname, sizeof(flow->ifname), dev->name);
    flow_map.update(&key, flow);
    events.perf_submit(args, flow, sizeof(*flow));

    if (stage == STAGE_REP_TX) {
        flow_map.delete(&key);
    }
    return 0;
}

RAW_TRACEPOINT_PROBE(net_dev_xmit) {
    // args: skb, rc, dev, len
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb)
        return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    struct tcp_flow_key key = {};
    u8 tcp_flags = 0;
    int pkt_type = parse_tcp_packet(skb, &key, &tcp_flags);

    if (pkt_type == 0)
        return 0;

    u8 stage;
    if (pkt_type == 1 && is_tx_iface(ifindex)) {
        stage = STAGE_REQ_TX;
    } else if (pkt_type == 2 && is_rx_iface(ifindex)) {
        stage = STAGE_REP_TX;
    } else {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    struct event_t *flow = flow_map.lookup(&key);

    if (!flow)
        return 0;  // TX events require existing flow

    if (flow->ts[stage] != 0)
        return 0;

    flow->ts[stage] = ts;
    flow->stage = stage;
    flow->tcp_flags = tcp_flags;
    bpf_probe_read_str(flow->ifname, sizeof(flow->ifname), dev->name);
    flow_map.update(&key, flow);
    events.perf_submit(ctx, flow, sizeof(*flow));

    if (stage == STAGE_REP_TX) {
        flow_map.delete(&key);
    }
    return 0;
}
"""

MAX_STAGES = 4
STAGE_NAMES = ["ReqRX", "ReqTX", "RepRX", "RepTX"]

# TCP flag bits
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


def format_tcp_flags(flags):
    """Format TCP flags as string"""
    result = []
    if flags & TCP_SYN:
        result.append("SYN")
    if flags & TCP_ACK:
        result.append("ACK")
    if flags & TCP_FIN:
        result.append("FIN")
    if flags & TCP_RST:
        result.append("RST")
    if flags & TCP_PSH:
        result.append("PSH")
    if flags & TCP_URG:
        result.append("URG")
    return ",".join(result) if result else "-"


class TcpFlowKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("expected_ack", ctypes.c_uint32),
        ("payload_len", ctypes.c_uint16),
        ("pad", ctypes.c_uint16),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("key", TcpFlowKey),
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("stage", ctypes.c_uint8),
        ("tcp_flags", ctypes.c_uint8),
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


class FlowTracker:
    """Track TCP flows and detect drops with latency statistics"""

    def __init__(self, timeout_ms, rx_iface, tx_iface, internal_only=False):
        self.flows = OrderedDict()
        self.timeout_ns = timeout_ms * 1000000
        self.rx_iface = rx_iface
        self.tx_iface = tx_iface
        self.internal_only = internal_only
        self.stats = {
            "total_flows": 0,
            "complete_flows": 0,
            "req_internal_drop": 0,
            "external_drop": 0,
            "rep_internal_drop": 0,
        }
        # Latency statistics (in microseconds)
        self.latency_stats = {
            "req_internal": [],    # ReqTX - ReqRX
            "external": [],        # RepRX - ReqTX
            "rep_internal": [],    # RepTX - RepRX
            "total": [],           # RepTX - ReqRX
        }

    def _make_key(self, event):
        return (event.key.sip, event.key.dip,
                socket.ntohs(event.key.sport), socket.ntohs(event.key.dport),
                socket.ntohl(event.key.expected_ack), socket.ntohs(event.key.payload_len))

    def update(self, event):
        key = self._make_key(event)
        ts_array = [event.ts[i] for i in range(MAX_STAGES)]
        stage = event.stage

        if key not in self.flows:
            if stage != 0:
                return None
            self.flows[key] = {
                "ts": ts_array,
                "first_seen": time.time(),
                "reported": False,
                "tcp_flags": event.tcp_flags,
            }
            self.stats["total_flows"] += 1
            return ("new", key, ts_array, event.tcp_flags)

        flow = self.flows[key]
        for i in range(MAX_STAGES):
            if ts_array[i] != 0 and flow["ts"][i] == 0:
                flow["ts"][i] = ts_array[i]

        # In internal-only mode, complete when ReqTX is done
        if self.internal_only and stage == 1 and not flow["reported"]:
            flow["reported"] = True
            self.stats["complete_flows"] += 1
            ts = flow["ts"]
            if ts[0] and ts[1]:
                self.latency_stats["req_internal"].append((ts[1] - ts[0]) / 1000.0)
            return ("complete", key, flow["ts"], event.tcp_flags)

        # Normal mode: complete when RepTX (stage 3) is done
        if not self.internal_only and stage == 3 and not flow["reported"]:
            flow["reported"] = True
            self.stats["complete_flows"] += 1
            # Collect latency statistics
            ts = flow["ts"]
            if ts[0] and ts[1]:
                self.latency_stats["req_internal"].append((ts[1] - ts[0]) / 1000.0)
            if ts[1] and ts[2]:
                self.latency_stats["external"].append((ts[2] - ts[1]) / 1000.0)
            if ts[2] and ts[3]:
                self.latency_stats["rep_internal"].append((ts[3] - ts[2]) / 1000.0)
            if ts[0] and ts[3]:
                self.latency_stats["total"].append((ts[3] - ts[0]) / 1000.0)
            return ("complete", key, flow["ts"], event.tcp_flags)

        return ("update", key, flow["ts"], event.tcp_flags)

    def check_timeouts(self):
        """Check for timed-out flows and report drops"""
        now = time.time()
        expired = []

        for key, flow in list(self.flows.items()):
            if flow["reported"]:
                expired.append(key)
                continue

            age_sec = now - flow["first_seen"]
            if age_sec * 1000 < self.timeout_ns / 1000000:
                continue

            ts = flow["ts"]
            drop_type = self._detect_drop(ts)
            if drop_type:
                self._report_drop(key, ts, drop_type, flow.get("tcp_flags", 0))
            expired.append(key)

        for key in expired:
            del self.flows[key]

    def _detect_drop(self, ts):
        """Detect drop type based on timestamps"""
        has_req_rx = ts[0] != 0
        has_req_tx = ts[1] != 0
        has_rep_rx = ts[2] != 0
        has_rep_tx = ts[3] != 0

        if has_req_rx and not has_req_tx:
            return "req_internal"

        # In internal-only mode, don't report external or reply drops
        if self.internal_only:
            return None

        if has_req_tx and not has_rep_rx:
            return "external"
        if has_rep_rx and not has_rep_tx:
            return "rep_internal"
        return None

    def _report_drop(self, key, ts, drop_type, tcp_flags):
        """Report a detected drop"""
        sip, dip, sport, dport, expected_ack, payload_len = key
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # For external drops, collect internal latency if available
        if drop_type == "external" and ts[0] and ts[1]:
            lat = (ts[1] - ts[0]) / 1000.0
            self.latency_stats["req_internal"].append(lat)

        print("\n=== TCP Drop Detected: %s ===" % now)
        print("Flow: %s:%d -> %s:%d (ExpectedACK=%u, PayloadLen=%d, Flags=%s)" % (
            format_ip(sip), sport, format_ip(dip), dport,
            expected_ack, payload_len, format_tcp_flags(tcp_flags)))

        stage_info = []
        for i, name in enumerate(STAGE_NAMES):
            if ts[i] != 0:
                stage_info.append("  [%d] %s: recorded" % (i, name))
            else:
                stage_info.append("  [%d] %s: MISSING" % (i, name))
        print("\n".join(stage_info))

        if drop_type == "req_internal":
            print("\nDrop Location: Request dropped INTERNALLY")
            print("  Request received at %s but NOT sent from %s" % (
                self.rx_iface, self.tx_iface))
            self.stats["req_internal_drop"] += 1
        elif drop_type == "external":
            print("\nDrop Location: EXTERNAL (network or peer)")
            print("  Request sent from %s but Reply NOT received at %s" % (
                self.tx_iface, self.tx_iface))
            if ts[0] and ts[1]:
                lat = (ts[1] - ts[0]) / 1000.0
                print("  Internal forwarding latency: %.1f us" % lat)
            print("  Note: For bulk TCP, Reply ACK may confirm multiple packets")
            self.stats["external_drop"] += 1
        elif drop_type == "rep_internal":
            print("\nDrop Location: Reply dropped INTERNALLY")
            print("  Reply received at %s but NOT sent from %s" % (
                self.tx_iface, self.rx_iface))
            self.stats["rep_internal_drop"] += 1

    def print_stats(self):
        """Print statistics summary"""
        print("\n=== TCP Flow Statistics ===")
        print("Total flows tracked: %d" % self.stats["total_flows"])
        print("Complete flows: %d" % self.stats["complete_flows"])
        print("Request internal drops: %d" % self.stats["req_internal_drop"])
        print("External drops: %d" % self.stats["external_drop"])
        print("Reply internal drops: %d" % self.stats["rep_internal_drop"])

        # Print latency statistics
        print("\n=== Latency Statistics ===")
        lat_names = [
            ("req_internal", "Request Internal"),
            ("external", "External        "),
            ("rep_internal", "Reply Internal  "),
            ("total", "Total RTT       "),
        ]
        for key, name in lat_names:
            samples = self.latency_stats[key]
            if samples:
                min_lat = min(samples)
                max_lat = max(samples)
                avg_lat = sum(samples) / len(samples)
                print("%s (%d samples): min=%.1f avg=%.1f max=%.1f us" % (
                    name, len(samples), min_lat, avg_lat, max_lat))
            else:
                print("%s: no samples" % name)


def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Detect TCP packet drops between two interfaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor TCP between eth0 (RX) and eth1 (TX)
  sudo ./tcp_drop_detector.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
      --rx-iface eth0 --tx-iface eth1

  # With port filtering (e.g., SSH traffic)
  sudo ./tcp_drop_detector.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --rx-iface ens1f0 --tx-iface ens1f1 --dst-port 22

  # For bond interfaces, specify all slaves
  sudo ./tcp_drop_detector.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --rx-iface ens4f0,ens4f1 --tx-iface vnet0

Flow stages:
  [0] ReqRX: Request received at rx-iface (src->dst)
  [1] ReqTX: Request sent from tx-iface (src->dst)
  [2] RepRX: Reply received at tx-iface (dst->src)
  [3] RepTX: Reply sent from rx-iface (dst->src)

Packet identification:
  TCP packets are uniquely identified by:
  {src_ip, dst_ip, src_port, dst_port, expected_ack, payload_len}
  where expected_ack = seq + payload_len (Request) or ack_seq (Reply)
""")

    parser.add_argument('--src-ip', type=str, required=True,
                        help='Source IP of TCP request')
    parser.add_argument('--dst-ip', type=str, required=True,
                        help='Destination IP of TCP request')
    parser.add_argument('--rx-iface', type=str, required=True,
                        help='Interface(s) where request is received (comma-separated)')
    parser.add_argument('--tx-iface', type=str, required=True,
                        help='Interface(s) where request is sent (comma-separated)')
    parser.add_argument('--src-port', type=int, default=0,
                        help='Filter by source port (optional)')
    parser.add_argument('--dst-port', type=int, default=0,
                        help='Filter by destination port (optional)')
    parser.add_argument('--timeout-ms', type=int, default=1000,
                        help='Timeout in ms to wait for complete flow (default: 1000)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print all flow events')
    parser.add_argument('--internal-only', action='store_true',
                        help='Only track internal latency (ReqRX->ReqTX), skip Reply tracking. '
                             'Use this for bulk TCP traffic where ACK matching is unreliable.')

    args = parser.parse_args()

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

    print("=== TCP Drop Detector ===")
    print("Source IP: %s" % args.src_ip)
    print("Destination IP: %s" % args.dst_ip)
    if args.src_port:
        print("Source Port Filter: %d" % args.src_port)
    if args.dst_port:
        print("Destination Port Filter: %d" % args.dst_port)
    print("RX Interface(s): %s" % ', '.join("%s(ifindex=%d)" % (n, i) for n, i in rx_ifindexes))
    print("TX Interface(s): %s" % ', '.join("%s(ifindex=%d)" % (n, i) for n, i in tx_ifindexes))
    print("Timeout: %d ms" % args.timeout_ms)
    if args.internal_only:
        print("Mode: Internal-only (track ReqRX->ReqTX, skip Reply)")
    else:
        print("Mode: Bidirectional (track full Request/Reply path)")
    print("")
    print("Flow path:")
    print("  [0] Request RX at %s" % args.rx_iface)
    print("  [1] Request TX at %s" % args.tx_iface)
    if not args.internal_only:
        print("  [2] Reply RX at %s" % args.tx_iface)
        print("  [3] Reply TX at %s" % args.rx_iface)
    print("")

    try:
        bpf_code = bpf_text % (src_ip_hex, dst_ip_hex, args.src_port, args.dst_port)
        bpf_code = bpf_code.replace("__IFACE_ARRAYS__", iface_arrays)
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    tracker = FlowTracker(args.timeout_ms, args.rx_iface, args.tx_iface, args.internal_only)

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        result = tracker.update(event)

        if args.verbose and result:
            action, key, ts, tcp_flags = result
            sip, dip, sport, dport, expected_ack, payload_len = key
            ts_str = " ".join(["%s:%s" % (STAGE_NAMES[i],
                "Y" if ts[i] != 0 else "-") for i in range(MAX_STAGES)])
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print("%s [%s] %s:%d->%s:%d ExpACK=%u Len=%d Flags=%s %s" % (
                now_str, action, format_ip(sip), sport, format_ip(dip), dport,
                expected_ack, payload_len, format_tcp_flags(tcp_flags), ts_str))
            if action == "complete":
                lat_req_internal = (ts[1] - ts[0]) / 1000.0 if ts[0] and ts[1] else 0
                if args.internal_only:
                    print("  Latency(us): Internal=%.1f" % lat_req_internal)
                else:
                    lat_external = (ts[2] - ts[1]) / 1000.0 if ts[1] and ts[2] else 0
                    lat_rep_internal = (ts[3] - ts[2]) / 1000.0 if ts[2] and ts[3] else 0
                    lat_total = (ts[3] - ts[0]) / 1000.0 if ts[0] and ts[3] else 0
                    print("  Latency(us): ReqInternal=%.1f  External=%.1f  RepInternal=%.1f  Total=%.1f" % (
                        lat_req_internal, lat_external, lat_rep_internal, lat_total))
                print("-" * 80)

    b["events"].open_perf_buffer(handle_event)

    print("Tracing... Hit Ctrl-C to end.\n")

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
