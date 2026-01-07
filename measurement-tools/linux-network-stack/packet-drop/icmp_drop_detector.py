#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ICMP Drop Detector - Detect ICMP packet drops between two interfaces
#
# This tool monitors ICMP request/reply packets at two network interfaces
# to detect packet drops in the forwarding path.
#
# Usage:
#   sudo ./icmp_drop_detector.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#       --rx-iface eth0 --tx-iface eth1 [--timeout-ms 1000]
#
#   # For bond interfaces, specify all slaves:
#   sudo ./icmp_drop_detector.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \
#       --rx-iface ens4f0,ens4f1 --tx-iface vnet0
#
# Flow tracking:
#   1. Request RX at rx-iface (src->dst, type=8)
#   2. Request TX at tx-iface (src->dst, type=8)
#   3. Reply RX at tx-iface (dst->src, type=0)
#   4. Reply TX at rx-iface (dst->src, type=0)
#
# Drop detection:
#   - Has 1, missing 2: Request dropped internally
#   - Has 2, missing 3: External drop (network/peer issue)
#   - Has 3, missing 4: Reply dropped internally

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
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x

// Multi-interface support: up to 8 interfaces per direction
#define MAX_IFACES 8
__IFACE_ARRAYS__

#define STAGE_REQ_RX  0  // Request received at rx-iface
#define STAGE_REQ_TX  1  // Request sent from tx-iface
#define STAGE_REP_RX  2  // Reply received at tx-iface
#define STAGE_REP_TX  3  // Reply sent from rx-iface
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

// ICMP flow key - uniquely identifies a ping session
struct icmp_flow_key {
    __be32 sip;   // Always SRC_IP_FILTER (canonical)
    __be32 dip;   // Always DST_IP_FILTER (canonical)
    __be16 id;
    __be16 seq;
};

// Event data sent to userspace
struct event_t {
    struct icmp_flow_key key;
    u64 ts[MAX_STAGES];
    u8 stage;           // Which stage triggered this event
    u8 icmp_type;
    char ifname[16];
};

BPF_TABLE("lru_hash", struct icmp_flow_key, struct event_t, flow_map, 10240);
BPF_PERF_OUTPUT(events);

// Parse ICMP packet and fill flow key
// Returns: 1=request(type8), 2=reply(type0), 0=not matched
static __always_inline int parse_icmp_packet(struct sk_buff *skb,
    struct icmp_flow_key *key, u8 *icmp_type_out)
{
    unsigned char *head;
    u16 network_header_offset;
    u16 transport_header_offset;

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

    if (ip.protocol != IPPROTO_ICMP)
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

    if (bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset),
            &skb->transport_header) < 0)
        return 0;

    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U ||
        transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    struct icmphdr icmph;
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset) < 0)
        return 0;

    *icmp_type_out = icmph.type;

    // Validate ICMP type matches direction
    if (is_request && icmph.type != 8)  // ICMP_ECHO
        return 0;
    if (is_reply && icmph.type != 0)    // ICMP_ECHOREPLY
        return 0;

    // Use canonical key (always src_ip, dst_ip order)
    key->sip = SRC_IP_FILTER;
    key->dip = DST_IP_FILTER;
    key->id = icmph.un.echo.id;
    key->seq = icmph.un.echo.sequence;

    return is_request ? 1 : 2;
}

static __always_inline void record_event(struct pt_regs *ctx,
    struct sk_buff *skb, u8 stage)
{
    struct net_device *dev;
    int ifindex = 0;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return;

    // Check interface match based on stage
    int match = 0;
    if (stage == STAGE_REQ_RX || stage == STAGE_REP_TX) {
        match = is_rx_iface(ifindex);
    } else {
        match = is_tx_iface(ifindex);
    }

    if (!match)
        return;

    struct icmp_flow_key key = {};
    u8 icmp_type = 0;
    int pkt_type = parse_icmp_packet(skb, &key, &icmp_type);

    if (pkt_type == 0)
        return;

    // Validate packet type matches stage
    if ((stage == STAGE_REQ_RX || stage == STAGE_REQ_TX) && pkt_type != 1)
        return;
    if ((stage == STAGE_REP_RX || stage == STAGE_REP_TX) && pkt_type != 2)
        return;

    u64 ts = bpf_ktime_get_ns();
    struct event_t *flow = flow_map.lookup(&key);

    if (!flow) {
        if (stage != STAGE_REQ_RX)
            return;  // First event must be request RX

        struct event_t new_flow = {};
        new_flow.key = key;
        new_flow.ts[stage] = ts;
        new_flow.stage = stage;
        new_flow.icmp_type = icmp_type;
        bpf_probe_read_kernel_str(new_flow.ifname, sizeof(new_flow.ifname), dev->name);
        flow_map.update(&key, &new_flow);

        events.perf_submit(ctx, &new_flow, sizeof(new_flow));
        return;
    }

    if (flow->ts[stage] != 0)
        return;  // Already recorded this stage

    flow->ts[stage] = ts;
    flow->stage = stage;
    flow->icmp_type = icmp_type;
    bpf_probe_read_kernel_str(flow->ifname, sizeof(flow->ifname), dev->name);
    flow_map.update(&key, flow);

    events.perf_submit(ctx, flow, sizeof(*flow));

    // Clean up completed flows
    if (stage == STAGE_REP_TX) {
        flow_map.delete(&key);
    }
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    struct icmp_flow_key key = {};
    u8 icmp_type = 0;
    int pkt_type = parse_icmp_packet(skb, &key, &icmp_type);

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
        new_flow.icmp_type = icmp_type;
        bpf_probe_read_kernel_str(new_flow.ifname, sizeof(new_flow.ifname), dev->name);
        flow_map.update(&key, &new_flow);
        events.perf_submit(args, &new_flow, sizeof(new_flow));
        return 0;
    }

    if (flow->ts[stage] != 0)
        return 0;

    flow->ts[stage] = ts;
    flow->stage = stage;
    flow->icmp_type = icmp_type;
    bpf_probe_read_kernel_str(flow->ifname, sizeof(flow->ifname), dev->name);
    flow_map.update(&key, flow);
    events.perf_submit(args, flow, sizeof(*flow));

    if (stage == STAGE_REP_TX) {
        flow_map.delete(&key);
    }
    return 0;
}

int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!skb)
        return 0;

    struct net_device *dev;
    int ifindex = 0;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    struct icmp_flow_key key = {};
    u8 icmp_type = 0;
    int pkt_type = parse_icmp_packet(skb, &key, &icmp_type);

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
    flow->icmp_type = icmp_type;
    bpf_probe_read_kernel_str(flow->ifname, sizeof(flow->ifname), dev->name);
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

class IcmpFlowKey(ctypes.Structure):
    _fields_ = [
        ("sip", ctypes.c_uint32),
        ("dip", ctypes.c_uint32),
        ("id", ctypes.c_uint16),
        ("seq", ctypes.c_uint16),
    ]

class Event(ctypes.Structure):
    _fields_ = [
        ("key", IcmpFlowKey),
        ("ts", ctypes.c_uint64 * MAX_STAGES),
        ("stage", ctypes.c_uint8),
        ("icmp_type", ctypes.c_uint8),
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


def ip_to_hex(ip_str):
    """Convert IP string to network-ordered hex value"""
    packed_ip = socket.inet_aton(ip_str)
    host_int = struct.unpack("!I", packed_ip)[0]
    return socket.htonl(host_int)


def format_ip(addr):
    """Format integer IP address to string"""
    return socket.inet_ntop(socket.AF_INET, struct.pack("=I", addr))


class FlowTracker:
    """Track ICMP flows and detect drops"""

    def __init__(self, timeout_ms, rx_iface, tx_iface):
        self.flows = OrderedDict()
        self.timeout_ns = timeout_ms * 1000000
        self.rx_iface = rx_iface
        self.tx_iface = tx_iface
        self.stats = {
            "total_flows": 0,
            "complete_flows": 0,
            "req_internal_drop": 0,
            "external_drop": 0,
            "rep_internal_drop": 0,
        }

    def _make_key(self, event):
        return (event.key.sip, event.key.dip,
                socket.ntohs(event.key.id), socket.ntohs(event.key.seq))

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
            }
            self.stats["total_flows"] += 1
            return ("new", key, ts_array)

        flow = self.flows[key]
        for i in range(MAX_STAGES):
            if ts_array[i] != 0 and flow["ts"][i] == 0:
                flow["ts"][i] = ts_array[i]

        if stage == 3 and not flow["reported"]:
            flow["reported"] = True
            self.stats["complete_flows"] += 1
            return ("complete", key, flow["ts"])

        return ("update", key, flow["ts"])

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
                self._report_drop(key, ts, drop_type)
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
        if has_req_tx and not has_rep_rx:
            return "external"
        if has_rep_rx and not has_rep_tx:
            return "rep_internal"
        return None

    def _report_drop(self, key, ts, drop_type):
        """Report a detected drop"""
        sip, dip, icmp_id, seq = key
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        print("\n=== ICMP Drop Detected: %s ===" % now)
        print("Flow: %s -> %s (ID=%d, Seq=%d)" % (
            format_ip(sip), format_ip(dip), icmp_id, seq))

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
            self.stats["external_drop"] += 1
        elif drop_type == "rep_internal":
            print("\nDrop Location: Reply dropped INTERNALLY")
            print("  Reply received at %s but NOT sent from %s" % (
                self.tx_iface, self.rx_iface))
            self.stats["rep_internal_drop"] += 1

    def print_stats(self):
        """Print statistics summary"""
        print("\n=== ICMP Flow Statistics ===")
        print("Total flows tracked: %d" % self.stats["total_flows"])
        print("Complete flows: %d" % self.stats["complete_flows"])
        print("Request internal drops: %d" % self.stats["req_internal_drop"])
        print("External drops: %d" % self.stats["external_drop"])
        print("Reply internal drops: %d" % self.stats["rep_internal_drop"])


def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Detect ICMP packet drops between two interfaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor ICMP between eth0 (RX) and eth1 (TX)
  sudo ./icmp_drop_detector.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \\
      --rx-iface eth0 --tx-iface eth1

  # With custom timeout
  sudo ./icmp_drop_detector.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --rx-iface ens1f0 --tx-iface ens1f1 --timeout-ms 2000

  # For bond interfaces, specify all slaves (LACP/802.3ad)
  sudo ./icmp_drop_detector.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --rx-iface ens4f0,ens4f1 --tx-iface vnet0

Flow stages:
  [0] ReqRX: Request received at rx-iface
  [1] ReqTX: Request sent from tx-iface
  [2] RepRX: Reply received at tx-iface
  [3] RepTX: Reply sent from rx-iface
""")

    parser.add_argument('--src-ip', type=str, required=True,
                        help='Source IP of ICMP request')
    parser.add_argument('--dst-ip', type=str, required=True,
                        help='Destination IP of ICMP request')
    parser.add_argument('--rx-iface', type=str, required=True,
                        help='Interface(s) where request is received (comma-separated for bond slaves)')
    parser.add_argument('--tx-iface', type=str, required=True,
                        help='Interface(s) where request is sent (comma-separated for bond slaves)')
    parser.add_argument('--timeout-ms', type=int, default=1000,
                        help='Timeout in ms to wait for complete flow (default: 1000)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print all flow events')

    args = parser.parse_args()

    # Parse comma-separated interface lists
    rx_ifaces = [s.strip() for s in args.rx_iface.split(',')]
    tx_ifaces = [s.strip() for s in args.tx_iface.split(',')]

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

    print("=== ICMP Drop Detector ===")
    print("Source IP: %s" % args.src_ip)
    print("Destination IP: %s" % args.dst_ip)
    print("RX Interface(s): %s" % ', '.join("%s(ifindex=%d)" % (n, i) for n, i in rx_ifindexes))
    print("TX Interface(s): %s" % ', '.join("%s(ifindex=%d)" % (n, i) for n, i in tx_ifindexes))
    print("Timeout: %d ms" % args.timeout_ms)
    print("")
    print("Flow path:")
    print("  [0] Request RX at %s" % args.rx_iface)
    print("  [1] Request TX at %s" % args.tx_iface)
    print("  [2] Reply RX at %s" % args.tx_iface)
    print("  [3] Reply TX at %s" % args.rx_iface)
    print("")

    try:
        bpf_code = bpf_text % (src_ip_hex, dst_ip_hex)
        bpf_code = bpf_code.replace("__IFACE_ARRAYS__", iface_arrays)
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    tracker = FlowTracker(args.timeout_ms, args.rx_iface, args.tx_iface)

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents
        result = tracker.update(event)

        if args.verbose and result:
            action, key, ts = result
            sip, dip, icmp_id, seq = key
            ts_str = " ".join(["%s:%s" % (STAGE_NAMES[i],
                "Y" if ts[i] != 0 else "-") for i in range(MAX_STAGES)])
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            print("%s [%s] ID=%d Seq=%d %s" % (now_str, action, icmp_id, seq, ts_str))
            if action == "complete":
                # Calculate latencies (nanoseconds to microseconds)
                lat_req_internal = (ts[1] - ts[0]) / 1000.0 if ts[0] and ts[1] else 0
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
