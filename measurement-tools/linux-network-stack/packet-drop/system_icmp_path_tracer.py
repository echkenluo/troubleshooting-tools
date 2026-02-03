#!/usr/bin/env python
# -*- coding: utf-8 -*-

# System Network ICMP Path Tracer - Detect ICMP drops between phy NIC and protocol stack
#
# For system network (host-endpoint) scenarios where the host is the ICMP target.
# Monitors packets at physical interface and protocol stack endpoints to detect
# internal drops in the OVS + protocol stack path.
#
# Usage:
#   sudo ./system_icmp_path_tracer.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
#       --phy-iface enp24s0f0np0 [--timeout-ms 1000]
#
# Stages (4 stages):
#   [0] Request RX @ phy interface  (netif_receive_skb)
#   [1] Request delivered to stack   (icmp_rcv)
#   [2] Reply sent by stack          (ip_send_skb)
#   [3] Reply TX @ phy interface     (net_dev_xmit)
#
# Drop detection:
#   - Has 0, missing 1: Request dropped internally (OVS or stack)
#   - Has 1, missing 2: Protocol stack did not generate reply
#   - Has 2, missing 3: Reply dropped internally (stack or OVS)
#   - Has 0+1, missing 2+3: Remote did not reply (external issue)

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
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x

#define MAX_IFACES 8
__IFACE_ARRAYS__

#define STAGE_REQ_RX    0  // Request received at phy interface
#define STAGE_REQ_STACK 1  // Request delivered to icmp_rcv
#define STAGE_REP_STACK 2  // Reply sent by ip_send_skb
#define STAGE_REP_TX    3  // Reply transmitted at phy interface
#define MAX_STAGES      4

struct icmp_flow_key {
    __be32 sip;
    __be32 dip;
    __be16 id;
    __be16 seq;
};

struct event_t {
    struct icmp_flow_key key;
    u64 ts[MAX_STAGES];
    u8 stage;
    u8 icmp_type;
    char ifname[16];
};

BPF_TABLE("lru_hash", struct icmp_flow_key, struct event_t, flow_map, 10240);
BPF_PERF_OUTPUT(events);

static __always_inline int is_phy_iface(int ifindex) {
    #pragma unroll
    for (int i = 0; i < PHY_IFACE_COUNT; i++) {
        if (phy_ifindexes[i] == ifindex)
            return 1;
    }
    return 0;
}

// Parse ICMP from skb using network_header offset (standard kernel path)
// Returns: 1=echo request(type 8), 2=echo reply(type 0), 0=not matched
static __always_inline int parse_icmp_skb(struct sk_buff *skb,
    struct icmp_flow_key *key, u8 *icmp_type_out)
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
    if (ip.protocol != IPPROTO_ICMP)
        return 0;

    __be32 actual_sip = ip.saddr;
    __be32 actual_dip = ip.daddr;
    int is_request = 0;
    int is_reply = 0;

    if (actual_sip == SRC_IP_FILTER && actual_dip == DST_IP_FILTER)
        is_request = 1;
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

    struct icmphdr icmph;
    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), head + transport_header_offset) < 0)
        return 0;

    *icmp_type_out = icmph.type;

    if (is_request && icmph.type != 8)
        return 0;
    if (is_reply && icmph.type != 0)
        return 0;

    // Canonical key: always use SRC_IP_FILTER, DST_IP_FILTER
    key->sip = SRC_IP_FILTER;
    key->dip = DST_IP_FILTER;
    key->id = icmph.un.echo.id;
    key->seq = icmph.un.echo.sequence;

    return is_request ? 1 : 2;
}

static __always_inline void record_stage(void *ctx, struct icmp_flow_key *key,
    u8 stage, u8 icmp_type, const char *ifname)
{
    u64 ts = bpf_ktime_get_ns();
    struct event_t *flow = flow_map.lookup(key);

    if (!flow) {
        if (stage != STAGE_REQ_RX)
            return;
        struct event_t new_flow = {};
        new_flow.key = *key;
        new_flow.ts[stage] = ts;
        new_flow.stage = stage;
        new_flow.icmp_type = icmp_type;
        if (ifname)
            bpf_probe_read_kernel_str(new_flow.ifname, sizeof(new_flow.ifname), ifname);
        flow_map.update(key, &new_flow);
        events.perf_submit(ctx, &new_flow, sizeof(new_flow));
        return;
    }

    if (flow->ts[stage] != 0)
        return;

    flow->ts[stage] = ts;
    flow->stage = stage;
    flow->icmp_type = icmp_type;
    if (ifname)
        bpf_probe_read_kernel_str(flow->ifname, sizeof(flow->ifname), ifname);
    flow_map.update(key, flow);
    events.perf_submit(ctx, flow, sizeof(*flow));

    if (stage == STAGE_REP_TX) {
        flow_map.delete(key);
    }
}

// Stage 0: Request RX at phy interface (netif_receive_skb)
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

    struct icmp_flow_key key = {};
    u8 icmp_type = 0;
    int pkt_type = parse_icmp_skb(skb, &key, &icmp_type);

    // Only track requests at phy RX (stage 0)
    if (pkt_type != 1)
        return 0;

    record_stage(args, &key, STAGE_REQ_RX, icmp_type, dev->name);
    return 0;
}

// Stage 1: Request delivered to protocol stack (icmp_rcv)
int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct icmp_flow_key key = {};
    u8 icmp_type = 0;
    int pkt_type = parse_icmp_skb(skb, &key, &icmp_type);

    // Only track requests at icmp_rcv (stage 1)
    if (pkt_type != 1)
        return 0;

    record_stage(ctx, &key, STAGE_REQ_STACK, icmp_type, NULL);
    return 0;
}

// Stage 2: Reply sent by protocol stack (ip_send_skb)
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net,
    struct sk_buff *skb)
{
    struct icmp_flow_key key = {};
    u8 icmp_type = 0;
    int pkt_type = parse_icmp_skb(skb, &key, &icmp_type);

    // Only track replies at ip_send_skb (stage 2)
    if (pkt_type != 2)
        return 0;

    record_stage(ctx, &key, STAGE_REP_STACK, icmp_type, NULL);
    return 0;
}

// Stage 3: Reply TX at phy interface (net_dev_xmit)
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

    struct icmp_flow_key key = {};
    u8 icmp_type = 0;
    int pkt_type = parse_icmp_skb(skb, &key, &icmp_type);

    // Only track replies at phy TX (stage 3)
    if (pkt_type != 2)
        return 0;

    record_stage(ctx, &key, STAGE_REP_TX, icmp_type, dev->name);
    return 0;
}
"""

MAX_STAGES = 4
STAGE_NAMES = ["ReqRX@phy", "ReqRcv@stack", "RepSnd@stack", "RepTX@phy"]


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
            "total_flows": 0,
            "complete_flows": 0,
            "req_internal_drop": 0,
            "stack_no_reply": 0,
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
        now = time.time()
        expired = []

        for key, flow in list(self.flows.items()):
            if flow["reported"]:
                expired.append(key)
                continue

            age_ms = (now - flow["first_seen"]) * 1000
            if age_ms < self.timeout_ms:
                continue

            drop_type = self._detect_drop(flow["ts"])
            if drop_type:
                self._report_drop(key, flow["ts"], drop_type)
            expired.append(key)

        for key in expired:
            del self.flows[key]

    def _detect_drop(self, ts):
        has = [ts[i] != 0 for i in range(MAX_STAGES)]
        if has[0] and not has[1]:
            return "req_internal"
        if has[1] and not has[2]:
            return "stack_no_reply"
        if has[2] and not has[3]:
            return "rep_internal"
        return None

    def _report_drop(self, key, ts, drop_type):
        sip, dip, icmp_id, seq = key
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        print("\n=== ICMP Drop Detected: %s ===" % now)
        print("Flow: %s -> %s (ID=%d, Seq=%d)" % (
            format_ip(sip), format_ip(dip), icmp_id, seq))

        for i, name in enumerate(STAGE_NAMES):
            status = "recorded" if ts[i] != 0 else "MISSING"
            print("  [%d] %s: %s" % (i, name, status))

        if drop_type == "req_internal":
            print("\nDrop: Request dropped INTERNALLY (between phy NIC and icmp_rcv)")
            self.stats["req_internal_drop"] += 1
        elif drop_type == "stack_no_reply":
            print("\nDrop: Protocol stack did NOT generate reply")
            self.stats["stack_no_reply"] += 1
        elif drop_type == "rep_internal":
            print("\nDrop: Reply dropped INTERNALLY (between ip_send_skb and phy NIC)")
            self.stats["rep_internal_drop"] += 1

    def print_stats(self):
        print("\n=== ICMP System Path Statistics ===")
        print("Total flows tracked: %d" % self.stats["total_flows"])
        print("Complete flows: %d" % self.stats["complete_flows"])
        print("Request internal drops: %d" % self.stats["req_internal_drop"])
        print("Stack no-reply: %d" % self.stats["stack_no_reply"])
        print("Reply internal drops: %d" % self.stats["rep_internal_drop"])


def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Detect ICMP drops between physical NIC and protocol stack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor ICMP path on host with physical interface
  sudo ./system_icmp_path_tracer.py --src-ip 192.168.70.32 --dst-ip 192.168.70.31 \\
      --phy-iface enp24s0f0np0

  # With custom timeout and verbose output
  sudo ./system_icmp_path_tracer.py --src-ip 10.0.0.1 --dst-ip 10.0.0.2 \\
      --phy-iface ens4f0,ens4f1 --timeout-ms 2000 --verbose

Stages:
  [0] ReqRX@phy     - Request received at physical interface
  [1] ReqRcv@stack  - Request delivered to icmp_rcv
  [2] RepSnd@stack  - Reply sent by ip_send_skb
  [3] RepTX@phy     - Reply transmitted at physical interface
""")

    parser.add_argument('--src-ip', type=str, required=True,
                        help='Source IP of ICMP request (remote peer)')
    parser.add_argument('--dst-ip', type=str, required=True,
                        help='Destination IP of ICMP request (local host)')
    parser.add_argument('--phy-iface', type=str, required=True,
                        help='Physical interface(s), comma-separated for bond')
    parser.add_argument('--timeout-ms', type=int, default=1000,
                        help='Timeout in ms for drop detection (default: 1000)')
    parser.add_argument('--verbose', action='store_true',
                        help='Print all flow events')

    args = parser.parse_args()

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

    print("=== System ICMP Path Tracer ===")
    print("Source IP (remote): %s" % args.src_ip)
    print("Destination IP (local): %s" % args.dst_ip)
    print("Physical interface(s): %s" % ', '.join(
        "%s(ifindex=%d)" % (n, i) for n, i in phy_ifindexes))
    print("Timeout: %d ms" % args.timeout_ms)
    print("")
    print("Path: phy RX -> icmp_rcv -> ip_send_skb -> phy TX")
    print("  [0] Request RX at %s" % args.phy_iface)
    print("  [1] Request delivered to icmp_rcv")
    print("  [2] Reply sent by ip_send_skb")
    print("  [3] Reply TX at %s" % args.phy_iface)
    print("")

    try:
        bpf_code = bpf_text % (src_ip_hex, dst_ip_hex)
        bpf_code = bpf_code.replace("__IFACE_ARRAYS__", iface_arrays)
        b = BPF(text=bpf_code)
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    tracker = FlowTracker(args.timeout_ms, args.phy_iface)

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
                lat_req = (ts[1] - ts[0]) / 1000.0 if ts[0] and ts[1] else 0
                lat_stack = (ts[2] - ts[1]) / 1000.0 if ts[1] and ts[2] else 0
                lat_rep = (ts[3] - ts[2]) / 1000.0 if ts[2] and ts[3] else 0
                lat_total = (ts[3] - ts[0]) / 1000.0 if ts[0] and ts[3] else 0
                print("  Latency(us): ReqPath=%.1f Stack=%.1f RepPath=%.1f Total=%.1f" % (
                    lat_req, lat_stack, lat_rep, lat_total))
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
