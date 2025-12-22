#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
tcp_perf_observer.py

eBPF-based TCP performance observer with low-overhead summary histograms
and throttled detail events. Designed to complement existing tcpsocket/
pcap analyzers by capturing RTT, handshake latency, retransmissions,
drops, and selected congestion control signals with per-interval summaries.

Key features:
- Summary: RTT histogram, connection setup latency histogram, retrans/drop/state counters.
- Detail (throttled): high RTT, slow handshake, retransmit, drop events with flow tuple.
- Filters: laddr/raddr/lport/rport (IPv4), disable filters by omitting args.
- Safety: per-CPU histograms, kernel-side event rate limiting.

Usage examples (root required):
    sudo python tcp_perf_observer.py --interval 5 --duration 30 --rtt-threshold-us 5000
    sudo python tcp_perf_observer.py --mode both --laddr 70.0.0.31 --raddr 70.0.0.32 --interval 2
    sudo python tcp_perf_observer.py --mode detail --detail-rate 100 --rtt-threshold-us 8000

Notes:
- IPv4 focused; IPv6 can be added by extending tuple handling.
- Designed to run under BCC; lazily imports BPF to allow --help/--dry-run on systems without BCC.
"""

import argparse
import ctypes
import ipaddress
import socket
import struct
import sys
import time

# ------------- Argument parsing -------------


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP performance observer (summary histograms + throttled detail events)"
    )
    parser.add_argument("--interval", type=int, default=5, help="Summary print interval seconds")
    parser.add_argument("--duration", type=int, default=0, help="Total run time seconds (0 = run until Ctrl-C)")
    parser.add_argument(
        "--mode", choices=["summary", "detail", "both"], default="both", help="Run summary only, detail only, or both"
    )
    parser.add_argument("--laddr", help="Filter by local IPv4 address")
    parser.add_argument("--raddr", help="Filter by remote IPv4 address")
    parser.add_argument("--lport", type=int, help="Filter by local TCP port")
    parser.add_argument("--rport", type=int, help="Filter by remote TCP port")
    parser.add_argument("--rtt-threshold-us", type=int, default=10000, help="RTT detail trigger threshold (usec)")
    parser.add_argument(
        "--connlat-threshold-us", type=int, default=20000, help="Handshake latency detail trigger threshold (usec)"
    )
    parser.add_argument(
        "--detail-rate",
        type=int,
        default=200,
        help="Max detail events per CPU per second (kernel-side limiter)",
    )
    parser.add_argument(
        "--sample-rate",
        type=int,
        default=1,
        help="Sample every N ack events for RTT/histogram (>=1); increase to reduce overhead",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated BPF program and exit (no kernel attachment)",
    )
    return parser.parse_args()


def ip_to_u32(ip_str):
    if not ip_str:
        return 0
    if sys.version_info[0] == 2 and isinstance(ip_str, str):
        ip_str = ip_str.decode('utf-8')
    # inet_saddr/daddr are stored in network byte order (big-endian)
    # but we need to match the actual representation in memory (little-endian on x86)
    packed = socket.inet_aton(str(ip_str))
    return struct.unpack("I", packed)[0]


# ------------- BPF program template -------------


def build_bpf_text(args):
    laddr = ip_to_u32(args.laddr)
    raddr = ip_to_u32(args.raddr)
    lport = args.lport or 0
    rport = args.rport or 0

    bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/bpf.h>
#include <linux/skbuff.h>
#include <linux/socket.h>

#define LADDR_FILTER %u
#define RADDR_FILTER %u
#define LPORT_FILTER %u
#define RPORT_FILTER %u
#define RTT_THRESHOLD_US %u
#define CONNLAT_THRESHOLD_US %u
#define EVENT_RATE_LIMIT %u
#define SAMPLE_EVERY %u

struct flow_id_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct rate_limit_t {
    u64 sec;
    u32 count;
};

// detail event types
enum event_type_e {
    EVT_RTT = 1,
    EVT_CONNLAT = 2,
    EVT_RETRANS = 3,
    EVT_DROP = 4,
};

struct detail_event_t {
    u64 ts_ns;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  ev_type;
    u8  state;
    u32 metric;       // RTT or connlat usec
    u32 extra1;       // cwnd or drop reason
    u32 extra2;       // ssthresh or retrans count
};

BPF_PERCPU_ARRAY(event_rl, struct rate_limit_t, 1);
BPF_PERF_OUTPUT(events);

// handshake start time per sock*
BPF_HASH(conn_start, struct sock *, u64, 16384);

// Histograms
BPF_HISTOGRAM(rtt_hist, int);
BPF_HISTOGRAM(connlat_hist, int);

// Counters
BPF_ARRAY(retrans_counter, u64, 1);
BPF_ARRAY(drop_counter, u64, 1);
BPF_ARRAY(state_counter, u64, 8); // SYN_SENT=0, ESTABLISHED=1, FIN_WAIT/close=2, CLOSE=3, TIME_WAIT=4, CLOSE_WAIT=5, LAST_ACK=6, CLOSING=7

static __always_inline bool pass_filter(struct sock *sk) {
    const struct inet_sock *inet = (struct inet_sock *)sk;
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    bpf_probe_read(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
    bpf_probe_read(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    bpf_probe_read(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read(&dport, sizeof(dport), (void *)&inet->inet_dport);

    // Bidirectional filter: if both laddr and raddr specified, match either direction
    #if LADDR_FILTER && RADDR_FILTER
        bool match1 = (saddr == LADDR_FILTER && daddr == RADDR_FILTER);
        bool match2 = (saddr == RADDR_FILTER && daddr == LADDR_FILTER);
        if (!match1 && !match2) return false;
    #else
        if (LADDR_FILTER && saddr != LADDR_FILTER) return false;
        if (RADDR_FILTER && daddr != RADDR_FILTER) return false;
    #endif
    if (LPORT_FILTER && sport != bpf_htons(LPORT_FILTER)) return false;
    if (RPORT_FILTER && dport != bpf_htons(RPORT_FILTER)) return false;
    return true;
}

static __always_inline bool allow_event() {
    u32 idx = 0;
    struct rate_limit_t *st = event_rl.lookup(&idx);
    if (!st) return false;
    u64 now_ns = bpf_ktime_get_ns();
    u64 sec = now_ns / 1000000000ULL;
    if (st->sec != sec) {
        st->sec = sec;
        st->count = 0;
    }
    if (st->count >= EVENT_RATE_LIMIT)
        return false;
    st->count++;
    return true;
}

static __always_inline void emit_event(void *ctx, struct sock *sk, u8 ev_type, u32 metric, u32 extra1, u32 extra2, u8 state) {
    if (!allow_event()) return;
    struct detail_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ev_type = ev_type;
    ev.metric = metric;
    ev.extra1 = extra1;
    ev.extra2 = extra2;
    ev.state = state;

    const struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read(&ev.saddr, sizeof(ev.saddr), (void *)&inet->inet_saddr);
    bpf_probe_read(&ev.daddr, sizeof(ev.daddr), (void *)&inet->inet_daddr);
    bpf_probe_read(&ev.sport, sizeof(ev.sport), (void *)&inet->inet_sport);
    bpf_probe_read(&ev.dport, sizeof(ev.dport), (void *)&inet->inet_dport);

    events.perf_submit(ctx, &ev, sizeof(ev));
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    if (!pass_filter(sk))
        return 0;
    u64 ts = bpf_ktime_get_ns();
    conn_start.update(&sk, &ts);
    return 0;
}

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int new_state) {
    if (!pass_filter(sk))
        return 0;

    if (new_state == TCP_ESTABLISHED) {
        u64 *tsp = conn_start.lookup(&sk);
        if (tsp) {
            u64 delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
            connlat_hist.increment(bpf_log2l(delta_us));
            if (delta_us > CONNLAT_THRESHOLD_US)
                emit_event(ctx, sk, EVT_CONNLAT, delta_us, 0, 0, new_state);
            conn_start.delete(&sk);
        }
    }

    u32 idx = 0;
    if (new_state == TCP_SYN_SENT) idx = 0;
    else if (new_state == TCP_ESTABLISHED) idx = 1;
    else if (new_state == TCP_FIN_WAIT1 || new_state == TCP_FIN_WAIT2) idx = 2;
    else if (new_state == TCP_CLOSE) idx = 3;
    else if (new_state == TCP_TIME_WAIT) idx = 4;
    else if (new_state == TCP_CLOSE_WAIT) idx = 5;
    else if (new_state == TCP_LAST_ACK) idx = 6;
    else if (new_state == TCP_CLOSING) idx = 7;

    u64 *cnt = state_counter.lookup(&idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    return 0;
}

int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (!pass_filter(sk))
        return 0;
    if (SAMPLE_EVERY > 1) {
        if ((bpf_get_prandom_u32() %% SAMPLE_EVERY) != 0)
            return 0;
    }
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u32 srtt = 0;
    bpf_probe_read(&srtt, sizeof(srtt), &tp->srtt_us);
    srtt >>= 3; // stored with 3 bits fractional shift
    if (srtt == 0)
        return 0;
    rtt_hist.increment(bpf_log2l(srtt));
    if (srtt > RTT_THRESHOLD_US) {
        u32 cwnd = 0, ssthresh = 0;
        bpf_probe_read(&cwnd, sizeof(cwnd), &tp->snd_cwnd);
        bpf_probe_read(&ssthresh, sizeof(ssthresh), &tp->snd_ssthresh);
        emit_event(ctx, sk, EVT_RTT, srtt, cwnd, ssthresh, TCP_ESTABLISHED);
    }
    return 0;
}

int kprobe__tcp_retransmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (!pass_filter(sk))
        return 0;
    u32 idx = 0;
    u64 *cnt = retrans_counter.lookup(&idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    emit_event(ctx, sk, EVT_RETRANS, 0, 0, 0, TCP_ESTABLISHED);
    return 0;
}

TRACEPOINT_PROBE(skb, kfree_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    struct sock *sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &skb->sk);
    if (!sk)
        return 0;

    u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return 0;

    u16 protocol = 0;
    bpf_probe_read(&protocol, sizeof(protocol), &args->protocol);
    if (protocol != 0x0800)
        return 0;

    if (!pass_filter(sk))
        return 0;

    u32 idx = 0;
    u64 *cnt = drop_counter.lookup(&idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    u8 state = 0;
    bpf_probe_read(&state, sizeof(state), &sk->__sk_common.skc_state);
    void *location = args->location;
    emit_event(args, sk, EVT_DROP, 0, (u32)(u64)location, 0, state);
    return 0;
}
"""
    return bpf_text % (
        laddr,
        raddr,
        lport,
        rport,
        args.rtt_threshold_us,
        args.connlat_threshold_us,
        args.detail_rate,
        max(args.sample_rate, 1),
    )


# ------------- Userspace helpers -------------


def lazy_bpf_import():
    try:
        from bcc import BPF
    except ImportError:
        try:
            from bpfcc import BPF
        except ImportError:
            print("Error: bcc/bpfcc module not found. Please install python-bcc or python3-bcc.")
            sys.exit(1)
    return BPF


def inet_ntoa_be(val):
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", val))


class DetailEvent(ctypes.Structure):
    _fields_ = [
        ("ts_ns", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("saddr", ctypes.c_uint),
        ("daddr", ctypes.c_uint),
        ("sport", ctypes.c_ushort),
        ("dport", ctypes.c_ushort),
        ("ev_type", ctypes.c_ubyte),
        ("state", ctypes.c_ubyte),
        ("metric", ctypes.c_uint),
        ("extra1", ctypes.c_uint),
        ("extra2", ctypes.c_uint),
    ]


def print_log2_hist(hist, label):
    if len(hist) == 0:
        return
    print("[{}]".format(label))
    hist.print_log2_hist(label)
    hist.clear()


def format_event(ev):
    ev_map = {1: "rtt", 2: "connlat", 3: "retrans", 4: "drop"}
    et = ev_map.get(ev.ev_type, str(ev.ev_type))
    ts_s = ev.ts_ns / 1e9
    return (
        "{:.6f}s ev={} pid={} ".format(ts_s, et, ev.pid) +
        "{}:{} -> ".format(inet_ntoa_be(ev.saddr), socket.ntohs(ev.sport)) +
        "{}:{} ".format(inet_ntoa_be(ev.daddr), socket.ntohs(ev.dport)) +
        "metric={} extra1={} extra2={} state={}".format(ev.metric, ev.extra1, ev.extra2, ev.state)
    )


def main():
    args = parse_args()
    bpf_text = build_bpf_text(args)
    if args.dry_run:
        print(bpf_text)
        return

    BPF = lazy_bpf_import()
    b = BPF(text=bpf_text)

    def handle_event(cpu, data, size):
        ev = ctypes.cast(data, ctypes.POINTER(DetailEvent)).contents
        print(format_event(ev))

    if args.mode in ("detail", "both"):
        b["events"].open_perf_buffer(handle_event)

    start_ts = time.time()
    next_print = start_ts + args.interval
    end_ts = start_ts + args.duration if args.duration > 0 else None

    print("tcp_perf_observer started. Press Ctrl-C to stop.")
    try:
        while True:
            if args.mode in ("detail", "both"):
                b.perf_buffer_poll(timeout=100)
            else:
                time.sleep(0.1)

            now = time.time()
            if now >= next_print and args.mode in ("summary", "both"):
                print("\n==== Summary @ {} ====".format(time.strftime('%H:%M:%S')))
                print_log2_hist(b.get_table("rtt_hist"), "RTT (us)")
                print_log2_hist(b.get_table("connlat_hist"), "ConnSetup (us)")
                retrans = b.get_table("retrans_counter")
                drops = b.get_table("drop_counter")
                states = b.get_table("state_counter")
                retrans_v = retrans[array_key(0)]
                drops_v = drops[array_key(0)]
                print("retrans: {}  drops: {}".format(retrans_v.value, drops_v.value))
                # states
                state_labels = [
                    "SYN_SENT",
                    "ESTABLISHED",
                    "FIN_WAIT",
                    "CLOSE",
                    "TIME_WAIT",
                    "CLOSE_WAIT",
                    "LAST_ACK",
                    "CLOSING",
                ]
                state_line = []
                for i, label in enumerate(state_labels):
                    cnt = states[array_key(i)]
                    state_line.append("{}:{}".format(label, cnt.value))
                print("states: " + " ".join(state_line))
                next_print = now + args.interval

            if end_ts and now >= end_ts:
                break
    except KeyboardInterrupt:
        pass


def array_key(idx):
    return ctypes.c_int(idx)


if __name__ == "__main__":
    main()
