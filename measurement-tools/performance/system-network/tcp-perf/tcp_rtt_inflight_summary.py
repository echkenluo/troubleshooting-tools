#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
tcp_rtt_inflight_hist.py

eBPF-based TCP RTT, in-flight packets, and cwnd histogram collector.
Captures per-packet SRTT, packets_out, snd_cwnd values from RECEIVE perspective
(tcp_rcv_established), aggregates into log2 histograms, and outputs time-series
data at configurable intervals.

Key features:
- Triple histograms: RTT (us), in-flight packets, cwnd
- Retransmission counters: total_retrans, retrans_out, lost_out
- Per-interval time-series output + cumulative totals
- Connection filtering by IP/port
- Optional bandwidth histogram (--bw-hist): linear 500Mbps buckets, 0-32Gbps range

Usage examples (root required):
    sudo python tcp_rtt_inflight_hist.py --interval 1 --duration 60
    sudo python tcp_rtt_inflight_hist.py --laddr 70.0.0.31 --raddr 70.0.0.32
    sudo python tcp_rtt_inflight_hist.py --bw-hist --interval 1
    sudo python tcp_rtt_inflight_hist.py --lport 5201 --raw

Notes:
- Attaches to tcp_rcv_established() kprobe (RECEIVE/ACK perspective)
- IPv4 only; extend tuple handling for IPv6
- Requires BCC (python-bcc or python3-bpfcc)
"""

import argparse
import ctypes
import socket
import struct
import sys
import time

# Bandwidth histogram constants
BW_BUCKET_SIZE_MBPS = 500   # 0.5 Gbps per bucket
BW_BUCKET_COUNT = 64        # 64 buckets = 0-32 Gbps range
MSS_BYTES = 1460            # Assume standard MSS

# ------------- Argument parsing -------------


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP RTT, in-flight, cwnd histogram collector (receive perspective)"
    )
    parser.add_argument("--interval", type=int, default=1, help="Histogram print interval seconds")
    parser.add_argument("--duration", type=int, default=0, help="Total run time seconds (0 = run until Ctrl-C)")
    parser.add_argument("--laddr", help="Filter by local IPv4 address")
    parser.add_argument("--raddr", help="Filter by remote IPv4 address")
    parser.add_argument("--lport", type=int, help="Filter by local TCP port")
    parser.add_argument("--rport", type=int, help="Filter by remote TCP port")
    parser.add_argument(
        "--sample-rate",
        type=int,
        default=1,
        help="Sample every N packets (>=1); increase to reduce overhead",
    )
    parser.add_argument(
        "--bw-hist",
        action="store_true",
        help="Enable bandwidth histogram (linear 500Mbps buckets, computes inflight*MSS/RTT per packet)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output raw histogram data for machine parsing",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated BPF program and exit",
    )
    return parser.parse_args()


def ip_to_u32(ip_str):
    if not ip_str:
        return 0
    if sys.version_info[0] == 2 and isinstance(ip_str, str):
        ip_str = ip_str.decode('utf-8')
    packed = socket.inet_aton(str(ip_str))
    return struct.unpack("I", packed)[0]


# ------------- BPF program template -------------


def build_bpf_text(args):
    laddr = ip_to_u32(args.laddr)
    raddr = ip_to_u32(args.raddr)
    lport = args.lport or 0
    rport = args.rport or 0
    enable_bw_hist = 1 if args.bw_hist else 0

    bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>

#define LADDR_FILTER %u
#define RADDR_FILTER %u
#define LPORT_FILTER %u
#define RPORT_FILTER %u
#define SAMPLE_EVERY %u
#define ENABLE_BW_HIST %d
#define BW_BUCKET_SIZE_MBPS %d
#define BW_BUCKET_COUNT %d
#define MSS_BYTES %d

// Histograms for RTT, in-flight packets, cwnd (per-interval)
BPF_HISTOGRAM(rtt_hist, int);
BPF_HISTOGRAM(inflight_hist, int);
BPF_HISTOGRAM(cwnd_hist, int);

// Cumulative histograms (never cleared, for final summary)
BPF_HISTOGRAM(rtt_hist_total, int);
BPF_HISTOGRAM(inflight_hist_total, int);
BPF_HISTOGRAM(cwnd_hist_total, int);

// Counters for statistics
BPF_ARRAY(sample_count, u64, 1);
BPF_ARRAY(sample_count_total, u64, 1);

// Retransmission counters
// Index 0: total_retrans, 1: retrans_out, 2: lost_out
BPF_ARRAY(retrans_stats, u64, 3);
BPF_ARRAY(retrans_stats_total, u64, 3);

#if ENABLE_BW_HIST
// Bandwidth histogram: linear buckets, 500 Mbps each, 64 buckets = 0-32 Gbps
BPF_ARRAY(bw_hist, u64, BW_BUCKET_COUNT);
BPF_ARRAY(bw_hist_total, u64, BW_BUCKET_COUNT);
#endif

static __always_inline bool pass_filter(struct sock *sk) {
    const struct inet_sock *inet = (struct inet_sock *)sk;
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    bpf_probe_read(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
    bpf_probe_read(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    bpf_probe_read(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read(&dport, sizeof(dport), (void *)&inet->inet_dport);

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

int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if (!pass_filter(sk))
        return 0;

    if (SAMPLE_EVERY > 1) {
        if ((bpf_get_prandom_u32() %% SAMPLE_EVERY) != 0)
            return 0;
    }

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    // Read SRTT (smoothed RTT, stored << 3)
    u32 srtt_us = 0;
    bpf_probe_read(&srtt_us, sizeof(srtt_us), &tp->srtt_us);
    srtt_us >>= 3;

    // Read packets_out (in-flight packets)
    u32 packets_out = 0;
    bpf_probe_read(&packets_out, sizeof(packets_out), &tp->packets_out);

    // Read snd_cwnd (congestion window)
    u32 snd_cwnd = 0;
    bpf_probe_read(&snd_cwnd, sizeof(snd_cwnd), &tp->snd_cwnd);

    // Read retransmission stats
    u32 total_retrans = 0, retrans_out = 0, lost_out = 0;
    bpf_probe_read(&total_retrans, sizeof(total_retrans), &tp->total_retrans);
    bpf_probe_read(&retrans_out, sizeof(retrans_out), &tp->retrans_out);
    bpf_probe_read(&lost_out, sizeof(lost_out), &tp->lost_out);

    // Skip if no valid RTT data
    if (srtt_us == 0)
        return 0;

    // Update per-interval histograms
    int rtt_slot = bpf_log2l(srtt_us);
    int inflight_slot = bpf_log2l(packets_out > 0 ? packets_out : 1);
    int cwnd_slot = bpf_log2l(snd_cwnd > 0 ? snd_cwnd : 1);

    rtt_hist.increment(rtt_slot);
    inflight_hist.increment(inflight_slot);
    cwnd_hist.increment(cwnd_slot);

    // Update cumulative histograms
    rtt_hist_total.increment(rtt_slot);
    inflight_hist_total.increment(inflight_slot);
    cwnd_hist_total.increment(cwnd_slot);

    // Update sample counters
    u32 idx = 0;
    u64 *cnt = sample_count.lookup(&idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
    u64 *cnt_total = sample_count_total.lookup(&idx);
    if (cnt_total) __sync_fetch_and_add(cnt_total, 1);

    // Update retrans stats
    u32 ridx = 0;
    u64 *rval = retrans_stats.lookup(&ridx);
    if (rval && total_retrans > *rval) *rval = total_retrans;
    rval = retrans_stats_total.lookup(&ridx);
    if (rval && total_retrans > *rval) *rval = total_retrans;

    ridx = 1;
    rval = retrans_stats.lookup(&ridx);
    if (rval) *rval = retrans_out;
    rval = retrans_stats_total.lookup(&ridx);
    if (rval && retrans_out > *rval) *rval = retrans_out;

    ridx = 2;
    rval = retrans_stats.lookup(&ridx);
    if (rval) *rval = lost_out;
    rval = retrans_stats_total.lookup(&ridx);
    if (rval && lost_out > *rval) *rval = lost_out;

#if ENABLE_BW_HIST
    // Bandwidth histogram: compute BW = inflight * MSS * 8 / RTT
    // Unit analysis: bits / microseconds = Mbits/second (Mbps)
    // So (packets * MSS_bytes * 8_bits) / RTT_us = Mbps directly
    if (packets_out > 0) {
        u64 bw_mbps = ((u64)packets_out * MSS_BYTES * 8) / srtt_us;
        u32 bw_bucket = bw_mbps / BW_BUCKET_SIZE_MBPS;
        if (bw_bucket >= BW_BUCKET_COUNT)
            bw_bucket = BW_BUCKET_COUNT - 1;

        u64 *bw_val = bw_hist.lookup(&bw_bucket);
        if (bw_val) __sync_fetch_and_add(bw_val, 1);
        bw_val = bw_hist_total.lookup(&bw_bucket);
        if (bw_val) __sync_fetch_and_add(bw_val, 1);
    }
#endif

    return 0;
}
"""
    return bpf_text % (
        laddr,
        raddr,
        lport,
        rport,
        max(args.sample_rate, 1),
        enable_bw_hist,
        BW_BUCKET_SIZE_MBPS,
        BW_BUCKET_COUNT,
        MSS_BYTES,
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


def array_key(idx):
    return ctypes.c_int(idx)


def compute_histogram_stats(hist):
    """Compute mean and percentiles from log2 histogram."""
    total_count = 0
    weighted_sum = 0
    values = []

    for k, v in hist.items():
        bucket = k.value
        count = v.value
        if count == 0:
            continue
        if bucket == 0:
            val = 1
        else:
            val = (1 << bucket) + ((1 << bucket) >> 1)
        total_count += count
        weighted_sum += val * count
        values.extend([val] * count)

    if total_count == 0:
        return {"count": 0, "mean": 0, "p50": 0, "p90": 0, "p99": 0}

    values.sort()
    mean = weighted_sum / total_count
    p50 = values[int(len(values) * 0.5)]
    p90 = values[int(len(values) * 0.9)] if len(values) > 10 else values[-1]
    p99 = values[int(len(values) * 0.99)] if len(values) > 100 else values[-1]

    return {"count": total_count, "mean": mean, "p50": p50, "p90": p90, "p99": p99}


def compute_linear_histogram_stats(hist_array, bucket_size_mbps, bucket_count):
    """Compute stats from linear bandwidth histogram."""
    total_count = 0
    weighted_sum = 0
    values = []

    for i in range(bucket_count):
        count = hist_array[array_key(i)].value
        if count == 0:
            continue
        # Use bucket midpoint as representative value (in Mbps)
        val_mbps = i * bucket_size_mbps + bucket_size_mbps // 2
        total_count += count
        weighted_sum += val_mbps * count
        values.extend([val_mbps] * count)

    if total_count == 0:
        return {"count": 0, "mean": 0, "p50": 0, "p90": 0, "p99": 0}

    values.sort()
    mean = weighted_sum / total_count
    p50 = values[int(len(values) * 0.5)]
    p90 = values[int(len(values) * 0.9)] if len(values) > 10 else values[-1]
    p99 = values[int(len(values) * 0.99)] if len(values) > 100 else values[-1]

    return {"count": total_count, "mean": mean, "p50": p50, "p90": p90, "p99": p99}


def print_raw_histogram(hist, label, ts):
    """Print histogram in machine-readable format."""
    print("HIST {} ts={}".format(label, ts))
    for k, v in sorted(hist.items(), key=lambda x: x[0].value):
        if v.value > 0:
            bucket = k.value
            low = 1 << bucket if bucket > 0 else 0
            high = (1 << (bucket + 1)) - 1 if bucket > 0 else 1
            print("  {}..{}: {}".format(low, high, v.value))


def print_bw_histogram(hist_array, bucket_size_mbps, bucket_count, raw=False, ts=""):
    """Print linear bandwidth histogram."""
    if raw:
        print("HIST bw_mbps ts={}".format(ts))
        for i in range(bucket_count):
            count = hist_array[array_key(i)].value
            if count > 0:
                low = i * bucket_size_mbps
                high = (i + 1) * bucket_size_mbps
                print("  {}..{}: {}".format(low, high, count))
    else:
        # Find max count for scaling
        max_count = 0
        for i in range(bucket_count):
            count = hist_array[array_key(i)].value
            if count > max_count:
                max_count = count

        if max_count == 0:
            print("     (no data)")
            return

        # Print histogram bars
        scale = 40.0 / max_count if max_count > 0 else 1
        for i in range(bucket_count):
            count = hist_array[array_key(i)].value
            if count > 0:
                low_gbps = i * bucket_size_mbps / 1000.0
                high_gbps = (i + 1) * bucket_size_mbps / 1000.0
                bar_len = int(count * scale)
                bar = '*' * bar_len
                print("{:5.1f}-{:5.1f} Gbps : {:8d} |{:<40}|".format(
                    low_gbps, high_gbps, count, bar))


def print_raw_bw_histogram(hist_array, bucket_size_mbps, bucket_count, ts):
    """Print raw bandwidth histogram."""
    print("HIST bw_mbps ts={}".format(ts))
    for i in range(bucket_count):
        count = hist_array[array_key(i)].value
        if count > 0:
            low = i * bucket_size_mbps
            high = (i + 1) * bucket_size_mbps
            print("  {}..{}: {}".format(low, high, count))


def main():
    args = parse_args()
    bpf_text = build_bpf_text(args)
    if args.dry_run:
        print(bpf_text)
        return

    BPF = lazy_bpf_import()
    b = BPF(text=bpf_text)

    start_ts = time.time()
    next_print = start_ts + args.interval
    end_ts = start_ts + args.duration if args.duration > 0 else None
    interval_num = 0
    prev_total_retrans = 0

    filter_desc = []
    if args.laddr:
        filter_desc.append("laddr={}".format(args.laddr))
    if args.raddr:
        filter_desc.append("raddr={}".format(args.raddr))
    if args.lport:
        filter_desc.append("lport={}".format(args.lport))
    if args.rport:
        filter_desc.append("rport={}".format(args.rport))
    filter_str = ", ".join(filter_desc) if filter_desc else "none"

    print("tcp_rtt_inflight_hist started (RECEIVE/ACK perspective)")
    print("Probe point: tcp_rcv_established")
    print("Filter: {}".format(filter_str))
    print("Interval: {}s, Sample rate: 1/{}".format(args.interval, args.sample_rate))
    if args.bw_hist:
        print("Bandwidth histogram: ENABLED ({}Mbps buckets, 0-{}Gbps range)".format(
            BW_BUCKET_SIZE_MBPS, BW_BUCKET_COUNT * BW_BUCKET_SIZE_MBPS // 1000))
    print("Press Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(0.1)
            now = time.time()

            if now >= next_print:
                interval_num += 1
                ts_str = time.strftime('%Y-%m-%d %H:%M:%S')
                elapsed = now - start_ts

                rtt_hist = b.get_table("rtt_hist")
                inflight_hist = b.get_table("inflight_hist")
                cwnd_hist = b.get_table("cwnd_hist")
                sample_count = b.get_table("sample_count")
                retrans_stats = b.get_table("retrans_stats")

                rtt_stats = compute_histogram_stats(rtt_hist)
                inflight_stats = compute_histogram_stats(inflight_hist)
                cwnd_stats = compute_histogram_stats(cwnd_hist)

                cnt = sample_count[array_key(0)].value
                total_retrans = retrans_stats[array_key(0)].value
                retrans_out = retrans_stats[array_key(1)].value
                lost_out = retrans_stats[array_key(2)].value
                retrans_delta = total_retrans - prev_total_retrans
                prev_total_retrans = total_retrans

                if args.bw_hist:
                    bw_hist = b.get_table("bw_hist")
                    bw_stats = compute_linear_histogram_stats(bw_hist, BW_BUCKET_SIZE_MBPS, BW_BUCKET_COUNT)

                if args.raw:
                    print("\n# interval={} ts={} elapsed={:.1f}s samples={}".format(
                        interval_num, ts_str, elapsed, cnt))
                    print_raw_histogram(rtt_hist, "rtt_us", ts_str)
                    print_raw_histogram(inflight_hist, "inflight_pkts", ts_str)
                    print_raw_histogram(cwnd_hist, "cwnd_pkts", ts_str)
                    print("STATS rtt_mean={:.1f} rtt_p50={} rtt_p90={} rtt_p99={} inflight_mean={:.1f} inflight_p50={} inflight_p90={} inflight_p99={} cwnd_mean={:.1f} cwnd_p50={} cwnd_p90={} cwnd_p99={}".format(
                        rtt_stats["mean"], rtt_stats["p50"], rtt_stats["p90"], rtt_stats["p99"],
                        inflight_stats["mean"], inflight_stats["p50"], inflight_stats["p90"], inflight_stats["p99"],
                        cwnd_stats["mean"], cwnd_stats["p50"], cwnd_stats["p90"], cwnd_stats["p99"]))
                    print("RETRANS total={} delta=+{} retrans_out={} lost_out={}".format(
                        total_retrans, retrans_delta, retrans_out, lost_out))
                    if args.bw_hist:
                        print_raw_bw_histogram(bw_hist, BW_BUCKET_SIZE_MBPS, BW_BUCKET_COUNT, ts_str)
                        print("STATS_BW bw_mean={:.1f} bw_p50={} bw_p90={} bw_p99={}".format(
                            bw_stats["mean"], bw_stats["p50"], bw_stats["p90"], bw_stats["p99"]))
                else:
                    print("\n==== Interval {} @ {} (elapsed {:.1f}s, samples: {}) ====".format(
                        interval_num, ts_str, elapsed, cnt))

                    print("\n[RTT (us)] mean={:.1f} p50={} p90={} p99={}".format(
                        rtt_stats["mean"], rtt_stats["p50"], rtt_stats["p90"], rtt_stats["p99"]))
                    rtt_hist.print_log2_hist("usecs")

                    print("\n[In-flight (packets)] mean={:.1f} p50={} p90={} p99={}".format(
                        inflight_stats["mean"], inflight_stats["p50"], inflight_stats["p90"], inflight_stats["p99"]))
                    inflight_hist.print_log2_hist("packets")

                    print("\n[CWND (packets)] mean={:.1f} p50={} p90={} p99={}".format(
                        cwnd_stats["mean"], cwnd_stats["p50"], cwnd_stats["p90"], cwnd_stats["p99"]))
                    cwnd_hist.print_log2_hist("packets")

                    print("\n[Retransmissions] total_retrans={} (delta: +{}) retrans_out={} lost_out={}".format(
                        total_retrans, retrans_delta, retrans_out, lost_out))

                    if args.bw_hist:
                        print("\n[Bandwidth (Gbps)] mean={:.1f}Mbps ({:.2f}Gbps) p50={}Mbps p90={}Mbps p99={}Mbps".format(
                            bw_stats["mean"], bw_stats["mean"]/1000,
                            bw_stats["p50"], bw_stats["p90"], bw_stats["p99"]))
                        print_bw_histogram(bw_hist, BW_BUCKET_SIZE_MBPS, BW_BUCKET_COUNT)

                # Clear per-interval data
                rtt_hist.clear()
                inflight_hist.clear()
                cwnd_hist.clear()
                sample_count.clear()
                retrans_stats.clear()
                if args.bw_hist:
                    bw_hist.clear()

                next_print = now + args.interval

            if end_ts and now >= end_ts:
                break

    except KeyboardInterrupt:
        pass

    # Print cumulative totals
    ts_str = time.strftime('%Y-%m-%d %H:%M:%S')
    print("\n" + "=" * 70)
    print("CUMULATIVE TOTALS @ {} (RECEIVE/ACK perspective)".format(ts_str))
    print("=" * 70)

    rtt_hist_total = b.get_table("rtt_hist_total")
    inflight_hist_total = b.get_table("inflight_hist_total")
    cwnd_hist_total = b.get_table("cwnd_hist_total")
    sample_count_total = b.get_table("sample_count_total")
    retrans_stats_total = b.get_table("retrans_stats_total")

    rtt_stats_total = compute_histogram_stats(rtt_hist_total)
    inflight_stats_total = compute_histogram_stats(inflight_hist_total)
    cwnd_stats_total = compute_histogram_stats(cwnd_hist_total)
    total_samples = sample_count_total[array_key(0)].value

    total_retrans_final = retrans_stats_total[array_key(0)].value
    max_retrans_out = retrans_stats_total[array_key(1)].value
    max_lost_out = retrans_stats_total[array_key(2)].value

    if args.bw_hist:
        bw_hist_total = b.get_table("bw_hist_total")
        bw_stats_total = compute_linear_histogram_stats(bw_hist_total, BW_BUCKET_SIZE_MBPS, BW_BUCKET_COUNT)

    elapsed_total = time.time() - start_ts

    print("\nTotal duration: {:.1f}s, Total samples: {}".format(elapsed_total, total_samples))

    if args.raw:
        print_raw_histogram(rtt_hist_total, "rtt_us_total", "TOTAL")
        print_raw_histogram(inflight_hist_total, "inflight_pkts_total", "TOTAL")
        print_raw_histogram(cwnd_hist_total, "cwnd_pkts_total", "TOTAL")
        print("STATS_TOTAL rtt_mean={:.1f} rtt_p50={} rtt_p90={} rtt_p99={} inflight_mean={:.1f} inflight_p50={} inflight_p90={} inflight_p99={} cwnd_mean={:.1f} cwnd_p50={} cwnd_p90={} cwnd_p99={}".format(
            rtt_stats_total["mean"], rtt_stats_total["p50"], rtt_stats_total["p90"], rtt_stats_total["p99"],
            inflight_stats_total["mean"], inflight_stats_total["p50"], inflight_stats_total["p90"], inflight_stats_total["p99"],
            cwnd_stats_total["mean"], cwnd_stats_total["p50"], cwnd_stats_total["p90"], cwnd_stats_total["p99"]))
        print("RETRANS_TOTAL total={} max_retrans_out={} max_lost_out={}".format(
            total_retrans_final, max_retrans_out, max_lost_out))
        if args.bw_hist:
            print_raw_bw_histogram(bw_hist_total, BW_BUCKET_SIZE_MBPS, BW_BUCKET_COUNT, "TOTAL")
            print("STATS_BW_TOTAL bw_mean={:.1f} bw_p50={} bw_p90={} bw_p99={}".format(
                bw_stats_total["mean"], bw_stats_total["p50"], bw_stats_total["p90"], bw_stats_total["p99"]))
    else:
        print("\n[RTT (us)] mean={:.1f} p50={} p90={} p99={}".format(
            rtt_stats_total["mean"], rtt_stats_total["p50"], rtt_stats_total["p90"], rtt_stats_total["p99"]))
        rtt_hist_total.print_log2_hist("usecs")

        print("\n[In-flight (packets)] mean={:.1f} p50={} p90={} p99={}".format(
            inflight_stats_total["mean"], inflight_stats_total["p50"], inflight_stats_total["p90"], inflight_stats_total["p99"]))
        inflight_hist_total.print_log2_hist("packets")

        print("\n[CWND (packets)] mean={:.1f} p50={} p90={} p99={}".format(
            cwnd_stats_total["mean"], cwnd_stats_total["p50"], cwnd_stats_total["p90"], cwnd_stats_total["p99"]))
        cwnd_hist_total.print_log2_hist("packets")

        print("\n[Retransmissions] total_retrans={} max_retrans_out={} max_lost_out={}".format(
            total_retrans_final, max_retrans_out, max_lost_out))

        if args.bw_hist:
            print("\n[Bandwidth (Gbps)] mean={:.1f}Mbps ({:.2f}Gbps) p50={}Mbps p90={}Mbps p99={}Mbps".format(
                bw_stats_total["mean"], bw_stats_total["mean"]/1000,
                bw_stats_total["p50"], bw_stats_total["p90"], bw_stats_total["p99"]))
            print_bw_histogram(bw_hist_total, BW_BUCKET_SIZE_MBPS, BW_BUCKET_COUNT)

    print("\nDone.")


if __name__ == "__main__":
    main()
