// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_send_rtt_inflight_hist - TCP RTT/inflight/cwnd histogram from SEND perspective

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcp_send_rtt_inflight_hist.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 targ_laddr = 0;
const volatile __be32 targ_raddr = 0;
const volatile __be16 targ_lport = 0;
const volatile __be16 targ_rport = 0;
const volatile __u32 sample_rate = 1;
const volatile bool enable_bw_hist = false;

/* RTT histogram (1D) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} rtt_hist SEC(".maps");

/* Inflight histogram (1D) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} inflight_hist SEC(".maps");

/* CWND histogram (1D) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} cwnd_hist SEC(".maps");

/* Bandwidth histogram (linear buckets) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, BW_BUCKET_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} bw_hist SEC(".maps");

/* Statistics counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Helper: log2 */
static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (v <= 1) break;
        v >>= 1;
        r++;
    }
    return r;
}

/* Helper: check filter */
static __always_inline bool check_filter(struct sock *sk)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    __be32 saddr = BPF_CORE_READ(inet, inet_saddr);
    __be32 daddr = BPF_CORE_READ(inet, inet_daddr);
    __be16 sport = BPF_CORE_READ(inet, inet_sport);
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    /* Support bidirectional filter */
    if (targ_laddr && targ_raddr) {
        bool match1 = (saddr == targ_laddr && daddr == targ_raddr);
        bool match2 = (saddr == targ_raddr && daddr == targ_laddr);
        if (!match1 && !match2) return false;
    } else {
        if (targ_laddr && saddr != targ_laddr) return false;
        if (targ_raddr && daddr != targ_raddr) return false;
    }

    if (targ_lport && sport != targ_lport) return false;
    if (targ_rport && dport != targ_rport) return false;

    return true;
}

/* Kprobe: tcp_rate_skb_sent - called per packet sent */
SEC("kprobe/tcp_rate_skb_sent")
int BPF_KPROBE(kprobe_tcp_rate_skb_sent, struct sock *sk, struct sk_buff *skb)
{
    if (!check_filter(sk))
        return 0;

    /* Sampling */
    if (sample_rate > 1) {
        if ((bpf_get_prandom_u32() % sample_rate) != 0)
            return 0;
    }

    struct tcp_sock *tp = (struct tcp_sock *)sk;

    /* Read SRTT (smoothed RTT, stored << 3) */
    __u32 srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;

    /* Skip if no valid RTT data */
    if (srtt_us == 0)
        return 0;

    /* Read packets_out (in-flight packets) */
    __u32 packets_out = BPF_CORE_READ(tp, packets_out);

    /* Read snd_cwnd (congestion window) */
    __u32 snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);

    /* Read retransmission stats */
    __u32 total_retrans = BPF_CORE_READ(tp, total_retrans);
    __u32 retrans_out = BPF_CORE_READ(tp, retrans_out);
    __u32 lost_out = BPF_CORE_READ(tp, lost_out);

    /* Calculate histogram slots */
    __u32 rtt_slot = log2l(srtt_us + 1);
    __u32 inflight_slot = log2l(packets_out > 0 ? packets_out : 1);
    __u32 cwnd_slot = log2l(snd_cwnd > 0 ? snd_cwnd : 1);

    if (rtt_slot >= MAX_SLOTS) rtt_slot = MAX_SLOTS - 1;
    if (inflight_slot >= MAX_SLOTS) inflight_slot = MAX_SLOTS - 1;
    if (cwnd_slot >= MAX_SLOTS) cwnd_slot = MAX_SLOTS - 1;

    /* Update RTT histogram */
    __u64 *cnt = bpf_map_lookup_elem(&rtt_hist, &rtt_slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    /* Update inflight histogram */
    cnt = bpf_map_lookup_elem(&inflight_hist, &inflight_slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    /* Update cwnd histogram */
    cnt = bpf_map_lookup_elem(&cwnd_hist, &cwnd_slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    /* Update sample count */
    __u32 idx = STAT_SAMPLES;
    cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    /* Update retrans stats (track max values) */
    idx = STAT_TOTAL_RETRANS;
    cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt && total_retrans > *cnt) *cnt = total_retrans;

    idx = STAT_RETRANS_OUT;
    cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt) *cnt = retrans_out;

    idx = STAT_LOST_OUT;
    cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt) *cnt = lost_out;

    /* Bandwidth histogram: BW = inflight * MSS * 8 / RTT (Mbps) */
    if (enable_bw_hist && packets_out > 0 && srtt_us > 0) {
        __u64 bw_mbps = ((__u64)packets_out * MSS_BYTES * 8) / srtt_us;
        __u32 bw_bucket = bw_mbps / BW_BUCKET_MBPS;
        if (bw_bucket >= BW_BUCKET_COUNT)
            bw_bucket = BW_BUCKET_COUNT - 1;

        cnt = bpf_map_lookup_elem(&bw_hist, &bw_bucket);
        if (cnt) __sync_fetch_and_add(cnt, 1);
    }

    return 0;
}
