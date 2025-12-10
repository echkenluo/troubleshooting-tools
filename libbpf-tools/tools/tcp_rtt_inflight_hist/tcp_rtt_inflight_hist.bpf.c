// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_rtt_inflight_hist - TCP RTT and inflight histogram BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcp_rtt_inflight_hist.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 targ_laddr = 0;
const volatile __be32 targ_raddr = 0;
const volatile __be16 targ_lport = 0;
const volatile __be16 targ_rport = 0;

/* 2D histogram: RTT x Inflight */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SLOTS * MAX_SLOTS);
    __type(key, struct hist_key);
    __type(value, __u64);
} hist_2d SEC(".maps");

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

    if (targ_laddr && saddr != targ_laddr) return false;
    if (targ_raddr && daddr != targ_raddr) return false;
    if (targ_lport && sport != targ_lport) return false;
    if (targ_rport && dport != targ_rport) return false;

    return true;
}

/* Kprobe: tcp_rcv_established */
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock *sk)
{
    if (!check_filter(sk)) return 0;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u32 srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
    __u32 packets_out = BPF_CORE_READ(tp, packets_out);
    __u32 mss = BPF_CORE_READ(tp, mss_cache);

    /* Calculate inflight bytes */
    __u64 inflight = (__u64)packets_out * mss;

    /* Calculate slots */
    __u32 rtt_slot = log2l(srtt_us + 1);
    __u32 inflight_slot = log2l(inflight / 1024 + 1);  /* In KB */

    if (rtt_slot >= MAX_SLOTS) rtt_slot = MAX_SLOTS - 1;
    if (inflight_slot >= MAX_SLOTS) inflight_slot = MAX_SLOTS - 1;

    /* Update 2D histogram */
    struct hist_key key = { .rtt_slot = rtt_slot, .inflight_slot = inflight_slot };
    __u64 *cnt = bpf_map_lookup_elem(&hist_2d, &key);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&hist_2d, &key, &one, BPF_ANY);
    }

    /* Update 1D histograms */
    cnt = bpf_map_lookup_elem(&rtt_hist, &rtt_slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    cnt = bpf_map_lookup_elem(&inflight_hist, &inflight_slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    return 0;
}
