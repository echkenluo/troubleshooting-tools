// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_perf_observer - TCP performance observer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcp_perf_observer.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 targ_laddr = 0;
const volatile __be32 targ_raddr = 0;
const volatile __be16 targ_lport = 0;
const volatile __be16 targ_rport = 0;
const volatile __u32 rtt_threshold_us = 10000;
const volatile __u32 connlat_threshold_us = 20000;

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* RTT histogram */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} rtt_hist SEC(".maps");

/* Connection latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} connlat_hist SEC(".maps");

/* Counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* Connection start time tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_id);
    __type(value, __u64);
} conn_start SEC(".maps");

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

/* Helper: emit event */
static __always_inline void emit_event(struct sock *sk, __u8 ev_type, __u32 metric,
                                       __u32 extra1, __u32 extra2)
{
    struct detail_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return;

    struct inet_sock *inet = (struct inet_sock *)sk;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->saddr = BPF_CORE_READ(inet, inet_saddr);
    e->daddr = BPF_CORE_READ(inet, inet_daddr);
    e->sport = BPF_CORE_READ(inet, inet_sport);
    e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->ev_type = ev_type;
    e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
    e->metric = metric;
    e->extra1 = extra1;
    e->extra2 = extra2;

    bpf_ringbuf_submit(e, 0);
}

/* Kprobe: tcp_rcv_established - RTT measurement */
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock *sk)
{
    if (!check_filter(sk)) return 0;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u32 srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;  /* Convert from scaled */

    /* Update RTT histogram */
    __u32 slot = log2l(srtt_us + 1);
    if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
    __u64 *cnt = bpf_map_lookup_elem(&rtt_hist, &slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    /* Update ACK counter */
    __u32 idx = CNT_ACK;
    cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    /* Emit event if RTT exceeds threshold */
    if (srtt_us > rtt_threshold_us) {
        __u32 cwnd = BPF_CORE_READ(tp, snd_cwnd);
        __u32 ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
        emit_event(sk, EVT_RTT, srtt_us, cwnd, ssthresh);
    }

    return 0;
}

/* Tracepoint: tcp_retransmit_skb */
SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint_tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    if (!check_filter(sk)) return 0;

    __u32 idx = CNT_RETRANS;
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u32 total_retrans = BPF_CORE_READ(tp, total_retrans);
    emit_event(sk, EVT_RETRANS, 0, 0, total_retrans);

    return 0;
}

/* Kprobe: tcp_v4_connect - connection start */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk)
{
    struct inet_sock *inet = (struct inet_sock *)sk;
    struct flow_id fid = {};
    fid.saddr = BPF_CORE_READ(inet, inet_saddr);
    fid.daddr = BPF_CORE_READ(inet, inet_daddr);
    fid.sport = BPF_CORE_READ(inet, inet_sport);
    fid.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&conn_start, &fid, &ts, BPF_ANY);

    return 0;
}

/* Kprobe: tcp_finish_connect - connection established */
SEC("kprobe/tcp_finish_connect")
int BPF_KPROBE(kprobe_tcp_finish_connect, struct sock *sk)
{
    if (!check_filter(sk)) return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    struct flow_id fid = {};
    fid.saddr = BPF_CORE_READ(inet, inet_saddr);
    fid.daddr = BPF_CORE_READ(inet, inet_daddr);
    fid.sport = BPF_CORE_READ(inet, inet_sport);
    fid.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

    __u64 *start_ts = bpf_map_lookup_elem(&conn_start, &fid);
    if (start_ts) {
        __u64 now = bpf_ktime_get_ns();
        __u64 latency_us = (now - *start_ts) / 1000;

        /* Update histogram */
        __u32 slot = log2l(latency_us + 1);
        if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
        __u64 *cnt = bpf_map_lookup_elem(&connlat_hist, &slot);
        if (cnt) __sync_fetch_and_add(cnt, 1);

        /* Update counter */
        __u32 idx = CNT_CONN;
        cnt = bpf_map_lookup_elem(&counters, &idx);
        if (cnt) __sync_fetch_and_add(cnt, 1);

        /* Emit event if slow */
        if (latency_us > connlat_threshold_us)
            emit_event(sk, EVT_CONNLAT, (__u32)latency_us, 0, 0);

        bpf_map_delete_elem(&conn_start, &fid);
    }

    return 0;
}
