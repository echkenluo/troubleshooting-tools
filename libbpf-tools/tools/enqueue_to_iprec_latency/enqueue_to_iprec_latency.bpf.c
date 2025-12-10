// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// enqueue_to_iprec_latency - RX latency measurement BPF program
//
// Measures critical async boundary latency in Linux RX path:
// enqueue_to_backlog -> __netif_receive_skb -> ip_rcv

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "enqueue_to_iprec_latency.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __be32 targ_src_ip = 0;
const volatile __be32 targ_dst_ip = 0;
const volatile __be16 targ_src_port = 0;
const volatile __be16 targ_dst_port = 0;
const volatile __u8 targ_protocol = 0;  /* 0=all, 6=TCP, 17=UDP */
const volatile __u32 high_latency_threshold_us = 0;

/* Ring buffer for high latency events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Flow tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct flow_data);
} flow_sessions SEC(".maps");

/* Latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} latency_hist SEC(".maps");

/* Packet counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* Helper: increment counter */
static __always_inline void inc_counter(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* Helper: check if device matches */
static __always_inline bool check_device(struct sk_buff *skb)
{
    if (targ_ifindex == 0)
        return true;

    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;

    __u32 ifindex = BPF_CORE_READ(dev, ifindex);
    return ifindex == targ_ifindex;
}

/* Helper: log2 approximation */
static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    if (v > 0) {
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (v <= 1)
                break;
            v >>= 1;
            r++;
        }
    }
    return r;
}

/* Helper: parse packet and fill key */
static __always_inline int parse_packet(struct sk_buff *skb, struct packet_key *key)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);

    if (!head || network_header == (__u16)~0U || network_header > 2048)
        return 0;

    struct iphdr ip;
    if (bpf_core_read(&ip, sizeof(ip), head + network_header) < 0)
        return 0;

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    /* Protocol filter */
    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;

    /* IP filters */
    if (targ_src_ip != 0 && ip.saddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.daddr != targ_dst_ip)
        return 0;

    /* Calculate transport header offset */
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    if (transport_header == 0 || transport_header == (__u16)~0U) {
        __u8 ihl = ip.ihl & 0x0F;
        if (ihl < 5)
            return 0;
        transport_header = network_header + (ihl * 4);
    }

    if (ip.protocol == 6) {  /* TCP */
        struct tcphdr tcp;
        if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header) < 0)
            return 0;

        key->src_port = tcp.source;
        key->dst_port = tcp.dest;
        key->seq_or_id = tcp.seq;

        /* Port filters */
        if (targ_src_port != 0 && tcp.source != targ_src_port && tcp.dest != targ_src_port)
            return 0;
        if (targ_dst_port != 0 && tcp.source != targ_dst_port && tcp.dest != targ_dst_port)
            return 0;

    } else if (ip.protocol == 17) {  /* UDP */
        struct udphdr udp;
        if (bpf_core_read(&udp, sizeof(udp), head + transport_header) < 0)
            return 0;

        key->src_port = udp.source;
        key->dst_port = udp.dest;
        key->seq_or_id = ip.id;

        /* Port filters */
        if (targ_src_port != 0 && udp.source != targ_src_port && udp.dest != targ_src_port)
            return 0;
        if (targ_dst_port != 0 && udp.source != targ_dst_port && udp.dest != targ_dst_port)
            return 0;
    } else {
        return 0;
    }

    return 1;
}

/* Helper: record latency in histogram */
static __always_inline void record_latency(__u8 prev_stage, __u8 curr_stage, __u64 latency_us)
{
    struct hist_key hkey = {};
    hkey.prev_stage = prev_stage;
    hkey.curr_stage = curr_stage;
    hkey.slot = log2l(latency_us + 1);
    if (hkey.slot >= MAX_SLOTS)
        hkey.slot = MAX_SLOTS - 1;

    __u64 *cnt = bpf_map_lookup_elem(&latency_hist, &hkey);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&latency_hist, &hkey, &one, BPF_ANY);
    }
}

/* Stage 1: enqueue_to_backlog */
SEC("kprobe/enqueue_to_backlog")
int BPF_KPROBE(kprobe_enqueue_to_backlog, struct sk_buff *skb, int cpu)
{
    if (!skb || !check_device(skb))
        return 0;

    struct packet_key key = {};
    if (!parse_packet(skb, &key)) {
        inc_counter(CNT_PARSE_FAIL);
        return 0;
    }

    __u64 ts = bpf_ktime_get_ns();
    __u32 current_cpu = bpf_get_smp_processor_id();

    struct flow_data flow = {};
    flow.enqueue_ts = ts;
    flow.enqueue_cpu = (__u8)(current_cpu & 0xFF);

    bpf_map_delete_elem(&flow_sessions, &key);
    bpf_map_update_elem(&flow_sessions, &key, &flow, BPF_ANY);

    inc_counter(CNT_ENQUEUE);
    return 0;
}

/* Stage 2: __netif_receive_skb - CRITICAL ASYNC BOUNDARY */
SEC("kprobe/__netif_receive_skb")
int BPF_KPROBE(kprobe_netif_receive_skb, struct sk_buff *skb)
{
    if (!skb || !check_device(skb))
        return 0;

    struct packet_key key = {};
    if (!parse_packet(skb, &key)) {
        inc_counter(CNT_PARSE_FAIL);
        return 0;
    }

    __u64 ts = bpf_ktime_get_ns();
    __u32 current_cpu = bpf_get_smp_processor_id();

    struct flow_data *flow = bpf_map_lookup_elem(&flow_sessions, &key);
    if (!flow) {
        inc_counter(CNT_FLOW_NOT_FOUND);
        return 0;
    }

    /* Calculate latency from enqueue */
    if (flow->enqueue_ts > 0 && ts > flow->enqueue_ts) {
        __u64 latency_ns = ts - flow->enqueue_ts;
        __u64 latency_us = latency_ns / 1000;

        record_latency(STAGE_ENQUEUE, STAGE_RECEIVE, latency_us);

        /* Check CPU migration */
        if (flow->enqueue_cpu != (__u8)(current_cpu & 0xFF))
            inc_counter(CNT_CROSS_CPU);

        /* Emit high latency event if threshold enabled */
        if (high_latency_threshold_us > 0 && latency_us > high_latency_threshold_us) {
            struct latency_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (e) {
                e->ts_start = flow->enqueue_ts;
                e->ts_end = ts;
                e->latency_us = latency_us;
                e->prev_stage = STAGE_ENQUEUE;
                e->curr_stage = STAGE_RECEIVE;
                e->cpu_start = flow->enqueue_cpu;
                e->cpu_end = (__u8)(current_cpu & 0xFF);
                e->src_ip = key.src_ip;
                e->dst_ip = key.dst_ip;
                e->src_port = key.src_port;
                e->dst_port = key.dst_port;
                e->protocol = key.protocol;
                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    /* Update flow for next stage */
    flow->receive_ts = ts;
    flow->receive_cpu = (__u8)(current_cpu & 0xFF);

    inc_counter(CNT_RECEIVE);
    return 0;
}

/* Stage 3: ip_rcv */
SEC("kprobe/ip_rcv")
int BPF_KPROBE(kprobe_ip_rcv, struct sk_buff *skb)
{
    if (!skb || !check_device(skb))
        return 0;

    struct packet_key key = {};
    if (!parse_packet(skb, &key)) {
        inc_counter(CNT_PARSE_FAIL);
        return 0;
    }

    __u64 ts = bpf_ktime_get_ns();

    struct flow_data *flow = bpf_map_lookup_elem(&flow_sessions, &key);
    if (!flow) {
        inc_counter(CNT_FLOW_NOT_FOUND);
        return 0;
    }

    /* Calculate latency from receive */
    if (flow->receive_ts > 0 && ts > flow->receive_ts) {
        __u64 latency_ns = ts - flow->receive_ts;
        __u64 latency_us = latency_ns / 1000;

        record_latency(STAGE_RECEIVE, STAGE_IP_RCV, latency_us);

        /* Emit high latency event if threshold enabled */
        if (high_latency_threshold_us > 0 && latency_us > high_latency_threshold_us) {
            struct latency_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (e) {
                e->ts_start = flow->receive_ts;
                e->ts_end = ts;
                e->latency_us = latency_us;
                e->prev_stage = STAGE_RECEIVE;
                e->curr_stage = STAGE_IP_RCV;
                e->cpu_start = flow->receive_cpu;
                e->cpu_end = bpf_get_smp_processor_id();
                e->src_ip = key.src_ip;
                e->dst_ip = key.dst_ip;
                e->src_port = key.src_port;
                e->dst_port = key.dst_port;
                e->protocol = key.protocol;
                bpf_ringbuf_submit(e, 0);
            }
        }
    }

    inc_counter(CNT_IP_RCV);

    /* Clean up flow */
    bpf_map_delete_elem(&flow_sessions, &key);
    return 0;
}
