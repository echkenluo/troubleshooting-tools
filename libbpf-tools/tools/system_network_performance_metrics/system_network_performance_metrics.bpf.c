// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_performance_metrics - System network performance BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "system_network_performance_metrics.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 target_ifindex = 0;
const volatile __u8 filter_protocol = 0;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct if_metrics_key);
    __type(value, struct perf_metrics);
} if_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct proto_metrics_key);
    __type(value, struct perf_metrics);
} proto_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} tx_latency_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} rx_latency_hist SEC(".maps");

/* Temporary storage for latency calculation */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);  /* skb pointer */
    __type(value, __u64); /* timestamp */
} tx_start_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} rx_start_ts SEC(".maps");

/* Update histogram */
static __always_inline void update_hist(void *hist_map, __u64 latency_ns)
{
    __u32 bucket = 0;
    __u64 lat_us = latency_ns / 1000;

    while (lat_us > 0 && bucket < 63) {
        lat_us >>= 1;
        bucket++;
    }

    __u64 *count = bpf_map_lookup_elem(hist_map, &bucket);
    if (count)
        __sync_fetch_and_add(count, 1);
}

/* Update metrics */
static __always_inline void update_metrics(struct perf_metrics *metrics,
                                           __u64 bytes, __u64 latency,
                                           bool is_tx)
{
    if (is_tx) {
        __sync_fetch_and_add(&metrics->tx_packets, 1);
        __sync_fetch_and_add(&metrics->tx_bytes, bytes);
        if (latency > 0) {
            __sync_fetch_and_add(&metrics->tx_latency_sum, latency);
            if (metrics->tx_latency_min == 0 || latency < metrics->tx_latency_min)
                metrics->tx_latency_min = latency;
            if (latency > metrics->tx_latency_max)
                metrics->tx_latency_max = latency;
        }
    } else {
        __sync_fetch_and_add(&metrics->rx_packets, 1);
        __sync_fetch_and_add(&metrics->rx_bytes, bytes);
        if (latency > 0) {
            __sync_fetch_and_add(&metrics->rx_latency_sum, latency);
            if (metrics->rx_latency_min == 0 || latency < metrics->rx_latency_min)
                metrics->rx_latency_min = latency;
            if (latency > metrics->rx_latency_max)
                metrics->rx_latency_max = latency;
        }
    }
}

/* TX start - ip_output */
SEC("kprobe/ip_output")
int BPF_KPROBE(kprobe_ip_output, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    __u64 ts = bpf_ktime_get_ns();
    __u64 skb_ptr = (__u64)skb;
    bpf_map_update_elem(&tx_start_ts, &skb_ptr, &ts, BPF_ANY);
    return 0;
}

/* TX end - dev_queue_xmit */
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    struct net_device *dev;
    __u32 ifindex = 0;
    __u32 skb_len = 0;
    __u64 skb_ptr = (__u64)skb;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    if (target_ifindex && ifindex != target_ifindex)
        return 0;

    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);

    /* Calculate latency */
    __u64 *start_ts = bpf_map_lookup_elem(&tx_start_ts, &skb_ptr);
    __u64 latency = 0;
    if (start_ts) {
        latency = bpf_ktime_get_ns() - *start_ts;
        bpf_map_delete_elem(&tx_start_ts, &skb_ptr);
        update_hist(&tx_latency_hist, latency);
    }

    /* Update interface metrics */
    struct if_metrics_key if_key = { .ifindex = ifindex };
    struct perf_metrics *if_m = bpf_map_lookup_elem(&if_metrics, &if_key);
    if (if_m) {
        update_metrics(if_m, skb_len, latency, true);
    } else {
        struct perf_metrics new_m = {};
        new_m.tx_packets = 1;
        new_m.tx_bytes = skb_len;
        if (latency > 0) {
            new_m.tx_latency_sum = latency;
            new_m.tx_latency_min = latency;
            new_m.tx_latency_max = latency;
        }
        bpf_map_update_elem(&if_metrics, &if_key, &new_m, BPF_ANY);
    }

    return 0;
}

/* RX start - netif_receive_skb */
SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    __u64 ts = bpf_ktime_get_ns();
    __u64 skb_ptr = (__u64)skb;

    struct net_device *dev;
    __u32 ifindex = 0;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    if (target_ifindex && ifindex != target_ifindex)
        return 0;

    bpf_map_update_elem(&rx_start_ts, &skb_ptr, &ts, BPF_ANY);
    return 0;
}

/* RX end - tcp_v4_rcv / udp_rcv */
SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(kprobe_tcp_v4_rcv, struct sk_buff *skb)
{
    __u64 skb_ptr = (__u64)skb;
    __u32 skb_len = 0;

    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);

    __u64 *start_ts = bpf_map_lookup_elem(&rx_start_ts, &skb_ptr);
    __u64 latency = 0;
    if (start_ts) {
        latency = bpf_ktime_get_ns() - *start_ts;
        bpf_map_delete_elem(&rx_start_ts, &skb_ptr);
        update_hist(&rx_latency_hist, latency);
    }

    /* Update protocol metrics */
    struct proto_metrics_key proto_key = { .protocol = IPPROTO_TCP };
    struct perf_metrics *proto_m = bpf_map_lookup_elem(&proto_metrics, &proto_key);
    if (proto_m) {
        update_metrics(proto_m, skb_len, latency, false);
    } else {
        struct perf_metrics new_m = {};
        new_m.rx_packets = 1;
        new_m.rx_bytes = skb_len;
        if (latency > 0) {
            new_m.rx_latency_sum = latency;
            new_m.rx_latency_min = latency;
            new_m.rx_latency_max = latency;
        }
        bpf_map_update_elem(&proto_metrics, &proto_key, &new_m, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/__udp4_lib_rcv")
int BPF_KPROBE(kprobe_udp4_lib_rcv, struct sk_buff *skb)
{
    __u64 skb_ptr = (__u64)skb;
    __u32 skb_len = 0;

    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);

    __u64 *start_ts = bpf_map_lookup_elem(&rx_start_ts, &skb_ptr);
    __u64 latency = 0;
    if (start_ts) {
        latency = bpf_ktime_get_ns() - *start_ts;
        bpf_map_delete_elem(&rx_start_ts, &skb_ptr);
        update_hist(&rx_latency_hist, latency);
    }

    struct proto_metrics_key proto_key = { .protocol = IPPROTO_UDP };
    struct perf_metrics *proto_m = bpf_map_lookup_elem(&proto_metrics, &proto_key);
    if (proto_m) {
        update_metrics(proto_m, skb_len, latency, false);
    } else {
        struct perf_metrics new_m = {};
        new_m.rx_packets = 1;
        new_m.rx_bytes = skb_len;
        if (latency > 0) {
            new_m.rx_latency_sum = latency;
            new_m.rx_latency_min = latency;
            new_m.rx_latency_max = latency;
        }
        bpf_map_update_elem(&proto_metrics, &proto_key, &new_m, BPF_ANY);
    }

    return 0;
}

/* Drop tracking */
SEC("tracepoint/skb/kfree_skb")
int tracepoint_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    struct net_device *dev;
    __u32 ifindex = 0;

    if (!skb)
        return 0;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return 0;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return 0;

    if (target_ifindex && ifindex != target_ifindex)
        return 0;

    struct if_metrics_key if_key = { .ifindex = ifindex };
    struct perf_metrics *if_m = bpf_map_lookup_elem(&if_metrics, &if_key);
    if (if_m) {
        __sync_fetch_and_add(&if_m->drops, 1);
    }

    return 0;
}
