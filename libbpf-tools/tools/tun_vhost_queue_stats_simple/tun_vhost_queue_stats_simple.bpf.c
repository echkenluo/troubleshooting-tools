// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_vhost_queue_stats_simple - Simple TUN to vhost-net queue statistics BPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tun_vhost_queue_stats_simple.h"

char LICENSE[] SEC("license") = "GPL";

#define NETDEV_ALIGN 32

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __u32 targ_queue = 0;
const volatile __u8 filter_queue_enabled = 0;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct queue_key);
} target_queues SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} vq_last_used_idx_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} ptr_ring_depth_xmit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct idx_value_key);
    __type(value, __u16);
} last_used_idx_values SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct idx_value_key);
    __type(value, struct napi_status);
} napi_status_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct idx_value_key);
    __type(value, struct simple_stats);
} queue_stats SEC(".maps");

/* Helper: log2 calculation */
static __always_inline __u64 log2l(__u64 v)
{
    __u64 r = 0;
    while (v >>= 1)
        r++;
    return r;
}

/* Helper: increment histogram */
static __always_inline void hist_increment(void *map, struct hist_key *key)
{
    __u64 *count = bpf_map_lookup_elem(map, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(map, key, &init, BPF_ANY);
    }
}

/* Helper: Get ptr_ring depth */
static __always_inline __u32 get_ptr_ring_depth(void *tfile)
{
    if (!tfile)
        return 0;

    void *tx_ring = tfile + 1024;

    __u32 producer = 0, consumer_tail = 0, size = 0;
    bpf_probe_read_kernel(&producer, sizeof(producer), tx_ring);
    bpf_probe_read_kernel(&consumer_tail, sizeof(consumer_tail), tx_ring + 8);
    bpf_probe_read_kernel(&size, sizeof(size), tx_ring + 12);

    if (size == 0)
        return 0;

    __u32 used;
    if (producer >= consumer_tail)
        used = producer - consumer_tail;
    else
        used = size - consumer_tail + producer;

    return used;
}

/* Probe: tun_net_xmit */
SEC("kprobe/tun_net_xmit")
int BPF_KPROBE(kprobe_tun_net_xmit, struct sk_buff *skb, struct net_device *dev)
{
    if (!skb || !dev)
        return 0;

    __u32 ifindex = BPF_CORE_READ(dev, ifindex);
    if (targ_ifindex != 0 && ifindex != targ_ifindex)
        return 0;

    __u32 queue_mapping = BPF_CORE_READ(skb, queue_mapping);
    if (filter_queue_enabled && queue_mapping != targ_queue)
        return 0;

    /* Get TUN private data */
    __u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    void *tun_priv = (void *)dev + aligned_size;

    __u32 numqueues = 0;
    bpf_probe_read_kernel(&numqueues, sizeof(numqueues), tun_priv + 2048);

    if (queue_mapping >= numqueues || numqueues == 0 || numqueues > 256)
        return 0;

    void *tfile = NULL;
    bpf_probe_read_kernel(&tfile, sizeof(tfile), tun_priv + (queue_mapping * 8));
    if (!tfile)
        return 0;

    __u64 sock_ptr = (__u64)(tfile + 640);

    /* Track this queue */
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_mapping;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), BPF_CORE_READ(dev, name));
    bpf_map_update_elem(&target_queues, &sock_ptr, &qkey, BPF_ANY);

    /* Get NAPI status */
    __u8 napi_enabled = 0, napi_frags_enabled = 0;
    bpf_probe_read_kernel(&napi_enabled, sizeof(napi_enabled), tfile + 800);
    bpf_probe_read_kernel(&napi_frags_enabled, sizeof(napi_frags_enabled), tfile + 801);

    struct idx_value_key idx_key = {};
    idx_key.queue_index = queue_mapping;
    bpf_probe_read_kernel_str(idx_key.dev_name, sizeof(idx_key.dev_name), BPF_CORE_READ(dev, name));

    struct napi_status napi = {};
    napi.napi_enabled = napi_enabled;
    napi.napi_frags_enabled = napi_frags_enabled;
    bpf_map_update_elem(&napi_status_map, &idx_key, &napi, BPF_ANY);

    /* Get PTR ring depth */
    __u32 depth = get_ptr_ring_depth(tfile);

    struct hist_key hist_key = {};
    hist_key.queue_index = queue_mapping;
    bpf_probe_read_kernel_str(hist_key.dev_name, sizeof(hist_key.dev_name), BPF_CORE_READ(dev, name));
    hist_key.slot = depth == 0 ? 0 : log2l(depth);

    hist_increment(&ptr_ring_depth_xmit, &hist_key);

    /* Update stats */
    struct simple_stats *stats = bpf_map_lookup_elem(&queue_stats, &idx_key);
    if (stats) {
        __sync_fetch_and_add(&stats->xmit_count, 1);
    } else {
        struct simple_stats new_stats = {};
        new_stats.xmit_count = 1;
        bpf_map_update_elem(&queue_stats, &idx_key, &new_stats, BPF_ANY);
    }

    return 0;
}

/* Probe: vhost_add_used_and_signal_n */
SEC("kprobe/vhost_add_used_and_signal_n")
int BPF_KPROBE(kprobe_vhost_signal, void *dev, void *vq)
{
    if (!vq)
        return 0;

    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 17424);

    __u64 sock_ptr = (__u64)private_data;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Get last_used_idx */
    __u16 last_used_idx = 0;
    bpf_probe_read_kernel(&last_used_idx, sizeof(last_used_idx), vq + 336);

    struct idx_value_key idx_key = {};
    idx_key.queue_index = qkey->queue_index;
    __builtin_memcpy(idx_key.dev_name, qkey->dev_name, sizeof(idx_key.dev_name));

    /* Store current value */
    bpf_map_update_elem(&last_used_idx_values, &idx_key, &last_used_idx, BPF_ANY);

    /* Record histogram */
    struct hist_key hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));

    if (last_used_idx == 0 || last_used_idx == 1)
        hist_key.slot = 0;
    else {
        __u64 log_result = log2l(last_used_idx);
        hist_key.slot = log_result > 15 ? 15 : log_result;
    }

    hist_increment(&vq_last_used_idx_hist, &hist_key);

    /* Update stats */
    struct simple_stats *stats = bpf_map_lookup_elem(&queue_stats, &idx_key);
    if (stats) {
        __sync_fetch_and_add(&stats->signal_count, 1);
        stats->last_used_idx = last_used_idx;
    } else {
        struct simple_stats new_stats = {};
        new_stats.signal_count = 1;
        new_stats.last_used_idx = last_used_idx;
        bpf_map_update_elem(&queue_stats, &idx_key, &new_stats, BPF_ANY);
    }

    return 0;
}
