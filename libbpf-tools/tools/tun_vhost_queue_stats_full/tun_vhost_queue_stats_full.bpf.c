// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_vhost_queue_stats_full - Full TUN to vhost-net queue statistics BPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tun_vhost_queue_stats_full.h"

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
    __type(key, __u64);
    __type(value, __u64);
} handle_rx_vqs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} vq_consumption_handle_rx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} vq_delay_handle_rx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} vq_consumption_signal SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} vq_delay_signal SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} ptr_ring_depth_xmit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct hist_key);
    __type(value, __u64);
} ptr_ring_depth_recv SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct queue_key);
    __type(value, struct queue_stats);
} queue_statistics SEC(".maps");

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

    /* tx_ring is at offset ~1024 in tun_file (after sock, socket, socket_wq) */
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

/* Probe: tun_net_xmit - Track PTR ring depth */
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

    /* Socket is at a fixed offset in tun_file */
    __u64 sock_ptr = (__u64)(tfile + 640);  /* Approximate offset to socket */

    /* Track this queue */
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_mapping;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), BPF_CORE_READ(dev, name));
    bpf_map_update_elem(&target_queues, &sock_ptr, &qkey, BPF_ANY);

    /* Get PTR ring depth */
    __u32 depth = get_ptr_ring_depth(tfile);

    /* Record histogram */
    struct hist_key hist_key = {};
    hist_key.queue_index = queue_mapping;
    bpf_probe_read_kernel_str(hist_key.dev_name, sizeof(hist_key.dev_name), BPF_CORE_READ(dev, name));
    hist_key.slot = depth == 0 ? 0 : log2l(depth);

    hist_increment(&ptr_ring_depth_xmit, &hist_key);

    /* Update queue statistics */
    struct queue_stats *stats = bpf_map_lookup_elem(&queue_statistics, &qkey);
    if (stats) {
        __sync_fetch_and_add(&stats->xmit_count, 1);
        __sync_fetch_and_add(&stats->ring_depth_sum, depth);
        if (depth > stats->ring_depth_max)
            stats->ring_depth_max = depth;
    } else {
        struct queue_stats new_stats = {};
        new_stats.xmit_count = 1;
        new_stats.ring_depth_sum = depth;
        new_stats.ring_depth_max = depth;
        bpf_map_update_elem(&queue_statistics, &qkey, &new_stats, BPF_ANY);
    }

    return 0;
}

/* Probe: handle_rx - Track VQ state */
SEC("kprobe/handle_rx")
int BPF_KPROBE(kprobe_handle_rx, void *net)
{
    if (!net)
        return 0;

    /* Get vhost_virtqueue from vhost_net structure */
    /* vhost_net_virtqueue is at offset after vhost_dev (~192 bytes) */
    void *nvq = net + 192;
    void *vq = nvq;  /* vhost_virtqueue is first in vhost_net_virtqueue */

    /* Get private_data (socket pointer) from vhost_virtqueue */
    /* private_data is at a large offset in vhost_virtqueue */
    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 17424);

    __u64 sock_ptr = (__u64)private_data;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Track VQ for signal filtering */
    __u64 vq_addr = (__u64)vq;
    bpf_map_update_elem(&handle_rx_vqs, &sock_ptr, &vq_addr, BPF_ANY);

    /* Get VQ indices */
    __u16 last_avail_idx = 0, avail_idx = 0, last_used_idx = 0;
    bpf_probe_read_kernel(&last_avail_idx, sizeof(last_avail_idx), vq + 332);
    bpf_probe_read_kernel(&avail_idx, sizeof(avail_idx), vq + 334);
    bpf_probe_read_kernel(&last_used_idx, sizeof(last_used_idx), vq + 336);

    /* Calculate metrics */
    __u16 consumption = 0, delay = 0;
    if (avail_idx >= last_avail_idx)
        consumption = avail_idx - last_avail_idx;
    else
        consumption = 65536 + avail_idx - last_avail_idx;

    if (last_avail_idx >= last_used_idx)
        delay = last_avail_idx - last_used_idx;
    else
        delay = 65536 + last_avail_idx - last_used_idx;

    /* Record histograms */
    struct hist_key hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));

    hist_key.slot = consumption == 0 ? 0 : log2l(consumption);
    hist_increment(&vq_consumption_handle_rx, &hist_key);

    hist_key.slot = delay == 0 ? 0 : log2l(delay);
    hist_increment(&vq_delay_handle_rx, &hist_key);

    /* Update statistics */
    struct queue_stats *stats = bpf_map_lookup_elem(&queue_statistics, qkey);
    if (stats)
        __sync_fetch_and_add(&stats->handle_rx_count, 1);

    return 0;
}

/* Probe: tun_recvmsg - Track PTR ring depth at receive */
SEC("kprobe/tun_recvmsg")
int BPF_KPROBE(kprobe_tun_recvmsg, void *sock, void *m, size_t len, int flags)
{
    if (!sock)
        return 0;

    /* Calculate tun_file from socket (socket is embedded in tun_file) */
    void *tfile = sock - 640;  /* Approximate offset */

    __u64 sock_ptr = (__u64)sock;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Get PTR ring depth */
    __u32 depth = get_ptr_ring_depth(tfile);

    /* Record histogram */
    struct hist_key hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    hist_key.slot = depth == 0 ? 0 : log2l(depth);

    hist_increment(&ptr_ring_depth_recv, &hist_key);

    /* Update statistics */
    struct queue_stats *stats = bpf_map_lookup_elem(&queue_statistics, qkey);
    if (stats)
        __sync_fetch_and_add(&stats->recvmsg_count, 1);

    return 0;
}

/* Probe: vhost_add_used_and_signal_n - Track signal state */
SEC("kprobe/vhost_add_used_and_signal_n")
int BPF_KPROBE(kprobe_vhost_signal, void *dev, void *vq)
{
    if (!vq)
        return 0;

    /* Get private_data from vhost_virtqueue */
    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 17424);

    __u64 sock_ptr = (__u64)private_data;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Filter: only process signals from handle_rx VQs */
    __u64 *expected_vq = bpf_map_lookup_elem(&handle_rx_vqs, &sock_ptr);
    if (expected_vq && *expected_vq != (__u64)vq)
        return 0;

    /* Get VQ indices */
    __u16 last_avail_idx = 0, avail_idx = 0, last_used_idx = 0;
    bpf_probe_read_kernel(&last_avail_idx, sizeof(last_avail_idx), vq + 332);
    bpf_probe_read_kernel(&avail_idx, sizeof(avail_idx), vq + 334);
    bpf_probe_read_kernel(&last_used_idx, sizeof(last_used_idx), vq + 336);

    /* Calculate metrics */
    __u16 consumption = 0, delay = 0;
    if (avail_idx >= last_avail_idx)
        consumption = avail_idx - last_avail_idx;
    else
        consumption = 65536 + avail_idx - last_avail_idx;

    if (last_avail_idx >= last_used_idx)
        delay = last_avail_idx - last_used_idx;
    else
        delay = 65536 + last_avail_idx - last_used_idx;

    /* Record histograms */
    struct hist_key hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));

    hist_key.slot = consumption == 0 ? 0 : log2l(consumption);
    hist_increment(&vq_consumption_signal, &hist_key);

    hist_key.slot = delay == 0 ? 0 : log2l(delay);
    hist_increment(&vq_delay_signal, &hist_key);

    /* Update statistics */
    struct queue_stats *stats = bpf_map_lookup_elem(&queue_statistics, qkey);
    if (stats)
        __sync_fetch_and_add(&stats->signal_count, 1);

    return 0;
}
