// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// iface_netstat - Per-queue packet size distribution monitor BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "iface_netstat.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 targ_ifindex = 0;

/* TX queue statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_QUEUE_NUM);
    __type(key, __u16);
    __type(value, struct queue_data);
} tx_q SEC(".maps");

/* RX queue statistics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_QUEUE_NUM);
    __type(key, __u16);
    __type(value, struct queue_data);
} rx_q SEC(".maps");

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

/* Helper: update queue data */
static __always_inline void update_data(struct queue_data *data, __u64 len)
{
    __sync_fetch_and_add(&data->total_pkt_len, len);
    __sync_fetch_and_add(&data->num_pkt, 1);

    if (len < 64) {
        __sync_fetch_and_add(&data->size_64B, 1);
    } else if (len < 512) {
        __sync_fetch_and_add(&data->size_512B, 1);
    } else if (len < 2048) {
        __sync_fetch_and_add(&data->size_2K, 1);
    } else if (len < 16384) {
        __sync_fetch_and_add(&data->size_16K, 1);
    } else {
        __sync_fetch_and_add(&data->size_64K, 1);
    }
}

/* Tracepoint: net:net_dev_start_xmit - TX path */
SEC("tracepoint/net/net_dev_start_xmit")
int tracepoint_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (!skb)
        return 0;

    if (!check_device(skb))
        return 0;

    __u16 qid = BPF_CORE_READ(skb, queue_mapping);
    __u32 len = BPF_CORE_READ(skb, len);

    struct queue_data *data = bpf_map_lookup_elem(&tx_q, &qid);
    if (!data) {
        struct queue_data new_data = {};
        bpf_map_update_elem(&tx_q, &qid, &new_data, BPF_NOEXIST);
        data = bpf_map_lookup_elem(&tx_q, &qid);
        if (!data)
            return 0;
    }

    update_data(data, len);
    return 0;
}

/* Tracepoint: net:netif_receive_skb - RX path */
SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_netif_receive_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (!skb)
        return 0;

    if (!check_device(skb))
        return 0;

    __u32 len = BPF_CORE_READ(skb, len);

    /* Get RX queue - check if recorded */
    __u16 qid = 0;
    __u16 rx_queue = BPF_CORE_READ(skb, queue_mapping);

    /* Check if queue is recorded (queue_mapping field is set) */
    if (rx_queue > 0 && rx_queue < MAX_QUEUE_NUM)
        qid = rx_queue;

    struct queue_data *data = bpf_map_lookup_elem(&rx_q, &qid);
    if (!data) {
        struct queue_data new_data = {};
        bpf_map_update_elem(&rx_q, &qid, &new_data, BPF_NOEXIST);
        data = bpf_map_lookup_elem(&rx_q, &qid);
        if (!data)
            return 0;
    }

    update_data(data, len);
    return 0;
}
