// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_pair_latency - VM pair latency measurement BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bits.bpf.h"
#include "vm_pair_latency.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __s32 src_ifindex = 0;    /* Source VM interface */
const volatile __s32 dst_ifindex = 0;    /* Destination VM interface */
const volatile __u16 targ_port = 0;      /* Target port to filter */

/* Send timestamps map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, __u64);
} send_ts SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hist);
} latency_hist SEC(".maps");

/* Counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* Helper: check if interface matches source */
static __always_inline bool is_src_interface(const struct sk_buff *skb)
{
    if (src_ifindex == 0)
        return false;
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;
    return BPF_CORE_READ(dev, ifindex) == src_ifindex;
}

/* Helper: check if interface matches destination */
static __always_inline bool is_dst_interface(const struct sk_buff *skb)
{
    if (dst_ifindex == 0)
        return false;
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;
    return BPF_CORE_READ(dev, ifindex) == dst_ifindex;
}

/* Helper: check if port matches */
static __always_inline bool is_target_port(__u16 port)
{
    if (targ_port == 0)
        return true;
    return bpf_ntohs(port) == targ_port;
}

/* Helper: parse UDP flow key */
static __always_inline int parse_udp_key(const struct sk_buff *skb, struct flow_key *key)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    __u16 protocol = BPF_CORE_READ(skb, protocol);

    if (!head || network_header == (__u16)~0U)
        return 0;

    /* Check if IP packet */
    if (protocol != bpf_htons(0x0800)) /* ETH_P_IP */
        return 0;

    struct iphdr ip;
    if (bpf_core_read(&ip, sizeof(ip), head + network_header) < 0)
        return 0;

    if (ip.protocol != PROTO_UDP)
        return 0;

    key->saddr = ip.saddr;
    key->daddr = ip.daddr;

    /* Get transport header */
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    if (transport_header == 0 || transport_header == (__u16)~0U ||
        transport_header == network_header) {
        __u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5)
            return 0;
        transport_header = network_header + (ip_ihl * 4);
    }

    struct udphdr udp;
    if (bpf_core_read(&udp, sizeof(udp), head + transport_header) < 0)
        return 0;

    key->sport = udp.source;
    key->dport = udp.dest;

    /* Port filter */
    if (!is_target_port(udp.source) && !is_target_port(udp.dest))
        return 0;

    return 1;
}

/* Record send timestamp (source VM transmit) */
SEC("tp/net/net_dev_xmit")
int handle_net_dev_xmit(void *ctx)
{
    struct trace_event_raw_net_dev_xmit {
        unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
        void *skbaddr;
        unsigned int len;
        int rc;
    } *args = ctx;

    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    if (!is_src_interface(skb))
        return 0;

    struct flow_key key = {};
    if (!parse_udp_key(skb, &key))
        return 0;

    /* Store timestamp */
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&send_ts, &key, &ts, BPF_ANY);

    /* Increment send counter */
    __u32 idx = 0;
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return 0;
}

/* Record receive and calculate latency (destination VM receive) */
SEC("tp/net/netif_receive_skb")
int handle_netif_receive_skb(void *ctx)
{
    struct trace_event_raw_net_dev_template {
        unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
        void *skbaddr;
    } *args = ctx;

    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    if (!is_dst_interface(skb))
        return 0;

    struct flow_key key = {};
    if (!parse_udp_key(skb, &key))
        return 0;

    /* Look up send timestamp */
    __u64 *send_ts_ptr = bpf_map_lookup_elem(&send_ts, &key);
    if (!send_ts_ptr)
        return 0;

    __u64 recv_ts = bpf_ktime_get_ns();
    __u64 latency_ns = recv_ts - *send_ts_ptr;

    /* Delete the entry */
    bpf_map_delete_elem(&send_ts, &key);

    /* Update histogram */
    __u32 hist_key = 0;
    struct hist *h = bpf_map_lookup_elem(&latency_hist, &hist_key);
    if (h) {
        __u64 lat_us = latency_ns / 1000;
        __u32 slot = log2l(lat_us);
        if (slot >= MAX_SLOTS)
            slot = MAX_SLOTS - 1;
        h->slots[slot]++;
    }

    /* Submit event */
    struct latency_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->key = key;
        e->latency_ns = latency_ns;
        e->timestamp = recv_ts;
        e->src_ifindex = src_ifindex;
        e->dst_ifindex = dst_ifindex;

        struct net_device *dev = BPF_CORE_READ(skb, dev);
        if (dev)
            bpf_probe_read_kernel_str(e->dst_ifname, IFNAMSIZ, BPF_CORE_READ(dev, name));

        bpf_ringbuf_submit(e, 0);
    }

    /* Increment receive counter */
    __u32 idx = 1;
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return 0;
}
