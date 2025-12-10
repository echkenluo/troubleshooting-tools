// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_icmp_rtt - ICMP RTT measurement BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "system_network_icmp_rtt.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 filter_src_ip = 0;
const volatile __be32 filter_dst_ip = 0;
const volatile __u32 target_ifindex = 0;
const volatile __u64 latency_threshold_ns = 0;

/* ICMP types */
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct icmp_key);
    __type(value, struct rtt_flow_data);
} flow_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} rtt_histogram SEC(".maps");

/* Parse ICMP key from skb */
static __always_inline int parse_icmp_key(struct sk_buff *skb,
                                          struct icmp_key *key,
                                          __u8 *icmp_type,
                                          bool is_request)
{
    unsigned char *head;
    __u16 network_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return -1;

    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0)
        return -1;

    if (network_header == (__u16)~0U || network_header > 2048)
        return -1;

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) < 0)
        return -1;

    if (ip.protocol != IPPROTO_ICMP)
        return -1;

    /* Check IP filter */
    if (is_request) {
        if (filter_src_ip && ip.saddr != filter_src_ip)
            return -1;
        if (filter_dst_ip && ip.daddr != filter_dst_ip)
            return -1;
    } else {
        if (filter_src_ip && ip.daddr != filter_src_ip)
            return -1;
        if (filter_dst_ip && ip.saddr != filter_dst_ip)
            return -1;
    }

    /* Parse ICMP header */
    __u8 ihl = ip.ihl & 0x0F;
    __u16 icmp_offset = network_header + (ihl * 4);

    struct icmphdr icmp;
    if (bpf_probe_read_kernel(&icmp, sizeof(icmp), head + icmp_offset) < 0)
        return -1;

    /* Check ICMP type */
    if (is_request && icmp.type != ICMP_ECHO)
        return -1;
    if (!is_request && icmp.type != ICMP_ECHOREPLY)
        return -1;

    *icmp_type = icmp.type;

    /* Use canonical key (always src_ip < dst_ip direction) */
    key->src_ip = filter_src_ip;
    key->dst_ip = filter_dst_ip;
    key->id = icmp.un.echo.id;
    key->seq = icmp.un.echo.sequence;

    return 0;
}

/* Check interface */
static __always_inline bool is_target_ifindex(struct sk_buff *skb)
{
    struct net_device *dev;
    int ifindex = 0;

    if (!target_ifindex)
        return true;

    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) < 0 || !dev)
        return false;
    if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) < 0)
        return false;

    return ifindex == target_ifindex;
}

/* Update histogram */
static __always_inline void update_histogram(__u64 latency_ns)
{
    __u32 bucket = 0;
    __u64 lat_us = latency_ns / 1000;

    /* Log2 bucketing */
    while (lat_us > 0 && bucket < 63) {
        lat_us >>= 1;
        bucket++;
    }

    __u64 *count = bpf_map_lookup_elem(&rtt_histogram, &bucket);
    if (count)
        __sync_fetch_and_add(count, 1);
}

/* TX request probe - ip_output */
SEC("kprobe/ip_output")
int BPF_KPROBE(kprobe_ip_output, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct icmp_key key = {};
    __u8 icmp_type = 0;

    if (parse_icmp_key(skb, &key, &icmp_type, true) < 0)
        return 0;

    struct rtt_flow_data flow = {};
    flow.ts[0] = bpf_ktime_get_ns();
    flow.pid = bpf_get_current_pid_tgid() >> 32;
    flow.request_type = icmp_type;
    flow.saw_request_start = 1;
    bpf_get_current_comm(&flow.comm, sizeof(flow.comm));

    bpf_map_update_elem(&flow_sessions, &key, &flow, BPF_ANY);
    return 0;
}

/* TX request end - dev_queue_xmit */
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    struct icmp_key key = {};
    __u8 icmp_type = 0;

    if (!is_target_ifindex(skb))
        return 0;

    if (parse_icmp_key(skb, &key, &icmp_type, true) < 0)
        return 0;

    struct rtt_flow_data *flow = bpf_map_lookup_elem(&flow_sessions, &key);
    if (!flow)
        return 0;

    flow->ts[6] = bpf_ktime_get_ns();
    flow->saw_request_end = 1;
    return 0;
}

/* RX reply start - netif_receive_skb */
SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    struct icmp_key key = {};
    __u8 icmp_type = 0;

    if (!is_target_ifindex(skb))
        return 0;

    if (parse_icmp_key(skb, &key, &icmp_type, false) < 0)
        return 0;

    struct rtt_flow_data *flow = bpf_map_lookup_elem(&flow_sessions, &key);
    if (!flow)
        return 0;

    flow->ts[7] = bpf_ktime_get_ns();
    flow->reply_type = icmp_type;
    flow->saw_reply_start = 1;
    return 0;
}

/* RX reply end - icmp_rcv */
SEC("kprobe/icmp_rcv")
int BPF_KPROBE(kprobe_icmp_rcv, struct sk_buff *skb)
{
    struct icmp_key key = {};
    __u8 icmp_type = 0;

    if (parse_icmp_key(skb, &key, &icmp_type, false) < 0)
        return 0;

    struct rtt_flow_data *flow = bpf_map_lookup_elem(&flow_sessions, &key);
    if (!flow || !flow->saw_request_start || !flow->saw_request_end || !flow->saw_reply_start)
        return 0;

    flow->ts[13] = bpf_ktime_get_ns();
    flow->saw_reply_end = 1;

    /* Calculate RTT */
    __u64 rtt_ns = flow->ts[13] - flow->ts[0];

    /* Check threshold */
    if (latency_threshold_ns > 0 && rtt_ns < latency_threshold_ns) {
        bpf_map_delete_elem(&flow_sessions, &key);
        return 0;
    }

    /* Update histogram */
    update_histogram(rtt_ns);

    /* Submit event */
    struct rtt_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->key = key;
        __builtin_memcpy(&event->data, flow, sizeof(event->data));
        bpf_ringbuf_submit(event, 0);
    }

    bpf_map_delete_elem(&flow_sessions, &key);
    return 0;
}
