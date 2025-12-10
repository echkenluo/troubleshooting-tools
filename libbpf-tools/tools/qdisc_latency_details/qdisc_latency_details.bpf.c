// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// qdisc_latency_details - Qdisc latency tracking BPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "qdisc_latency_details.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __be32 targ_saddr = 0;
const volatile __be32 targ_daddr = 0;
const volatile __u16 targ_sport = 0;
const volatile __u16 targ_dport = 0;
const volatile __u8 targ_proto = 0;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct flow_data);
} qdisc_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Helper: Parse packet key from skb */
static __always_inline int parse_packet(struct sk_buff *skb, struct packet_key *key, char *dev_name)
{
    struct net_device *dev;
    unsigned char *head;
    __u16 network_header;

    /* Get device info */
    dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return 0;

    __u32 ifindex = BPF_CORE_READ(dev, ifindex);
    if (targ_ifindex && ifindex != targ_ifindex)
        return 0;

    if (dev_name)
        bpf_probe_read_kernel_str(dev_name, IFNAMSIZ, BPF_CORE_READ(dev, name));

    /* Parse IP header */
    head = BPF_CORE_READ(skb, head);
    network_header = BPF_CORE_READ(skb, network_header);

    if (!head || network_header == (__u16)~0U || network_header > 2048)
        return 0;

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) < 0)
        return 0;

    /* Apply filters */
    if (targ_proto && ip.protocol != targ_proto)
        return 0;
    if (targ_saddr && ip.saddr != targ_saddr && ip.daddr != targ_saddr)
        return 0;
    if (targ_daddr && ip.saddr != targ_daddr && ip.daddr != targ_daddr)
        return 0;

    key->saddr = ip.saddr;
    key->daddr = ip.daddr;
    key->protocol = ip.protocol;

    /* Parse transport header */
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    if (transport_header == 0 || transport_header == network_header) {
        __u8 ihl = ip.ihl & 0xF;
        transport_header = network_header + (ihl * 4);
    }

    if (ip.protocol == 6) {  /* TCP */
        struct tcphdr tcp;
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) == 0) {
            key->sport = tcp.source;
            key->dport = tcp.dest;
            key->seq_or_id = tcp.seq;

            if (targ_sport && bpf_ntohs(tcp.source) != targ_sport && bpf_ntohs(tcp.dest) != targ_sport)
                return 0;
            if (targ_dport && bpf_ntohs(tcp.source) != targ_dport && bpf_ntohs(tcp.dest) != targ_dport)
                return 0;
        }
    } else if (ip.protocol == 17) {  /* UDP */
        struct udphdr udp;
        if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
            key->sport = udp.source;
            key->dport = udp.dest;
            key->seq_or_id = ip.id;

            if (targ_sport && bpf_ntohs(udp.source) != targ_sport && bpf_ntohs(udp.dest) != targ_sport)
                return 0;
            if (targ_dport && bpf_ntohs(udp.source) != targ_dport && bpf_ntohs(udp.dest) != targ_dport)
                return 0;
        }
    } else if (ip.protocol == 1) {  /* ICMP */
        struct icmphdr icmp;
        if (bpf_probe_read_kernel(&icmp, sizeof(icmp), head + transport_header) == 0) {
            key->sport = icmp.un.echo.id;
            key->dport = icmp.un.echo.sequence;
            key->seq_or_id = (icmp.type << 8) | icmp.code;
        }
    } else {
        return 0;
    }

    return 1;
}

/* Tracepoint: net_dev_queue (qdisc enqueue) */
SEC("raw_tracepoint/net_dev_queue")
int raw_tp_net_dev_queue(struct bpf_raw_tracepoint_args *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb)
        return 0;

    struct packet_key key = {};
    struct flow_data data = {};

    if (!parse_packet(skb, &key, data.dev_name))
        return 0;

    data.enqueue_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&qdisc_sessions, &key, &data, BPF_ANY);

    return 0;
}

/* Tracepoint: qdisc_dequeue */
SEC("raw_tracepoint/qdisc_dequeue")
int raw_tp_qdisc_dequeue(struct bpf_raw_tracepoint_args *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->args[3];
    if (!skb)
        return 0;

    struct packet_key key = {};
    if (!parse_packet(skb, &key, NULL))
        return 0;

    struct flow_data *data = bpf_map_lookup_elem(&qdisc_sessions, &key);
    if (!data || data->enqueue_time == 0)
        return 0;

    __u64 dequeue_time = bpf_ktime_get_ns();
    __u64 delay = dequeue_time - data->enqueue_time;

    struct qdisc_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = dequeue_time;
    e->enqueue_time = data->enqueue_time;
    e->dequeue_time = dequeue_time;
    e->delay_ns = delay;
    e->saddr = key.saddr;
    e->daddr = key.daddr;
    e->sport = key.sport;
    e->dport = key.dport;
    e->protocol = key.protocol;
    __builtin_memcpy(e->dev_name, data->dev_name, sizeof(e->dev_name));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&qdisc_sessions, &key);

    return 0;
}
