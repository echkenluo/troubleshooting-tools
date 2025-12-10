// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kernel_drop_stack_stats_summary - Kernel packet drop statistics BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernel_drop_stack_stats_summary.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 filter_src_ip = 0;
const volatile __be32 filter_dst_ip = 0;
const volatile __u16 filter_src_port = 0;
const volatile __u16 filter_dst_port = 0;
const volatile __u8 filter_protocol = 0;
const volatile bool output_events = false;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct drop_key);
    __type(value, struct drop_stats);
} drop_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Parse packet info from skb */
static __always_inline int parse_skb_info(struct sk_buff *skb,
                                          __be32 *src_ip, __be32 *dst_ip,
                                          __be16 *src_port, __be16 *dst_port,
                                          __u8 *protocol, __u32 *ifindex)
{
    unsigned char *head;
    __u16 network_header;
    struct net_device *dev;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return -1;

    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0)
        return -1;

    if (network_header == (__u16)~0U || network_header > 2048)
        return -1;

    /* Read IP header */
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) < 0)
        return -1;

    *src_ip = ip.saddr;
    *dst_ip = ip.daddr;
    *protocol = ip.protocol;

    /* Get interface index */
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_kernel(ifindex, sizeof(*ifindex), &dev->ifindex);
    }

    /* Parse transport header for ports */
    __u16 transport_header;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0)
        return 0;

    if (transport_header == 0 || transport_header == (__u16)~0U) {
        __u8 ihl = ip.ihl & 0x0F;
        transport_header = network_header + (ihl * 4);
    }

    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) == 0) {
            *src_port = tcp.source;
            *dst_port = tcp.dest;
        }
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
            *src_port = udp.source;
            *dst_port = udp.dest;
        }
    }

    return 0;
}

/* Check filters */
static __always_inline bool should_filter(__be32 src_ip, __be32 dst_ip,
                                          __be16 src_port, __be16 dst_port,
                                          __u8 protocol)
{
    if (filter_src_ip && src_ip != filter_src_ip)
        return true;
    if (filter_dst_ip && dst_ip != filter_dst_ip)
        return true;
    if (filter_protocol && protocol != filter_protocol)
        return true;
    if (filter_src_port && src_port != bpf_htons(filter_src_port))
        return true;
    if (filter_dst_port && dst_port != bpf_htons(filter_dst_port))
        return true;
    return false;
}

/* Tracepoint for kfree_skb - main packet drop monitoring point */
SEC("tracepoint/skb/kfree_skb")
int tracepoint_kfree_skb(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    __u32 reason = 0;

    if (!skb)
        return 0;

    /* Get drop reason if available (kernel 5.17+) */
    reason = BPF_CORE_READ_BITFIELD_PROBED(ctx, reason);

    /* Parse packet info */
    __be32 src_ip = 0, dst_ip = 0;
    __be16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;
    __u32 ifindex = 0;

    if (parse_skb_info(skb, &src_ip, &dst_ip, &src_port, &dst_port, &protocol, &ifindex) < 0)
        return 0;

    /* Apply filters */
    if (should_filter(src_ip, dst_ip, src_port, dst_port, protocol))
        return 0;

    /* Get stack trace */
    __s32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);

    /* Update statistics */
    struct drop_key key = {
        .stack_id = stack_id > 0 ? stack_id : 0,
        .drop_reason = reason,
    };

    struct drop_stats *stats = bpf_map_lookup_elem(&drop_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        stats->last_timestamp = bpf_ktime_get_ns();
    } else {
        struct drop_stats new_stats = {
            .count = 1,
            .bytes = 0,
            .last_timestamp = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&drop_stats_map, &key, &new_stats, BPF_ANY);
    }

    /* Output detailed event if enabled */
    if (output_events) {
        struct drop_event *event;
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->drop_reason = reason;
            event->ifindex = ifindex;
            event->protocol = protocol;
            event->src_ip = src_ip;
            event->dst_ip = dst_ip;
            event->src_port = src_port;
            event->dst_port = dst_port;
            event->stack_id = stack_id;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}
