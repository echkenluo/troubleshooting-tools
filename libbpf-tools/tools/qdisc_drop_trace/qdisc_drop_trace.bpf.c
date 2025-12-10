// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// qdisc_drop_trace - Queueing discipline drop tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "qdisc_drop_trace.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 filter_ifindex = 0;
const volatile bool trace_events = true;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct qdisc_stats_key);
    __type(value, struct qdisc_stats);
} qdisc_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Parse packet info from skb */
static __always_inline void parse_skb_info(struct sk_buff *skb,
                                           struct qdisc_drop_event *event)
{
    unsigned char *head;
    __u16 network_header;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return;

    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0)
        return;

    if (network_header == (__u16)~0U || network_header > 2048)
        return;

    /* Read IP header */
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) < 0)
        return;

    event->src_ip = ip.saddr;
    event->dst_ip = ip.daddr;
    event->protocol = ip.protocol;

    /* Parse transport header for ports */
    __u16 transport_header;
    if (bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header) < 0)
        return;

    if (transport_header == 0 || transport_header == (__u16)~0U) {
        __u8 ihl = ip.ihl & 0x0F;
        transport_header = network_header + (ihl * 4);
    }

    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + transport_header) == 0) {
            event->src_port = tcp.source;
            event->dst_port = tcp.dest;
        }
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
            event->src_port = udp.source;
            event->dst_port = udp.dest;
        }
    }
}

/* Tracepoint for qdisc drop */
SEC("tracepoint/qdisc/qdisc_drop")
int tracepoint_qdisc_drop(struct trace_event_raw_qdisc_qlen_template *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    struct Qdisc *qdisc;
    struct net_device *dev;
    __u32 ifindex = 0;
    __u32 handle = 0;
    __u32 skb_len = 0;

    if (!skb)
        return 0;

    /* Get qdisc handle from context */
    qdisc = (struct Qdisc *)BPF_CORE_READ(ctx, qdisc);
    if (qdisc) {
        handle = BPF_CORE_READ(qdisc, handle);
    }

    /* Get interface info */
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
    }

    /* Apply interface filter */
    if (filter_ifindex && ifindex != filter_ifindex)
        return 0;

    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);

    /* Update statistics */
    struct qdisc_stats_key key = {
        .ifindex = ifindex,
        .qdisc_handle = handle,
    };

    struct qdisc_stats *stats = bpf_map_lookup_elem(&qdisc_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->drops, 1);
        __sync_fetch_and_add(&stats->bytes, skb_len);
        stats->last_drop_ts = bpf_ktime_get_ns();
    } else {
        struct qdisc_stats new_stats = {
            .drops = 1,
            .bytes = skb_len,
            .last_drop_ts = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&qdisc_stats_map, &key, &new_stats, BPF_ANY);
    }

    /* Output event */
    if (trace_events) {
        struct qdisc_drop_event *event;
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->ifindex = ifindex;
            event->qdisc_handle = handle;
            event->skb_len = skb_len;
            event->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
            bpf_get_current_comm(&event->comm, sizeof(event->comm));

            /* Get interface name */
            if (dev) {
                bpf_probe_read_kernel_str(&event->ifname, IFNAMSIZ, dev->name);
            }

            /* Parse packet info */
            parse_skb_info(skb, event);

            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}

/* Kprobe fallback for qdisc_drop - for kernels without tracepoint */
SEC("kprobe/qdisc_drop")
int BPF_KPROBE(kprobe_qdisc_drop, struct sk_buff *skb, struct Qdisc *qdisc)
{
    struct net_device *dev;
    __u32 ifindex = 0;
    __u32 handle = 0;
    __u32 skb_len = 0;

    if (!skb)
        return 0;

    /* Get qdisc handle */
    if (qdisc) {
        handle = BPF_CORE_READ(qdisc, handle);
    }

    /* Get interface info */
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex);
    }

    /* Apply interface filter */
    if (filter_ifindex && ifindex != filter_ifindex)
        return 0;

    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);

    /* Update statistics */
    struct qdisc_stats_key key = {
        .ifindex = ifindex,
        .qdisc_handle = handle,
    };

    struct qdisc_stats *stats = bpf_map_lookup_elem(&qdisc_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->drops, 1);
        __sync_fetch_and_add(&stats->bytes, skb_len);
        stats->last_drop_ts = bpf_ktime_get_ns();
    } else {
        struct qdisc_stats new_stats = {
            .drops = 1,
            .bytes = skb_len,
            .last_drop_ts = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&qdisc_stats_map, &key, &new_stats, BPF_ANY);
    }

    /* Output event */
    if (trace_events) {
        struct qdisc_drop_event *event;
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->timestamp = bpf_ktime_get_ns();
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->ifindex = ifindex;
            event->qdisc_handle = handle;
            event->skb_len = skb_len;
            event->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
            bpf_get_current_comm(&event->comm, sizeof(event->comm));

            /* Get interface name */
            if (dev) {
                bpf_probe_read_kernel_str(&event->ifname, IFNAMSIZ, dev->name);
            }

            /* Parse packet info */
            parse_skb_info(skb, event);

            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}
