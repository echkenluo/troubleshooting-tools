// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// trace_ip_defrag - IP fragmentation/defragmentation tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_ip_defrag.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 filter_src_ip = 0;
const volatile __be32 filter_dst_ip = 0;
const volatile __u8 filter_protocol = 0;
const volatile bool trace_events = true;

/* IP fragment flags */
#define IP_MF 0x2000      /* More Fragments flag */
#define IP_OFFSET 0x1FFF  /* Fragment offset mask */

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 32 * sizeof(__u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct frag_stats_key);
    __type(value, struct frag_stats);
} frag_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_frag_stats);
} global_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Check filters */
static __always_inline bool should_filter(__be32 src_ip, __be32 dst_ip,
                                          __u8 protocol)
{
    if (filter_src_ip && src_ip != filter_src_ip)
        return true;
    if (filter_dst_ip && dst_ip != filter_dst_ip)
        return true;
    if (filter_protocol && protocol != filter_protocol)
        return true;
    return false;
}

/* Update global statistics */
static __always_inline void update_global_stats(__u32 event_type, __u32 bytes)
{
    __u32 key = 0;
    struct global_frag_stats *stats = bpf_map_lookup_elem(&global_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_fragments, 1);
        __sync_fetch_and_add(&stats->total_bytes, bytes);
        if (event_type == FRAG_EVENT_COMPLETE)
            __sync_fetch_and_add(&stats->reassembled, 1);
        else if (event_type == FRAG_EVENT_TIMEOUT)
            __sync_fetch_and_add(&stats->timeouts, 1);
        else if (event_type == FRAG_EVENT_DROP)
            __sync_fetch_and_add(&stats->drops, 1);
    }
}

/* Common handler for fragment events */
static __always_inline int handle_frag_event(void *ctx, struct sk_buff *skb,
                                             __u32 event_type)
{
    struct frag_event *event;
    struct iphdr ip;
    unsigned char *head;
    __u16 network_header;
    __u16 frag_off;
    struct net_device *dev;

    if (!skb)
        return 0;

    /* Get IP header */
    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        return 0;
    if (bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header) < 0)
        return 0;
    if (network_header == (__u16)~0U || network_header > 2048)
        return 0;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) < 0)
        return 0;

    /* Check if this is a fragment */
    frag_off = bpf_ntohs(ip.frag_off);
    bool is_fragment = (frag_off & IP_MF) || (frag_off & IP_OFFSET);

    if (!is_fragment && event_type == FRAG_EVENT_RECV)
        return 0;

    /* Apply filters */
    if (should_filter(ip.saddr, ip.daddr, ip.protocol))
        return 0;

    /* Update per-flow statistics */
    struct frag_stats_key stats_key = {
        .src_ip = ip.saddr,
        .dst_ip = ip.daddr,
        .ip_id = ip.id,
    };

    struct frag_stats *stats = bpf_map_lookup_elem(&frag_stats_map, &stats_key);
    __u64 now = bpf_ktime_get_ns();
    __u32 skb_len = 0;
    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);

    if (stats) {
        __sync_fetch_and_add(&stats->fragments_recv, 1);
        __sync_fetch_and_add(&stats->bytes_recv, skb_len);
        stats->last_seen_ns = now;
        if (event_type == FRAG_EVENT_COMPLETE)
            __sync_fetch_and_add(&stats->reassembled, 1);
        else if (event_type == FRAG_EVENT_TIMEOUT)
            __sync_fetch_and_add(&stats->timeouts, 1);
        else if (event_type == FRAG_EVENT_DROP)
            __sync_fetch_and_add(&stats->drops, 1);
    } else {
        struct frag_stats new_stats = {
            .fragments_recv = 1,
            .bytes_recv = skb_len,
            .first_seen_ns = now,
            .last_seen_ns = now,
        };
        if (event_type == FRAG_EVENT_COMPLETE)
            new_stats.reassembled = 1;
        else if (event_type == FRAG_EVENT_TIMEOUT)
            new_stats.timeouts = 1;
        else if (event_type == FRAG_EVENT_DROP)
            new_stats.drops = 1;
        bpf_map_update_elem(&frag_stats_map, &stats_key, &new_stats, BPF_ANY);
    }

    /* Update global stats */
    update_global_stats(event_type, skb_len);

    /* Output event */
    if (trace_events) {
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->timestamp = now;
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->event_type = event_type;
            event->src_ip = ip.saddr;
            event->dst_ip = ip.daddr;
            event->ip_id = bpf_ntohs(ip.id);
            event->frag_offset = (frag_off & IP_OFFSET) * 8;
            event->total_len = bpf_ntohs(ip.tot_len);
            event->data_len = skb_len;
            event->protocol = ip.protocol;
            event->more_frags = (frag_off & IP_MF) ? 1 : 0;
            event->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
            bpf_get_current_comm(&event->comm, sizeof(event->comm));

            /* Get interface info */
            if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
                bpf_probe_read_kernel(&event->ifindex, sizeof(event->ifindex), &dev->ifindex);
                bpf_probe_read_kernel_str(&event->ifname, IFNAMSIZ, dev->name);
            }

            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}

/* Trace ip_defrag - fragment queue entry */
SEC("kprobe/ip_defrag")
int BPF_KPROBE(kprobe_ip_defrag, struct net *net, struct sk_buff *skb, __u32 user)
{
    return handle_frag_event(ctx, skb, FRAG_EVENT_RECV);
}

/* Trace ip_frag_queue - fragment queued for reassembly */
SEC("kprobe/ip_frag_queue")
int BPF_KPROBE(kprobe_ip_frag_queue, struct ipq *qp, struct sk_buff *skb)
{
    return handle_frag_event(ctx, skb, FRAG_EVENT_RECV);
}

/* Trace ip_frag_reasm - reassembly complete */
SEC("kprobe/ip_frag_reasm")
int BPF_KPROBE(kprobe_ip_frag_reasm, struct ipq *qp, struct sk_buff *skb)
{
    return handle_frag_event(ctx, skb, FRAG_EVENT_COMPLETE);
}

/* Trace inet_frag_destroy - fragment queue destroyed (timeout or drop) */
SEC("kprobe/inet_frag_destroy")
int BPF_KPROBE(kprobe_inet_frag_destroy, struct inet_frag_queue *q)
{
    /* This catches both timeouts and explicit drops */
    /* We can't easily get the skb here, so just update global stats */
    __u32 key = 0;
    struct global_frag_stats *stats = bpf_map_lookup_elem(&global_stats, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->timeouts, 1);
    }
    return 0;
}
