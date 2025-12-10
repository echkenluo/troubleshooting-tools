// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// trace_conntrack - Connection tracking event tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_conntrack.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 filter_src_ip = 0;
const volatile __be32 filter_dst_ip = 0;
const volatile __u16 filter_src_port = 0;
const volatile __u16 filter_dst_port = 0;
const volatile __u8 filter_protocol = 0;
const volatile bool trace_new = true;
const volatile bool trace_destroy = true;
const volatile bool trace_update = false;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ct_stats_key);
    __type(value, struct ct_stats);
} ct_stats_map SEC(".maps");

/* Helper to check filters */
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

/* Common handler for conntrack events */
static __always_inline int handle_ct_event(void *ctx, struct nf_conn *ct,
                                           __u32 event_type)
{
    struct ct_event *event;
    struct nf_conntrack_tuple *orig, *reply;
    __u8 protocol;
    __be32 src_ip = 0, dst_ip = 0;
    __be16 src_port = 0, dst_port = 0;

    if (!ct)
        return 0;

    /* Get original tuple */
    orig = (struct nf_conntrack_tuple *)BPF_CORE_READ(ct, tuplehash[0].tuple);
    if (!orig)
        return 0;

    /* Read connection info from original direction */
    protocol = BPF_CORE_READ(orig, dst.protonum);
    src_ip = BPF_CORE_READ(orig, src.u3.ip);
    dst_ip = BPF_CORE_READ(orig, dst.u3.ip);

    /* Get ports for TCP/UDP */
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        src_port = BPF_CORE_READ(orig, src.u.all);
        dst_port = BPF_CORE_READ(orig, dst.u.all);
    }

    /* Apply filters */
    if (should_filter(src_ip, dst_ip, src_port, dst_port, protocol))
        return 0;

    /* Check event type filtering */
    if (event_type == CT_EVENT_NEW && !trace_new)
        return 0;
    if (event_type == CT_EVENT_DESTROY && !trace_destroy)
        return 0;
    if (event_type == CT_EVENT_UPDATE && !trace_update)
        return 0;

    /* Update statistics */
    struct ct_stats_key stats_key = {
        .protocol = protocol,
        .state = 0,
    };

    struct ct_stats *stats = bpf_map_lookup_elem(&ct_stats_map, &stats_key);
    if (stats) {
        if (event_type == CT_EVENT_NEW)
            __sync_fetch_and_add(&stats->new_count, 1);
        else if (event_type == CT_EVENT_DESTROY)
            __sync_fetch_and_add(&stats->destroy_count, 1);
        else if (event_type == CT_EVENT_UPDATE)
            __sync_fetch_and_add(&stats->update_count, 1);
    } else {
        struct ct_stats new_stats = {};
        if (event_type == CT_EVENT_NEW)
            new_stats.new_count = 1;
        else if (event_type == CT_EVENT_DESTROY)
            new_stats.destroy_count = 1;
        else if (event_type == CT_EVENT_UPDATE)
            new_stats.update_count = 1;
        bpf_map_update_elem(&ct_stats_map, &stats_key, &new_stats, BPF_ANY);
    }

    /* Output event */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->event_type = event_type;
    event->protocol = protocol;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->mark = BPF_CORE_READ(ct, mark);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* Get reply tuple info */
    reply = (struct nf_conntrack_tuple *)BPF_CORE_READ(ct, tuplehash[1].tuple);
    if (reply) {
        event->reply_src_ip = BPF_CORE_READ(reply, src.u3.ip);
        event->reply_dst_ip = BPF_CORE_READ(reply, dst.u3.ip);
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
            event->reply_src_port = BPF_CORE_READ(reply, src.u.all);
            event->reply_dst_port = BPF_CORE_READ(reply, dst.u.all);
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace nf_conntrack_confirm - new connections */
SEC("kprobe/nf_conntrack_confirm")
int BPF_KPROBE(kprobe_nf_conntrack_confirm, struct sk_buff *skb)
{
    struct nf_conn *ct;

    /* Get conntrack from skb->_nfct */
    ct = (struct nf_conn *)BPF_CORE_READ(skb, _nfct);
    if (!ct)
        return 0;

    /* Clear the lowest bits which store ctinfo */
    ct = (struct nf_conn *)((unsigned long)ct & ~0x7UL);

    return handle_ct_event(ctx, ct, CT_EVENT_NEW);
}

/* Trace nf_ct_destroy - connection destruction */
SEC("kprobe/nf_ct_destroy")
int BPF_KPROBE(kprobe_nf_ct_destroy, struct nf_conntrack *nfct)
{
    struct nf_conn *ct;

    if (!nfct)
        return 0;

    /* nf_conn starts with nf_conntrack */
    ct = (struct nf_conn *)nfct;

    return handle_ct_event(ctx, ct, CT_EVENT_DESTROY);
}

/* Trace __nf_ct_refresh_acct - connection updates */
SEC("kprobe/__nf_ct_refresh_acct")
int BPF_KPROBE(kprobe_nf_ct_refresh_acct, struct nf_conn *ct)
{
    return handle_ct_event(ctx, ct, CT_EVENT_UPDATE);
}
