// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_kernel_drop_monitor - OVS kernel module drop monitoring BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ovs_kernel_drop_monitor.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 filter_src_ip = 0;
const volatile __be32 filter_dst_ip = 0;
const volatile __u16 filter_src_port = 0;
const volatile __u16 filter_dst_port = 0;
const volatile __u8 filter_protocol = 0;
const volatile bool output_events = true;

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
    __type(key, struct ovs_drop_key);
    __type(value, struct ovs_drop_stats);
} drop_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Parse packet info from skb */
static __always_inline int parse_skb_info(struct sk_buff *skb,
                                          struct ovs_drop_event *event)
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

    event->src_ip = ip.saddr;
    event->dst_ip = ip.daddr;
    event->protocol = ip.protocol;

    /* Get interface info */
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_kernel(&event->ifindex, sizeof(event->ifindex), &dev->ifindex);
        bpf_probe_read_kernel_str(&event->ifname, IFNAMSIZ, dev->name);
    }

    /* Parse transport header */
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

    return 0;
}

/* Check filters */
static __always_inline bool should_filter(struct ovs_drop_event *event)
{
    if (filter_src_ip && event->src_ip != filter_src_ip)
        return true;
    if (filter_dst_ip && event->dst_ip != filter_dst_ip)
        return true;
    if (filter_protocol && event->protocol != filter_protocol)
        return true;
    if (filter_src_port && event->src_port != bpf_htons(filter_src_port))
        return true;
    if (filter_dst_port && event->dst_port != bpf_htons(filter_dst_port))
        return true;
    return false;
}

/* Common handler for OVS drops */
static __always_inline int handle_ovs_drop(void *ctx, struct sk_buff *skb,
                                           __u32 drop_reason)
{
    struct ovs_drop_event *event;
    __u32 skb_len = 0;

    if (!skb)
        return 0;

    bpf_probe_read_kernel(&skb_len, sizeof(skb_len), &skb->len);

    /* Get stack trace */
    __s32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);

    /* Update statistics */
    struct ovs_drop_key key = {
        .drop_reason = drop_reason,
        .stack_id = stack_id > 0 ? stack_id : 0,
    };

    struct ovs_drop_stats *stats = bpf_map_lookup_elem(&drop_stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        __sync_fetch_and_add(&stats->bytes, skb_len);
        stats->last_timestamp = bpf_ktime_get_ns();
    } else {
        struct ovs_drop_stats new_stats = {
            .count = 1,
            .bytes = skb_len,
            .last_timestamp = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&drop_stats_map, &key, &new_stats, BPF_ANY);
    }

    /* Output event */
    if (output_events) {
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            __builtin_memset(event, 0, sizeof(*event));
            event->timestamp = bpf_ktime_get_ns();
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->drop_reason = drop_reason;
            event->stack_id = stack_id;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));

            /* Parse packet info */
            if (parse_skb_info(skb, event) < 0 || should_filter(event)) {
                bpf_ringbuf_discard(event, 0);
                return 0;
            }

            bpf_ringbuf_submit(event, 0);
        }
    }

    return 0;
}

/* Trace ovs_dp_process_packet exit - packets not matched */
SEC("kretprobe/ovs_dp_process_packet")
int BPF_KRETPROBE(kretprobe_ovs_dp_process_packet, int ret)
{
    if (ret != 0) {
        /* Can't easily get skb in kretprobe, just update simple stats */
        struct ovs_drop_key key = {
            .drop_reason = OVS_DROP_UNKNOWN,
            .stack_id = 0,
        };

        struct ovs_drop_stats *stats = bpf_map_lookup_elem(&drop_stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->count, 1);
        } else {
            struct ovs_drop_stats new_stats = {
                .count = 1,
                .last_timestamp = bpf_ktime_get_ns(),
            };
            bpf_map_update_elem(&drop_stats_map, &key, &new_stats, BPF_ANY);
        }
    }
    return 0;
}

/* Trace ovs_vport_receive - track incoming packets for drop analysis */
SEC("kprobe/ovs_vport_receive")
int BPF_KPROBE(kprobe_ovs_vport_receive, void *vport, struct sk_buff *skb)
{
    /* This is an entry point, we'll track it in conjunction with drops */
    return 0;
}

/* Trace kfree_skb in OVS context */
SEC("tracepoint/skb/kfree_skb")
int tracepoint_kfree_skb_ovs(struct trace_event_raw_kfree_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    char comm[TASK_COMM_LEN];

    if (!skb)
        return 0;

    /* Get current comm to check if we're in OVS context */
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Check if comm contains "ovs" or is a known OVS worker */
    bool is_ovs = false;
    if (comm[0] == 'o' && comm[1] == 'v' && comm[2] == 's')
        is_ovs = true;
    if (comm[0] == 'h' && comm[1] == 'a' && comm[2] == 'n') /* handler */
        is_ovs = true;

    if (!is_ovs)
        return 0;

    return handle_ovs_drop(ctx, skb, OVS_DROP_UNKNOWN);
}

/* Trace ovs_flow_cmd_del - flow deletion */
SEC("kprobe/ovs_flow_cmd_del")
int BPF_KPROBE(kprobe_ovs_flow_cmd_del)
{
    /* Flow deletion tracking */
    return 0;
}
