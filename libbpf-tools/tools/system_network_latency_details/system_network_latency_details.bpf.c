// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_latency_details - Detailed system network latency BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "system_network_latency_details.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 filter_src_ip = 0;
const volatile __be32 filter_dst_ip = 0;
const volatile __u16 filter_src_port = 0;
const volatile __u16 filter_dst_port = 0;
const volatile __u8 filter_protocol = 0;
const volatile __u32 target_ifindex = 0;
const volatile __u8 direction = 1;  /* 1=tx, 2=rx */

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct flow_data);
} flow_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Parse packet key from skb */
static __always_inline int parse_packet_key(struct sk_buff *skb,
                                            struct packet_key *key,
                                            __u8 stage_id)
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

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    /* Apply filters */
    if (filter_protocol && ip.protocol != filter_protocol)
        return -1;
    if (filter_src_ip && ip.saddr != filter_src_ip && ip.daddr != filter_src_ip)
        return -1;
    if (filter_dst_ip && ip.saddr != filter_dst_ip && ip.daddr != filter_dst_ip)
        return -1;

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
            key->src_port = tcp.source;
            key->dst_port = tcp.dest;
            key->seq = bpf_ntohl(tcp.seq);
        }
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
            key->src_port = udp.source;
            key->dst_port = udp.dest;
            key->seq = bpf_ntohs(ip.id);
        }
    }

    /* Apply port filters */
    if (filter_src_port && key->src_port != bpf_htons(filter_src_port))
        return -1;
    if (filter_dst_port && key->dst_port != bpf_htons(filter_dst_port))
        return -1;

    return 0;
}

/* Check if interface matches target */
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

/* Common event handler */
static __always_inline void handle_stage(void *ctx, struct sk_buff *skb,
                                         __u8 stage_id, bool is_start, bool is_end)
{
    struct packet_key key = {};
    struct flow_data *flow;

    if (!skb)
        return;

    if (parse_packet_key(skb, &key, stage_id) < 0)
        return;

    __u64 ts = bpf_ktime_get_ns();
    __s32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);

    if (is_start) {
        /* Create new flow entry */
        struct flow_data new_flow = {};
        new_flow.ts[stage_id] = ts;
        new_flow.skb_ptr[stage_id] = (__u64)skb;
        new_flow.stack_id[stage_id] = stack_id;
        new_flow.pid = bpf_get_current_pid_tgid() >> 32;
        new_flow.direction = direction;
        new_flow.saw_start = 1;
        bpf_get_current_comm(&new_flow.comm, sizeof(new_flow.comm));

        struct net_device *dev;
        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
            bpf_probe_read_kernel_str(&new_flow.ifname, IFNAMSIZ, dev->name);
        }

        bpf_map_update_elem(&flow_sessions, &key, &new_flow, BPF_ANY);
        return;
    }

    flow = bpf_map_lookup_elem(&flow_sessions, &key);
    if (!flow)
        return;

    /* Update timestamp for this stage */
    if (flow->ts[stage_id] == 0) {
        flow->ts[stage_id] = ts;
        flow->skb_ptr[stage_id] = (__u64)skb;
        flow->stack_id[stage_id] = stack_id;
    }

    if (is_end) {
        flow->saw_end = 1;

        /* Submit event */
        struct latency_event *event;
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            event->key = key;
            __builtin_memcpy(&event->data, flow, sizeof(event->data));
            bpf_ringbuf_submit(event, 0);
        }

        bpf_map_delete_elem(&flow_sessions, &key);
    }
}

/* TX path probes */
SEC("kprobe/__ip_queue_xmit")
int BPF_KPROBE(kprobe_ip_queue_xmit, struct sock *sk, struct sk_buff *skb)
{
    if (direction == 2) return 0;
    handle_stage(ctx, skb, TX_STAGE_0, true, false);
    return 0;
}

SEC("kprobe/ip_send_skb")
int BPF_KPROBE(kprobe_ip_send_skb, struct net *net, struct sk_buff *skb)
{
    if (direction == 2) return 0;
    handle_stage(ctx, skb, TX_STAGE_0, true, false);
    return 0;
}

SEC("kprobe/internal_dev_xmit")
int BPF_KPROBE(kprobe_internal_dev_xmit, struct sk_buff *skb)
{
    if (direction == 2) return 0;
    handle_stage(ctx, skb, TX_STAGE_1, false, false);
    return 0;
}

SEC("kprobe/ovs_dp_process_packet")
int BPF_KPROBE(kprobe_ovs_dp_process_packet, struct sk_buff *skb)
{
    if (direction == 1)
        handle_stage(ctx, skb, TX_STAGE_2, false, false);
    else
        handle_stage(ctx, skb, RX_STAGE_2, false, false);
    return 0;
}

SEC("kprobe/ovs_dp_upcall")
int BPF_KPROBE(kprobe_ovs_dp_upcall, void *dp, struct sk_buff *skb)
{
    if (direction == 1)
        handle_stage(ctx, skb, TX_STAGE_3, false, false);
    else
        handle_stage(ctx, skb, RX_STAGE_3, false, false);
    return 0;
}

SEC("kprobe/ovs_vport_send")
int BPF_KPROBE(kprobe_ovs_vport_send, void *vport, struct sk_buff *skb)
{
    if (direction == 1)
        handle_stage(ctx, skb, TX_STAGE_5, false, false);
    else
        handle_stage(ctx, skb, RX_STAGE_5, false, false);
    return 0;
}

SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    if (direction == 2) return 0;
    if (!is_target_ifindex(skb)) return 0;
    handle_stage(ctx, skb, TX_STAGE_6, false, true);
    return 0;
}

/* RX path probes */
SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    if (direction == 1) return 0;
    if (!is_target_ifindex(skb)) return 0;
    handle_stage(ctx, skb, RX_STAGE_0, true, false);
    return 0;
}

SEC("kprobe/netdev_frame_hook")
int BPF_KPROBE(kprobe_netdev_frame_hook, struct sk_buff **pskb)
{
    struct sk_buff *skb = NULL;
    if (direction == 1) return 0;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || !skb)
        return 0;
    handle_stage(ctx, skb, RX_STAGE_1, false, false);
    return 0;
}

SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(kprobe_tcp_v4_rcv, struct sk_buff *skb)
{
    if (direction == 1) return 0;
    if (filter_protocol && filter_protocol != IPPROTO_TCP) return 0;
    handle_stage(ctx, skb, RX_STAGE_6, false, true);
    return 0;
}

SEC("kprobe/__udp4_lib_rcv")
int BPF_KPROBE(kprobe_udp4_lib_rcv, struct sk_buff *skb)
{
    if (direction == 1) return 0;
    if (filter_protocol && filter_protocol != IPPROTO_UDP) return 0;
    handle_stage(ctx, skb, RX_STAGE_6, false, true);
    return 0;
}
