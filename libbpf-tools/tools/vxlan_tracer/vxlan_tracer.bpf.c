// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vxlan_tracer - VXLAN packet tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vxlan_tracer.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __u32 targ_vni = 0;

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* VXLAN header (8 bytes) */
struct vxlanhdr {
    __be32 vx_flags;
    __be32 vx_vni;
};

/* Helper: parse and emit VXLAN event */
static __always_inline void trace_vxlan(struct sk_buff *skb, __u8 direction)
{
    if (!skb)
        return;

    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return;

    __u32 ifindex = BPF_CORE_READ(dev, ifindex);
    if (targ_ifindex && ifindex != targ_ifindex)
        return;

    /* Get packet data */
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);

    if (!head || network_header == (__u16)~0U || network_header > 2048)
        return;

    /* Read outer IP header */
    struct iphdr outer_ip;
    if (bpf_core_read(&outer_ip, sizeof(outer_ip), head + network_header) < 0)
        return;

    /* Check for UDP */
    if (outer_ip.protocol != IPPROTO_UDP)
        return;

    /* Calculate outer UDP offset */
    __u8 ihl = outer_ip.ihl & 0xF;
    if (ihl < 5)
        return;
    __u16 udp_offset = network_header + (ihl * 4);

    /* Read outer UDP header */
    struct udphdr outer_udp;
    if (bpf_core_read(&outer_udp, sizeof(outer_udp), head + udp_offset) < 0)
        return;

    /* Check for VXLAN port (4789 or 8472) */
    __u16 dport = bpf_ntohs(outer_udp.dest);
    if (dport != 4789 && dport != 8472)
        return;

    /* Read VXLAN header */
    __u16 vxlan_offset = udp_offset + sizeof(struct udphdr);
    struct vxlanhdr vxlan;
    if (bpf_core_read(&vxlan, sizeof(vxlan), head + vxlan_offset) < 0)
        return;

    __u32 vni = (bpf_ntohl(vxlan.vx_vni) >> 8) & 0xFFFFFF;

    /* Filter by VNI if specified */
    if (targ_vni && vni != targ_vni)
        return;

    /* Read inner Ethernet + IP */
    __u16 inner_eth_offset = vxlan_offset + sizeof(struct vxlanhdr);
    __u16 inner_ip_offset = inner_eth_offset + 14;  /* Ethernet header */

    struct iphdr inner_ip;
    if (bpf_core_read(&inner_ip, sizeof(inner_ip), head + inner_ip_offset) < 0)
        return;

    /* Emit event */
    struct vxlan_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->dev_name, sizeof(e->dev_name), BPF_CORE_READ(dev, name));

    e->vni = vni;
    e->outer_src = outer_ip.saddr;
    e->outer_dst = outer_ip.daddr;
    e->outer_sport = outer_udp.source;
    e->outer_dport = outer_udp.dest;

    e->inner_src = inner_ip.saddr;
    e->inner_dst = inner_ip.daddr;
    e->inner_proto = inner_ip.protocol;
    e->direction = direction;
    e->len = BPF_CORE_READ(skb, len);

    /* Read inner transport ports if TCP/UDP */
    e->inner_sport = 0;
    e->inner_dport = 0;
    if (inner_ip.protocol == IPPROTO_TCP || inner_ip.protocol == IPPROTO_UDP) {
        __u8 inner_ihl = inner_ip.ihl & 0xF;
        __u16 inner_trans_offset = inner_ip_offset + (inner_ihl * 4);
        struct udphdr inner_trans;
        if (bpf_core_read(&inner_trans, sizeof(inner_trans), head + inner_trans_offset) == 0) {
            e->inner_sport = inner_trans.source;
            e->inner_dport = inner_trans.dest;
        }
    }

    bpf_ringbuf_submit(e, 0);

    /* Update counter */
    __u32 idx = direction;
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* Tracepoint: netif_receive_skb - RX path */
SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_netif_receive_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    trace_vxlan(skb, DIR_RX);
    return 0;
}

/* Tracepoint: net_dev_start_xmit - TX path */
SEC("tracepoint/net/net_dev_start_xmit")
int tracepoint_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    trace_vxlan(skb, DIR_TX);
    return 0;
}
