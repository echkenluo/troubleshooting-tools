// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_performance_metrics - VM Network performance metrics BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vm_network_performance_metrics.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_src_ip = 0;
const volatile __u32 targ_dst_ip = 0;
const volatile __u16 targ_src_port = 0;
const volatile __u16 targ_dst_port = 0;
const volatile __u8 targ_protocol = 0;
const volatile __u8 targ_direction = 0;
const volatile __s32 targ_vm_ifindex = 0;
const volatile __s32 targ_phy_ifindex = 0;

/* Flow sessions map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct flow_data);
} flow_sessions SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Probe statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} probe_stats SEC(".maps");

/* Helper: check if interface matches VM interface */
static __always_inline bool is_vm_interface(const struct sk_buff *skb)
{
    if (targ_vm_ifindex == 0)
        return false;
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;
    int ifindex = BPF_CORE_READ(dev, ifindex);
    return ifindex == targ_vm_ifindex;
}

/* Helper: check if interface matches physical interface */
static __always_inline bool is_phy_interface(const struct sk_buff *skb)
{
    if (targ_phy_ifindex == 0)
        return false;
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;
    int ifindex = BPF_CORE_READ(dev, ifindex);
    return ifindex == targ_phy_ifindex;
}

/* Helper: get IP header */
static __always_inline int get_ip_header(const struct sk_buff *skb, struct iphdr *ip)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);

    if (!head || network_header == (__u16)~0U || network_header > 2048)
        return -1;

    if (bpf_core_read(ip, sizeof(*ip), head + network_header) < 0)
        return -1;

    return 0;
}

/* Helper: get transport header */
static __always_inline int get_transport_header(const struct sk_buff *skb,
                                                  void *hdr, __u16 hdr_size)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    __u16 network_header = BPF_CORE_READ(skb, network_header);

    if (!head)
        return -1;

    if (transport_header == 0 || transport_header == (__u16)~0U ||
        transport_header == network_header) {
        struct iphdr ip;
        if (bpf_core_read(&ip, sizeof(ip), head + network_header) < 0)
            return -1;
        __u8 ip_ihl = ip.ihl & 0x0F;
        if (ip_ihl < 5)
            return -1;
        transport_header = network_header + (ip_ihl * 4);
    }

    if (bpf_core_read(hdr, hdr_size, head + transport_header) < 0)
        return -1;

    return 0;
}

/* Parse packet key */
static __always_inline int parse_packet_key(const struct sk_buff *skb,
                                             struct packet_key *key,
                                             __u8 direction)
{
    struct iphdr ip;

    if (get_ip_header(skb, &ip) != 0)
        return 0;

    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;

    if (targ_src_ip != 0 && ip.saddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.daddr != targ_dst_ip)
        return 0;

    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;

    switch (ip.protocol) {
    case PROTO_TCP: {
        struct tcphdr tcp;
        if (get_transport_header(skb, &tcp, sizeof(tcp)) != 0)
            return 0;
        key->tcp.source = tcp.source;
        key->tcp.dest = tcp.dest;
        key->tcp.seq = tcp.seq;

        if (targ_src_port != 0 &&
            key->tcp.source != bpf_htons(targ_src_port) &&
            key->tcp.dest != bpf_htons(targ_src_port))
            return 0;
        if (targ_dst_port != 0 &&
            key->tcp.source != bpf_htons(targ_dst_port) &&
            key->tcp.dest != bpf_htons(targ_dst_port))
            return 0;
        break;
    }
    case PROTO_UDP: {
        key->udp.id = ip.id;
        struct udphdr udp;
        if (get_transport_header(skb, &udp, sizeof(udp)) == 0) {
            key->udp.source = udp.source;
            key->udp.dest = udp.dest;
            key->udp.len = udp.len;
        }
        if (targ_src_port != 0 &&
            key->udp.source != bpf_htons(targ_src_port) &&
            key->udp.dest != bpf_htons(targ_src_port))
            return 0;
        if (targ_dst_port != 0 &&
            key->udp.source != bpf_htons(targ_dst_port) &&
            key->udp.dest != bpf_htons(targ_dst_port))
            return 0;
        break;
    }
    case PROTO_ICMP: {
        struct icmphdr icmp;
        if (get_transport_header(skb, &icmp, sizeof(icmp)) != 0)
            return 0;
        key->icmp.type = icmp.type;
        key->icmp.code = icmp.code;
        key->icmp.id = icmp.un.echo.id;
        key->icmp.sequence = icmp.un.echo.sequence;
        break;
    }
    default:
        return 0;
    }

    return 1;
}

/* Main event handling function */
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb,
                                                 __u8 stage_id, __u8 direction)
{
    struct packet_key key = {};
    __u64 current_ts = bpf_ktime_get_ns();

    if (!parse_packet_key(skb, &key, direction))
        return;

    bool is_first_stage = false;
    if ((direction == DIR_VNET_RX && stage_id == STG_VNET_RX) ||
        (direction == DIR_VNET_TX && stage_id == STG_PHY_RX))
        is_first_stage = true;

    struct flow_data *flow_ptr;

    if (is_first_stage) {
        struct flow_data zero = {};
        bpf_map_delete_elem(&flow_sessions, &key);
        bpf_map_update_elem(&flow_sessions, &key, &zero, BPF_ANY);

        flow_ptr = bpf_map_lookup_elem(&flow_sessions, &key);
        if (!flow_ptr)
            return;

        flow_ptr->first_pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&flow_ptr->first_comm, sizeof(flow_ptr->first_comm));

        struct net_device *dev = BPF_CORE_READ(skb, dev);
        if (dev)
            bpf_probe_read_kernel_str(flow_ptr->first_ifname, IFNAMSIZ,
                                      BPF_CORE_READ(dev, name));

        flow_ptr->direction = direction;
    } else {
        flow_ptr = bpf_map_lookup_elem(&flow_sessions, &key);
    }

    if (!flow_ptr)
        return;

    /* Record stage info */
    if (stage_id < MAX_STAGES && !flow_ptr->stages[stage_id].valid) {
        struct stage_info *stage = &flow_ptr->stages[stage_id];

        stage->timestamp = current_ts;
        stage->skb_ptr = (__u64)skb;
        stage->cpu = bpf_get_smp_processor_id();

        struct net_device *dev = BPF_CORE_READ(skb, dev);
        if (dev) {
            stage->ifindex = BPF_CORE_READ(dev, ifindex);
            bpf_probe_read_kernel_str(stage->devname, IFNAMSIZ, BPF_CORE_READ(dev, name));
        }

        stage->queue_mapping = BPF_CORE_READ(skb, queue_mapping);
        stage->skb_hash = BPF_CORE_READ(skb, hash);
        stage->len = BPF_CORE_READ(skb, len);
        stage->data_len = BPF_CORE_READ(skb, data_len);
        stage->valid = 1;
        flow_ptr->stage_count++;
    }

    /* Handle qdisc timing */
    if (stage_id == STG_QDISC_ENQ || stage_id == STG_VNET_QDISC_ENQ)
        flow_ptr->qdisc_enq_time = current_ts;

    /* Handle conntrack timing */
    if (stage_id == STG_CT_RX || stage_id == STG_CT_TX)
        flow_ptr->ct_start_time = current_ts;

    if (stage_id == STG_CT_OUT_RX || stage_id == STG_CT_OUT_TX) {
        if (flow_ptr->ct_start_time > 0)
            flow_ptr->ct_lookup_duration = (__u32)(current_ts - flow_ptr->ct_start_time);
    }

    /* Check if last stage */
    bool is_last_stage = false;
    if ((direction == DIR_VNET_RX && stage_id == STG_TX_XMIT) ||
        (direction == DIR_VNET_TX && stage_id == STG_VNET_TX))
        is_last_stage = true;

    if (is_last_stage) {
        struct perf_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->pkt_id = (__u64)skb;
            __builtin_memcpy(&e->key, &key, sizeof(key));
            __builtin_memcpy(&e->flow, flow_ptr, sizeof(e->flow));
            e->timestamp = current_ts;
            e->cpu = bpf_get_smp_processor_id();
            e->stage = stage_id;
            e->event_type = 1;

            struct net_device *dev = BPF_CORE_READ(skb, dev);
            if (dev) {
                e->ifindex = BPF_CORE_READ(dev, ifindex);
                bpf_probe_read_kernel_str(e->devname, IFNAMSIZ, BPF_CORE_READ(dev, name));
            }

            bpf_ringbuf_submit(e, 0);
        }
        bpf_map_delete_elem(&flow_sessions, &key);
    }

    /* Update statistics */
    __u32 stat_idx = stage_id % 32;
    __u64 *counter = bpf_map_lookup_elem(&probe_stats, &stat_idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

/* Probe: netif_receive_skb */
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

    if (is_phy_interface(skb)) {
        if (targ_direction == DIR_VNET_RX)
            return 0;
        handle_stage_event(ctx, skb, STG_PHY_RX, DIR_VNET_TX);
    }

    if (is_vm_interface(skb)) {
        if (targ_direction == DIR_VNET_TX)
            return 0;
        handle_stage_event(ctx, skb, STG_VNET_RX, DIR_VNET_RX);
    }

    return 0;
}

/* Probe: ovs_vport_receive */
SEC("kprobe/ovs_vport_receive")
int BPF_KPROBE(kprobe_ovs_vport_receive, void *vport, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    if (targ_direction != DIR_VNET_TX)
        handle_stage_event(ctx, skb, STG_OVS_RX, DIR_VNET_RX);
    if (targ_direction != DIR_VNET_RX)
        handle_stage_event(ctx, skb, STG_OVS_TX, DIR_VNET_TX);

    return 0;
}

/* Probe: nf_conntrack_in */
SEC("kprobe/nf_conntrack_in")
int BPF_KPROBE(kprobe_nf_conntrack_in, struct net *net, __u8 pf,
               unsigned int hooknum, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    if (targ_direction != DIR_VNET_TX)
        handle_stage_event(ctx, skb, STG_CT_RX, DIR_VNET_RX);
    if (targ_direction != DIR_VNET_RX)
        handle_stage_event(ctx, skb, STG_CT_TX, DIR_VNET_TX);

    return 0;
}

/* Probe: ovs_dp_upcall */
SEC("kprobe/ovs_dp_upcall")
int BPF_KPROBE(kprobe_ovs_dp_upcall, void *dp, const struct sk_buff *skb_const)
{
    struct sk_buff *skb = (struct sk_buff *)skb_const;
    if (!skb)
        return 0;

    if (targ_direction != DIR_VNET_TX)
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_RX, DIR_VNET_RX);
    if (targ_direction != DIR_VNET_RX)
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_TX, DIR_VNET_TX);

    return 0;
}

/* Probe: ovs_flow_key_extract_userspace */
SEC("kprobe/ovs_flow_key_extract_userspace")
int BPF_KPROBE(kprobe_ovs_flow_key_extract, struct net *net,
               const struct nlattr *attr, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    if (targ_direction != DIR_VNET_TX)
        handle_stage_event(ctx, skb, STG_OVS_USERSPACE_RX, DIR_VNET_RX);
    if (targ_direction != DIR_VNET_RX)
        handle_stage_event(ctx, skb, STG_OVS_USERSPACE_TX, DIR_VNET_TX);

    return 0;
}

/* Probe: ovs_ct_update_key */
SEC("kprobe/ovs_ct_update_key")
int BPF_KPROBE(kprobe_ovs_ct_update_key, struct sk_buff *skb, void *info,
               void *key, bool post_ct)
{
    if (!skb)
        return 0;

    if (post_ct) {
        if (targ_direction != DIR_VNET_TX)
            handle_stage_event(ctx, skb, STG_CT_OUT_RX, DIR_VNET_RX);
        if (targ_direction != DIR_VNET_RX)
            handle_stage_event(ctx, skb, STG_CT_OUT_TX, DIR_VNET_TX);
    } else {
        if (targ_direction != DIR_VNET_TX)
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_RX, DIR_VNET_RX);
        if (targ_direction != DIR_VNET_RX)
            handle_stage_event(ctx, skb, STG_FLOW_EXTRACT_END_TX, DIR_VNET_TX);
    }

    return 0;
}

/* Probe: net_dev_queue tracepoint for qdisc enqueue */
SEC("tp/net/net_dev_queue")
int handle_net_dev_queue(void *ctx)
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

    if (is_phy_interface(skb)) {
        if (targ_direction == DIR_VNET_TX)
            return 0;
        handle_stage_event(ctx, skb, STG_QDISC_ENQ, DIR_VNET_RX);
    }

    if (is_vm_interface(skb)) {
        if (targ_direction == DIR_VNET_RX)
            return 0;
        handle_stage_event(ctx, skb, STG_VNET_QDISC_ENQ, DIR_VNET_TX);
    }

    return 0;
}

/* Probe: dev_hard_start_xmit */
SEC("kprobe/dev_hard_start_xmit")
int BPF_KPROBE(kprobe_dev_hard_start_xmit, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    if (is_phy_interface(skb)) {
        if (targ_direction == DIR_VNET_TX)
            return 0;
        handle_stage_event(ctx, skb, STG_TX_QUEUE, DIR_VNET_RX);
    }

    if (is_vm_interface(skb)) {
        if (targ_direction == DIR_VNET_RX)
            return 0;
        handle_stage_event(ctx, skb, STG_VNET_TX, DIR_VNET_TX);
    }

    return 0;
}

/* Probe: dev_queue_xmit_nit for TX completion */
SEC("kprobe/dev_queue_xmit_nit")
int BPF_KPROBE(kprobe_dev_queue_xmit_nit, struct sk_buff *skb)
{
    if (!skb || !is_phy_interface(skb))
        return 0;

    if (targ_direction == DIR_VNET_TX)
        return 0;

    handle_stage_event(ctx, skb, STG_TX_XMIT, DIR_VNET_RX);
    return 0;
}
