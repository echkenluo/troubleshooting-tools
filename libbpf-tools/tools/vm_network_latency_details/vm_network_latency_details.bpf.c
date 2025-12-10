// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_latency_details - VM Network detailed latency tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "vm_network_latency_details.h"

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

/* Stack traces */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Packet counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

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
                                             struct packet_key *key)
{
    struct iphdr ip;

    if (get_ip_header(skb, &ip) != 0)
        return 0;

    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;

    if (targ_src_ip != 0 && ip.saddr != targ_src_ip && ip.daddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.saddr != targ_dst_ip && ip.daddr != targ_dst_ip)
        return 0;

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    if (ip.protocol == PROTO_TCP) {
        struct tcphdr tcp;
        if (get_transport_header(skb, &tcp, sizeof(tcp)) != 0)
            return 0;

        key->tcp.src_port = tcp.source;
        key->tcp.dst_port = tcp.dest;
        key->tcp.seq = tcp.seq;

        if (targ_src_port != 0 &&
            key->tcp.src_port != bpf_htons(targ_src_port) &&
            key->tcp.dst_port != bpf_htons(targ_src_port))
            return 0;
        if (targ_dst_port != 0 &&
            key->tcp.src_port != bpf_htons(targ_dst_port) &&
            key->tcp.dst_port != bpf_htons(targ_dst_port))
            return 0;
    } else if (ip.protocol == PROTO_UDP) {
        struct udphdr udp;
        if (get_transport_header(skb, &udp, sizeof(udp)) == 0) {
            key->udp.src_port = udp.source;
            key->udp.dst_port = udp.dest;
            key->udp.ip_id = ip.id;

            if (targ_src_port != 0 &&
                key->udp.src_port != bpf_htons(targ_src_port) &&
                key->udp.dst_port != bpf_htons(targ_src_port))
                return 0;
            if (targ_dst_port != 0 &&
                key->udp.src_port != bpf_htons(targ_dst_port) &&
                key->udp.dst_port != bpf_htons(targ_dst_port))
                return 0;
        }
    } else if (ip.protocol == PROTO_ICMP) {
        struct icmphdr icmp;
        if (get_transport_header(skb, &icmp, sizeof(icmp)) == 0) {
            key->icmp.id = icmp.un.echo.id;
            key->icmp.seq = icmp.un.echo.sequence;
            key->icmp.type = icmp.type;
            key->icmp.code = icmp.code;
        }
    } else {
        return 0;
    }

    return 1;
}

/* Main stage event handler */
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb,
                                                 __u8 stage_id, __u8 direction)
{
    struct packet_key key = {};
    __u64 current_ts = bpf_ktime_get_ns();

    if (!parse_packet_key(skb, &key))
        return;

    __u8 first_stage = (direction == DIRECTION_RX) ? RX_STAGE_0 : TX_STAGE_0;
    __u8 last_stage = (direction == DIRECTION_RX) ? RX_STAGE_6 : TX_STAGE_6;

    bool is_first = (stage_id == first_stage);
    struct flow_data *flow_ptr;

    if (is_first) {
        struct flow_data zero = {};
        zero.direction = direction;
        zero.first_seen_ns = current_ts;

        bpf_map_delete_elem(&flow_sessions, &key);
        bpf_map_update_elem(&flow_sessions, &key, &zero, BPF_ANY);

        flow_ptr = bpf_map_lookup_elem(&flow_sessions, &key);
        if (!flow_ptr)
            return;

        if (direction == DIRECTION_RX) {
            flow_ptr->rx_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->rx_comm, sizeof(flow_ptr->rx_comm));
            struct net_device *dev = BPF_CORE_READ(skb, dev);
            if (dev)
                bpf_probe_read_kernel_str(flow_ptr->rx_vnet_ifname, IFNAMSIZ, BPF_CORE_READ(dev, name));
            flow_ptr->rx_start = 1;
        } else {
            flow_ptr->tx_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->tx_comm, sizeof(flow_ptr->tx_comm));
            struct net_device *dev = BPF_CORE_READ(skb, dev);
            if (dev)
                bpf_probe_read_kernel_str(flow_ptr->tx_pnic_ifname, IFNAMSIZ, BPF_CORE_READ(dev, name));
            flow_ptr->tx_start = 1;
        }
    } else {
        flow_ptr = bpf_map_lookup_elem(&flow_sessions, &key);
        if (!flow_ptr)
            return;
    }

    if (stage_id < MAX_STAGES && flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->skb_ptr[stage_id] = (__u64)skb;
        flow_ptr->kstack_id[stage_id] = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
    }

    if (stage_id == RX_STAGE_6) {
        struct net_device *dev = BPF_CORE_READ(skb, dev);
        if (dev)
            bpf_probe_read_kernel_str(flow_ptr->tx_pnic_ifname, IFNAMSIZ, BPF_CORE_READ(dev, name));
        flow_ptr->rx_end = 1;
    } else if (stage_id == TX_STAGE_6) {
        struct net_device *dev = BPF_CORE_READ(skb, dev);
        if (dev)
            bpf_probe_read_kernel_str(flow_ptr->rx_vnet_ifname, IFNAMSIZ, BPF_CORE_READ(dev, name));
        flow_ptr->tx_end = 1;
    }

    bool is_complete = false;
    if (direction == DIRECTION_RX && flow_ptr->rx_start && flow_ptr->rx_end)
        is_complete = true;
    if (direction == DIRECTION_TX && flow_ptr->tx_start && flow_ptr->tx_end)
        is_complete = true;

    if (is_complete) {
        struct latency_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            __builtin_memcpy(&e->key, &key, sizeof(key));
            __builtin_memcpy(&e->data, flow_ptr, sizeof(e->data));
            e->event_ts = current_ts;
            bpf_ringbuf_submit(e, 0);
        }
        bpf_map_delete_elem(&flow_sessions, &key);

        __u32 idx = (direction == DIRECTION_RX) ? 0 : 1;
        __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
    }
}

/* Probe: netif_receive_skb tracepoint */
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

    if (targ_direction != DIRECTION_TX && is_vm_interface(skb))
        handle_stage_event(ctx, skb, RX_STAGE_0, DIRECTION_RX);

    if (targ_direction != DIRECTION_RX && is_phy_interface(skb))
        handle_stage_event(ctx, skb, TX_STAGE_0, DIRECTION_TX);

    return 0;
}

/* Probe: netdev_frame_hook */
SEC("kprobe/netdev_frame_hook")
int BPF_KPROBE(kprobe_netdev_frame_hook, struct sk_buff **pskb)
{
    struct sk_buff *skb = NULL;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), pskb) < 0 || !skb)
        return 0;

    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_1, DIRECTION_RX);
    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_1, DIRECTION_TX);

    return 0;
}

/* Probe: ovs_dp_process_packet */
SEC("kprobe/ovs_dp_process_packet")
int BPF_KPROBE(kprobe_ovs_dp_process, const struct sk_buff *skb_const)
{
    struct sk_buff *skb = (struct sk_buff *)skb_const;

    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_2, DIRECTION_RX);
    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_2, DIRECTION_TX);

    return 0;
}

/* Probe: ovs_dp_upcall */
SEC("kprobe/ovs_dp_upcall")
int BPF_KPROBE(kprobe_ovs_upcall, void *dp, const struct sk_buff *skb_const)
{
    struct sk_buff *skb = (struct sk_buff *)skb_const;

    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_3, DIRECTION_RX);
    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_3, DIRECTION_TX);

    return 0;
}

/* Probe: ovs_flow_key_extract_userspace */
SEC("kprobe/ovs_flow_key_extract_userspace")
int BPF_KPROBE(kprobe_ovs_flow_extract, struct net *net, const struct nlattr *attr,
               struct sk_buff *skb)
{
    if (!skb)
        return 0;

    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_4, DIRECTION_RX);
    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_4, DIRECTION_TX);

    return 0;
}

/* Probe: ovs_vport_send */
SEC("kprobe/ovs_vport_send")
int BPF_KPROBE(kprobe_ovs_vport_send, const void *vport, struct sk_buff *skb)
{
    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_5, DIRECTION_RX);
    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_5, DIRECTION_TX);

    return 0;
}

/* Probe: __dev_queue_xmit (RX direction end) */
SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_TX)
        return 0;

    if (!is_phy_interface(skb))
        return 0;

    handle_stage_event(ctx, skb, RX_STAGE_6, DIRECTION_RX);
    return 0;
}

/* Probe: tun_net_xmit (TX direction end) */
SEC("kprobe/tun_net_xmit")
int BPF_KPROBE(kprobe_tun_net_xmit, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_RX)
        return 0;

    handle_stage_event(ctx, skb, TX_STAGE_6, DIRECTION_TX);
    return 0;
}
