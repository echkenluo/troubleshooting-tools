// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_latency_summary - VM Network stack latency tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bits.bpf.h"
#include "vm_network_latency_summary.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_src_ip = 0;
const volatile __u32 targ_dst_ip = 0;
const volatile __u16 targ_src_port = 0;
const volatile __u16 targ_dst_port = 0;
const volatile __u8 targ_protocol = 0;       /* 0=all, 1=ICMP, 6=TCP, 17=UDP */
const volatile __u8 targ_direction = 0;      /* 1=VNET_RX, 2=VNET_TX */
const volatile __s32 targ_vm_ifindex = 0;    /* VM interface index */
const volatile __s32 targ_phy_ifindex = 0;   /* Physical interface index */

/* Flow sessions map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct flow_data);
} flow_sessions SEC(".maps");

/* Adjacent stage latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct stage_pair_key);
    __type(value, struct stage_pair_hist);
} adjacent_latency_hist SEC(".maps");

/* Total end-to-end latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct total_hist);
} total_latency_hist SEC(".maps");

/* Packet counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} packet_counters SEC(".maps");

/* Flow stage counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FSC);
    __type(key, __u32);
    __type(value, __u64);
} flow_stage_counters SEC(".maps");

/* Helper: check if interface matches VM interface */
static __always_inline bool is_vm_interface(const struct sk_buff *skb)
{
    struct net_device *dev;
    int ifindex;

    if (targ_vm_ifindex == 0)
        return false;

    dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;

    ifindex = BPF_CORE_READ(dev, ifindex);
    return ifindex == targ_vm_ifindex;
}

/* Helper: check if interface matches physical interface */
static __always_inline bool is_phy_interface(const struct sk_buff *skb)
{
    struct net_device *dev;
    int ifindex;

    if (targ_phy_ifindex == 0)
        return false;

    dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;

    ifindex = BPF_CORE_READ(dev, ifindex);
    return ifindex == targ_phy_ifindex;
}

/* Helper: get IP header */
static __always_inline int get_ip_header(const struct sk_buff *skb, struct iphdr *ip)
{
    unsigned char *head;
    __u16 network_header;

    head = BPF_CORE_READ(skb, head);
    network_header = BPF_CORE_READ(skb, network_header);

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
    unsigned char *head;
    __u16 transport_header;
    __u16 network_header;

    head = BPF_CORE_READ(skb, head);
    transport_header = BPF_CORE_READ(skb, transport_header);
    network_header = BPF_CORE_READ(skb, network_header);

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

    /* Apply protocol filter */
    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;

    /* Direction-specific IP filtering */
    if (targ_src_ip != 0 && ip.saddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.daddr != targ_dst_ip)
        return 0;

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    /* Parse transport layer */
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
            key->udp.udp_len = udp.len;
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

/* Update histogram */
static __always_inline void update_adjacent_hist(__u8 prev_stage, __u8 curr_stage,
                                                   __u8 direction, __u64 latency_us)
{
    struct stage_pair_key pair_key = {
        .prev_stage = prev_stage,
        .curr_stage = curr_stage,
        .direction = direction,
    };

    struct stage_pair_hist *hist = bpf_map_lookup_elem(&adjacent_latency_hist, &pair_key);
    if (!hist) {
        struct stage_pair_hist zero = {};
        bpf_map_update_elem(&adjacent_latency_hist, &pair_key, &zero, BPF_NOEXIST);
        hist = bpf_map_lookup_elem(&adjacent_latency_hist, &pair_key);
        if (!hist)
            return;
    }

    __u64 slot = log2l(latency_us + 1);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    __sync_fetch_and_add(&hist->slots[slot], 1);
}

/* Update total latency histogram */
static __always_inline void update_total_hist(__u64 latency_us)
{
    __u32 key = 0;
    struct total_hist *hist = bpf_map_lookup_elem(&total_latency_hist, &key);
    if (!hist)
        return;

    __u64 slot = log2l(latency_us);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    hist->slots[slot]++;
}

/* Increment counter */
static __always_inline void inc_counter(__u32 idx)
{
    __u64 *counter = bpf_map_lookup_elem(&packet_counters, &idx);
    if (counter)
        (*counter)++;
}

/* Increment flow stage counter */
static __always_inline void inc_fsc(__u32 idx)
{
    __u64 *counter = bpf_map_lookup_elem(&flow_stage_counters, &idx);
    if (counter)
        (*counter)++;
}

/* Main stage event handler */
static __always_inline void handle_stage_event(void *ctx, struct sk_buff *skb,
                                                 __u8 stage_id, __u8 direction)
{
    struct packet_key key = {};
    __u64 current_ts = bpf_ktime_get_ns();

    if (!parse_packet_key(skb, &key, direction))
        return;

    /* Determine first and last stages */
    __u8 first_stage = (direction == DIRECTION_VNET_RX) ? STG_VNET_RX : STG_PHY_RX;
    __u8 last_stage = (direction == DIRECTION_VNET_RX) ? STG_TX_XMIT : STG_VNET_TX;

    bool is_first_stage = (stage_id == first_stage);
    struct flow_data *flow_ptr;

    if (is_first_stage) {
        struct flow_data zero = {
            .direction = direction,
            .last_stage = stage_id,
            .last_timestamp = current_ts,
            .first_timestamp = current_ts,
        };

        bpf_map_delete_elem(&flow_sessions, &key);
        bpf_map_update_elem(&flow_sessions, &key, &zero, BPF_ANY);

        inc_counter(direction);
        inc_fsc(direction == DIRECTION_VNET_RX ? FSC_FIRST_RX : FSC_FIRST_TX);
        return;
    }

    flow_ptr = bpf_map_lookup_elem(&flow_sessions, &key);
    if (!flow_ptr) {
        bpf_map_delete_elem(&flow_sessions, &key);
        return;
    }

    /* Calculate and record latency */
    if (flow_ptr->last_timestamp > 0 && flow_ptr->last_timestamp < current_ts) {
        __u64 latency_ns = current_ts - flow_ptr->last_timestamp;
        __u64 latency_us = latency_ns / 1000;

        update_adjacent_hist(flow_ptr->last_stage, stage_id, direction, latency_us);
    }

    /* Update tracking */
    flow_ptr->last_stage = stage_id;
    flow_ptr->last_timestamp = current_ts;

    /* Check if last stage */
    bool is_last_stage = (stage_id == last_stage);

    if (is_last_stage) {
        if (flow_ptr->first_timestamp > 0 && current_ts > flow_ptr->first_timestamp) {
            __u64 total_latency_us = (current_ts - flow_ptr->first_timestamp) / 1000;
            if (total_latency_us > 0)
                update_total_hist(total_latency_us);
        }

        inc_fsc(direction == DIRECTION_VNET_RX ? FSC_LAST_RX : FSC_LAST_TX);
        bpf_map_delete_elem(&flow_sessions, &key);
    }
}

/* ========== Probe Points ========== */

/* VNET RX: netif_receive_skb (VM interface) */
SEC("tp/net/netif_receive_skb")
int handle_vnet_rx(void *ctx)
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

    if (targ_direction == DIRECTION_VNET_TX)
        return 0;

    if (!is_vm_interface(skb))
        return 0;

    handle_stage_event(ctx, skb, STG_VNET_RX, DIRECTION_VNET_RX);
    return 0;
}

/* Physical RX: netif_receive_skb (Physical interface) */
SEC("kprobe/__netif_receive_skb_core")
int BPF_KPROBE(kprobe_phy_rx, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_VNET_RX)
        return 0;

    if (!is_phy_interface(skb))
        return 0;

    handle_stage_event(ctx, skb, STG_PHY_RX, DIRECTION_VNET_TX);
    return 0;
}

/* OVS: ovs_dp_process_packet */
SEC("kprobe/ovs_dp_process_packet")
int BPF_KPROBE(kprobe_ovs_dp_process, const struct sk_buff *skb_const)
{
    struct sk_buff *skb = (struct sk_buff *)skb_const;

    if (targ_direction != DIRECTION_VNET_TX)
        handle_stage_event(ctx, skb, STG_OVS_RX, DIRECTION_VNET_RX);
    if (targ_direction != DIRECTION_VNET_RX)
        handle_stage_event(ctx, skb, STG_OVS_TX, DIRECTION_VNET_TX);

    return 0;
}

/* OVS: ovs_dp_upcall */
SEC("kprobe/ovs_dp_upcall")
int BPF_KPROBE(kprobe_ovs_upcall, void *dp, const struct sk_buff *skb_const)
{
    struct sk_buff *skb = (struct sk_buff *)skb_const;

    if (targ_direction != DIRECTION_VNET_TX)
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_RX, DIRECTION_VNET_RX);
    if (targ_direction != DIRECTION_VNET_RX)
        handle_stage_event(ctx, skb, STG_OVS_UPCALL_TX, DIRECTION_VNET_TX);

    return 0;
}

/* OVS: ovs_vport_send */
SEC("kprobe/ovs_vport_send")
int BPF_KPROBE(kprobe_ovs_vport_send, const void *vport, struct sk_buff *skb)
{
    if (targ_direction != DIRECTION_VNET_TX)
        handle_stage_event(ctx, skb, STG_CT_OUT_RX, DIRECTION_VNET_RX);
    if (targ_direction != DIRECTION_VNET_RX)
        handle_stage_event(ctx, skb, STG_CT_OUT_TX, DIRECTION_VNET_TX);

    return 0;
}

/* TX: dev_queue_xmit (Physical interface) */
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_VNET_TX)
        return 0;

    if (!is_phy_interface(skb))
        return 0;

    handle_stage_event(ctx, skb, STG_TX_XMIT, DIRECTION_VNET_RX);
    return 0;
}

/* VNET TX: tun_net_xmit or tap_xmit */
SEC("kprobe/tun_net_xmit")
int BPF_KPROBE(kprobe_vnet_tx, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_VNET_RX)
        return 0;

    handle_stage_event(ctx, skb, STG_VNET_TX, DIRECTION_VNET_TX);
    return 0;
}
