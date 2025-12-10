// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_latency_summary - Network stack latency tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bits.bpf.h"
#include "system_network_latency_summary.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_src_ip = 0;
const volatile __u32 targ_dst_ip = 0;
const volatile __u16 targ_src_port = 0;
const volatile __u16 targ_dst_port = 0;
const volatile __u8 targ_protocol = 0;       /* 0=all, 6=TCP, 17=UDP */
const volatile __u8 targ_direction = 0;      /* 1=TX, 2=RX */
const volatile __s32 targ_ifindex1 = 0;
const volatile __s32 targ_ifindex2 = 0;

/* Flow sessions map (LRU hash for automatic cleanup) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct flow_data);
} flow_sessions SEC(".maps");

/* Adjacent stage latency histogram (per stage pair) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
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

/* Helper: check if interface matches target */
static __always_inline bool is_target_ifindex(const struct sk_buff *skb)
{
    struct net_device *dev;
    int ifindex;

    dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;

    ifindex = BPF_CORE_READ(dev, ifindex);
    return (ifindex == targ_ifindex1 || ifindex == targ_ifindex2);
}

/* Helper: get IP header from skb */
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

/* Helper: get transport header from skb */
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

    /* If transport header not set, calculate from IP header */
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

/* Parse packet key for standard skb */
static __always_inline int parse_packet_key(const struct sk_buff *skb,
                                             struct packet_key *key,
                                             __u8 direction)
{
    struct iphdr ip;

    if (get_ip_header(skb, &ip) != 0)
        return 0;

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    /* Apply filters */
    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;
    if (targ_src_ip != 0 && ip.saddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.daddr != targ_dst_ip)
        return 0;

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
        key->udp.ip_id = ip.id;

        struct udphdr udp = {};
        if (get_transport_header(skb, &udp, sizeof(udp)) == 0) {
            key->udp.src_port = udp.source;
            key->udp.dst_port = udp.dest;
            key->udp.udp_len = udp.len;
        }

        __u16 frag_off_flags = bpf_ntohs(ip.frag_off);
        key->udp.frag_off = (frag_off_flags & 0x1FFF) * 8;

        if (key->udp.frag_off == 0) {
            if (targ_src_port != 0 &&
                key->udp.src_port != bpf_htons(targ_src_port) &&
                key->udp.dst_port != bpf_htons(targ_src_port))
                return 0;
            if (targ_dst_port != 0 &&
                key->udp.src_port != bpf_htons(targ_dst_port) &&
                key->udp.dst_port != bpf_htons(targ_dst_port))
                return 0;
        }
    } else {
        return 0;
    }

    return 1;
}

/* Parse packet key for TCP early stage (from socket) */
static __always_inline int parse_packet_key_tcp_early(const struct sk_buff *skb,
                                                       struct sock *sk,
                                                       struct packet_key *key)
{
    struct inet_sock *inet;
    struct tcp_sock *tp;

    if (!sk)
        return 0;

    inet = (struct inet_sock *)sk;

    key->src_ip = BPF_CORE_READ(inet, inet_saddr);
    key->dst_ip = BPF_CORE_READ(inet, inet_daddr);
    key->tcp.src_port = BPF_CORE_READ(inet, inet_sport);
    key->tcp.dst_port = BPF_CORE_READ(inet, inet_dport);
    key->protocol = PROTO_TCP;

    /* Apply filters */
    if (targ_protocol != 0 && key->protocol != targ_protocol)
        return 0;
    if (targ_src_ip != 0 && key->src_ip != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && key->dst_ip != targ_dst_ip)
        return 0;

    /* Get TCP sequence number */
    tp = (struct tcp_sock *)sk;
    __u32 snd_nxt = BPF_CORE_READ(tp, snd_nxt);
    key->tcp.seq = bpf_htonl(snd_nxt);

    /* Apply port filters */
    if (targ_src_port != 0 &&
        key->tcp.src_port != bpf_htons(targ_src_port) &&
        key->tcp.dst_port != bpf_htons(targ_src_port))
        return 0;
    if (targ_dst_port != 0 &&
        key->tcp.src_port != bpf_htons(targ_dst_port) &&
        key->tcp.dst_port != bpf_htons(targ_dst_port))
        return 0;

    return 1;
}

/* Parse packet key for userspace SKB (ovs_flow_key_extract_userspace) */
static __always_inline int parse_packet_key_userspace(const struct sk_buff *skb,
                                                       struct packet_key *key,
                                                       __u8 direction)
{
    unsigned char *skb_head;
    unsigned long skb_data_ptr;
    unsigned int data_offset;
    struct ethhdr eth;
    struct iphdr ip;
    __u16 h_proto;

    skb_head = BPF_CORE_READ(skb, head);
    skb_data_ptr = (unsigned long)BPF_CORE_READ(skb, data);

    if (!skb_head)
        return 0;

    data_offset = (unsigned int)(skb_data_ptr - (unsigned long)skb_head);

    /* Read Ethernet header */
    if (bpf_core_read(&eth, sizeof(eth), skb_head + data_offset) < 0)
        return 0;

    unsigned int net_offset = data_offset + 14; /* ETH_HLEN */
    h_proto = eth.h_proto;

    /* Handle VLAN */
    if (h_proto == bpf_htons(0x8100) || h_proto == bpf_htons(0x88A8)) {
        net_offset += 4;
        if (bpf_core_read(&h_proto, sizeof(h_proto), skb_head + data_offset + 14 + 2) < 0)
            return 0;
    }

    if (h_proto != bpf_htons(0x0800)) /* ETH_P_IP */
        return 0;

    /* Read IP header */
    if (bpf_core_read(&ip, sizeof(ip), skb_head + net_offset) < 0)
        return 0;

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    /* Apply filters */
    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;
    if (targ_src_ip != 0 && ip.saddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.daddr != targ_dst_ip)
        return 0;

    __u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5)
        return 0;

    unsigned int trans_offset = net_offset + (ip_ihl * 4);

    /* Parse transport layer */
    if (ip.protocol == PROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_core_read(&tcp, sizeof(tcp), skb_head + trans_offset) < 0)
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
        key->udp.ip_id = ip.id;

        __u16 frag_off_flags = bpf_ntohs(ip.frag_off);
        __u16 frag_offset = frag_off_flags & 0x1FFF;
        key->udp.frag_off = frag_offset * 8;

        if (frag_offset == 0) {
            struct udphdr udp;
            if (bpf_core_read(&udp, sizeof(udp), skb_head + trans_offset) == 0) {
                key->udp.src_port = udp.source;
                key->udp.dst_port = udp.dest;

                if (targ_src_port != 0 &&
                    key->udp.src_port != bpf_htons(targ_src_port) &&
                    key->udp.dst_port != bpf_htons(targ_src_port))
                    return 0;
                if (targ_dst_port != 0 &&
                    key->udp.src_port != bpf_htons(targ_dst_port) &&
                    key->udp.dst_port != bpf_htons(targ_dst_port))
                    return 0;
            }
        }
    } else {
        return 0;
    }

    return 1;
}

/* Update histogram for adjacent stage latency */
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
    int parse_success = 0;

    /* Parse packet key based on stage */
    if (stage_id == TX_STAGE_4 || stage_id == RX_STAGE_4) {
        parse_success = parse_packet_key_userspace(skb, &key, direction);
    } else {
        parse_success = parse_packet_key(skb, &key, direction);
    }

    if (!parse_success)
        return;

    /* Check if this is first stage */
    bool is_first_stage = false;
    if ((direction == DIRECTION_TX && stage_id == TX_STAGE_0) ||
        (direction == DIRECTION_RX && stage_id == RX_STAGE_0)) {
        is_first_stage = true;
    }

    struct flow_data *flow_ptr;

    if (is_first_stage) {
        /* Initialize new flow */
        struct flow_data zero = {
            .direction = direction,
            .last_stage = stage_id,
            .last_timestamp = current_ts,
            .first_timestamp = current_ts,
        };

        bpf_map_delete_elem(&flow_sessions, &key);
        bpf_map_update_elem(&flow_sessions, &key, &zero, BPF_ANY);

        inc_counter(direction);
        inc_fsc(direction == DIRECTION_TX ? FSC_FIRST_TX : FSC_FIRST_RX);
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
    bool is_last_stage = false;
    if ((direction == DIRECTION_TX && stage_id == TX_STAGE_6) ||
        (direction == DIRECTION_RX && stage_id == RX_STAGE_6)) {
        is_last_stage = true;

        /* Calculate total latency */
        if (flow_ptr->first_timestamp > 0 && current_ts > flow_ptr->first_timestamp) {
            __u64 total_latency_us = (current_ts - flow_ptr->first_timestamp) / 1000;
            if (total_latency_us > 0)
                update_total_hist(total_latency_us);
        }

        inc_fsc(direction == DIRECTION_TX ? FSC_LAST_TX : FSC_LAST_RX);
        bpf_map_delete_elem(&flow_sessions, &key);
    }
}

/* Handle TCP early stage */
static __always_inline void handle_stage_event_tcp_early(void *ctx,
                                                          struct sock *sk,
                                                          struct sk_buff *skb,
                                                          __u8 stage_id,
                                                          __u8 direction)
{
    struct packet_key key = {};

    if (!parse_packet_key_tcp_early(skb, sk, &key))
        return;

    __u64 current_ts = bpf_ktime_get_ns();

    struct flow_data zero = {
        .direction = direction,
        .last_stage = stage_id,
        .last_timestamp = current_ts,
        .first_timestamp = current_ts,
    };

    bpf_map_delete_elem(&flow_sessions, &key);
    bpf_map_update_elem(&flow_sessions, &key, &zero, BPF_ANY);

    inc_counter(direction);
    inc_fsc(FSC_FIRST_TX);
}

/* ========== Probe Points ========== */

/* TX Stage 0: TCP __ip_queue_xmit */
SEC("kprobe/__ip_queue_xmit")
int BPF_KPROBE(kprobe_ip_queue_xmit, struct sock *sk, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_RX)
        return 0;
    if (targ_protocol != 0 && targ_protocol != PROTO_TCP)
        return 0;

    handle_stage_event_tcp_early(ctx, sk, skb, TX_STAGE_0, DIRECTION_TX);
    return 0;
}

/* TX Stage 0: UDP ip_send_skb */
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(kprobe_ip_send_skb, struct net *net, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_RX)
        return 0;
    if (targ_protocol != 0 && targ_protocol != PROTO_UDP)
        return 0;

    handle_stage_event(ctx, skb, TX_STAGE_0, DIRECTION_TX);
    return 0;
}

/* TX Stage 1: internal_dev_xmit */
SEC("kprobe/internal_dev_xmit")
int BPF_KPROBE(kprobe_internal_dev_xmit, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_RX)
        return 0;

    handle_stage_event(ctx, skb, TX_STAGE_1, DIRECTION_TX);
    return 0;
}

/* OVS: ovs_dp_process_packet */
SEC("kprobe/ovs_dp_process_packet")
int BPF_KPROBE(kprobe_ovs_dp_process_packet, const struct sk_buff *skb_const)
{
    struct sk_buff *skb = (struct sk_buff *)skb_const;

    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_2, DIRECTION_TX);
    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_2, DIRECTION_RX);

    return 0;
}

/* OVS: ovs_dp_upcall */
SEC("kprobe/ovs_dp_upcall")
int BPF_KPROBE(kprobe_ovs_dp_upcall, void *dp, const struct sk_buff *skb_const)
{
    struct sk_buff *skb = (struct sk_buff *)skb_const;

    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_3, DIRECTION_TX);
    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_3, DIRECTION_RX);

    return 0;
}

/* OVS: ovs_flow_key_extract_userspace */
SEC("kprobe/ovs_flow_key_extract_userspace")
int BPF_KPROBE(kprobe_ovs_flow_key_extract_userspace, struct net *net,
               const void *attr, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_4, DIRECTION_TX);
    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_4, DIRECTION_RX);

    return 0;
}

/* OVS: ovs_vport_send */
SEC("kprobe/ovs_vport_send")
int BPF_KPROBE(kprobe_ovs_vport_send, const void *vport, struct sk_buff *skb)
{
    if (targ_direction != DIRECTION_RX)
        handle_stage_event(ctx, skb, TX_STAGE_5, DIRECTION_TX);
    if (targ_direction != DIRECTION_TX)
        handle_stage_event(ctx, skb, RX_STAGE_5, DIRECTION_RX);

    return 0;
}

/* TX Stage 6: dev_queue_xmit */
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    if (!is_target_ifindex(skb))
        return 0;
    if (targ_direction == DIRECTION_RX)
        return 0;

    handle_stage_event(ctx, skb, TX_STAGE_6, DIRECTION_TX);
    return 0;
}

/* RX Stage 0: netif_receive_skb tracepoint */
SEC("tp/net/netif_receive_skb")
int handle_netif_receive_skb(void *ctx)
{
    struct sk_buff *skb;
    struct trace_event_raw_net_dev_template {
        unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
        void *skbaddr;
        unsigned int len;
        char name[16];
    } *args = ctx;

    if (targ_direction == DIRECTION_TX)
        return 0;

    skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    if (!is_target_ifindex(skb))
        return 0;

    handle_stage_event(ctx, skb, RX_STAGE_0, DIRECTION_RX);
    return 0;
}

/* RX Stage 1: netdev_frame_hook */
SEC("kprobe/netdev_frame_hook")
int BPF_KPROBE(kprobe_netdev_frame_hook, struct sk_buff **pskb)
{
    struct sk_buff *skb = NULL;

    if (targ_direction == DIRECTION_TX)
        return 0;

    if (bpf_core_read(&skb, sizeof(skb), pskb) < 0 || !skb)
        return 0;

    handle_stage_event(ctx, skb, RX_STAGE_1, DIRECTION_RX);
    return 0;
}

/* RX Stage 6: tcp_v4_rcv */
SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(kprobe_tcp_v4_rcv, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_TX)
        return 0;
    if (targ_protocol != 0 && targ_protocol != PROTO_TCP)
        return 0;

    handle_stage_event(ctx, skb, RX_STAGE_6, DIRECTION_RX);
    return 0;
}

/* RX Stage 6: __udp4_lib_rcv */
SEC("kprobe/__udp4_lib_rcv")
int BPF_KPROBE(kprobe_udp4_lib_rcv, struct sk_buff *skb)
{
    if (targ_direction == DIRECTION_TX)
        return 0;
    if (targ_protocol != 0 && targ_protocol != PROTO_UDP)
        return 0;

    handle_stage_event(ctx, skb, RX_STAGE_6, DIRECTION_RX);
    return 0;
}
