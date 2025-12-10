// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_rx_internal_latency - Detailed RX path latency measurement

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "system_network_rx_internal_latency.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 targ_src_ip = 0;
const volatile __be32 targ_dst_ip = 0;
const volatile __be16 targ_src_port = 0;
const volatile __be16 targ_dst_port = 0;
const volatile __u8 targ_protocol = 0;  /* 0=all, 6=TCP, 17=UDP */
const volatile __u32 targ_ifindex = 0;

/* Flow tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct flow_data);
} flow_sessions SEC(".maps");

/* Stage pair latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_STAGES * MAX_STAGES * MAX_SLOTS);
    __type(key, struct stage_pair_key);
    __type(value, __u64);
} stage_latency_hist SEC(".maps");

/* Total latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} total_latency_hist SEC(".maps");

/* CPU migration histogram */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 256 * MAX_SLOTS);
    __type(key, struct cpu_pair_key);
    __type(value, __u64);
} cpu_migration_hist SEC(".maps");

/* Counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* Helper: log2 */
static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (v <= 1) break;
        v >>= 1;
        r++;
    }
    return r;
}

/* Helper: parse packet key from sk_buff */
static __always_inline bool parse_packet_key(struct sk_buff *skb, struct packet_key *key)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);

    if (!head || network_header == (__u16)~0U || network_header > 2048)
        return false;

    /* Read IP header */
    struct iphdr ip;
    if (bpf_core_read(&ip, sizeof(ip), head + network_header) < 0)
        return false;

    key->src_ip = ip.saddr;
    key->dst_ip = ip.daddr;
    key->protocol = ip.protocol;

    /* Apply filters */
    if (targ_protocol && ip.protocol != targ_protocol)
        return false;
    if (targ_src_ip && ip.saddr != targ_src_ip)
        return false;
    if (targ_dst_ip && ip.daddr != targ_dst_ip)
        return false;

    /* Parse transport header */
    __u8 ihl = ip.ihl & 0xF;
    if (ihl < 5) return false;
    __u16 transport_offset = network_header + (ihl * 4);

    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_core_read(&tcp, sizeof(tcp), head + transport_offset) < 0)
            return false;
        key->src_port = tcp.source;
        key->dst_port = tcp.dest;
        key->seq = tcp.seq;

        if (targ_src_port && tcp.source != targ_src_port && tcp.dest != targ_src_port)
            return false;
        if (targ_dst_port && tcp.source != targ_dst_port && tcp.dest != targ_dst_port)
            return false;
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_core_read(&udp, sizeof(udp), head + transport_offset) < 0)
            return false;
        key->src_port = udp.source;
        key->dst_port = udp.dest;
        key->seq = ip.id;

        if (targ_src_port && udp.source != targ_src_port && udp.dest != targ_src_port)
            return false;
        if (targ_dst_port && udp.source != targ_dst_port && udp.dest != targ_dst_port)
            return false;
    } else {
        return false;
    }

    return true;
}

/* Helper: handle stage event */
static __always_inline void handle_stage(struct sk_buff *skb, __u8 stage_id, __u8 cpu_id)
{
    struct packet_key key = {};
    __u64 current_ts = bpf_ktime_get_ns();

    if (!parse_packet_key(skb, &key))
        return;

    struct flow_data *flow = bpf_map_lookup_elem(&flow_sessions, &key);

    if (stage_id == RX_S5_0_OVS_VPORT_SEND) {
        /* First stage: initialize flow */
        struct flow_data new_flow = {
            .first_ts = current_ts,
            .last_ts = current_ts,
            .last_stage = stage_id,
            .enqueue_cpu = 0xFF,
            .process_cpu = 0xFF,
        };
        bpf_map_update_elem(&flow_sessions, &key, &new_flow, BPF_ANY);

        __u32 idx = CNT_RX_PACKETS;
        __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
        if (cnt) __sync_fetch_and_add(cnt, 1);
        return;
    }

    if (!flow)
        return;

    /* Calculate stage latency */
    if (flow->last_ts > 0 && current_ts > flow->last_ts) {
        __u64 latency_ns = current_ts - flow->last_ts;
        __u64 latency_us = latency_ns / 1000;

        struct stage_pair_key pair_key = {
            .prev_stage = flow->last_stage,
            .curr_stage = stage_id,
            .latency_bucket = log2l(latency_us + 1),
        };
        if (pair_key.latency_bucket >= MAX_SLOTS)
            pair_key.latency_bucket = MAX_SLOTS - 1;

        __u64 *cnt = bpf_map_lookup_elem(&stage_latency_hist, &pair_key);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        } else {
            __u64 one = 1;
            bpf_map_update_elem(&stage_latency_hist, &pair_key, &one, BPF_NOEXIST);
        }
    }

    /* Track CPU for enqueue/process stages */
    if (stage_id == RX_S5_4_ENQUEUE_TO_BACKLOG) {
        flow->enqueue_cpu = cpu_id;
    } else if (stage_id == RX_S5_5_PROCESS_BACKLOG || stage_id == RX_S5_6_NETIF_RECEIVE_SKB) {
        flow->process_cpu = cpu_id;

        /* Track CPU migration for critical boundary */
        if (flow->enqueue_cpu != 0xFF) {
            __u64 latency_us = (current_ts - flow->last_ts) / 1000;
            struct cpu_pair_key cpu_key = {
                .enqueue_cpu = flow->enqueue_cpu,
                .process_cpu = cpu_id,
                .latency_bucket = log2l(latency_us + 1),
            };
            if (cpu_key.latency_bucket >= MAX_SLOTS)
                cpu_key.latency_bucket = MAX_SLOTS - 1;

            __u64 *cnt = bpf_map_lookup_elem(&cpu_migration_hist, &cpu_key);
            if (cnt) {
                __sync_fetch_and_add(cnt, 1);
            } else {
                __u64 one = 1;
                bpf_map_update_elem(&cpu_migration_hist, &cpu_key, &one, BPF_NOEXIST);
            }

            /* Count cross-CPU */
            if (flow->enqueue_cpu != cpu_id) {
                __u32 idx = CNT_CROSS_CPU;
                cnt = bpf_map_lookup_elem(&counters, &idx);
                if (cnt) __sync_fetch_and_add(cnt, 1);
            }
        }
    }

    /* Update flow */
    flow->last_stage = stage_id;
    flow->last_ts = current_ts;

    /* Last stage: record total latency and cleanup */
    if (stage_id == RX_S6_PROTOCOL_RCV) {
        if (flow->first_ts > 0 && current_ts > flow->first_ts) {
            __u64 total_latency_us = (current_ts - flow->first_ts) / 1000;
            __u32 slot = log2l(total_latency_us + 1);
            if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;

            __u64 *cnt = bpf_map_lookup_elem(&total_latency_hist, &slot);
            if (cnt) __sync_fetch_and_add(cnt, 1);
        }
        bpf_map_delete_elem(&flow_sessions, &key);
    }
}

/* Stage probes */
SEC("kprobe/ovs_vport_send")
int BPF_KPROBE(kprobe_ovs_vport_send, const void *vport, struct sk_buff *skb)
{
    handle_stage(skb, RX_S5_0_OVS_VPORT_SEND, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/internal_dev_recv")
int BPF_KPROBE(kprobe_internal_dev_recv, struct sk_buff *skb)
{
    handle_stage(skb, RX_S5_1_INTERNAL_DEV_RECV, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/netif_rx")
int BPF_KPROBE(kprobe_netif_rx, struct sk_buff *skb)
{
    handle_stage(skb, RX_S5_2_NETIF_RX, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/netif_rx_internal")
int BPF_KPROBE(kprobe_netif_rx_internal, struct sk_buff *skb)
{
    handle_stage(skb, RX_S5_3_NETIF_RX_INTERNAL, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/enqueue_to_backlog")
int BPF_KPROBE(kprobe_enqueue_to_backlog, struct sk_buff *skb, int cpu)
{
    handle_stage(skb, RX_S5_4_ENQUEUE_TO_BACKLOG, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/__netif_receive_skb_core")
int BPF_KPROBE(kprobe_netif_receive_skb_core, struct sk_buff **pskb, bool pfmemalloc)
{
    struct sk_buff *skb = NULL;
    bpf_probe_read_kernel(&skb, sizeof(skb), pskb);
    if (skb)
        handle_stage(skb, RX_S5_6_NETIF_RECEIVE_SKB, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/ip_rcv")
int BPF_KPROBE(kprobe_ip_rcv, struct sk_buff *skb)
{
    handle_stage(skb, RX_S5_7_IP_RCV, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/ip_local_deliver")
int BPF_KPROBE(kprobe_ip_local_deliver, struct sk_buff *skb)
{
    handle_stage(skb, RX_S5_8_IP_LOCAL_DELIVER, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(kprobe_tcp_v4_rcv, struct sk_buff *skb)
{
    handle_stage(skb, RX_S6_PROTOCOL_RCV, bpf_get_smp_processor_id());
    return 0;
}

SEC("kprobe/__udp4_lib_rcv")
int BPF_KPROBE(kprobe_udp4_lib_rcv, struct sk_buff *skb)
{
    handle_stage(skb, RX_S6_PROTOCOL_RCV, bpf_get_smp_processor_id());
    return 0;
}
