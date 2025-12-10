// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_upcall_latency_summary - OVS upcall latency histogram BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "bits.bpf.h"
#include "ovs_upcall_latency_summary.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_src_ip = 0;
const volatile __u32 targ_dst_ip = 0;
const volatile __u16 targ_src_port = 0;
const volatile __u16 targ_dst_port = 0;
const volatile __u8 targ_protocol = 0;  /* 0=all, 6=TCP, 17=UDP, 1=ICMP */

/* Upcall sessions map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct packet_key);
    __type(value, struct upcall_data);
} upcall_sessions SEC(".maps");

/* Latency histogram - log2 buckets */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

/* Performance counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} packet_counters SEC(".maps");

/* Ring buffer for detailed events (optional) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Helper: increment counter */
static __always_inline void inc_counter(__u32 idx)
{
    __u64 *counter = bpf_map_lookup_elem(&packet_counters, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

/* Helper: increment histogram bucket */
static __always_inline void hist_increment(__u32 slot)
{
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __u64 *count = bpf_map_lookup_elem(&latency_hist, &slot);
    if (count)
        __sync_fetch_and_add(count, 1);
}

/* Parse packet key from sk_buff using network_header */
static __always_inline int parse_packet_key(struct sk_buff *skb, struct packet_key *key)
{
    unsigned char *head;
    __u16 network_header_offset;
    struct iphdr ip;
    __u8 ip_ihl;
    __u16 transport_header_offset;

    head = BPF_CORE_READ(skb, head);
    network_header_offset = BPF_CORE_READ(skb, network_header);

    if (!head || network_header_offset == (__u16)~0U || network_header_offset > 2048)
        return 0;

    if (bpf_core_read(&ip, sizeof(ip), head + network_header_offset) < 0)
        return 0;

    /* Apply protocol filter */
    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;

    /* Apply IP filters - match either direction */
    if (targ_src_ip != 0 && ip.saddr != targ_src_ip && ip.daddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.saddr != targ_dst_ip && ip.daddr != targ_dst_ip)
        return 0;

    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;

    ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5)
        return 0;

    transport_header_offset = network_header_offset + (ip_ihl * 4);

    switch (ip.protocol) {
    case IPPROTO_TCP: {
        struct tcphdr tcp;
        if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header_offset) < 0)
            return 0;

        key->tcp.source = tcp.source;
        key->tcp.dest = tcp.dest;
        key->tcp.seq = tcp.seq;

        if (targ_src_port != 0 &&
            tcp.source != bpf_htons(targ_src_port) &&
            tcp.dest != bpf_htons(targ_src_port))
            return 0;
        if (targ_dst_port != 0 &&
            tcp.source != bpf_htons(targ_dst_port) &&
            tcp.dest != bpf_htons(targ_dst_port))
            return 0;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr udp;
        if (bpf_core_read(&udp, sizeof(udp), head + transport_header_offset) < 0)
            return 0;

        key->udp.source = udp.source;
        key->udp.dest = udp.dest;
        key->udp.id = ip.id;
        key->udp.len = udp.len;

        if (targ_src_port != 0 &&
            udp.source != bpf_htons(targ_src_port) &&
            udp.dest != bpf_htons(targ_src_port))
            return 0;
        if (targ_dst_port != 0 &&
            udp.source != bpf_htons(targ_dst_port) &&
            udp.dest != bpf_htons(targ_dst_port))
            return 0;
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr icmp;
        if (bpf_core_read(&icmp, sizeof(icmp), head + transport_header_offset) < 0)
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

/* Parse packet key from userspace SKB (different data layout) */
static __always_inline int parse_packet_key_userspace(struct sk_buff *skb, struct packet_key *key)
{
    unsigned char *head;
    unsigned long data_ptr;
    unsigned int data_offset;
    unsigned int mac_offset;
    unsigned int net_offset;
    struct ethhdr eth;
    __be16 h_proto;
    struct iphdr ip;
    __u8 ip_ihl;
    unsigned int trans_offset;

    if (!skb)
        return 0;

    head = BPF_CORE_READ(skb, head);
    if (!head)
        return 0;

    data_ptr = (unsigned long)BPF_CORE_READ(skb, data);
    data_offset = (unsigned int)(data_ptr - (unsigned long)head);
    mac_offset = data_offset;

    if (bpf_core_read(&eth, sizeof(eth), head + mac_offset) < 0)
        return 0;

    net_offset = mac_offset + 14; /* ETH_HLEN */
    h_proto = eth.h_proto;

    /* Handle VLAN tags */
    if (h_proto == bpf_htons(0x8100) || h_proto == bpf_htons(0x88A8)) {
        net_offset += 4; /* VLAN_HLEN */
        if (bpf_core_read(&h_proto, sizeof(h_proto), head + mac_offset + 14 + 2) < 0)
            return 0;
        if (h_proto == bpf_htons(0x8100) || h_proto == bpf_htons(0x88A8)) {
            net_offset += 4;
            if (bpf_core_read(&h_proto, sizeof(h_proto), head + mac_offset + 8 + 2) < 0)
                return 0;
        }
    }

    if (h_proto != bpf_htons(0x0800)) /* ETH_P_IP */
        return 0;

    if (bpf_core_read(&ip, sizeof(ip), head + net_offset) < 0)
        return 0;

    /* Apply protocol filter */
    if (targ_protocol != 0 && ip.protocol != targ_protocol)
        return 0;

    /* Apply IP filters */
    if (targ_src_ip != 0 && ip.saddr != targ_src_ip && ip.daddr != targ_src_ip)
        return 0;
    if (targ_dst_ip != 0 && ip.saddr != targ_dst_ip && ip.daddr != targ_dst_ip)
        return 0;

    key->sip = ip.saddr;
    key->dip = ip.daddr;
    key->proto = ip.protocol;

    ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5)
        return 0;

    trans_offset = net_offset + (ip_ihl * 4);

    switch (ip.protocol) {
    case IPPROTO_TCP: {
        struct tcphdr tcp;
        if (bpf_core_read(&tcp, sizeof(tcp), head + trans_offset) < 0)
            return 0;

        key->tcp.source = tcp.source;
        key->tcp.dest = tcp.dest;
        key->tcp.seq = tcp.seq;

        if (targ_src_port != 0 &&
            tcp.source != bpf_htons(targ_src_port) &&
            tcp.dest != bpf_htons(targ_src_port))
            return 0;
        if (targ_dst_port != 0 &&
            tcp.source != bpf_htons(targ_dst_port) &&
            tcp.dest != bpf_htons(targ_dst_port))
            return 0;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr udp;
        if (bpf_core_read(&udp, sizeof(udp), head + trans_offset) < 0)
            return 0;

        key->udp.source = udp.source;
        key->udp.dest = udp.dest;
        key->udp.id = ip.id;
        key->udp.len = udp.len;

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
    case IPPROTO_ICMP: {
        struct icmphdr icmp;
        if (bpf_core_read(&icmp, sizeof(icmp), head + trans_offset) < 0)
            return 0;

        key->icmp.id = icmp.un.echo.id;
        key->icmp.sequence = icmp.un.echo.sequence;
        key->icmp.type = icmp.type;
        key->icmp.code = icmp.code;
        break;
    }
    default:
        return 0;
    }

    return 1;
}

/* Probe: OVS upcall start - ovs_dp_upcall */
SEC("kprobe/ovs_dp_upcall")
int BPF_KPROBE(kprobe_ovs_dp_upcall, void *dp, struct sk_buff *skb)
{
    struct packet_key key = {};
    struct upcall_data data = {};

    if (!skb)
        return 0;

    if (!parse_packet_key(skb, &key))
        return 0;

    data.upcall_timestamp = bpf_ktime_get_ns();
    bpf_map_update_elem(&upcall_sessions, &key, &data, BPF_ANY);

    inc_counter(COUNTER_TOTAL_UPCALLS);

    return 0;
}

/* Probe: OVS userspace processing - ovs_flow_key_extract_userspace */
SEC("kprobe/ovs_flow_key_extract_userspace")
int BPF_KPROBE(kprobe_ovs_flow_key_extract_userspace, struct net *net, void *attr, struct sk_buff *skb)
{
    struct packet_key key = {};
    struct upcall_data *data;
    __u64 current_ts;
    __u64 latency_ns;
    __u64 latency_us;
    __u32 slot;

    if (!skb)
        return 0;

    if (!parse_packet_key_userspace(skb, &key))
        return 0;

    data = bpf_map_lookup_elem(&upcall_sessions, &key);
    if (!data) {
        bpf_map_delete_elem(&upcall_sessions, &key);
        return 0;
    }

    current_ts = bpf_ktime_get_ns();

    if (current_ts > data->upcall_timestamp) {
        latency_ns = current_ts - data->upcall_timestamp;
        latency_us = latency_ns / 1000;

        /* Calculate log2 bucket for histogram */
        if (latency_us > 0)
            slot = log2l(latency_us);
        else
            slot = 0;

        hist_increment(slot);
        inc_counter(COUNTER_COMPLETED_UPCALLS);
    }

    bpf_map_delete_elem(&upcall_sessions, &key);
    return 0;
}
