// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_userspace_megaflow - OVS userspace megaflow tracker BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ovs_userspace_megaflow.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __be32 filter_src_ip = 0;
const volatile __be32 filter_dst_ip = 0;
const volatile __u16 filter_src_port = 0;
const volatile __u16 filter_dst_port = 0;
const volatile __u8 filter_protocol = 0;
const volatile bool trace_upcalls = true;
const volatile bool trace_flows = true;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct upcall_stats_key);
    __type(value, struct upcall_stats);
} upcall_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} upcall_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} flow_events SEC(".maps");

/* Parse packet info from skb (userspace format - data starts at ethernet header) */
static __always_inline int parse_skb_userspace(struct sk_buff *skb,
                                               struct upcall_event *event)
{
    unsigned char *skb_head;
    unsigned long skb_data_ptr;
    struct net_device *dev;

    if (bpf_probe_read_kernel(&skb_head, sizeof(skb_head), &skb->head) < 0)
        return -1;

    if (bpf_probe_read_kernel(&skb_data_ptr, sizeof(skb_data_ptr), &skb->data) < 0)
        return -1;

    unsigned int data_offset = (unsigned int)(skb_data_ptr - (unsigned long)skb_head);

    /* Read Ethernet header */
    struct ethhdr eth;
    if (bpf_probe_read_kernel(&eth, sizeof(eth), skb_head + data_offset) < 0)
        return -1;

    __builtin_memcpy(event->eth_dst, eth.h_dest, ETH_ALEN);
    __builtin_memcpy(event->eth_src, eth.h_source, ETH_ALEN);
    event->eth_type = bpf_ntohs(eth.h_proto);

    unsigned int net_offset = data_offset + sizeof(struct ethhdr);
    __be16 h_proto = eth.h_proto;

    /* Handle VLAN tags */
    if (bpf_ntohs(h_proto) == 0x8100 || bpf_ntohs(h_proto) == 0x88a8) {
        net_offset += 4;
        if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), skb_head + data_offset + sizeof(struct ethhdr) + 2) < 0)
            return -1;
        event->eth_type = bpf_ntohs(h_proto);
    }

    /* Only process IPv4 */
    if (bpf_ntohs(h_proto) != 0x0800)
        return 0;

    /* Read IP header */
    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), skb_head + net_offset) < 0)
        return -1;

    event->src_ip = ip.saddr;
    event->dst_ip = ip.daddr;
    event->protocol = ip.protocol;

    /* Parse transport layer */
    __u8 ihl = ip.ihl & 0x0F;
    if (ihl < 5)
        return -1;

    unsigned int trans_offset = net_offset + (ihl * 4);

    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcp;
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), skb_head + trans_offset) == 0) {
            event->src_port = tcp.source;
            event->dst_port = tcp.dest;
        }
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udp;
        if (bpf_probe_read_kernel(&udp, sizeof(udp), skb_head + trans_offset) == 0) {
            event->src_port = udp.source;
            event->dst_port = udp.dest;
        }
    }

    /* Get interface info */
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_kernel(&event->ifindex, sizeof(event->ifindex), &dev->ifindex);
        bpf_probe_read_kernel_str(&event->ifname, IFNAMSIZ, dev->name);
    }

    /* Get skb mark */
    bpf_probe_read_kernel(&event->skb_mark, sizeof(event->skb_mark), &skb->mark);

    return 0;
}

/* Check filters */
static __always_inline bool should_filter(struct upcall_event *event)
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

/* Trace ovs_dp_upcall - upcall from kernel to userspace */
SEC("kprobe/ovs_dp_upcall")
int BPF_KPROBE(kprobe_ovs_dp_upcall, void *dp, struct sk_buff *skb, void *key_ptr, void *upcall_info)
{
    struct upcall_event *event;

    if (!skb || !trace_upcalls)
        return 0;

    event = bpf_ringbuf_reserve(&upcall_events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* Get portid from upcall_info */
    if (upcall_info) {
        bpf_probe_read_kernel(&event->portid, sizeof(__u32), upcall_info);
    }

    /* Parse packet info */
    if (parse_skb_userspace(skb, event) < 0 || should_filter(event)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    /* Update statistics */
    struct upcall_stats_key stats_key = {
        .src_ip = event->src_ip,
        .dst_ip = event->dst_ip,
        .protocol = event->protocol,
    };

    struct upcall_stats *stats = bpf_map_lookup_elem(&upcall_stats_map, &stats_key);
    if (stats) {
        __sync_fetch_and_add(&stats->count, 1);
        stats->last_timestamp = event->timestamp;
    } else {
        struct upcall_stats new_stats = {
            .count = 1,
            .last_timestamp = event->timestamp,
        };
        bpf_map_update_elem(&upcall_stats_map, &stats_key, &new_stats, BPF_ANY);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace ovs_flow_cmd_new - new flow installation */
SEC("kprobe/ovs_flow_cmd_new")
int BPF_KPROBE(kprobe_ovs_flow_cmd_new, struct sk_buff *skb, void *info)
{
    struct flow_new_event *event;

    if (!skb || !trace_flows)
        return 0;

    event = bpf_ringbuf_reserve(&flow_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* Get netlink portid from genl_info */
    if (info) {
        bpf_probe_read_kernel(&event->netlink_portid, sizeof(event->netlink_portid),
                              info + 8); /* offset of snd_portid in genl_info */
    }

    /* Get skb length */
    bpf_probe_read_kernel(&event->skb_len, sizeof(event->skb_len), &skb->len);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
