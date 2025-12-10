// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// eth_drop - Network packet drop tracer BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "eth_drop.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_src_ip = 0;
const volatile __u32 targ_dst_ip = 0;
const volatile __u16 targ_src_port = 0;
const volatile __u16 targ_dst_port = 0;
const volatile __u16 targ_protocol = 0;      /* EtherType filter (0 = all) */
const volatile __u8 targ_l4_protocol = 0;    /* L4 protocol (0 = all) */
const volatile __u16 targ_vlan_id = 0;       /* VLAN filter (0 = all) */
const volatile bool targ_interface_filter = false;

/* Interface name for filtering */
const volatile char targ_ifname[IFNAMSIZ] = {};

/* Stack trace map */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Helper function to check if packet should be captured based on protocol */
static __always_inline bool should_capture_packet(__u16 protocol, __u16 filter_protocol)
{
    if (filter_protocol == 0)
        return true;  /* Capture all */
    if (filter_protocol == 0xFFFF) {
        /* "other" protocols - not IP, ARP, RARP, IPv6, LLDP, Flow Control */
        return !(protocol == ETH_P_IP || protocol == ETH_P_ARP ||
                 protocol == ETH_P_RARP || protocol == ETH_P_IPV6 ||
                 protocol == ETH_P_LLDP || protocol == ETH_P_FLOW_CTRL);
    }
    return protocol == filter_protocol;
}

/* Helper function to filter interface */
static __always_inline bool interface_filter(struct sk_buff *skb)
{
    char ifname[IFNAMSIZ] = {};
    struct net_device *dev;

    if (!targ_interface_filter)
        return true;  /* No interface filtering */

    dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;

    bpf_core_read_str(ifname, sizeof(ifname), &dev->name);

    /* Compare interface names */
    #pragma unroll
    for (int i = 0; i < IFNAMSIZ; i++) {
        if (targ_ifname[i] != ifname[i])
            return false;
        if (targ_ifname[i] == '\0')
            break;
    }

    return true;
}

SEC("kprobe/kfree_skb")
int BPF_KPROBE(trace_kfree_skb, struct sk_buff *skb)
{
    struct drop_event *e;
    unsigned char *mac_header_ptr = NULL;
    unsigned char *skb_head;
    __u16 mac_header_offset;
    __u16 network_header_offset;
    __u16 transport_header_offset;
    __u16 real_protocol;
    struct ethhdr eth;
    struct net_device *dev;

    if (!skb)
        return 0;

    /* Apply interface filter first */
    if (!interface_filter(skb))
        return 0;

    /* Get SKB offsets */
    mac_header_offset = BPF_CORE_READ(skb, mac_header);
    network_header_offset = BPF_CORE_READ(skb, network_header);
    transport_header_offset = BPF_CORE_READ(skb, transport_header);
    skb_head = BPF_CORE_READ(skb, head);

    if (!skb_head)
        return 0;

    /* Get MAC header pointer */
    if (mac_header_offset != (__u16)~0U) {
        mac_header_ptr = skb_head + mac_header_offset;
    } else {
        /* Fallback to skb->data */
        unsigned char *skb_data = BPF_CORE_READ(skb, data);
        if (!skb_data)
            return 0;
        mac_header_ptr = skb_data;
    }

    /* Read Ethernet header */
    if (bpf_core_read(&eth, sizeof(eth), mac_header_ptr) < 0)
        return 0;

    __u16 eth_type = bpf_ntohs(eth.h_proto);
    real_protocol = eth_type;

    /* Handle VLAN */
    unsigned char *network_ptr = mac_header_ptr + 14; /* ETH_HLEN */
    __u16 vlan_id = 0;
    __u16 vlan_priority = 0;
    __u16 inner_protocol = 0;
    __u8 has_vlan = 0;

    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr {
            __be16 h_vlan_TCI;
            __be16 h_vlan_encapsulated_proto;
        } vlan;

        if (bpf_core_read(&vlan, sizeof(vlan), network_ptr) == 0) {
            __u16 tci = bpf_ntohs(vlan.h_vlan_TCI);
            vlan_id = tci & 0x0FFF;
            vlan_priority = (tci >> 13) & 0x07;
            inner_protocol = bpf_ntohs(vlan.h_vlan_encapsulated_proto);
            has_vlan = 1;
            real_protocol = inner_protocol;
            network_ptr += 4;
        }
    }

    /* Apply protocol filter */
    if (!should_capture_packet(real_protocol, targ_protocol))
        return 0;

    /* Apply VLAN filter */
    if (targ_vlan_id > 0 && vlan_id != targ_vlan_id)
        return 0;

    /* Reserve ring buffer space */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    /* Fill basic fields */
    e->timestamp = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid;
    e->tgid = pid_tgid >> 32;
    e->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->cpu_id = bpf_get_smp_processor_id();
    e->in_interrupt = 0;

    /* Get interface name */
    dev = BPF_CORE_READ(skb, dev);
    if (dev) {
        bpf_core_read_str(e->ifname, sizeof(e->ifname), &dev->name);
    }

    /* Fill SKB debug info */
    e->skb_mac_header = mac_header_offset;
    e->skb_network_header = network_header_offset;
    e->skb_transport_header = transport_header_offset;
    e->skb_len = BPF_CORE_READ(skb, len);
    e->skb_data_len = BPF_CORE_READ(skb, data_len);

    /* Fill Ethernet fields */
    __builtin_memcpy(e->eth_src, eth.h_source, ETH_ALEN);
    __builtin_memcpy(e->eth_dst, eth.h_dest, ETH_ALEN);
    e->eth_type = eth_type;

    /* Fill VLAN fields */
    e->vlan_id = vlan_id;
    e->vlan_priority = vlan_priority;
    e->inner_protocol = inner_protocol;
    e->has_vlan = has_vlan;

    /* Parse protocol-specific data */
    if (real_protocol == ETH_P_IP) {
        e->protocol_type = PROTO_TYPE_IPV4;
        struct iphdr iph;

        if (bpf_core_read(&iph, sizeof(iph), network_ptr) == 0) {
            e->ipv4_saddr = iph.saddr;
            e->ipv4_daddr = iph.daddr;
            e->ipv4_protocol = iph.protocol;
            e->ipv4_ttl = iph.ttl;
            e->ipv4_id = bpf_ntohs(iph.id);
            e->ipv4_tot_len = bpf_ntohs(iph.tot_len);
            e->ipv4_tos = iph.tos;

            /* Check L4 protocol filter */
            if (targ_l4_protocol != 0 && iph.protocol != targ_l4_protocol) {
                bpf_ringbuf_discard(e, 0);
                return 0;
            }

            /* Check IP address filters */
            if ((targ_src_ip != 0 && iph.saddr != targ_src_ip) ||
                (targ_dst_ip != 0 && iph.daddr != targ_dst_ip)) {
                bpf_ringbuf_discard(e, 0);
                return 0;
            }

            /* Parse TCP/UDP ports */
            if (iph.protocol == L4_PROTO_TCP || iph.protocol == L4_PROTO_UDP) {
                __u8 ip_ihl = iph.ihl & 0x0F;
                unsigned char *transport_ptr = network_ptr + (ip_ihl * 4);

                if (iph.protocol == L4_PROTO_TCP) {
                    struct tcphdr tcph;
                    if (bpf_core_read(&tcph, sizeof(tcph), transport_ptr) == 0) {
                        e->ipv4_sport = bpf_ntohs(tcph.source);
                        e->ipv4_dport = bpf_ntohs(tcph.dest);
                    }
                } else {
                    struct udphdr udph;
                    if (bpf_core_read(&udph, sizeof(udph), transport_ptr) == 0) {
                        e->ipv4_sport = bpf_ntohs(udph.source);
                        e->ipv4_dport = bpf_ntohs(udph.dest);
                    }
                }

                /* Check port filters */
                if ((targ_src_port != 0 && e->ipv4_sport != targ_src_port) ||
                    (targ_dst_port != 0 && e->ipv4_dport != targ_dst_port)) {
                    bpf_ringbuf_discard(e, 0);
                    return 0;
                }
            }
        }
    } else if (real_protocol == ETH_P_IPV6) {
        e->protocol_type = PROTO_TYPE_IPV6;
        struct ipv6hdr ip6h;

        if (bpf_core_read(&ip6h, sizeof(ip6h), network_ptr) == 0) {
            __builtin_memcpy(e->ipv6_saddr, &ip6h.saddr, 16);
            __builtin_memcpy(e->ipv6_daddr, &ip6h.daddr, 16);
            e->ipv6_nexthdr = ip6h.nexthdr;
            e->ipv6_hop_limit = ip6h.hop_limit;
            e->ipv6_payload_len = bpf_ntohs(ip6h.payload_len);
        }
    } else if (real_protocol == ETH_P_ARP) {
        e->protocol_type = PROTO_TYPE_ARP;
        struct arphdr_custom {
            __be16 ar_hrd;
            __be16 ar_pro;
            __u8 ar_hln;
            __u8 ar_pln;
            __be16 ar_op;
            __u8 ar_sha[ETH_ALEN];
            __u8 ar_sip[4];
            __u8 ar_tha[ETH_ALEN];
            __u8 ar_tip[4];
        } arph;

        if (bpf_core_read(&arph, sizeof(arph), network_ptr) == 0) {
            e->arp_hrd = bpf_ntohs(arph.ar_hrd);
            e->arp_pro = bpf_ntohs(arph.ar_pro);
            e->arp_op = bpf_ntohs(arph.ar_op);
            __builtin_memcpy(e->arp_sha, arph.ar_sha, ETH_ALEN);
            __builtin_memcpy(e->arp_sip, arph.ar_sip, 4);
            __builtin_memcpy(e->arp_tha, arph.ar_tha, ETH_ALEN);
            __builtin_memcpy(e->arp_tip, arph.ar_tip, 4);
        }
    } else if (real_protocol == ETH_P_RARP) {
        e->protocol_type = PROTO_TYPE_RARP;
        /* Same as ARP */
        struct arphdr_custom {
            __be16 ar_hrd;
            __be16 ar_pro;
            __u8 ar_hln;
            __u8 ar_pln;
            __be16 ar_op;
            __u8 ar_sha[ETH_ALEN];
            __u8 ar_sip[4];
            __u8 ar_tha[ETH_ALEN];
            __u8 ar_tip[4];
        } arph;

        if (bpf_core_read(&arph, sizeof(arph), network_ptr) == 0) {
            e->arp_hrd = bpf_ntohs(arph.ar_hrd);
            e->arp_pro = bpf_ntohs(arph.ar_pro);
            e->arp_op = bpf_ntohs(arph.ar_op);
            __builtin_memcpy(e->arp_sha, arph.ar_sha, ETH_ALEN);
            __builtin_memcpy(e->arp_sip, arph.ar_sip, 4);
            __builtin_memcpy(e->arp_tha, arph.ar_tha, ETH_ALEN);
            __builtin_memcpy(e->arp_tip, arph.ar_tip, 4);
        }
    } else {
        e->protocol_type = PROTO_TYPE_OTHER;
        e->other_ethertype = real_protocol;
        bpf_core_read(&e->other_data, sizeof(e->other_data), network_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
