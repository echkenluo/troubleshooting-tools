// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kernel_icmp_rtt - ICMP RTT tracer for kernel network stack BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "kernel_icmp_rtt.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_src_ip = 0;
const volatile __u32 targ_dst_ip = 0;
const volatile __u64 targ_latency_threshold_ns = 0;
const volatile __s32 targ_ifindex = 0;
const volatile __u8 targ_direction = DIRECTION_TX;

/* Flow sessions map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct icmp_packet_key);
    __type(value, struct icmp_flow_data);
} flow_sessions SEC(".maps");

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

/* Helper: check if interface matches target */
static __always_inline bool is_target_ifindex(const struct sk_buff *skb)
{
    struct net_device *dev;
    int ifindex;

    if (targ_ifindex == 0)
        return true;  /* No filter */

    dev = BPF_CORE_READ(skb, dev);
    if (!dev)
        return false;

    ifindex = BPF_CORE_READ(dev, ifindex);
    return ifindex == targ_ifindex;
}

/* Parse ICMP packet key */
static __always_inline int parse_icmp_packet_key(const struct sk_buff *skb,
                                                  struct icmp_packet_key *key,
                                                  __u8 *icmp_type_out,
                                                  int expect_echo_reply,
                                                  int reverse_ips,
                                                  __u8 stage_id)
{
    unsigned char *head;
    __u16 network_header_offset;
    __u16 transport_header_offset;
    struct iphdr ip;
    struct icmphdr icmph;
    __be32 expected_sip, expected_dip;
    __u8 expected_icmp_type;
    __u8 ip_ihl;

    head = BPF_CORE_READ(skb, head);
    network_header_offset = BPF_CORE_READ(skb, network_header);
    transport_header_offset = BPF_CORE_READ(skb, transport_header);

    if (!head || network_header_offset == (__u16)~0U || network_header_offset > 4096)
        return 0;

    if (bpf_core_read(&ip, sizeof(ip), head + network_header_offset) < 0)
        return 0;

    if (ip.protocol != 1) /* IPPROTO_ICMP */
        return 0;

    /* Determine expected IPs based on direction and path */
    expected_sip = reverse_ips ? targ_dst_ip : targ_src_ip;
    expected_dip = reverse_ips ? targ_src_ip : targ_dst_ip;

    if (ip.saddr != expected_sip || ip.daddr != expected_dip)
        return 0;

    expected_icmp_type = expect_echo_reply ? ICMP_ECHOREPLY : ICMP_ECHO;

    ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5)
        return 0;

    if (transport_header_offset == 0 || transport_header_offset == (__u16)~0U ||
        transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    if (bpf_core_read(&icmph, sizeof(icmph), head + transport_header_offset) < 0)
        return 0;

    if (icmph.type != expected_icmp_type)
        return 0;

    *icmp_type_out = icmph.type;
    key->src_ip = targ_src_ip;
    key->dst_ip = targ_dst_ip;
    key->proto = ip.protocol;
    key->id = icmph.un.echo.id;
    key->seq = icmph.un.echo.sequence;

    return 1;
}

/* Handle stage event */
static __always_inline void handle_event(void *ctx, struct sk_buff *skb,
                                          __u8 stage_id,
                                          struct icmp_packet_key *key,
                                          __u8 icmp_type)
{
    struct icmp_flow_data *flow_ptr;
    __u64 current_ts = bpf_ktime_get_ns();
    int stack_id;
    struct net_device *dev;

    /* Check interface for boundary stages */
    if (stage_id == PATH2_STAGE_0 && targ_direction == DIRECTION_TX) {
        if (!is_target_ifindex(skb))
            return;
    }
    if (stage_id == PATH1_STAGE_0 && targ_direction == DIRECTION_RX) {
        if (!is_target_ifindex(skb))
            return;
    }
    if (stage_id == PATH1_STAGE_1 && targ_direction == DIRECTION_TX) {
        if (!is_target_ifindex(skb))
            return;
    }
    if (stage_id == PATH2_STAGE_2 && targ_direction == DIRECTION_RX) {
        if (!is_target_ifindex(skb))
            return;
    }

    stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);

    if (stage_id == PATH1_STAGE_0) {
        /* Initialize new flow */
        struct icmp_flow_data zero = {};
        bpf_map_update_elem(&flow_sessions, key, &zero, BPF_ANY);
        flow_ptr = bpf_map_lookup_elem(&flow_sessions, key);
    } else {
        flow_ptr = bpf_map_lookup_elem(&flow_sessions, key);
    }

    if (!flow_ptr)
        return;

    /* Only record if not already recorded */
    if (flow_ptr->ts[stage_id] == 0) {
        flow_ptr->ts[stage_id] = current_ts;
        flow_ptr->kstack_id[stage_id] = stack_id;

        /* Get interface name */
        char if_name[IFNAMSIZ] = {};
        dev = BPF_CORE_READ(skb, dev);
        if (dev) {
            bpf_core_read_str(if_name, sizeof(if_name), &dev->name);
        }

        if (stage_id == PATH1_STAGE_0) {
            flow_ptr->p1_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p1_comm, sizeof(flow_ptr->p1_comm));
            __builtin_memcpy(flow_ptr->p1_ifname, if_name, IFNAMSIZ);
            flow_ptr->request_type = icmp_type;
            flow_ptr->saw_path1_start = 1;
        }

        if ((targ_direction == DIRECTION_TX && stage_id == PATH1_STAGE_1) ||
            (targ_direction == DIRECTION_RX && stage_id == PATH1_STAGE_2)) {
            flow_ptr->saw_path1_end = 1;
        }

        if (stage_id == PATH2_STAGE_0 || stage_id == PATH2_STAGE_1) {
            flow_ptr->p2_pid = bpf_get_current_pid_tgid() >> 32;
            bpf_get_current_comm(&flow_ptr->p2_comm, sizeof(flow_ptr->p2_comm));
            __builtin_memcpy(flow_ptr->p2_ifname, if_name, IFNAMSIZ);
            flow_ptr->reply_type = icmp_type;
            flow_ptr->saw_path2_start = 1;
        }

        if (stage_id == PATH2_STAGE_2) {
            flow_ptr->saw_path2_end = 1;
        }
    }

    /* Check if flow is complete */
    if (stage_id == PATH2_STAGE_2 &&
        flow_ptr->saw_path1_start && flow_ptr->saw_path1_end &&
        flow_ptr->saw_path2_start && flow_ptr->saw_path2_end) {

        __u64 rtt_start = flow_ptr->ts[PATH1_STAGE_0];
        __u64 rtt_end = flow_ptr->ts[PATH2_STAGE_2];

        /* Apply latency threshold filter */
        if (targ_latency_threshold_ns > 0) {
            if (rtt_start == 0 || rtt_end == 0 ||
                (rtt_end - rtt_start) < targ_latency_threshold_ns) {
                bpf_map_delete_elem(&flow_sessions, key);
                return;
            }
        }

        /* Submit event */
        struct icmp_rtt_event *event;
        event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
        if (event) {
            __builtin_memcpy(&event->key, key, sizeof(*key));
            __builtin_memcpy(&event->data, flow_ptr, sizeof(event->data));
            bpf_ringbuf_submit(event, 0);
        }

        bpf_map_delete_elem(&flow_sessions, key);
    }
}

/* ========== Probe Points ========== */

/* ip_local_out */
SEC("kprobe/ip_local_out")
int BPF_KPROBE(kprobe_ip_local_out, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    struct icmp_packet_key key = {};
    __u8 icmp_type = 0;

    if (targ_direction == DIRECTION_TX) {
        /* TX: Request path (local -> remote ECHO) */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 0, 0, PATH1_STAGE_0)) {
            handle_event(ctx, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    } else {
        /* RX: Reply path */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 1, 0, PATH2_STAGE_1)) {
            handle_event(ctx, skb, PATH2_STAGE_1, &key, icmp_type);
        }
    }
    return 0;
}

/* dev_queue_xmit */
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    struct icmp_packet_key key = {};
    __u8 icmp_type = 0;

    if (targ_direction == DIRECTION_TX) {
        /* TX: Request path final */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 0, 0, PATH1_STAGE_1)) {
            handle_event(ctx, skb, PATH1_STAGE_1, &key, icmp_type);
        }
    } else {
        /* RX: Reply path final */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 1, 0, PATH2_STAGE_2)) {
            handle_event(ctx, skb, PATH2_STAGE_2, &key, icmp_type);
        }
    }
    return 0;
}

/* netif_receive_skb tracepoint */
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

    struct icmp_packet_key key = {};
    __u8 icmp_type = 0;

    if (targ_direction == DIRECTION_TX) {
        /* TX: Reply path (incoming echo-reply) */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_0)) {
            handle_event(ctx, skb, PATH2_STAGE_0, &key, icmp_type);
        }
    } else {
        /* RX: Request path (source is remote, dest is local) */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_0)) {
            handle_event(ctx, skb, PATH1_STAGE_0, &key, icmp_type);
        }
    }
    return 0;
}

/* ip_rcv */
SEC("kprobe/ip_rcv")
int BPF_KPROBE(kprobe_ip_rcv, struct sk_buff *skb)
{
    struct icmp_packet_key key = {};
    __u8 icmp_type = 0;

    if (targ_direction == DIRECTION_TX) {
        /* TX: Reply path */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_1)) {
            handle_event(ctx, skb, PATH2_STAGE_1, &key, icmp_type);
        }
    } else {
        /* RX: Request path */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_1)) {
            handle_event(ctx, skb, PATH1_STAGE_1, &key, icmp_type);
        }
    }
    return 0;
}

/* icmp_rcv */
SEC("kprobe/icmp_rcv")
int BPF_KPROBE(kprobe_icmp_rcv, struct sk_buff *skb)
{
    struct icmp_packet_key key = {};
    __u8 icmp_type = 0;

    if (targ_direction == DIRECTION_TX) {
        /* TX: Reply path final */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 1, 1, PATH2_STAGE_2)) {
            handle_event(ctx, skb, PATH2_STAGE_2, &key, icmp_type);
        }
    } else {
        /* RX: Request path final */
        if (parse_icmp_packet_key(skb, &key, &icmp_type, 0, 1, PATH1_STAGE_2)) {
            handle_event(ctx, skb, PATH1_STAGE_2, &key, icmp_type);
        }
    }
    return 0;
}
