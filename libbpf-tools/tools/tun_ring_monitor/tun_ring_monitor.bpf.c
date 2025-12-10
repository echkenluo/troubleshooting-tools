// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_ring_monitor - TUN ptr_ring monitor BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tun_ring_monitor.h"

char LICENSE[] SEC("license") = "GPL";

#define NETDEV_ALIGN 32

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __u8 show_all_events = 0;

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

/* TUN private data structures - extracted from kernel */
struct tun_file_layout {
    struct sock sk;
    struct socket socket;
};

/* Helper: Get ptr_ring depth */
static __always_inline __u32 get_ptr_ring_depth(void *ptr_ring)
{
    if (!ptr_ring)
        return 0;

    __u32 producer = 0, consumer_tail = 0, size = 0;

    /* Read ptr_ring fields at known offsets */
    /* struct ptr_ring: producer at 0, consumer_head at 4, consumer_tail at 8, size at 12 */
    bpf_probe_read_kernel(&producer, sizeof(producer), ptr_ring);
    bpf_probe_read_kernel(&consumer_tail, sizeof(consumer_tail), ptr_ring + 8);
    bpf_probe_read_kernel(&size, sizeof(size), ptr_ring + 12);

    if (size == 0)
        return 0;

    __u32 used;
    if (producer >= consumer_tail)
        used = producer - consumer_tail;
    else
        used = size - consumer_tail + producer;

    return used;
}

/* Probe: tun_net_xmit */
SEC("kprobe/tun_net_xmit")
int BPF_KPROBE(kprobe_tun_net_xmit, struct sk_buff *skb, struct net_device *dev)
{
    __u32 ifindex;
    struct ring_event *e;

    if (!skb || !dev)
        return 0;

    ifindex = BPF_CORE_READ(dev, ifindex);
    if (targ_ifindex != 0 && ifindex != targ_ifindex)
        return 0;

    /* Get queue mapping */
    __u32 queue_mapping = BPF_CORE_READ(skb, queue_mapping);

    /* Get TUN private data (located after net_device) */
    __u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    void *tun_priv = (void *)dev + aligned_size;

    /* Read numqueues - first field in tun_struct after tfiles array */
    __u32 numqueues = 0;
    /* tfiles is array of 256 pointers at offset 0, numqueues at offset 2048 (256 * 8) */
    bpf_probe_read_kernel(&numqueues, sizeof(numqueues), tun_priv + 2048);

    if (queue_mapping >= numqueues || numqueues == 0 || numqueues > 256)
        return 0;

    /* Get tfile pointer from tfiles array */
    void *tfile = NULL;
    bpf_probe_read_kernel(&tfile, sizeof(tfile), tun_priv + (queue_mapping * 8));
    if (!tfile)
        return 0;

    /* Get ptr_ring - located after known fields in tun_file */
    /* Approximate offset based on struct layout */
    void *tx_ring = tfile + 1024;  /* Approximate offset to tx_ring */

    __u32 producer = 0, consumer_head = 0, consumer_tail = 0, ring_size = 0;
    bpf_probe_read_kernel(&producer, sizeof(producer), tx_ring);
    bpf_probe_read_kernel(&consumer_head, sizeof(consumer_head), tx_ring + 4);
    bpf_probe_read_kernel(&consumer_tail, sizeof(consumer_tail), tx_ring + 8);
    bpf_probe_read_kernel(&ring_size, sizeof(ring_size), tx_ring + 12);

    /* Check if ring is full */
    void **queue = NULL;
    bpf_probe_read_kernel(&queue, sizeof(queue), tx_ring + 24);

    __u32 ring_full = 0;
    __u64 queue_producer_ptr = 0;

    if (queue && ring_size > 0 && producer < ring_size) {
        void *entry = NULL;
        bpf_probe_read_kernel(&entry, sizeof(entry), &queue[producer]);
        queue_producer_ptr = (__u64)entry;
        ring_full = (entry != NULL) ? 1 : 0;
    }

    /* Only emit event if ring is full or show_all_events is set */
    if (!ring_full && !show_all_events)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->dev_name, sizeof(e->dev_name), BPF_CORE_READ(dev, name));
    e->queue_mapping = queue_mapping;
    e->ptr_ring_size = ring_size;
    e->producer = producer;
    e->consumer_head = consumer_head;
    e->consumer_tail = consumer_tail;
    e->ring_full = ring_full;
    e->skb_addr = (__u64)skb;
    e->queue_producer_ptr = queue_producer_ptr;
    e->tun_numqueues = numqueues;
    e->queue_index = queue_mapping;

    /* Parse packet headers if possible */
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);

    if (head && network_header != (__u16)~0U && network_header < 2048) {
        struct iphdr ip;
        if (bpf_core_read(&ip, sizeof(ip), head + network_header) == 0) {
            e->saddr = ip.saddr;
            e->daddr = ip.daddr;
            e->protocol = ip.protocol;

            __u16 transport_header = BPF_CORE_READ(skb, transport_header);
            if (transport_header == 0 || transport_header == network_header) {
                __u8 ihl = ip.ihl & 0xF;
                transport_header = network_header + (ihl * 4);
            }

            if (ip.protocol == 6) { /* TCP */
                struct tcphdr tcp;
                if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header) == 0) {
                    e->sport = tcp.source;
                    e->dport = tcp.dest;
                }
            } else if (ip.protocol == 17) { /* UDP */
                struct udphdr udp;
                if (bpf_core_read(&udp, sizeof(udp), head + transport_header) == 0) {
                    e->sport = udp.source;
                    e->dport = udp.dest;
                }
            }
        }
    }

    bpf_ringbuf_submit(e, 0);

    /* Update counters */
    __u32 idx = ring_full ? 0 : 1;
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return 0;
}
