// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_queue_correlation_details - VHOST-NET queue correlation BPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vhost_queue_correlation_details.h"

char LICENSE[] SEC("license") = "GPL";

#define NETDEV_ALIGN 32

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __u32 targ_queue = 0;
const volatile __u8 filter_queue_enabled = 0;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct queue_key);
} target_queues SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} handle_rx_vqs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Helper: Get ptr_ring state */
static __always_inline void get_ptr_ring_state(void *tfile, struct queue_event *event)
{
    if (!tfile)
        return;

    void *tx_ring = tfile + 1024;

    bpf_probe_read_kernel(&event->producer, sizeof(event->producer), tx_ring);
    bpf_probe_read_kernel(&event->consumer_head, sizeof(event->consumer_head), tx_ring + 4);
    bpf_probe_read_kernel(&event->consumer_tail, sizeof(event->consumer_tail), tx_ring + 8);
    bpf_probe_read_kernel(&event->ptr_ring_size, sizeof(event->ptr_ring_size), tx_ring + 12);

    if (event->ptr_ring_size > 0) {
        void **queue = NULL;
        bpf_probe_read_kernel(&queue, sizeof(queue), tx_ring + 24);
        if (queue && event->producer < event->ptr_ring_size) {
            void *entry = NULL;
            bpf_probe_read_kernel(&entry, sizeof(entry), &queue[event->producer]);
            event->ring_full = entry != NULL ? 1 : 0;
        }
    }
}

/* Helper: Get VQ state */
static __always_inline void get_vq_state(void *vq, struct queue_event *event)
{
    if (!vq)
        return;

    bpf_probe_read_kernel(&event->last_avail_idx, sizeof(event->last_avail_idx), vq + 332);
    bpf_probe_read_kernel(&event->avail_idx, sizeof(event->avail_idx), vq + 334);
    bpf_probe_read_kernel(&event->last_used_idx, sizeof(event->last_used_idx), vq + 336);
    bpf_probe_read_kernel(&event->used_flags, sizeof(event->used_flags), vq + 338);
    bpf_probe_read_kernel(&event->signalled_used, sizeof(event->signalled_used), vq + 340);
    bpf_probe_read_kernel(&event->signalled_used_valid, sizeof(event->signalled_used_valid), vq + 342);
    bpf_probe_read_kernel(&event->acked_features, sizeof(event->acked_features), vq + 17440);
}

/* Probe: tun_net_xmit */
SEC("kprobe/tun_net_xmit")
int BPF_KPROBE(kprobe_tun_net_xmit, struct sk_buff *skb, struct net_device *dev)
{
    if (!skb || !dev)
        return 0;

    __u32 ifindex = BPF_CORE_READ(dev, ifindex);
    if (targ_ifindex != 0 && ifindex != targ_ifindex)
        return 0;

    __u32 queue_mapping = BPF_CORE_READ(skb, queue_mapping);
    if (filter_queue_enabled && queue_mapping != targ_queue)
        return 0;

    /* Get TUN private data */
    __u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    void *tun_priv = (void *)dev + aligned_size;

    __u32 numqueues = 0;
    bpf_probe_read_kernel(&numqueues, sizeof(numqueues), tun_priv + 2048);

    if (queue_mapping >= numqueues || numqueues == 0 || numqueues > 256)
        return 0;

    void *tfile = NULL;
    bpf_probe_read_kernel(&tfile, sizeof(tfile), tun_priv + (queue_mapping * 8));
    if (!tfile)
        return 0;

    __u64 sock_ptr = (__u64)(tfile + 640);

    /* Track this queue */
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_mapping;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), BPF_CORE_READ(dev, name));
    bpf_map_update_elem(&target_queues, &sock_ptr, &qkey, BPF_ANY);

    /* Create event */
    struct queue_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_TUN_XMIT;

    e->sock_ptr = sock_ptr;
    e->queue_index = queue_mapping;
    bpf_probe_read_kernel_str(e->dev_name, sizeof(e->dev_name), BPF_CORE_READ(dev, name));
    e->skb_ptr = (__u64)skb;
    e->tfile_ptr = (__u64)tfile;

    /* Parse packet headers */
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

            if (ip.protocol == 6) {
                struct tcphdr tcp;
                if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header) == 0) {
                    e->sport = tcp.source;
                    e->dport = tcp.dest;
                }
            } else if (ip.protocol == 17) {
                struct udphdr udp;
                if (bpf_core_read(&udp, sizeof(udp), head + transport_header) == 0) {
                    e->sport = udp.source;
                    e->dport = udp.dest;
                }
            }
        }
    }

    get_ptr_ring_state(tfile, e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Probe: handle_rx */
SEC("kprobe/handle_rx")
int BPF_KPROBE(kprobe_handle_rx, void *net)
{
    if (!net)
        return 0;

    void *nvq = net + 192;
    void *vq = nvq;

    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 17424);

    __u64 sock_ptr = (__u64)private_data;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Track VQ for signal filtering */
    __u64 vq_addr = (__u64)vq;
    bpf_map_update_elem(&handle_rx_vqs, &sock_ptr, &vq_addr, BPF_ANY);

    struct queue_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_HANDLE_RX;

    e->sock_ptr = sock_ptr;
    e->queue_index = qkey->queue_index;
    __builtin_memcpy(e->dev_name, qkey->dev_name, sizeof(e->dev_name));
    e->vq_ptr = (__u64)vq;
    e->nvq_ptr = (__u64)nvq;

    /* Get busyloop timeouts */
    bpf_probe_read_kernel(&e->rx_busyloop_timeout, sizeof(e->rx_busyloop_timeout), vq + 17464);

    void *tx_nvq = net + 192 + 17500;  /* Approximate offset to TX NVQ */
    void *tx_vq = tx_nvq;
    bpf_probe_read_kernel(&e->tx_busyloop_timeout, sizeof(e->tx_busyloop_timeout), tx_vq + 17464);

    get_vq_state(vq, e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Probe: tun_recvmsg */
SEC("kprobe/tun_recvmsg")
int BPF_KPROBE(kprobe_tun_recvmsg, void *sock, void *m, size_t len, int flags)
{
    if (!sock)
        return 0;

    __u64 sock_ptr = (__u64)sock;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    void *tfile = sock - 640;

    struct queue_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_TUN_RECVMSG;

    e->sock_ptr = sock_ptr;
    e->queue_index = qkey->queue_index;
    __builtin_memcpy(e->dev_name, qkey->dev_name, sizeof(e->dev_name));
    e->tfile_ptr = (__u64)tfile;

    get_ptr_ring_state(tfile, e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Probe: vhost_signal */
SEC("kprobe/vhost_signal")
int BPF_KPROBE(kprobe_vhost_signal, void *dev, void *vq)
{
    if (!vq)
        return 0;

    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 17424);

    __u64 sock_ptr = (__u64)private_data;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Filter: only process signals from handle_rx VQs */
    __u64 *expected_vq = bpf_map_lookup_elem(&handle_rx_vqs, &sock_ptr);
    if (expected_vq && *expected_vq != (__u64)vq)
        return 0;

    struct queue_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_VHOST_SIGNAL;

    e->sock_ptr = sock_ptr;
    e->queue_index = qkey->queue_index;
    __builtin_memcpy(e->dev_name, qkey->dev_name, sizeof(e->dev_name));
    e->vq_ptr = (__u64)vq;

    get_vq_state(vq, e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Probe: vhost_add_used_and_signal_n */
SEC("kprobe/vhost_add_used_and_signal_n")
int BPF_KPROBE(kprobe_vhost_add_signal, void *dev, void *vq)
{
    if (!vq)
        return 0;

    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 17424);

    __u64 sock_ptr = (__u64)private_data;

    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    struct queue_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->event_type = EVENT_VHOST_NOTIFY;

    e->sock_ptr = sock_ptr;
    e->queue_index = qkey->queue_index;
    __builtin_memcpy(e->dev_name, qkey->dev_name, sizeof(e->dev_name));
    e->vq_ptr = (__u64)vq;

    get_vq_state(vq, e);

    /* Check EVENT_IDX feature */
    e->has_event_idx_feature = (e->acked_features & (1ULL << 29)) != 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
