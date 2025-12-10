// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_tx_to_kvm_irq - TUN TX to KVM IRQ interrupt chain tracer BPF program
//
// Traces the complete interrupt chain for TUN TX queue:
// tun_net_xmit -> vhost_signal -> irqfd_wakeup

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tun_tx_to_kvm_irq.h"

char LICENSE[] SEC("license") = "GPL";

#define NETDEV_ALIGN 32

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __u32 targ_queue = 0xFFFFFFFF;  /* 0xFFFFFFFF = all queues */

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Track target queues: sock_ptr -> queue_key */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct queue_key);
} target_queues SEC(".maps");

/* Track interrupt chains: eventfd_ctx -> connection info */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct interrupt_connection);
} interrupt_chains SEC(".maps");

/* Sequence tracking: eventfd_ctx -> last stage */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} sequence_check SEC(".maps");

/* Stage counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* Helper to submit event */
static __always_inline void submit_event(struct interrupt_event *e, __u8 stage)
{
    e->timestamp = bpf_ktime_get_ns();
    e->cpu_id = bpf_get_smp_processor_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->stage = stage;

    bpf_ringbuf_submit(e, 0);

    /* Update counter */
    __u32 idx = stage;
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* Stage 1: tun_net_xmit - packet entering TUN device TX path */
SEC("kprobe/tun_net_xmit")
int BPF_KPROBE(kprobe_tun_net_xmit, struct sk_buff *skb, struct net_device *dev)
{
    __u32 ifindex;

    if (!skb || !dev)
        return 0;

    ifindex = BPF_CORE_READ(dev, ifindex);
    if (targ_ifindex != 0 && ifindex != targ_ifindex)
        return 0;

    __u32 queue_mapping = BPF_CORE_READ(skb, queue_mapping);

    /* Check queue filter */
    if (targ_queue != 0xFFFFFFFF && queue_mapping != targ_queue)
        return 0;

    /* Get TUN private data (located after net_device) */
    __u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    void *tun_priv = (void *)dev + aligned_size;

    /* Read numqueues */
    __u32 numqueues = 0;
    bpf_probe_read_kernel(&numqueues, sizeof(numqueues), tun_priv + 2048);

    if (queue_mapping >= numqueues || numqueues == 0 || numqueues > 256)
        return 0;

    /* Get tfile pointer from tfiles array */
    void *tfile = NULL;
    bpf_probe_read_kernel(&tfile, sizeof(tfile), tun_priv + (queue_mapping * 8));
    if (!tfile)
        return 0;

    /* Get socket pointer from tfile */
    __u64 sock_ptr = (__u64)tfile + sizeof(struct sock);

    /* Register this queue as target */
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_mapping;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), BPF_CORE_READ(dev, name));

    bpf_map_update_elem(&target_queues, &sock_ptr, &qkey, BPF_ANY);

    /* Reserve event */
    struct interrupt_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->queue_index = queue_mapping;
    e->sock_ptr = sock_ptr;
    __builtin_memcpy(e->dev_name, qkey.dev_name, sizeof(e->dev_name));

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

            if (ip.protocol == 6) {  /* TCP */
                struct tcphdr tcp;
                if (bpf_core_read(&tcp, sizeof(tcp), head + transport_header) == 0) {
                    e->sport = tcp.source;
                    e->dport = tcp.dest;
                }
            } else if (ip.protocol == 17) {  /* UDP */
                struct udphdr udp;
                if (bpf_core_read(&udp, sizeof(udp), head + transport_header) == 0) {
                    e->sport = udp.source;
                    e->dport = udp.dest;
                }
            }
        }
    }

    submit_event(e, STAGE_TUN_NET_XMIT);
    return 0;
}

/* Stage 2: vhost_add_used_and_signal_n - vhost signaling guest */
SEC("kprobe/vhost_add_used_and_signal_n")
int BPF_KPROBE(kprobe_vhost_signal, void *dev, struct vhost_virtqueue *vq)
{
    if (!vq)
        return 0;

    /* Get sock pointer from private_data */
    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data),
                          (void *)vq + offsetof(struct vhost_virtqueue, private_data));

    __u64 sock_ptr = (__u64)private_data;

    /* Check if this is our target queue */
    struct queue_key *qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Get eventfd_ctx for chain connection */
    struct eventfd_ctx *call_ctx = NULL;
    bpf_probe_read_kernel(&call_ctx, sizeof(call_ctx),
                          (void *)vq + offsetof(struct vhost_virtqueue, call_ctx));

    if (!call_ctx)
        return 0;

    __u64 eventfd_ctx = (__u64)call_ctx;

    /* Save interrupt chain connection */
    struct interrupt_connection ic = {};
    ic.sock_ptr = sock_ptr;
    ic.eventfd_ctx = eventfd_ctx;
    __builtin_memcpy(ic.dev_name, qkey->dev_name, sizeof(ic.dev_name));
    ic.queue_index = qkey->queue_index;
    ic.timestamp = bpf_ktime_get_ns();

    bpf_map_update_elem(&interrupt_chains, &eventfd_ctx, &ic, BPF_ANY);

    /* Update sequence - Stage 2 */
    __u64 stage = STAGE_VHOST_SIGNAL;
    bpf_map_update_elem(&sequence_check, &eventfd_ctx, &stage, BPF_ANY);

    /* Submit event */
    struct interrupt_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->dev_name, qkey->dev_name, sizeof(e->dev_name));
    e->queue_index = qkey->queue_index;
    e->sock_ptr = sock_ptr;
    e->eventfd_ctx = eventfd_ctx;
    e->vq_ptr = (__u64)vq;

    submit_event(e, STAGE_VHOST_SIGNAL);
    return 0;
}

/* Stage 3: irqfd_wakeup - KVM irqfd wakeup callback */
SEC("kprobe/irqfd_wakeup")
int BPF_KPROBE(kprobe_irqfd_wakeup, wait_queue_entry_t *wait, unsigned int mode,
               int sync, void *key)
{
    if (!wait)
        return 0;

    /* Check EPOLLIN flag */
    __u64 flags = (__u64)key;
    if (!(flags & 0x1))
        return 0;

    /*
     * Get kvm_kernel_irqfd from wait using container_of
     * wait is at offset 8 in kvm_kernel_irqfd (after struct kvm *)
     */
    void *irqfd = (void *)wait - 8;

    /* Read eventfd_ctx and gsi from irqfd */
    struct eventfd_ctx *eventfd = NULL;
    int gsi = 0;

    /* eventfd is at offset 80 in kvm_kernel_irqfd */
    bpf_probe_read_kernel(&eventfd, sizeof(eventfd), irqfd + 80);
    /* gsi is at offset 48 */
    bpf_probe_read_kernel(&gsi, sizeof(gsi), irqfd + 48);

    __u64 eventfd_ctx = (__u64)eventfd;

    /* Validate eventfd_ctx */
    if (!eventfd || eventfd_ctx < 0xffff000000000000ULL)
        return 0;

    /* Check interrupt chain */
    struct interrupt_connection *ic = bpf_map_lookup_elem(&interrupt_chains, &eventfd_ctx);
    if (!ic)
        return 0;

    /* Validate GSI range */
    if (gsi < 24 || gsi > 255)
        return 0;

    /* Verify sequence - Stage 2 should have happened */
    __u64 *last_stage = bpf_map_lookup_elem(&sequence_check, &eventfd_ctx);
    if (!last_stage || *last_stage != STAGE_VHOST_SIGNAL)
        return 0;

    /* Calculate delay */
    __u64 timestamp = bpf_ktime_get_ns();
    __u64 delay_ns = timestamp - ic->timestamp;

    /* Update sequence - Stage 3 */
    __u64 stage = STAGE_IRQFD_WAKEUP;
    bpf_map_update_elem(&sequence_check, &eventfd_ctx, &stage, BPF_ANY);

    /* Submit event */
    struct interrupt_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    __builtin_memcpy(e->dev_name, ic->dev_name, sizeof(e->dev_name));
    e->queue_index = ic->queue_index;
    e->sock_ptr = ic->sock_ptr;
    e->eventfd_ctx = eventfd_ctx;
    e->gsi = (__u32)gsi;
    e->delay_ns = delay_ns;

    submit_event(e, STAGE_IRQFD_WAKEUP);
    return 0;
}
