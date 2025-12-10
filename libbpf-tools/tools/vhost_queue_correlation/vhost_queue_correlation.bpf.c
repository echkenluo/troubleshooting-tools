// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_queue_correlation - VHOST queue correlation BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vhost_queue_correlation.h"

char LICENSE[] SEC("license") = "GPL";

#define NETDEV_ALIGN 32

/* Configuration - set from userspace before load */
const volatile __u32 targ_queue_index = 0xFFFFFFFF;  /* 0xFFFFFFFF = no filter */
const volatile __u8 targ_filter_queue = 0;

/* Target device name filter */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, union name_buf);
} name_map SEC(".maps");

/* Target queues map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);  /* sock_ptr */
    __type(value, struct queue_key);
} target_queues SEC(".maps");

/* Thread-local storage for vhost_notify */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);  /* tid */
    __type(value, void *);  /* vq pointer */
} vhost_notify_params SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Helper: check if device name matches filter */
static __always_inline bool name_filter(struct net_device *dev)
{
    union name_buf real_devname = {};
    union name_buf *filter;
    __u32 key = 0;

    bpf_probe_read_kernel(&real_devname, IFNAMSIZ, dev->name);

    filter = bpf_map_lookup_elem(&name_map, &key);
    if (!filter)
        return true;

    if (filter->name_int.hi == 0 && filter->name_int.lo == 0)
        return true;

    if (filter->name_int.hi != real_devname.name_int.hi ||
        filter->name_int.lo != real_devname.name_int.lo)
        return false;

    return true;
}

/* Helper: get vhost_virtqueue state */
static __always_inline void get_vhost_vq_state(void *vq, struct queue_event *event)
{
    if (!vq)
        return;

    /* Read VQ fields - offsets based on kernel struct vhost_virtqueue */
    bpf_probe_read_kernel(&event->last_avail_idx, sizeof(__u16), vq + 192);
    bpf_probe_read_kernel(&event->avail_idx, sizeof(__u16), vq + 194);
    bpf_probe_read_kernel(&event->last_used_idx, sizeof(__u16), vq + 196);
    bpf_probe_read_kernel(&event->used_flags, sizeof(__u16), vq + 198);
    bpf_probe_read_kernel(&event->signalled_used, sizeof(__u16), vq + 200);
    bpf_probe_read_kernel(&event->signalled_used_valid, sizeof(__u8), vq + 202);
    bpf_probe_read_kernel(&event->log_used, sizeof(__u8), vq + 203);
    bpf_probe_read_kernel(&event->log_addr, sizeof(__u64), vq + 208);
    bpf_probe_read_kernel(&event->acked_features, sizeof(__u64), vq + 8296);
    bpf_probe_read_kernel(&event->acked_backend_features, sizeof(__u64), vq + 8304);
}

/* Trace: tun_net_xmit - track queue */
SEC("kprobe/tun_net_xmit")
int BPF_KPROBE(kprobe_tun_net_xmit, struct sk_buff *skb, struct net_device *dev)
{
    __u32 queue_index;
    void *tun;
    __u32 tun_numqueues;
    void *tfile;
    __u64 sock_ptr;
    struct queue_key qkey = {};

    if (!skb || !dev)
        return 0;

    /* Apply device filter */
    if (!name_filter(dev))
        return 0;

    queue_index = BPF_CORE_READ(skb, queue_mapping);

    /* Check queue filter */
    if (targ_filter_queue && queue_index != targ_queue_index)
        return 0;

    /* Get TUN structure - located after net_device with alignment */
    __u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    tun = (void *)((char *)dev + aligned_size);

    bpf_probe_read_kernel(&tun_numqueues, sizeof(tun_numqueues), tun + 260);

    if (queue_index >= tun_numqueues || queue_index >= MAX_QUEUES)
        return 0;

    /* Get tfile pointer */
    void **tfile_ptr_addr = (void **)(tun + queue_index * sizeof(void *));
    if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0 || !tfile)
        return 0;

    /* Get socket pointer from tfile - socket is at offset 16 after sock */
    sock_ptr = (__u64)(tfile + 216);  /* Approximate offset to socket */

    /* Track this queue's sock pointer */
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_index;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), dev->name);
    bpf_map_update_elem(&target_queues, &sock_ptr, &qkey, BPF_ANY);

    return 0;
}

/* Trace: vhost_signal */
SEC("kprobe/vhost_signal")
int BPF_KPROBE(kprobe_vhost_signal, void *dev, void *vq)
{
    void *private_data;
    __u64 sock_ptr;
    struct queue_key *qkey;
    struct queue_event *event;

    if (!vq)
        return 0;

    /* Get private_data (socket) from vq */
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 8312);  /* private_data offset */
    sock_ptr = (__u64)private_data;

    /* Check if this is our target queue */
    qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Create event */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->event_type = EVENT_VHOST_SIGNAL;

    event->sock_ptr = sock_ptr;
    event->queue_index = qkey->queue_index;
    __builtin_memcpy(event->dev_name, qkey->dev_name, sizeof(event->dev_name));
    event->vq_ptr = (__u64)vq;

    /* Get vhost virtqueue state */
    get_vhost_vq_state(vq, event);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace: vhost_notify entry */
SEC("kprobe/vhost_notify")
int BPF_KPROBE(kprobe_vhost_notify_entry, void *dev, void *vq)
{
    void *private_data;
    __u64 sock_ptr;
    struct queue_key *qkey;
    __u64 tid;

    if (!vq)
        return 0;

    /* Get private_data (socket) from vq */
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 8312);
    sock_ptr = (__u64)private_data;

    /* Check if this is our target queue */
    qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Store vq pointer for return probe */
    tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&vhost_notify_params, &tid, &vq, BPF_ANY);

    return 0;
}

/* Trace: vhost_notify return */
SEC("kretprobe/vhost_notify")
int BPF_KRETPROBE(kretprobe_vhost_notify, int ret)
{
    __u64 tid = bpf_get_current_pid_tgid();
    void **vq_ptr;
    void *vq;
    void *private_data;
    __u64 sock_ptr;
    struct queue_key *qkey;
    struct queue_event *event;

    vq_ptr = bpf_map_lookup_elem(&vhost_notify_params, &tid);
    if (!vq_ptr || !*vq_ptr)
        return 0;

    vq = *vq_ptr;
    bpf_map_delete_elem(&vhost_notify_params, &tid);

    /* Get sock pointer */
    bpf_probe_read_kernel(&private_data, sizeof(private_data), vq + 8312);
    sock_ptr = (__u64)private_data;

    /* Check if this is our target queue */
    qkey = bpf_map_lookup_elem(&target_queues, &sock_ptr);
    if (!qkey)
        return 0;

    /* Create event */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = tid >> 32;
    event->tid = tid & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->event_type = EVENT_VHOST_NOTIFY;

    event->sock_ptr = sock_ptr;
    event->queue_index = qkey->queue_index;
    __builtin_memcpy(event->dev_name, qkey->dev_name, sizeof(event->dev_name));
    event->vq_ptr = (__u64)vq;

    /* Get return value */
    event->ret_val = ret;

    /* Get vhost virtqueue state */
    get_vhost_vq_state(vq, event);

    /* Check VIRTIO_RING_F_EVENT_IDX feature */
    __u64 acked_features = 0;
    bpf_probe_read_kernel(&acked_features, sizeof(acked_features), vq + 8296);
    event->has_event_idx_feature = (acked_features & (1ULL << 29)) != 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}
