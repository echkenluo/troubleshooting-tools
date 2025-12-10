// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// virtnet_poll_monitor - Virtio-net RX monitor BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "virtnet_poll_monitor.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_queue_index = 0xFFFFFFFF;  /* 0xFFFFFFFF = no filter */
const volatile __u8 targ_filter_queue = 0;

/* Device name filter */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct device_filter);
} filter_device SEC(".maps");

/* Queue filter enabled flag */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_queue_enabled SEC(".maps");

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Poll tracking for correlating entry/exit */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);  /* napi pointer */
    __type(value, struct virtnet_poll_event);
} poll_tracking SEC(".maps");

/* Helper: check if device name matches filter */
static __always_inline bool check_device_filter(struct net_device *dev)
{
    char real_devname[IFNAMSIZ] = {};
    struct device_filter *filter;
    __u32 key = 0;
    int i;

    if (!dev)
        return false;

    bpf_probe_read_kernel_str(real_devname, IFNAMSIZ, dev->name);

    filter = bpf_map_lookup_elem(&filter_device, &key);
    if (!filter)
        return true;

    /* Check if filter is empty (accept all) */
    if (filter->name[0] == 0)
        return true;

    /* Compare device names */
    #pragma unroll
    for (i = 0; i < IFNAMSIZ; i++) {
        if (real_devname[i] != filter->name[i])
            return false;
        if (real_devname[i] == 0)
            break;
    }

    return true;
}

/* Helper: check if queue index matches filter */
static __always_inline bool check_queue_filter(__u32 queue_index)
{
    __u32 key = 0;
    __u32 *enabled;

    enabled = bpf_map_lookup_elem(&filter_queue_enabled, &key);
    if (!enabled || *enabled == 0)
        return true;

    return queue_index == targ_queue_index;
}

/* Trace: virtnet_poll entry */
SEC("kprobe/virtnet_poll")
int BPF_KPROBE(kprobe_virtnet_poll_entry, struct napi_struct *napi, int budget)
{
    struct virtnet_poll_event *event;
    struct net_device *dev;
    void *rq;
    void *vq;
    __u32 vq_index = 0;
    __u32 queue_index;
    __u64 napi_key;

    if (!napi)
        return 0;

    /* Calculate receive_queue pointer using container_of approximation */
    /* rq = container_of(napi, struct receive_queue, napi) */
    rq = (void *)((char *)napi - 8);  /* Approximate offset */

    /* Get virtqueue pointer from rq->vq */
    if (bpf_probe_read_kernel(&vq, sizeof(vq), rq) != 0 || !vq)
        return 0;

    /* Get queue index from vq->index */
    if (bpf_probe_read_kernel(&vq_index, sizeof(vq_index), vq + 4) != 0)
        return 0;
    queue_index = vq_index / 2;

    /* Check queue filter */
    if (!check_queue_filter(queue_index))
        return 0;

    /* Get net_device from napi->dev */
    dev = BPF_CORE_READ(napi, dev);
    if (!dev)
        return 0;

    /* Check device filter */
    if (!check_device_filter(dev))
        return 0;

    /* Create event */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_probe_read_kernel_str(event->dev_name, sizeof(event->dev_name), dev->name);
    event->queue_index = queue_index;
    event->vq_index = vq_index;
    event->budget = budget;

    event->napi_ptr = (__u64)napi;
    event->rq_ptr = (__u64)rq;
    event->vq_ptr = (__u64)vq;
    event->netdev_ptr = (__u64)dev;

    event->event_type = EVENT_POLL_ENTRY;

    /* Store event for correlation with return probe */
    napi_key = (__u64)napi;
    struct virtnet_poll_event stored_event = *event;
    bpf_map_update_elem(&poll_tracking, &napi_key, &stored_event, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* Trace: virtnet_poll return */
SEC("kretprobe/virtnet_poll")
int BPF_KRETPROBE(kretprobe_virtnet_poll, int ret)
{
    /* Note: Getting napi pointer in kretprobe is tricky
     * We'd need to store it in entry probe and correlate by tid */
    return 0;
}

/* Trace: skb_recv_done - virtio-net RX interrupt handler */
SEC("kprobe/skb_recv_done")
int BPF_KPROBE(kprobe_skb_recv_done, void *rvq)
{
    struct virtnet_poll_event *event;
    void *vdev;
    void *vi;
    struct net_device *dev;
    __u32 vq_index = 0;
    __u32 queue_index;

    if (!rvq)
        return 0;

    /* Get vq->index */
    if (bpf_probe_read_kernel(&vq_index, sizeof(vq_index), rvq + 4) != 0)
        return 0;
    queue_index = vq_index / 2;

    /* Check queue filter */
    if (!check_queue_filter(queue_index))
        return 0;

    /* Get virtio_device from virtqueue */
    if (bpf_probe_read_kernel(&vdev, sizeof(vdev), rvq + 8) != 0 || !vdev)
        return 0;

    /* Get virtnet_info from vdev->priv */
    if (bpf_probe_read_kernel(&vi, sizeof(vi), vdev + 248) != 0 || !vi)
        return 0;

    /* Get net_device from virtnet_info->dev (offset 16) */
    if (bpf_probe_read_kernel(&dev, sizeof(dev), vi + 16) != 0 || !dev)
        return 0;

    /* Check device filter */
    if (!check_device_filter(dev))
        return 0;

    /* Create event */
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_probe_read_kernel_str(event->dev_name, sizeof(event->dev_name), dev->name);
    event->queue_index = queue_index;
    event->vq_index = vq_index;

    event->vq_ptr = (__u64)rvq;
    event->netdev_ptr = (__u64)dev;

    event->event_type = EVENT_SKB_RECV_DONE;

    bpf_ringbuf_submit(event, 0);
    return 0;
}
