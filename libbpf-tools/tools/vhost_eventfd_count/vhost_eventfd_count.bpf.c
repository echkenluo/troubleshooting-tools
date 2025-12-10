// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_eventfd_count - Count vhost virtqueue + eventfd combinations BPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vhost_eventfd_count.h"

char LICENSE[] SEC("license") = "GPL";

/* Map to count VQ + eventfd combinations */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct count_key);
    __type(value, __u64);
} counts SEC(".maps");

/* Probe: vhost_add_used_and_signal_n */
SEC("kprobe/vhost_add_used_and_signal_n")
int BPF_KPROBE(kprobe_vhost_signal, void *dev, void *vq)
{
    if (!vq)
        return 0;

    struct count_key key = {};
    key.vq_ptr = (__u64)vq;

    /* Read eventfd_ctx pointer at offset 424 (call_ctx field) */
    __u64 eventfd_ptr = 0;
    bpf_probe_read_kernel(&eventfd_ptr, sizeof(eventfd_ptr), vq + 424);
    key.eventfd_ptr = eventfd_ptr;

    __u64 *count = bpf_map_lookup_elem(&counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&counts, &key, &init, BPF_ANY);
    }

    return 0;
}
