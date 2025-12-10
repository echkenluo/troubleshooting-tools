// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_buf_peek_stats - Track vhost_net_buf_peek return values BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vhost_buf_peek_stats.h"

char LICENSE[] SEC("license") = "GPL";

/* Stats map - keyed by nvq_ptr and ret_val */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct stats_key);
    __type(value, __u64);
} counts SEC(".maps");

/* Thread-local storage for nvq pointer */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  /* pid_tgid */
    __type(value, __u64);  /* nvq_ptr */
} nvq_map SEC(".maps");

/* Trace: vhost_net_buf_peek entry */
SEC("kprobe/vhost_net_buf_peek")
int BPF_KPROBE(kprobe_vhost_net_buf_peek_entry, void *nvq)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 nvq_val = (__u64)nvq;

    bpf_map_update_elem(&nvq_map, &pid_tgid, &nvq_val, BPF_ANY);
    return 0;
}

/* Trace: vhost_net_buf_peek return */
SEC("kretprobe/vhost_net_buf_peek")
int BPF_KRETPROBE(kretprobe_vhost_net_buf_peek, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *nvq_ptr;
    struct stats_key key = {};
    __u64 *count;

    nvq_ptr = bpf_map_lookup_elem(&nvq_map, &pid_tgid);
    if (!nvq_ptr)
        return 0;

    key.nvq_ptr = *nvq_ptr;
    key.ret_val = ret;

    count = bpf_map_lookup_elem(&counts, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&counts, &key, &one, BPF_ANY);
    }

    bpf_map_delete_elem(&nvq_map, &pid_tgid);
    return 0;
}
