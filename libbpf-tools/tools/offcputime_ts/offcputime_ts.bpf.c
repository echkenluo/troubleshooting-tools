// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// offcputime_ts - Off-CPU time analysis with timeseries support BPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "offcputime_ts.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u64 min_block_us = 1;
const volatile __u64 max_block_us = -1ULL;
const volatile __u32 targ_tgid = 0;
const volatile __u32 targ_pid = 0;
const volatile __u8 user_threads_only = 0;
const volatile __u8 kernel_threads_only = 0;
const volatile __u8 user_stacks_only = 0;
const volatile __u8 kernel_stacks_only = 0;
const volatile __u32 state_filter = 0;
const volatile __u8 state_filter_enabled = 0;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 16384);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, __u64);
} counts SEC(".maps");

static __always_inline bool allow_thread(struct task_struct *task)
{
    __u32 pid = BPF_CORE_READ(task, pid);
    __u32 tgid = BPF_CORE_READ(task, tgid);

    if (targ_tgid && tgid != targ_tgid)
        return false;
    if (targ_pid && pid != targ_pid)
        return false;

    if (user_threads_only) {
        __u32 flags = BPF_CORE_READ(task, flags);
        if (flags & PF_KTHREAD)
            return false;
    }

    if (kernel_threads_only) {
        __u32 flags = BPF_CORE_READ(task, flags);
        if (!(flags & PF_KTHREAD))
            return false;
    }

    return true;
}

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(kprobe_finish_task_switch, struct task_struct *prev)
{
    __u32 prev_pid = BPF_CORE_READ(prev, pid);
    __u32 prev_tgid = BPF_CORE_READ(prev, tgid);
    __u64 ts;

    /* Record previous thread sleep time */
    if (allow_thread(prev)) {
        if (state_filter_enabled) {
            __u64 state = BPF_CORE_READ(prev, __state);
            if (!(state & state_filter))
                goto current;
        }
        ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&start, &prev_pid, &ts, BPF_ANY);
    }

current:;
    /* Get current thread's start time */
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id & 0xFFFFFFFF;
    __u32 tgid = id >> 32;

    __u64 *tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp)
        return 0;

    __u64 t_start = *tsp;
    __u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&start, &pid);

    if (t_start > t_end)
        return 0;

    __u64 delta = (t_end - t_start) / 1000;  /* Convert to microseconds */
    if (delta < min_block_us || delta > max_block_us)
        return 0;

    /* Create map key */
    struct key_t key = {};
    key.pid = pid;
    key.tgid = tgid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    if (kernel_stacks_only) {
        key.user_stack_id = -1;
    } else {
        key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    }

    if (user_stacks_only) {
        key.kernel_stack_id = -1;
    } else {
        key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    }

    __u64 *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        __sync_fetch_and_add(val, delta);
    } else {
        bpf_map_update_elem(&counts, &key, &delta, BPF_ANY);
    }

    return 0;
}

/* Alternative attachment point for kernels with isra suffix */
SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(kprobe_finish_task_switch_isra, struct task_struct *prev)
{
    return kprobe_finish_task_switch(ctx, prev);
}
