// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ksoftirqd_sched_latency - ksoftirqd scheduling latency measurement BPF program
//
// Measures scheduling latency of ksoftirqd kernel threads

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ksoftirqd_sched_latency.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __s32 targ_cpu = -1;  /* -1 means all CPUs */

/* Wakeup timestamp map: PID -> timestamp */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} wakeup_ts SEC(".maps");

/* Per-CPU scheduling latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CPUS * MAX_SLOTS);
    __type(key, struct hist_key);
    __type(value, __u64);
} latency_hist SEC(".maps");

/* Per-CPU wakeup count */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __type(value, __u64);
} wakeup_count SEC(".maps");

/* Per-CPU run count */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __type(value, __u64);
} run_count SEC(".maps");

/* Per-CPU high latency count (>100us) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, __u32);
    __type(value, __u64);
} high_latency_count SEC(".maps");

/* Helper: log2 approximation */
static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    if (v > 0) {
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (v <= 1)
                break;
            v >>= 1;
            r++;
        }
    }
    return r;
}

/* Helper: check if task is ksoftirqd */
static __always_inline bool is_ksoftirqd(const char *comm)
{
    /* Check for "ksoftirqd/" prefix */
    return (comm[0] == 'k' && comm[1] == 's' && comm[2] == 'o' &&
            comm[3] == 'f' && comm[4] == 't' && comm[5] == 'i' &&
            comm[6] == 'r' && comm[7] == 'q' && comm[8] == 'd');
}

/* Tracepoint: sched_wakeup - ksoftirqd is woken up */
SEC("tracepoint/sched/sched_wakeup")
int tracepoint_sched_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    char comm[TASK_COMM_LEN];
    bpf_probe_read_kernel_str(comm, sizeof(comm), ctx->comm);

    if (!is_ksoftirqd(comm))
        return 0;

    __u32 pid = ctx->pid;
    __u32 target_cpu = ctx->target_cpu;

    /* Apply CPU filter */
    if (targ_cpu >= 0 && target_cpu != (__u32)targ_cpu)
        return 0;

    /* Record wakeup timestamp */
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &pid, &ts, BPF_ANY);

    /* Increment wakeup counter */
    __u64 *cnt = bpf_map_lookup_elem(&wakeup_count, &target_cpu);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return 0;
}

/* Tracepoint: sched_switch - ksoftirqd starts running */
SEC("tracepoint/sched/sched_switch")
int tracepoint_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    char next_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel_str(next_comm, sizeof(next_comm), ctx->next_comm);

    if (!is_ksoftirqd(next_comm))
        return 0;

    __u32 pid = ctx->next_pid;
    __u32 cpu = bpf_get_smp_processor_id();

    /* Apply CPU filter */
    if (targ_cpu >= 0 && cpu != (__u32)targ_cpu)
        return 0;

    /* Lookup wakeup timestamp */
    __u64 *wakeup_ts_ptr = bpf_map_lookup_elem(&wakeup_ts, &pid);
    if (!wakeup_ts_ptr)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 latency_ns = now - *wakeup_ts_ptr;
    __u64 latency_us = latency_ns / 1000;

    /* Update histogram */
    struct hist_key hkey = {
        .cpu = cpu,
        .slot = log2l(latency_us + 1)
    };
    if (hkey.slot >= MAX_SLOTS)
        hkey.slot = MAX_SLOTS - 1;

    __u64 *hist_cnt = bpf_map_lookup_elem(&latency_hist, &hkey);
    if (hist_cnt) {
        __sync_fetch_and_add(hist_cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&latency_hist, &hkey, &one, BPF_ANY);
    }

    /* Increment run counter */
    __u64 *run_cnt = bpf_map_lookup_elem(&run_count, &cpu);
    if (run_cnt)
        __sync_fetch_and_add(run_cnt, 1);

    /* Track high latency events (>100us) */
    if (latency_us > 100) {
        __u64 *high_cnt = bpf_map_lookup_elem(&high_latency_count, &cpu);
        if (high_cnt)
            __sync_fetch_and_add(high_cnt, 1);
    }

    /* Clean up wakeup timestamp */
    bpf_map_delete_elem(&wakeup_ts, &pid);

    return 0;
}
