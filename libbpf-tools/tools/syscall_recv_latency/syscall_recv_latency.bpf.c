// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// syscall_recv_latency - recv/read syscall latency measurement BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_recv_latency.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 targ_pid = 0;
const volatile __u32 high_latency_threshold_us = 0;

/* Track recv start */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct recv_key);
    __type(value, struct recv_enter);
} recv_start SEC(".maps");

/* Latency histogram */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} latency_hist SEC(".maps");

/* Counters */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

/* Ring buffer for high latency events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Helper: log2 */
static __always_inline __u32 log2l(__u64 v)
{
    __u32 r = 0;
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (v <= 1) break;
        v >>= 1;
        r++;
    }
    return r;
}

/* Helper: check filter */
static __always_inline bool should_trace(__u32 pid)
{
    return (targ_pid == 0 || pid == targ_pid);
}

/* Helper: record latency */
static __always_inline void record_latency(struct recv_enter *enter, __s64 bytes,
                                           __u8 syscall_type)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();
    __u64 latency_ns = now - enter->ts;
    __u64 latency_us = latency_ns / 1000;

    /* Update histogram */
    __u32 slot = log2l(latency_us + 1);
    if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
    __u64 *cnt = bpf_map_lookup_elem(&latency_hist, &slot);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    /* Update counters */
    __u32 idx = CNT_TOTAL_CALLS;
    cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);

    if (bytes > 0) {
        idx = CNT_TOTAL_BYTES;
        cnt = bpf_map_lookup_elem(&counters, &idx);
        if (cnt) __sync_fetch_and_add(cnt, bytes);
    } else if (bytes == 0) {
        idx = CNT_ZERO_READS;
        cnt = bpf_map_lookup_elem(&counters, &idx);
        if (cnt) __sync_fetch_and_add(cnt, 1);
    } else {
        idx = CNT_ERRORS;
        cnt = bpf_map_lookup_elem(&counters, &idx);
        if (cnt) __sync_fetch_and_add(cnt, 1);
    }

    if (enter->cpu != cpu) {
        idx = CNT_CPU_MIGRATE;
        cnt = bpf_map_lookup_elem(&counters, &idx);
        if (cnt) __sync_fetch_and_add(cnt, 1);
    }

    /* High latency event */
    if (high_latency_threshold_us > 0 && latency_us > high_latency_threshold_us) {
        struct recv_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->ts_enter = enter->ts;
            e->ts_exit = now;
            e->latency_us = latency_us;
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->tid = bpf_get_current_pid_tgid();
            e->cpu_enter = enter->cpu;
            e->cpu_exit = cpu;
            e->fd = enter->fd;
            e->bytes = bytes;
            bpf_get_current_comm(&e->comm, sizeof(e->comm));
            bpf_ringbuf_submit(e, 0);
        }
    }
}

/* Tracepoint: sys_enter_recvfrom */
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!should_trace(pid)) return 0;

    struct recv_key key = { .tid = bpf_get_current_pid_tgid(), .syscall_type = SYSCALL_RECVFROM };
    struct recv_enter enter = { .ts = bpf_ktime_get_ns(), .cpu = bpf_get_smp_processor_id(), .fd = ctx->args[0] };
    bpf_map_update_elem(&recv_start, &key, &enter, BPF_ANY);
    return 0;
}

/* Tracepoint: sys_exit_recvfrom */
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
    struct recv_key key = { .tid = bpf_get_current_pid_tgid(), .syscall_type = SYSCALL_RECVFROM };
    struct recv_enter *enter = bpf_map_lookup_elem(&recv_start, &key);
    if (!enter) return 0;

    record_latency(enter, ctx->ret, SYSCALL_RECVFROM);
    bpf_map_delete_elem(&recv_start, &key);
    return 0;
}

/* Tracepoint: sys_enter_recvmsg */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!should_trace(pid)) return 0;

    struct recv_key key = { .tid = bpf_get_current_pid_tgid(), .syscall_type = SYSCALL_RECVMSG };
    struct recv_enter enter = { .ts = bpf_ktime_get_ns(), .cpu = bpf_get_smp_processor_id(), .fd = ctx->args[0] };
    bpf_map_update_elem(&recv_start, &key, &enter, BPF_ANY);
    return 0;
}

/* Tracepoint: sys_exit_recvmsg */
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tracepoint_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx)
{
    struct recv_key key = { .tid = bpf_get_current_pid_tgid(), .syscall_type = SYSCALL_RECVMSG };
    struct recv_enter *enter = bpf_map_lookup_elem(&recv_start, &key);
    if (!enter) return 0;

    record_latency(enter, ctx->ret, SYSCALL_RECVMSG);
    bpf_map_delete_elem(&recv_start, &key);
    return 0;
}
