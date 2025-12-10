// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// virtnet_irq_monitor - Virtio-net IRQ monitor BPF

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "virtnet_irq_monitor.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - IRQs to monitor */
const volatile __u32 target_irqs[MAX_IRQS] = {};
const volatile __u32 num_target_irqs = 0;

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct irq_stats);
} irq_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct cpu_key);
    __type(value, __u64);
} cpu_dist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct ret_key);
    __type(value, __u64);
} ret_dist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);  /* CPU ID */
    __type(value, struct irq_timing);
} timing_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} interval_sum SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} last_time_map SEC(".maps");

/* Check if IRQ is in target list */
static __always_inline bool is_target_irq(__u32 irq)
{
    for (int i = 0; i < MAX_IRQS && i < num_target_irqs; i++) {
        if (target_irqs[i] == irq)
            return true;
    }
    return false;
}

/* Tracepoint: irq_handler_entry */
SEC("tracepoint/irq/irq_handler_entry")
int tracepoint_irq_entry(struct trace_event_raw_irq_handler_entry *ctx)
{
    __u32 irq = ctx->irq;

    if (!is_target_irq(irq))
        return 0;

    __u32 cpu = bpf_get_smp_processor_id();
    __u64 timestamp = bpf_ktime_get_ns();

    /* Store entry timing */
    struct irq_timing timing = {
        .entry_time = timestamp,
        .irq = irq,
    };
    bpf_map_update_elem(&timing_map, &cpu, &timing, BPF_ANY);

    /* Update call count */
    struct irq_stats *stats = bpf_map_lookup_elem(&irq_stats_map, &irq);
    if (stats) {
        __sync_fetch_and_add(&stats->call_count, 1);
    } else {
        struct irq_stats new_stats = { .call_count = 1 };
        bpf_map_update_elem(&irq_stats_map, &irq, &new_stats, BPF_ANY);
    }

    /* Update CPU distribution */
    struct cpu_key ckey = { .irq = irq, .cpu = cpu };
    __u64 *cpu_count = bpf_map_lookup_elem(&cpu_dist, &ckey);
    if (cpu_count) {
        __sync_fetch_and_add(cpu_count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&cpu_dist, &ckey, &init, BPF_ANY);
    }

    /* Calculate interval from last interrupt */
    __u64 *last_time = bpf_map_lookup_elem(&last_time_map, &irq);
    if (last_time && timestamp > *last_time) {
        __u64 interval = timestamp - *last_time;
        __u64 *isum = bpf_map_lookup_elem(&interval_sum, &irq);
        if (isum) {
            __sync_fetch_and_add(isum, interval);
        } else {
            bpf_map_update_elem(&interval_sum, &irq, &interval, BPF_ANY);
        }
    }

    bpf_map_update_elem(&last_time_map, &irq, &timestamp, BPF_ANY);

    return 0;
}

/* Tracepoint: irq_handler_exit */
SEC("tracepoint/irq/irq_handler_exit")
int tracepoint_irq_exit(struct trace_event_raw_irq_handler_exit *ctx)
{
    __u32 irq = ctx->irq;
    __u32 retval = ctx->ret;

    if (!is_target_irq(irq))
        return 0;

    __u32 cpu = bpf_get_smp_processor_id();
    __u64 exit_time = bpf_ktime_get_ns();

    /* Calculate duration */
    struct irq_timing *timing = bpf_map_lookup_elem(&timing_map, &cpu);
    if (timing && timing->irq == irq) {
        __u32 duration_us = (__u32)((exit_time - timing->entry_time) / 1000);

        struct irq_stats *stats = bpf_map_lookup_elem(&irq_stats_map, &irq);
        if (stats) {
            __sync_fetch_and_add(&stats->duration_sum, duration_us);
            if (duration_us > stats->duration_max)
                stats->duration_max = duration_us;
        }

        bpf_map_delete_elem(&timing_map, &cpu);
    }

    /* Update return value distribution */
    struct ret_key rkey = { .irq = irq, .retval = retval };
    __u64 *ret_count = bpf_map_lookup_elem(&ret_dist, &rkey);
    if (ret_count) {
        __sync_fetch_and_add(ret_count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&ret_dist, &rkey, &init, BPF_ANY);
    }

    return 0;
}
