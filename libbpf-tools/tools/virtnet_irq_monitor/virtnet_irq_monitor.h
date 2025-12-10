// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// virtnet_irq_monitor - Virtio-net IRQ monitor
// Shared types between BPF and userspace

#ifndef __VIRTNET_IRQ_MONITOR_H
#define __VIRTNET_IRQ_MONITOR_H

#define MAX_IRQS        16
#define HANDLER_NAME_LEN 32

/* IRQ return values */
#define IRQ_NONE        0
#define IRQ_HANDLED     1
#define IRQ_WAKE_THREAD 2

/* IRQ statistics per IRQ number */
struct irq_stats {
    __u64 call_count;
    __u64 duration_sum;     /* Sum of durations in ns */
    __u32 duration_max;     /* Max duration in us */
    __u32 pad;
};

/* CPU distribution key */
struct cpu_key {
    __u32 irq;
    __u32 cpu;
};

/* Return value distribution key */
struct ret_key {
    __u32 irq;
    __u32 retval;
};

/* IRQ timing entry for duration calculation */
struct irq_timing {
    __u64 entry_time;
    __u32 irq;
    __u32 pad;
};

#endif /* __VIRTNET_IRQ_MONITOR_H */
