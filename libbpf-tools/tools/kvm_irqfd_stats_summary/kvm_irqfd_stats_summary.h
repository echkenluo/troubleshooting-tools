// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kvm_irqfd_stats_summary - VM interrupt statistics histogram tool
// Shared types between BPF and userspace

#ifndef __KVM_IRQFD_STATS_SUMMARY_H
#define __KVM_IRQFD_STATS_SUMMARY_H

#define TASK_COMM_LEN   16
#define MAX_SLOTS       64

/* Filter categories */
#define FILTER_ALL      0
#define FILTER_DATA     1   /* vhost threads only */
#define FILTER_CONTROL  2   /* QEMU process only */

/* Filter subcategories */
#define SUBCAT_ALL      0
#define SUBCAT_RX       1
#define SUBCAT_TX       2

/* Histogram key for irqfd_wakeup */
struct hist_key {
    __u64 kvm_ptr;
    __u64 irqfd_ptr;
    __u32 gsi;
    __u32 cpu_id;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    /* irqfd_wakeup function parameters */
    __u64 wait_ptr;
    __u32 mode;
    __u32 sync;
    __u64 key_flags;
    __u64 slot;
};

/* IRQFD info structure */
struct irqfd_info {
    __u32 gsi;
    __u64 eventfd_ctx;
    __u64 first_timestamp;
    __u64 last_timestamp;
};

/* KVM+GSI tracking key */
struct kvm_gsi_key {
    __u64 kvm_ptr;
    __u32 gsi;
    __u32 pad;
};

/* Arch set IRQ histogram key */
struct arch_set_irq_hist_key {
    __u64 kvm_ptr;
    __u32 gsi;
    __u32 pad;
    __u64 slot;
};

/* Arch set IRQ return statistics */
struct arch_set_irq_ret_key {
    __u64 kvm_ptr;
    __u32 gsi;
    __u32 pad;
};

struct arch_set_irq_ret_val {
    __u64 total_calls;
    __u64 success_count;
    __u64 fail_count;
    __u64 total_delivered;
};

/* KVM set MSI histogram key */
struct kvm_set_msi_hist_key {
    __u64 kvm_ptr;
    __u32 gsi;
    __u32 pad;
    __u64 slot;
};

/* KVM VCPU kick histogram key */
struct kvm_vcpu_kick_hist_key {
    __u64 kvm_ptr;
    __u32 vcpu_id;
    __u32 pad;
    __u64 slot;
};

/* Filter parameters */
struct filter_params {
    __u32 qemu_pid;
    __u32 vhost_pid;
    __u8 filter_category;
    __u8 filter_subcategory;
    __u8 pad[2];
};

/* Summary event for reporting */
struct irqfd_summary_event {
    __u64 kvm_ptr;
    __u64 irqfd_ptr;
    __u32 gsi;
    __u32 cpu_id;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 count;
};

#endif /* __KVM_IRQFD_STATS_SUMMARY_H */
