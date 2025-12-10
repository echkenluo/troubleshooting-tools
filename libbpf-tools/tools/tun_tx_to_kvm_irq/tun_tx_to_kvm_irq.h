// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_tx_to_kvm_irq - TUN TX to KVM IRQ interrupt chain tracer
// Shared types between BPF and userspace

#ifndef __TUN_TX_TO_KVM_IRQ_H
#define __TUN_TX_TO_KVM_IRQ_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16

/* Interrupt trace stages */
#define STAGE_TUN_NET_XMIT      1
#define STAGE_VHOST_SIGNAL      2
#define STAGE_IRQFD_WAKEUP      3

/* Event data for interrupt chain tracing */
struct interrupt_event {
    __u64 timestamp;
    __u8 stage;
    __u8 protocol;
    __u8 pad[2];
    __u32 cpu_id;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char dev_name[IFNAMSIZ];
    __u32 queue_index;
    __u32 gsi;
    __u64 sock_ptr;
    __u64 eventfd_ctx;
    __u64 vq_ptr;
    __u64 delay_ns;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

/* Queue key for tracking */
struct queue_key {
    __u64 sock_ptr;
    __u32 queue_index;
    char dev_name[IFNAMSIZ];
    __u32 pad;
};

/* Interrupt chain connection */
struct interrupt_connection {
    __u64 sock_ptr;
    __u64 eventfd_ctx;
    char dev_name[IFNAMSIZ];
    __u32 queue_index;
    __u32 pad;
    __u64 timestamp;
};

#endif /* __TUN_TX_TO_KVM_IRQ_H */
