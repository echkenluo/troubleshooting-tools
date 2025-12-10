// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// CO-RE compatibility fixes for different kernel versions

#ifndef __CORE_FIXES_BPF_H
#define __CORE_FIXES_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
 * CO-RE Field Existence Checks
 * These macros help handle field differences across kernel versions
 */

/* Check if a field exists in a struct */
#define bpf_core_field_exists(field) \
    __builtin_preserve_field_info(field, BPF_FIELD_EXISTS)

/* Get the size of a field */
#define bpf_core_field_size(field) \
    __builtin_preserve_field_info(field, BPF_FIELD_BYTE_SIZE)

/* Get the offset of a field */
#define bpf_core_field_offset(field) \
    __builtin_preserve_field_info(field, BPF_FIELD_BYTE_OFFSET)

/*
 * Network Structure Helpers
 * Handle differences in network structures across kernels
 */

/* Read skb->head safely */
static __always_inline unsigned char *skb_head(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, head);
}

/* Read skb->data safely */
static __always_inline unsigned char *skb_data(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, data);
}

/* Read skb->network_header safely */
static __always_inline __u16 skb_network_header_offset(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, network_header);
}

/* Read skb->transport_header safely */
static __always_inline __u16 skb_transport_header_offset(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, transport_header);
}

/* Read skb->mac_header safely */
static __always_inline __u16 skb_mac_header_offset(const struct sk_buff *skb)
{
    return BPF_CORE_READ(skb, mac_header);
}

/* Get network header pointer */
static __always_inline unsigned char *skb_network_header_ptr(const struct sk_buff *skb)
{
    unsigned char *head = skb_head(skb);
    __u16 offset = skb_network_header_offset(skb);

    if (offset == (__u16)~0U)
        return NULL;

    return head + offset;
}

/* Get transport header pointer */
static __always_inline unsigned char *skb_transport_header_ptr(const struct sk_buff *skb)
{
    unsigned char *head = skb_head(skb);
    __u16 offset = skb_transport_header_offset(skb);

    if (offset == (__u16)~0U)
        return NULL;

    return head + offset;
}

/* Get mac header pointer */
static __always_inline unsigned char *skb_mac_header_ptr(const struct sk_buff *skb)
{
    unsigned char *head = skb_head(skb);
    __u16 offset = skb_mac_header_offset(skb);

    if (offset == (__u16)~0U)
        return NULL;

    return head + offset;
}

/*
 * Socket Helpers
 * Handle differences in socket structures across kernels
 */

/* Read socket state */
static __always_inline unsigned char sk_state(const struct sock *sk)
{
    return BPF_CORE_READ(sk, __sk_common.skc_state);
}

/* Read socket family */
static __always_inline __u16 sk_family(const struct sock *sk)
{
    return BPF_CORE_READ(sk, __sk_common.skc_family);
}

/* Read socket source address (IPv4) */
static __always_inline __be32 sk_rcv_saddr(const struct sock *sk)
{
    return BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
}

/* Read socket destination address (IPv4) */
static __always_inline __be32 sk_daddr(const struct sock *sk)
{
    return BPF_CORE_READ(sk, __sk_common.skc_daddr);
}

/* Read socket source port */
static __always_inline __u16 sk_num(const struct sock *sk)
{
    return BPF_CORE_READ(sk, __sk_common.skc_num);
}

/* Read socket destination port */
static __always_inline __be16 sk_dport(const struct sock *sk)
{
    return BPF_CORE_READ(sk, __sk_common.skc_dport);
}

/*
 * Net Device Helpers
 */

/* Read device ifindex */
static __always_inline int dev_ifindex(const struct net_device *dev)
{
    return BPF_CORE_READ(dev, ifindex);
}

/* Read device name */
static __always_inline int dev_name(const struct net_device *dev, char *buf, int len)
{
    return bpf_core_read_str(buf, len, &dev->name);
}

/*
 * Task Helpers
 */

/* Read task pid */
static __always_inline pid_t task_pid(const struct task_struct *task)
{
    return BPF_CORE_READ(task, pid);
}

/* Read task tgid */
static __always_inline pid_t task_tgid(const struct task_struct *task)
{
    return BPF_CORE_READ(task, tgid);
}

/* Read task comm */
static __always_inline int task_comm(const struct task_struct *task, char *buf, int len)
{
    return bpf_core_read_str(buf, len, &task->comm);
}

#endif /* __CORE_FIXES_BPF_H */
