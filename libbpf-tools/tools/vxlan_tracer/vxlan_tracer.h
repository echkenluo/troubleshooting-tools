// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vxlan_tracer - VXLAN packet tracer
// Shared types between BPF and userspace

#ifndef __VXLAN_TRACER_H
#define __VXLAN_TRACER_H

#define TASK_COMM_LEN   16
#define IFNAMSIZ        16

/* VXLAN event */
struct vxlan_event {
    __u64 timestamp;
    __u32 pid;
    __u32 cpu;
    char comm[TASK_COMM_LEN];
    char dev_name[IFNAMSIZ];
    __u32 vni;
    __be32 outer_src;
    __be32 outer_dst;
    __be32 inner_src;
    __be32 inner_dst;
    __be16 outer_sport;
    __be16 outer_dport;
    __be16 inner_sport;
    __be16 inner_dport;
    __u8 inner_proto;
    __u8 direction;  /* 0=RX, 1=TX */
    __u16 len;
};

#define DIR_RX  0
#define DIR_TX  1

#endif /* __VXLAN_TRACER_H */
