// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_upcall_latency_summary - OVS upcall latency histogram tool
// Shared types between BPF and userspace

#ifndef __OVS_UPCALL_LATENCY_SUMMARY_H
#define __OVS_UPCALL_LATENCY_SUMMARY_H

#define TASK_COMM_LEN   16
#define MAX_SLOTS       64

/* Protocol constants */
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17

/* Packet key structure for unique packet identification */
struct packet_key {
    __be32 sip;
    __be32 dip;
    __u8 proto;
    __u8 pad[3];

    union {
        struct {
            __be16 source;
            __be16 dest;
            __be32 seq;
        } tcp;

        struct {
            __be16 source;
            __be16 dest;
            __be16 id;
            __be16 len;
        } udp;

        struct {
            __be16 id;
            __be16 sequence;
            __u8 type;
            __u8 code;
            __u8 pad[2];
        } icmp;
    };
};

/* Upcall session tracking */
struct upcall_data {
    __u64 upcall_timestamp;
};

/* Histogram key */
struct hist_key {
    __u32 slot;
};

/* Statistics counters */
#define COUNTER_TOTAL_UPCALLS     0
#define COUNTER_COMPLETED_UPCALLS 1
#define COUNTER_TIMEOUTS          2
#define COUNTER_ERRORS            3
#define NUM_COUNTERS              4

/* Event for detailed output (optional) */
struct upcall_event {
    __u64 timestamp;
    __u64 latency_ns;
    __be32 sip;
    __be32 dip;
    __u8 proto;
    __u8 pad[3];
    __u32 pid;
    char comm[TASK_COMM_LEN];
};

#endif /* __OVS_UPCALL_LATENCY_SUMMARY_H */
