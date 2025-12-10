// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_perf_observer - TCP performance observer
// Shared types between BPF and userspace

#ifndef __TCP_PERF_OBSERVER_H
#define __TCP_PERF_OBSERVER_H

#define TASK_COMM_LEN   16
#define MAX_SLOTS       32

/* Event types */
#define EVT_RTT         1
#define EVT_CONNLAT     2
#define EVT_RETRANS     3
#define EVT_DROP        4

/* Flow ID */
struct flow_id {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

/* Detail event */
struct detail_event {
    __u64 ts_ns;
    __u32 pid;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 ev_type;
    __u8 state;
    __u32 metric;      /* RTT or connlat in usec */
    __u32 extra1;      /* cwnd or drop reason */
    __u32 extra2;      /* ssthresh or retrans count */
};

/* Counter indices */
#define CNT_ACK         0
#define CNT_RETRANS     1
#define CNT_DROP        2
#define CNT_CONN        3
#define CNT_MAX         4

#endif /* __TCP_PERF_OBSERVER_H */
