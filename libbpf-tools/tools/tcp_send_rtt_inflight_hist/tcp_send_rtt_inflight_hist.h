// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_send_rtt_inflight_hist - TCP RTT/inflight/cwnd histogram from SEND perspective
// Shared types between BPF and userspace

#ifndef __TCP_SEND_RTT_INFLIGHT_HIST_H
#define __TCP_SEND_RTT_INFLIGHT_HIST_H

#define MAX_SLOTS       32
#define BW_BUCKET_COUNT 64
#define BW_BUCKET_MBPS  500   /* 500 Mbps per bucket, 64 buckets = 0-32 Gbps */
#define MSS_BYTES       1460

/* 2D histogram key: RTT bucket x Inflight bucket */
struct hist_key {
    __u32 rtt_slot;
    __u32 inflight_slot;
};

/* Statistics counters indices */
#define STAT_SAMPLES      0
#define STAT_TOTAL_RETRANS 1
#define STAT_RETRANS_OUT   2
#define STAT_LOST_OUT      3
#define STAT_MAX           4

#endif /* __TCP_SEND_RTT_INFLIGHT_HIST_H */
