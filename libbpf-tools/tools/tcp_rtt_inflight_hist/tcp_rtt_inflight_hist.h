// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_rtt_inflight_hist - TCP RTT and inflight histogram
// Shared types between BPF and userspace

#ifndef __TCP_RTT_INFLIGHT_HIST_H
#define __TCP_RTT_INFLIGHT_HIST_H

#define MAX_SLOTS       32

/* 2D histogram key: RTT bucket x Inflight bucket */
struct hist_key {
    __u32 rtt_slot;
    __u32 inflight_slot;
};

#endif /* __TCP_RTT_INFLIGHT_HIST_H */
