// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_buf_peek_stats - Track vhost_net_buf_peek return values
// Shared types between BPF and userspace

#ifndef __VHOST_BUF_PEEK_STATS_H
#define __VHOST_BUF_PEEK_STATS_H

/* Key structure for tracking by nvq pointer and return value */
struct stats_key {
    __u64 nvq_ptr;
    __s32 ret_val;
    __u32 pad;
};

#endif /* __VHOST_BUF_PEEK_STATS_H */
