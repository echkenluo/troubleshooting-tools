// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_eventfd_count - Count vhost virtqueue + eventfd combinations
// Shared types between BPF and userspace

#ifndef __VHOST_EVENTFD_COUNT_H
#define __VHOST_EVENTFD_COUNT_H

/* Key combining VQ and eventfd */
struct count_key {
    __u64 vq_ptr;
    __u64 eventfd_ptr;
};

#endif /* __VHOST_EVENTFD_COUNT_H */
