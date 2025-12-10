// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// From libbpf-tools - BPF helper functions for bit operations

#ifndef __BITS_BPF_H
#define __BITS_BPF_H

/**
 * log2 - Calculate the integer log base 2 of a 32-bit value
 * @v: 32-bit value to compute log2 of
 *
 * Returns: Integer log base 2 of v (floor)
 */
static __always_inline __u64 log2(__u32 v)
{
    __u32 shift, r;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);

    return r;
}

/**
 * log2l - Calculate the integer log base 2 of a 64-bit value
 * @v: 64-bit value to compute log2 of
 *
 * Returns: Integer log base 2 of v (floor)
 */
static __always_inline __u64 log2l(__u64 v)
{
    __u32 hi = v >> 32;

    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

#endif /* __BITS_BPF_H */
