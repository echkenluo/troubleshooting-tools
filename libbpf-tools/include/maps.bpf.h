// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Common BPF map definition macros

#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * BPF Map Definition Macros
 * These macros provide convenient ways to define various types of BPF maps
 * using the BTF-defined map style.
 */

/* Hash map with custom max entries */
#define BPF_HASH(_name, _key_type, _value_type, _max_entries)  \
struct {                                                        \
    __uint(type, BPF_MAP_TYPE_HASH);                           \
    __uint(max_entries, _max_entries);                         \
    __type(key, _key_type);                                    \
    __type(value, _value_type);                                \
} _name SEC(".maps")

/* LRU hash map with custom max entries */
#define BPF_LRU_HASH(_name, _key_type, _value_type, _max_entries) \
struct {                                                           \
    __uint(type, BPF_MAP_TYPE_LRU_HASH);                          \
    __uint(max_entries, _max_entries);                            \
    __type(key, _key_type);                                       \
    __type(value, _value_type);                                   \
} _name SEC(".maps")

/* Array map with custom max entries */
#define BPF_ARRAY(_name, _value_type, _max_entries) \
struct {                                             \
    __uint(type, BPF_MAP_TYPE_ARRAY);               \
    __uint(max_entries, _max_entries);              \
    __type(key, __u32);                             \
    __type(value, _value_type);                     \
} _name SEC(".maps")

/* Per-CPU array map with custom max entries */
#define BPF_PERCPU_ARRAY(_name, _value_type, _max_entries) \
struct {                                                    \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);               \
    __uint(max_entries, _max_entries);                     \
    __type(key, __u32);                                    \
    __type(value, _value_type);                            \
} _name SEC(".maps")

/* Per-CPU hash map with custom max entries */
#define BPF_PERCPU_HASH(_name, _key_type, _value_type, _max_entries) \
struct {                                                              \
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);                          \
    __uint(max_entries, _max_entries);                               \
    __type(key, _key_type);                                          \
    __type(value, _value_type);                                      \
} _name SEC(".maps")

/* Stack trace map with custom max entries */
#define BPF_STACK_TRACE(_name, _max_entries) \
struct {                                      \
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);  \
    __uint(key_size, sizeof(__u32));         \
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64)); \
    __uint(max_entries, _max_entries);       \
} _name SEC(".maps")

/* Perf event array for ring buffer output */
#define BPF_PERF_OUTPUT(_name, _max_entries) \
struct {                                      \
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
    __uint(key_size, sizeof(__u32));         \
    __uint(value_size, sizeof(__u32));       \
    __uint(max_entries, _max_entries);       \
} _name SEC(".maps")

/* Ring buffer for event output (5.8+) */
#define BPF_RINGBUF(_name, _size) \
struct {                           \
    __uint(type, BPF_MAP_TYPE_RINGBUF); \
    __uint(max_entries, _size);    \
} _name SEC(".maps")

#endif /* __MAPS_BPF_H */
