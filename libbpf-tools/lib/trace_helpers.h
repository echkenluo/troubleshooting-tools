// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Trace helper functions for libbpf tools

#ifndef __TRACE_HELPERS_H
#define __TRACE_HELPERS_H

#include <bpf/libbpf.h>
#include <stdbool.h>

/* Maximum symbol name length */
#define KSYM_NAME_MAX 128

/* Get kernel symbol name for address */
const char *ksym_name(unsigned long addr);

/* Look up kernel symbol address */
unsigned long ksym_addr(const char *name);

/* Check if kernel symbol exists */
bool ksym_exists(const char *name);

/* Print stack trace from stack_id */
void print_stack_trace(int stack_map_fd, int stack_id);

/* Setup and cleanup for symbol resolution */
int ksyms_init(void);
void ksyms_cleanup(void);

/* Get the number of CPUs on the system */
int get_online_cpus(void);

/* Bump RLIMIT_MEMLOCK to allow BPF memory allocation */
int bump_memlock_rlimit(void);

/* Set up libbpf print callback */
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

/* Parse IP address to 32-bit value (network order) */
int parse_ip_addr(const char *str, unsigned int *addr);

/* Get interface index by name */
int get_ifindex(const char *ifname);

/* Check if running as root */
bool is_root(void);

/* Probe tracepoint availability */
bool tracepoint_exists(const char *category, const char *name);

/* Probe kprobe availability */
bool kprobe_exists(const char *func);

#endif /* __TRACE_HELPERS_H */
