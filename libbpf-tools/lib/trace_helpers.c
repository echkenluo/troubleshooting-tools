// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// Trace helper functions for libbpf tools

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "trace_helpers.h"

/* Kernel symbol table entry */
struct ksym {
    unsigned long addr;
    char name[KSYM_NAME_MAX];
};

/* Global symbol table */
static struct ksym *syms = NULL;
static int sym_count = 0;
static int sym_capacity = 0;

/* Compare function for binary search */
static int ksym_cmp(const void *a, const void *b)
{
    const struct ksym *ka = a;
    const struct ksym *kb = b;

    if (ka->addr < kb->addr)
        return -1;
    else if (ka->addr > kb->addr)
        return 1;
    return 0;
}

/* Initialize kernel symbol table from /proc/kallsyms */
int ksyms_init(void)
{
    FILE *f;
    char line[256];
    unsigned long addr;
    char type;
    char name[KSYM_NAME_MAX];

    if (syms)
        return 0; /* Already initialized */

    f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "Failed to open /proc/kallsyms: %s\n", strerror(errno));
        return -1;
    }

    sym_capacity = 65536;
    syms = malloc(sym_capacity * sizeof(struct ksym));
    if (!syms) {
        fclose(f);
        return -ENOMEM;
    }

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx %c %127s", &addr, &type, name) != 3)
            continue;

        if (addr == 0)
            continue;

        if (sym_count >= sym_capacity) {
            sym_capacity *= 2;
            struct ksym *new_syms = realloc(syms, sym_capacity * sizeof(struct ksym));
            if (!new_syms) {
                fclose(f);
                return -ENOMEM;
            }
            syms = new_syms;
        }

        syms[sym_count].addr = addr;
        strncpy(syms[sym_count].name, name, KSYM_NAME_MAX - 1);
        syms[sym_count].name[KSYM_NAME_MAX - 1] = '\0';
        sym_count++;
    }

    fclose(f);

    /* Sort by address for binary search */
    qsort(syms, sym_count, sizeof(struct ksym), ksym_cmp);

    return 0;
}

/* Cleanup symbol table */
void ksyms_cleanup(void)
{
    free(syms);
    syms = NULL;
    sym_count = 0;
    sym_capacity = 0;
}

/* Get kernel symbol name for address */
const char *ksym_name(unsigned long addr)
{
    static char buf[KSYM_NAME_MAX + 32];
    int low = 0, high = sym_count - 1;
    int best = -1;

    if (!syms || sym_count == 0) {
        snprintf(buf, sizeof(buf), "0x%lx", addr);
        return buf;
    }

    /* Binary search for closest symbol */
    while (low <= high) {
        int mid = (low + high) / 2;

        if (syms[mid].addr <= addr) {
            best = mid;
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    if (best >= 0) {
        unsigned long offset = addr - syms[best].addr;
        if (offset)
            snprintf(buf, sizeof(buf), "%s+0x%lx", syms[best].name, offset);
        else
            snprintf(buf, sizeof(buf), "%s", syms[best].name);
        return buf;
    }

    snprintf(buf, sizeof(buf), "0x%lx", addr);
    return buf;
}

/* Look up kernel symbol address by name */
unsigned long ksym_addr(const char *name)
{
    int i;

    if (!syms || sym_count == 0)
        return 0;

    for (i = 0; i < sym_count; i++) {
        if (strcmp(syms[i].name, name) == 0)
            return syms[i].addr;
    }

    return 0;
}

/* Check if kernel symbol exists */
bool ksym_exists(const char *name)
{
    return ksym_addr(name) != 0;
}

/* Print stack trace from stack_id */
void print_stack_trace(int stack_map_fd, int stack_id)
{
    unsigned long stack[MAX_STACK_DEPTH];
    int i;

    if (stack_id < 0) {
        printf("    [stack trace unavailable: %d]\n", stack_id);
        return;
    }

    if (bpf_map_lookup_elem(stack_map_fd, &stack_id, &stack) != 0) {
        printf("    [failed to read stack trace]\n");
        return;
    }

    for (i = 0; i < MAX_STACK_DEPTH && stack[i]; i++) {
        printf("    %s\n", ksym_name(stack[i]));
    }
}

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 50
#endif

/* Get the number of online CPUs */
int get_online_cpus(void)
{
    return libbpf_num_possible_cpus();
}

/* Bump RLIMIT_MEMLOCK to allow BPF memory allocation */
int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/* libbpf print callback */
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

/* Parse IP address string to 32-bit value (network order) */
int parse_ip_addr(const char *str, unsigned int *addr)
{
    struct in_addr in;

    if (!str || !addr)
        return -EINVAL;

    if (inet_pton(AF_INET, str, &in) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", str);
        return -EINVAL;
    }

    *addr = in.s_addr;
    return 0;
}

/* Get interface index by name */
int get_ifindex(const char *ifname)
{
    unsigned int ifindex;

    if (!ifname)
        return -EINVAL;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n", ifname, strerror(errno));
        return -errno;
    }

    return ifindex;
}

/* Check if running as root */
bool is_root(void)
{
    return geteuid() == 0;
}

/* Probe tracepoint availability */
bool tracepoint_exists(const char *category, const char *name)
{
    char path[256];
    struct stat st;

    snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s", category, name);
    return stat(path, &st) == 0;
}

/* Probe kprobe availability */
bool kprobe_exists(const char *func)
{
    char path[256];
    FILE *f;
    char line[256];
    bool found = false;

    /* First check kallsyms */
    f = fopen("/proc/kallsyms", "r");
    if (!f)
        return false;

    while (fgets(line, sizeof(line), f)) {
        char name[128];
        unsigned long addr;
        char type;

        if (sscanf(line, "%lx %c %127s", &addr, &type, name) == 3) {
            if (strcmp(name, func) == 0) {
                found = true;
                break;
            }
        }
    }

    fclose(f);
    return found;
}
