// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// offcputime_ts - Off-CPU time analysis with timeseries support userspace

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "offcputime_ts.h"
#include "offcputime_ts.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int tgid;
    int pid;
    int interval;
    int duration;
    __u64 min_block_us;
    __u64 max_block_us;
    bool user_threads_only;
    bool kernel_threads_only;
    bool user_stacks_only;
    bool kernel_stacks_only;
    bool folded;
    int stack_storage_size;
    __u32 state;
    bool state_set;
} env = {
    .duration = 99999999,
    .min_block_us = 1,
    .max_block_us = -1ULL,
    .stack_storage_size = 16384,
};

const char *argp_program_version = "offcputime_ts 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Summarize off-CPU time by stack trace with timeseries support.\n"
"\n"
"USAGE: offcputime_ts [OPTIONS] [duration]\n"
"\n"
"EXAMPLES:\n"
"    offcputime_ts                 # trace until Ctrl-C\n"
"    offcputime_ts 5               # trace for 5 seconds\n"
"    offcputime_ts -I 1 10         # output every 1 second for 10 seconds\n"
"    offcputime_ts -p 185          # trace PID 185 only\n"
"    offcputime_ts -m 1000         # trace events > 1000 usec\n";

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "Trace this PID only" },
    { "tid", 't', "TID", 0, "Trace this TID only" },
    { "user-threads-only", 'u', NULL, 0, "User threads only" },
    { "kernel-threads-only", 'k', NULL, 0, "Kernel threads only" },
    { "user-stacks-only", 'U', NULL, 0, "Show user stacks only" },
    { "kernel-stacks-only", 'K', NULL, 0, "Show kernel stacks only" },
    { "folded", 'f', NULL, 0, "Output folded format" },
    { "min-block-time", 'm', "USEC", 0, "Minimum block time (us)" },
    { "max-block-time", 'M', "USEC", 0, "Maximum block time (us)" },
    { "interval", 'I', "SEC", 0, "Output interval in seconds" },
    { "state", 's', "STATE", 0, "Filter on thread state bitmask" },
    { "stack-storage-size", 'S', "SIZE", 0, "Stack storage size (default 16384)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        env.tgid = atoi(arg);
        break;
    case 't':
        env.pid = atoi(arg);
        break;
    case 'u':
        env.user_threads_only = true;
        break;
    case 'k':
        env.kernel_threads_only = true;
        break;
    case 'U':
        env.user_stacks_only = true;
        break;
    case 'K':
        env.kernel_stacks_only = true;
        break;
    case 'f':
        env.folded = true;
        break;
    case 'm':
        env.min_block_us = strtoull(arg, NULL, 10);
        break;
    case 'M':
        env.max_block_us = strtoull(arg, NULL, 10);
        break;
    case 'I':
        env.interval = atoi(arg);
        break;
    case 's':
        env.state = strtoul(arg, NULL, 10);
        env.state_set = true;
        break;
    case 'S':
        env.stack_storage_size = atoi(arg);
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        env.duration = atoi(arg);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_stats(struct offcputime_ts_bpf *skel, struct ksyms *ksyms, struct syms_cache *syms_cache)
{
    int counts_fd = bpf_map__fd(skel->maps.counts);
    int stacks_fd = bpf_map__fd(skel->maps.stack_traces);
    struct key_t key = {}, next_key;
    __u64 value;
    time_t now;
    struct tm *tm;
    char ts[64];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    if (env.interval) {
        printf("\n================================================================================\n");
        printf("=== Off-CPU Analysis Report - %s ===\n", ts);
        printf("================================================================================\n");
    } else {
        printf("\n");
    }

    while (bpf_map_get_next_key(counts_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(counts_fd, &next_key, &value) == 0) {
            if (env.folded) {
                /* Folded format */
                printf("%s", next_key.comm);

                /* Print user stack */
                if (!env.kernel_stacks_only && next_key.user_stack_id >= 0) {
                    __u64 ip[MAX_STACK_DEPTH];
                    int depth = bpf_map_lookup_elem(stacks_fd, &next_key.user_stack_id, ip);
                    if (depth >= 0) {
                        const struct syms *syms = syms_cache__get_syms(syms_cache, next_key.tgid);
                        for (int i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
                            const struct sym *sym = syms ? syms__map_addr(syms, ip[i]) : NULL;
                            printf(";%s", sym ? sym->name : "[unknown]");
                        }
                    }
                }

                /* Print kernel stack */
                if (!env.user_stacks_only && next_key.kernel_stack_id >= 0) {
                    __u64 ip[MAX_STACK_DEPTH];
                    int depth = bpf_map_lookup_elem(stacks_fd, &next_key.kernel_stack_id, ip);
                    if (depth >= 0) {
                        for (int i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
                            const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);
                            printf(";%s", ksym ? ksym->name : "[unknown]");
                        }
                    }
                }

                printf(" %llu\n", (unsigned long long)value);
            } else {
                /* Multi-line format */
                if (!env.user_stacks_only && next_key.kernel_stack_id >= 0) {
                    __u64 ip[MAX_STACK_DEPTH];
                    int depth = bpf_map_lookup_elem(stacks_fd, &next_key.kernel_stack_id, ip);
                    if (depth >= 0) {
                        for (int i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
                            const struct ksym *ksym = ksyms__map_addr(ksyms, ip[i]);
                            printf("    %s\n", ksym ? ksym->name : "[unknown]");
                        }
                    }
                }

                if (!env.kernel_stacks_only && next_key.user_stack_id >= 0) {
                    __u64 ip[MAX_STACK_DEPTH];
                    int depth = bpf_map_lookup_elem(stacks_fd, &next_key.user_stack_id, ip);
                    if (depth >= 0) {
                        const struct syms *syms = syms_cache__get_syms(syms_cache, next_key.tgid);
                        for (int i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
                            const struct sym *sym = syms ? syms__map_addr(syms, ip[i]) : NULL;
                            printf("    %s\n", sym ? sym->name : "[unknown]");
                        }
                    }
                }

                printf("    %-16s %s (%d)\n", "-", next_key.comm, next_key.pid);
                printf("        %llu\n\n", (unsigned long long)value);
            }
        }
        key = next_key;
    }

    if (env.interval) {
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
        printf("================================================================================\n");
        printf("=== Off-CPU Analysis Report End - %s ===\n", ts);
        printf("================================================================================\n");
    }

    /* Clear counts for next interval */
    key = (struct key_t){};
    while (bpf_map_get_next_key(counts_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(counts_fd, &next_key);
        key = next_key;
    }
}

int main(int argc, char **argv)
{
    struct offcputime_ts_bpf *skel;
    struct ksyms *ksyms = NULL;
    struct syms_cache *syms_cache = NULL;
    int err;
    time_t start_time, end_time, last_output;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = offcputime_ts_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure BPF program */
    skel->rodata->min_block_us = env.min_block_us;
    skel->rodata->max_block_us = env.max_block_us;
    skel->rodata->targ_tgid = env.tgid;
    skel->rodata->targ_pid = env.pid;
    skel->rodata->user_threads_only = env.user_threads_only;
    skel->rodata->kernel_threads_only = env.kernel_threads_only;
    skel->rodata->user_stacks_only = env.user_stacks_only;
    skel->rodata->kernel_stacks_only = env.kernel_stacks_only;
    if (env.state_set) {
        skel->rodata->state_filter = env.state;
        skel->rodata->state_filter_enabled = 1;
    }

    err = offcputime_ts_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = offcputime_ts_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    ksyms = ksyms__load();
    syms_cache = syms_cache__new(0);
    if (!ksyms || !syms_cache) {
        fprintf(stderr, "Failed to load symbols\n");
        err = -1;
        goto cleanup;
    }

    printf("Tracing off-CPU time (us)");
    if (env.interval) {
        printf(", output every %d secs", env.interval);
        if (env.duration < 99999999)
            printf(" for %d secs total", env.duration);
    } else if (env.duration < 99999999) {
        printf(" for %d secs", env.duration);
    }
    printf("... Hit Ctrl-C to end.\n");

    start_time = time(NULL);
    end_time = start_time + env.duration;
    last_output = start_time;

    while (!exiting) {
        time_t now = time(NULL);

        if (now >= end_time)
            break;

        if (env.interval && (now - last_output) >= env.interval) {
            print_stats(skel, ksyms, syms_cache);
            last_output = now;
        }

        sleep(1);
    }

    /* Print final stats */
    if (!env.interval || (time(NULL) - last_output) > 0)
        print_stats(skel, ksyms, syms_cache);

cleanup:
    syms_cache__free(syms_cache);
    ksyms__free(ksyms);
    offcputime_ts_bpf__destroy(skel);
    return err != 0;
}
