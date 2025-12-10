// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// virtnet_irq_monitor - Virtio-net IRQ monitor userspace

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "virtnet_irq_monitor.h"
#include "virtnet_irq_monitor.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int irqs[MAX_IRQS];
    int num_irqs;
    int interval;
    bool trace_cpu;
} env = {
    .interval = 5,
};

const char *argp_program_version = "virtnet_irq_monitor 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Virtio-net IRQ monitor.\n"
"\n"
"USAGE: virtnet_irq_monitor --irqs IRQ1,IRQ2,... [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    virtnet_irq_monitor --irqs 69,71,73,75\n"
"    virtnet_irq_monitor --irqs 69,71 --interval 10\n"
"    virtnet_irq_monitor --irqs 69 --trace-cpu\n";

static const struct argp_option opts[] = {
    { "irqs", 'r', "LIST", 0, "Comma-separated list of IRQ numbers (required)" },
    { "interval", 'i', "SEC", 0, "Reporting interval (default: 5)" },
    { "trace-cpu", 'c', NULL, 0, "Show per-CPU distribution" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static int parse_irq_list(const char *str)
{
    char *copy = strdup(str);
    char *token = strtok(copy, ",");
    env.num_irqs = 0;

    while (token && env.num_irqs < MAX_IRQS) {
        env.irqs[env.num_irqs++] = atoi(token);
        token = strtok(NULL, ",");
    }

    free(copy);
    return env.num_irqs > 0 ? 0 : -1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'r':
        if (parse_irq_list(arg) < 0) {
            fprintf(stderr, "Invalid IRQ list: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'i':
        env.interval = atoi(arg);
        break;
    case 'c':
        env.trace_cpu = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_END:
        if (env.num_irqs == 0) {
            fprintf(stderr, "Error: --irqs is required\n");
            argp_usage(state);
        }
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

static const char *ret_str(int ret)
{
    switch (ret) {
    case IRQ_NONE:
        return "IRQ_NONE";
    case IRQ_HANDLED:
        return "IRQ_HANDLED";
    case IRQ_WAKE_THREAD:
        return "IRQ_WAKE_THREAD";
    default:
        return "UNKNOWN";
    }
}

static void print_statistics(struct virtnet_irq_monitor_bpf *skel)
{
    time_t now;
    struct tm *tm;
    char ts[32];
    int i;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("\n================================================================================\n");
    printf("IRQ Statistics Report - %s\n", ts);
    printf("================================================================================\n");

    int stats_fd = bpf_map__fd(skel->maps.irq_stats_map);
    int cpu_fd = bpf_map__fd(skel->maps.cpu_dist);
    int ret_fd = bpf_map__fd(skel->maps.ret_dist);

    for (i = 0; i < env.num_irqs; i++) {
        __u32 irq = env.irqs[i];
        struct irq_stats stats = {};

        printf("\nIRQ %u:\n", irq);

        if (bpf_map_lookup_elem(stats_fd, &irq, &stats) == 0 && stats.call_count > 0) {
            printf("  Total Calls: %llu\n", (unsigned long long)stats.call_count);

            /* CPU distribution */
            if (env.trace_cpu) {
                printf("  CPU Distribution: ");
                struct cpu_key ckey = { .irq = irq };
                struct cpu_key next_ckey;
                __u64 cpu_count;
                bool first = true;

                ckey.cpu = 0;
                while (bpf_map_get_next_key(cpu_fd, &ckey, &next_ckey) == 0) {
                    if (next_ckey.irq == irq) {
                        if (bpf_map_lookup_elem(cpu_fd, &next_ckey, &cpu_count) == 0) {
                            if (!first)
                                printf(", ");
                            printf("CPU%u: %llu", next_ckey.cpu, (unsigned long long)cpu_count);
                            first = false;
                        }
                    }
                    ckey = next_ckey;
                }
                printf("\n");
            }

            /* Return value distribution */
            printf("  Return Value Distribution:\n    ");
            struct ret_key rkey = {};
            struct ret_key next_rkey;
            __u64 ret_count;
            __u64 total_ret = 0;

            /* First pass: get total */
            rkey.irq = 0;
            rkey.retval = 0;
            while (bpf_map_get_next_key(ret_fd, &rkey, &next_rkey) == 0) {
                if (next_rkey.irq == irq) {
                    if (bpf_map_lookup_elem(ret_fd, &next_rkey, &ret_count) == 0)
                        total_ret += ret_count;
                }
                rkey = next_rkey;
            }

            /* Second pass: print */
            rkey.irq = 0;
            rkey.retval = 0;
            bool first = true;
            while (bpf_map_get_next_key(ret_fd, &rkey, &next_rkey) == 0) {
                if (next_rkey.irq == irq) {
                    if (bpf_map_lookup_elem(ret_fd, &next_rkey, &ret_count) == 0) {
                        double pct = total_ret > 0 ? (ret_count * 100.0 / total_ret) : 0;
                        if (!first)
                            printf(", ");
                        printf("%s: %llu (%.1f%%)", ret_str(next_rkey.retval),
                               (unsigned long long)ret_count, pct);
                        first = false;
                    }
                }
                rkey = next_rkey;
            }
            printf("\n");

            /* Latency statistics */
            if (stats.call_count > 0) {
                double avg_lat = (double)stats.duration_sum / stats.call_count;
                printf("  Average Latency: %.1fus\n", avg_lat);
                printf("  Max Latency: %uus\n", stats.duration_max);
            }
        } else {
            printf("  No calls recorded\n");
        }
    }

    printf("================================================================================\n");

    /* Clear maps for next period */
    __u32 key = 0, next_key;
    while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(stats_fd, &next_key);
        key = next_key;
    }

    struct cpu_key ckey = {}, next_ckey;
    while (bpf_map_get_next_key(cpu_fd, &ckey, &next_ckey) == 0) {
        bpf_map_delete_elem(cpu_fd, &next_ckey);
        ckey = next_ckey;
    }

    struct ret_key rkey = {}, next_rkey;
    while (bpf_map_get_next_key(ret_fd, &rkey, &next_rkey) == 0) {
        bpf_map_delete_elem(ret_fd, &next_rkey);
        rkey = next_rkey;
    }

    int interval_fd = bpf_map__fd(skel->maps.interval_sum);
    key = 0;
    while (bpf_map_get_next_key(interval_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(interval_fd, &next_key);
        key = next_key;
    }
}

int main(int argc, char **argv)
{
    struct virtnet_irq_monitor_bpf *skel;
    int err, i;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = virtnet_irq_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure target IRQs */
    for (i = 0; i < env.num_irqs && i < MAX_IRQS; i++) {
        skel->rodata->target_irqs[i] = env.irqs[i];
    }
    skel->rodata->num_target_irqs = env.num_irqs;

    err = virtnet_irq_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = virtnet_irq_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Enhanced Virtio IRQ Monitor\n");
    printf("Monitoring IRQs: ");
    for (i = 0; i < env.num_irqs; i++) {
        printf("%d%s", env.irqs[i], i < env.num_irqs - 1 ? "," : "");
    }
    printf("\n");
    printf("Reporting interval: %d seconds\n", env.interval);
    printf("CPU tracking: %s\n", env.trace_cpu ? "ON" : "OFF");
    printf("--------------------------------------------------------------------------------\n");
    printf("Starting IRQ monitoring... Press Ctrl+C to stop\n");

    while (!exiting) {
        sleep(env.interval);
        if (!exiting)
            print_statistics(skel);
    }

    printf("\nStopping IRQ monitoring...\n");
    print_statistics(skel);

cleanup:
    virtnet_irq_monitor_bpf__destroy(skel);
    return err != 0;
}
