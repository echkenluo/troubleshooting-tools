// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_buf_peek_stats - Track vhost_net_buf_peek return values userspace program

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "vhost_buf_peek_stats.h"
#include "vhost_buf_peek_stats.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool clear;
} env = {
    .interval = 1,
    .clear = false,
};

const char *argp_program_version = "vhost_buf_peek_stats 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Track vhost_net_buf_peek return values by nvq pointer\n"
"\n"
"USAGE: vhost_buf_peek_stats [-i INTERVAL] [-c]\n"
"\n"
"EXAMPLES:\n"
"    vhost_buf_peek_stats\n"
"    vhost_buf_peek_stats -i 5\n"
"    vhost_buf_peek_stats -i 1 -c\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Output interval in seconds (default: 1)" },
    { "clear", 'c', NULL, 0, "Clear counters after each output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interval = atoi(arg);
        if (env.interval <= 0)
            env.interval = 1;
        break;
    case 'c':
        env.clear = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
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

static void print_stats(int counts_fd)
{
    struct stats_key key = {}, next_key;
    __u64 count;
    time_t now;
    struct tm *tm;
    char ts[32];

    /* Collect data by nvq_ptr */
    struct {
        __u64 nvq_ptr;
        __s32 ret_vals[32];
        __u64 ret_counts[32];
        int num_ret_vals;
        __u64 total;
    } nvq_data[256];
    int num_nvqs = 0;

    /* Iterate through counts map */
    while (bpf_map_get_next_key(counts_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(counts_fd, &next_key, &count) == 0 && count > 0) {
            /* Find or create nvq entry */
            int found = -1;
            for (int i = 0; i < num_nvqs; i++) {
                if (nvq_data[i].nvq_ptr == next_key.nvq_ptr) {
                    found = i;
                    break;
                }
            }
            if (found < 0 && num_nvqs < 256) {
                found = num_nvqs++;
                nvq_data[found].nvq_ptr = next_key.nvq_ptr;
                nvq_data[found].num_ret_vals = 0;
                nvq_data[found].total = 0;
            }
            if (found >= 0 && nvq_data[found].num_ret_vals < 32) {
                int idx = nvq_data[found].num_ret_vals++;
                nvq_data[found].ret_vals[idx] = next_key.ret_val;
                nvq_data[found].ret_counts[idx] = count;
                nvq_data[found].total += count;
            }
        }
        key = next_key;
    }

    /* Print header */
    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
    printf("\n%s\n", ts);
    printf("%-18s %-10s %8s\n", "NVQ_PTR", "RET_VAL", "COUNT");
    printf("----------------------------------------\n");

    if (num_nvqs == 0) {
        printf("No data\n");
        return;
    }

    /* Print data */
    for (int i = 0; i < num_nvqs; i++) {
        printf("\nNVQ: 0x%016llx\n", (unsigned long long)nvq_data[i].nvq_ptr);
        printf("  Total calls: %llu\n", (unsigned long long)nvq_data[i].total);

        for (int j = 0; j < nvq_data[i].num_ret_vals; j++) {
            double pct = nvq_data[i].total > 0 ?
                (nvq_data[i].ret_counts[j] * 100.0 / nvq_data[i].total) : 0;
            printf("  ret=%d: %llu times (%.1f%%)\n",
                   nvq_data[i].ret_vals[j],
                   (unsigned long long)nvq_data[i].ret_counts[j],
                   pct);
        }
    }

    /* Clear if requested */
    if (env.clear) {
        memset(&key, 0, sizeof(key));
        while (bpf_map_get_next_key(counts_fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(counts_fd, &next_key);
            key = next_key;
        }
    }
}

int main(int argc, char **argv)
{
    struct vhost_buf_peek_stats_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vhost_buf_peek_stats_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = vhost_buf_peek_stats_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Tracking vhost_net_buf_peek return values... Ctrl-C to stop\n");
    printf("Output interval: %d seconds\n", env.interval);

    while (!exiting) {
        sleep(env.interval);
        print_stats(bpf_map__fd(skel->maps.counts));
    }

    printf("\nFinal statistics:\n");
    print_stats(bpf_map__fd(skel->maps.counts));

cleanup:
    vhost_buf_peek_stats_bpf__destroy(skel);
    return err != 0;
}
