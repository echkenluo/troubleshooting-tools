// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_eventfd_count - Count vhost virtqueue + eventfd combinations userspace

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "vhost_eventfd_count.h"
#include "vhost_eventfd_count.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool clear;
} env = {
    .interval = 1,
};

const char *argp_program_version = "vhost_eventfd_count 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Count vhost virtqueue + eventfd combinations.\n"
"\n"
"USAGE: vhost_eventfd_count [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    vhost_eventfd_count               # 1 second interval\n"
"    vhost_eventfd_count -i 5          # 5 second interval\n"
"    vhost_eventfd_count -c            # Clear counters after each output\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Output interval (default: 1)" },
    { "clear", 'c', NULL, 0, "Clear counters after each output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interval = atoi(arg);
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

static void print_stats(struct vhost_eventfd_count_bpf *skel)
{
    int fd = bpf_map__fd(skel->maps.counts);
    struct count_key key = {}, next_key;
    __u64 value;
    time_t now;
    struct tm *tm;
    char ts[32];
    int count = 0;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s\n", ts);
    printf("%-18s %-18s %8s\n", "VQ_PTR", "EVENTFD_PTR", "COUNT");
    printf("-------------------------------------------------\n");

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            printf("0x%016llx 0x%016llx %8llu\n",
                   (unsigned long long)next_key.vq_ptr,
                   (unsigned long long)next_key.eventfd_ptr,
                   (unsigned long long)value);
            count++;
        }
        key = next_key;
    }

    if (count == 0)
        printf("No data\n");

    if (env.clear) {
        key = (struct count_key){};
        while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(fd, &next_key);
            key = next_key;
        }
    }
}

int main(int argc, char **argv)
{
    struct vhost_eventfd_count_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vhost_eventfd_count_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = vhost_eventfd_count_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Counting vhost_virtqueue + eventfd_ctx combinations... Ctrl-C to stop\n");
    printf("Output interval: %d seconds\n", env.interval);

    while (!exiting) {
        sleep(env.interval);
        print_stats(skel);
    }

    printf("\nFinal statistics:\n");
    print_stats(skel);

cleanup:
    vhost_eventfd_count_bpf__destroy(skel);
    return err != 0;
}
