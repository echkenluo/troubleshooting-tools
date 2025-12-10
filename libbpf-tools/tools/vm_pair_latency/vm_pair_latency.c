// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_pair_latency - VM pair latency measurement userspace

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "vm_pair_latency.h"
#include "vm_pair_latency.skel.h"
#include "trace_helpers.h"
#include "histogram.h"

static volatile bool exiting = false;

static struct env {
    char *src_interface;
    char *dst_interface;
    __u16 port;
    int interval;
    bool histogram;
    bool verbose;
} env = {
    .interval = 1,
    .histogram = false,
};

const char *argp_program_version = "vm_pair_latency 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Measure latency between VM pairs (vnet interfaces)\n"
"\n"
"USAGE: vm_pair_latency [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    vm_pair_latency --src vnet100 --dst vnet103\n"
"    vm_pair_latency --src vnet100 --dst vnet103 --port 62109\n"
"    vm_pair_latency --src vnet100 --dst vnet103 --histogram\n";

static const struct argp_option opts[] = {
    { "src", 's', "DEV", 0, "Source VM interface (required)" },
    { "dst", 'd', "DEV", 0, "Destination VM interface (required)" },
    { "port", 'p', "PORT", 0, "UDP port to filter (optional)" },
    { "interval", 'i', "SEC", 0, "Output interval in seconds (default: 1)" },
    { "histogram", 'H', NULL, 0, "Show latency histogram" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 's':
        env.src_interface = arg;
        break;
    case 'd':
        env.dst_interface = arg;
        break;
    case 'p':
        env.port = atoi(arg);
        break;
    case 'i':
        env.interval = atoi(arg);
        if (env.interval <= 0)
            env.interval = 1;
        break;
    case 'H':
        env.histogram = true;
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_END:
        if (!env.src_interface || !env.dst_interface) {
            fprintf(stderr, "Error: --src and --dst are required\n");
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

static void format_ip(char *buf, size_t len, __be32 addr)
{
    struct in_addr in = { .s_addr = addr };
    inet_ntop(AF_INET, &in, buf, len);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct latency_event *e = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    time_t now;
    struct tm *tm;
    char ts[32];

    if (!env.verbose)
        return 0;

    format_ip(src_ip, sizeof(src_ip), e->key.saddr);
    format_ip(dst_ip, sizeof(dst_ip), e->key.daddr);

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    double latency_us = (double)e->latency_ns / 1000.0;

    printf("[%s] %s:%u -> %s:%u latency=%.3f us dst_if=%s\n",
           ts, src_ip, ntohs(e->key.sport),
           dst_ip, ntohs(e->key.dport),
           latency_us, e->dst_ifname);

    return 0;
}

static void print_histogram(int hist_fd)
{
    __u32 key = 0;
    struct hist h = {};

    if (bpf_map_lookup_elem(hist_fd, &key, &h) < 0)
        return;

    printf("\nLatency Histogram (us):\n");
    print_log2_hist(h.slots, MAX_SLOTS, "us");
}

static void print_summary(struct vm_pair_latency_bpf *skel)
{
    int counters_fd = bpf_map__fd(skel->maps.counters);
    __u64 send_count = 0, recv_count = 0;
    __u32 idx;
    time_t now;
    struct tm *tm;
    char ts[32];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    idx = 0;
    bpf_map_lookup_elem(counters_fd, &idx, &send_count);
    idx = 1;
    bpf_map_lookup_elem(counters_fd, &idx, &recv_count);

    printf("\n%s - VM Pair Latency Summary\n", ts);
    printf("===========================================\n");
    printf("Source interface: %s\n", env.src_interface);
    printf("Destination interface: %s\n", env.dst_interface);
    if (env.port > 0)
        printf("Port filter: %u\n", env.port);
    printf("Packets sent: %llu\n", (unsigned long long)send_count);
    printf("Packets received: %llu\n", (unsigned long long)recv_count);

    if (send_count > 0 && recv_count > 0) {
        double match_rate = (double)recv_count / send_count * 100.0;
        printf("Match rate: %.1f%%\n", match_rate);
    }

    if (env.histogram) {
        int hist_fd = bpf_map__fd(skel->maps.latency_hist);
        print_histogram(hist_fd);
    }

    printf("===========================================\n");
}

int main(int argc, char **argv)
{
    struct vm_pair_latency_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vm_pair_latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    unsigned int src_idx = if_nametoindex(env.src_interface);
    unsigned int dst_idx = if_nametoindex(env.dst_interface);

    if (src_idx == 0) {
        fprintf(stderr, "Invalid source interface: %s\n", env.src_interface);
        err = 1;
        goto cleanup;
    }
    if (dst_idx == 0) {
        fprintf(stderr, "Invalid destination interface: %s\n", env.dst_interface);
        err = 1;
        goto cleanup;
    }

    skel->rodata->src_ifindex = src_idx;
    skel->rodata->dst_ifindex = dst_idx;
    skel->rodata->targ_port = env.port;

    err = vm_pair_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = vm_pair_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing VM pair latency: %s -> %s\n", env.src_interface, env.dst_interface);
    if (env.port > 0)
        printf("Filtering UDP port: %u\n", env.port);
    printf("Output interval: %d seconds\n", env.interval);
    printf("Hit Ctrl-C to end.\n\n");

    time_t last_print = time(NULL);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }

        time_t now = time(NULL);
        if (now - last_print >= env.interval) {
            print_summary(skel);
            last_print = now;
        }
    }

    /* Final summary */
    print_summary(skel);

cleanup:
    ring_buffer__free(rb);
    vm_pair_latency_bpf__destroy(skel);
    return err != 0;
}
