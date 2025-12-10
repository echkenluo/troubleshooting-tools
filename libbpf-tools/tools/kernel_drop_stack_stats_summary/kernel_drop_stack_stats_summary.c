// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kernel_drop_stack_stats_summary - Kernel packet drop statistics userspace program

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kernel_drop_stack_stats_summary.h"
#include "kernel_drop_stack_stats_summary.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool verbose;
    bool clear;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    int protocol;
} env = {
    .interval = 5,
    .verbose = false,
    .clear = false,
};

const char *argp_program_version = "kernel_drop_stack_stats_summary 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Track kernel packet drops with stack trace aggregation\n"
"\n"
"USAGE: kernel_drop_stack_stats_summary [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    kernel_drop_stack_stats_summary                    # Default 5s interval\n"
"    kernel_drop_stack_stats_summary -i 10              # 10s interval\n"
"    kernel_drop_stack_stats_summary --src-ip 10.0.0.1  # Filter by source IP\n"
"    kernel_drop_stack_stats_summary -v                 # Verbose output\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Output interval in seconds (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output with stack traces" },
    { "clear", 'c', NULL, 0, "Clear counters after each output" },
    { "src-ip", 's', "IP", 0, "Filter by source IP" },
    { "dst-ip", 'd', "IP", 0, "Filter by destination IP" },
    { "src-port", 'S', "PORT", 0, "Filter by source port" },
    { "dst-port", 'D', "PORT", 0, "Filter by destination port" },
    { "protocol", 'p', "PROTO", 0, "Filter by protocol (tcp/udp/icmp)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interval = atoi(arg);
        if (env.interval <= 0)
            env.interval = 5;
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'c':
        env.clear = true;
        break;
    case 's':
        env.src_ip = arg;
        break;
    case 'd':
        env.dst_ip = arg;
        break;
    case 'S':
        env.src_port = atoi(arg);
        break;
    case 'D':
        env.dst_port = atoi(arg);
        break;
    case 'p':
        if (strcasecmp(arg, "tcp") == 0)
            env.protocol = IPPROTO_TCP;
        else if (strcasecmp(arg, "udp") == 0)
            env.protocol = IPPROTO_UDP;
        else if (strcasecmp(arg, "icmp") == 0)
            env.protocol = IPPROTO_ICMP;
        else
            env.protocol = atoi(arg);
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

static const char *drop_reason_str(__u32 reason)
{
    static const char *reasons[] = {
        [DROP_REASON_NOT_SPECIFIED] = "NOT_SPECIFIED",
        [DROP_REASON_NO_SOCKET] = "NO_SOCKET",
        [DROP_REASON_PKT_TOO_SMALL] = "PKT_TOO_SMALL",
        [DROP_REASON_TCP_CSUM] = "TCP_CSUM",
        [DROP_REASON_SOCKET_FILTER] = "SOCKET_FILTER",
        [DROP_REASON_UDP_CSUM] = "UDP_CSUM",
        [DROP_REASON_NETFILTER_DROP] = "NETFILTER_DROP",
        [DROP_REASON_OTHERHOST] = "OTHERHOST",
        [DROP_REASON_IP_CSUM] = "IP_CSUM",
        [DROP_REASON_IP_INHDR] = "IP_INHDR",
        [DROP_REASON_IP_RPFILTER] = "IP_RPFILTER",
        [DROP_REASON_UNICAST_IN_L2_MULTICAST] = "UNICAST_IN_L2_MULTICAST",
    };

    if (reason < DROP_REASON_MAX)
        return reasons[reason];
    return "UNKNOWN";
}

static __u32 ip_to_u32(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 1)
        return addr.s_addr;
    return 0;
}

static void print_stats(struct kernel_drop_stack_stats_summary_bpf *skel)
{
    int stats_fd = bpf_map__fd(skel->maps.drop_stats_map);
    int stack_fd = bpf_map__fd(skel->maps.stack_traces);
    struct drop_key key = {}, next_key;
    struct drop_stats stats;
    time_t now;
    struct tm *tm;
    char ts[32];

    /* Print header */
    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s - Kernel Drop Statistics Summary\n", ts);
    printf("%-20s %-12s %10s\n", "DROP_REASON", "STACK_ID", "COUNT");
    printf("----------------------------------------\n");

    /* Collect and sort entries */
    struct {
        struct drop_key key;
        struct drop_stats stats;
    } entries[1024];
    int num_entries = 0;

    while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(stats_fd, &next_key, &stats) == 0) {
            if (num_entries < 1024) {
                entries[num_entries].key = next_key;
                entries[num_entries].stats = stats;
                num_entries++;
            }
        }
        key = next_key;
    }

    /* Sort by count descending */
    for (int i = 0; i < num_entries - 1; i++) {
        for (int j = i + 1; j < num_entries; j++) {
            if (entries[j].stats.count > entries[i].stats.count) {
                struct drop_key tmp_key = entries[i].key;
                struct drop_stats tmp_stats = entries[i].stats;
                entries[i].key = entries[j].key;
                entries[i].stats = entries[j].stats;
                entries[j].key = tmp_key;
                entries[j].stats = tmp_stats;
            }
        }
    }

    /* Print entries */
    __u64 total_drops = 0;
    for (int i = 0; i < num_entries && i < 50; i++) {
        printf("%-20s %-12d %10llu\n",
               drop_reason_str(entries[i].key.drop_reason),
               entries[i].key.stack_id,
               (unsigned long long)entries[i].stats.count);
        total_drops += entries[i].stats.count;

        /* Print stack trace in verbose mode */
        if (env.verbose && entries[i].key.stack_id > 0) {
            __u64 stack[MAX_STACK_DEPTH];
            if (bpf_map_lookup_elem(stack_fd, &entries[i].key.stack_id, stack) == 0) {
                printf("  Stack trace:\n");
                for (int j = 0; j < MAX_STACK_DEPTH && stack[j]; j++) {
                    printf("    %p\n", (void *)stack[j]);
                }
            }
        }
    }

    printf("----------------------------------------\n");
    printf("Total drops: %llu\n", (unsigned long long)total_drops);

    /* Clear if requested */
    if (env.clear) {
        memset(&key, 0, sizeof(key));
        while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(stats_fd, &next_key);
            key = next_key;
        }
    }
}

int main(int argc, char **argv)
{
    struct kernel_drop_stack_stats_summary_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = kernel_drop_stack_stats_summary_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set filters */
    if (env.src_ip)
        skel->rodata->filter_src_ip = ip_to_u32(env.src_ip);
    if (env.dst_ip)
        skel->rodata->filter_dst_ip = ip_to_u32(env.dst_ip);
    if (env.src_port)
        skel->rodata->filter_src_port = env.src_port;
    if (env.dst_port)
        skel->rodata->filter_dst_port = env.dst_port;
    if (env.protocol)
        skel->rodata->filter_protocol = env.protocol;
    skel->rodata->output_events = env.verbose;

    err = kernel_drop_stack_stats_summary_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = kernel_drop_stack_stats_summary_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Tracking kernel packet drops... Ctrl-C to stop\n");
    printf("Output interval: %d seconds\n", env.interval);

    while (!exiting) {
        sleep(env.interval);
        print_stats(skel);
    }

    printf("\nFinal statistics:\n");
    print_stats(skel);

cleanup:
    kernel_drop_stack_stats_summary_bpf__destroy(skel);
    return err != 0;
}
