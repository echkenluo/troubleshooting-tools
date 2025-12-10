// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_upcall_latency_summary - OVS upcall latency histogram userspace program

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
#include "ovs_upcall_latency_summary.h"
#include "ovs_upcall_latency_summary.skel.h"
#include "trace_helpers.h"
#include "histogram.h"

static volatile bool exiting = false;

/* Command line arguments */
static struct env {
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    char *protocol;
    int interval;
    bool verbose;
} env = {
    .src_ip = NULL,
    .dst_ip = NULL,
    .src_port = 0,
    .dst_port = 0,
    .protocol = "all",
    .interval = 5,
    .verbose = false,
};

const char *argp_program_version = "ovs_upcall_latency_summary 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"OVS Upcall Latency Histogram Tool\n"
"\n"
"Measures latency distribution between OVS upcall and userspace processing.\n"
"\n"
"USAGE: ovs_upcall_latency_summary [--src-ip IP] [--dst-ip IP] [--protocol PROTO]\n"
"\n"
"EXAMPLES:\n"
"    ovs_upcall_latency_summary --interval 5\n"
"    ovs_upcall_latency_summary --src-ip 192.168.1.10 --protocol tcp\n"
"    ovs_upcall_latency_summary --protocol tcp --dst-port 22 --interval 10\n";

static const struct argp_option opts[] = {
    { "src-ip", 's', "IP", 0, "Source IP address filter" },
    { "dst-ip", 'd', "IP", 0, "Destination IP address filter" },
    { "src-port", 'S', "PORT", 0, "Source port filter (TCP/UDP)" },
    { "dst-port", 'D', "PORT", 0, "Destination port filter (TCP/UDP)" },
    { "protocol", 'p', "PROTO", 0, "Protocol filter (tcp, udp, icmp, all)" },
    { "interval", 'i', "SEC", 0, "Statistics output interval (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
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
        env.protocol = arg;
        break;
    case 'i':
        env.interval = atoi(arg);
        if (env.interval <= 0) {
            fprintf(stderr, "Invalid interval: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
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

static __u32 ip_to_int(const char *ip)
{
    struct in_addr addr;
    if (!ip || inet_pton(AF_INET, ip, &addr) != 1)
        return 0;
    return addr.s_addr;
}

static __u8 protocol_to_int(const char *proto)
{
    if (!proto || strcmp(proto, "all") == 0)
        return 0;
    if (strcmp(proto, "tcp") == 0)
        return IPPROTO_TCP;
    if (strcmp(proto, "udp") == 0)
        return IPPROTO_UDP;
    if (strcmp(proto, "icmp") == 0)
        return IPPROTO_ICMP;
    return 0;
}

static const char *protocol_name(__u8 proto)
{
    switch (proto) {
    case 0: return "all";
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_ICMP: return "ICMP";
    default: return "unknown";
    }
}

static void print_histogram(int hist_fd, int counter_fd, time_t interval_start)
{
    __u64 hist_data[MAX_SLOTS] = {};
    __u64 counters[NUM_COUNTERS] = {};
    __u32 key;
    time_t now = time(NULL);
    struct tm *tm_info;
    char time_buf[64];

    /* Read histogram data */
    for (key = 0; key < MAX_SLOTS; key++) {
        bpf_map_lookup_elem(hist_fd, &key, &hist_data[key]);
    }

    /* Read counters */
    for (key = 0; key < NUM_COUNTERS; key++) {
        bpf_map_lookup_elem(counter_fd, &key, &counters[key]);
    }

    /* Print header */
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("\n");
    printf("================================================================================\n");
    printf("[%s] OVS Upcall Latency Report (Interval: %lds)\n",
           time_buf, now - interval_start);
    printf("================================================================================\n");

    /* Print statistics */
    printf("Upcall Statistics:\n");
    printf("  Total upcalls: %llu\n", counters[COUNTER_TOTAL_UPCALLS]);
    printf("  Completed upcalls: %llu\n", counters[COUNTER_COMPLETED_UPCALLS]);
    if (counters[COUNTER_TOTAL_UPCALLS] > 0) {
        double completion_rate = (double)counters[COUNTER_COMPLETED_UPCALLS] * 100.0 /
                                 counters[COUNTER_TOTAL_UPCALLS];
        printf("  Completion rate: %.1f%%\n", completion_rate);
        printf("  Lost/timeout upcalls: %llu\n",
               counters[COUNTER_TOTAL_UPCALLS] - counters[COUNTER_COMPLETED_UPCALLS]);
    }

    /* Calculate and print histogram */
    __u64 total_samples = 0;
    __u64 max_count = 0;
    int max_bucket = -1;
    int min_bucket = MAX_SLOTS;

    for (key = 0; key < MAX_SLOTS; key++) {
        if (hist_data[key] > 0) {
            total_samples += hist_data[key];
            if (hist_data[key] > max_count)
                max_count = hist_data[key];
            if ((int)key < min_bucket)
                min_bucket = key;
            if ((int)key > max_bucket)
                max_bucket = key;
        }
    }

    if (total_samples > 0) {
        printf("\nUpcall Latency Distribution:\n");
        printf("------------------------------------------------------------\n");
        printf("  Total samples: %llu\n", total_samples);
        printf("  Latency histogram:\n");

        for (key = min_bucket; key <= (__u32)max_bucket; key++) {
            if (hist_data[key] == 0)
                continue;

            char range_str[32];
            __u64 low, high;

            if (key == 0) {
                snprintf(range_str, sizeof(range_str), "0-1us");
            } else {
                low = 1ULL << (key - 1);
                high = (1ULL << key) - 1;

                if (high >= 1000000) {
                    snprintf(range_str, sizeof(range_str), "%.1f-%.1fs",
                             (double)low / 1000000.0, (double)high / 1000000.0);
                } else if (high >= 1000) {
                    snprintf(range_str, sizeof(range_str), "%.1f-%.1fms",
                             (double)low / 1000.0, (double)high / 1000.0);
                } else {
                    snprintf(range_str, sizeof(range_str), "%llu-%lluus", low, high);
                }
            }

            /* Create bar graph */
            int bar_width = max_count > 0 ? (int)(40 * hist_data[key] / max_count) : 0;
            char bar[41];
            memset(bar, '*', bar_width);
            bar[bar_width] = '\0';

            printf("    %-15s: %6llu |%-40s|\n", range_str, hist_data[key], bar);
        }
    } else {
        printf("\nNo upcall latency data collected in this interval\n");
    }

    /* Clear histogram for next interval */
    __u64 zero = 0;
    for (key = 0; key < MAX_SLOTS; key++) {
        bpf_map_update_elem(hist_fd, &key, &zero, BPF_ANY);
    }
    for (key = 0; key < NUM_COUNTERS; key++) {
        bpf_map_update_elem(counter_fd, &key, &zero, BPF_ANY);
    }
}

int main(int argc, char **argv)
{
    struct ovs_upcall_latency_summary_bpf *skel;
    int err;
    time_t interval_start;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Setup signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    skel = ovs_upcall_latency_summary_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    skel->rodata->targ_src_ip = ip_to_int(env.src_ip);
    skel->rodata->targ_dst_ip = ip_to_int(env.dst_ip);
    skel->rodata->targ_src_port = env.src_port;
    skel->rodata->targ_dst_port = env.dst_port;
    skel->rodata->targ_protocol = protocol_to_int(env.protocol);

    /* Load & verify BPF programs */
    err = ovs_upcall_latency_summary_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach tracepoints/kprobes */
    err = ovs_upcall_latency_summary_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Print startup info */
    printf("=== OVS Upcall Latency Histogram Tool ===\n");
    printf("Protocol filter: %s\n", protocol_name(protocol_to_int(env.protocol)));
    if (env.src_ip)
        printf("Source IP filter: %s\n", env.src_ip);
    if (env.dst_ip)
        printf("Destination IP filter: %s\n", env.dst_ip);
    if (env.src_port)
        printf("Source port filter: %d\n", env.src_port);
    if (env.dst_port)
        printf("Destination port filter: %d\n", env.dst_port);
    printf("Statistics interval: %d seconds\n", env.interval);
    printf("BPF program loaded successfully\n");
    printf("\nCollecting OVS upcall latency data... Hit Ctrl-C to end.\n");
    printf("Statistics will be displayed every %d seconds\n", env.interval);

    /* Main loop */
    interval_start = time(NULL);
    while (!exiting) {
        sleep(env.interval);
        if (exiting)
            break;

        print_histogram(
            bpf_map__fd(skel->maps.latency_hist),
            bpf_map__fd(skel->maps.packet_counters),
            interval_start
        );
        interval_start = time(NULL);
    }

    /* Print final statistics */
    printf("\n\nFinal statistics:\n");
    print_histogram(
        bpf_map__fd(skel->maps.latency_hist),
        bpf_map__fd(skel->maps.packet_counters),
        interval_start
    );
    printf("\nExiting...\n");

cleanup:
    ovs_upcall_latency_summary_bpf__destroy(skel);
    return err != 0;
}
