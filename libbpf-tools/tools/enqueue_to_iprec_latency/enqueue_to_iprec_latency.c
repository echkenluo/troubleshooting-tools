// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// enqueue_to_iprec_latency - RX latency measurement tool
//
// Measures critical async boundary latency in Linux RX path:
// enqueue_to_backlog -> __netif_receive_skb -> ip_rcv

#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "enqueue_to_iprec_latency.h"
#include "enqueue_to_iprec_latency.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *interface;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    char *protocol;
    int interval;
    int duration;
    int threshold;
    bool verbose;
} env = {
    .interval = 5,
    .duration = 0,
    .threshold = 0,
    .verbose = false,
};

/* Cumulative statistics */
static __u64 cum_counters[CNT_MAX] = {0};
static __u64 cum_hist[3][3][MAX_SLOTS] = {0};  /* [prev_stage][curr_stage][slot] */

const char *argp_program_version = "enqueue_to_iprec_latency 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Measure RX latency: enqueue_to_backlog -> ip_rcv\n"
"\n"
"USAGE: enqueue_to_iprec_latency --interface <dev> [OPTIONS]\n"
"\n"
"Measures 3 critical stages:\n"
"  1. enqueue_to_backlog  - Queue insertion\n"
"  2. __netif_receive_skb - Softirq processing (ASYNC BOUNDARY)\n"
"  3. ip_rcv              - IP layer entry\n"
"\n"
"EXAMPLES:\n"
"    enqueue_to_iprec_latency --interface eth0\n"
"    enqueue_to_iprec_latency --interface eth0 --src-ip 10.0.0.1 --protocol tcp\n"
"    enqueue_to_iprec_latency --interface eth0 --threshold 100  # Alert >100us\n";

static const struct argp_option opts[] = {
    { "interface", 'i', "DEV", 0, "Target interface (required)" },
    { "src-ip", 's', "IP", 0, "Source IP filter" },
    { "dst-ip", 'd', "IP", 0, "Destination IP filter" },
    { "src-port", 'S', "PORT", 0, "Source port filter" },
    { "dst-port", 'D', "PORT", 0, "Destination port filter" },
    { "protocol", 'p', "PROTO", 0, "Protocol filter (tcp/udp/all)" },
    { "interval", 'I', "SEC", 0, "Statistics interval (default: 5)" },
    { "duration", 'T', "SEC", 0, "Total duration (0=unlimited)" },
    { "threshold", 't', "US", 0, "High latency threshold in microseconds" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interface = arg;
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
        env.protocol = arg;
        break;
    case 'I':
        env.interval = atoi(arg);
        break;
    case 'T':
        env.duration = atoi(arg);
        break;
    case 't':
        env.threshold = atoi(arg);
        break;
    case 'v':
        env.verbose = true;
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

static const char *stage_name(__u8 stage)
{
    switch (stage) {
    case STAGE_ENQUEUE:
        return "enqueue_to_backlog";
    case STAGE_RECEIVE:
        return "__netif_receive_skb";
    case STAGE_IP_RCV:
        return "ip_rcv";
    default:
        return "unknown";
    }
}

static void print_ip(__be32 addr, char *buf, size_t buflen)
{
    struct in_addr in = { .s_addr = addr };
    inet_ntop(AF_INET, &in, buf, buflen);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct latency_event *e = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct tm *tm;
    char ts[32];
    time_t t;

    t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    print_ip(e->src_ip, src_ip, sizeof(src_ip));
    print_ip(e->dst_ip, dst_ip, sizeof(dst_ip));

    printf("\n");
    printf("================================================================================\n");
    printf("HIGH LATENCY EVENT at %s\n", ts);
    printf("================================================================================\n");
    printf("Latency: %llu us (%.3f ms)\n",
           (unsigned long long)e->latency_us,
           (double)e->latency_us / 1000.0);
    printf("Stage: %s -> %s\n", stage_name(e->prev_stage), stage_name(e->curr_stage));

    if (e->prev_stage == STAGE_ENQUEUE && e->curr_stage == STAGE_RECEIVE)
        printf("^^^ CRITICAL ASYNC BOUNDARY ^^^\n");

    printf("CPU: %u -> %u", e->cpu_start, e->cpu_end);
    if (e->cpu_start != e->cpu_end)
        printf(" (MIGRATION)");
    printf("\n");

    printf("Flow: %s:%u -> %s:%u (%s)\n",
           src_ip, ntohs(e->src_port),
           dst_ip, ntohs(e->dst_port),
           e->protocol == 6 ? "TCP" : "UDP");
    printf("================================================================================\n");

    return 0;
}

static void print_histogram(int hist_fd, bool cumulative)
{
    struct hist_key key = {}, next_key;
    __u64 value;
    __u64 hist[3][3][MAX_SLOTS] = {0};

    /* Collect histogram data */
    while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(hist_fd, &next_key, &value) == 0) {
            if (next_key.prev_stage < 3 && next_key.curr_stage < 3 &&
                next_key.slot < MAX_SLOTS) {
                hist[next_key.prev_stage][next_key.curr_stage][next_key.slot] = value;
                if (!cumulative) {
                    cum_hist[next_key.prev_stage][next_key.curr_stage][next_key.slot] += value;
                }
            }
        }
        key = next_key;
    }

    __u64 (*data)[3][MAX_SLOTS] = cumulative ? cum_hist : hist;

    /* Print stage pairs */
    int pairs[][2] = {{STAGE_ENQUEUE, STAGE_RECEIVE}, {STAGE_RECEIVE, STAGE_IP_RCV}};

    for (int p = 0; p < 2; p++) {
        int prev = pairs[p][0];
        int curr = pairs[p][1];

        __u64 total = 0;
        __u64 max_count = 0;
        for (int s = 0; s < MAX_SLOTS; s++) {
            total += data[prev][curr][s];
            if (data[prev][curr][s] > max_count)
                max_count = data[prev][curr][s];
        }

        if (total == 0)
            continue;

        printf("\n  %s -> %s:\n", stage_name(prev), stage_name(curr));
        if (prev == STAGE_ENQUEUE && curr == STAGE_RECEIVE)
            printf("    ^^^ CRITICAL ASYNC BOUNDARY ^^^\n");
        printf("    Total samples: %llu\n", (unsigned long long)total);
        printf("    Latency distribution:\n");

        for (int s = 0; s < MAX_SLOTS; s++) {
            if (data[prev][curr][s] == 0)
                continue;

            char range[32];
            if (s == 0) {
                snprintf(range, sizeof(range), "0-1us");
            } else {
                __u64 low = 1ULL << (s - 1);
                __u64 high = (1ULL << s) - 1;
                snprintf(range, sizeof(range), "%llu-%lluus",
                         (unsigned long long)low, (unsigned long long)high);
            }

            int bar_width = max_count > 0 ? (int)(40 * data[prev][curr][s] / max_count) : 0;
            double pct = 100.0 * data[prev][curr][s] / total;

            printf("      %-16s: %6llu (%5.1f%%) |",
                   range, (unsigned long long)data[prev][curr][s], pct);
            for (int b = 0; b < bar_width; b++)
                printf("*");
            printf("\n");
        }
    }

    /* Clear histogram for next interval if not cumulative */
    if (!cumulative) {
        key.prev_stage = 0;
        key.curr_stage = 0;
        key.slot = 0;
        while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(hist_fd, &next_key);
            key = next_key;
        }
    }
}

static void print_counters(int cnt_fd, bool cumulative)
{
    __u64 counters[CNT_MAX] = {0};

    for (__u32 i = 0; i < CNT_MAX; i++) {
        bpf_map_lookup_elem(cnt_fd, &i, &counters[i]);
        if (!cumulative)
            cum_counters[i] += counters[i];
    }

    __u64 *data = cumulative ? cum_counters : counters;

    printf("\nPacket Counters%s:\n", cumulative ? " (Cumulative)" : "");
    printf("  Enqueued packets:     %llu\n", (unsigned long long)data[CNT_ENQUEUE]);
    printf("  Received packets:     %llu\n", (unsigned long long)data[CNT_RECEIVE]);
    printf("  IP layer packets:     %llu\n", (unsigned long long)data[CNT_IP_RCV]);
    printf("  Cross-CPU migrations: %llu\n", (unsigned long long)data[CNT_CROSS_CPU]);
    printf("  Parse failures:       %llu\n", (unsigned long long)data[CNT_PARSE_FAIL]);
    printf("  Flow not found:       %llu\n", (unsigned long long)data[CNT_FLOW_NOT_FOUND]);

    /* Clear counters for next interval if not cumulative */
    if (!cumulative) {
        __u64 zero = 0;
        for (__u32 i = 0; i < CNT_MAX; i++)
            bpf_map_update_elem(cnt_fd, &i, &zero, BPF_ANY);
    }
}

static void print_report(int hist_fd, int cnt_fd, time_t start_time, bool cumulative)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n");
    printf("================================================================================\n");
    printf("[%s] %sLatency Report (Duration: %lds)\n",
           ts, cumulative ? "CUMULATIVE " : "", now - start_time);
    printf("================================================================================\n");

    print_histogram(hist_fd, cumulative);
    print_counters(cnt_fd, cumulative);
    printf("================================================================================\n");
}

int main(int argc, char **argv)
{
    struct enqueue_to_iprec_latency_bpf *skel;
    struct ring_buffer *rb = NULL;
    time_t start_time, last_report;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!env.interface) {
        fprintf(stderr, "Please specify interface with --interface\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = enqueue_to_iprec_latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure filters */
    unsigned int ifindex = if_nametoindex(env.interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", env.interface);
        err = 1;
        goto cleanup;
    }
    skel->rodata->targ_ifindex = ifindex;

    if (env.src_ip) {
        struct in_addr addr;
        if (inet_pton(AF_INET, env.src_ip, &addr) == 1)
            skel->rodata->targ_src_ip = addr.s_addr;
    }

    if (env.dst_ip) {
        struct in_addr addr;
        if (inet_pton(AF_INET, env.dst_ip, &addr) == 1)
            skel->rodata->targ_dst_ip = addr.s_addr;
    }

    if (env.src_port)
        skel->rodata->targ_src_port = htons(env.src_port);
    if (env.dst_port)
        skel->rodata->targ_dst_port = htons(env.dst_port);

    if (env.protocol) {
        if (strcasecmp(env.protocol, "tcp") == 0)
            skel->rodata->targ_protocol = 6;
        else if (strcasecmp(env.protocol, "udp") == 0)
            skel->rodata->targ_protocol = 17;
    }

    if (env.threshold > 0)
        skel->rodata->high_latency_threshold_us = env.threshold;

    err = enqueue_to_iprec_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = enqueue_to_iprec_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Setup ring buffer for high latency events */
    if (env.threshold > 0) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            err = 1;
            goto cleanup;
        }
    }

    printf("================================================================================\n");
    printf("RX Latency Measurement: enqueue_to_backlog -> ip_rcv\n");
    printf("================================================================================\n");
    printf("Interface: %s (ifindex %u)\n", env.interface, ifindex);
    if (env.src_ip)
        printf("Source IP: %s\n", env.src_ip);
    if (env.dst_ip)
        printf("Dest IP: %s\n", env.dst_ip);
    if (env.src_port)
        printf("Source port: %d\n", env.src_port);
    if (env.dst_port)
        printf("Dest port: %d\n", env.dst_port);
    if (env.protocol)
        printf("Protocol: %s\n", env.protocol);
    printf("Interval: %d seconds\n", env.interval);
    if (env.threshold > 0)
        printf("High latency threshold: %d us\n", env.threshold);
    printf("\nMeasuring stages:\n");
    printf("  1. enqueue_to_backlog  - Queue insertion\n");
    printf("  2. __netif_receive_skb - Softirq processing (ASYNC BOUNDARY)\n");
    printf("  3. ip_rcv              - IP layer entry\n");
    printf("================================================================================\n");
    printf("Press Ctrl+C to stop\n\n");

    start_time = time(NULL);
    last_report = start_time;

    int hist_fd = bpf_map__fd(skel->maps.latency_hist);
    int cnt_fd = bpf_map__fd(skel->maps.counters);

    while (!exiting) {
        if (rb)
            ring_buffer__poll(rb, 100);
        else
            usleep(100000);

        time_t now = time(NULL);

        /* Check duration limit */
        if (env.duration > 0 && (now - start_time) >= env.duration) {
            printf("\nDuration limit reached\n");
            break;
        }

        /* Print periodic report */
        if ((now - last_report) >= env.interval) {
            print_report(hist_fd, cnt_fd, start_time, false);
            last_report = now;
        }
    }

    /* Print final cumulative report */
    printf("\n\nFINAL CUMULATIVE REPORT\n");
    print_report(hist_fd, cnt_fd, start_time, true);

cleanup:
    ring_buffer__free(rb);
    enqueue_to_iprec_latency_bpf__destroy(skel);
    return err != 0;
}
