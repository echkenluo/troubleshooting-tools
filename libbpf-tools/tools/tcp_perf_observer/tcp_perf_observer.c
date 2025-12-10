// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_perf_observer - TCP performance observer

#include <argp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcp_perf_observer.h"
#include "tcp_perf_observer.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *laddr;
    char *raddr;
    int lport;
    int rport;
    int interval;
    int rtt_threshold;
    int connlat_threshold;
    bool verbose;
} env = {
    .interval = 5,
    .rtt_threshold = 10000,
    .connlat_threshold = 20000,
};

const char *argp_program_version = "tcp_perf_observer 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"TCP performance observer - RTT, handshake latency, retransmissions.\n"
"\n"
"USAGE: tcp_perf_observer [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    tcp_perf_observer                          # Monitor all TCP\n"
"    tcp_perf_observer --laddr 10.0.0.1         # Filter by local IP\n"
"    tcp_perf_observer --rtt-threshold 5000     # Alert on >5ms RTT\n";

static const struct argp_option opts[] = {
    { "laddr", 'l', "IP", 0, "Local IP filter" },
    { "raddr", 'r', "IP", 0, "Remote IP filter" },
    { "lport", 'L', "PORT", 0, "Local port filter" },
    { "rport", 'R', "PORT", 0, "Remote port filter" },
    { "interval", 'i', "SEC", 0, "Statistics interval (default: 5)" },
    { "rtt-threshold", 't', "US", 0, "RTT threshold in microseconds (default: 10000)" },
    { "connlat-threshold", 'c', "US", 0, "Connection latency threshold (default: 20000)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'l': env.laddr = arg; break;
    case 'r': env.raddr = arg; break;
    case 'L': env.lport = atoi(arg); break;
    case 'R': env.rport = atoi(arg); break;
    case 'i': env.interval = atoi(arg); break;
    case 't': env.rtt_threshold = atoi(arg); break;
    case 'c': env.connlat_threshold = atoi(arg); break;
    case 'v': env.verbose = true; break;
    case 'h': argp_state_help(state, stderr, ARGP_HELP_STD_HELP); break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static void sig_handler(int sig) { exiting = true; }

static const char *event_type_str(__u8 type)
{
    switch (type) {
    case EVT_RTT: return "HIGH_RTT";
    case EVT_CONNLAT: return "SLOW_CONN";
    case EVT_RETRANS: return "RETRANS";
    case EVT_DROP: return "DROP";
    default: return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct detail_event *e = data;
    char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
    struct tm *tm;
    char ts[32];
    time_t t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));

    printf("[%s] %s: %s:%u -> %s:%u metric=%u extra1=%u extra2=%u\n",
           ts, event_type_str(e->ev_type),
           saddr, ntohs(e->sport), daddr, ntohs(e->dport),
           e->metric, e->extra1, e->extra2);

    return 0;
}

static void print_histogram(int fd, const char *name)
{
    __u64 hist[MAX_SLOTS] = {0};
    __u64 total = 0, max_count = 0;

    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_lookup_elem(fd, &i, &hist[i]);
        total += hist[i];
        if (hist[i] > max_count) max_count = hist[i];
    }

    if (total == 0) {
        printf("  %s: No data\n", name);
        return;
    }

    printf("  %s (total: %llu):\n", name, (unsigned long long)total);
    for (int s = 0; s < MAX_SLOTS; s++) {
        if (hist[s] == 0) continue;
        char range[32];
        if (s == 0) snprintf(range, sizeof(range), "0-1us");
        else snprintf(range, sizeof(range), "%llu-%lluus", 1ULL << (s-1), (1ULL << s) - 1);

        int bar = max_count > 0 ? (int)(30 * hist[s] / max_count) : 0;
        double pct = 100.0 * hist[s] / total;
        printf("    %-14s: %6llu (%5.1f%%) |", range, (unsigned long long)hist[s], pct);
        for (int b = 0; b < bar; b++) printf("*");
        printf("\n");
    }
}

static void print_report(struct tcp_perf_observer_bpf *skel, time_t start_time)
{
    int rtt_fd = bpf_map__fd(skel->maps.rtt_hist);
    int conn_fd = bpf_map__fd(skel->maps.connlat_hist);
    int cnt_fd = bpf_map__fd(skel->maps.counters);
    __u64 counters[CNT_MAX] = {0};

    for (__u32 i = 0; i < CNT_MAX; i++)
        bpf_map_lookup_elem(cnt_fd, &i, &counters[i]);

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n================================================================================\n");
    printf("[%s] TCP Performance Report (Duration: %lds)\n", ts, now - start_time);
    printf("================================================================================\n");

    printf("\nCounters:\n");
    printf("  ACK packets:    %llu\n", (unsigned long long)counters[CNT_ACK]);
    printf("  Retransmits:    %llu\n", (unsigned long long)counters[CNT_RETRANS]);
    printf("  Connections:    %llu\n", (unsigned long long)counters[CNT_CONN]);

    printf("\nHistograms:\n");
    print_histogram(rtt_fd, "RTT");
    print_histogram(conn_fd, "Connection Latency");

    printf("================================================================================\n");

    /* Clear for next interval */
    __u64 zero = 0;
    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_update_elem(rtt_fd, &i, &zero, BPF_ANY);
        bpf_map_update_elem(conn_fd, &i, &zero, BPF_ANY);
    }
    for (__u32 i = 0; i < CNT_MAX; i++)
        bpf_map_update_elem(cnt_fd, &i, &zero, BPF_ANY);
}

int main(int argc, char **argv)
{
    struct tcp_perf_observer_bpf *skel;
    struct ring_buffer *rb = NULL;
    time_t start_time, last_report;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tcp_perf_observer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (env.laddr) {
        struct in_addr addr;
        if (inet_pton(AF_INET, env.laddr, &addr) == 1)
            skel->rodata->targ_laddr = addr.s_addr;
    }
    if (env.raddr) {
        struct in_addr addr;
        if (inet_pton(AF_INET, env.raddr, &addr) == 1)
            skel->rodata->targ_raddr = addr.s_addr;
    }
    if (env.lport) skel->rodata->targ_lport = htons(env.lport);
    if (env.rport) skel->rodata->targ_rport = htons(env.rport);
    skel->rodata->rtt_threshold_us = env.rtt_threshold;
    skel->rodata->connlat_threshold_us = env.connlat_threshold;

    err = tcp_perf_observer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = tcp_perf_observer_bpf__attach(skel);
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

    printf("TCP Performance Observer Started\n");
    printf("RTT threshold: %d us, Connection latency threshold: %d us\n",
           env.rtt_threshold, env.connlat_threshold);
    printf("Press Ctrl+C to stop\n\n");

    start_time = time(NULL);
    last_report = start_time;

    while (!exiting) {
        ring_buffer__poll(rb, 100);

        time_t now = time(NULL);
        if ((now - last_report) >= env.interval) {
            print_report(skel, start_time);
            last_report = now;
        }
    }

    print_report(skel, start_time);

cleanup:
    ring_buffer__free(rb);
    tcp_perf_observer_bpf__destroy(skel);
    return err != 0;
}
