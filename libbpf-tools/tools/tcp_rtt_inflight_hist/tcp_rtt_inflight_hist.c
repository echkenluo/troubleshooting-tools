// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_rtt_inflight_hist - TCP RTT and inflight histogram

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
#include "tcp_rtt_inflight_hist.h"
#include "tcp_rtt_inflight_hist.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *laddr;
    char *raddr;
    int lport;
    int rport;
    int interval;
    bool verbose;
} env = {
    .interval = 5,
};

const char *argp_program_version = "tcp_rtt_inflight_hist 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"TCP RTT vs Inflight histogram.\n"
"\n"
"USAGE: tcp_rtt_inflight_hist [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    tcp_rtt_inflight_hist                    # Monitor all TCP\n"
"    tcp_rtt_inflight_hist --laddr 10.0.0.1   # Filter by local IP\n";

static const struct argp_option opts[] = {
    { "laddr", 'l', "IP", 0, "Local IP filter" },
    { "raddr", 'r', "IP", 0, "Remote IP filter" },
    { "lport", 'L', "PORT", 0, "Local port filter" },
    { "rport", 'R', "PORT", 0, "Remote port filter" },
    { "interval", 'i', "SEC", 0, "Statistics interval (default: 5)" },
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

static void print_histogram(int fd, const char *name, const char *unit)
{
    __u64 hist[MAX_SLOTS] = {0};
    __u64 total = 0, max_count = 0;

    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_lookup_elem(fd, &i, &hist[i]);
        total += hist[i];
        if (hist[i] > max_count) max_count = hist[i];
    }

    if (total == 0) return;

    printf("\n  %s (total: %llu):\n", name, (unsigned long long)total);
    for (int s = 0; s < MAX_SLOTS; s++) {
        if (hist[s] == 0) continue;
        char range[32];
        if (s == 0) snprintf(range, sizeof(range), "0-1%s", unit);
        else snprintf(range, sizeof(range), "%llu-%llu%s", 1ULL << (s-1), (1ULL << s) - 1, unit);

        int bar = max_count > 0 ? (int)(30 * hist[s] / max_count) : 0;
        double pct = 100.0 * hist[s] / total;
        printf("    %-16s: %6llu (%5.1f%%) |", range, (unsigned long long)hist[s], pct);
        for (int b = 0; b < bar; b++) printf("*");
        printf("\n");
    }
}

static void print_report(struct tcp_rtt_inflight_hist_bpf *skel, time_t start_time)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n================================================================================\n");
    printf("[%s] TCP RTT vs Inflight Report (Duration: %lds)\n", ts, now - start_time);
    printf("================================================================================\n");

    print_histogram(bpf_map__fd(skel->maps.rtt_hist), "RTT Distribution", "us");
    print_histogram(bpf_map__fd(skel->maps.inflight_hist), "Inflight Distribution", "KB");

    printf("================================================================================\n");

    /* Clear histograms */
    __u64 zero = 0;
    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_update_elem(bpf_map__fd(skel->maps.rtt_hist), &i, &zero, BPF_ANY);
        bpf_map_update_elem(bpf_map__fd(skel->maps.inflight_hist), &i, &zero, BPF_ANY);
    }

    /* Clear 2D histogram */
    struct hist_key key = {}, next;
    int fd = bpf_map__fd(skel->maps.hist_2d);
    while (bpf_map_get_next_key(fd, &key, &next) == 0) {
        bpf_map_delete_elem(fd, &next);
        key = next;
    }
}

int main(int argc, char **argv)
{
    struct tcp_rtt_inflight_hist_bpf *skel;
    time_t start_time, last_report;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tcp_rtt_inflight_hist_bpf__open();
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

    err = tcp_rtt_inflight_hist_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = tcp_rtt_inflight_hist_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("TCP RTT vs Inflight Histogram Started\n");
    printf("Press Ctrl+C to stop\n\n");

    start_time = time(NULL);
    last_report = start_time;

    while (!exiting) {
        sleep(1);

        time_t now = time(NULL);
        if ((now - last_report) >= env.interval) {
            print_report(skel, start_time);
            last_report = now;
        }
    }

    print_report(skel, start_time);

cleanup:
    tcp_rtt_inflight_hist_bpf__destroy(skel);
    return err != 0;
}
