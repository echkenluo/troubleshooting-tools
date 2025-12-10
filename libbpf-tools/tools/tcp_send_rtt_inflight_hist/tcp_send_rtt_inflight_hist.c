// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tcp_send_rtt_inflight_hist - TCP RTT/inflight/cwnd histogram from SEND perspective

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
#include "tcp_send_rtt_inflight_hist.h"
#include "tcp_send_rtt_inflight_hist.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *laddr;
    char *raddr;
    int lport;
    int rport;
    int interval;
    int duration;
    int sample_rate;
    bool bw_hist;
    bool verbose;
} env = {
    .interval = 1,
    .sample_rate = 1,
};

const char *argp_program_version = "tcp_send_rtt_inflight_hist 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"TCP RTT, inflight, and cwnd histogram collector from SEND perspective.\n"
"\n"
"Captures SRTT, packets_out, snd_cwnd at the moment each data packet is SENT.\n"
"Probes tcp_rate_skb_sent (called per packet sent).\n"
"\n"
"USAGE: tcp_send_rtt_inflight_hist [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    tcp_send_rtt_inflight_hist --interval 1 --duration 60\n"
"    tcp_send_rtt_inflight_hist --laddr 70.0.0.31 --raddr 70.0.0.32\n"
"    tcp_send_rtt_inflight_hist --bw-hist --interval 1\n"
"    tcp_send_rtt_inflight_hist --lport 5201\n";

static const struct argp_option opts[] = {
    { "laddr", 'l', "IP", 0, "Filter by local IPv4 address" },
    { "raddr", 'r', "IP", 0, "Filter by remote IPv4 address" },
    { "lport", 'L', "PORT", 0, "Filter by local TCP port" },
    { "rport", 'R', "PORT", 0, "Filter by remote TCP port" },
    { "interval", 'i', "SECS", 0, "Print interval seconds (default: 1)" },
    { "duration", 'd', "SECS", 0, "Total run time seconds (0 = infinite)" },
    { "sample-rate", 's', "N", 0, "Sample every N packets (default: 1)" },
    { "bw-hist", 'b', NULL, 0, "Enable bandwidth histogram (500Mbps buckets)" },
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
    case 'd': env.duration = atoi(arg); break;
    case 's': env.sample_rate = atoi(arg); break;
    case 'b': env.bw_hist = true; break;
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

static __u32 ip_to_u32(const char *ip)
{
    struct in_addr addr;
    if (!ip || inet_pton(AF_INET, ip, &addr) != 1)
        return 0;
    return addr.s_addr;
}

static void print_log2_hist(__u64 *vals, int slots, const char *unit)
{
    __u64 max_val = 0;
    int max_slot = -1;

    for (int i = 0; i < slots; i++) {
        if (vals[i] > 0) max_slot = i;
        if (vals[i] > max_val) max_val = vals[i];
    }

    if (max_slot < 0) {
        printf("     (no data)\n");
        return;
    }

    for (int i = 0; i <= max_slot; i++) {
        __u64 low = (1ULL << i);
        __u64 high = (1ULL << (i + 1)) - 1;
        if (i == 0) low = 0;

        int stars = max_val > 0 ? (vals[i] * 40 / max_val) : 0;
        printf("%10llu -> %-10llu : %-8llu |", low, high, vals[i]);
        for (int j = 0; j < stars; j++) printf("*");
        printf("\n");
    }
}

static void print_bw_hist(int map_fd)
{
    __u64 vals[BW_BUCKET_COUNT] = {};
    __u64 max_val = 0;
    int max_slot = -1;

    for (__u32 i = 0; i < BW_BUCKET_COUNT; i++) {
        bpf_map_lookup_elem(map_fd, &i, &vals[i]);
        if (vals[i] > 0) max_slot = i;
        if (vals[i] > max_val) max_val = vals[i];
    }

    if (max_slot < 0) {
        printf("     (no data)\n");
        return;
    }

    for (int i = 0; i <= max_slot; i++) {
        if (vals[i] == 0) continue;
        double low_gbps = i * BW_BUCKET_MBPS / 1000.0;
        double high_gbps = (i + 1) * BW_BUCKET_MBPS / 1000.0;
        int stars = max_val > 0 ? (vals[i] * 40 / max_val) : 0;
        printf("%5.1f-%5.1f Gbps : %-8llu |", low_gbps, high_gbps, vals[i]);
        for (int j = 0; j < stars; j++) printf("*");
        printf("\n");
    }
}

static void compute_stats(__u64 *vals, int slots, __u64 *count, double *mean, __u64 *p50, __u64 *p90, __u64 *p99)
{
    __u64 total_count = 0;
    __u64 weighted_sum = 0;

    for (int i = 0; i < slots; i++) {
        if (vals[i] == 0) continue;
        __u64 bucket_val = (1ULL << i) + ((1ULL << i) >> 1);
        if (i == 0) bucket_val = 1;
        total_count += vals[i];
        weighted_sum += bucket_val * vals[i];
    }

    *count = total_count;
    *mean = total_count > 0 ? (double)weighted_sum / total_count : 0;

    /* Calculate percentiles */
    __u64 p50_idx = total_count / 2;
    __u64 p90_idx = total_count * 90 / 100;
    __u64 p99_idx = total_count * 99 / 100;
    __u64 cumulative = 0;
    *p50 = *p90 = *p99 = 0;

    for (int i = 0; i < slots; i++) {
        __u64 bucket_val = (1ULL << i);
        if (i == 0) bucket_val = 1;
        cumulative += vals[i];
        if (*p50 == 0 && cumulative >= p50_idx) *p50 = bucket_val;
        if (*p90 == 0 && cumulative >= p90_idx) *p90 = bucket_val;
        if (*p99 == 0 && cumulative >= p99_idx) *p99 = bucket_val;
    }
}

static void print_stats(struct tcp_send_rtt_inflight_hist_bpf *skel)
{
    __u64 rtt_vals[MAX_SLOTS] = {};
    __u64 inflight_vals[MAX_SLOTS] = {};
    __u64 cwnd_vals[MAX_SLOTS] = {};
    __u64 stat_vals[STAT_MAX] = {};

    int rtt_fd = bpf_map__fd(skel->maps.rtt_hist);
    int inflight_fd = bpf_map__fd(skel->maps.inflight_hist);
    int cwnd_fd = bpf_map__fd(skel->maps.cwnd_hist);
    int stats_fd = bpf_map__fd(skel->maps.stats);

    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_lookup_elem(rtt_fd, &i, &rtt_vals[i]);
        bpf_map_lookup_elem(inflight_fd, &i, &inflight_vals[i]);
        bpf_map_lookup_elem(cwnd_fd, &i, &cwnd_vals[i]);
    }

    for (__u32 i = 0; i < STAT_MAX; i++) {
        bpf_map_lookup_elem(stats_fd, &i, &stat_vals[i]);
    }

    __u64 count;
    double mean;
    __u64 p50, p90, p99;

    char ts[32];
    time_t t = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));

    printf("\n==== %s (pkts_sent: %llu) ====\n", ts, stat_vals[STAT_SAMPLES]);

    compute_stats(rtt_vals, MAX_SLOTS, &count, &mean, &p50, &p90, &p99);
    printf("\n[RTT (us)] mean=%.1f p50=%llu p90=%llu p99=%llu\n", mean, p50, p90, p99);
    print_log2_hist(rtt_vals, MAX_SLOTS, "usecs");

    compute_stats(inflight_vals, MAX_SLOTS, &count, &mean, &p50, &p90, &p99);
    printf("\n[In-flight (packets)] mean=%.1f p50=%llu p90=%llu p99=%llu\n", mean, p50, p90, p99);
    print_log2_hist(inflight_vals, MAX_SLOTS, "packets");

    compute_stats(cwnd_vals, MAX_SLOTS, &count, &mean, &p50, &p90, &p99);
    printf("\n[CWND (packets)] mean=%.1f p50=%llu p90=%llu p99=%llu\n", mean, p50, p90, p99);
    print_log2_hist(cwnd_vals, MAX_SLOTS, "packets");

    printf("\n[Retransmissions] total_retrans=%llu retrans_out=%llu lost_out=%llu\n",
           stat_vals[STAT_TOTAL_RETRANS], stat_vals[STAT_RETRANS_OUT], stat_vals[STAT_LOST_OUT]);

    if (env.bw_hist) {
        printf("\n[Bandwidth (Gbps)]\n");
        print_bw_hist(bpf_map__fd(skel->maps.bw_hist));
    }
}

static void clear_maps(struct tcp_send_rtt_inflight_hist_bpf *skel)
{
    int rtt_fd = bpf_map__fd(skel->maps.rtt_hist);
    int inflight_fd = bpf_map__fd(skel->maps.inflight_hist);
    int cwnd_fd = bpf_map__fd(skel->maps.cwnd_hist);
    int stats_fd = bpf_map__fd(skel->maps.stats);
    int bw_fd = bpf_map__fd(skel->maps.bw_hist);
    __u64 zero = 0;

    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_update_elem(rtt_fd, &i, &zero, BPF_ANY);
        bpf_map_update_elem(inflight_fd, &i, &zero, BPF_ANY);
        bpf_map_update_elem(cwnd_fd, &i, &zero, BPF_ANY);
    }

    for (__u32 i = 0; i < STAT_MAX; i++) {
        bpf_map_update_elem(stats_fd, &i, &zero, BPF_ANY);
    }

    if (env.bw_hist) {
        for (__u32 i = 0; i < BW_BUCKET_COUNT; i++) {
            bpf_map_update_elem(bw_fd, &i, &zero, BPF_ANY);
        }
    }
}

int main(int argc, char **argv)
{
    struct tcp_send_rtt_inflight_hist_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tcp_send_rtt_inflight_hist_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set filters */
    skel->rodata->targ_laddr = ip_to_u32(env.laddr);
    skel->rodata->targ_raddr = ip_to_u32(env.raddr);
    skel->rodata->targ_lport = env.lport ? htons(env.lport) : 0;
    skel->rodata->targ_rport = env.rport ? htons(env.rport) : 0;
    skel->rodata->sample_rate = env.sample_rate > 0 ? env.sample_rate : 1;
    skel->rodata->enable_bw_hist = env.bw_hist;

    err = tcp_send_rtt_inflight_hist_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = tcp_send_rtt_inflight_hist_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("tcp_send_rtt_inflight_hist started (SEND perspective)\n");
    printf("Probe point: tcp_rate_skb_sent (called per packet sent)\n");
    printf("Filter:");
    if (env.laddr) printf(" laddr=%s", env.laddr);
    if (env.raddr) printf(" raddr=%s", env.raddr);
    if (env.lport) printf(" lport=%d", env.lport);
    if (env.rport) printf(" rport=%d", env.rport);
    if (!env.laddr && !env.raddr && !env.lport && !env.rport) printf(" none");
    printf("\nInterval: %ds, Sample rate: 1/%d\n", env.interval, env.sample_rate);
    if (env.bw_hist)
        printf("Bandwidth histogram: ENABLED (%dMbps buckets, 0-%.0fGbps range)\n",
               BW_BUCKET_MBPS, (double)BW_BUCKET_COUNT * BW_BUCKET_MBPS / 1000);
    printf("Press Ctrl-C to stop.\n");

    time_t start_time = time(NULL);
    time_t last_print = start_time;

    while (!exiting) {
        sleep(1);
        time_t now = time(NULL);

        if (now - last_print >= env.interval) {
            print_stats(skel);
            clear_maps(skel);
            last_print = now;
        }

        if (env.duration > 0 && now - start_time >= env.duration)
            break;
    }

    /* Final stats */
    print_stats(skel);

cleanup:
    tcp_send_rtt_inflight_hist_bpf__destroy(skel);
    return err != 0;
}
