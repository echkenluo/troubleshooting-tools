// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_performance_metrics - System network performance userspace

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "system_network_performance_metrics.h"
#include "system_network_performance_metrics.skel.h"
#include "trace_helpers.h"
#include "histogram.h"

static volatile bool exiting = false;

static struct env {
    char *interface;
    int interval;
    bool histogram;
} env = {
    .interval = 5,
    .histogram = false,
};

const char *argp_program_version = "system_network_performance_metrics 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Collect system network performance metrics\n"
"\n"
"USAGE: system_network_performance_metrics [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    system_network_performance_metrics\n"
"    system_network_performance_metrics -i eth0 -I 10\n";

static const struct argp_option opts[] = {
    { "interface", 'i', "DEV", 0, "Filter by interface" },
    { "interval", 'I', "SEC", 0, "Output interval (default: 5)" },
    { "histogram", 'H', NULL, 0, "Show latency histograms" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interface = arg;
        break;
    case 'I':
        env.interval = atoi(arg);
        break;
    case 'H':
        env.histogram = true;
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

static void print_metrics(struct system_network_performance_metrics_bpf *skel)
{
    int if_fd = bpf_map__fd(skel->maps.if_metrics);
    int proto_fd = bpf_map__fd(skel->maps.proto_metrics);
    struct if_metrics_key if_key = {}, if_next;
    struct proto_metrics_key proto_key = {}, proto_next;
    struct perf_metrics metrics;
    char ifname[IFNAMSIZ];
    time_t now;
    struct tm *tm;
    char ts[32];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s - Network Performance Metrics\n", ts);
    printf("============================================================\n");

    /* Interface metrics */
    printf("\nInterface Metrics:\n");
    printf("%-16s %12s %14s %12s %14s %8s\n",
           "INTERFACE", "TX_PKTS", "TX_BYTES", "RX_PKTS", "RX_BYTES", "DROPS");
    printf("------------------------------------------------------------\n");

    while (bpf_map_get_next_key(if_fd, &if_key, &if_next) == 0) {
        if (bpf_map_lookup_elem(if_fd, &if_next, &metrics) == 0) {
            if_indextoname(if_next.ifindex, ifname);
            printf("%-16s %12llu %14llu %12llu %14llu %8llu\n",
                   ifname[0] ? ifname : "unknown",
                   (unsigned long long)metrics.tx_packets,
                   (unsigned long long)metrics.tx_bytes,
                   (unsigned long long)metrics.rx_packets,
                   (unsigned long long)metrics.rx_bytes,
                   (unsigned long long)metrics.drops);

            if (metrics.tx_packets > 0) {
                double avg_tx_lat = (double)metrics.tx_latency_sum / metrics.tx_packets / 1000.0;
                printf("  TX latency: avg=%.1f us, min=%.1f us, max=%.1f us\n",
                       avg_tx_lat,
                       metrics.tx_latency_min / 1000.0,
                       metrics.tx_latency_max / 1000.0);
            }
            if (metrics.rx_packets > 0) {
                double avg_rx_lat = (double)metrics.rx_latency_sum / metrics.rx_packets / 1000.0;
                printf("  RX latency: avg=%.1f us, min=%.1f us, max=%.1f us\n",
                       avg_rx_lat,
                       metrics.rx_latency_min / 1000.0,
                       metrics.rx_latency_max / 1000.0);
            }
        }
        if_key = if_next;
    }

    /* Protocol metrics */
    printf("\nProtocol Metrics:\n");
    printf("%-10s %12s %14s\n", "PROTOCOL", "RX_PKTS", "RX_BYTES");
    printf("------------------------------------------------------------\n");

    while (bpf_map_get_next_key(proto_fd, &proto_key, &proto_next) == 0) {
        if (bpf_map_lookup_elem(proto_fd, &proto_next, &metrics) == 0) {
            const char *proto_name = "OTHER";
            if (proto_next.protocol == IPPROTO_TCP)
                proto_name = "TCP";
            else if (proto_next.protocol == IPPROTO_UDP)
                proto_name = "UDP";

            printf("%-10s %12llu %14llu\n",
                   proto_name,
                   (unsigned long long)metrics.rx_packets,
                   (unsigned long long)metrics.rx_bytes);
        }
        proto_key = proto_next;
    }

    /* Histograms */
    if (env.histogram) {
        __u64 tx_hist[64] = {}, rx_hist[64] = {};
        int tx_hist_fd = bpf_map__fd(skel->maps.tx_latency_hist);
        int rx_hist_fd = bpf_map__fd(skel->maps.rx_latency_hist);

        for (int i = 0; i < 64; i++) {
            bpf_map_lookup_elem(tx_hist_fd, &i, &tx_hist[i]);
            bpf_map_lookup_elem(rx_hist_fd, &i, &rx_hist[i]);
        }

        printf("\nTX Latency Histogram (us):\n");
        print_log2_hist(tx_hist, 64, "us");

        printf("\nRX Latency Histogram (us):\n");
        print_log2_hist(rx_hist, 64, "us");
    }

    printf("============================================================\n");
}

int main(int argc, char **argv)
{
    struct system_network_performance_metrics_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = system_network_performance_metrics_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (env.interface) {
        unsigned int ifindex = if_nametoindex(env.interface);
        if (ifindex == 0) {
            fprintf(stderr, "Invalid interface: %s\n", env.interface);
            err = 1;
            goto cleanup;
        }
        skel->rodata->target_ifindex = ifindex;
    }

    err = system_network_performance_metrics_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = system_network_performance_metrics_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Collecting network performance metrics... Ctrl-C to stop\n");
    printf("Output interval: %d seconds\n", env.interval);

    while (!exiting) {
        sleep(env.interval);
        print_metrics(skel);
    }

    print_metrics(skel);

cleanup:
    system_network_performance_metrics_bpf__destroy(skel);
    return err != 0;
}
