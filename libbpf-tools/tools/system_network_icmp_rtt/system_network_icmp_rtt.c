// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_icmp_rtt - ICMP RTT measurement userspace program

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
#include "system_network_icmp_rtt.h"
#include "system_network_icmp_rtt.skel.h"
#include "trace_helpers.h"
#include "histogram.h"

static volatile bool exiting = false;

static struct env {
    char *phy_interface;
    char *src_ip;
    char *dst_ip;
    float latency_ms;
    int interval;
} env = {
    .latency_ms = 0,
    .interval = 5,
};

const char *argp_program_version = "system_network_icmp_rtt 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Measure ICMP RTT through system network stack\n"
"\n"
"USAGE: system_network_icmp_rtt --src-ip IP --dst-ip IP --phy-interface DEV [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    system_network_icmp_rtt --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --phy-interface eth0\n";

static const struct argp_option opts[] = {
    { "phy-interface", 'i', "DEV", 0, "Physical interface" },
    { "src-ip", 's', "IP", 0, "Source IP (local)" },
    { "dst-ip", 'd', "IP", 0, "Destination IP (remote)" },
    { "latency-ms", 'l', "MS", 0, "Minimum latency threshold (ms)" },
    { "interval", 'I', "SEC", 0, "Histogram output interval" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.phy_interface = arg;
        break;
    case 's':
        env.src_ip = arg;
        break;
    case 'd':
        env.dst_ip = arg;
        break;
    case 'l':
        env.latency_ms = atof(arg);
        break;
    case 'I':
        env.interval = atoi(arg);
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

static __u32 ip_to_u32(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 1)
        return addr.s_addr;
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct rtt_event *event = data;
    struct icmp_key *key = &event->key;
    struct rtt_flow_data *flow = &event->data;
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    __u64 rtt_ns = flow->ts[13] - flow->ts[0];
    double rtt_us = rtt_ns / 1000.0;
    double rtt_ms = rtt_us / 1000.0;

    printf("%s ICMP RTT: id=%u seq=%u rtt=%.3f ms (%.1f us)\n",
           ts, ntohs(key->id), ntohs(key->seq), rtt_ms, rtt_us);

    /* Print segment latencies */
    if (flow->ts[0] > 0 && flow->ts[6] > 0) {
        double tx_us = (flow->ts[6] - flow->ts[0]) / 1000.0;
        printf("  TX path: %.1f us\n", tx_us);
    }
    if (flow->ts[7] > 0 && flow->ts[13] > 0) {
        double rx_us = (flow->ts[13] - flow->ts[7]) / 1000.0;
        printf("  RX path: %.1f us\n", rx_us);
    }
    if (flow->ts[6] > 0 && flow->ts[7] > 0) {
        double wire_us = (flow->ts[7] - flow->ts[6]) / 1000.0;
        printf("  Wire time: %.1f us\n", wire_us);
    }

    return 0;
}

static void print_histogram(struct system_network_icmp_rtt_bpf *skel)
{
    int hist_fd = bpf_map__fd(skel->maps.rtt_histogram);
    __u64 values[64] = {};

    for (int i = 0; i < 64; i++) {
        bpf_map_lookup_elem(hist_fd, &i, &values[i]);
    }

    printf("\nRTT Histogram (us):\n");
    print_log2_hist(values, 64, "us");
}

int main(int argc, char **argv)
{
    struct system_network_icmp_rtt_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!env.src_ip || !env.dst_ip || !env.phy_interface) {
        fprintf(stderr, "Error: --src-ip, --dst-ip, and --phy-interface are required\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = system_network_icmp_rtt_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    skel->rodata->filter_src_ip = ip_to_u32(env.src_ip);
    skel->rodata->filter_dst_ip = ip_to_u32(env.dst_ip);

    unsigned int ifindex = if_nametoindex(env.phy_interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", env.phy_interface);
        err = 1;
        goto cleanup;
    }
    skel->rodata->target_ifindex = ifindex;

    if (env.latency_ms > 0)
        skel->rodata->latency_threshold_ns = (__u64)(env.latency_ms * 1000000);

    err = system_network_icmp_rtt_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = system_network_icmp_rtt_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing ICMP RTT: %s -> %s on %s... Ctrl-C to stop\n",
           env.src_ip, env.dst_ip, env.phy_interface);

    time_t last_hist = time(NULL);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }

        time_t now = time(NULL);
        if (now - last_hist >= env.interval) {
            print_histogram(skel);
            last_hist = now;
        }
    }

    print_histogram(skel);

cleanup:
    ring_buffer__free(rb);
    system_network_icmp_rtt_bpf__destroy(skel);
    return err != 0;
}
