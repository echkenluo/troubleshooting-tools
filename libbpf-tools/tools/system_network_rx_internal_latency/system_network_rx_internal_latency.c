// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_rx_internal_latency - Detailed RX path latency measurement

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
#include "system_network_rx_internal_latency.h"
#include "system_network_rx_internal_latency.skel.h"
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
    bool verbose;
} env = {
    .interval = 5,
    .protocol = "all",
};

const char *argp_program_version = "system_network_rx_internal_latency 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Detailed RX path latency measurement from OVS to TCP/UDP layer.\n"
"\n"
"Measures latency distribution at 10 detailed stages in the RX path\n"
"to identify the source of tail latency (e.g., 8-16ms spikes).\n"
"\n"
"Key measurement points:\n"
"  S0: ovs_vport_send (OVS handoff)\n"
"  S1: internal_dev_recv (kernel entry)\n"
"  S2: netif_rx\n"
"  S3: netif_rx_internal (CPU selection)\n"
"  S4: enqueue_to_backlog (CRITICAL - queue insertion)\n"
"  S5: process_backlog (CRITICAL ASYNC BOUNDARY)\n"
"  S6: netif_receive_skb (core reception)\n"
"  S7: ip_rcv (IP layer)\n"
"  S8: ip_local_deliver (local delivery)\n"
"  S9: tcp_v4_rcv/udp_rcv (protocol)\n"
"\n"
"USAGE: system_network_rx_internal_latency [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    system_network_rx_internal_latency --interface eth0 --src-ip 10.0.0.1\n"
"    system_network_rx_internal_latency --protocol tcp --dst-port 5201\n";

static const struct argp_option opts[] = {
    { "interface", 'i', "DEV", 0, "Physical interface to monitor" },
    { "src-ip", 's', "IP", 0, "Filter by source IP" },
    { "dst-ip", 'd', "IP", 0, "Filter by destination IP" },
    { "src-port", 'S', "PORT", 0, "Filter by source port" },
    { "dst-port", 'D', "PORT", 0, "Filter by destination port" },
    { "protocol", 'p', "PROTO", 0, "Protocol: tcp, udp, all (default: all)" },
    { "interval", 'I', "SECS", 0, "Print interval (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i': env.interface = arg; break;
    case 's': env.src_ip = arg; break;
    case 'd': env.dst_ip = arg; break;
    case 'S': env.src_port = atoi(arg); break;
    case 'D': env.dst_port = atoi(arg); break;
    case 'p': env.protocol = arg; break;
    case 'I': env.interval = atoi(arg); break;
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

static __u8 protocol_to_num(const char *proto)
{
    if (!proto || strcmp(proto, "all") == 0) return 0;
    if (strcmp(proto, "tcp") == 0) return 6;
    if (strcmp(proto, "udp") == 0) return 17;
    return 0;
}

static void print_latency_dist(__u64 *vals, int slots, const char *unit)
{
    __u64 max_val = 0;
    int max_slot = -1;

    for (int i = 0; i < slots; i++) {
        if (vals[i] > 0) max_slot = i;
        if (vals[i] > max_val) max_val = vals[i];
    }

    if (max_slot < 0) {
        printf("  (no data)\n");
        return;
    }

    __u64 total = 0;
    for (int i = 0; i <= max_slot; i++) total += vals[i];

    for (int i = 0; i <= max_slot; i++) {
        if (vals[i] == 0) continue;
        __u64 low = (1ULL << i);
        __u64 high = (1ULL << (i + 1)) - 1;
        if (i == 0) low = 0;

        int stars = max_val > 0 ? (vals[i] * 40 / max_val) : 0;
        double pct = total > 0 ? 100.0 * vals[i] / total : 0;
        printf("  %8llu-%-8llu%s: %6llu (%5.1f%%) |", low, high, unit, vals[i], pct);
        for (int j = 0; j < stars; j++) printf("*");
        printf("\n");
    }
}

static void print_stats(struct system_network_rx_internal_latency_bpf *skel)
{
    char ts[32];
    time_t t = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));

    printf("\n");
    printf("================================================================================\n");
    printf("[%s] Detailed RX Internal Path Latency Report\n", ts);
    printf("================================================================================\n");

    /* Read counters */
    __u64 cnt_vals[CNT_MAX] = {};
    int counters_fd = bpf_map__fd(skel->maps.counters);
    for (__u32 i = 0; i < CNT_MAX; i++) {
        bpf_map_lookup_elem(counters_fd, &i, &cnt_vals[i]);
    }

    printf("RX Packets: %llu, Cross-CPU: %llu\n", cnt_vals[CNT_RX_PACKETS], cnt_vals[CNT_CROSS_CPU]);

    /* Read and display stage pair latencies */
    printf("\n--- Stage Transition Latencies ---\n");

    int stage_hist_fd = bpf_map__fd(skel->maps.stage_latency_hist);
    struct stage_pair_key key = {}, next_key;

    /* Collect data per stage pair */
    __u64 stage_data[MAX_STAGES][MAX_STAGES][MAX_SLOTS] = {};

    while (bpf_map_get_next_key(stage_hist_fd, &key, &next_key) == 0) {
        __u64 count;
        if (bpf_map_lookup_elem(stage_hist_fd, &next_key, &count) == 0) {
            if (next_key.prev_stage < MAX_STAGES && next_key.curr_stage < MAX_STAGES &&
                next_key.latency_bucket < MAX_SLOTS) {
                stage_data[next_key.prev_stage][next_key.curr_stage][next_key.latency_bucket] = count;
            }
        }
        key = next_key;
    }

    /* Print each stage pair */
    for (int prev = 0; prev < MAX_STAGES; prev++) {
        for (int curr = 0; curr < MAX_STAGES; curr++) {
            __u64 total = 0;
            for (int b = 0; b < MAX_SLOTS; b++) total += stage_data[prev][curr][b];
            if (total == 0) continue;

            printf("\n%s -> %s:\n", stage_names[prev], stage_names[curr]);
            printf("  Total samples: %llu\n", total);

            if (prev == RX_S5_4_ENQUEUE_TO_BACKLOG && curr >= RX_S5_5_PROCESS_BACKLOG) {
                printf("  ^^^ CRITICAL ASYNC BOUNDARY - Expected tail latency location ^^^\n");
            }

            print_latency_dist(stage_data[prev][curr], MAX_SLOTS, "us");
        }
    }

    /* Read total latency histogram */
    printf("\n--- Total End-to-End Latency (ovs_vport_send -> tcp/udp_rcv) ---\n");

    __u64 total_hist[MAX_SLOTS] = {};
    int total_fd = bpf_map__fd(skel->maps.total_latency_hist);
    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_lookup_elem(total_fd, &i, &total_hist[i]);
    }
    print_latency_dist(total_hist, MAX_SLOTS, "us");

    /* Read CPU migration histogram */
    printf("\n--- CPU Migration Analysis (enqueue -> process) ---\n");

    int cpu_hist_fd = bpf_map__fd(skel->maps.cpu_migration_hist);
    struct cpu_pair_key cpu_key = {}, cpu_next;

    /* Collect per CPU pair */
    typedef struct { __u64 same_cpu; __u64 cross_cpu; } cpu_stats;
    cpu_stats stats = {};

    while (bpf_map_get_next_key(cpu_hist_fd, &cpu_key, &cpu_next) == 0) {
        __u64 count;
        if (bpf_map_lookup_elem(cpu_hist_fd, &cpu_next, &count) == 0) {
            if (cpu_next.enqueue_cpu == cpu_next.process_cpu)
                stats.same_cpu += count;
            else
                stats.cross_cpu += count;
        }
        cpu_key = cpu_next;
    }

    printf("  Same-CPU: %llu, Cross-CPU: %llu\n", stats.same_cpu, stats.cross_cpu);
    if (stats.same_cpu + stats.cross_cpu > 0) {
        double cross_pct = 100.0 * stats.cross_cpu / (stats.same_cpu + stats.cross_cpu);
        printf("  Cross-CPU rate: %.1f%%\n", cross_pct);
    }
}

static void clear_maps(struct system_network_rx_internal_latency_bpf *skel)
{
    /* Clear stage latency histogram */
    int stage_fd = bpf_map__fd(skel->maps.stage_latency_hist);
    struct stage_pair_key key = {}, next;
    while (bpf_map_get_next_key(stage_fd, &key, &next) == 0) {
        bpf_map_delete_elem(stage_fd, &next);
        key = next;
    }

    /* Clear total latency histogram */
    int total_fd = bpf_map__fd(skel->maps.total_latency_hist);
    __u64 zero = 0;
    for (__u32 i = 0; i < MAX_SLOTS; i++) {
        bpf_map_update_elem(total_fd, &i, &zero, BPF_ANY);
    }

    /* Clear CPU migration histogram */
    int cpu_fd = bpf_map__fd(skel->maps.cpu_migration_hist);
    struct cpu_pair_key cpu_key = {}, cpu_next;
    while (bpf_map_get_next_key(cpu_fd, &cpu_key, &cpu_next) == 0) {
        bpf_map_delete_elem(cpu_fd, &cpu_next);
        cpu_key = cpu_next;
    }

    /* Clear counters */
    int cnt_fd = bpf_map__fd(skel->maps.counters);
    for (__u32 i = 0; i < CNT_MAX; i++) {
        bpf_map_update_elem(cnt_fd, &i, &zero, BPF_ANY);
    }
}

int main(int argc, char **argv)
{
    struct system_network_rx_internal_latency_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = system_network_rx_internal_latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set filters */
    skel->rodata->targ_src_ip = ip_to_u32(env.src_ip);
    skel->rodata->targ_dst_ip = ip_to_u32(env.dst_ip);
    skel->rodata->targ_src_port = env.src_port ? htons(env.src_port) : 0;
    skel->rodata->targ_dst_port = env.dst_port ? htons(env.dst_port) : 0;
    skel->rodata->targ_protocol = protocol_to_num(env.protocol);

    if (env.interface) {
        unsigned int ifindex = if_nametoindex(env.interface);
        if (ifindex == 0) {
            fprintf(stderr, "Invalid interface: %s\n", env.interface);
            err = 1;
            goto cleanup;
        }
        skel->rodata->targ_ifindex = ifindex;
    }

    err = system_network_rx_internal_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        fprintf(stderr, "Note: This tool requires OVS kernel module functions.\n");
        goto cleanup;
    }

    err = system_network_rx_internal_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("================================================================================\n");
    printf("System Network RX Internal Path Detailed Latency Measurement\n");
    printf("================================================================================\n");
    printf("Protocol filter: %s\n", env.protocol);
    if (env.src_ip) printf("Source IP filter: %s\n", env.src_ip);
    if (env.dst_ip) printf("Destination IP filter: %s\n", env.dst_ip);
    if (env.src_port) printf("Source port filter: %d\n", env.src_port);
    if (env.dst_port) printf("Destination port filter: %d\n", env.dst_port);
    if (env.interface) printf("Interface: %s\n", env.interface);
    printf("Interval: %d seconds\n", env.interval);
    printf("\nMeasuring 10 detailed stages in RX path:\n");
    for (int i = 0; i < MAX_STAGES; i++) {
        const char *marker = "";
        if (i == RX_S5_4_ENQUEUE_TO_BACKLOG) marker = " <- CRITICAL";
        if (i == RX_S5_5_PROCESS_BACKLOG) marker = " <- CRITICAL ASYNC BOUNDARY";
        printf("  S%d: %s%s\n", i, stage_names[i], marker);
    }
    printf("\nPress Ctrl-C to stop.\n");

    while (!exiting) {
        sleep(env.interval);
        if (exiting) break;
        print_stats(skel);
        clear_maps(skel);
    }

    /* Final stats */
    print_stats(skel);

cleanup:
    system_network_rx_internal_latency_bpf__destroy(skel);
    return err != 0;
}
