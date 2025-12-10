// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// iface_netstat - Per-queue packet size distribution monitor

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <dirent.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iface_netstat.h"
#include "iface_netstat.skel.h"
#include "trace_helpers.h"

#define ROOT_PATH "/sys/class/net"

static volatile bool exiting = false;

static struct env {
    char *device;
    float interval;
    bool throughput;
    bool verbose;
} env = {
    .interval = 1.0,
    .throughput = false,
    .verbose = false,
};

const char *argp_program_version = "iface_netstat 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Monitor per-queue packet size distribution for a network interface.\n"
"\n"
"USAGE: iface_netstat -n <device> [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    iface_netstat -n eth0                # Monitor eth0 with default 1s interval\n"
"    iface_netstat -n eth0 -i 2           # Monitor with 2s interval\n"
"    iface_netstat -n eth0 -t             # Include throughput (BPS/PPS)\n";

static const struct argp_option opts[] = {
    { "name", 'n', "DEV", 0, "Target device name (required)" },
    { "interval", 'i', "SEC", 0, "Sampling interval in seconds (default: 1)" },
    { "throughput", 't', NULL, 0, "Show throughput (BPS/PPS)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'n':
        env.device = arg;
        break;
    case 'i':
        env.interval = atof(arg);
        break;
    case 't':
        env.throughput = true;
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

static void format_num(double num, char *buf, size_t buflen)
{
    if (num > 1000000) {
        snprintf(buf, buflen, "%.2fM", num / (1024.0 * 1024.0));
    } else if (num > 1000) {
        snprintf(buf, buflen, "%.2fK", num / 1024.0);
    } else {
        snprintf(buf, buflen, "%.2f", num);
    }
}

static int get_queue_count(const char *device, const char *type)
{
    char path[256];
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    snprintf(path, sizeof(path), "%s/%s/queues", ROOT_PATH, device);
    dir = opendir(path);
    if (!dir)
        return 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == type[0])
            count++;
    }
    closedir(dir);
    return count;
}

static void print_table(int map_fd, int queue_count, float interval, const char *direction)
{
    char buf[32];
    __u16 key, next_key;
    struct queue_data data;
    struct queue_data queue_stats[MAX_QUEUE_NUM] = {0};
    __u64 total_len = 0, total_pkt = 0;
    __u32 total_groups[5] = {0};

    /* Collect all queue data */
    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &data) == 0) {
            if (next_key < MAX_QUEUE_NUM)
                queue_stats[next_key] = data;
        }
        key = next_key;
    }

    /* Calculate totals */
    for (int i = 0; i < queue_count && i < MAX_QUEUE_NUM; i++) {
        total_len += queue_stats[i].total_pkt_len;
        total_pkt += queue_stats[i].num_pkt;
        total_groups[0] += queue_stats[i].size_64B;
        total_groups[1] += queue_stats[i].size_512B;
        total_groups[2] += queue_stats[i].size_2K;
        total_groups[3] += queue_stats[i].size_16K;
        total_groups[4] += queue_stats[i].size_64K;
    }

    /* Print header */
    printf("%s\n", direction);
    printf(" %-11s%-11s%-11s%-11s%-11s%-11s%-11s",
           "QueueID", "avg_size", "[0,64)", "[64,512)", "[512,2K)", "[2K,16K)", "[16K,64K)");
    if (env.throughput)
        printf("%-11s%-11s", "BPS", "PPS");
    printf("\n");

    /* Print per-queue stats */
    for (int i = 0; i < queue_count && i < MAX_QUEUE_NUM; i++) {
        struct queue_data *q = &queue_stats[i];
        double avg = (q->num_pkt > 0) ? (double)q->total_pkt_len / q->num_pkt : 0;

        format_num(avg, buf, sizeof(buf));
        printf(" %-11d%-11s", i, buf);

        format_num(q->size_64B, buf, sizeof(buf));
        printf("%-11s", buf);
        format_num(q->size_512B, buf, sizeof(buf));
        printf("%-11s", buf);
        format_num(q->size_2K, buf, sizeof(buf));
        printf("%-11s", buf);
        format_num(q->size_16K, buf, sizeof(buf));
        printf("%-11s", buf);
        format_num(q->size_64K, buf, sizeof(buf));
        printf("%-11s", buf);

        if (env.throughput) {
            double bps = q->total_pkt_len / interval;
            double pps = q->num_pkt / interval;
            format_num(bps, buf, sizeof(buf));
            printf("%-11s", buf);
            format_num(pps, buf, sizeof(buf));
            printf("%-11s", buf);
        }
        printf("\n");
    }

    /* Print totals */
    double total_avg = (total_pkt > 0) ? (double)total_len / total_pkt : 0;
    format_num(total_avg, buf, sizeof(buf));
    printf(" %-11s%-11s", "Total", buf);

    for (int i = 0; i < 5; i++) {
        format_num(total_groups[i], buf, sizeof(buf));
        printf("%-11s", buf);
    }

    if (env.throughput) {
        double total_bps = total_len / interval;
        double total_pps = total_pkt / interval;
        format_num(total_bps, buf, sizeof(buf));
        printf("%-11s", buf);
        format_num(total_pps, buf, sizeof(buf));
        printf("%-11s", buf);
    }
    printf("\n");

    /* Clear map for next interval */
    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(map_fd, &next_key);
        key = next_key;
    }
}

int main(int argc, char **argv)
{
    struct iface_netstat_bpf *skel;
    int tx_num, rx_num;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!env.device) {
        fprintf(stderr, "Please specify a network interface with -n\n");
        return 1;
    }

    if (env.interval <= 0) {
        fprintf(stderr, "Interval must be positive\n");
        return 1;
    }

    /* Get queue counts */
    tx_num = get_queue_count(env.device, "tx");
    rx_num = get_queue_count(env.device, "rx");

    if (tx_num == 0 && rx_num == 0) {
        fprintf(stderr, "Interface %s does not exist or has no queues\n", env.device);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = iface_netstat_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure device filter */
    unsigned int ifindex = if_nametoindex(env.device);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid device: %s\n", env.device);
        err = 1;
        goto cleanup;
    }
    skel->rodata->targ_ifindex = ifindex;

    err = iface_netstat_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = iface_netstat_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Monitoring %s (TX queues: %d, RX queues: %d)\n", env.device, tx_num, rx_num);
    printf("Interval: %.1f seconds\n", env.interval);
    if (env.throughput)
        printf("Throughput mode: ENABLED\n");
    printf("Press Ctrl+C to stop\n\n");

    int tx_fd = bpf_map__fd(skel->maps.tx_q);
    int rx_fd = bpf_map__fd(skel->maps.rx_q);

    while (!exiting) {
        usleep((__useconds_t)(env.interval * 1000000));
        if (exiting)
            break;

        time_t now = time(NULL);
        printf("%s", ctime(&now));

        print_table(tx_fd, tx_num, env.interval, "TX");
        printf("\n");
        print_table(rx_fd, rx_num, env.interval, "RX");

        if (env.throughput)
            printf("-------------------------------------------------------------------------------\n\n");
        else
            printf("-----------------------------------------------------------------------------\n\n");
    }

cleanup:
    iface_netstat_bpf__destroy(skel);
    return err != 0;
}
