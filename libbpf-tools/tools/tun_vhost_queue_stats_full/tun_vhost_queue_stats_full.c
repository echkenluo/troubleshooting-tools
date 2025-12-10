// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_vhost_queue_stats_full - Full TUN to vhost-net queue statistics userspace

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
#include "tun_vhost_queue_stats_full.h"
#include "tun_vhost_queue_stats_full.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *device;
    int queue;
    int interval;
    int count;
    bool timestamp;
} env = {
    .queue = -1,
    .interval = 1,
    .count = 99999999,
};

const char *argp_program_version = "tun_vhost_queue_stats_full 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Full TUN to vhost-net queue statistics monitor.\n"
"\n"
"USAGE: tun_vhost_queue_stats_full [OPTIONS] [COUNT]\n"
"\n"
"EXAMPLES:\n"
"    tun_vhost_queue_stats_full                    # Monitor all queues\n"
"    tun_vhost_queue_stats_full -d vnet33          # Monitor specific device\n"
"    tun_vhost_queue_stats_full -d vnet33 -q 0     # Monitor specific queue\n"
"    tun_vhost_queue_stats_full -i 5 10            # 5s interval, 10 outputs\n";

static const struct argp_option opts[] = {
    { "device", 'd', "DEV", 0, "Target device name (e.g., vnet33)" },
    { "queue", 'q', "QUEUE", 0, "Filter by queue index" },
    { "interval", 'i', "SEC", 0, "Output interval (default: 1)" },
    { "timestamp", 'T', NULL, 0, "Include timestamp on output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'd':
        env.device = arg;
        break;
    case 'q':
        env.queue = atoi(arg);
        break;
    case 'i':
        env.interval = atoi(arg);
        break;
    case 'T':
        env.timestamp = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        env.count = atoi(arg);
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

static void print_histogram(int fd, const char *title, const char *desc)
{
    struct hist_key key = {}, next_key;
    __u64 value;
    int count = 0;

    printf("\n%s:\n", title);
    printf("%s\n", desc);

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0 && value > 0) {
            if (count == 0) {
                printf("  Queue: %s:q%u\n", next_key.dev_name, next_key.queue_index);
            }

            __u64 slot = next_key.slot;
            __u64 low = slot == 0 ? 0 : (1ULL << slot);
            __u64 high = slot == 0 ? 1 : ((1ULL << (slot + 1)) - 1);

            printf("    %8llu-%-8llu : %8llu\n",
                   (unsigned long long)low,
                   (unsigned long long)high,
                   (unsigned long long)value);
            count++;
        }
        key = next_key;
    }

    if (count == 0)
        printf("    No data\n");
}

static void print_stats(struct tun_vhost_queue_stats_full_bpf *skel)
{
    time_t now;
    struct tm *tm;
    char ts[32];

    if (env.timestamp) {
        now = time(NULL);
        tm = localtime(&now);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
        printf("\nTime: %s\n", ts);
    }

    printf("\n");
    printf("================================================================================\n");

    /* Print histograms */
    print_histogram(bpf_map__fd(skel->maps.vq_consumption_handle_rx),
                    "VQ Consumption Progress at handle_rx (avail_idx - last_avail_idx)",
                    "Descriptors available for consumption when VHOST handles RX");

    print_histogram(bpf_map__fd(skel->maps.vq_delay_handle_rx),
                    "VQ Processing Delay at handle_rx (last_avail_idx - last_used_idx)",
                    "Descriptors in-flight when VHOST handles RX");

    print_histogram(bpf_map__fd(skel->maps.vq_consumption_signal),
                    "VQ Consumption Progress at vhost_signal",
                    "Descriptors available when VHOST signals guest");

    print_histogram(bpf_map__fd(skel->maps.vq_delay_signal),
                    "VQ Processing Delay at vhost_signal",
                    "Descriptors in-flight when VHOST signals guest");

    print_histogram(bpf_map__fd(skel->maps.ptr_ring_depth_xmit),
                    "PTR Ring Depth at tun_net_xmit",
                    "Ring buffer utilization when packets are transmitted");

    print_histogram(bpf_map__fd(skel->maps.ptr_ring_depth_recv),
                    "PTR Ring Depth at tun_recvmsg",
                    "Ring buffer utilization when packets are received");

    /* Print queue statistics summary */
    printf("\nQueue Statistics Summary:\n");
    int stats_fd = bpf_map__fd(skel->maps.queue_statistics);
    struct queue_key qkey = {}, next_qkey;
    struct queue_stats stats;
    bool has_stats = false;

    while (bpf_map_get_next_key(stats_fd, &qkey, &next_qkey) == 0) {
        if (bpf_map_lookup_elem(stats_fd, &next_qkey, &stats) == 0) {
            printf("  Queue: %s:q%u\n", next_qkey.dev_name, next_qkey.queue_index);
            printf("    xmit: %llu, handle_rx: %llu, recvmsg: %llu, signal: %llu\n",
                   (unsigned long long)stats.xmit_count,
                   (unsigned long long)stats.handle_rx_count,
                   (unsigned long long)stats.recvmsg_count,
                   (unsigned long long)stats.signal_count);
            if (stats.xmit_count > 0) {
                printf("    avg_ring_depth: %.1f, max_ring_depth: %u\n",
                       (double)stats.ring_depth_sum / stats.xmit_count,
                       stats.ring_depth_max);
            }
            has_stats = true;
        }
        qkey = next_qkey;
    }

    if (!has_stats)
        printf("    No data\n");

    printf("================================================================================\n");
}

static void clear_maps(struct tun_vhost_queue_stats_full_bpf *skel)
{
    struct hist_key hkey = {}, next_hkey;
    struct queue_key qkey = {}, next_qkey;
    int fd;

    /* Clear histogram maps */
    fd = bpf_map__fd(skel->maps.vq_consumption_handle_rx);
    while (bpf_map_get_next_key(fd, &hkey, &next_hkey) == 0) {
        bpf_map_delete_elem(fd, &next_hkey);
        hkey = next_hkey;
    }

    fd = bpf_map__fd(skel->maps.vq_delay_handle_rx);
    hkey = (struct hist_key){};
    while (bpf_map_get_next_key(fd, &hkey, &next_hkey) == 0) {
        bpf_map_delete_elem(fd, &next_hkey);
        hkey = next_hkey;
    }

    fd = bpf_map__fd(skel->maps.vq_consumption_signal);
    hkey = (struct hist_key){};
    while (bpf_map_get_next_key(fd, &hkey, &next_hkey) == 0) {
        bpf_map_delete_elem(fd, &next_hkey);
        hkey = next_hkey;
    }

    fd = bpf_map__fd(skel->maps.vq_delay_signal);
    hkey = (struct hist_key){};
    while (bpf_map_get_next_key(fd, &hkey, &next_hkey) == 0) {
        bpf_map_delete_elem(fd, &next_hkey);
        hkey = next_hkey;
    }

    fd = bpf_map__fd(skel->maps.ptr_ring_depth_xmit);
    hkey = (struct hist_key){};
    while (bpf_map_get_next_key(fd, &hkey, &next_hkey) == 0) {
        bpf_map_delete_elem(fd, &next_hkey);
        hkey = next_hkey;
    }

    fd = bpf_map__fd(skel->maps.ptr_ring_depth_recv);
    hkey = (struct hist_key){};
    while (bpf_map_get_next_key(fd, &hkey, &next_hkey) == 0) {
        bpf_map_delete_elem(fd, &next_hkey);
        hkey = next_hkey;
    }

    fd = bpf_map__fd(skel->maps.queue_statistics);
    while (bpf_map_get_next_key(fd, &qkey, &next_qkey) == 0) {
        bpf_map_delete_elem(fd, &next_qkey);
        qkey = next_qkey;
    }
}

int main(int argc, char **argv)
{
    struct tun_vhost_queue_stats_full_bpf *skel;
    int err;
    int countdown;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    countdown = env.count;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tun_vhost_queue_stats_full_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure BPF program */
    if (env.device) {
        unsigned int ifindex = if_nametoindex(env.device);
        if (ifindex == 0) {
            fprintf(stderr, "Invalid device: %s\n", env.device);
            err = 1;
            goto cleanup;
        }
        skel->rodata->targ_ifindex = ifindex;
        printf("Device filter: %s\n", env.device);
    } else {
        printf("Device filter: All TUN devices\n");
    }

    if (env.queue >= 0) {
        skel->rodata->targ_queue = env.queue;
        skel->rodata->filter_queue_enabled = 1;
        printf("Queue filter: %d\n", env.queue);
    } else {
        printf("Queue filter: All queues\n");
    }

    err = tun_vhost_queue_stats_full_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = tun_vhost_queue_stats_full_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Full TUN-VHOST Queue Statistics Monitor Started\n");
    printf("Tracking: tun_net_xmit, handle_rx, tun_recvmsg, vhost_signal\n");
    printf("Interval: %ds | Outputs: %s\n", env.interval,
           env.count == 99999999 ? "unlimited" : "limited");
    printf("Collecting statistics... Press Ctrl+C to stop\n");

    while (!exiting && countdown > 0) {
        sleep(env.interval);
        print_stats(skel);
        clear_maps(skel);
        countdown--;
    }

    printf("\nMonitoring stopped.\n");

cleanup:
    tun_vhost_queue_stats_full_bpf__destroy(skel);
    return err != 0;
}
