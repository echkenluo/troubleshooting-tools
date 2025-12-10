// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_vhost_queue_stats_simple - Simple TUN to vhost-net queue statistics userspace

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
#include "tun_vhost_queue_stats_simple.h"
#include "tun_vhost_queue_stats_simple.skel.h"
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

const char *argp_program_version = "tun_vhost_queue_stats_simple 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Simple TUN to vhost-net queue statistics monitor.\n"
"\n"
"USAGE: tun_vhost_queue_stats_simple [OPTIONS] [COUNT]\n"
"\n"
"Tracks only tun_net_xmit and vhost_signal for minimal overhead.\n"
"\n"
"EXAMPLES:\n"
"    tun_vhost_queue_stats_simple                 # Monitor all queues\n"
"    tun_vhost_queue_stats_simple -d vnet33       # Monitor specific device\n"
"    tun_vhost_queue_stats_simple -d vnet33 -q 0  # Monitor specific queue\n";

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

static void print_stats(struct tun_vhost_queue_stats_simple_bpf *skel)
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

    /* Print current values */
    printf("\nVQ last_used_idx Values (current):\n");
    int idx_fd = bpf_map__fd(skel->maps.last_used_idx_values);
    int stats_fd = bpf_map__fd(skel->maps.queue_stats);
    int napi_fd = bpf_map__fd(skel->maps.napi_status_map);

    struct idx_value_key idx_key = {}, next_idx_key;
    __u16 idx_value;
    struct simple_stats stats;
    struct napi_status napi;
    bool has_data = false;

    while (bpf_map_get_next_key(idx_fd, &idx_key, &next_idx_key) == 0) {
        if (bpf_map_lookup_elem(idx_fd, &next_idx_key, &idx_value) == 0) {
            printf("  Queue: %s:q%u", next_idx_key.dev_name, next_idx_key.queue_index);
            printf(" | last_used_idx: %u", idx_value);

            if (bpf_map_lookup_elem(stats_fd, &next_idx_key, &stats) == 0) {
                printf(" | xmit: %llu, signal: %llu",
                       (unsigned long long)stats.xmit_count,
                       (unsigned long long)stats.signal_count);
            }

            if (bpf_map_lookup_elem(napi_fd, &next_idx_key, &napi) == 0) {
                printf(" | napi: %s, napi_frags: %s",
                       napi.napi_enabled ? "on" : "off",
                       napi.napi_frags_enabled ? "on" : "off");
            }
            printf("\n");
            has_data = true;
        }
        idx_key = next_idx_key;
    }

    if (!has_data)
        printf("    No data\n");

    /* Print histograms */
    print_histogram(bpf_map__fd(skel->maps.vq_last_used_idx_hist),
                    "VQ last_used_idx Distribution at vhost_signal",
                    "last_used_idx value ranges when VHOST signals guest");

    print_histogram(bpf_map__fd(skel->maps.ptr_ring_depth_xmit),
                    "PTR Ring Depth at tun_net_xmit",
                    "Ring buffer utilization when packets are transmitted");

    printf("================================================================================\n");
}

static void clear_maps(struct tun_vhost_queue_stats_simple_bpf *skel)
{
    struct hist_key hkey = {}, next_hkey;
    struct idx_value_key idx_key = {}, next_idx_key;
    int fd;

    fd = bpf_map__fd(skel->maps.vq_last_used_idx_hist);
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

    fd = bpf_map__fd(skel->maps.last_used_idx_values);
    while (bpf_map_get_next_key(fd, &idx_key, &next_idx_key) == 0) {
        bpf_map_delete_elem(fd, &next_idx_key);
        idx_key = next_idx_key;
    }

    fd = bpf_map__fd(skel->maps.queue_stats);
    idx_key = (struct idx_value_key){};
    while (bpf_map_get_next_key(fd, &idx_key, &next_idx_key) == 0) {
        bpf_map_delete_elem(fd, &next_idx_key);
        idx_key = next_idx_key;
    }

    fd = bpf_map__fd(skel->maps.napi_status_map);
    idx_key = (struct idx_value_key){};
    while (bpf_map_get_next_key(fd, &idx_key, &next_idx_key) == 0) {
        bpf_map_delete_elem(fd, &next_idx_key);
        idx_key = next_idx_key;
    }
}

int main(int argc, char **argv)
{
    struct tun_vhost_queue_stats_simple_bpf *skel;
    int err;
    int countdown;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    countdown = env.count;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tun_vhost_queue_stats_simple_bpf__open();
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

    err = tun_vhost_queue_stats_simple_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = tun_vhost_queue_stats_simple_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Simple TUN-VHOST Queue Statistics Monitor Started\n");
    printf("Tracking: tun_net_xmit and vhost_signal only\n");
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
    tun_vhost_queue_stats_simple_bpf__destroy(skel);
    return err != 0;
}
