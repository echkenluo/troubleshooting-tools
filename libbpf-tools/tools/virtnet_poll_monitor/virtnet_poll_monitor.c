// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// virtnet_poll_monitor - Virtio-net RX monitor userspace program

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "virtnet_poll_monitor.h"
#include "virtnet_poll_monitor.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *device;
    int queue;
    bool verbose;
} env = {
    .device = NULL,
    .queue = -1,
    .verbose = false,
};

const char *argp_program_version = "virtnet_poll_monitor 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Monitor virtio-net RX functions (virtnet_poll and skb_recv_done)\n"
"\n"
"USAGE: virtnet_poll_monitor [--device DEV] [--queue N]\n"
"\n"
"EXAMPLES:\n"
"    virtnet_poll_monitor\n"
"    virtnet_poll_monitor --device eth0\n"
"    virtnet_poll_monitor --device eth0 --queue 0\n";

static const struct argp_option opts[] = {
    { "device", 'd', "DEV", 0, "Filter by device name (e.g., eth0)" },
    { "queue", 'q', "N", 0, "Filter by RX queue index" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct virtnet_poll_event *event = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    t = event->timestamp / 1000000000;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    if (event->event_type == EVENT_POLL_ENTRY) {
        printf("%s.%06lu [%u] virtnet_poll ENTRY: dev=%s queue=%u budget=%u vq_idx=%u napi=0x%llx\n",
               ts, (event->timestamp % 1000000000) / 1000,
               event->pid, event->dev_name, event->queue_index,
               event->budget, event->vq_index, (unsigned long long)event->napi_ptr);
    } else if (event->event_type == EVENT_POLL_EXIT) {
        double efficiency = event->budget > 0 ?
            (event->processed * 100.0 / event->budget) : 0;
        printf("%s.%06lu [%u] virtnet_poll EXIT:  dev=%s queue=%u processed=%u/%u (%.1f%%)\n",
               ts, (event->timestamp % 1000000000) / 1000,
               event->pid, event->dev_name, event->queue_index,
               event->processed, event->budget, efficiency);
    } else if (event->event_type == EVENT_SKB_RECV_DONE) {
        printf("%s.%06lu [%u] skb_recv_done:     dev=%s queue=%u vq_idx=%u vq=0x%llx\n",
               ts, (event->timestamp % 1000000000) / 1000,
               event->pid, event->dev_name, event->queue_index,
               event->vq_index, (unsigned long long)event->vq_ptr);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct virtnet_poll_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (env.verbose)
        printf("Loading BPF program...\n");

    skel = virtnet_poll_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (env.queue >= 0) {
        skel->rodata->targ_queue_index = env.queue;
        skel->rodata->targ_filter_queue = 1;
    }

    err = virtnet_poll_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Set device filter */
    if (env.device) {
        struct device_filter devfilter = {};
        strncpy(devfilter.name, env.device, sizeof(devfilter.name) - 1);
        __u32 key = 0;
        bpf_map_update_elem(bpf_map__fd(skel->maps.filter_device), &key, &devfilter, BPF_ANY);
        printf("Device filter: %s\n", env.device);
    } else {
        printf("Device filter: All devices\n");
    }

    if (env.queue >= 0) {
        __u32 key = 0;
        __u32 enabled = 1;
        bpf_map_update_elem(bpf_map__fd(skel->maps.filter_queue_enabled), &key, &enabled, BPF_ANY);
        printf("Queue filter: %d\n", env.queue);
    } else {
        printf("Queue filter: All queues\n");
    }

    err = virtnet_poll_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    if (env.verbose)
        printf("Probes attached successfully\n");

    printf("\nVirtio-net RX Monitor Started\n");
    printf("Monitoring virtnet_poll and skb_recv_done events\n");
    printf("Waiting for events... Press Ctrl+C to stop\n\n");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    printf("\nMonitoring stopped.\n");

cleanup:
    ring_buffer__free(rb);
    virtnet_poll_monitor_bpf__destroy(skel);
    return err != 0;
}
