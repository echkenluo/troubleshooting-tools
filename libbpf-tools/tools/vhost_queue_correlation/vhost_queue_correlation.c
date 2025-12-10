// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_queue_correlation - VHOST queue correlation userspace program

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "vhost_queue_correlation.h"
#include "vhost_queue_correlation.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

/* Command line arguments */
static struct env {
    char *device;
    int queue;
    bool verbose;
} env = {
    .device = NULL,
    .queue = -1,
    .verbose = false,
};

const char *argp_program_version = "vhost_queue_correlation 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Simple VHOST Queue Monitor (vhost_signal & vhost_notify)\n"
"\n"
"Monitors vhost_signal and vhost_notify events for TUN/TAP devices.\n"
"\n"
"USAGE: vhost_queue_correlation [--device DEV] [--queue N]\n"
"\n"
"EXAMPLES:\n"
"    vhost_queue_correlation\n"
"    vhost_queue_correlation --device vnet33 --queue 0\n"
"    vhost_queue_correlation --device vnet33 --verbose\n";

static const struct argp_option opts[] = {
    { "device", 'd', "DEV", 0, "Target device name (e.g., vnet33)" },
    { "queue", 'q', "N", 0, "Filter by queue index" },
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
    case ARGP_KEY_ARG:
        argp_usage(state);
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
    struct queue_event *event = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    t = event->timestamp / 1000000000;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("================================================================================\n");
    printf("Event: %s | Time: %s.%06lu | Timestamp: %lluns\n",
           event->event_type == EVENT_VHOST_SIGNAL ? "vhost_signal" : "vhost_notify",
           ts, (event->timestamp % 1000000000) / 1000,
           (unsigned long long)event->timestamp);
    printf("Queue: %u | Device: %s | Process: %s (PID: %u)\n",
           event->queue_index, event->dev_name,
           event->comm, event->pid);
    printf("Sock: 0x%llx\n", (unsigned long long)event->sock_ptr);

    if (event->event_type == EVENT_VHOST_SIGNAL) {
        printf("VQ: 0x%llx\n", (unsigned long long)event->vq_ptr);
        printf("VQ State: avail_idx=%u, last_avail=%u, last_used=%u, used_flags=0x%x\n",
               event->avail_idx, event->last_avail_idx,
               event->last_used_idx, event->used_flags);
        printf("Signal: signalled_used=%u, valid=%s, log_used=%s\n",
               event->signalled_used,
               event->signalled_used_valid ? "YES" : "NO",
               event->log_used ? "YES" : "NO");
        printf("Features: acked=0x%llx, backend=0x%llx\n",
               (unsigned long long)event->acked_features,
               (unsigned long long)event->acked_backend_features);
        if (event->log_used && event->log_addr)
            printf("Log: addr=0x%llx\n", (unsigned long long)event->log_addr);
    } else if (event->event_type == EVENT_VHOST_NOTIFY) {
        printf("VQ: 0x%llx | Return: %d (notify=%s)\n",
               (unsigned long long)event->vq_ptr, event->ret_val,
               event->ret_val ? "YES" : "NO");
        printf("VQ State: avail_idx=%u, last_avail=%u, last_used=%u, used_flags=0x%x\n",
               event->avail_idx, event->last_avail_idx,
               event->last_used_idx, event->used_flags);
        printf("Features: acked=0x%llx, backend=0x%llx, EVENT_IDX=%s\n",
               (unsigned long long)event->acked_features,
               (unsigned long long)event->acked_backend_features,
               event->has_event_idx_feature ? "ENABLED" : "DISABLED");
        if (event->guest_flags_valid) {
            bool no_interrupt = (event->avail_flags & 0x1) != 0;
            printf("Guest avail_flags: 0x%x (NO_INTERRUPT=%s)\n",
                   event->avail_flags, no_interrupt ? "YES" : "NO");
        } else {
            printf("Guest avail_flags: <failed to read>\n");
        }
        if (event->has_event_idx_feature) {
            if (event->guest_event_valid)
                printf("Guest used_event_idx: %u (host last_used=%u)\n",
                       event->used_event_idx, event->last_used_idx);
            else
                printf("Guest used_event_idx: <failed to read>\n");
        }
    }

    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    struct vhost_queue_correlation_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Setup signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    if (env.verbose)
        printf("Loading BPF program...\n");

    skel = vhost_queue_correlation_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    if (env.queue >= 0) {
        skel->rodata->targ_queue_index = env.queue;
        skel->rodata->targ_filter_queue = 1;
    }

    /* Load & verify BPF programs */
    err = vhost_queue_correlation_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Set device filter */
    if (env.device) {
        union name_buf devname = {};
        strncpy(devname.name, env.device, sizeof(devname.name) - 1);
        __u32 key = 0;
        bpf_map_update_elem(bpf_map__fd(skel->maps.name_map), &key, &devname, BPF_ANY);
        printf("Device filter: %s\n", env.device);
    } else {
        printf("Device filter: All TUN devices\n");
    }

    if (env.queue >= 0)
        printf("Queue filter: %d\n", env.queue);
    else
        printf("Queue filter: All queues\n");

    /* Attach probes */
    err = vhost_queue_correlation_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    if (env.verbose)
        printf("All probes attached successfully\n");

    printf("Simple VHOST Queue Monitor Started\n");
    printf("Monitoring: vhost_signal & vhost_notify events\n");
    printf("Waiting for events... Press Ctrl+C to stop\n\n");

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Main loop */
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
    vhost_queue_correlation_bpf__destroy(skel);
    return err != 0;
}
