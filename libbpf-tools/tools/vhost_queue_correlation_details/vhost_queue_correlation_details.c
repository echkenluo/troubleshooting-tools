// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vhost_queue_correlation_details - VHOST-NET queue correlation userspace

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
#include "vhost_queue_correlation_details.h"
#include "vhost_queue_correlation_details.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *device;
    int queue;
    bool verbose;
} env = {
    .queue = -1,
};

const char *argp_program_version = "vhost_queue_correlation_details 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"VHOST-NET queue correlation monitor.\n"
"\n"
"Traces events across TUN -> vhost-net path using socket correlation.\n"
"\n"
"USAGE: vhost_queue_correlation_details [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    vhost_queue_correlation_details              # Monitor all queues\n"
"    vhost_queue_correlation_details -d vnet33    # Monitor specific device\n"
"    vhost_queue_correlation_details -d vnet33 -q 0  # Monitor specific queue\n";

static const struct argp_option opts[] = {
    { "device", 'd', "DEV", 0, "Target device name (e.g., vnet33)" },
    { "queue", 'q', "QUEUE", 0, "Filter by queue index" },
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

static const char *event_name(__u8 type)
{
    switch (type) {
    case EVENT_TUN_XMIT:
        return "tun_net_xmit";
    case EVENT_HANDLE_RX:
        return "handle_rx";
    case EVENT_TUN_RECVMSG:
        return "tun_recvmsg";
    case EVENT_VHOST_SIGNAL:
        return "vhost_signal";
    case EVENT_VHOST_NOTIFY:
        return "vhost_notify";
    default:
        return "unknown";
    }
}

static const char *protocol_str(__u8 proto)
{
    switch (proto) {
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 1:
        return "ICMP";
    default:
        return "OTHER";
    }
}

static void print_ip(__be32 addr, char *buf, size_t buflen)
{
    struct in_addr in = { .s_addr = addr };
    if (addr == 0)
        snprintf(buf, buflen, "N/A");
    else
        inet_ntop(AF_INET, &in, buf, buflen);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct queue_event *e = data;
    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    struct tm *tm;
    char ts[32];
    time_t t;

    t = e->timestamp / 1000000000ULL;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    __u64 ns_part = (e->timestamp % 1000000000ULL) / 1000000ULL;

    printf("================================================================================\n");
    printf("Event: %s | Time: %s.%03llu\n", event_name(e->event_type), ts, (unsigned long long)ns_part);
    printf("Queue: %u | Device: %s | Process: %s (PID: %u)\n",
           e->queue_index, e->dev_name, e->comm, e->pid);
    printf("Sock: 0x%llx\n", (unsigned long long)e->sock_ptr);

    switch (e->event_type) {
    case EVENT_TUN_XMIT:
        printf("SKB: 0x%llx | TFile: 0x%llx\n",
               (unsigned long long)e->skb_ptr, (unsigned long long)e->tfile_ptr);
        if (e->saddr != 0) {
            print_ip(e->saddr, saddr_str, sizeof(saddr_str));
            print_ip(e->daddr, daddr_str, sizeof(daddr_str));
            printf("Flow: %s:%u -> %s:%u (%s)\n",
                   saddr_str, ntohs(e->sport),
                   daddr_str, ntohs(e->dport),
                   protocol_str(e->protocol));
        }
        break;

    case EVENT_HANDLE_RX:
        printf("VQ: 0x%llx | NVQ: 0x%llx\n",
               (unsigned long long)e->vq_ptr, (unsigned long long)e->nvq_ptr);
        printf("Busyloop: RX=%d, TX=%d\n", e->rx_busyloop_timeout, e->tx_busyloop_timeout);
        printf("VQ State: avail_idx=%u, last_avail=%u, last_used=%u, used_flags=0x%x\n",
               e->avail_idx, e->last_avail_idx, e->last_used_idx, e->used_flags);
        printf("Signal: signalled_used=%u, valid=%s\n",
               e->signalled_used, e->signalled_used_valid ? "YES" : "NO");
        printf("Features: acked=0x%llx\n", (unsigned long long)e->acked_features);
        break;

    case EVENT_TUN_RECVMSG:
        printf("TFile: 0x%llx\n", (unsigned long long)e->tfile_ptr);
        break;

    case EVENT_VHOST_SIGNAL:
        printf("VQ: 0x%llx\n", (unsigned long long)e->vq_ptr);
        printf("VQ State: avail_idx=%u, last_avail=%u, last_used=%u, used_flags=0x%x\n",
               e->avail_idx, e->last_avail_idx, e->last_used_idx, e->used_flags);
        printf("Signal: signalled_used=%u, valid=%s, log_used=%s\n",
               e->signalled_used, e->signalled_used_valid ? "YES" : "NO",
               e->log_used ? "YES" : "NO");
        break;

    case EVENT_VHOST_NOTIFY:
        printf("VQ: 0x%llx | Return: %d (notify=%s)\n",
               (unsigned long long)e->vq_ptr, e->ret_val,
               e->ret_val ? "YES" : "NO");
        printf("VQ State: avail_idx=%u, last_avail=%u, last_used=%u\n",
               e->avail_idx, e->last_avail_idx, e->last_used_idx);
        printf("Features: EVENT_IDX=%s\n",
               e->has_event_idx_feature ? "ENABLED" : "DISABLED");
        if (e->guest_flags_valid) {
            printf("Guest avail_flags: 0x%x (NO_INTERRUPT=%s)\n",
                   e->avail_flags, (e->avail_flags & 0x1) ? "YES" : "NO");
        }
        break;
    }

    /* Show ptr_ring state if available */
    if (e->ptr_ring_size > 0) {
        __u32 used;
        if (e->producer >= e->consumer_tail)
            used = e->producer - e->consumer_tail;
        else
            used = e->ptr_ring_size - e->consumer_tail + e->producer;
        __u32 utilization = (used * 100) / e->ptr_ring_size;

        printf("PTR Ring: size=%u, producer=%u, consumer_t=%u, full=%s, util=%u%%\n",
               e->ptr_ring_size, e->producer, e->consumer_tail,
               e->ring_full ? "YES" : "NO", utilization);
    }

    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    struct vhost_queue_correlation_details_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vhost_queue_correlation_details_bpf__open();
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

    err = vhost_queue_correlation_details_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = vhost_queue_correlation_details_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("VHOST-NET Queue Correlation Monitor Started\n");
    printf("Using socket pointer to correlate events across stages\n");
    printf("Waiting for events... Press Ctrl+C to stop\n\n");

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
    vhost_queue_correlation_details_bpf__destroy(skel);
    return err != 0;
}
