// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// qdisc_drop_trace - Queueing discipline drop tracer userspace program

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
#include "qdisc_drop_trace.h"
#include "qdisc_drop_trace.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool verbose;
    bool trace;
    char *interface;
} env = {
    .interval = 5,
    .verbose = false,
    .trace = false,
};

const char *argp_program_version = "qdisc_drop_trace 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Trace queueing discipline (qdisc) packet drops\n"
"\n"
"USAGE: qdisc_drop_trace [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    qdisc_drop_trace                    # Summary mode\n"
"    qdisc_drop_trace -t                 # Trace individual events\n"
"    qdisc_drop_trace -i eth0            # Filter by interface\n"
"    qdisc_drop_trace -I 10              # 10s interval\n";

static const struct argp_option opts[] = {
    { "interval", 'I', "SEC", 0, "Output interval in seconds (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { "trace", 't', NULL, 0, "Trace individual drop events" },
    { "interface", 'i', "DEV", 0, "Filter by interface name" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'I':
        env.interval = atoi(arg);
        if (env.interval <= 0)
            env.interval = 5;
        break;
    case 'v':
        env.verbose = true;
        break;
    case 't':
        env.trace = true;
        break;
    case 'i':
        env.interface = arg;
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

static const char *proto_str(__u8 protocol)
{
    switch (protocol) {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    case IPPROTO_ICMP:
        return "ICMP";
    default:
        return "OTHER";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct qdisc_drop_event *event = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &event->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &event->dst_ip, dst_ip, sizeof(dst_ip));

    printf("%s %-16s qdisc:0x%08x len:%-5u %s %s:%u -> %s:%u\n",
           ts,
           event->ifname[0] ? event->ifname : "unknown",
           event->qdisc_handle,
           event->skb_len,
           proto_str(event->protocol),
           src_ip, ntohs(event->src_port),
           dst_ip, ntohs(event->dst_port));

    if (env.verbose) {
        printf("  pid=%u comm=%s\n", event->pid, event->comm);
    }

    return 0;
}

static void print_stats(struct qdisc_drop_trace_bpf *skel)
{
    int stats_fd = bpf_map__fd(skel->maps.qdisc_stats_map);
    struct qdisc_stats_key key = {}, next_key;
    struct qdisc_stats stats;
    time_t now;
    struct tm *tm;
    char ts[32];
    char ifname[IFNAMSIZ];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s - Qdisc Drop Statistics\n", ts);
    printf("%-16s %-12s %12s %14s\n", "INTERFACE", "QDISC_HANDLE", "DROPS", "BYTES");
    printf("------------------------------------------------------\n");

    __u64 total_drops = 0;
    __u64 total_bytes = 0;

    while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(stats_fd, &next_key, &stats) == 0) {
            if_indextoname(next_key.ifindex, ifname);
            printf("%-16s 0x%08x   %12llu %14llu\n",
                   ifname[0] ? ifname : "unknown",
                   next_key.qdisc_handle,
                   (unsigned long long)stats.drops,
                   (unsigned long long)stats.bytes);
            total_drops += stats.drops;
            total_bytes += stats.bytes;
        }
        key = next_key;
    }

    printf("------------------------------------------------------\n");
    printf("%-16s %-12s %12llu %14llu\n", "TOTAL", "",
           (unsigned long long)total_drops, (unsigned long long)total_bytes);
}

int main(int argc, char **argv)
{
    struct qdisc_drop_trace_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = qdisc_drop_trace_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set interface filter */
    if (env.interface) {
        unsigned int ifindex = if_nametoindex(env.interface);
        if (ifindex == 0) {
            fprintf(stderr, "Invalid interface: %s\n", env.interface);
            err = 1;
            goto cleanup;
        }
        skel->rodata->filter_ifindex = ifindex;
    }

    skel->rodata->trace_events = env.trace;

    err = qdisc_drop_trace_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = qdisc_drop_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Tracing qdisc drops... Ctrl-C to stop\n");

    if (env.trace) {
        /* Setup ring buffer for events */
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            err = 1;
            goto cleanup;
        }

        printf("%-8s %-16s %-12s %-8s %-5s %-21s -> %-21s\n",
               "TIME", "INTERFACE", "QDISC", "LEN", "PROTO", "SRC", "DST");

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
    } else {
        /* Summary mode */
        printf("Output interval: %d seconds\n", env.interval);

        while (!exiting) {
            sleep(env.interval);
            print_stats(skel);
        }

        printf("\nFinal statistics:\n");
        print_stats(skel);
    }

cleanup:
    ring_buffer__free(rb);
    qdisc_drop_trace_bpf__destroy(skel);
    return err != 0;
}
