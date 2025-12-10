// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// trace_conntrack - Connection tracking event tracer userspace program

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_conntrack.h"
#include "trace_conntrack.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool verbose;
    bool trace_update;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    int protocol;
} env = {
    .interval = 5,
    .verbose = false,
    .trace_update = false,
};

const char *argp_program_version = "trace_conntrack 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Trace netfilter connection tracking events\n"
"\n"
"USAGE: trace_conntrack [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    trace_conntrack                         # Trace new and destroy events\n"
"    trace_conntrack -u                      # Also trace update events\n"
"    trace_conntrack --src-ip 10.0.0.1       # Filter by source IP\n"
"    trace_conntrack -p tcp                  # Filter by protocol\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Statistics output interval (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { "update", 'u', NULL, 0, "Also trace update events" },
    { "src-ip", 's', "IP", 0, "Filter by source IP" },
    { "dst-ip", 'd', "IP", 0, "Filter by destination IP" },
    { "src-port", 'S', "PORT", 0, "Filter by source port" },
    { "dst-port", 'D', "PORT", 0, "Filter by destination port" },
    { "protocol", 'p', "PROTO", 0, "Filter by protocol (tcp/udp/icmp)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interval = atoi(arg);
        if (env.interval <= 0)
            env.interval = 5;
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'u':
        env.trace_update = true;
        break;
    case 's':
        env.src_ip = arg;
        break;
    case 'd':
        env.dst_ip = arg;
        break;
    case 'S':
        env.src_port = atoi(arg);
        break;
    case 'D':
        env.dst_port = atoi(arg);
        break;
    case 'p':
        if (strcasecmp(arg, "tcp") == 0)
            env.protocol = IPPROTO_TCP;
        else if (strcasecmp(arg, "udp") == 0)
            env.protocol = IPPROTO_UDP;
        else if (strcasecmp(arg, "icmp") == 0)
            env.protocol = IPPROTO_ICMP;
        else
            env.protocol = atoi(arg);
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

static const char *event_type_str(__u32 type)
{
    switch (type) {
    case CT_EVENT_NEW:
        return "NEW";
    case CT_EVENT_DESTROY:
        return "DESTROY";
    case CT_EVENT_UPDATE:
        return "UPDATE";
    default:
        return "UNKNOWN";
    }
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
    struct ct_event *event = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char reply_src_ip[INET_ADDRSTRLEN], reply_dst_ip[INET_ADDRSTRLEN];
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &event->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &event->dst_ip, dst_ip, sizeof(dst_ip));

    printf("%s %-8s %-5s %s:%u -> %s:%u",
           ts,
           event_type_str(event->event_type),
           proto_str(event->protocol),
           src_ip, ntohs(event->src_port),
           dst_ip, ntohs(event->dst_port));

    if (env.verbose) {
        inet_ntop(AF_INET, &event->reply_src_ip, reply_src_ip, sizeof(reply_src_ip));
        inet_ntop(AF_INET, &event->reply_dst_ip, reply_dst_ip, sizeof(reply_dst_ip));
        printf(" reply=%s:%u->%s:%u mark=0x%x",
               reply_src_ip, ntohs(event->reply_src_port),
               reply_dst_ip, ntohs(event->reply_dst_port),
               event->mark);
    }

    printf("\n");

    return 0;
}

static void print_stats(struct trace_conntrack_bpf *skel)
{
    int stats_fd = bpf_map__fd(skel->maps.ct_stats_map);
    struct ct_stats_key key = {}, next_key;
    struct ct_stats stats;
    time_t now;
    struct tm *tm;
    char ts[32];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s - Conntrack Statistics\n", ts);
    printf("%-10s %12s %12s %12s\n", "PROTOCOL", "NEW", "DESTROY", "UPDATE");
    printf("--------------------------------------------------\n");

    __u64 total_new = 0, total_destroy = 0, total_update = 0;

    while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(stats_fd, &next_key, &stats) == 0) {
            printf("%-10s %12llu %12llu %12llu\n",
                   proto_str(next_key.protocol),
                   (unsigned long long)stats.new_count,
                   (unsigned long long)stats.destroy_count,
                   (unsigned long long)stats.update_count);
            total_new += stats.new_count;
            total_destroy += stats.destroy_count;
            total_update += stats.update_count;
        }
        key = next_key;
    }

    printf("--------------------------------------------------\n");
    printf("%-10s %12llu %12llu %12llu\n", "TOTAL",
           (unsigned long long)total_new,
           (unsigned long long)total_destroy,
           (unsigned long long)total_update);
}

int main(int argc, char **argv)
{
    struct trace_conntrack_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = trace_conntrack_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set filters */
    if (env.src_ip)
        skel->rodata->filter_src_ip = ip_to_u32(env.src_ip);
    if (env.dst_ip)
        skel->rodata->filter_dst_ip = ip_to_u32(env.dst_ip);
    if (env.src_port)
        skel->rodata->filter_src_port = env.src_port;
    if (env.dst_port)
        skel->rodata->filter_dst_port = env.dst_port;
    if (env.protocol)
        skel->rodata->filter_protocol = env.protocol;

    skel->rodata->trace_update = env.trace_update;

    err = trace_conntrack_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = trace_conntrack_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Setup ring buffer for events */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing conntrack events... Ctrl-C to stop\n");
    printf("%-8s %-8s %-5s %-21s -> %-21s\n",
           "TIME", "EVENT", "PROTO", "SRC", "DST");

    time_t last_stats = time(NULL);

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

        /* Print periodic stats */
        time_t now = time(NULL);
        if (now - last_stats >= env.interval) {
            print_stats(skel);
            last_stats = now;
        }
    }

    printf("\nFinal statistics:\n");
    print_stats(skel);

cleanup:
    ring_buffer__free(rb);
    trace_conntrack_bpf__destroy(skel);
    return err != 0;
}
