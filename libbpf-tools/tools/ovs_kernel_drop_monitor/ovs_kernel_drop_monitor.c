// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_kernel_drop_monitor - OVS kernel module drop monitoring userspace program

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
#include "ovs_kernel_drop_monitor.h"
#include "ovs_kernel_drop_monitor.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool verbose;
    bool trace;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    int protocol;
} env = {
    .interval = 5,
    .verbose = false,
    .trace = false,
};

const char *argp_program_version = "ovs_kernel_drop_monitor 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Monitor OVS kernel module packet drops\n"
"\n"
"USAGE: ovs_kernel_drop_monitor [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    ovs_kernel_drop_monitor                    # Summary mode\n"
"    ovs_kernel_drop_monitor -t                 # Trace individual drops\n"
"    ovs_kernel_drop_monitor --src-ip 10.0.0.1  # Filter by source IP\n"
"    ovs_kernel_drop_monitor -v                 # Verbose with stacks\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Output interval in seconds (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output with stack traces" },
    { "trace", 't', NULL, 0, "Trace individual drop events" },
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
    case 't':
        env.trace = true;
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

static const char *drop_reason_str(__u32 reason)
{
    static const char *reasons[] = {
        [OVS_DROP_UNKNOWN] = "UNKNOWN",
        [OVS_DROP_ACTION_ERROR] = "ACTION_ERROR",
        [OVS_DROP_EXPLICIT] = "EXPLICIT",
        [OVS_DROP_IP_TTL] = "IP_TTL",
        [OVS_DROP_FRAG] = "FRAG",
        [OVS_DROP_CONNTRACK] = "CONNTRACK",
        [OVS_DROP_TUNNEL_ERROR] = "TUNNEL_ERROR",
        [OVS_DROP_HEADROOM] = "HEADROOM",
    };

    if (reason < OVS_DROP_MAX)
        return reasons[reason];
    return "UNKNOWN";
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

static __u32 ip_to_u32(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 1)
        return addr.s_addr;
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct ovs_drop_event *event = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &event->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &event->dst_ip, dst_ip, sizeof(dst_ip));

    printf("%s %-16s %-14s %-5s %s:%u -> %s:%u\n",
           ts,
           event->ifname[0] ? event->ifname : "unknown",
           drop_reason_str(event->drop_reason),
           proto_str(event->protocol),
           src_ip, ntohs(event->src_port),
           dst_ip, ntohs(event->dst_port));

    if (env.verbose) {
        printf("  pid=%u comm=%s stack_id=%d\n",
               event->pid, event->comm, event->stack_id);
    }

    return 0;
}

static void print_stats(struct ovs_kernel_drop_monitor_bpf *skel)
{
    int stats_fd = bpf_map__fd(skel->maps.drop_stats_map);
    struct ovs_drop_key key = {}, next_key;
    struct ovs_drop_stats stats;
    time_t now;
    struct tm *tm;
    char ts[32];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s - OVS Kernel Drop Statistics\n", ts);
    printf("%-20s %-12s %12s %14s\n", "DROP_REASON", "STACK_ID", "COUNT", "BYTES");
    printf("------------------------------------------------------------\n");

    __u64 total_drops = 0;
    __u64 total_bytes = 0;

    while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(stats_fd, &next_key, &stats) == 0) {
            printf("%-20s %-12d %12llu %14llu\n",
                   drop_reason_str(next_key.drop_reason),
                   next_key.stack_id,
                   (unsigned long long)stats.count,
                   (unsigned long long)stats.bytes);
            total_drops += stats.count;
            total_bytes += stats.bytes;
        }
        key = next_key;
    }

    printf("------------------------------------------------------------\n");
    printf("%-20s %-12s %12llu %14llu\n", "TOTAL", "",
           (unsigned long long)total_drops, (unsigned long long)total_bytes);
}

int main(int argc, char **argv)
{
    struct ovs_kernel_drop_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = ovs_kernel_drop_monitor_bpf__open();
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

    skel->rodata->output_events = env.trace;

    err = ovs_kernel_drop_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = ovs_kernel_drop_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Monitoring OVS kernel drops... Ctrl-C to stop\n");

    if (env.trace) {
        /* Setup ring buffer for events */
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            err = 1;
            goto cleanup;
        }

        printf("%-8s %-16s %-14s %-5s %-21s -> %-21s\n",
               "TIME", "INTERFACE", "REASON", "PROTO", "SRC", "DST");

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
    }

    printf("\nFinal statistics:\n");
    print_stats(skel);

cleanup:
    ring_buffer__free(rb);
    ovs_kernel_drop_monitor_bpf__destroy(skel);
    return err != 0;
}
