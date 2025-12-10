// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// trace_ip_defrag - IP fragmentation/defragmentation tracer userspace program

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
#include "trace_ip_defrag.h"
#include "trace_ip_defrag.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool verbose;
    bool summary_only;
    char *src_ip;
    char *dst_ip;
    int protocol;
} env = {
    .interval = 5,
    .verbose = false,
    .summary_only = false,
};

const char *argp_program_version = "trace_ip_defrag 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Trace IP fragmentation and defragmentation events\n"
"\n"
"USAGE: trace_ip_defrag [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    trace_ip_defrag                         # Trace all fragment events\n"
"    trace_ip_defrag -S                      # Summary mode only\n"
"    trace_ip_defrag --src-ip 10.0.0.1       # Filter by source IP\n"
"    trace_ip_defrag -p udp                  # Filter by protocol\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Statistics output interval (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output with stack traces" },
    { "summary", 'S', NULL, 0, "Summary mode only (no individual events)" },
    { "src-ip", 's', "IP", 0, "Filter by source IP" },
    { "dst-ip", 'd', "IP", 0, "Filter by destination IP" },
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
    case 'S':
        env.summary_only = true;
        break;
    case 's':
        env.src_ip = arg;
        break;
    case 'd':
        env.dst_ip = arg;
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
    case FRAG_EVENT_RECV:
        return "RECV";
    case FRAG_EVENT_COMPLETE:
        return "COMPLETE";
    case FRAG_EVENT_TIMEOUT:
        return "TIMEOUT";
    case FRAG_EVENT_DROP:
        return "DROP";
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
    struct frag_event *event = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &event->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &event->dst_ip, dst_ip, sizeof(dst_ip));

    printf("%s %-8s %-5s id=%-5u off=%-5u len=%-4u %s -> %s",
           ts,
           event_type_str(event->event_type),
           proto_str(event->protocol),
           event->ip_id,
           event->frag_offset,
           event->data_len,
           src_ip,
           dst_ip);

    if (event->more_frags)
        printf(" MF");

    if (event->ifname[0])
        printf(" [%s]", event->ifname);

    printf("\n");

    if (env.verbose) {
        printf("  pid=%u comm=%s total_len=%u\n",
               event->pid, event->comm, event->total_len);
    }

    return 0;
}

static void print_stats(struct trace_ip_defrag_bpf *skel)
{
    int global_fd = bpf_map__fd(skel->maps.global_stats);
    int frag_fd = bpf_map__fd(skel->maps.frag_stats_map);
    __u32 key = 0;
    struct global_frag_stats global;
    struct frag_stats_key frag_key = {}, next_key;
    struct frag_stats frag;
    time_t now;
    struct tm *tm;
    char ts[32];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s - IP Fragment Statistics\n", ts);
    printf("============================================================\n");

    /* Print global stats */
    if (bpf_map_lookup_elem(global_fd, &key, &global) == 0) {
        printf("Global Statistics:\n");
        printf("  Total fragments: %llu\n", (unsigned long long)global.total_fragments);
        printf("  Total bytes:     %llu\n", (unsigned long long)global.total_bytes);
        printf("  Reassembled:     %llu\n", (unsigned long long)global.reassembled);
        printf("  Timeouts:        %llu\n", (unsigned long long)global.timeouts);
        printf("  Drops:           %llu\n", (unsigned long long)global.drops);
    }

    /* Print per-flow stats (top 10) */
    printf("\nPer-Flow Statistics (top active):\n");
    printf("%-15s %-15s %-8s %10s %10s\n",
           "SRC_IP", "DST_IP", "IP_ID", "FRAGS", "BYTES");
    printf("------------------------------------------------------------\n");

    int count = 0;
    while (bpf_map_get_next_key(frag_fd, &frag_key, &next_key) == 0 && count < 10) {
        if (bpf_map_lookup_elem(frag_fd, &next_key, &frag) == 0) {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next_key.src_ip, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &next_key.dst_ip, dst_ip, sizeof(dst_ip));

            printf("%-15s %-15s %-8u %10llu %10llu\n",
                   src_ip, dst_ip, ntohs(next_key.ip_id),
                   (unsigned long long)frag.fragments_recv,
                   (unsigned long long)frag.bytes_recv);
            count++;
        }
        frag_key = next_key;
    }

    if (count == 0) {
        printf("  No active fragment flows\n");
    }

    printf("============================================================\n");
}

int main(int argc, char **argv)
{
    struct trace_ip_defrag_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = trace_ip_defrag_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set filters */
    if (env.src_ip)
        skel->rodata->filter_src_ip = ip_to_u32(env.src_ip);
    if (env.dst_ip)
        skel->rodata->filter_dst_ip = ip_to_u32(env.dst_ip);
    if (env.protocol)
        skel->rodata->filter_protocol = env.protocol;

    skel->rodata->trace_events = !env.summary_only;

    err = trace_ip_defrag_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = trace_ip_defrag_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Initialize global stats */
    __u32 key = 0;
    struct global_frag_stats zero = {};
    bpf_map_update_elem(bpf_map__fd(skel->maps.global_stats), &key, &zero, BPF_ANY);

    printf("Tracing IP fragmentation... Ctrl-C to stop\n");

    if (!env.summary_only) {
        /* Setup ring buffer for events */
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            err = 1;
            goto cleanup;
        }

        printf("%-8s %-8s %-5s %-8s %-8s %-8s %-15s -> %-15s\n",
               "TIME", "EVENT", "PROTO", "ID", "OFFSET", "LEN", "SRC", "DST");

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
    trace_ip_defrag_bpf__destroy(skel);
    return err != 0;
}
