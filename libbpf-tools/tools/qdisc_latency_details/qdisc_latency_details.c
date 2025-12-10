// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// qdisc_latency_details - Qdisc latency tracking userspace

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
#include "qdisc_latency_details.h"
#include "qdisc_latency_details.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *dev;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    char *proto;
} env = {};

const char *argp_program_version = "qdisc_latency_details 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Track qdisc enqueue/dequeue latency.\n"
"\n"
"USAGE: qdisc_latency_details [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    qdisc_latency_details                    # Track all packets\n"
"    qdisc_latency_details --dev eth0         # Track on eth0 only\n"
"    qdisc_latency_details --proto tcp        # Track TCP only\n"
"    qdisc_latency_details --src-ip 10.0.0.1  # Filter by source IP\n";

static const struct argp_option opts[] = {
    { "dev", 'd', "DEV", 0, "Network device to monitor" },
    { "src-ip", 's', "IP", 0, "Source IP filter" },
    { "dst-ip", 'D', "IP", 0, "Destination IP filter" },
    { "src-port", 'p', "PORT", 0, "Source port filter" },
    { "dst-port", 'P', "PORT", 0, "Destination port filter" },
    { "proto", 'r', "PROTO", 0, "Protocol filter (tcp/udp/icmp)" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'd':
        env.dev = arg;
        break;
    case 's':
        env.src_ip = arg;
        break;
    case 'D':
        env.dst_ip = arg;
        break;
    case 'p':
        env.src_port = atoi(arg);
        break;
    case 'P':
        env.dst_port = atoi(arg);
        break;
    case 'r':
        env.proto = arg;
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

static __be32 ip_str_to_be32(const char *ip_str)
{
    struct in_addr addr;
    if (!ip_str || inet_pton(AF_INET, ip_str, &addr) != 1)
        return 0;
    return addr.s_addr;
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
    inet_ntop(AF_INET, &in, buf, buflen);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct qdisc_event *e = data;
    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    struct tm *tm;
    char ts[32];
    time_t t;

    t = e->timestamp / 1000000000ULL;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    __u64 ns_part = (e->timestamp % 1000000000ULL) / 1000000ULL;

    print_ip(e->saddr, saddr_str, sizeof(saddr_str));
    print_ip(e->daddr, daddr_str, sizeof(daddr_str));

    double delay_us = e->delay_ns / 1000.0;

    printf("[%s.%03llu] %s:%u -> %s:%u %s dev=%s delay=%.3fus\n",
           ts, (unsigned long long)ns_part,
           saddr_str, ntohs(e->sport),
           daddr_str, ntohs(e->dport),
           protocol_str(e->protocol),
           e->dev_name,
           delay_us);

    return 0;
}

int main(int argc, char **argv)
{
    struct qdisc_latency_details_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = qdisc_latency_details_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure BPF program */
    if (env.dev) {
        unsigned int ifindex = if_nametoindex(env.dev);
        if (ifindex == 0) {
            fprintf(stderr, "Invalid device: %s\n", env.dev);
            err = 1;
            goto cleanup;
        }
        skel->rodata->targ_ifindex = ifindex;
        printf("Device filter: %s (ifindex %u)\n", env.dev, ifindex);
    }

    if (env.src_ip) {
        skel->rodata->targ_saddr = ip_str_to_be32(env.src_ip);
        printf("Source IP filter: %s\n", env.src_ip);
    }

    if (env.dst_ip) {
        skel->rodata->targ_daddr = ip_str_to_be32(env.dst_ip);
        printf("Destination IP filter: %s\n", env.dst_ip);
    }

    if (env.src_port) {
        skel->rodata->targ_sport = env.src_port;
        printf("Source port filter: %d\n", env.src_port);
    }

    if (env.dst_port) {
        skel->rodata->targ_dport = env.dst_port;
        printf("Destination port filter: %d\n", env.dst_port);
    }

    if (env.proto) {
        if (strcasecmp(env.proto, "tcp") == 0)
            skel->rodata->targ_proto = 6;
        else if (strcasecmp(env.proto, "udp") == 0)
            skel->rodata->targ_proto = 17;
        else if (strcasecmp(env.proto, "icmp") == 0)
            skel->rodata->targ_proto = 1;
        printf("Protocol filter: %s\n", env.proto);
    }

    err = qdisc_latency_details_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = qdisc_latency_details_bpf__attach(skel);
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

    printf("Qdisc Latency Tracker Started\n");
    printf("Tracing qdisc enqueue/dequeue latency... Hit Ctrl-C to end.\n\n");

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

    printf("\nDetaching...\n");

cleanup:
    ring_buffer__free(rb);
    qdisc_latency_details_bpf__destroy(skel);
    return err != 0;
}
