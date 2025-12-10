// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_ring_monitor - TUN ptr_ring monitor userspace program

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
#include "tun_ring_monitor.h"
#include "tun_ring_monitor.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *device;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    char *protocol;
    bool show_all;
    bool verbose;
} env = {
    .show_all = false,
    .verbose = false,
};

const char *argp_program_version = "tun_ring_monitor 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Monitor TUN device ptr_ring for full conditions.\n"
"\n"
"USAGE: tun_ring_monitor [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    tun_ring_monitor                        # Monitor all TUN devices for ring full\n"
"    tun_ring_monitor -d vnet12              # Monitor specific device\n"
"    tun_ring_monitor -d vnet12 --all        # Show all events, not just ring full\n"
"    tun_ring_monitor --src-ip 192.168.1.100 # Filter by source IP\n";

static const struct argp_option opts[] = {
    { "device", 'd', "DEV", 0, "Target device name (e.g., vnet12)" },
    { "src-ip", 's', "IP", 0, "Filter by source IP" },
    { "dst-ip", 'D', "IP", 0, "Filter by destination IP" },
    { "src-port", 'p', "PORT", 0, "Filter by source port" },
    { "dst-port", 'P', "PORT", 0, "Filter by destination port" },
    { "protocol", 'r', "PROTO", 0, "Filter by protocol (tcp/udp)" },
    { "all", 'a', NULL, 0, "Show all events (not just ring full)" },
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
        env.protocol = arg;
        break;
    case 'a':
        env.show_all = true;
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
    if (addr == 0) {
        snprintf(buf, buflen, "N/A");
    } else {
        inet_ntop(AF_INET, &in, buf, buflen);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct ring_event *e = data;
    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    struct tm *tm;
    char ts[32];
    time_t t;
    __u32 used, utilization = 0;

    /* Calculate ring utilization */
    if (e->ptr_ring_size > 0) {
        if (e->producer >= e->consumer_tail)
            used = e->producer - e->consumer_tail;
        else
            used = e->ptr_ring_size - e->consumer_tail + e->producer;
        utilization = (used * 100) / e->ptr_ring_size;
    }

    /* Format timestamp */
    t = e->timestamp / 1000000000ULL;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    __u64 ns_part = (e->timestamp % 1000000000ULL) / 1000000ULL;

    print_ip(e->saddr, saddr_str, sizeof(saddr_str));
    print_ip(e->daddr, daddr_str, sizeof(daddr_str));

    printf("================================================================================\n");
    if (e->ring_full)
        printf("TUN RING FULL DETECTED!\n");
    else
        printf("TUN Ring Status\n");

    printf("Time: %s.%03llu\n", ts, (unsigned long long)ns_part);
    printf("Process: %s (PID: %u)\n", e->comm, e->pid);
    printf("Device: %s\n", e->dev_name);
    printf("Queue: %u (numqueues: %u)\n", e->queue_mapping, e->tun_numqueues);
    printf("SKB Address: 0x%llx\n", (unsigned long long)e->skb_addr);
    printf("\n");

    /* 5-tuple info */
    printf("5-Tuple Info:\n");
    if (e->saddr != 0 || e->daddr != 0 || e->sport != 0 || e->dport != 0) {
        printf("  Source: %s:%u\n", saddr_str, ntohs(e->sport));
        printf("  Destination: %s:%u\n", daddr_str, ntohs(e->dport));
        printf("  Protocol: %s\n", protocol_str(e->protocol));
    } else {
        printf("  Packet headers not parsed (may be non-IP or parsing failed)\n");
    }
    printf("\n");

    /* PTR Ring details */
    printf("PTR Ring Details:\n");
    if (e->ptr_ring_size > 0) {
        printf("  Size: %u\n", e->ptr_ring_size);
        printf("  Producer: %u\n", e->producer);
        printf("  Consumer Head: %u\n", e->consumer_head);
        printf("  Consumer Tail: %u\n", e->consumer_tail);
        printf("  Queue[Producer] Ptr: 0x%llx\n", (unsigned long long)e->queue_producer_ptr);

        if (e->ring_full)
            printf("  Status: FULL (queue[producer] != NULL)\n");
        else
            printf("  Status: Available (queue[producer] == NULL), %u%% used\n", utilization);
    } else {
        printf("  Status: Not found (ptr_ring structure not accessible)\n");
    }

    printf("================================================================================\n\n");

    return 0;
}

static __u32 ip_str_to_be32(const char *ip_str)
{
    struct in_addr addr;
    if (!ip_str || inet_pton(AF_INET, ip_str, &addr) != 1)
        return 0;
    return addr.s_addr;
}

int main(int argc, char **argv)
{
    struct tun_ring_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tun_ring_monitor_bpf__open();
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
    }

    skel->rodata->show_all_events = env.show_all ? 1 : 0;

    err = tun_ring_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = tun_ring_monitor_bpf__attach(skel);
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

    printf("TUN Ring Monitor Started...\n");
    if (env.device)
        printf("Device filter: %s\n", env.device);
    else
        printf("Device filter: All TUN devices\n");

    if (env.show_all)
        printf("Mode: Monitoring ALL TUN transmit events\n");
    else
        printf("Mode: Monitoring ptr_ring FULL conditions only\n");

    printf("\nWaiting for TUN device events... Press Ctrl+C to stop\n\n");

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
    tun_ring_monitor_bpf__destroy(skel);
    return err != 0;
}
