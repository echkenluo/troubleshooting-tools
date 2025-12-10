// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_latency_details - Detailed system network latency userspace

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
#include "system_network_latency_details.h"
#include "system_network_latency_details.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *phy_interface;
    char *direction;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    int protocol;
    bool verbose;
} env = {
    .verbose = false,
};

const char *argp_program_version = "system_network_latency_details 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Trace detailed per-packet latency through system network stack\n"
"\n"
"USAGE: system_network_latency_details --phy-interface DEV --direction DIR [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    system_network_latency_details --phy-interface eth0 --direction tx\n"
"    system_network_latency_details --phy-interface eth0 --direction rx --src-ip 10.0.0.1\n";

static const struct argp_option opts[] = {
    { "phy-interface", 'i', "DEV", 0, "Physical interface to monitor" },
    { "direction", 'd', "DIR", 0, "Direction: tx or rx" },
    { "src-ip", 's', "IP", 0, "Filter by source IP" },
    { "dst-ip", 'D', "IP", 0, "Filter by destination IP" },
    { "src-port", 'S', "PORT", 0, "Filter by source port" },
    { "dst-port", 'P', "PORT", 0, "Filter by destination port" },
    { "protocol", 'p', "PROTO", 0, "Filter by protocol (tcp/udp)" },
    { "verbose", 'v', NULL, 0, "Verbose output with stack traces" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.phy_interface = arg;
        break;
    case 'd':
        env.direction = arg;
        break;
    case 's':
        env.src_ip = arg;
        break;
    case 'D':
        env.dst_ip = arg;
        break;
    case 'S':
        env.src_port = atoi(arg);
        break;
    case 'P':
        env.dst_port = atoi(arg);
        break;
    case 'p':
        if (strcasecmp(arg, "tcp") == 0)
            env.protocol = IPPROTO_TCP;
        else if (strcasecmp(arg, "udp") == 0)
            env.protocol = IPPROTO_UDP;
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

static const char *stage_name(__u8 stage, __u8 dir)
{
    static const char *tx_stages[] = {
        "ip_queue_xmit", "internal_dev_xmit", "ovs_dp_process",
        "ovs_dp_upcall", "ovs_flow_key_extract", "ovs_vport_send",
        "dev_queue_xmit"
    };
    static const char *rx_stages[] = {
        "netif_receive_skb", "netdev_frame_hook", "ovs_dp_process",
        "ovs_dp_upcall", "ovs_flow_key_extract", "ovs_vport_send",
        "tcp/udp_rcv"
    };

    if (dir == 1 && stage < 7)
        return tx_stages[stage];
    if (dir == 2 && stage >= 7 && stage < 14)
        return rx_stages[stage - 7];
    return "unknown";
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
    struct latency_event *event = data;
    struct packet_key *key = &event->key;
    struct flow_data *flow = &event->data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &key->dst_ip, dst_ip, sizeof(dst_ip));

    printf("\n=== %s Latency Trace: %s ===\n",
           flow->direction == 1 ? "TX" : "RX", ts);
    printf("Flow: %s:%u -> %s:%u (%s)\n",
           src_ip, ntohs(key->src_port),
           dst_ip, ntohs(key->dst_port),
           key->protocol == IPPROTO_TCP ? "TCP" : "UDP");
    printf("Process: PID=%u COMM=%s IF=%s\n",
           flow->pid, flow->comm, flow->ifname);

    /* Print stage latencies */
    printf("\nStage Latencies (us):\n");

    __u8 start_stage = flow->direction == 1 ? 0 : 7;
    __u8 end_stage = flow->direction == 1 ? 6 : 13;
    __u8 prev_stage = 255;

    for (int i = start_stage; i <= end_stage; i++) {
        if (flow->ts[i] == 0)
            continue;

        if (prev_stage != 255 && flow->ts[prev_stage] > 0) {
            __u64 latency_ns = flow->ts[i] - flow->ts[prev_stage];
            double latency_us = latency_ns / 1000.0;
            printf("  [%d->%d] %-20s -> %-20s: %10.3f us\n",
                   prev_stage, i,
                   stage_name(prev_stage, flow->direction),
                   stage_name(i, flow->direction),
                   latency_us);
        }
        prev_stage = i;
    }

    /* Print total latency */
    if (flow->ts[start_stage] > 0 && flow->ts[end_stage] > 0) {
        __u64 total_ns = flow->ts[end_stage] - flow->ts[start_stage];
        double total_us = total_ns / 1000.0;
        printf("\nTotal %s Latency: %.3f us\n",
               flow->direction == 1 ? "TX" : "RX", total_us);
    }

    printf("========================================\n");
    return 0;
}

int main(int argc, char **argv)
{
    struct system_network_latency_details_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!env.phy_interface || !env.direction) {
        fprintf(stderr, "Error: --phy-interface and --direction are required\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = system_network_latency_details_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    unsigned int ifindex = if_nametoindex(env.phy_interface);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface: %s\n", env.phy_interface);
        err = 1;
        goto cleanup;
    }
    skel->rodata->target_ifindex = ifindex;

    if (strcasecmp(env.direction, "tx") == 0)
        skel->rodata->direction = 1;
    else if (strcasecmp(env.direction, "rx") == 0)
        skel->rodata->direction = 2;
    else {
        fprintf(stderr, "Invalid direction: %s (use tx or rx)\n", env.direction);
        err = 1;
        goto cleanup;
    }

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

    err = system_network_latency_details_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = system_network_latency_details_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Tracing %s network latency on %s... Ctrl-C to stop\n",
           env.direction, env.phy_interface);

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

cleanup:
    ring_buffer__free(rb);
    system_network_latency_details_bpf__destroy(skel);
    return err != 0;
}
