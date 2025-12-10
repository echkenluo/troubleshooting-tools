// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_latency_details - VM Network detailed latency tracer userspace

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
#include "vm_network_latency_details.h"
#include "vm_network_latency_details.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *src_ip;
    char *dst_ip;
    __u16 src_port;
    __u16 dst_port;
    char *protocol;
    char *direction;
    char *vm_interface;
    char *phy_interface;
    bool verbose;
} env = {
    .protocol = "all",
    .direction = "rx",
};

const char *argp_program_version = "vm_network_latency_details 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"VM Network End-to-End Latency Measurement Tool with detailed per-packet tracing\n"
"\n"
"USAGE: vm_network_latency_details [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    vm_network_latency_details --vm-interface vnet0 --phy-interface eth0 --direction rx\n"
"    vm_network_latency_details --vm-interface vnet0 --phy-interface eth0 --src-ip 192.168.1.10\n";

static const struct argp_option opts[] = {
    { "src-ip", 's', "IP", 0, "Source IP address filter" },
    { "dst-ip", 'd', "IP", 0, "Destination IP address filter" },
    { "src-port", 'S', "PORT", 0, "Source port filter (TCP/UDP)" },
    { "dst-port", 'D', "PORT", 0, "Destination port filter (TCP/UDP)" },
    { "protocol", 'p', "PROTO", 0, "Protocol filter: tcp, udp, icmp, all (default: all)" },
    { "direction", 'r', "DIR", 0, "Direction: rx (VM->Phy), tx (Phy->VM) (default: rx)" },
    { "vm-interface", 'v', "DEV", 0, "VM interface to monitor (required)" },
    { "phy-interface", 'P', "DEV", 0, "Physical interface to monitor (required)" },
    { "verbose", 'V', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
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
        env.protocol = arg;
        break;
    case 'r':
        env.direction = arg;
        break;
    case 'v':
        env.vm_interface = arg;
        break;
    case 'P':
        env.phy_interface = arg;
        break;
    case 'V':
        env.verbose = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_END:
        if (!env.vm_interface || !env.phy_interface) {
            fprintf(stderr, "Error: --vm-interface and --phy-interface are required\n");
            argp_usage(state);
        }
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

static const char *stage_names[] = {
    [RX_STAGE_0] = "RX0_netif_receive_skb",
    [RX_STAGE_1] = "RX1_netdev_frame_hook",
    [RX_STAGE_2] = "RX2_ovs_dp_process",
    [RX_STAGE_3] = "RX3_ovs_dp_upcall",
    [RX_STAGE_4] = "RX4_ovs_flow_key_extract",
    [RX_STAGE_5] = "RX5_ovs_vport_send",
    [RX_STAGE_6] = "RX6_dev_queue_xmit",
    [TX_STAGE_0] = "TX0_netif_receive_skb",
    [TX_STAGE_1] = "TX1_netdev_frame_hook",
    [TX_STAGE_2] = "TX2_ovs_dp_process",
    [TX_STAGE_3] = "TX3_ovs_dp_upcall",
    [TX_STAGE_4] = "TX4_ovs_flow_key_extract",
    [TX_STAGE_5] = "TX5_ovs_vport_send",
    [TX_STAGE_6] = "TX6_tun_net_xmit",
};

static const char *get_stage_name(int stage)
{
    if (stage >= 0 && stage < MAX_STAGES)
        return stage_names[stage];
    return "UNKNOWN";
}

static void format_ip(char *buf, size_t len, __be32 addr)
{
    struct in_addr in = { .s_addr = addr };
    inet_ntop(AF_INET, &in, buf, len);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct latency_event *e = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    time_t now;
    struct tm *tm;
    char ts[32];
    int start_stage, end_stage;

    format_ip(src_ip, sizeof(src_ip), e->key.src_ip);
    format_ip(dst_ip, sizeof(dst_ip), e->key.dst_ip);

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n=== VM Network Latency Trace: %s ===\n", ts);

    /* Print flow info */
    const char *proto_name = "UNKNOWN";
    if (e->key.protocol == PROTO_TCP)
        proto_name = "TCP";
    else if (e->key.protocol == PROTO_UDP)
        proto_name = "UDP";
    else if (e->key.protocol == PROTO_ICMP)
        proto_name = "ICMP";

    printf("Flow: %s -> %s (%s)\n", src_ip, dst_ip, proto_name);

    if (e->key.protocol == PROTO_TCP) {
        printf("TCP: %s:%u -> %s:%u (seq=%u)\n",
               src_ip, ntohs(e->key.tcp.src_port),
               dst_ip, ntohs(e->key.tcp.dst_port),
               ntohl(e->key.tcp.seq));
    } else if (e->key.protocol == PROTO_UDP) {
        printf("UDP: %s:%u -> %s:%u (ip_id=%u)\n",
               src_ip, ntohs(e->key.udp.src_port),
               dst_ip, ntohs(e->key.udp.dst_port),
               ntohs(e->key.udp.ip_id));
    } else if (e->key.protocol == PROTO_ICMP) {
        printf("ICMP: %s -> %s (id=%u, seq=%u, type=%u)\n",
               src_ip, dst_ip,
               ntohs(e->key.icmp.id), ntohs(e->key.icmp.seq),
               e->key.icmp.type);
    }

    /* Print interface info */
    if (e->data.direction == DIRECTION_RX) {
        printf("Direction: RX (VM -> Physical)\n");
        printf("VM Interface: %s -> Physical Interface: %s\n",
               e->data.rx_vnet_ifname, e->data.tx_pnic_ifname);
        start_stage = RX_STAGE_0;
        end_stage = RX_STAGE_6;
    } else {
        printf("Direction: TX (Physical -> VM)\n");
        printf("Physical Interface: %s -> VM Interface: %s\n",
               e->data.tx_pnic_ifname, e->data.rx_vnet_ifname);
        start_stage = TX_STAGE_0;
        end_stage = TX_STAGE_6;
    }

    /* Print process info */
    if (e->data.direction == DIRECTION_RX && e->data.rx_pid > 0) {
        printf("Process: PID=%u COMM=%s\n", e->data.rx_pid, e->data.rx_comm);
    } else if (e->data.direction == DIRECTION_TX && e->data.tx_pid > 0) {
        printf("Process: PID=%u COMM=%s\n", e->data.tx_pid, e->data.tx_comm);
    }

    /* Print per-stage latencies */
    printf("\nPath Latencies (us):\n");

    __u64 prev_ts = 0;
    int prev_stage = -1;

    for (int i = start_stage; i <= end_stage; i++) {
        if (e->data.ts[i] > 0) {
            if (prev_ts > 0) {
                double latency_us = (double)(e->data.ts[i] - prev_ts) / 1000.0;
                printf("  [%d->%d] %s -> %s: %.3f us\n",
                       prev_stage, i,
                       get_stage_name(prev_stage),
                       get_stage_name(i),
                       latency_us);
            }
            prev_ts = e->data.ts[i];
            prev_stage = i;
        }
    }

    /* Print total latency */
    __u64 first_ts = 0, last_ts = 0;
    for (int i = start_stage; i <= end_stage; i++) {
        if (e->data.ts[i] > 0) {
            if (first_ts == 0)
                first_ts = e->data.ts[i];
            last_ts = e->data.ts[i];
        }
    }

    if (first_ts > 0 && last_ts > 0 && last_ts > first_ts) {
        double total_us = (double)(last_ts - first_ts) / 1000.0;
        printf("  Total Latency: %.3f us\n", total_us);
    }

    printf("================================================================================\n");

    return 0;
}

static __u32 ip_to_int(const char *ip_str)
{
    struct in_addr addr;
    if (!ip_str || inet_pton(AF_INET, ip_str, &addr) != 1)
        return 0;
    return addr.s_addr;
}

static __u8 proto_to_int(const char *proto)
{
    if (!proto || strcmp(proto, "all") == 0)
        return 0;
    if (strcmp(proto, "tcp") == 0)
        return PROTO_TCP;
    if (strcmp(proto, "udp") == 0)
        return PROTO_UDP;
    if (strcmp(proto, "icmp") == 0)
        return PROTO_ICMP;
    return 0;
}

static __u8 direction_to_int(const char *dir)
{
    if (!dir)
        return 0;
    if (strcmp(dir, "rx") == 0)
        return DIRECTION_RX;
    if (strcmp(dir, "tx") == 0)
        return DIRECTION_TX;
    return 0;
}

int main(int argc, char **argv)
{
    struct vm_network_latency_details_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vm_network_latency_details_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    unsigned int vm_ifindex = if_nametoindex(env.vm_interface);
    unsigned int phy_ifindex = if_nametoindex(env.phy_interface);

    if (vm_ifindex == 0) {
        fprintf(stderr, "Invalid VM interface: %s\n", env.vm_interface);
        err = 1;
        goto cleanup;
    }
    if (phy_ifindex == 0) {
        fprintf(stderr, "Invalid physical interface: %s\n", env.phy_interface);
        err = 1;
        goto cleanup;
    }

    skel->rodata->targ_src_ip = ip_to_int(env.src_ip);
    skel->rodata->targ_dst_ip = ip_to_int(env.dst_ip);
    skel->rodata->targ_src_port = env.src_port;
    skel->rodata->targ_dst_port = env.dst_port;
    skel->rodata->targ_protocol = proto_to_int(env.protocol);
    skel->rodata->targ_direction = direction_to_int(env.direction);
    skel->rodata->targ_vm_ifindex = vm_ifindex;
    skel->rodata->targ_phy_ifindex = phy_ifindex;

    err = vm_network_latency_details_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = vm_network_latency_details_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("=== VM Network Latency Tracer ===\n");
    printf("Protocol filter: %s\n", env.protocol);
    printf("Direction filter: %s (%s)\n", env.direction,
           strcmp(env.direction, "rx") == 0 ? "VM->Physical" : "Physical->VM");
    if (env.src_ip)
        printf("Source IP filter: %s\n", env.src_ip);
    if (env.dst_ip)
        printf("Destination IP filter: %s\n", env.dst_ip);
    if (env.src_port)
        printf("Source port filter: %u\n", env.src_port);
    if (env.dst_port)
        printf("Destination port filter: %u\n", env.dst_port);
    printf("VM interface: %s (ifindex %u)\n", env.vm_interface, vm_ifindex);
    printf("Physical interface: %s (ifindex %u)\n", env.phy_interface, phy_ifindex);
    printf("\nTracing VM network latency... Hit Ctrl-C to end.\n");

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

    /* Print final statistics */
    printf("\n=== Statistics ===\n");
    int counters_fd = bpf_map__fd(skel->maps.counters);
    __u64 rx_count = 0, tx_count = 0;
    __u32 idx = 0;
    bpf_map_lookup_elem(counters_fd, &idx, &rx_count);
    idx = 1;
    bpf_map_lookup_elem(counters_fd, &idx, &tx_count);
    printf("RX flows completed: %llu\n", (unsigned long long)rx_count);
    printf("TX flows completed: %llu\n", (unsigned long long)tx_count);

cleanup:
    ring_buffer__free(rb);
    vm_network_latency_details_bpf__destroy(skel);
    return err != 0;
}
