// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_performance_metrics - VM Network performance metrics userspace

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
#include "vm_network_performance_metrics.h"
#include "vm_network_performance_metrics.skel.h"
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

const char *argp_program_version = "vm_network_performance_metrics 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"VM Network Performance Metrics Tool with detailed per-stage tracking\n"
"\n"
"USAGE: vm_network_performance_metrics [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    vm_network_performance_metrics --vm-interface vnet37 --phy-interface enp94s0f0np0 --direction rx\n"
"    vm_network_performance_metrics --vm-interface vnet37 --phy-interface enp94s0f0np0 --src-ip 192.168.76.198\n";

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
    [0] = "UNKNOWN",
    [STG_VNET_RX] = "VNET_RX",
    [STG_OVS_RX] = "OVS_RX",
    [STG_FLOW_EXTRACT_END_RX] = "FLOW_EXTRACT_END_RX",
    [STG_OVS_UPCALL_RX] = "OVS_UPCALL_RX",
    [STG_OVS_USERSPACE_RX] = "OVS_USERSPACE_RX",
    [STG_CT_RX] = "CT_RX",
    [STG_CT_OUT_RX] = "CT_OUT_RX",
    [STG_QDISC_ENQ] = "QDISC_ENQ",
    [STG_QDISC_DEQ] = "QDISC_DEQ",
    [STG_TX_QUEUE] = "TX_QUEUE",
    [STG_TX_XMIT] = "TX_XMIT",
    [STG_PHY_RX] = "PHY_RX",
    [STG_OVS_TX] = "OVS_TX",
    [STG_FLOW_EXTRACT_END_TX] = "FLOW_EXTRACT_END_TX",
    [STG_OVS_UPCALL_TX] = "OVS_UPCALL_TX",
    [STG_OVS_USERSPACE_TX] = "OVS_USERSPACE_TX",
    [STG_CT_TX] = "CT_TX",
    [STG_CT_OUT_TX] = "CT_OUT_TX",
    [STG_VNET_QDISC_ENQ] = "VNET_QDISC_ENQ",
    [STG_VNET_QDISC_DEQ] = "VNET_QDISC_DEQ",
    [STG_VNET_TX] = "VNET_TX",
};

static const char *get_stage_name(int stage)
{
    if (stage >= 0 && stage < MAX_STAGES && stage_names[stage])
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
    struct perf_event *e = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    time_t now;
    struct tm *tm;
    char ts[32];

    format_ip(src_ip, sizeof(src_ip), e->key.sip);
    format_ip(dst_ip, sizeof(dst_ip), e->key.dip);

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n[%s] === FLOW COMPLETE: %d stages captured ===\n",
           ts, e->flow.stage_count);

    /* Print flow info */
    const char *proto_name = "UNKNOWN";
    if (e->key.proto == PROTO_TCP)
        proto_name = "TCP";
    else if (e->key.proto == PROTO_UDP)
        proto_name = "UDP";
    else if (e->key.proto == PROTO_ICMP)
        proto_name = "ICMP";

    printf("FLOW: %s -> %s (%s)\n", src_ip, dst_ip, proto_name);

    /* Print 5-tuple */
    const char *dir_str = (e->flow.direction == DIR_VNET_RX) ? "VNET_RX" : "VNET_TX";
    if (e->key.proto == PROTO_TCP) {
        printf("5-TUPLE: %s:%u -> %s:%u TCP (seq=%u) DIR=%s\n",
               src_ip, ntohs(e->key.tcp.source),
               dst_ip, ntohs(e->key.tcp.dest),
               ntohl(e->key.tcp.seq), dir_str);
    } else if (e->key.proto == PROTO_UDP) {
        printf("5-TUPLE: %s:%u -> %s:%u UDP (id=%u) DIR=%s\n",
               src_ip, ntohs(e->key.udp.source),
               dst_ip, ntohs(e->key.udp.dest),
               ntohs(e->key.udp.id), dir_str);
    } else if (e->key.proto == PROTO_ICMP) {
        printf("5-TUPLE: %s -> %s ICMP (id=%u seq=%u type=%u) DIR=%s\n",
               src_ip, dst_ip,
               ntohs(e->key.icmp.id), ntohs(e->key.icmp.sequence),
               e->key.icmp.type, dir_str);
    }

    /* Collect and sort valid stages */
    struct {
        int stage_id;
        struct stage_info *info;
    } stages[MAX_STAGES];
    int stage_count = 0;

    for (int i = 0; i < MAX_STAGES; i++) {
        if (e->flow.stages[i].valid) {
            stages[stage_count].stage_id = i;
            stages[stage_count].info = &e->flow.stages[i];
            stage_count++;
        }
    }

    /* Print stages with timing */
    __u64 prev_ts = 0;
    for (int i = 0; i < stage_count; i++) {
        int stage_id = stages[i].stage_id;
        struct stage_info *stage = stages[i].info;
        double delta_us = 0;
        char delta_str[32] = "";

        if (prev_ts > 0 && stage->timestamp > prev_ts) {
            delta_us = (double)(stage->timestamp - prev_ts) / 1000.0;
            snprintf(delta_str, sizeof(delta_str), " (+%.3fus)", delta_us);
        }

        printf("  Stage %s: KTIME=%lluns%s\n",
               get_stage_name(stage_id),
               (unsigned long long)stage->timestamp,
               delta_str);

        printf("    SKB: ptr=0x%llx len=%u data_len=%u queue_mapping=%d hash=0x%x\n",
               (unsigned long long)stage->skb_ptr,
               stage->len, stage->data_len,
               stage->queue_mapping, stage->skb_hash);

        printf("    DEV: %s (ifindex=%u) CPU=%u\n",
               stage->devname, stage->ifindex, stage->cpu);

        prev_ts = stage->timestamp;
    }

    /* Total duration */
    if (stage_count >= 2) {
        __u64 first_ts = stages[0].info->timestamp;
        __u64 last_ts = stages[stage_count - 1].info->timestamp;
        double total_us = (double)(last_ts - first_ts) / 1000.0;
        printf("  TOTAL DURATION: %.3fus\n", total_us);
    }

    /* Process info */
    printf("  PROCESS: pid=%u comm=%s first_dev=%s\n",
           e->flow.first_pid, e->flow.first_comm, e->flow.first_ifname);

    /* Final stage */
    printf("  FINAL_STAGE: dev=%s(ifindex=%u) cpu=%u\n",
           e->devname, e->ifindex, e->cpu);

    /* Qdisc metrics */
    if (e->flow.qdisc_enq_time > 0) {
        for (int i = 0; i < stage_count; i++) {
            int stage_id = stages[i].stage_id;
            if (stage_id == STG_QDISC_DEQ || stage_id == STG_VNET_QDISC_DEQ) {
                __u64 sojourn_ns = stages[i].info->timestamp - e->flow.qdisc_enq_time;
                const char *qdisc_type = (stage_id == STG_QDISC_DEQ) ? "QDISC" : "VNET_QDISC";
                printf("  %s: sojourn=%.3fus qlen=%u\n",
                       qdisc_type, (double)sojourn_ns / 1000.0, e->flow.qdisc_qlen);
                break;
            }
        }
    }

    /* CT metrics */
    if (e->flow.ct_lookup_duration > 0) {
        printf("  CT: lookup=%.3fus\n", (double)e->flow.ct_lookup_duration / 1000.0);
    }

    printf("\n");
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
        return DIR_VNET_RX;
    if (strcmp(dir, "tx") == 0)
        return DIR_VNET_TX;
    return 0;
}

int main(int argc, char **argv)
{
    struct vm_network_performance_metrics_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vm_network_performance_metrics_bpf__open();
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

    err = vm_network_performance_metrics_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = vm_network_performance_metrics_bpf__attach(skel);
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

    printf("=== VM Network Performance Tracer ===\n");
    printf("Protocol filter: %s\n", env.protocol);
    printf("Direction filter: %s (1=VNET_RX/VM_TX, 2=VNET_TX/VM_RX)\n", env.direction);
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
    printf("\nTracing VM network performance... Hit Ctrl-C to end.\n\n");

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

    /* Print statistics */
    printf("\n=== Performance Statistics ===\n");
    printf("Event counts by probe point:\n");
    int stats_fd = bpf_map__fd(skel->maps.probe_stats);
    for (int i = 0; i < 32; i++) {
        __u64 count = 0;
        bpf_map_lookup_elem(stats_fd, &i, &count);
        if (count > 0)
            printf("  Probe %d (%s): %llu events\n",
                   i, get_stage_name(i), (unsigned long long)count);
    }

cleanup:
    ring_buffer__free(rb);
    vm_network_performance_metrics_bpf__destroy(skel);
    return err != 0;
}
