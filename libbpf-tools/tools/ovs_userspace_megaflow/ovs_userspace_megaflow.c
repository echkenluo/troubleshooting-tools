// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ovs_userspace_megaflow - OVS userspace megaflow tracker userspace program

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
#include "ovs_userspace_megaflow.h"
#include "ovs_userspace_megaflow.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int interval;
    bool verbose;
    bool upcalls_only;
    bool flows_only;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    int protocol;
} env = {
    .interval = 5,
    .verbose = false,
    .upcalls_only = false,
    .flows_only = false,
};

const char *argp_program_version = "ovs_userspace_megaflow 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Track OVS userspace megaflow creation and upcalls\n"
"\n"
"USAGE: ovs_userspace_megaflow [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    ovs_userspace_megaflow                    # Trace all events\n"
"    ovs_userspace_megaflow -u                 # Upcalls only\n"
"    ovs_userspace_megaflow -f                 # Flow events only\n"
"    ovs_userspace_megaflow --src-ip 10.0.0.1  # Filter by source IP\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Statistics output interval (default: 5)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { "upcalls", 'u', NULL, 0, "Trace upcalls only" },
    { "flows", 'f', NULL, 0, "Trace flow events only" },
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
        env.upcalls_only = true;
        break;
    case 'f':
        env.flows_only = true;
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

static void mac_to_str(const __u8 *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static __u32 ip_to_u32(const char *ip_str)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 1)
        return addr.s_addr;
    return 0;
}

static int handle_upcall_event(void *ctx, void *data, size_t data_sz)
{
    struct upcall_event *event = data;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    char src_mac[18], dst_mac[18];
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &event->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &event->dst_ip, dst_ip, sizeof(dst_ip));

    printf("%s UPCALL %-5s %s:%u -> %s:%u",
           ts,
           proto_str(event->protocol),
           src_ip, ntohs(event->src_port),
           dst_ip, ntohs(event->dst_port));

    if (event->ifname[0])
        printf(" [%s]", event->ifname);

    if (event->skb_mark)
        printf(" mark=0x%x", event->skb_mark);

    printf("\n");

    if (env.verbose) {
        mac_to_str(event->eth_src, src_mac, sizeof(src_mac));
        mac_to_str(event->eth_dst, dst_mac, sizeof(dst_mac));
        printf("  pid=%u comm=%s portid=%u eth=%s->%s type=0x%04x\n",
               event->pid, event->comm, event->portid,
               src_mac, dst_mac, event->eth_type);
    }

    return 0;
}

static int handle_flow_event(void *ctx, void *data, size_t data_sz)
{
    struct flow_new_event *event = data;
    char ts[32];
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%s FLOW_NEW pid=%u comm=%s portid=%u skb_len=%u\n",
           ts, event->pid, event->comm, event->netlink_portid, event->skb_len);

    return 0;
}

static void print_stats(struct ovs_userspace_megaflow_bpf *skel)
{
    int stats_fd = bpf_map__fd(skel->maps.upcall_stats_map);
    struct upcall_stats_key key = {}, next_key;
    struct upcall_stats stats;
    time_t now;
    struct tm *tm;
    char ts[32];

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n%s - OVS Upcall Statistics\n", ts);
    printf("%-15s %-15s %-8s %12s\n", "SRC_IP", "DST_IP", "PROTOCOL", "UPCALLS");
    printf("------------------------------------------------------------\n");

    __u64 total_upcalls = 0;
    int count = 0;

    while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0 && count < 20) {
        if (bpf_map_lookup_elem(stats_fd, &next_key, &stats) == 0) {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &next_key.src_ip, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &next_key.dst_ip, dst_ip, sizeof(dst_ip));

            printf("%-15s %-15s %-8s %12llu\n",
                   src_ip, dst_ip, proto_str(next_key.protocol),
                   (unsigned long long)stats.count);
            total_upcalls += stats.count;
            count++;
        }
        key = next_key;
    }

    printf("------------------------------------------------------------\n");
    printf("%-15s %-15s %-8s %12llu\n", "TOTAL", "", "",
           (unsigned long long)total_upcalls);
}

int main(int argc, char **argv)
{
    struct ovs_userspace_megaflow_bpf *skel;
    struct ring_buffer *upcall_rb = NULL;
    struct ring_buffer *flow_rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = ovs_userspace_megaflow_bpf__open();
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

    skel->rodata->trace_upcalls = !env.flows_only;
    skel->rodata->trace_flows = !env.upcalls_only;

    err = ovs_userspace_megaflow_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = ovs_userspace_megaflow_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Tracking OVS megaflow events... Ctrl-C to stop\n");

    /* Setup ring buffers */
    if (!env.flows_only) {
        upcall_rb = ring_buffer__new(bpf_map__fd(skel->maps.upcall_events),
                                     handle_upcall_event, NULL, NULL);
        if (!upcall_rb) {
            fprintf(stderr, "Failed to create upcall ring buffer\n");
            err = 1;
            goto cleanup;
        }
    }

    if (!env.upcalls_only) {
        flow_rb = ring_buffer__new(bpf_map__fd(skel->maps.flow_events),
                                   handle_flow_event, NULL, NULL);
        if (!flow_rb) {
            fprintf(stderr, "Failed to create flow ring buffer\n");
            err = 1;
            goto cleanup;
        }
    }

    time_t last_stats = time(NULL);

    while (!exiting) {
        if (upcall_rb) {
            err = ring_buffer__poll(upcall_rb, 50);
            if (err == -EINTR) {
                err = 0;
                break;
            }
        }
        if (flow_rb) {
            err = ring_buffer__poll(flow_rb, 50);
            if (err == -EINTR) {
                err = 0;
                break;
            }
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
    ring_buffer__free(upcall_rb);
    ring_buffer__free(flow_rb);
    ovs_userspace_megaflow_bpf__destroy(skel);
    return err != 0;
}
