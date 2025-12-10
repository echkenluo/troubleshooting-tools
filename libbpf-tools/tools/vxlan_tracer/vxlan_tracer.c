// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vxlan_tracer - VXLAN packet tracer

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
#include "vxlan_tracer.h"
#include "vxlan_tracer.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *interface;
    int vni;
    bool verbose;
} env = {0};

const char *argp_program_version = "vxlan_tracer 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Trace VXLAN encapsulated packets.\n"
"\n"
"USAGE: vxlan_tracer [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    vxlan_tracer                     # Trace all VXLAN packets\n"
"    vxlan_tracer -i eth0             # Filter by interface\n"
"    vxlan_tracer --vni 100           # Filter by VNI\n";

static const struct argp_option opts[] = {
    { "interface", 'i', "DEV", 0, "Target interface" },
    { "vni", 'n', "VNI", 0, "Filter by VNI" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i': env.interface = arg; break;
    case 'n': env.vni = atoi(arg); break;
    case 'v': env.verbose = true; break;
    case 'h': argp_state_help(state, stderr, ARGP_HELP_STD_HELP); break;
    default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static void sig_handler(int sig) { exiting = true; }

static const char *proto_str(__u8 proto)
{
    switch (proto) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMP";
    default: return "OTHER";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct vxlan_event *e = data;
    char outer_src[INET_ADDRSTRLEN], outer_dst[INET_ADDRSTRLEN];
    char inner_src[INET_ADDRSTRLEN], inner_dst[INET_ADDRSTRLEN];
    struct tm *tm;
    char ts[32];
    time_t t;

    t = e->timestamp / 1000000000ULL;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    __u64 ms = (e->timestamp % 1000000000ULL) / 1000000ULL;

    inet_ntop(AF_INET, &e->outer_src, outer_src, sizeof(outer_src));
    inet_ntop(AF_INET, &e->outer_dst, outer_dst, sizeof(outer_dst));
    inet_ntop(AF_INET, &e->inner_src, inner_src, sizeof(inner_src));
    inet_ntop(AF_INET, &e->inner_dst, inner_dst, sizeof(inner_dst));

    printf("[%s.%03llu] %s CPU%-2u %s(%u) dev=%s len=%u VNI=%u\n",
           ts, (unsigned long long)ms,
           e->direction == DIR_RX ? "RX" : "TX",
           e->cpu, e->comm, e->pid, e->dev_name, e->len, e->vni);

    printf("  Outer: %s:%u -> %s:%u\n",
           outer_src, ntohs(e->outer_sport),
           outer_dst, ntohs(e->outer_dport));

    printf("  Inner: %s", inner_src);
    if (e->inner_proto == 6 || e->inner_proto == 17)
        printf(":%u", ntohs(e->inner_sport));
    printf(" -> %s", inner_dst);
    if (e->inner_proto == 6 || e->inner_proto == 17)
        printf(":%u", ntohs(e->inner_dport));
    printf(" (%s)\n", proto_str(e->inner_proto));

    return 0;
}

int main(int argc, char **argv)
{
    struct vxlan_tracer_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = vxlan_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    if (env.interface) {
        unsigned int ifindex = if_nametoindex(env.interface);
        if (ifindex == 0) {
            fprintf(stderr, "Invalid interface: %s\n", env.interface);
            err = 1;
            goto cleanup;
        }
        skel->rodata->targ_ifindex = ifindex;
    }

    if (env.vni > 0)
        skel->rodata->targ_vni = env.vni;

    err = vxlan_tracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = vxlan_tracer_bpf__attach(skel);
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

    printf("VXLAN Tracer Started\n");
    if (env.interface) printf("Interface: %s\n", env.interface);
    if (env.vni > 0) printf("VNI filter: %d\n", env.vni);
    printf("Monitoring VXLAN ports 4789 and 8472\n");
    printf("Press Ctrl+C to stop\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) break;
    }

    /* Print summary */
    __u64 rx = 0, tx = 0;
    __u32 idx = DIR_RX;
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &idx, &rx);
    idx = DIR_TX;
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.counters), &idx, &tx);

    printf("\nSummary: RX=%llu TX=%llu\n", (unsigned long long)rx, (unsigned long long)tx);

cleanup:
    ring_buffer__free(rb);
    vxlan_tracer_bpf__destroy(skel);
    return err != 0;
}
