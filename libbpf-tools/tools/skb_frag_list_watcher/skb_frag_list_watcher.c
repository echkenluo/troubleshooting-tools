// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// skb_frag_list_watcher - SKB frag_list change monitor

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
#include "skb_frag_list_watcher.h"
#include "skb_frag_list_watcher.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *interface;
    char *src_ip;
    char *dst_ip;
    bool gso_only;
    bool stack_trace;
    bool verbose;
} env = {0};

const char *argp_program_version = "skb_frag_list_watcher 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Monitor SKB frag_list changes for GSO debugging.\n"
"\n"
"USAGE: skb_frag_list_watcher [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    skb_frag_list_watcher                    # Monitor all frag_list changes\n"
"    skb_frag_list_watcher --gso-only         # Filter GSO packets only\n"
"    skb_frag_list_watcher --stack-trace      # Include stack traces\n";

static const struct argp_option opts[] = {
    { "interface", 'i', "DEV", 0, "Target interface" },
    { "src-ip", 's', "IP", 0, "Source IP filter" },
    { "dst-ip", 'd', "IP", 0, "Destination IP filter" },
    { "gso-only", 'g', NULL, 0, "Filter GSO packets only" },
    { "stack-trace", 't', NULL, 0, "Enable stack traces" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i': env.interface = arg; break;
    case 's': env.src_ip = arg; break;
    case 'd': env.dst_ip = arg; break;
    case 'g': env.gso_only = true; break;
    case 't': env.stack_trace = true; break;
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

static const char *event_type_str(__u8 type)
{
    switch (type) {
    case EVENT_FRAG_LIST_CREATE: return "CREATE";
    case EVENT_FRAG_LIST_CLEAR: return "CLEAR";
    case EVENT_FRAG_LIST_MODIFY: return "MODIFY";
    case EVENT_FRAG_LIST_ACCESS: return "ACCESS";
    case EVENT_GSO_INCONSISTENT: return "INCONSISTENT";
    default: return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct frag_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    t = e->timestamp_ns / 1000000000ULL;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    __u64 ns = (e->timestamp_ns % 1000000000ULL) / 1000000ULL;

    printf("[%s.%03llu] CPU%-2u %s(%u) %s | SKB=0x%llx | frag_list: 0x%llx -> 0x%llx",
           ts, (unsigned long long)ns, e->cpu, e->comm, e->pid,
           e->func_name, (unsigned long long)e->skb_addr,
           (unsigned long long)e->frag_list_before,
           (unsigned long long)e->frag_list_after);

    printf(" | gso_type=0x%x gso_size=%u gso_segs=%u nr_frags=%u",
           e->gso_type, e->gso_size, e->gso_segs, e->nr_frags);

    printf(" [%s]\n", event_type_str(e->event_type));

    if (e->event_type == EVENT_GSO_INCONSISTENT)
        printf("  ^^^ WARNING: frag_list NULL but gso_size=%u > 0 ^^^\n", e->gso_size);

    return 0;
}

int main(int argc, char **argv)
{
    struct skb_frag_list_watcher_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = skb_frag_list_watcher_bpf__open();
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

    skel->rodata->gso_only = env.gso_only ? 1 : 0;
    skel->rodata->enable_stack_trace = env.stack_trace ? 1 : 0;

    err = skb_frag_list_watcher_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = skb_frag_list_watcher_bpf__attach(skel);
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

    printf("SKB frag_list Watcher Started\n");
    printf("Monitoring: skb_gro_receive_list, skb_segment_list, skb_segment, __skb_linearize\n");
    printf("Press Ctrl+C to stop\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) break;
    }

cleanup:
    ring_buffer__free(rb);
    skb_frag_list_watcher_bpf__destroy(skel);
    return err != 0;
}
