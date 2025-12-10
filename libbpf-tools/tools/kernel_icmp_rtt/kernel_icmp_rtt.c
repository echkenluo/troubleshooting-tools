// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kernel_icmp_rtt - ICMP RTT tracer for kernel network stack userspace program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "kernel_icmp_rtt.h"
#include "kernel_icmp_rtt.skel.h"
#include "trace_helpers.h"

#define PROGRAM_NAME "kernel_icmp_rtt"

/* Command line options */
static struct env {
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    __u32 src_ip;
    __u32 dst_ip;
    char interface[IFNAMSIZ];
    double latency_ms;
    __u8 direction;
    bool disable_kernel_stacks;
    bool verbose;
} env = {
    .latency_ms = 0,
    .direction = DIRECTION_TX,
    .disable_kernel_stacks = false,
    .verbose = false,
};

static volatile bool exiting = false;
static struct kernel_icmp_rtt_bpf *skel = NULL;

static const char *argp_program_doc =
    "Kernel ICMP RTT Tracer\n"
    "\n"
    "Traces ICMP packets through kernel network stack (no OVS).\n"
    "\n"
    "USAGE: " PROGRAM_NAME " [OPTIONS]\n"
    "\n"
    "EXAMPLES:\n"
    "    # TX mode (local ping remote):\n"
    "    " PROGRAM_NAME " --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --interface eth0 --direction tx\n"
    "\n"
    "    # RX mode (remote ping local):\n"
    "    " PROGRAM_NAME " --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --interface eth0 --direction rx\n"
    "\n"
    "    # With latency threshold:\n"
    "    " PROGRAM_NAME " --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --latency-ms 10\n";

static const struct option long_options[] = {
    {"src-ip", required_argument, NULL, 's'},
    {"dst-ip", required_argument, NULL, 'd'},
    {"interface", required_argument, NULL, 'i'},
    {"latency-ms", required_argument, NULL, 'l'},
    {"direction", required_argument, NULL, 'r'},
    {"disable-kernel-stacks", no_argument, NULL, 'k'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_usage(void)
{
    printf("%s", argp_program_doc);
    printf("\nOptions:\n");
    printf("  -s, --src-ip IP            Local IP address (required)\n");
    printf("  -d, --dst-ip IP            Remote IP address (required)\n");
    printf("  -i, --interface IFACE      Network interface to monitor\n");
    printf("  -l, --latency-ms MS        Minimum RTT latency threshold in ms\n");
    printf("  -r, --direction DIR        Direction: tx (local pings remote) or rx (remote pings local)\n");
    printf("  -k, --disable-kernel-stacks Disable kernel stack trace output\n");
    printf("  -v, --verbose              Enable verbose output\n");
    printf("  -h, --help                 Show this help message\n");
}

static int parse_args(int argc, char **argv)
{
    int opt;

    while ((opt = getopt_long(argc, argv, "s:d:i:l:r:kvh",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 's':
            strncpy(env.src_ip_str, optarg, sizeof(env.src_ip_str) - 1);
            if (inet_pton(AF_INET, optarg, &env.src_ip) != 1) {
                fprintf(stderr, "Invalid source IP: %s\n", optarg);
                return -1;
            }
            break;
        case 'd':
            strncpy(env.dst_ip_str, optarg, sizeof(env.dst_ip_str) - 1);
            if (inet_pton(AF_INET, optarg, &env.dst_ip) != 1) {
                fprintf(stderr, "Invalid destination IP: %s\n", optarg);
                return -1;
            }
            break;
        case 'i':
            strncpy(env.interface, optarg, sizeof(env.interface) - 1);
            break;
        case 'l':
            env.latency_ms = atof(optarg);
            break;
        case 'r':
            if (strcmp(optarg, "tx") == 0) {
                env.direction = DIRECTION_TX;
            } else if (strcmp(optarg, "rx") == 0) {
                env.direction = DIRECTION_RX;
            } else {
                fprintf(stderr, "Invalid direction: %s\n", optarg);
                return -1;
            }
            break;
        case 'k':
            env.disable_kernel_stacks = true;
            break;
        case 'v':
            env.verbose = true;
            break;
        case 'h':
            print_usage();
            exit(0);
        default:
            print_usage();
            return -1;
        }
    }

    /* Validate required arguments */
    if (env.src_ip_str[0] == '\0') {
        fprintf(stderr, "Error: --src-ip is required\n");
        print_usage();
        return -1;
    }

    if (env.dst_ip_str[0] == '\0') {
        fprintf(stderr, "Error: --dst-ip is required\n");
        print_usage();
        return -1;
    }

    return 0;
}

static const char *get_stage_name(int stage_id, int direction)
{
    if (direction == DIRECTION_TX) {
        switch (stage_id) {
        case PATH1_STAGE_0: return "P1:S0 (ip_local_out)";
        case PATH1_STAGE_1: return "P1:S1 (dev_queue_xmit)";
        case PATH1_STAGE_2: return "P1:S2 (unused)";
        case PATH2_STAGE_0: return "P2:S0 (__netif_receive_skb)";
        case PATH2_STAGE_1: return "P2:S1 (ip_rcv)";
        case PATH2_STAGE_2: return "P2:S2 (icmp_rcv)";
        default: return "Unknown";
        }
    } else {
        switch (stage_id) {
        case PATH1_STAGE_0: return "P1:S0 (__netif_receive_skb)";
        case PATH1_STAGE_1: return "P1:S1 (ip_rcv)";
        case PATH1_STAGE_2: return "P1:S2 (icmp_rcv)";
        case PATH2_STAGE_0: return "P2:S0 (unused)";
        case PATH2_STAGE_1: return "P2:S1 (ip_local_out)";
        case PATH2_STAGE_2: return "P2:S2 (dev_queue_xmit)";
        default: return "Unknown";
        }
    }
}

static const char *format_latency(__u64 ts_start, __u64 ts_end)
{
    static char buf[32];

    if (ts_start == 0 || ts_end == 0) {
        return "   N/A ";
    }

    double delta_us = (double)(ts_end - ts_start) / 1000.0;
    snprintf(buf, sizeof(buf), "%7.3f", delta_us);
    return buf;
}

static void print_stack_trace(int stack_id, int stage_idx)
{
    int stack_map_fd;

    printf("  Stage %d (%s):\n", stage_idx, get_stage_name(stage_idx, env.direction));

    if (stack_id <= 0) {
        printf("    <No stack trace: id=%d>\n", stack_id);
        return;
    }

    stack_map_fd = bpf_map__fd(skel->maps.stack_traces);
    print_stack_trace(stack_map_fd, stack_id);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct icmp_rtt_event *event = data;
    struct icmp_packet_key *key = &event->key;
    struct icmp_flow_data *flow = &event->data;
    char time_str[64];
    time_t now;
    struct tm *tm;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    const char *dir_str;

    now = time(NULL);
    tm = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

    inet_ntop(AF_INET, &key->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &key->dst_ip, dst_ip, sizeof(dst_ip));

    dir_str = (env.direction == DIRECTION_TX) ? "TX (Local -> Remote)" : "RX (Remote -> Local)";

    printf("================================================================================\n");
    printf("=== ICMP RTT Trace: %s (%s) ===\n", time_str, dir_str);
    printf("Session: %s -> %s (ID: %d, Seq: %d)\n",
           src_ip, dst_ip, ntohs(key->id), ntohs(key->seq));

    /* Path descriptions */
    const char *path1_desc, *path2_desc;
    if (env.direction == DIRECTION_TX) {
        path1_desc = "Path 1 (Request: TX to remote)";
        path2_desc = "Path 2 (Reply: RX from remote)";
    } else {
        path1_desc = "Path 1 (Request: RX from remote)";
        path2_desc = "Path 2 (Reply: TX to remote)";
    }

    printf("%-45s: PID=%-6u COMM=%-12s IF=%-10s ICMP_Type=%u\n",
           path1_desc, flow->p1_pid, flow->p1_comm, flow->p1_ifname, flow->request_type);

    printf("%-45s: PID=%-6u COMM=%-12s IF=%-10s ICMP_Type=%u\n",
           path2_desc, flow->p2_pid, flow->p2_comm, flow->p2_ifname, flow->reply_type);

    /* Path 1 latencies */
    printf("\nPath 1 Latencies (us):\n");
    printf("  [0->1] %-40s -> %-40s: %s us\n",
           get_stage_name(0, env.direction),
           get_stage_name(1, env.direction),
           format_latency(flow->ts[0], flow->ts[1]));

    if (env.direction == DIRECTION_RX) {
        printf("  [1->2] %-40s -> %-40s: %s us\n",
               get_stage_name(1, env.direction),
               get_stage_name(2, env.direction),
               format_latency(flow->ts[1], flow->ts[2]));

        if (flow->ts[0] > 0 && flow->ts[2] > 0) {
            printf("  Total Path 1: %s us\n", format_latency(flow->ts[0], flow->ts[2]));
        }
    } else {
        if (flow->ts[0] > 0 && flow->ts[1] > 0) {
            printf("  Total Path 1: %s us\n", format_latency(flow->ts[0], flow->ts[1]));
        }
    }

    /* Path 2 latencies */
    printf("\nPath 2 Latencies (us):\n");
    if (env.direction == DIRECTION_TX) {
        printf("  [3->4] %-40s -> %-40s: %s us\n",
               get_stage_name(3, env.direction),
               get_stage_name(4, env.direction),
               format_latency(flow->ts[3], flow->ts[4]));
        printf("  [4->5] %-40s -> %-40s: %s us\n",
               get_stage_name(4, env.direction),
               get_stage_name(5, env.direction),
               format_latency(flow->ts[4], flow->ts[5]));

        if (flow->ts[3] > 0 && flow->ts[5] > 0) {
            printf("  Total Path 2: %s us\n", format_latency(flow->ts[3], flow->ts[5]));
        }
    } else {
        printf("  [4->5] %-40s -> %-40s: %s us\n",
               get_stage_name(4, env.direction),
               get_stage_name(5, env.direction),
               format_latency(flow->ts[4], flow->ts[5]));

        if (flow->ts[4] > 0 && flow->ts[5] > 0) {
            printf("  Total Path 2: %s us\n", format_latency(flow->ts[4], flow->ts[5]));
        }
    }

    /* Total RTT */
    if (flow->ts[0] > 0 && flow->ts[5] > 0) {
        printf("\nTotal RTT (Path1 Start to Path2 End): %s us\n",
               format_latency(flow->ts[0], flow->ts[5]));

        /* Inter-path latency */
        if (env.direction == DIRECTION_TX && flow->ts[1] > 0 && flow->ts[3] > 0) {
            printf("Inter-Path Latency (P1 end -> P2 start): %s us\n",
                   format_latency(flow->ts[1], flow->ts[3]));
        }
        if (env.direction == DIRECTION_RX && flow->ts[2] > 0 && flow->ts[4] > 0) {
            printf("Inter-Path Latency (P1 end -> P2 start): %s us\n",
                   format_latency(flow->ts[2], flow->ts[4]));
        }
    }

    /* Kernel stack traces */
    if (!env.disable_kernel_stacks) {
        printf("\nKernel Stack Traces:\n");
        for (int i = 0; i < MAX_STAGES; i++) {
            if (flow->ts[i] != 0) {
                print_stack_trace(flow->kstack_id[i], i);
            }
        }
    }

    printf("================================================================================\n\n");

    return 0;
}

static int libbpf_print_callback(enum libbpf_print_level level,
                                  const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int ifindex = 0;
    int err;

    err = parse_args(argc, argv);
    if (err)
        return err;

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return 1;
    }

    /* Get interface index if specified */
    if (env.interface[0] != '\0') {
        ifindex = if_nametoindex(env.interface);
        if (ifindex == 0) {
            fprintf(stderr, "Failed to get ifindex for %s: %s\n",
                    env.interface, strerror(errno));
            return 1;
        }
    }

    libbpf_set_print(libbpf_print_callback);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "Failed to increase rlimit\n");
        return 1;
    }

    if (ksyms_init()) {
        fprintf(stderr, "Failed to initialize kernel symbols\n");
        return 1;
    }

    skel = kernel_icmp_rtt_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    /* Set configuration */
    skel->rodata->targ_src_ip = env.src_ip;
    skel->rodata->targ_dst_ip = env.dst_ip;
    skel->rodata->targ_latency_threshold_ns = (__u64)(env.latency_ms * 1000000);
    skel->rodata->targ_ifindex = ifindex;
    skel->rodata->targ_direction = env.direction;

    err = kernel_icmp_rtt_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = kernel_icmp_rtt_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    /* Setup ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    /* Print configuration */
    printf("=== Kernel ICMP RTT Tracer ===\n");
    printf("Trace Direction: %s\n", env.direction == DIRECTION_TX ? "TX" : "RX");
    printf("SRC_IP_FILTER (Local IP): %s\n", env.src_ip_str);
    printf("DST_IP_FILTER (Remote IP): %s\n", env.dst_ip_str);

    if (env.interface[0] != '\0') {
        printf("Monitoring interface: %s (ifindex %d)\n", env.interface, ifindex);
    } else {
        printf("Monitoring all interfaces\n");
    }

    if (env.latency_ms > 0) {
        printf("Reporting only RTT >= %.3f ms\n", env.latency_ms);
    }

    printf("\nTracing ICMP RTT (src=%s, dst=%s, dir=%s) ... Hit Ctrl-C to end.\n",
           env.src_ip_str, env.dst_ip_str,
           env.direction == DIRECTION_TX ? "tx" : "rx");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

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
    kernel_icmp_rtt_bpf__destroy(skel);
    ksyms_cleanup();

    printf("\nExiting.\n");

    return err != 0;
}
