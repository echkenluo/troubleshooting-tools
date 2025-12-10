// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// system_network_latency_summary - Network stack latency tracer userspace program

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

#include "system_network_latency_summary.h"
#include "system_network_latency_summary.skel.h"
#include "trace_helpers.h"
#include "histogram.h"
#include "network_helpers.h"

#define PROGRAM_NAME "system_network_latency_summary"

/* Command line options */
static struct env {
    char phy_interface[IFNAMSIZ * 2 + 1];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u8 direction;
    int interval;
    bool verbose;
} env = {
    .interval = 5,
    .verbose = false,
};

static volatile bool exiting = false;
static struct system_network_latency_summary_bpf *skel = NULL;

static const char *argp_program_doc =
    "System Network Adjacent Stage Latency Histogram Tool\n"
    "\n"
    "Measures latency distribution between adjacent network stack stages.\n"
    "\n"
    "USAGE: " PROGRAM_NAME " [OPTIONS]\n"
    "\n"
    "EXAMPLES:\n"
    "    " PROGRAM_NAME " --phy-interface enp94s0f0np0 --direction tx --src-ip 70.0.0.33\n"
    "    " PROGRAM_NAME " --phy-interface eth0 --direction rx --protocol udp --interval 10\n";

static const struct option long_options[] = {
    {"phy-interface", required_argument, NULL, 'I'},
    {"src-ip", required_argument, NULL, 's'},
    {"dst-ip", required_argument, NULL, 'd'},
    {"src-port", required_argument, NULL, 'S'},
    {"dst-port", required_argument, NULL, 'D'},
    {"protocol", required_argument, NULL, 'p'},
    {"direction", required_argument, NULL, 'r'},
    {"interval", required_argument, NULL, 'i'},
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
    printf("  -I, --phy-interface IFACE  Physical interface to monitor (required)\n");
    printf("  -s, --src-ip IP            Source IP address filter\n");
    printf("  -d, --dst-ip IP            Destination IP address filter\n");
    printf("  -S, --src-port PORT        Source port filter\n");
    printf("  -D, --dst-port PORT        Destination port filter\n");
    printf("  -p, --protocol PROTO       Protocol filter (tcp|udp|all)\n");
    printf("  -r, --direction DIR        Direction filter (tx|rx, required)\n");
    printf("  -i, --interval SECS        Statistics interval in seconds (default: 5)\n");
    printf("  -v, --verbose              Enable verbose output\n");
    printf("  -h, --help                 Show this help message\n");
}

static int parse_args(int argc, char **argv)
{
    int opt;

    while ((opt = getopt_long(argc, argv, "I:s:d:S:D:p:r:i:vh",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 'I':
            strncpy(env.phy_interface, optarg, sizeof(env.phy_interface) - 1);
            break;
        case 's':
            if (inet_pton(AF_INET, optarg, &env.src_ip) != 1) {
                fprintf(stderr, "Invalid source IP: %s\n", optarg);
                return -1;
            }
            break;
        case 'd':
            if (inet_pton(AF_INET, optarg, &env.dst_ip) != 1) {
                fprintf(stderr, "Invalid destination IP: %s\n", optarg);
                return -1;
            }
            break;
        case 'S':
            env.src_port = (__u16)atoi(optarg);
            break;
        case 'D':
            env.dst_port = (__u16)atoi(optarg);
            break;
        case 'p':
            if (strcmp(optarg, "tcp") == 0) {
                env.protocol = PROTO_TCP;
            } else if (strcmp(optarg, "udp") == 0) {
                env.protocol = PROTO_UDP;
            } else if (strcmp(optarg, "all") == 0) {
                env.protocol = 0;
            } else {
                fprintf(stderr, "Invalid protocol: %s\n", optarg);
                return -1;
            }
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
        case 'i':
            env.interval = atoi(optarg);
            if (env.interval <= 0) {
                fprintf(stderr, "Invalid interval: %s\n", optarg);
                return -1;
            }
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
    if (env.phy_interface[0] == '\0') {
        fprintf(stderr, "Error: --phy-interface is required\n");
        print_usage();
        return -1;
    }

    if (env.direction == 0) {
        fprintf(stderr, "Error: --direction is required\n");
        print_usage();
        return -1;
    }

    return 0;
}

static void print_histogram_summary(time_t interval_start)
{
    int hist_fd, counters_fd, fsc_fd, flow_fd;
    struct stage_pair_key key, next_key;
    struct stage_pair_hist hist;
    __u64 counters[MAX_COUNTERS] = {};
    __u64 fsc[MAX_FSC] = {};
    time_t now;
    struct tm *tm;
    char time_str[32];
    int ncpus;

    now = time(NULL);
    tm = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n================================================================================\n");
    printf("[%s] System Network Latency Report (Interval: %lds)\n",
           time_str, (long)(now - interval_start));
    printf("================================================================================\n");

    hist_fd = bpf_map__fd(skel->maps.adjacent_latency_hist);
    counters_fd = bpf_map__fd(skel->maps.packet_counters);
    fsc_fd = bpf_map__fd(skel->maps.flow_stage_counters);
    flow_fd = bpf_map__fd(skel->maps.flow_sessions);

    /* Read counters */
    for (int i = 0; i < MAX_COUNTERS; i++) {
        __u32 idx = i;
        bpf_map_lookup_elem(counters_fd, &idx, &counters[i]);
    }

    /* Read flow stage counters */
    for (int i = 0; i < MAX_FSC; i++) {
        __u32 idx = i;
        bpf_map_lookup_elem(fsc_fd, &idx, &fsc[i]);
    }

    /* Collect and print stage pair histograms */
    memset(&key, 0, sizeof(key));
    int pair_count = 0;

    /* Count pairs first */
    while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
        pair_count++;
        key = next_key;
    }

    if (pair_count == 0) {
        printf("No adjacent stage data collected in this interval\n");
    } else {
        printf("Found %d unique stage pairs\n", pair_count);

        /* Print by direction */
        for (int dir = DIRECTION_TX; dir <= DIRECTION_RX; dir++) {
            int found = 0;

            memset(&key, 0, sizeof(key));
            while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
                if (next_key.direction == dir) {
                    if (!found) {
                        printf("\n%s:\n", get_direction_name(dir));
                        printf("------------------------------------------------------------\n");
                        found = 1;
                    }

                    if (bpf_map_lookup_elem(hist_fd, &next_key, &hist) == 0) {
                        printf("\n  %s -> %s:\n",
                               get_stage_name(next_key.prev_stage),
                               get_stage_name(next_key.curr_stage));

                        /* Calculate total samples */
                        __u64 total = 0;
                        for (int i = 0; i < MAX_SLOTS; i++)
                            total += hist.slots[i];

                        if (total > 0) {
                            printf("    Total samples: %lu\n", (unsigned long)total);
                            printf("    Latency distribution:\n");

                            /* Find max for bar scaling */
                            __u64 max_count = 0;
                            for (int i = 0; i < MAX_SLOTS; i++) {
                                if (hist.slots[i] > max_count)
                                    max_count = hist.slots[i];
                            }

                            /* Print histogram */
                            for (int i = 0; i < MAX_SLOTS; i++) {
                                if (hist.slots[i] > 0) {
                                    __u64 low = (i == 0) ? 0 : (1ULL << (i - 1));
                                    __u64 high = (1ULL << i) - 1;
                                    int bar_width = (int)(40 * hist.slots[i] / max_count);

                                    printf("      %6llu-%-6llu us: %6lu |",
                                           (unsigned long long)low,
                                           (unsigned long long)high,
                                           (unsigned long)hist.slots[i]);
                                    for (int j = 0; j < bar_width; j++)
                                        printf("*");
                                    printf("|\n");
                                }
                            }
                        }
                    }
                }
                key = next_key;
            }
        }
    }

    /* Print packet counters */
    printf("\nPacket Counters:\n");
    printf("  TX packets: %lu\n", (unsigned long)counters[COUNTER_TX]);
    printf("  RX packets: %lu\n", (unsigned long)counters[COUNTER_RX]);

    /* Print flow session analysis */
    __u64 incomplete_tx = fsc[FSC_FIRST_TX] - fsc[FSC_LAST_TX];
    __u64 incomplete_rx = fsc[FSC_FIRST_RX] - fsc[FSC_LAST_RX];

    printf("\nFlow Session Analysis:\n");
    if (fsc[FSC_FIRST_TX] > 0) {
        printf("  TX started: %lu, completed: %lu, incomplete: %lu (%.2f%%)\n",
               (unsigned long)fsc[FSC_FIRST_TX],
               (unsigned long)fsc[FSC_LAST_TX],
               (unsigned long)incomplete_tx,
               fsc[FSC_FIRST_TX] > 0 ? 100.0 * incomplete_tx / fsc[FSC_FIRST_TX] : 0);
    }
    if (fsc[FSC_FIRST_RX] > 0) {
        printf("  RX started: %lu, completed: %lu, incomplete: %lu (%.2f%%)\n",
               (unsigned long)fsc[FSC_FIRST_RX],
               (unsigned long)fsc[FSC_LAST_RX],
               (unsigned long)incomplete_rx,
               fsc[FSC_FIRST_RX] > 0 ? 100.0 * incomplete_rx / fsc[FSC_FIRST_RX] : 0);
    }

    /* Print total latency histogram */
    printf("\nTotal End-to-End Latency Distribution:\n");
    printf("------------------------------------------------------------\n");

    ncpus = libbpf_num_possible_cpus();
    if (ncpus < 0) {
        printf("  Error: failed to get CPU count\n");
    } else {
        struct total_hist *percpu_hist = calloc(ncpus, sizeof(struct total_hist));
        if (percpu_hist) {
            __u32 total_key = 0;
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.total_latency_hist),
                                    &total_key, percpu_hist) == 0) {
                /* Aggregate per-CPU histograms */
                __u64 total_slots[MAX_SLOTS] = {};
                for (int cpu = 0; cpu < ncpus; cpu++) {
                    for (int i = 0; i < MAX_SLOTS; i++) {
                        total_slots[i] += percpu_hist[cpu].slots[i];
                    }
                }

                /* Check if we have any data */
                __u64 total_count = 0;
                for (int i = 0; i < MAX_SLOTS; i++)
                    total_count += total_slots[i];

                if (total_count > 0) {
                    __u64 max_count = 0;
                    for (int i = 0; i < MAX_SLOTS; i++) {
                        if (total_slots[i] > max_count)
                            max_count = total_slots[i];
                    }

                    for (int i = 0; i < MAX_SLOTS; i++) {
                        if (total_slots[i] > 0) {
                            __u64 low = (i == 0) ? 1 : (1ULL << (i - 1));
                            __u64 high = (1ULL << i) - 1;
                            int bar_width = (int)(40 * total_slots[i] / max_count);

                            printf("  %6llu-%-6llu us: %6lu |",
                                   (unsigned long long)low,
                                   (unsigned long long)high,
                                   (unsigned long)total_slots[i]);
                            for (int j = 0; j < bar_width; j++)
                                printf("*");
                            printf("|\n");
                        }
                    }
                } else {
                    printf("  No total latency data collected in this interval\n");
                }
            }
            free(percpu_hist);
        }
    }

    /* Clear histograms for next interval */
    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(hist_fd, &next_key);
        key = next_key;
    }

    /* Clear total histogram */
    ncpus = libbpf_num_possible_cpus();
    if (ncpus > 0) {
        struct total_hist *zero = calloc(ncpus, sizeof(struct total_hist));
        if (zero) {
            __u32 total_key = 0;
            bpf_map_update_elem(bpf_map__fd(skel->maps.total_latency_hist),
                               &total_key, zero, BPF_ANY);
            free(zero);
        }
    }
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
    int ifindex1 = 0, ifindex2 = 0;
    int err;
    time_t interval_start;

    /* Parse arguments */
    err = parse_args(argc, argv);
    if (err)
        return err;

    /* Check root */
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return 1;
    }

    /* Get interface indices */
    err = parse_interfaces(env.phy_interface, &ifindex1, &ifindex2);
    if (err) {
        fprintf(stderr, "Failed to get interface index\n");
        return 1;
    }

    /* Setup libbpf */
    libbpf_set_print(libbpf_print_callback);

    /* Bump rlimit */
    if (bump_memlock_rlimit()) {
        fprintf(stderr, "Failed to increase rlimit\n");
        return 1;
    }

    /* Open BPF skeleton */
    skel = system_network_latency_summary_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    skel->rodata->targ_src_ip = env.src_ip;
    skel->rodata->targ_dst_ip = env.dst_ip;
    skel->rodata->targ_src_port = env.src_port;
    skel->rodata->targ_dst_port = env.dst_port;
    skel->rodata->targ_protocol = env.protocol;
    skel->rodata->targ_direction = env.direction;
    skel->rodata->targ_ifindex1 = ifindex1;
    skel->rodata->targ_ifindex2 = ifindex2;

    /* Load BPF program */
    err = system_network_latency_summary_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach BPF programs */
    err = system_network_latency_summary_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    /* Print configuration */
    printf("=== System Network Adjacent Stage Latency Histogram Tool ===\n");
    printf("Protocol filter: %s\n",
           env.protocol == PROTO_TCP ? "TCP" :
           env.protocol == PROTO_UDP ? "UDP" : "ALL");
    printf("Direction filter: %s (tx=System->Physical, rx=Physical->System)\n",
           env.direction == DIRECTION_TX ? "TX" : "RX");
    if (env.src_ip) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &env.src_ip, buf, sizeof(buf));
        printf("Source IP filter: %s\n", buf);
    }
    if (env.dst_ip) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &env.dst_ip, buf, sizeof(buf));
        printf("Destination IP filter: %s\n", buf);
    }
    if (env.src_port)
        printf("Source port filter: %u\n", env.src_port);
    if (env.dst_port)
        printf("Destination port filter: %u\n", env.dst_port);
    printf("Physical interfaces: %s (ifindex %d, %d)\n",
           env.phy_interface, ifindex1, ifindex2);
    printf("Statistics interval: %d seconds\n", env.interval);
    printf("Mode: Adjacent stage latency tracking only\n");
    printf("\nCollecting adjacent stage latency data... Hit Ctrl-C to end.\n");
    printf("Statistics will be displayed every %d seconds\n", env.interval);

    /* Setup signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Main loop */
    interval_start = time(NULL);

    while (!exiting) {
        sleep(env.interval);
        print_histogram_summary(interval_start);
        interval_start = time(NULL);
    }

    /* Final output */
    printf("\n\nFinal statistics:\n");
    print_histogram_summary(interval_start);

cleanup:
    system_network_latency_summary_bpf__destroy(skel);
    printf("\nExiting...\n");

    return err != 0;
}
