// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// vm_network_latency_summary - VM Network stack latency tracer userspace program

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

#include "vm_network_latency_summary.h"
#include "vm_network_latency_summary.skel.h"
#include "trace_helpers.h"
#include "histogram.h"

#define PROGRAM_NAME "vm_network_latency_summary"

/* Stage name mapping */
static const char *stage_names[] = {
    [0]  = "UNKNOWN",
    [STG_VNET_RX] = "STG_VNET_RX",
    [STG_OVS_RX] = "STG_OVS_RX",
    [STG_FLOW_EXTRACT_END_RX] = "STG_FLOW_EXTRACT_END_RX",
    [STG_OVS_UPCALL_RX] = "STG_OVS_UPCALL_RX",
    [STG_OVS_USERSPACE_RX] = "STG_OVS_USERSPACE_RX",
    [STG_CT_RX] = "STG_CT_RX",
    [STG_CT_OUT_RX] = "STG_CT_OUT_RX",
    [STG_QDISC_ENQ] = "STG_QDISC_ENQ",
    [STG_QDISC_DEQ] = "STG_QDISC_DEQ",
    [STG_TX_QUEUE] = "STG_TX_QUEUE",
    [STG_TX_XMIT] = "STG_TX_XMIT",
    [STG_PHY_RX] = "STG_PHY_RX",
    [STG_OVS_TX] = "STG_OVS_TX",
    [STG_FLOW_EXTRACT_END_TX] = "STG_FLOW_EXTRACT_END_TX",
    [STG_OVS_UPCALL_TX] = "STG_OVS_UPCALL_TX",
    [STG_OVS_USERSPACE_TX] = "STG_OVS_USERSPACE_TX",
    [STG_CT_TX] = "STG_CT_TX",
    [STG_CT_OUT_TX] = "STG_CT_OUT_TX",
    [STG_VNET_QDISC_ENQ] = "STG_VNET_QDISC_ENQ",
    [STG_VNET_QDISC_DEQ] = "STG_VNET_QDISC_DEQ",
    [STG_VNET_TX] = "STG_VNET_TX",
};

/* Command line options */
static struct env {
    char vm_interface[IFNAMSIZ];
    char phy_interface[IFNAMSIZ];
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
static struct vm_network_latency_summary_bpf *skel = NULL;

static const char *argp_program_doc =
    "VM Network Adjacent Stage Latency Histogram Tool\n"
    "\n"
    "Measures latency distribution between adjacent network stack stages.\n"
    "\n"
    "USAGE: " PROGRAM_NAME " [OPTIONS]\n"
    "\n"
    "EXAMPLES:\n"
    "    " PROGRAM_NAME " --vm-interface vnet0 --phy-interface eth0 --direction rx\n"
    "    " PROGRAM_NAME " --vm-interface vnet37 --phy-interface enp0s31f6 --direction tx --src-ip 192.168.76.198\n";

static const struct option long_options[] = {
    {"vm-interface", required_argument, NULL, 'V'},
    {"phy-interface", required_argument, NULL, 'P'},
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
    printf("  -V, --vm-interface IFACE   VM interface to monitor (required)\n");
    printf("  -P, --phy-interface IFACE  Physical interface to monitor (required)\n");
    printf("  -s, --src-ip IP            Source IP address filter\n");
    printf("  -d, --dst-ip IP            Destination IP address filter\n");
    printf("  -S, --src-port PORT        Source port filter\n");
    printf("  -D, --dst-port PORT        Destination port filter\n");
    printf("  -p, --protocol PROTO       Protocol filter (tcp|udp|icmp|all)\n");
    printf("  -r, --direction DIR        Direction filter (rx|tx, required)\n");
    printf("                              rx = VNET RX (VM TX, VM->External)\n");
    printf("                              tx = VNET TX (VM RX, External->VM)\n");
    printf("  -i, --interval SECS        Statistics interval in seconds (default: 5)\n");
    printf("  -v, --verbose              Enable verbose output\n");
    printf("  -h, --help                 Show this help message\n");
}

static const char *get_stage_name(int stage_id)
{
    if (stage_id >= 0 && stage_id < MAX_STAGES && stage_names[stage_id])
        return stage_names[stage_id];
    return "UNKNOWN";
}

static int parse_args(int argc, char **argv)
{
    int opt;

    while ((opt = getopt_long(argc, argv, "V:P:s:d:S:D:p:r:i:vh",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 'V':
            strncpy(env.vm_interface, optarg, sizeof(env.vm_interface) - 1);
            break;
        case 'P':
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
            } else if (strcmp(optarg, "icmp") == 0) {
                env.protocol = PROTO_ICMP;
            } else if (strcmp(optarg, "all") == 0) {
                env.protocol = 0;
            } else {
                fprintf(stderr, "Invalid protocol: %s\n", optarg);
                return -1;
            }
            break;
        case 'r':
            if (strcmp(optarg, "rx") == 0) {
                env.direction = DIRECTION_VNET_RX;
            } else if (strcmp(optarg, "tx") == 0) {
                env.direction = DIRECTION_VNET_TX;
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
    if (env.vm_interface[0] == '\0') {
        fprintf(stderr, "Error: --vm-interface is required\n");
        print_usage();
        return -1;
    }

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
    int hist_fd, counters_fd, fsc_fd;
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
    printf("[%s] VM Network Latency Report (Interval: %lds)\n",
           time_str, (long)(now - interval_start));
    printf("================================================================================\n");

    hist_fd = bpf_map__fd(skel->maps.adjacent_latency_hist);
    counters_fd = bpf_map__fd(skel->maps.packet_counters);
    fsc_fd = bpf_map__fd(skel->maps.flow_stage_counters);

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

    /* Count pairs */
    memset(&key, 0, sizeof(key));
    int pair_count = 0;
    while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
        pair_count++;
        key = next_key;
    }

    if (pair_count == 0) {
        printf("No adjacent stage data collected in this interval\n");
    } else {
        printf("Found %d unique stage pairs\n", pair_count);

        /* Print by direction */
        for (int dir = DIRECTION_VNET_RX; dir <= DIRECTION_VNET_TX; dir++) {
            int found = 0;

            memset(&key, 0, sizeof(key));
            while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
                if (next_key.direction == dir) {
                    if (!found) {
                        const char *dir_name = (dir == DIRECTION_VNET_RX) ?
                            "VNET RX Direction (VM TX: VM -> External)" :
                            "VNET TX Direction (VM RX: External -> VM)";
                        printf("\n%s:\n", dir_name);
                        printf("------------------------------------------------------------\n");
                        found = 1;
                    }

                    if (bpf_map_lookup_elem(hist_fd, &next_key, &hist) == 0) {
                        printf("\n  %s -> %s:\n",
                               get_stage_name(next_key.prev_stage),
                               get_stage_name(next_key.curr_stage));

                        __u64 total = 0;
                        for (int i = 0; i < MAX_SLOTS; i++)
                            total += hist.slots[i];

                        if (total > 0) {
                            printf("    Total samples: %lu\n", (unsigned long)total);
                            printf("    Latency distribution:\n");

                            __u64 max_count = 0;
                            for (int i = 0; i < MAX_SLOTS; i++) {
                                if (hist.slots[i] > max_count)
                                    max_count = hist.slots[i];
                            }

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

    /* Print counters */
    printf("\nPacket Counters:\n");
    printf("  VNET RX (VM TX): %lu\n", (unsigned long)counters[COUNTER_VNET_RX]);
    printf("  VNET TX (VM RX): %lu\n", (unsigned long)counters[COUNTER_VNET_TX]);

    /* Print flow session analysis */
    printf("\nFlow Session Analysis:\n");
    if (fsc[FSC_FIRST_RX] > 0) {
        __u64 incomplete = fsc[FSC_FIRST_RX] - fsc[FSC_LAST_RX];
        printf("  VNET RX started: %lu, completed: %lu, incomplete: %lu (%.2f%%)\n",
               (unsigned long)fsc[FSC_FIRST_RX],
               (unsigned long)fsc[FSC_LAST_RX],
               (unsigned long)incomplete,
               fsc[FSC_FIRST_RX] > 0 ? 100.0 * incomplete / fsc[FSC_FIRST_RX] : 0);
    }
    if (fsc[FSC_FIRST_TX] > 0) {
        __u64 incomplete = fsc[FSC_FIRST_TX] - fsc[FSC_LAST_TX];
        printf("  VNET TX started: %lu, completed: %lu, incomplete: %lu (%.2f%%)\n",
               (unsigned long)fsc[FSC_FIRST_TX],
               (unsigned long)fsc[FSC_LAST_TX],
               (unsigned long)incomplete,
               fsc[FSC_FIRST_TX] > 0 ? 100.0 * incomplete / fsc[FSC_FIRST_TX] : 0);
    }

    /* Print total latency histogram */
    printf("\nTotal End-to-End Latency Distribution:\n");
    printf("------------------------------------------------------------\n");

    ncpus = libbpf_num_possible_cpus();
    if (ncpus > 0) {
        struct total_hist *percpu_hist = calloc(ncpus, sizeof(struct total_hist));
        if (percpu_hist) {
            __u32 total_key = 0;
            if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.total_latency_hist),
                                    &total_key, percpu_hist) == 0) {
                __u64 total_slots[MAX_SLOTS] = {};
                for (int cpu = 0; cpu < ncpus; cpu++) {
                    for (int i = 0; i < MAX_SLOTS; i++) {
                        total_slots[i] += percpu_hist[cpu].slots[i];
                    }
                }

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

    /* Clear histograms */
    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(hist_fd, &next_key);
        key = next_key;
    }

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
    int vm_ifindex = 0, phy_ifindex = 0;
    int err;
    time_t interval_start;

    err = parse_args(argc, argv);
    if (err)
        return err;

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return 1;
    }

    /* Get interface indices */
    vm_ifindex = if_nametoindex(env.vm_interface);
    if (vm_ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n",
                env.vm_interface, strerror(errno));
        return 1;
    }

    phy_ifindex = if_nametoindex(env.phy_interface);
    if (phy_ifindex == 0) {
        fprintf(stderr, "Failed to get ifindex for %s: %s\n",
                env.phy_interface, strerror(errno));
        return 1;
    }

    libbpf_set_print(libbpf_print_callback);

    if (bump_memlock_rlimit()) {
        fprintf(stderr, "Failed to increase rlimit\n");
        return 1;
    }

    skel = vm_network_latency_summary_bpf__open();
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
    skel->rodata->targ_vm_ifindex = vm_ifindex;
    skel->rodata->targ_phy_ifindex = phy_ifindex;

    err = vm_network_latency_summary_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = vm_network_latency_summary_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    /* Print configuration */
    printf("=== VM Network Adjacent Stage Latency Histogram Tool ===\n");
    printf("VM interface: %s (ifindex %d)\n", env.vm_interface, vm_ifindex);
    printf("Physical interface: %s (ifindex %d)\n", env.phy_interface, phy_ifindex);
    printf("Direction: %s\n",
           env.direction == DIRECTION_VNET_RX ? "VNET RX (VM TX)" : "VNET TX (VM RX)");
    printf("Protocol filter: %s\n",
           env.protocol == PROTO_TCP ? "TCP" :
           env.protocol == PROTO_UDP ? "UDP" :
           env.protocol == PROTO_ICMP ? "ICMP" : "ALL");
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
    printf("Statistics interval: %d seconds\n", env.interval);
    printf("\nCollecting data... Hit Ctrl-C to end.\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    interval_start = time(NULL);

    while (!exiting) {
        sleep(env.interval);
        print_histogram_summary(interval_start);
        interval_start = time(NULL);
    }

    printf("\n\nFinal statistics:\n");
    print_histogram_summary(interval_start);

cleanup:
    vm_network_latency_summary_bpf__destroy(skel);
    printf("\nExiting...\n");

    return err != 0;
}
