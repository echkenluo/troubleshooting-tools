// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// eth_drop - Network packet drop tracer userspace program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "eth_drop.h"
#include "eth_drop.skel.h"
#include "trace_helpers.h"

#define PROGRAM_NAME "eth_drop"

/* Protocol name mappings */
static const struct {
    const char *name;
    __u16 value;
} protocol_map[] = {
    {"arp", 0x0806},
    {"rarp", 0x8035},
    {"ipv4", 0x0800},
    {"ipv6", 0x86DD},
    {"lldp", 0x88CC},
    {"flow_control", 0x8808},
    {"other", 0xFFFF},
    {NULL, 0}
};

/* L4 protocol mappings */
static const struct {
    const char *name;
    __u8 value;
} l4_protocol_map[] = {
    {"all", 0},
    {"icmp", 1},
    {"tcp", 6},
    {"udp", 17},
    {NULL, 0}
};

/* Normal kfree patterns to filter */
static const char *normal_patterns[][2] = {
    {"kfree_skb", "icmp_rcv"},
    {"kfree_skb", "tcp_v4_rcv"},
    {"kfree_skb", "tcp_v4_do_rcv"},
    {"kfree_skb", "skb_release_data"},
    {"kfree_skb", "__kfree_skb"},
    {"kfree_skb", "tcp_recvmsg"},
    {"kfree_skb", "sk_stream_kill_queues"},
    {NULL, NULL}
};

/* Command line options */
static struct env {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 protocol;
    __u8 l4_protocol;
    __u16 vlan_id;
    char ifname[IFNAMSIZ];
    bool verbose;
    bool no_stack_trace;
    bool disable_normal_filter;
} env = {
    .verbose = false,
    .no_stack_trace = false,
    .disable_normal_filter = false,
};

static volatile bool exiting = false;
static struct eth_drop_bpf *skel = NULL;

static const char *argp_program_doc =
    "Enhanced network packet drop tracing with protocol filtering.\n"
    "\n"
    "USAGE: " PROGRAM_NAME " [OPTIONS]\n"
    "\n"
    "EXAMPLES:\n"
    "    " PROGRAM_NAME " --type ipv4 --src-ip 10.0.0.1\n"
    "    " PROGRAM_NAME " --l4-protocol tcp --dst-port 80\n"
    "    " PROGRAM_NAME " --interface eth0 --verbose\n";

static const struct option long_options[] = {
    {"type", required_argument, NULL, 't'},
    {"l4-protocol", required_argument, NULL, 'p'},
    {"src-ip", required_argument, NULL, 's'},
    {"dst-ip", required_argument, NULL, 'd'},
    {"src-port", required_argument, NULL, 'S'},
    {"dst-port", required_argument, NULL, 'D'},
    {"vlan-id", required_argument, NULL, 'V'},
    {"interface", required_argument, NULL, 'i'},
    {"verbose", no_argument, NULL, 'v'},
    {"no-stack-trace", no_argument, NULL, 'n'},
    {"disable-normal-filter", no_argument, NULL, 'N'},
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
    printf("  -t, --type TYPE          Protocol type filter (arp|rarp|ipv4|ipv6|lldp|other|all)\n");
    printf("  -p, --l4-protocol PROTO  L4 protocol filter (all|icmp|tcp|udp)\n");
    printf("  -s, --src-ip IP          Source IP address filter\n");
    printf("  -d, --dst-ip IP          Destination IP address filter\n");
    printf("  -S, --src-port PORT      Source port filter\n");
    printf("  -D, --dst-port PORT      Destination port filter\n");
    printf("  -V, --vlan-id ID         VLAN ID filter\n");
    printf("  -i, --interface IFACE    Network interface filter\n");
    printf("  -v, --verbose            Enable verbose output\n");
    printf("  -n, --no-stack-trace     Disable stack trace output\n");
    printf("  -N, --disable-normal-filter  Disable normal kfree pattern filtering\n");
    printf("  -h, --help               Show this help message\n");
}

static __u16 parse_protocol(const char *str)
{
    if (strcmp(str, "all") == 0)
        return 0;

    for (int i = 0; protocol_map[i].name; i++) {
        if (strcmp(str, protocol_map[i].name) == 0)
            return protocol_map[i].value;
    }

    /* Try parsing as hex */
    if (strncmp(str, "0x", 2) == 0) {
        return ((__u16)strtol(str, NULL, 16));
    }

    fprintf(stderr, "Unknown protocol: %s\n", str);
    return 0;
}

static __u8 parse_l4_protocol(const char *str)
{
    for (int i = 0; l4_protocol_map[i].name; i++) {
        if (strcmp(str, l4_protocol_map[i].name) == 0)
            return l4_protocol_map[i].value;
    }
    fprintf(stderr, "Unknown L4 protocol: %s\n", str);
    return 0;
}

static int parse_args(int argc, char **argv)
{
    int opt;

    while ((opt = getopt_long(argc, argv, "t:p:s:d:S:D:V:i:vnNh",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 't':
            env.protocol = parse_protocol(optarg);
            break;
        case 'p':
            env.l4_protocol = parse_l4_protocol(optarg);
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
        case 'V':
            env.vlan_id = (__u16)atoi(optarg);
            break;
        case 'i':
            strncpy(env.ifname, optarg, IFNAMSIZ - 1);
            break;
        case 'v':
            env.verbose = true;
            break;
        case 'n':
            env.no_stack_trace = true;
            break;
        case 'N':
            env.disable_normal_filter = true;
            break;
        case 'h':
            print_usage();
            exit(0);
        default:
            print_usage();
            return -1;
        }
    }

    return 0;
}

static const char *format_mac(const __u8 *mac)
{
    static char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static const char *format_ip(const __u32 addr)
{
    static char buf[INET_ADDRSTRLEN];
    struct in_addr in = { .s_addr = addr };
    return inet_ntop(AF_INET, &in, buf, sizeof(buf));
}

static const char *format_ipv6(const __u8 *addr)
{
    static char buf[INET6_ADDRSTRLEN];
    return inet_ntop(AF_INET6, addr, buf, sizeof(buf));
}

static bool is_normal_kfree_pattern(int stack_map_fd, int stack_id)
{
    unsigned long stack[MAX_STACK_DEPTH] = {};
    const char *first_sym = NULL;
    const char *second_sym = NULL;

    if (stack_id < 0)
        return false;

    if (bpf_map_lookup_elem(stack_map_fd, &stack_id, &stack) != 0)
        return false;

    if (stack[0])
        first_sym = ksym_name(stack[0]);
    if (stack[1])
        second_sym = ksym_name(stack[1]);

    if (!first_sym || !second_sym)
        return false;

    /* Check against normal patterns */
    for (int i = 0; normal_patterns[i][0]; i++) {
        if (strstr(first_sym, normal_patterns[i][0]) &&
            strstr(second_sym, normal_patterns[i][1])) {
            return true;
        }
    }

    return false;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct drop_event *e = data;
    char time_str[32];
    time_t t;
    struct tm *tm;
    int stack_map_fd;

    /* Filter normal patterns */
    if (!env.disable_normal_filter && e->stack_id >= 0) {
        stack_map_fd = bpf_map__fd(skel->maps.stack_traces);
        if (is_normal_kfree_pattern(stack_map_fd, e->stack_id))
            return 0;
    }

    /* Format timestamp */
    t = time(NULL);
    tm = localtime(&t);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm);

    printf("[%s] PID: %u TGID: %u COMM: %s CPU: %u\n",
           time_str, e->pid, e->tgid, e->comm, e->cpu_id);

    if (env.verbose) {
        printf("Debug Info:\n");
        printf("  SKB Length: %u bytes, Data Length: %u bytes\n",
               e->skb_len, e->skb_data_len);
        printf("  MAC Header Offset: %u, Network Header Offset: %u, Transport Header Offset: %u\n",
               e->skb_mac_header, e->skb_network_header, e->skb_transport_header);
    }

    /* VLAN info */
    if (e->has_vlan) {
        printf("VLAN ID: %u, Priority: %u, Inner Protocol: 0x%04x\n",
               e->vlan_id, e->vlan_priority, e->inner_protocol);
    }

    /* Ethernet header */
    printf("Ethernet Header:\n");
    printf("  Source MAC: %s\n", format_mac(e->eth_src));
    printf("  Dest MAC:   %s\n", format_mac(e->eth_dst));
    printf("  EtherType:  0x%04x\n", e->eth_type);

    /* Protocol-specific info */
    switch (e->protocol_type) {
    case PROTO_TYPE_IPV4:
        printf("IPv4 PACKET\n");
        printf("IPv4 Header:\n");
        printf("  ToS:        0x%02x\n", e->ipv4_tos);
        printf("  Length:     %u\n", e->ipv4_tot_len);
        printf("  ID:         0x%04x\n", e->ipv4_id);
        printf("  TTL:        %u\n", e->ipv4_ttl);
        printf("  Protocol:   %u\n", e->ipv4_protocol);
        printf("  Source IP:  %s\n", format_ip(e->ipv4_saddr));
        printf("  Dest IP:    %s\n", format_ip(e->ipv4_daddr));

        if (e->ipv4_protocol == L4_PROTO_TCP || e->ipv4_protocol == L4_PROTO_UDP) {
            const char *proto_name = (e->ipv4_protocol == L4_PROTO_TCP) ? "TCP" : "UDP";
            printf("  %s Ports: %u -> %u\n", proto_name, e->ipv4_sport, e->ipv4_dport);
        }
        break;

    case PROTO_TYPE_IPV6:
        printf("IPv6 PACKET\n");
        printf("IPv6 Header:\n");
        printf("  Payload Len: %u\n", e->ipv6_payload_len);
        printf("  Next Header: %u\n", e->ipv6_nexthdr);
        printf("  Hop Limit:   %u\n", e->ipv6_hop_limit);
        printf("  Source IP:   %s\n", format_ipv6(e->ipv6_saddr));
        printf("  Dest IP:     %s\n", format_ipv6(e->ipv6_daddr));
        break;

    case PROTO_TYPE_ARP:
        printf("ARP PACKET\n");
        printf("ARP Header:\n");
        printf("  Hardware Type: 0x%04x\n", e->arp_hrd);
        printf("  Protocol Type: 0x%04x\n", e->arp_pro);
        printf("  Operation:     %s\n", e->arp_op == 1 ? "Request" : "Reply");
        printf("  Sender MAC:    %s\n", format_mac(e->arp_sha));
        printf("  Sender IP:     %u.%u.%u.%u\n",
               e->arp_sip[0], e->arp_sip[1], e->arp_sip[2], e->arp_sip[3]);
        printf("  Target MAC:    %s\n", format_mac(e->arp_tha));
        printf("  Target IP:     %u.%u.%u.%u\n",
               e->arp_tip[0], e->arp_tip[1], e->arp_tip[2], e->arp_tip[3]);
        break;

    case PROTO_TYPE_RARP:
        printf("RARP PACKET\n");
        printf("RARP Header:\n");
        printf("  Hardware Type: 0x%04x\n", e->arp_hrd);
        printf("  Protocol Type: 0x%04x\n", e->arp_pro);
        printf("  Operation:     %s\n", e->arp_op == 3 ? "Request" : "Reply");
        break;

    default:
        printf("OTHER PROTOCOL\n");
        printf("  EtherType: 0x%04x\n", e->other_ethertype);
        if (env.verbose) {
            printf("  Payload (first 32 bytes): ");
            for (int i = 0; i < PAYLOAD_LEN; i++)
                printf("%02x ", e->other_data[i]);
            printf("\n");
        }
        break;
    }

    printf("Interface: %s\n", e->ifname);

    /* Stack trace */
    if (!env.no_stack_trace) {
        printf("Stack trace:\n");
        if (e->stack_id < 0) {
            printf("  <Stack trace unavailable: %d>\n", e->stack_id);
        } else {
            stack_map_fd = bpf_map__fd(skel->maps.stack_traces);
            print_stack_trace(stack_map_fd, e->stack_id);
        }
    }

    printf("--------------------------------------------------------------------------------\n");

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
    int err;

    /* Parse arguments */
    err = parse_args(argc, argv);
    if (err)
        return err;

    /* Check root */
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root\n");
        return 1;
    }

    /* Setup libbpf */
    libbpf_set_print(libbpf_print_callback);

    /* Bump rlimit */
    if (bump_memlock_rlimit()) {
        fprintf(stderr, "Failed to increase rlimit\n");
        return 1;
    }

    /* Initialize kernel symbol table */
    if (ksyms_init()) {
        fprintf(stderr, "Failed to initialize kernel symbols\n");
        return 1;
    }

    /* Open BPF skeleton */
    skel = eth_drop_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    /* Set configuration */
    skel->rodata->targ_src_ip = env.src_ip;
    skel->rodata->targ_dst_ip = env.dst_ip;
    skel->rodata->targ_src_port = env.src_port;
    skel->rodata->targ_dst_port = env.dst_port;
    skel->rodata->targ_protocol = env.protocol;
    skel->rodata->targ_l4_protocol = env.l4_protocol;
    skel->rodata->targ_vlan_id = env.vlan_id;
    skel->rodata->targ_interface_filter = (env.ifname[0] != '\0');
    if (env.ifname[0] != '\0') {
        strncpy((char *)skel->rodata->targ_ifname, env.ifname, IFNAMSIZ - 1);
    }

    /* Load and attach BPF program */
    err = eth_drop_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = eth_drop_bpf__attach(skel);
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
    printf("Enhanced Ethernet Packet Drop Monitor\n");
    printf("Protocol filter: 0x%04x\n", env.protocol);
    printf("L4 Protocol filter: %u\n", env.l4_protocol);
    if (env.src_ip)
        printf("Source IP filter: %s\n", format_ip(env.src_ip));
    if (env.dst_ip)
        printf("Destination IP filter: %s\n", format_ip(env.dst_ip));
    if (env.src_port)
        printf("Source port filter: %u\n", env.src_port);
    if (env.dst_port)
        printf("Destination port filter: %u\n", env.dst_port);
    if (env.vlan_id)
        printf("VLAN ID filter: %u\n", env.vlan_id);
    if (env.ifname[0])
        printf("Interface filter: %s\n", env.ifname);
    printf("Verbose mode: %s\n", env.verbose ? "ON" : "OFF");
    printf("Stack trace: %s\n", env.no_stack_trace ? "OFF" : "ON");
    printf("Normal pattern filter: %s\n", env.disable_normal_filter ? "OFF" : "ON");
    printf("--------------------------------------------------------------------------------\n");
    printf("Starting packet drop monitoring... Press Ctrl+C to stop\n");

    /* Setup signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Main loop */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
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
    eth_drop_bpf__destroy(skel);
    ksyms_cleanup();

    printf("\nStopping packet drop monitoring...\n");

    return err != 0;
}
