// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// tun_tx_to_kvm_irq - TUN TX to KVM IRQ interrupt chain tracer
//
// Traces the complete interrupt chain for TUN TX queue:
// tun_net_xmit -> vhost_signal -> irqfd_wakeup

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
#include "tun_tx_to_kvm_irq.h"
#include "tun_tx_to_kvm_irq.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    char *device;
    int queue;
    int stats_interval;
    bool analyze_chains;
    bool verbose;
} env = {
    .queue = -1,
    .stats_interval = 10,
    .analyze_chains = false,
    .verbose = false,
};

/* Statistics tracking */
static __u64 stage_counts[4] = {0};
static __u64 total_delay_ns = 0;
static __u64 delay_count = 0;
static __u64 min_delay_ns = UINT64_MAX;
static __u64 max_delay_ns = 0;

const char *argp_program_version = "tun_tx_to_kvm_irq 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Trace TUN TX to KVM IRQ interrupt chain.\n"
"\n"
"USAGE: tun_tx_to_kvm_irq [OPTIONS]\n"
"\n"
"Traces the complete interrupt chain for specified TUN TX queue:\n"
"  Stage 1: tun_net_xmit   - Packet enters TUN device TX path\n"
"  Stage 2: vhost_signal   - vhost signals guest via eventfd\n"
"  Stage 3: irqfd_wakeup   - KVM irqfd wakes up guest\n"
"\n"
"EXAMPLES:\n"
"    tun_tx_to_kvm_irq -d vnet0              # Trace specific device\n"
"    tun_tx_to_kvm_irq -d vnet0 -q 0         # Trace specific queue\n"
"    tun_tx_to_kvm_irq -d vnet0 --analyze    # Enable chain analysis\n";

static const struct argp_option opts[] = {
    { "device", 'd', "DEV", 0, "Target device name (e.g., vnet0)" },
    { "queue", 'q', "QUEUE", 0, "Filter by queue index" },
    { "analyze", 'a', NULL, 0, "Enable interrupt chain analysis" },
    { "interval", 'i', "SEC", 0, "Statistics output interval (default: 10s)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'd':
        env.device = arg;
        break;
    case 'q':
        env.queue = atoi(arg);
        break;
    case 'a':
        env.analyze_chains = true;
        break;
    case 'i':
        env.stats_interval = atoi(arg);
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

static const char *stage_name(__u8 stage)
{
    switch (stage) {
    case STAGE_TUN_NET_XMIT:
        return "tun_net_xmit";
    case STAGE_VHOST_SIGNAL:
        return "vhost_signal";
    case STAGE_IRQFD_WAKEUP:
        return "irqfd_wakeup";
    default:
        return "unknown";
    }
}

static const char *protocol_str(__u8 proto)
{
    switch (proto) {
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 1:
        return "ICMP";
    default:
        return "OTHER";
    }
}

static void print_ip(__be32 addr, char *buf, size_t buflen)
{
    struct in_addr in = { .s_addr = addr };
    if (addr == 0) {
        snprintf(buf, buflen, "N/A");
    } else {
        inet_ntop(AF_INET, &in, buf, buflen);
    }
}

static void print_statistics(void)
{
    printf("\n");
    printf("================================================================================\n");
    printf("TUN TX INTERRUPT CHAIN STATISTICS\n");
    printf("================================================================================\n");
    printf("\nStage Event Counts:\n");
    printf("  Stage 1 [tun_net_xmit]:  %llu events\n", (unsigned long long)stage_counts[1]);
    printf("  Stage 2 [vhost_signal]:  %llu events\n", (unsigned long long)stage_counts[2]);
    printf("  Stage 3 [irqfd_wakeup]:  %llu events\n", (unsigned long long)stage_counts[3]);

    if (stage_counts[1] > 0 && stage_counts[2] > 0 && stage_counts[3] > 0) {
        printf("\nChain Status: COMPLETE (all stages detected)\n");
    } else if (stage_counts[1] > 0 && stage_counts[2] > 0) {
        printf("\nChain Status: PARTIAL (missing irqfd_wakeup)\n");
    } else if (stage_counts[1] > 0) {
        printf("\nChain Status: INCOMPLETE (only tun_net_xmit detected)\n");
    }

    if (delay_count > 0) {
        double avg_delay = (double)total_delay_ns / delay_count / 1000.0;
        printf("\nInterrupt Latency (vhost_signal -> irqfd_wakeup):\n");
        printf("  Samples: %llu\n", (unsigned long long)delay_count);
        printf("  Average: %.2f us\n", avg_delay);
        printf("  Min:     %.2f us\n", (double)min_delay_ns / 1000.0);
        printf("  Max:     %.2f us\n", (double)max_delay_ns / 1000.0);
    }
    printf("================================================================================\n\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct interrupt_event *e = data;
    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    struct tm *tm;
    char ts[32];
    time_t t;

    /* Update statistics */
    if (e->stage < 4)
        stage_counts[e->stage]++;

    if (e->delay_ns > 0) {
        total_delay_ns += e->delay_ns;
        delay_count++;
        if (e->delay_ns < min_delay_ns)
            min_delay_ns = e->delay_ns;
        if (e->delay_ns > max_delay_ns)
            max_delay_ns = e->delay_ns;
    }

    /* Format timestamp */
    t = e->timestamp / 1000000000ULL;
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    __u64 ns_part = (e->timestamp % 1000000000ULL) / 1000000ULL;

    print_ip(e->saddr, saddr_str, sizeof(saddr_str));
    print_ip(e->daddr, daddr_str, sizeof(daddr_str));

    printf("TUN_IRQ [%s:q%u] Stage %u [%s] Time=%s.%03llu ",
           e->dev_name[0] ? e->dev_name : "unknown",
           e->queue_index,
           e->stage,
           stage_name(e->stage),
           ts,
           (unsigned long long)ns_part);

    printf("Sock=0x%llx ", (unsigned long long)e->sock_ptr);

    if (e->eventfd_ctx)
        printf("EventFD=0x%llx ", (unsigned long long)e->eventfd_ctx);

    if (e->gsi)
        printf("GSI=%u ", e->gsi);

    if (e->vq_ptr)
        printf("VQ=0x%llx ", (unsigned long long)e->vq_ptr);

    if (e->delay_ns > 0)
        printf("Delay=%.3fms ", (double)e->delay_ns / 1000000.0);

    printf("CPU=%u PID=%u COMM=%s", e->cpu_id, e->pid, e->comm);

    /* Show packet info for Stage 1 */
    if (e->stage == STAGE_TUN_NET_XMIT && e->saddr) {
        if (e->protocol == 6 || e->protocol == 17) {
            printf(" %s %s:%u->%s:%u",
                   protocol_str(e->protocol),
                   saddr_str, ntohs(e->sport),
                   daddr_str, ntohs(e->dport));
        } else {
            printf(" %s %s->%s", protocol_str(e->protocol), saddr_str, daddr_str);
        }
    }

    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    struct tun_tx_to_kvm_irq_bpf *skel;
    struct ring_buffer *rb = NULL;
    time_t last_stats_time;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tun_tx_to_kvm_irq_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure BPF program */
    if (env.device) {
        unsigned int ifindex = if_nametoindex(env.device);
        if (ifindex == 0) {
            fprintf(stderr, "Invalid device: %s\n", env.device);
            err = 1;
            goto cleanup;
        }
        skel->rodata->targ_ifindex = ifindex;
    }

    if (env.queue >= 0)
        skel->rodata->targ_queue = env.queue;

    err = tun_tx_to_kvm_irq_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = tun_tx_to_kvm_irq_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("================================================================================\n");
    printf("TUN TX TO KVM IRQ INTERRUPT TRACING\n");
    printf("================================================================================\n");
    printf("Tracing: tun_net_xmit -> vhost_signal -> irqfd_wakeup\n");

    if (env.device)
        printf("Device filter: %s\n", env.device);
    else
        printf("Device filter: All TUN devices\n");

    if (env.queue >= 0)
        printf("Queue filter: %d\n", env.queue);
    else
        printf("Queue filter: All queues\n");

    if (env.analyze_chains)
        printf("Chain analysis: ENABLED (interval: %ds)\n", env.stats_interval);

    printf("\nPress Ctrl+C to stop\n\n");

    last_stats_time = time(NULL);

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

        /* Print statistics periodically */
        if (env.analyze_chains) {
            time_t now = time(NULL);
            if (now - last_stats_time >= env.stats_interval) {
                print_statistics();
                last_stats_time = now;
            }
        }
    }

    /* Final statistics */
    printf("\n");
    printf("================================================================================\n");
    printf("FINAL SUMMARY\n");
    print_statistics();

cleanup:
    ring_buffer__free(rb);
    tun_tx_to_kvm_irq_bpf__destroy(skel);
    return err != 0;
}
