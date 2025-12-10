// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kvm_irqfd_stats_summary - VM interrupt statistics histogram userspace program

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kvm_irqfd_stats_summary.h"
#include "kvm_irqfd_stats_summary.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

/* Command line arguments */
static struct env {
    __u32 qemu_pid;
    __u32 vhost_pid;
    char *category;
    char *subcategory;
    int interval;
    bool verbose;
} env = {
    .qemu_pid = 0,
    .vhost_pid = 0,
    .category = NULL,
    .subcategory = NULL,
    .interval = 5,
    .verbose = false,
};

const char *argp_program_version = "kvm_irqfd_stats_summary 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"VM Interrupt Statistics Tool - Histogram Version\n"
"\n"
"Smart VM-centric interrupt monitoring tool that automatically tracks\n"
"all interrupts for a specific VM. Requires QEMU PID as mandatory parameter.\n"
"\n"
"USAGE: kvm_irqfd_stats_summary QEMU_PID [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    kvm_irqfd_stats_summary 12345\n"
"    kvm_irqfd_stats_summary 12345 --category data\n"
"    kvm_irqfd_stats_summary 12345 --category data --vhost-pid 12350\n"
"    kvm_irqfd_stats_summary 12345 --interval 10\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Statistics output interval (default: 5)" },
    { "vhost-pid", 'v', "PID", 0, "Filter specific VHOST thread PID (only with --category=data)" },
    { "category", 'c', "CAT", 0, "Filter interrupt category (data, control)" },
    { "subcategory", 's', "SUBCAT", 0, "Filter RX or TX (only with --category=data)" },
    { "verbose", 'V', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interval = atoi(arg);
        if (env.interval <= 0) {
            fprintf(stderr, "Invalid interval: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'v':
        env.vhost_pid = (__u32)atoi(arg);
        break;
    case 'c':
        env.category = arg;
        break;
    case 's':
        env.subcategory = arg;
        break;
    case 'V':
        env.verbose = true;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        if (state->arg_num == 0) {
            env.qemu_pid = (__u32)atoi(arg);
            if (env.qemu_pid == 0) {
                fprintf(stderr, "Invalid QEMU PID: %s\n", arg);
                argp_usage(state);
            }
        } else {
            argp_usage(state);
        }
        break;
    case ARGP_KEY_END:
        if (env.qemu_pid == 0) {
            fprintf(stderr, "Error: QEMU PID is required\n");
            argp_usage(state);
        }
        if (env.vhost_pid && (!env.category || strcmp(env.category, "data") != 0)) {
            fprintf(stderr, "Error: --vhost-pid can only be used with --category=data\n");
            argp_usage(state);
        }
        if (env.subcategory && !env.category) {
            fprintf(stderr, "Error: --subcategory requires --category to be specified\n");
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
    .args_doc = "QEMU_PID",
    .doc = argp_program_doc,
};

static void sig_handler(int sig)
{
    exiting = true;
}

static __u8 category_to_int(const char *cat)
{
    if (!cat)
        return FILTER_ALL;
    if (strcmp(cat, "data") == 0)
        return FILTER_DATA;
    if (strcmp(cat, "control") == 0)
        return FILTER_CONTROL;
    return FILTER_ALL;
}

static __u8 subcategory_to_int(const char *subcat)
{
    if (!subcat)
        return SUBCAT_ALL;
    if (strcmp(subcat, "rx") == 0)
        return SUBCAT_RX;
    if (strcmp(subcat, "tx") == 0)
        return SUBCAT_TX;
    return SUBCAT_ALL;
}

static void print_stats(struct kvm_irqfd_stats_summary_bpf *skel, time_t start_time,
                        time_t last_print_time)
{
    time_t now = time(NULL);
    double duration = difftime(now, start_time);
    double interval = last_print_time ? difftime(now, last_print_time) : duration;
    struct tm *tm_info;
    char time_buf[64];

    /* Print header */
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S.000", tm_info);

    printf("\n");
    printf("====================================================================================================\n");
    printf("VM Interrupt Statistics Summary (Histogram Version)\n");
    printf("====================================================================================================\n");
    printf("Timestamp: %s\n", time_buf);
    printf("Statistics Duration: %.2f seconds (Current Interval: %.2f seconds)\n",
           duration, interval);

    /* Count total interrupts from irq_count_hist */
    __u64 total_interrupts = 0;
    __u64 total_arch_set_irq = 0;
    __u64 total_kvm_set_msi = 0;
    __u64 total_vcpu_kick = 0;

    int irq_hist_fd = bpf_map__fd(skel->maps.irq_count_hist);
    int arch_hist_fd = bpf_map__fd(skel->maps.arch_set_irq_hist);
    int msi_hist_fd = bpf_map__fd(skel->maps.kvm_set_msi_hist);
    int kick_hist_fd = bpf_map__fd(skel->maps.kvm_vcpu_kick_hist);

    /* Iterate through irq_count_hist */
    struct hist_key key = {}, next_key;
    __u64 count;

    while (bpf_map_get_next_key(irq_hist_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(irq_hist_fd, &next_key, &count) == 0) {
            total_interrupts += count;
        }
        key = next_key;
    }

    /* Iterate through arch_set_irq_hist */
    struct arch_set_irq_hist_key arch_key = {}, arch_next_key;
    while (bpf_map_get_next_key(arch_hist_fd, &arch_key, &arch_next_key) == 0) {
        if (bpf_map_lookup_elem(arch_hist_fd, &arch_next_key, &count) == 0) {
            total_arch_set_irq += count;
        }
        arch_key = arch_next_key;
    }

    /* Iterate through kvm_set_msi_hist */
    struct kvm_set_msi_hist_key msi_key = {}, msi_next_key;
    while (bpf_map_get_next_key(msi_hist_fd, &msi_key, &msi_next_key) == 0) {
        if (bpf_map_lookup_elem(msi_hist_fd, &msi_next_key, &count) == 0) {
            total_kvm_set_msi += count;
        }
        msi_key = msi_next_key;
    }

    /* Iterate through kvm_vcpu_kick_hist */
    struct kvm_vcpu_kick_hist_key kick_key = {}, kick_next_key;
    while (bpf_map_get_next_key(kick_hist_fd, &kick_key, &kick_next_key) == 0) {
        if (bpf_map_lookup_elem(kick_hist_fd, &kick_next_key, &count) == 0) {
            total_vcpu_kick += count;
        }
        kick_key = kick_next_key;
    }

    printf("DEBUG: Interrupt chain analysis:\n");
    printf("  Total irqfd_wakeup calls: %llu\n", (unsigned long long)total_interrupts);
    printf("  Total kvm_arch_set_irq_inatomic calls: %llu\n", (unsigned long long)total_arch_set_irq);
    printf("  Total kvm_set_msi calls: %llu\n", (unsigned long long)total_kvm_set_msi);
    printf("  Total kvm_vcpu_kick calls: %llu\n", (unsigned long long)total_vcpu_kick);
    printf("Total Interrupts: %llu (%.2f interrupts/sec)\n",
           (unsigned long long)total_interrupts,
           interval > 0 ? total_interrupts / interval : 0);

    /* Print detailed per-thread statistics */
    printf("\nThread Details:\n");

    memset(&key, 0, sizeof(key));
    int thread_idx = 0;
    while (bpf_map_get_next_key(irq_hist_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(irq_hist_fd, &next_key, &count) == 0 && count > 0) {
            thread_idx++;
            double rate = interval > 0 ? count / interval : 0;
            printf("  Thread #%d: IRQFD=0x%llx\n", thread_idx,
                   (unsigned long long)next_key.irqfd_ptr);
            printf("    GSI: %u\n", next_key.gsi);
            printf("    Interrupts: %llu (%.2f/sec)\n", (unsigned long long)count, rate);
            printf("    CPU: %u\n", next_key.cpu_id);
            printf("    Process: %s (PID: %u)\n", next_key.comm, next_key.pid);
        }
        key = next_key;
    }

    /* Clear histograms for next interval */
    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(irq_hist_fd, &key, &next_key) == 0) {
        bpf_map_delete_elem(irq_hist_fd, &next_key);
        key = next_key;
    }

    memset(&arch_key, 0, sizeof(arch_key));
    while (bpf_map_get_next_key(arch_hist_fd, &arch_key, &arch_next_key) == 0) {
        bpf_map_delete_elem(arch_hist_fd, &arch_next_key);
        arch_key = arch_next_key;
    }

    memset(&msi_key, 0, sizeof(msi_key));
    while (bpf_map_get_next_key(msi_hist_fd, &msi_key, &msi_next_key) == 0) {
        bpf_map_delete_elem(msi_hist_fd, &msi_next_key);
        msi_key = msi_next_key;
    }

    memset(&kick_key, 0, sizeof(kick_key));
    while (bpf_map_get_next_key(kick_hist_fd, &kick_key, &kick_next_key) == 0) {
        bpf_map_delete_elem(kick_hist_fd, &kick_next_key);
        kick_key = kick_next_key;
    }

    printf("\n");
}

int main(int argc, char **argv)
{
    struct kvm_irqfd_stats_summary_bpf *skel;
    int err;
    time_t start_time, last_print_time = 0;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Setup signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    skel = kvm_irqfd_stats_summary_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    skel->rodata->targ_qemu_pid = env.qemu_pid;
    skel->rodata->targ_vhost_pid = env.vhost_pid;
    skel->rodata->targ_filter_category = category_to_int(env.category);
    skel->rodata->targ_filter_subcategory = subcategory_to_int(env.subcategory);

    /* Load & verify BPF programs */
    printf("Loading VM interrupt statistics program (histogram version)...\n");
    err = kvm_irqfd_stats_summary_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach probes */
    err = kvm_irqfd_stats_summary_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Successfully attached to irqfd_wakeup\n");
    printf("Successfully attached to kvm_arch_set_irq_inatomic\n");
    printf("Successfully attached to kvm_set_msi\n");
    printf("Successfully attached to kvm_vcpu_kick\n");

    /* Print startup info */
    printf("\n");
    printf("================================================================================\n");
    printf("VM Interrupt Statistics Monitor - Histogram Version\n");
    printf("================================================================================\n");
    printf("Features:\n");
    printf("  - Use BPF maps for kernel-side statistics aggregation\n");
    printf("  - Fixed vhost PID and COMM filtering issues\n");
    printf("  - Periodic statistics histogram output\n");
    printf("  - Call source analysis with irqfd_wakeup parameter tracking\n");
    printf("  - Complete interrupt chain tracking: irqfd_wakeup -> kvm_arch_set_irq_inatomic -> kvm_set_msi -> kvm_vcpu_kick\n");
    printf("  - Ultra-high performance, suitable for high-frequency scenarios\n");

    printf("\nMonitoring VM with QEMU PID: %u\n", env.qemu_pid);

    if (!env.category) {
        printf("Tracking both vhost-%u threads and control interrupts\n", env.qemu_pid);
    } else if (strcmp(env.category, "data") == 0) {
        printf("Category: data (vhost-%u threads only)\n", env.qemu_pid);
        if (env.vhost_pid)
            printf("VHOST Thread PID: %u (specific thread)\n", env.vhost_pid);
    } else if (strcmp(env.category, "control") == 0) {
        printf("Category: control (QEMU process only)\n");
    }

    if (env.subcategory)
        printf("Subcategory: %s\n", env.subcategory);

    printf("\nStatistics Interval: %d seconds\n", env.interval);
    printf("\nStarting monitor... (Press Ctrl+C to exit)\n");
    printf("================================================================================\n");

    /* Main loop */
    start_time = time(NULL);
    while (!exiting) {
        sleep(env.interval);
        if (exiting)
            break;
        print_stats(skel, start_time, last_print_time);
        last_print_time = time(NULL);
    }

    /* Print final statistics */
    printf("\n\nReceived interrupt signal, displaying final statistics...\n");
    print_stats(skel, start_time, last_print_time);
    printf("\nMonitoring ended\n");

cleanup:
    kvm_irqfd_stats_summary_bpf__destroy(skel);
    return err != 0;
}
