// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kvm_irqfd_stats_summary_arm - VM interrupt statistics for ARM GIC userspace

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kvm_irqfd_stats_summary_arm.h"
#include "kvm_irqfd_stats_summary_arm.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    __u32 qemu_pid;
    __u32 vhost_pid;
    char *category;
    char *subcategory;
    int interval;
} env = {
    .interval = 5,
};

const char *argp_program_version = "kvm_irqfd_stats_summary_arm 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"VM Interrupt Statistics Tool for ARM GIC with complete interrupt chain tracking\n"
"\n"
"USAGE: kvm_irqfd_stats_summary_arm QEMU_PID [OPTIONS]\n"
"\n"
"Complete ARM interrupt chain:\n"
"  irqfd_wakeup -> kvm_arch_set_irq_inatomic -> kvm_set_msi -> vgic_queue_irq_unlock\n"
"  -> kvm_vcpu_kick -> vgic_v2/v3_populate_lr (actual hardware injection)\n"
"\n"
"EXAMPLES:\n"
"    kvm_irqfd_stats_summary_arm 12345\n"
"    kvm_irqfd_stats_summary_arm 12345 --interval 10\n"
"    kvm_irqfd_stats_summary_arm 12345 --category data\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "SEC", 0, "Output interval in seconds (default: 5)" },
    { "vhost-pid", 'v', "PID", 0, "Filter specific vhost thread PID (only with --category=data)" },
    { "category", 'c', "CAT", 0, "Filter category: data, control (default: all)" },
    { "subcategory", 's', "SUBCAT", 0, "Filter subcategory: rx, tx (only with --category=data)" },
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
        env.vhost_pid = atoi(arg);
        break;
    case 'c':
        env.category = arg;
        break;
    case 's':
        env.subcategory = arg;
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        if (state->arg_num == 0)
            env.qemu_pid = atoi(arg);
        else
            argp_usage(state);
        break;
    case ARGP_KEY_END:
        if (env.qemu_pid == 0) {
            fprintf(stderr, "Error: QEMU_PID is required\n");
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

static void print_stats(struct kvm_irqfd_stats_summary_arm_bpf *skel, double interval)
{
    int irq_hist_fd = bpf_map__fd(skel->maps.irq_count_hist);
    int arch_hist_fd = bpf_map__fd(skel->maps.arch_set_irq_hist);
    int msi_hist_fd = bpf_map__fd(skel->maps.kvm_set_msi_hist);
    int vgic_hist_fd = bpf_map__fd(skel->maps.vgic_queue_hist);
    int kick_hist_fd = bpf_map__fd(skel->maps.kvm_vcpu_kick_hist);
    int lr_hist_fd = bpf_map__fd(skel->maps.vgic_populate_lr_hist);
    int ret_stats_fd = bpf_map__fd(skel->maps.arch_set_irq_ret_stats);

    struct hist_key irq_key = {}, irq_next;
    struct arch_set_irq_hist_key arch_key = {}, arch_next;
    struct kvm_set_msi_hist_key msi_key = {}, msi_next;
    struct vgic_queue_hist_key vgic_key = {}, vgic_next;
    struct kvm_vcpu_kick_hist_key kick_key = {}, kick_next;
    struct vgic_populate_lr_hist_key lr_key = {}, lr_next;
    struct arch_set_irq_ret_key ret_key = {}, ret_next;
    struct arch_set_irq_ret_val ret_val;
    __u64 count;
    time_t now;
    struct tm *tm;
    char ts[32];

    /* Totals */
    __u64 total_irqfd = 0, total_arch = 0, total_msi = 0;
    __u64 total_vgic = 0, total_kick = 0, total_lr = 0;
    __u64 total_lr_v2 = 0, total_lr_v3 = 0;

    /* Count totals */
    while (bpf_map_get_next_key(irq_hist_fd, &irq_key, &irq_next) == 0) {
        if (bpf_map_lookup_elem(irq_hist_fd, &irq_next, &count) == 0)
            total_irqfd += count;
        irq_key = irq_next;
    }

    while (bpf_map_get_next_key(arch_hist_fd, &arch_key, &arch_next) == 0) {
        if (bpf_map_lookup_elem(arch_hist_fd, &arch_next, &count) == 0)
            total_arch += count;
        arch_key = arch_next;
    }

    while (bpf_map_get_next_key(msi_hist_fd, &msi_key, &msi_next) == 0) {
        if (bpf_map_lookup_elem(msi_hist_fd, &msi_next, &count) == 0)
            total_msi += count;
        msi_key = msi_next;
    }

    while (bpf_map_get_next_key(vgic_hist_fd, &vgic_key, &vgic_next) == 0) {
        if (bpf_map_lookup_elem(vgic_hist_fd, &vgic_next, &count) == 0)
            total_vgic += count;
        vgic_key = vgic_next;
    }

    while (bpf_map_get_next_key(kick_hist_fd, &kick_key, &kick_next) == 0) {
        if (bpf_map_lookup_elem(kick_hist_fd, &kick_next, &count) == 0)
            total_kick += count;
        kick_key = kick_next;
    }

    while (bpf_map_get_next_key(lr_hist_fd, &lr_key, &lr_next) == 0) {
        if (bpf_map_lookup_elem(lr_hist_fd, &lr_next, &count) == 0) {
            total_lr += count;
            if (lr_next.version == 2)
                total_lr_v2 += count;
            else if (lr_next.version == 3)
                total_lr_v3 += count;
        }
        lr_key = lr_next;
    }

    now = time(NULL);
    tm = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n");
    printf("================================================================================\n");
    printf("VM Interrupt Statistics Summary (ARM GIC)\n");
    printf("================================================================================\n");
    printf("Timestamp: %s\n", ts);
    printf("Statistics Interval: %.2f seconds\n", interval);
    printf("\n");

    printf("ARM Interrupt Chain Analysis:\n");
    printf("  irqfd_wakeup calls:           %llu (%.2f/sec)\n",
           (unsigned long long)total_irqfd, total_irqfd / interval);
    printf("  kvm_arch_set_irq_inatomic:    %llu (%.2f/sec)\n",
           (unsigned long long)total_arch, total_arch / interval);
    printf("  kvm_set_msi calls:            %llu (%.2f/sec)\n",
           (unsigned long long)total_msi, total_msi / interval);
    printf("  vgic_queue_irq_unlock calls:  %llu (%.2f/sec)\n",
           (unsigned long long)total_vgic, total_vgic / interval);
    printf("  kvm_vcpu_kick calls:          %llu (%.2f/sec)\n",
           (unsigned long long)total_kick, total_kick / interval);
    printf("  vgic_populate_lr (injection): %llu (%.2f/sec)\n",
           (unsigned long long)total_lr, total_lr / interval);
    if (total_lr_v2 > 0 || total_lr_v3 > 0) {
        printf("    GICv2: %llu, GICv3: %llu\n",
               (unsigned long long)total_lr_v2, (unsigned long long)total_lr_v3);
    }
    printf("\n");

    /* Print arch_set_irq return stats */
    printf("kvm_arch_set_irq_inatomic Return Statistics:\n");
    printf("  %-10s %-10s %-10s %-10s %-10s\n",
           "GSI", "Total", "Success", "Fail", "AvgDelivered");

    memset(&ret_key, 0, sizeof(ret_key));
    while (bpf_map_get_next_key(ret_stats_fd, &ret_key, &ret_next) == 0) {
        if (bpf_map_lookup_elem(ret_stats_fd, &ret_next, &ret_val) == 0 &&
            ret_val.total_calls > 0) {
            double avg_delivered = ret_val.success_count > 0 ?
                (double)ret_val.total_delivered / ret_val.success_count : 0;
            printf("  %-10u %-10llu %-10llu %-10llu %-10.1f\n",
                   ret_next.gsi,
                   (unsigned long long)ret_val.total_calls,
                   (unsigned long long)ret_val.success_count,
                   (unsigned long long)ret_val.fail_count,
                   avg_delivered);
        }
        ret_key = ret_next;
    }

    /* Print vgic_queue_irq_unlock by intid */
    printf("\nvgic_queue_irq_unlock by intid:\n");
    printf("  %-10s %-15s %-15s\n", "IntID", "Count", "Rate/sec");

    memset(&vgic_key, 0, sizeof(vgic_key));
    while (bpf_map_get_next_key(vgic_hist_fd, &vgic_key, &vgic_next) == 0) {
        if (bpf_map_lookup_elem(vgic_hist_fd, &vgic_next, &count) == 0 && count > 0) {
            printf("  %-10u %-15llu %-15.2f\n",
                   vgic_next.intid,
                   (unsigned long long)count,
                   count / interval);
        }
        vgic_key = vgic_next;
    }

    /* Print kvm_vcpu_kick by vcpu_id */
    printf("\nkvm_vcpu_kick by VCPU ID:\n");
    printf("  %-10s %-15s %-15s\n", "VCPU", "Kicks", "Rate/sec");

    memset(&kick_key, 0, sizeof(kick_key));
    while (bpf_map_get_next_key(kick_hist_fd, &kick_key, &kick_next) == 0) {
        if (bpf_map_lookup_elem(kick_hist_fd, &kick_next, &count) == 0 && count > 0) {
            printf("  %-10u %-15llu %-15.2f\n",
                   kick_next.vcpu_id,
                   (unsigned long long)count,
                   count / interval);
        }
        kick_key = kick_next;
    }

    /* Print vgic_populate_lr by intid */
    printf("\nvgic_populate_lr by intid (actual hardware injection):\n");
    printf("  %-10s %-10s %-15s %-15s\n", "IntID", "GIC Ver", "Injections", "Rate/sec");

    memset(&lr_key, 0, sizeof(lr_key));
    while (bpf_map_get_next_key(lr_hist_fd, &lr_key, &lr_next) == 0) {
        if (bpf_map_lookup_elem(lr_hist_fd, &lr_next, &count) == 0 && count > 0) {
            printf("  %-10u %-10s %-15llu %-15.2f\n",
                   lr_next.intid,
                   lr_next.version == 2 ? "GICv2" : "GICv3",
                   (unsigned long long)count,
                   count / interval);
        }
        lr_key = lr_next;
    }

    printf("================================================================================\n");
}

int main(int argc, char **argv)
{
    struct kvm_irqfd_stats_summary_arm_bpf *skel;
    int err;
    time_t start_time, last_time;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Validate arguments */
    if (env.vhost_pid && (!env.category || strcmp(env.category, "data") != 0)) {
        fprintf(stderr, "Error: --vhost-pid can only be used with --category=data\n");
        return 1;
    }

    if (env.subcategory && !env.category) {
        fprintf(stderr, "Error: --subcategory requires --category to be specified\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = kvm_irqfd_stats_summary_arm_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set configuration */
    skel->rodata->targ_qemu_pid = env.qemu_pid;
    skel->rodata->targ_vhost_pid = env.vhost_pid;

    if (!env.category) {
        skel->rodata->targ_filter_category = FILTER_ALL;
    } else if (strcmp(env.category, "data") == 0) {
        skel->rodata->targ_filter_category = FILTER_DATA;
    } else if (strcmp(env.category, "control") == 0) {
        skel->rodata->targ_filter_category = FILTER_CONTROL;
    } else {
        skel->rodata->targ_filter_category = FILTER_ALL;
    }

    if (!env.subcategory) {
        skel->rodata->targ_filter_subcategory = SUBCAT_ALL;
    } else if (strcmp(env.subcategory, "rx") == 0) {
        skel->rodata->targ_filter_subcategory = SUBCAT_RX;
    } else if (strcmp(env.subcategory, "tx") == 0) {
        skel->rodata->targ_filter_subcategory = SUBCAT_TX;
    } else {
        skel->rodata->targ_filter_subcategory = SUBCAT_ALL;
    }

    err = kvm_irqfd_stats_summary_arm_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = kvm_irqfd_stats_summary_arm_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("================================================================================\n");
    printf("VM Interrupt Statistics Monitor - ARM GIC Version\n");
    printf("================================================================================\n");
    printf("Features:\n");
    printf("  - Complete ARM interrupt chain tracking:\n");
    printf("    irqfd_wakeup -> kvm_arch_set_irq_inatomic -> kvm_set_msi\n");
    printf("    -> vgic_queue_irq_unlock -> kvm_vcpu_kick -> vgic_v2/v3_populate_lr\n");
    printf("  - GICv2 and GICv3 support\n");
    printf("  - Ultra-high performance with kernel-side aggregation\n");
    printf("\n");
    printf("Monitoring VM with QEMU PID: %u\n", env.qemu_pid);
    if (env.category) {
        printf("Category filter: %s\n", env.category);
        if (env.vhost_pid)
            printf("Vhost PID filter: %u\n", env.vhost_pid);
    }
    if (env.subcategory)
        printf("Subcategory filter: %s\n", env.subcategory);
    printf("Statistics Interval: %d seconds\n", env.interval);
    printf("\nStarting monitor... (Press Ctrl+C to exit)\n");
    printf("================================================================================\n");

    start_time = time(NULL);
    last_time = start_time;

    while (!exiting) {
        sleep(env.interval);

        time_t now = time(NULL);
        double interval = difftime(now, last_time);
        if (interval < 1.0)
            interval = 1.0;

        print_stats(skel, interval);
        last_time = now;
    }

    printf("\nFinal statistics:\n");
    time_t now = time(NULL);
    double total_duration = difftime(now, start_time);
    if (total_duration < 1.0)
        total_duration = 1.0;
    print_stats(skel, total_duration);

cleanup:
    kvm_irqfd_stats_summary_arm_bpf__destroy(skel);
    return err != 0;
}
