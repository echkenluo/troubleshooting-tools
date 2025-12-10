// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// ksoftirqd_sched_latency - ksoftirqd scheduling latency measurement
//
// Measures scheduling latency of ksoftirqd kernel threads

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ksoftirqd_sched_latency.h"
#include "ksoftirqd_sched_latency.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int cpu;
    int interval;
    int duration;
    bool verbose;
} env = {
    .cpu = -1,
    .interval = 5,
    .duration = 0,
    .verbose = false,
};

/* Cumulative statistics */
static __u64 cum_hist[MAX_CPUS][MAX_SLOTS] = {0};
static __u64 cum_wakeup[MAX_CPUS] = {0};
static __u64 cum_run[MAX_CPUS] = {0};
static __u64 cum_high_latency[MAX_CPUS] = {0};

const char *argp_program_version = "ksoftirqd_sched_latency 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Measure ksoftirqd scheduling latency.\n"
"\n"
"USAGE: ksoftirqd_sched_latency [OPTIONS]\n"
"\n"
"Measures the scheduling latency of ksoftirqd kernel threads - the delay\n"
"between when ksoftirqd is woken up and when it starts running.\n"
"\n"
"EXAMPLES:\n"
"    ksoftirqd_sched_latency                # Monitor all CPUs\n"
"    ksoftirqd_sched_latency --cpu 0        # Monitor specific CPU\n"
"    ksoftirqd_sched_latency --interval 10  # 10 second intervals\n";

static const struct argp_option opts[] = {
    { "cpu", 'c', "CPU", 0, "Target CPU (default: all)" },
    { "interval", 'i', "SEC", 0, "Statistics interval (default: 5)" },
    { "duration", 'd', "SEC", 0, "Total duration (0=unlimited)" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'c':
        env.cpu = atoi(arg);
        break;
    case 'i':
        env.interval = atoi(arg);
        break;
    case 'd':
        env.duration = atoi(arg);
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

static void print_report(struct ksoftirqd_sched_latency_bpf *skel,
                        time_t start_time, bool cumulative)
{
    struct hist_key key = {}, next_key;
    __u64 value;
    __u64 hist[MAX_CPUS][MAX_SLOTS] = {0};
    __u64 wakeup[MAX_CPUS] = {0};
    __u64 run[MAX_CPUS] = {0};
    __u64 high_lat[MAX_CPUS] = {0};
    int active_cpus[MAX_CPUS];
    int num_active = 0;

    int hist_fd = bpf_map__fd(skel->maps.latency_hist);
    int wakeup_fd = bpf_map__fd(skel->maps.wakeup_count);
    int run_fd = bpf_map__fd(skel->maps.run_count);
    int high_fd = bpf_map__fd(skel->maps.high_latency_count);

    /* Collect histogram data */
    while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(hist_fd, &next_key, &value) == 0) {
            if (next_key.cpu < MAX_CPUS && next_key.slot < MAX_SLOTS) {
                hist[next_key.cpu][next_key.slot] = value;
                if (!cumulative)
                    cum_hist[next_key.cpu][next_key.slot] += value;
            }
        }
        key = next_key;
    }

    /* Collect counter data */
    for (__u32 cpu = 0; cpu < MAX_CPUS; cpu++) {
        bpf_map_lookup_elem(wakeup_fd, &cpu, &wakeup[cpu]);
        bpf_map_lookup_elem(run_fd, &cpu, &run[cpu]);
        bpf_map_lookup_elem(high_fd, &cpu, &high_lat[cpu]);

        if (!cumulative) {
            cum_wakeup[cpu] += wakeup[cpu];
            cum_run[cpu] += run[cpu];
            cum_high_latency[cpu] += high_lat[cpu];
        }

        /* Track active CPUs */
        __u64 *w = cumulative ? &cum_wakeup[cpu] : &wakeup[cpu];
        if (*w > 0 || cum_run[cpu] > 0) {
            if (env.cpu < 0 || cpu == (__u32)env.cpu) {
                active_cpus[num_active++] = cpu;
            }
        }
    }

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n");
    printf("================================================================================\n");
    printf("[%s] %sksoftirqd Scheduling Latency (Duration: %lds)\n",
           ts, cumulative ? "CUMULATIVE " : "", now - start_time);
    printf("================================================================================\n");

    if (num_active == 0) {
        printf("No ksoftirqd activity detected\n");
        return;
    }

    __u64 (*h)[MAX_SLOTS] = cumulative ? cum_hist : hist;
    __u64 *w = cumulative ? cum_wakeup : wakeup;
    __u64 *r = cumulative ? cum_run : run;
    __u64 *hl = cumulative ? cum_high_latency : high_lat;

    __u64 total_wakeups = 0, total_runs = 0, total_high = 0;

    for (int i = 0; i < num_active; i++) {
        int cpu = active_cpus[i];

        printf("\nCPU %d (ksoftirqd/%d):\n", cpu, cpu);
        printf("  Wakeup count: %llu\n", (unsigned long long)w[cpu]);
        printf("  Run count:    %llu\n", (unsigned long long)r[cpu]);
        printf("  High latency (>100us): %llu\n", (unsigned long long)hl[cpu]);

        if (w[cpu] != r[cpu])
            printf("  WARNING: Wakeup/run mismatch!\n");

        total_wakeups += w[cpu];
        total_runs += r[cpu];
        total_high += hl[cpu];

        /* Calculate total samples */
        __u64 total_samples = 0;
        __u64 max_count = 0;
        for (int s = 0; s < MAX_SLOTS; s++) {
            total_samples += h[cpu][s];
            if (h[cpu][s] > max_count)
                max_count = h[cpu][s];
        }

        if (total_samples == 0) {
            printf("  No latency samples\n");
            continue;
        }

        printf("  Total samples: %llu\n", (unsigned long long)total_samples);
        printf("  Latency distribution:\n");

        for (int s = 0; s < MAX_SLOTS; s++) {
            if (h[cpu][s] == 0)
                continue;

            char range[32];
            if (s == 0) {
                snprintf(range, sizeof(range), "0-1us");
            } else {
                __u64 low = 1ULL << (s - 1);
                __u64 high = (1ULL << s) - 1;
                snprintf(range, sizeof(range), "%llu-%lluus",
                         (unsigned long long)low, (unsigned long long)high);
            }

            int bar_width = max_count > 0 ? (int)(40 * h[cpu][s] / max_count) : 0;
            double pct = 100.0 * h[cpu][s] / total_samples;

            printf("    %-16s: %6llu (%5.1f%%) |",
                   range, (unsigned long long)h[cpu][s], pct);
            for (int b = 0; b < bar_width; b++)
                printf("*");
            printf("\n");
        }

        /* Warn on high latency */
        bool has_high = false;
        for (int s = 7; s < MAX_SLOTS; s++) {  /* >= 64us */
            if (h[cpu][s] > 0) {
                has_high = true;
                break;
            }
        }
        if (has_high)
            printf("    ^^^ WARNING: High scheduling latency (>=64us) ^^^\n");
    }

    printf("\n");
    printf("================================================================================\n");
    printf("Summary:\n");
    printf("  Total wakeups:            %llu\n", (unsigned long long)total_wakeups);
    printf("  Total runs:               %llu\n", (unsigned long long)total_runs);
    printf("  Total high latency (>100us): %llu\n", (unsigned long long)total_high);

    if (total_runs > 0) {
        double rate = 100.0 * total_high / total_runs;
        printf("  High latency rate:        %.2f%%\n", rate);
    }
    printf("================================================================================\n");

    /* Clear maps for next interval if not cumulative */
    if (!cumulative) {
        key.cpu = 0;
        key.slot = 0;
        while (bpf_map_get_next_key(hist_fd, &key, &next_key) == 0) {
            bpf_map_delete_elem(hist_fd, &next_key);
            key = next_key;
        }

        __u64 zero = 0;
        for (__u32 cpu = 0; cpu < MAX_CPUS; cpu++) {
            bpf_map_update_elem(wakeup_fd, &cpu, &zero, BPF_ANY);
            bpf_map_update_elem(run_fd, &cpu, &zero, BPF_ANY);
            bpf_map_update_elem(high_fd, &cpu, &zero, BPF_ANY);
        }
    }
}

int main(int argc, char **argv)
{
    struct ksoftirqd_sched_latency_bpf *skel;
    time_t start_time, last_report;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = ksoftirqd_sched_latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Configure CPU filter */
    skel->rodata->targ_cpu = env.cpu;

    err = ksoftirqd_sched_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = ksoftirqd_sched_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("================================================================================\n");
    printf("ksoftirqd Scheduling Latency Measurement\n");
    printf("================================================================================\n");
    if (env.cpu >= 0)
        printf("Target CPU: %d\n", env.cpu);
    else
        printf("Target CPU: All\n");
    printf("Interval: %d seconds\n", env.interval);
    printf("\nMeasuring ksoftirqd scheduling latency...\n");
    printf("  Wakeup: tracepoint:sched:sched_wakeup\n");
    printf("  Run:    tracepoint:sched:sched_switch\n");
    printf("================================================================================\n");
    printf("Press Ctrl+C to stop\n\n");

    start_time = time(NULL);
    last_report = start_time;

    while (!exiting) {
        sleep(1);

        time_t now = time(NULL);

        /* Check duration limit */
        if (env.duration > 0 && (now - start_time) >= env.duration) {
            printf("\nDuration limit reached\n");
            break;
        }

        /* Print periodic report */
        if ((now - last_report) >= env.interval) {
            print_report(skel, start_time, false);
            last_report = now;
        }
    }

    /* Print final cumulative report */
    printf("\n\nFINAL CUMULATIVE REPORT\n");
    print_report(skel, start_time, true);

cleanup:
    ksoftirqd_sched_latency_bpf__destroy(skel);
    return err != 0;
}
