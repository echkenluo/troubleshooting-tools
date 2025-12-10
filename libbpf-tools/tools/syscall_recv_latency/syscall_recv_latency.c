// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// syscall_recv_latency - recv/read syscall latency measurement

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_recv_latency.h"
#include "syscall_recv_latency.skel.h"
#include "trace_helpers.h"

static volatile bool exiting = false;

static struct env {
    int pid;
    int interval;
    int threshold;
    bool verbose;
} env = {
    .interval = 5,
    .threshold = 0,
};

const char *argp_program_version = "syscall_recv_latency 1.0";
const char *argp_program_bug_address = "https://github.com/network-troubleshooting-tools";
const char argp_program_doc[] =
"Measure recv/recvfrom/recvmsg syscall latency.\n"
"\n"
"USAGE: syscall_recv_latency [OPTIONS]\n"
"\n"
"EXAMPLES:\n"
"    syscall_recv_latency                # Monitor all processes\n"
"    syscall_recv_latency --pid 1234     # Monitor specific PID\n"
"    syscall_recv_latency --threshold 100 # Alert on >100us latency\n";

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "Target PID" },
    { "interval", 'i', "SEC", 0, "Statistics interval (default: 5)" },
    { "threshold", 't', "US", 0, "High latency threshold in microseconds" },
    { "verbose", 'v', NULL, 0, "Verbose output" },
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show this help" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p': env.pid = atoi(arg); break;
    case 'i': env.interval = atoi(arg); break;
    case 't': env.threshold = atoi(arg); break;
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct recv_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("[%s] HIGH_LATENCY: %s(%u) fd=%d latency=%lluus bytes=%lld cpu=%u->%u\n",
           ts, e->comm, e->pid, e->fd,
           (unsigned long long)e->latency_us, (long long)e->bytes,
           e->cpu_enter, e->cpu_exit);

    if (e->cpu_enter != e->cpu_exit)
        printf("  ^^^ CPU MIGRATION ^^^\n");

    return 0;
}

static void print_report(struct syscall_recv_latency_bpf *skel, time_t start_time)
{
    int hist_fd = bpf_map__fd(skel->maps.latency_hist);
    int cnt_fd = bpf_map__fd(skel->maps.counters);
    __u64 hist[MAX_SLOTS] = {0};
    __u64 counters[CNT_MAX] = {0};

    for (__u32 i = 0; i < MAX_SLOTS; i++)
        bpf_map_lookup_elem(hist_fd, &i, &hist[i]);
    for (__u32 i = 0; i < CNT_MAX; i++)
        bpf_map_lookup_elem(cnt_fd, &i, &counters[i]);

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

    printf("\n================================================================================\n");
    printf("[%s] Recv Syscall Latency (Duration: %lds)\n", ts, now - start_time);
    printf("================================================================================\n");

    printf("\nCounters:\n");
    printf("  Total calls:      %llu\n", (unsigned long long)counters[CNT_TOTAL_CALLS]);
    printf("  Total bytes:      %llu\n", (unsigned long long)counters[CNT_TOTAL_BYTES]);
    printf("  CPU migrations:   %llu\n", (unsigned long long)counters[CNT_CPU_MIGRATE]);
    printf("  Errors:           %llu\n", (unsigned long long)counters[CNT_ERRORS]);
    printf("  Zero reads:       %llu\n", (unsigned long long)counters[CNT_ZERO_READS]);

    __u64 total = 0, max_count = 0;
    for (int s = 0; s < MAX_SLOTS; s++) {
        total += hist[s];
        if (hist[s] > max_count) max_count = hist[s];
    }

    if (total > 0) {
        printf("\nLatency distribution:\n");
        for (int s = 0; s < MAX_SLOTS; s++) {
            if (hist[s] == 0) continue;
            char range[32];
            if (s == 0) snprintf(range, sizeof(range), "0-1us");
            else snprintf(range, sizeof(range), "%llu-%lluus", 1ULL << (s-1), (1ULL << s) - 1);

            int bar = max_count > 0 ? (int)(40 * hist[s] / max_count) : 0;
            double pct = 100.0 * hist[s] / total;
            printf("  %-16s: %6llu (%5.1f%%) |", range, (unsigned long long)hist[s], pct);
            for (int b = 0; b < bar; b++) printf("*");
            printf("\n");
        }
    }
    printf("================================================================================\n");

    /* Clear for next interval */
    __u64 zero = 0;
    for (__u32 i = 0; i < MAX_SLOTS; i++)
        bpf_map_update_elem(hist_fd, &i, &zero, BPF_ANY);
    for (__u32 i = 0; i < CNT_MAX; i++)
        bpf_map_update_elem(cnt_fd, &i, &zero, BPF_ANY);
}

int main(int argc, char **argv)
{
    struct syscall_recv_latency_bpf *skel;
    struct ring_buffer *rb = NULL;
    time_t start_time, last_report;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = syscall_recv_latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->targ_pid = env.pid;
    skel->rodata->high_latency_threshold_us = env.threshold;

    err = syscall_recv_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = syscall_recv_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    if (env.threshold > 0) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            err = 1;
            goto cleanup;
        }
    }

    printf("Recv Syscall Latency Monitor Started\n");
    if (env.pid) printf("PID filter: %d\n", env.pid);
    if (env.threshold) printf("High latency threshold: %d us\n", env.threshold);
    printf("Press Ctrl+C to stop\n\n");

    start_time = time(NULL);
    last_report = start_time;

    while (!exiting) {
        if (rb) ring_buffer__poll(rb, 100);
        else usleep(100000);

        time_t now = time(NULL);
        if ((now - last_report) >= env.interval) {
            print_report(skel, start_time);
            last_report = now;
        }
    }

    print_report(skel, start_time);

cleanup:
    ring_buffer__free(rb);
    syscall_recv_latency_bpf__destroy(skel);
    return err != 0;
}
