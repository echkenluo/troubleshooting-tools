#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ksoftirqd Scheduling Latency Measurement Tool

Measures the scheduling latency of ksoftirqd kernel threads - the delay between
when ksoftirqd is woken up and when it actually starts running on a CPU.

High scheduling latency (>100us) indicates CPU contention and can cause network
packet processing delays, leading to tail latency in network performance.

Usage:
    # Measure all CPUs
    sudo ./ksoftirqd_sched_latency.py

    # Measure specific CPU
    sudo ./ksoftirqd_sched_latency.py --cpu 105

    # Measure multiple CPUs
    sudo ./ksoftirqd_sched_latency.py --cpu 105,106,107

    # Set custom interval
    sudo ./ksoftirqd_sched_latency.py --interval 10

Key Metrics:
    - Scheduling latency histogram (microseconds)
    - Wakeup vs run counts (mismatches indicate lost wakeups)
    - High latency event count (>100us threshold)
    - Per-CPU breakdown
"""

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)

from time import sleep, time as time_time
import argparse
import ctypes
import os
import sys
import datetime
import signal

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Target CPU filter (-1 means all CPUs)
#define TARGET_CPU %d

// Wakeup timestamp map (key: ksoftirqd PID)
BPF_HASH(wakeup_ts, u32, u64);

// Per-CPU scheduling latency histogram (key: CPU ID, value: log2 histogram)
struct hist_key_t {
    u32 cpu;
    u32 slot;  // log2(latency_us)
};
BPF_HISTOGRAM(sched_latency_hist, struct hist_key_t, 2048);

// Counters per CPU
BPF_ARRAY(wakeup_count, u64, 256);    // Total wakeups
BPF_ARRAY(run_count, u64, 256);       // Total runs
BPF_ARRAY(high_latency_count, u64, 256);  // Latency > 100us

// Check if task is ksoftirqd
static __always_inline bool is_ksoftirqd(const char *comm) {
    // Check for "ksoftirqd/" prefix (9 characters)
    char prefix[10];
    bpf_probe_read_kernel(&prefix, sizeof(prefix), comm);

    return (prefix[0] == 'k' && prefix[1] == 's' && prefix[2] == 'o' &&
            prefix[3] == 'f' && prefix[4] == 't' && prefix[5] == 'i' &&
            prefix[6] == 'r' && prefix[7] == 'q' && prefix[8] == 'd');
}

// Extract CPU number from ksoftirqd task (it's bound to specific CPU)
static __always_inline u32 get_ksoftirqd_cpu(struct task_struct *task) {
    u32 cpu = 0;
    bpf_probe_read_kernel(&cpu, sizeof(cpu), &task->cpu);
    return cpu;
}

// Tracepoint: sched_wakeup - ksoftirqd is woken up
TRACEPOINT_PROBE(sched, sched_wakeup)
{
    char comm[TASK_COMM_LEN];
    bpf_probe_read_kernel(&comm, sizeof(comm), args->comm);

    // Check if this is ksoftirqd
    if (!is_ksoftirqd(comm)) {
        return 0;
    }

    u32 pid = args->pid;
    u64 ts = bpf_ktime_get_ns();

    // Record wakeup timestamp
    wakeup_ts.update(&pid, &ts);

    // Get target CPU for this ksoftirqd
    // Note: ksoftirqd/N always runs on CPU N
    // We can extract CPU from the PID's bound CPU
    u32 target_cpu = args->target_cpu;

    // Apply CPU filter
    if (TARGET_CPU >= 0 && target_cpu != TARGET_CPU) {
        return 0;
    }

    // Increment wakeup counter
    u64 *count = wakeup_count.lookup(&target_cpu);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

// Tracepoint: sched_switch - ksoftirqd starts running
TRACEPOINT_PROBE(sched, sched_switch)
{
    char next_comm[TASK_COMM_LEN];
    bpf_probe_read_kernel(&next_comm, sizeof(next_comm), args->next_comm);

    // Check if the next task is ksoftirqd
    if (!is_ksoftirqd(next_comm)) {
        return 0;
    }

    u32 pid = args->next_pid;
    u32 cpu = bpf_get_smp_processor_id();

    // Apply CPU filter
    if (TARGET_CPU >= 0 && cpu != TARGET_CPU) {
        return 0;
    }

    // Lookup wakeup timestamp
    u64 *wakeup_ts_ptr = wakeup_ts.lookup(&pid);
    if (!wakeup_ts_ptr) {
        // No wakeup recorded (might have happened before tracing started)
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 latency_ns = now - *wakeup_ts_ptr;
    u64 latency_us = latency_ns / 1000;

    // Update histogram
    struct hist_key_t key = {
        .cpu = cpu,
        .slot = bpf_log2l(latency_us + 1)
    };
    sched_latency_hist.increment(key);

    // Increment run counter
    u64 *run_cnt = run_count.lookup(&cpu);
    if (run_cnt) {
        __sync_fetch_and_add(run_cnt, 1);
    }

    // Track high latency events (>100us)
    if (latency_us > 100) {
        u64 *high_cnt = high_latency_count.lookup(&cpu);
        if (high_cnt) {
            __sync_fetch_and_add(high_cnt, 1);
        }
    }

    // Clean up wakeup timestamp
    wakeup_ts.delete(&pid);

    return 0;
}
"""

# Cumulative statistics (from start to end)
cumulative_stats = {
    'cpu_data': {},  # {cpu: {slot: count}}
    'wakeup_counts': {},  # {cpu: count}
    'run_counts': {},  # {cpu: count}
    'high_latency_counts': {}  # {cpu: count}
}

def parse_cpu_list(cpu_str):
    """Parse CPU list string like '1,2,5-8' into list of CPU IDs"""
    if not cpu_str:
        return None

    cpus = set()
    for part in cpu_str.split(','):
        if '-' in part:
            start, end = part.split('-')
            cpus.update(range(int(start), int(end) + 1))
        else:
            cpus.add(int(part))

    return sorted(list(cpus))

def print_histogram_summary(b, target_cpus, interval_start_time, update_cumulative=True):
    """Print histogram summary for the current interval"""
    global cumulative_stats

    current_time = datetime.datetime.now()
    print("\n" + "=" * 80)
    print("[%s] ksoftirqd Scheduling Latency Report (Interval: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        time_time() - interval_start_time
    ))
    print("=" * 80)

    # Get histogram data
    hist = b["sched_latency_hist"]
    wakeup_counts = b["wakeup_count"]
    run_counts = b["run_count"]
    high_latency_counts = b["high_latency_count"]

    # Collect per-CPU histogram data
    cpu_data = {}  # {cpu: {slot: count}}

    try:
        for k, v in hist.items():
            cpu = k.cpu
            slot = k.slot
            count = v.value if hasattr(v, 'value') else int(v)

            if cpu not in cpu_data:
                cpu_data[cpu] = {}
            cpu_data[cpu][slot] = count

            # Update cumulative histogram
            if update_cumulative:
                if cpu not in cumulative_stats['cpu_data']:
                    cumulative_stats['cpu_data'][cpu] = {}
                cumulative_stats['cpu_data'][cpu][slot] = cumulative_stats['cpu_data'][cpu].get(slot, 0) + count
    except Exception as e:
        print("Error reading histogram data:", str(e))
        return

    if not cpu_data:
        print("No scheduling latency data collected in this interval")
        return

    # Filter CPUs if target_cpus specified
    if target_cpus:
        cpu_data = {cpu: data for cpu, data in cpu_data.items() if cpu in target_cpus}

    if not cpu_data:
        print("No data for specified CPUs")
        return

    # Print per-CPU statistics
    print("\nPer-CPU ksoftirqd Scheduling Latency (Interval):")
    print("-" * 80)

    for cpu in sorted(cpu_data.keys()):
        print("\nCPU %d (ksoftirqd/%d):" % (cpu, cpu))

        # Get counters (ensure CPU is int for Python 2 compatibility)
        cpu_key = ctypes.c_int(int(cpu))
        wakeup_cnt = wakeup_counts[cpu_key].value
        run_cnt = run_counts[cpu_key].value
        high_lat_cnt = high_latency_counts[cpu_key].value

        # Update cumulative counters
        if update_cumulative:
            cumulative_stats['wakeup_counts'][cpu] = cumulative_stats['wakeup_counts'].get(cpu, 0) + wakeup_cnt
            cumulative_stats['run_counts'][cpu] = cumulative_stats['run_counts'].get(cpu, 0) + run_cnt
            cumulative_stats['high_latency_counts'][cpu] = cumulative_stats['high_latency_counts'].get(cpu, 0) + high_lat_cnt

        print("  Wakeup count: %d" % wakeup_cnt)
        print("  Run count:    %d" % run_cnt)
        print("  High latency events (>100us): %d" % high_lat_cnt)

        if wakeup_cnt != run_cnt:
            print("  WARNING: Wakeup/run count mismatch (%d wakeups but %d runs)" % (
                wakeup_cnt, run_cnt))

        # Print histogram
        slots = cpu_data[cpu]
        total_samples = sum(slots.values())

        if total_samples == 0:
            print("  No latency samples")
            continue

        print("  Total samples: %d" % total_samples)
        print("  Latency distribution:")

        sorted_slots = sorted(slots.items())
        max_count = max(slots.values())

        for slot, count in sorted_slots:
            if count > 0:
                if slot == 0:
                    range_str = "0-1us"
                else:
                    low = 1 << (slot - 1)
                    high = (1 << slot) - 1
                    range_str = "%d-%dus" % (low, high)

                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                percentage = 100.0 * count / total_samples

                print("    %-16s: %6d (%5.1f%%) |%-40s|" % (
                    range_str, count, percentage, bar))

        # Highlight high latency
        high_latency_slots = [slot for slot, count in sorted_slots if slot >= 7 and count > 0]  # >= 64us
        if high_latency_slots:
            print("    ^^^ WARNING: High scheduling latency detected (>= 64us) ^^^")

    # Print summary
    print("\n" + "=" * 80)
    print("Summary:")
    total_wakeups = sum(wakeup_counts[ctypes.c_int(int(cpu))].value for cpu in cpu_data.keys())
    total_runs = sum(run_counts[ctypes.c_int(int(cpu))].value for cpu in cpu_data.keys())
    total_high = sum(high_latency_counts[ctypes.c_int(int(cpu))].value for cpu in cpu_data.keys())

    print("  Total wakeups:           %d" % total_wakeups)
    print("  Total runs:              %d" % total_runs)
    print("  Total high latency (>100us): %d" % total_high)

    if total_runs > 0:
        high_latency_rate = 100.0 * total_high / total_runs
        print("  High latency rate:       %.2f%%" % high_latency_rate)

    print("=" * 80)

    # Clear histogram for next interval
    hist.clear()

def print_cumulative_summary(target_cpus, program_start_time):
    """Print cumulative statistics from start to end"""
    global cumulative_stats

    current_time = datetime.datetime.now()
    total_duration = time_time() - program_start_time

    print("\n" + "=" * 80)
    print("[%s] CUMULATIVE ksoftirqd Scheduling Latency Report (Total Duration: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        total_duration
    ))
    print("=" * 80)

    cpu_data = cumulative_stats['cpu_data']

    # Filter CPUs if target_cpus specified
    if target_cpus:
        cpu_data = {cpu: data for cpu, data in cpu_data.items() if cpu in target_cpus}

    if not cpu_data:
        print("No cumulative data collected")
        return

    # Print per-CPU cumulative statistics
    print("\nPer-CPU ksoftirqd Scheduling Latency (Cumulative):")
    print("-" * 80)

    for cpu in sorted(cpu_data.keys()):
        print("\nCPU %d (ksoftirqd/%d):" % (cpu, cpu))

        wakeup_cnt = cumulative_stats['wakeup_counts'].get(cpu, 0)
        run_cnt = cumulative_stats['run_counts'].get(cpu, 0)
        high_lat_cnt = cumulative_stats['high_latency_counts'].get(cpu, 0)

        print("  Wakeup count: %d" % wakeup_cnt)
        print("  Run count:    %d" % run_cnt)
        print("  High latency events (>100us): %d" % high_lat_cnt)

        if wakeup_cnt != run_cnt:
            print("  WARNING: Wakeup/run count mismatch (%d wakeups but %d runs)" % (
                wakeup_cnt, run_cnt))

        # Print histogram
        slots = cpu_data[cpu]
        total_samples = sum(slots.values())

        if total_samples == 0:
            print("  No latency samples")
            continue

        print("  Total samples: %d" % total_samples)
        print("  Latency distribution:")

        sorted_slots = sorted(slots.items())
        max_count = max(slots.values())

        for slot, count in sorted_slots:
            if count > 0:
                if slot == 0:
                    range_str = "0-1us"
                else:
                    low = 1 << (slot - 1)
                    high = (1 << slot) - 1
                    range_str = "%d-%dus" % (low, high)

                bar_width = int(40 * count / max_count)
                bar = "*" * bar_width
                percentage = 100.0 * count / total_samples

                print("    %-16s: %6d (%5.1f%%) |%-40s|" % (
                    range_str, count, percentage, bar))

        # Highlight high latency
        high_latency_slots = [slot for slot, count in sorted_slots if slot >= 7 and count > 0]
        if high_latency_slots:
            print("    ^^^ WARNING: High scheduling latency detected (>= 64us) ^^^")

    # Print summary
    print("\n" + "=" * 80)
    print("Cumulative Summary:")
    total_wakeups = sum(cumulative_stats['wakeup_counts'].get(cpu, 0) for cpu in cpu_data.keys())
    total_runs = sum(cumulative_stats['run_counts'].get(cpu, 0) for cpu in cpu_data.keys())
    total_high = sum(cumulative_stats['high_latency_counts'].get(cpu, 0) for cpu in cpu_data.keys())

    print("  Total wakeups:           %d" % total_wakeups)
    print("  Total runs:              %d" % total_runs)
    print("  Total high latency (>100us): %d" % total_high)

    if total_runs > 0:
        high_latency_rate = 100.0 * total_high / total_runs
        print("  High latency rate:       %.2f%%" % high_latency_rate)

    print("=" * 80)

def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="ksoftirqd Scheduling Latency Measurement Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Measure all CPUs with 5s interval:
    sudo %(prog)s --interval 5

  Measure specific CPU:
    sudo %(prog)s --cpu 105

  Measure multiple CPUs:
    sudo %(prog)s --cpu 105,106,107

  Measure CPU range:
    sudo %(prog)s --cpu 100-110

This tool measures the scheduling latency of ksoftirqd kernel threads,
which is the delay between wakeup and actual execution. High latency
(>100us) can cause network packet processing delays.
"""
    )

    parser.add_argument('--cpu', type=str, required=False,
                        help='Target CPU(s) to monitor (e.g., 105 or 105,106 or 100-110). Default: all CPUs')
    parser.add_argument('--interval', type=int, default=5,
                        help='Statistics interval in seconds (default: 5)')
    parser.add_argument('--duration', type=int, default=0,
                        help='Total execution time in seconds (default: 0 = run indefinitely)')

    args = parser.parse_args()

    # Parse CPU filter
    target_cpus = parse_cpu_list(args.cpu) if args.cpu else None
    cpu_filter = target_cpus[0] if target_cpus and len(target_cpus) == 1 else -1

    print("=" * 80)
    print("ksoftirqd Scheduling Latency Measurement")
    print("=" * 80)

    if target_cpus:
        if len(target_cpus) == 1:
            print("Target CPU: %d" % target_cpus[0])
        else:
            print("Target CPUs: %s" % ', '.join(map(str, target_cpus)))
    else:
        print("Target CPUs: All")

    print("Statistics interval: %d seconds" % args.interval)
    if args.duration > 0:
        print("Total duration: %d seconds" % args.duration)
    else:
        print("Total duration: Unlimited (run until Ctrl-C)")
    print("\nMeasuring ksoftirqd scheduling latency...")
    print("  - Wakeup event: sched:sched_wakeup")
    print("  - Run event: sched:sched_switch")
    print("  - Latency = run_time - wakeup_time")
    print("=" * 80)

    try:
        b = BPF(text=bpf_text % cpu_filter)
        print("\nBPF program loaded successfully")
        print("Tracepoints attached:")
        print("  - tracepoint:sched:sched_wakeup")
        print("  - tracepoint:sched:sched_switch")
    except Exception as e:
        print("\nError loading BPF program: %s" % e)
        sys.exit(1)

    print("\nCollecting latency data... Hit Ctrl-C to end.")
    print("Statistics will be displayed every %d seconds\n" % args.interval)

    # Setup signal handler
    program_start_time = time_time()

    def signal_handler(sig, frame):
        print("\n\nFinal interval statistics:")
        print_histogram_summary(b, target_cpus, interval_start_time, update_cumulative=False)
        print("\n")
        print_cumulative_summary(target_cpus, program_start_time)
        print("\nExiting...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Main loop
    interval_start_time = time_time()

    try:
        while True:
            sleep(args.interval)

            # Check if duration limit exceeded
            if args.duration > 0 and (time_time() - program_start_time) >= args.duration:
                print("\n\nDuration limit reached (%d seconds)" % args.duration)
                print("\nFinal interval statistics:")
                print_histogram_summary(b, target_cpus, interval_start_time, update_cumulative=False)
                print("\n")
                print_cumulative_summary(target_cpus, program_start_time)
                break

            print_histogram_summary(b, target_cpus, interval_start_time, update_cumulative=True)
            interval_start_time = time_time()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        print("\nFinal interval statistics:")
        print_histogram_summary(b, target_cpus, interval_start_time, update_cumulative=False)
        print("\n")
        print_cumulative_summary(target_cpus, program_start_time)

if __name__ == "__main__":
    main()
