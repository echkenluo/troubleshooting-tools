#!/usr/bin/env python
# vhost_wakeup_latency.py - Measure vhost worker scheduling delay
#
# This tool measures the time from when a vhost worker is woken up
# (via wake_up_process) to when it actually starts running.
#
# Usage: sudo python vhost_wakeup_latency.py [-d DURATION] [-i INTERVAL]

from __future__ import print_function
try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF
import argparse
import time
import signal
import sys

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct wakeup_event_t {
    u64 ts;
    u32 waker_pid;
    u32 waker_cpu;
    u32 target_cpu;
};

struct latency_event_t {
    u64 latency_ns;
    u32 target_pid;
    u32 waker_cpu;
    u32 target_cpu;
    u32 run_cpu;
    char comm[16];
};

BPF_HASH(start_ts, u32, struct wakeup_event_t);
BPF_HISTOGRAM(wakeup_latency_us, int);
BPF_PERF_OUTPUT(events);

// Count statistics
BPF_ARRAY(stats, u64, 4);  // 0: wakeup_count, 1: switch_count, 2: total_latency, 3: max_latency

// Trace try_to_wake_up or wake_up_process
TRACEPOINT_PROBE(sched, sched_wakeup) {
    char comm[16];
    bpf_probe_read_kernel_str(comm, sizeof(comm), args->comm);

    // Filter for vhost worker threads
    if (comm[0] != 'v' || comm[1] != 'h' || comm[2] != 'o' ||
        comm[3] != 's' || comm[4] != 't' || comm[5] != '-') {
        return 0;
    }

    u32 target_pid = args->pid;
    struct wakeup_event_t event = {};
    event.ts = bpf_ktime_get_ns();
    event.waker_pid = bpf_get_current_pid_tgid();
    event.waker_cpu = bpf_get_smp_processor_id();
    event.target_cpu = args->target_cpu;

    start_ts.update(&target_pid, &event);

    // Update wakeup count
    int idx = 0;
    u64 *count = stats.lookup(&idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

// Trace when the process actually starts running
TRACEPOINT_PROBE(sched, sched_switch) {
    u32 next_pid = args->next_pid;

    struct wakeup_event_t *start = start_ts.lookup(&next_pid);
    if (!start) {
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 delta_ns = now - start->ts;
    u64 delta_us = delta_ns / 1000;

    // Record histogram (in microseconds)
    int bucket = delta_us;
    if (bucket > 1000000) bucket = 1000000;  // Cap at 1 second
    wakeup_latency_us.increment(bpf_log2l(bucket));

    // Update statistics
    int idx = 1;
    u64 *count = stats.lookup(&idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    idx = 2;  // total_latency
    u64 *total = stats.lookup(&idx);
    if (total) {
        __sync_fetch_and_add(total, delta_us);
    }

    idx = 3;  // max_latency
    u64 *max_lat = stats.lookup(&idx);
    if (max_lat && delta_us > *max_lat) {
        *max_lat = delta_us;
    }

    // Send detailed event if latency > threshold (50us)
    if (delta_us > 50) {
        struct latency_event_t evt = {};
        evt.latency_ns = delta_ns;
        evt.target_pid = next_pid;
        evt.waker_cpu = start->waker_cpu;
        evt.target_cpu = start->target_cpu;
        evt.run_cpu = bpf_get_smp_processor_id();
        bpf_probe_read_kernel_str(evt.comm, sizeof(evt.comm), args->next_comm);
        events.perf_submit(args, &evt, sizeof(evt));
    }

    start_ts.delete(&next_pid);
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    latency_us = event.latency_ns / 1000.0
    comm = event.comm.decode('utf-8', 'replace')
    print("  [%s] pid=%d latency=%.1fus waker_cpu=%d target_cpu=%d run_cpu=%d" %
          (comm, event.target_pid, latency_us, event.waker_cpu, event.target_cpu, event.run_cpu))

def main():
    parser = argparse.ArgumentParser(
        description="Measure vhost worker scheduling delay")
    parser.add_argument("-d", "--duration", type=int, default=10,
        help="Duration to trace in seconds (default: 10)")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="Print interval in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Show individual high-latency events")
    args = parser.parse_args()

    global b
    b = BPF(text=bpf_text)

    if args.verbose:
        b["events"].open_perf_buffer(print_event)

    print("Tracing vhost worker wakeup latency...")
    print("Press Ctrl-C to exit")
    print("")

    exiting = [False]
    def signal_handler(sig, frame):
        exiting[0] = True
    signal.signal(signal.SIGINT, signal_handler)

    start_time = time.time()
    last_print = start_time

    while not exiting[0]:
        try:
            if args.verbose:
                b.perf_buffer_poll(timeout=100)
            else:
                time.sleep(0.1)

            now = time.time()
            if now - last_print >= args.interval:
                # Get statistics
                stats = b["stats"]
                wakeup_count = stats[0].value
                switch_count = stats[1].value
                total_latency = stats[2].value
                max_latency = stats[3].value

                avg_latency = total_latency / switch_count if switch_count > 0 else 0

                print("\n[%.1fs] Statistics:" % (now - start_time))
                print("  Wakeups: %d, Completed switches: %d" % (wakeup_count, switch_count))
                print("  Avg latency: %.1f us, Max latency: %d us" % (avg_latency, max_latency))
                last_print = now

            if args.duration > 0 and now - start_time >= args.duration:
                break

        except KeyboardInterrupt:
            break

    # Print final histogram
    print("\n" + "="*60)
    print("Wakeup Latency Histogram (microseconds):")
    print("="*60)
    b["wakeup_latency_us"].print_log2_hist("latency(us)")

    # Print final statistics
    stats = b["stats"]
    wakeup_count = stats[0].value
    switch_count = stats[1].value
    total_latency = stats[2].value
    max_latency = stats[3].value
    avg_latency = total_latency / switch_count if switch_count > 0 else 0

    print("\nFinal Statistics:")
    print("  Total wakeups: %d" % wakeup_count)
    print("  Completed switches: %d" % switch_count)
    print("  Average latency: %.1f us" % avg_latency)
    print("  Maximum latency: %d us" % max_latency)

if __name__ == "__main__":
    main()
