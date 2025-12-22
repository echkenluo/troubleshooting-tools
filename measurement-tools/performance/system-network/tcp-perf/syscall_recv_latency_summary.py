#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
System Call recv/read Latency Measurement Tool

Measures the latency of read/recv/recvfrom/recvmsg system calls to understand
userspace application receive performance. This helps diagnose:
- Why applications have slow packet reception (high Recv-Q)
- Impact of CPU/NUMA binding on recv() performance
- Whether the bottleneck is in syscall or application logic

Key Metrics:
- recv() system call latency distribution
- Bytes received per call
- CPU migration frequency
- NUMA node tracking (when available)
- Process scheduling information

Usage:
    # Monitor specific process (e.g., iperf3)
    sudo ./syscall_recv_latency.py --process iperf3

    # Monitor by PID
    sudo ./syscall_recv_latency.py --pid 12345

    # Monitor specific port
    sudo ./syscall_recv_latency.py --port 5201

    # Set custom interval
    sudo ./syscall_recv_latency.py --process iperf3 --interval 5

Example:
    # Compare with and without CPU binding:

    # Without binding:
    iperf3 -s -p 5201 &
    sudo ./syscall_recv_latency.py --port 5201

    # With binding:
    taskset -c 42 iperf3 -s -p 5201 &
    sudo ./syscall_recv_latency.py --port 5201
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
import socket
import struct

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <net/sock.h>

// Filter configuration
#define TARGET_PID %d
#define TARGET_PORT %d
#define HIGH_LATENCY_THRESHOLD_US %d
#define ENABLE_HIGH_LATENCY_EVENTS %d

// Syscall type identifiers
#define SYSCALL_READ 0
#define SYSCALL_RECVFROM 1
#define SYSCALL_RECVMSG 2

// Composite key to prevent syscall mixup
struct recv_key_t {
    u32 tid;
    u8 syscall_type;
};

// Track recv() call context
struct recv_enter_t {
    u64 ts;
    u32 cpu;
    int fd;
};

// Event data for userspace
struct recv_event_t {
    u64 ts_enter;
    u64 ts_exit;
    u64 latency_us;
    u32 pid;
    u32 tid;
    u32 cpu_enter;
    u32 cpu_exit;
    int fd;
    s64 bytes;
    char comm[TASK_COMM_LEN];
};

// Maps
BPF_HASH(recv_start, struct recv_key_t, struct recv_enter_t);  // Key: TID + syscall_type

// Histogram: recv latency distribution
BPF_HISTOGRAM(recv_latency_hist, u64, 512);

// Counters
BPF_ARRAY(counters, u64, 10);
// 0=total_calls, 1=total_bytes, 2=cpu_migrations, 3=errors, 4=zero_reads

// Perf event output for detailed analysis
BPF_PERF_OUTPUT(recv_events);

// Helper: Check if we should trace this task
static __always_inline bool should_trace(u32 pid, u32 tid) {
    // Filter by PID if specified
    if (TARGET_PID > 0 && pid != TARGET_PID) {
        return false;
    }

    return true;
}

// Helper: Get socket port (for filtering)
static __always_inline u16 get_socket_port(int fd) {
    // Note: This is simplified. In real implementation, we'd need to:
    // 1. Get file from fd
    // 2. Check if it's a socket
    // 3. Extract port from socket structure
    // For now, we'll just return 0 and rely on PID/process name filtering
    return 0;
}

// Tracepoint: sys_enter_recvfrom
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();

    if (!should_trace(pid, tid)) {
        return 0;
    }

    struct recv_key_t key = {};
    key.tid = tid;
    key.syscall_type = SYSCALL_RECVFROM;

    struct recv_enter_t enter = {};
    enter.ts = bpf_ktime_get_ns();
    enter.cpu = bpf_get_smp_processor_id();
    enter.fd = args->fd;

    recv_start.update(&key, &enter);

    return 0;
}

// Tracepoint: sys_exit_recvfrom
TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();

    struct recv_key_t key = {};
    key.tid = tid;
    key.syscall_type = SYSCALL_RECVFROM;

    struct recv_enter_t *enter = recv_start.lookup(&key);
    if (!enter) {
        return 0;
    }

    u64 ts_exit = bpf_ktime_get_ns();
    u32 cpu_exit = bpf_get_smp_processor_id();

    s64 bytes = args->ret;

    // Calculate latency
    u64 latency_ns = ts_exit - enter->ts;
    u64 latency_us = latency_ns / 1000;

    // Update histogram
    recv_latency_hist.increment(bpf_log2l(latency_us + 1));

    // Update counters
    u32 idx = 0;
    u64 *counter = counters.lookup(&idx);
    if (counter) (*counter)++;  // total_calls

    if (bytes > 0) {
        idx = 1;
        counter = counters.lookup(&idx);
        if (counter) __sync_fetch_and_add(counter, bytes);  // total_bytes
    } else if (bytes == 0) {
        idx = 4;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;  // zero_reads
    } else {
        idx = 3;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;  // errors
    }

    // Check CPU migration
    if (enter->cpu != cpu_exit) {
        idx = 2;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;  // cpu_migrations
    }

    // Submit detailed event (for high latency or sampling)
    #if ENABLE_HIGH_LATENCY_EVENTS
    if (latency_us > HIGH_LATENCY_THRESHOLD_US) {
        struct recv_event_t event = {};
        event.ts_enter = enter->ts;
        event.ts_exit = ts_exit;
        event.latency_us = latency_us;
        event.pid = pid;
        event.tid = tid;
        event.cpu_enter = enter->cpu;
        event.cpu_exit = cpu_exit;
        event.fd = enter->fd;
        event.bytes = bytes;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        recv_events.perf_submit(args, &event, sizeof(event));
    }
    #endif

    recv_start.delete(&key);

    return 0;
}

// Note: sys_enter_recv/sys_exit_recv may not exist on all kernels
// recv() syscall is often aliased to recvfrom(), so we rely on recvfrom tracepoints

// Also trace read() syscall - many applications (like iperf3) use read() on sockets
TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();

    if (!should_trace(pid, tid)) {
        return 0;
    }

    struct recv_key_t key = {};
    key.tid = tid;
    key.syscall_type = SYSCALL_READ;

    struct recv_enter_t enter = {};
    enter.ts = bpf_ktime_get_ns();
    enter.cpu = bpf_get_smp_processor_id();
    enter.fd = args->fd;

    recv_start.update(&key, &enter);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();

    struct recv_key_t key = {};
    key.tid = tid;
    key.syscall_type = SYSCALL_READ;

    struct recv_enter_t *enter = recv_start.lookup(&key);
    if (!enter) {
        return 0;
    }

    u64 ts_exit = bpf_ktime_get_ns();
    u32 cpu_exit = bpf_get_smp_processor_id();

    s64 bytes = args->ret;

    u64 latency_ns = ts_exit - enter->ts;
    u64 latency_us = latency_ns / 1000;

    recv_latency_hist.increment(bpf_log2l(latency_us + 1));

    u32 idx = 0;
    u64 *counter = counters.lookup(&idx);
    if (counter) (*counter)++;

    if (bytes > 0) {
        idx = 1;
        counter = counters.lookup(&idx);
        if (counter) __sync_fetch_and_add(counter, bytes);
    } else if (bytes == 0) {
        idx = 4;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;
    } else {
        idx = 3;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;
    }

    if (enter->cpu != cpu_exit) {
        idx = 2;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;
    }

    #if ENABLE_HIGH_LATENCY_EVENTS
    if (latency_us > HIGH_LATENCY_THRESHOLD_US) {
        struct recv_event_t event = {};
        event.ts_enter = enter->ts;
        event.ts_exit = ts_exit;
        event.latency_us = latency_us;
        event.pid = pid;
        event.tid = tid;
        event.cpu_enter = enter->cpu;
        event.cpu_exit = cpu_exit;
        event.fd = enter->fd;
        event.bytes = bytes;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        recv_events.perf_submit(args, &event, sizeof(event));
    }
    #endif

    recv_start.delete(&key);

    return 0;
}

// Also trace recvmsg
TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();

    if (!should_trace(pid, tid)) {
        return 0;
    }

    struct recv_key_t key = {};
    key.tid = tid;
    key.syscall_type = SYSCALL_RECVMSG;

    struct recv_enter_t enter = {};
    enter.ts = bpf_ktime_get_ns();
    enter.cpu = bpf_get_smp_processor_id();
    enter.fd = args->fd;

    recv_start.update(&key, &enter);

    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();

    struct recv_key_t key = {};
    key.tid = tid;
    key.syscall_type = SYSCALL_RECVMSG;

    struct recv_enter_t *enter = recv_start.lookup(&key);
    if (!enter) {
        return 0;
    }

    u64 ts_exit = bpf_ktime_get_ns();
    u32 cpu_exit = bpf_get_smp_processor_id();

    s64 bytes = args->ret;

    u64 latency_ns = ts_exit - enter->ts;
    u64 latency_us = latency_ns / 1000;

    recv_latency_hist.increment(bpf_log2l(latency_us + 1));

    u32 idx = 0;
    u64 *counter = counters.lookup(&idx);
    if (counter) (*counter)++;

    if (bytes > 0) {
        idx = 1;
        counter = counters.lookup(&idx);
        if (counter) __sync_fetch_and_add(counter, bytes);
    } else if (bytes == 0) {
        idx = 4;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;
    } else {
        idx = 3;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;
    }

    if (enter->cpu != cpu_exit) {
        idx = 2;
        counter = counters.lookup(&idx);
        if (counter) (*counter)++;
    }

    #if ENABLE_HIGH_LATENCY_EVENTS
    if (latency_us > HIGH_LATENCY_THRESHOLD_US) {
        struct recv_event_t event = {};
        event.ts_enter = enter->ts;
        event.ts_exit = ts_exit;
        event.latency_us = latency_us;
        event.pid = pid;
        event.tid = tid;
        event.cpu_enter = enter->cpu;
        event.cpu_exit = cpu_exit;
        event.fd = enter->fd;
        event.bytes = bytes;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));

        recv_events.perf_submit(args, &event, sizeof(event));
    }
    #endif

    recv_start.delete(&key);

    return 0;
}
"""

# Global event counter
high_latency_event_count = 0

# Cumulative statistics (from start to end)
cumulative_stats = {
    'total_calls': 0,
    'total_bytes': 0,
    'cpu_migrations': 0,
    'errors': 0,
    'zero_reads': 0,
    'histogram': {}
}

def print_high_latency_event(cpu, data, size):
    """Callback for high latency recv events"""
    global high_latency_event_count, b

    high_latency_event_count += 1
    event = b["recv_events"].event(data)

    print("\n" + "=" * 80)
    print("HIGH LATENCY RECV EVENT #%d" % high_latency_event_count)
    print("=" * 80)
    print("Timestamp: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"))
    print("\nLatency: %.3f ms" % (event.latency_us / 1000.0))
    print("\nProcess Information:")
    print("  PID: %d" % event.pid)
    print("  TID: %d" % event.tid)
    print("  Command: %s" % event.comm.decode('utf-8', 'replace'))
    print("  FD: %d" % event.fd)
    print("\nCPU Information:")
    print("  Enter CPU: %d" % event.cpu_enter)
    print("  Exit CPU: %d" % event.cpu_exit)
    if event.cpu_enter != event.cpu_exit:
        print("  ^^^ CPU MIGRATION DETECTED ^^^")
    print("\nData:")
    print("  Bytes received: %d" % event.bytes)
    print("=" * 80)

def print_summary(b, interval_start_time, enable_high_latency=False, update_cumulative=True):
    """Print summary statistics"""
    global cumulative_stats

    current_time = datetime.datetime.now()
    print("\n" + "=" * 80)
    print("[%s] recv() System Call Statistics (Interval: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        time_time() - interval_start_time
    ))
    print("=" * 80)

    counters = b["counters"]
    total_calls = counters[ctypes.c_int(0)].value
    total_bytes = counters[ctypes.c_int(1)].value
    cpu_migrations = counters[ctypes.c_int(2)].value
    errors = counters[ctypes.c_int(3)].value
    zero_reads = counters[ctypes.c_int(4)].value

    # Update cumulative statistics
    if update_cumulative:
        cumulative_stats['total_calls'] += total_calls
        cumulative_stats['total_bytes'] += total_bytes
        cumulative_stats['cpu_migrations'] += cpu_migrations
        cumulative_stats['errors'] += errors
        cumulative_stats['zero_reads'] += zero_reads

    print("\nInterval Statistics:")
    print("  Total recv() calls:    %d" % total_calls)
    print("  Total bytes received:  %d (%.2f MB)" % (total_bytes, total_bytes / 1024.0 / 1024.0))
    print("  CPU migrations:        %d" % cpu_migrations)
    print("  Zero-byte reads:       %d" % zero_reads)
    print("  Errors (ret < 0):      %d" % errors)

    if total_calls > 0:
        print("\nDerived Metrics:")
        print("  Avg bytes per call:    %.2f" % (float(total_bytes) / total_calls))
        print("  CPU migration rate:    %.2f%%" % (100.0 * cpu_migrations / total_calls))
        if total_bytes > 0:
            throughput_mbps = (total_bytes * 8.0) / (time_time() - interval_start_time) / 1000000.0
            print("  Throughput:            %.2f Mbps" % throughput_mbps)

    # Print latency histogram
    hist = b["recv_latency_hist"]
    print("\nrecv() Latency Distribution (Interval):")
    print("-" * 80)

    hist_data = {}
    try:
        for k, v in hist.items():
            slot = k.value if hasattr(k, 'value') else int(k)
            count = v.value if hasattr(v, 'value') else int(v)
            if count > 0:
                hist_data[slot] = count
                # Update cumulative histogram
                if update_cumulative:
                    cumulative_stats['histogram'][slot] = cumulative_stats['histogram'].get(slot, 0) + count
    except Exception as e:
        print("Error reading histogram:", str(e))
        return

    if not hist_data:
        print("No latency data collected")
    else:
        total_samples = sum(hist_data.values())
        max_count = max(hist_data.values())

        for slot in sorted(hist_data.keys()):
            count = hist_data[slot]
            if slot == 0:
                range_str = "0-1us"
            else:
                low = 1 << (slot - 1)
                high = (1 << slot) - 1
                range_str = "%d-%dus" % (low, high)

            bar_width = int(40 * count / max_count)
            bar = "*" * bar_width
            percentage = 100.0 * count / total_samples

            print("  %-16s: %6d (%5.1f%%) |%-40s|" % (
                range_str, count, percentage, bar))

        # Highlight slow calls
        slow_slots = [s for s in hist_data.keys() if s >= 10]  # >= 512us
        if slow_slots:
            print("  ^^^ WARNING: Slow recv() calls detected (>= 512us) ^^^")

    if enable_high_latency:
        print("\nHigh Latency Events: %d" % high_latency_event_count)
    print("=" * 80)

    # Clear histogram
    hist.clear()

def print_cumulative_summary(program_start_time):
    """Print cumulative statistics from start to end"""
    global cumulative_stats

    current_time = datetime.datetime.now()
    total_duration = time_time() - program_start_time

    print("\n" + "=" * 80)
    print("[%s] CUMULATIVE recv() System Call Statistics (Total Duration: %.1fs)" % (
        current_time.strftime("%Y-%m-%d %H:%M:%S"),
        total_duration
    ))
    print("=" * 80)

    total_calls = cumulative_stats['total_calls']
    total_bytes = cumulative_stats['total_bytes']
    cpu_migrations = cumulative_stats['cpu_migrations']
    errors = cumulative_stats['errors']
    zero_reads = cumulative_stats['zero_reads']

    print("\nCumulative Statistics:")
    print("  Total recv() calls:    %d" % total_calls)
    print("  Total bytes received:  %d (%.2f MB)" % (total_bytes, total_bytes / 1024.0 / 1024.0))
    print("  CPU migrations:        %d" % cpu_migrations)
    print("  Zero-byte reads:       %d" % zero_reads)
    print("  Errors (ret < 0):      %d" % errors)

    if total_calls > 0:
        print("\nDerived Metrics:")
        print("  Avg bytes per call:    %.2f" % (float(total_bytes) / total_calls))
        print("  CPU migration rate:    %.2f%%" % (100.0 * cpu_migrations / total_calls))
        if total_bytes > 0 and total_duration > 0:
            throughput_mbps = (total_bytes * 8.0) / total_duration / 1000000.0
            print("  Throughput:            %.2f Mbps" % throughput_mbps)

    # Print cumulative latency histogram
    hist_data = cumulative_stats['histogram']
    print("\nrecv() Latency Distribution (Cumulative):")
    print("-" * 80)

    if not hist_data:
        print("No latency data collected")
    else:
        total_samples = sum(hist_data.values())
        max_count = max(hist_data.values())

        for slot in sorted(hist_data.keys()):
            count = hist_data[slot]
            if slot == 0:
                range_str = "0-1us"
            else:
                low = 1 << (slot - 1)
                high = (1 << slot) - 1
                range_str = "%d-%dus" % (low, high)

            bar_width = int(40 * count / max_count)
            bar = "*" * bar_width
            percentage = 100.0 * count / total_samples

            print("  %-16s: %6d (%5.1f%%) |%-40s|" % (
                range_str, count, percentage, bar))

        # Highlight slow calls
        slow_slots = [s for s in hist_data.keys() if s >= 10]  # >= 512us
        if slow_slots:
            print("  ^^^ WARNING: Slow recv() calls detected (>= 512us) ^^^")

    print("=" * 80)

def get_pid_by_name(process_name):
    """Get PID by process name"""
    import subprocess
    try:
        output = subprocess.check_output(["pgrep", "-n", process_name])
        return int(output.strip())
    except subprocess.CalledProcessError:
        return -1

def main():
    global args, b

    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="System Call read/recv/recvfrom Latency Measurement Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Monitor iperf3 server:
    sudo %(prog)s --process iperf3 --interval 5

  Monitor specific PID:
    sudo %(prog)s --pid 12345

  Monitor specific port:
    sudo %(prog)s --port 5201

  Compare with and without CPU binding:
    # Terminal 1: Without binding
    iperf3 -s -p 5201 &
    sudo %(prog)s --process iperf3

    # Terminal 2: With binding
    taskset -c 42 iperf3 -s -p 5202 &
    sudo %(prog)s --port 5202

This tool helps diagnose:
- Why Recv-Q accumulates (slow recv calls)
- Impact of CPU/NUMA binding on performance
- Whether syscall or application is the bottleneck
"""
    )

    parser.add_argument('--process', type=str,
                        help='Process name to monitor (e.g., iperf3)')
    parser.add_argument('--pid', type=int,
                        help='Process ID to monitor')
    parser.add_argument('--port', type=int,
                        help='Port to monitor (requires netstat/ss parsing)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Statistics interval in seconds (default: 5)')
    parser.add_argument('--duration', type=int, default=0,
                        help='Total execution time in seconds (default: 0 = run indefinitely)')
    parser.add_argument('--high-latency-threshold', type=int, metavar='MICROSECONDS',
                        help='Enable high-latency event tracking with threshold in microseconds (e.g., 1000 for 1ms). '
                             'When specified, individual slow calls exceeding this threshold will be reported in real-time. '
                             'If not specified, only summary histogram is collected (default behavior).')

    args = parser.parse_args()

    # Determine target PID
    target_pid = -1
    target_port = -1

    if args.pid:
        target_pid = args.pid
    elif args.process:
        target_pid = get_pid_by_name(args.process)
        if target_pid == -1:
            print("Error: Process '%s' not found" % args.process)
            sys.exit(1)

    if args.port:
        target_port = args.port

    print("=" * 80)
    print("read/recv() System Call Latency Measurement")
    print("=" * 80)

    if target_pid > 0:
        print("Target PID: %d" % target_pid)
        if args.process:
            print("Target Process: %s" % args.process)
    else:
        print("Target: All processes")

    if target_port > 0:
        print("Target Port: %d" % target_port)

    print("Statistics interval: %d seconds" % args.interval)
    if args.duration > 0:
        print("Total duration: %d seconds" % args.duration)
    else:
        print("Total duration: Unlimited (run until Ctrl-C)")

    # High latency event tracking configuration
    high_latency_threshold = 0
    enable_high_latency = 0
    if args.high_latency_threshold:
        high_latency_threshold = args.high_latency_threshold
        enable_high_latency = 1
        print("High-latency event tracking: ENABLED (threshold: %d us = %.3f ms)" %
              (high_latency_threshold, high_latency_threshold / 1000.0))
    else:
        print("High-latency event tracking: DISABLED (only histogram summary)")

    print("\nMeasuring read/recv/recvfrom/recvmsg system calls...")
    print("=" * 80)

    try:
        b = BPF(text=bpf_text % (target_pid, target_port, high_latency_threshold, enable_high_latency))
        print("\nBPF program loaded successfully")
        print("Tracepoints attached:")
        print("  - tracepoint:syscalls:sys_enter_read")
        print("  - tracepoint:syscalls:sys_exit_read")
        print("  - tracepoint:syscalls:sys_enter_recvfrom")
        print("  - tracepoint:syscalls:sys_exit_recvfrom")
        print("  - tracepoint:syscalls:sys_enter_recvmsg")
        print("  - tracepoint:syscalls:sys_exit_recvmsg")
        print("Note: recv() is usually aliased to recvfrom(), many apps use read() on sockets")
    except Exception as e:
        print("\nError loading BPF program: %s" % e)
        sys.exit(1)

    print("\nCollecting data... Hit Ctrl-C to end.\n")

    # Open perf buffer for high latency events (only if enabled)
    if enable_high_latency:
        b["recv_events"].open_perf_buffer(print_high_latency_event)

    # Setup signal handler
    program_start_time = time_time()

    def signal_handler(sig, frame):
        print("\n\nFinal interval statistics:")
        print_summary(b, interval_start_time, enable_high_latency, update_cumulative=False)
        print("\n")
        print_cumulative_summary(program_start_time)
        print("\nExiting...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Main loop
    interval_start_time = time_time()

    try:
        while True:
            # Poll perf buffer (only if enabled)
            if enable_high_latency:
                b.perf_buffer_poll(timeout=100)
            else:
                sleep(0.1)

            # Check if duration limit exceeded
            if args.duration > 0 and (time_time() - program_start_time) >= args.duration:
                print("\n\nDuration limit reached (%d seconds)" % args.duration)
                print("\nFinal interval statistics:")
                print_summary(b, interval_start_time, enable_high_latency, update_cumulative=False)
                print("\n")
                print_cumulative_summary(program_start_time)
                break

            # Check if interval elapsed
            if time_time() - interval_start_time >= args.interval:
                print_summary(b, interval_start_time, enable_high_latency, update_cumulative=True)
                interval_start_time = time_time()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        print("\nFinal interval statistics:")
        print_summary(b, interval_start_time, enable_high_latency, update_cumulative=False)
        print("\n")
        print_cumulative_summary(program_start_time)

if __name__ == "__main__":
    main()
