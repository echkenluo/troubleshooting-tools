#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
OVS queue_userspace_packet Return Value Tracer

Traces the return value of queue_userspace_packet function to diagnose
upcall failures in OVS datapath.

Usage:
    sudo ./queue_userspace_packet_retval.py
    sudo ./queue_userspace_packet_retval.py --filter-error   # Only show errors
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

import argparse
import sys
import os
from time import strftime
import errno

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>

struct event_t {
    u64 timestamp;
    u32 pid;
    int retval;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// Statistics counters
BPF_ARRAY(stats, u64, 16);

// Index definitions for stats array
#define STAT_TOTAL      0
#define STAT_SUCCESS    1
#define STAT_ENODEV     2
#define STAT_ENOMEM     3
#define STAT_EFBIG      4
#define STAT_EINVAL     5
#define STAT_EMSGSIZE   6
#define STAT_ENOBUFS    7
#define STAT_ENOTCONN   8
#define STAT_ECONNREFUSED 9
#define STAT_OTHER      10

static __always_inline void update_stat(int idx) {
    u64 *val = stats.lookup(&idx);
    if (val) {
        (*val)++;
    }
}

int trace_queue_userspace_packet_return(struct pt_regs *ctx)
{
    struct event_t event = {};
    int retval = PT_REGS_RC(ctx);

    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.retval = retval;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Update statistics
    int idx = STAT_TOTAL;
    update_stat(idx);

    if (retval == 0) {
        idx = STAT_SUCCESS;
    } else if (retval == -19) {  // -ENODEV
        idx = STAT_ENODEV;
    } else if (retval == -12) {  // -ENOMEM
        idx = STAT_ENOMEM;
    } else if (retval == -27) {  // -EFBIG
        idx = STAT_EFBIG;
    } else if (retval == -22) {  // -EINVAL
        idx = STAT_EINVAL;
    } else if (retval == -90) {  // -EMSGSIZE
        idx = STAT_EMSGSIZE;
    } else if (retval == -105) { // -ENOBUFS
        idx = STAT_ENOBUFS;
    } else if (retval == -107) { // -ENOTCONN
        idx = STAT_ENOTCONN;
    } else if (retval == -111) { // -ECONNREFUSED
        idx = STAT_ECONNREFUSED;
    } else {
        idx = STAT_OTHER;
    }
    update_stat(idx);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Error code mapping
ERRNO_MAP = {
    0: "SUCCESS",
    -errno.ENODEV: "ENODEV",
    -errno.ENOMEM: "ENOMEM",
    -errno.EFBIG: "EFBIG",
    -errno.EINVAL: "EINVAL",
    -errno.EMSGSIZE: "EMSGSIZE",
    -errno.ENOBUFS: "ENOBUFS",
    -errno.ENOTCONN: "ENOTCONN",
    -errno.ECONNREFUSED: "ECONNREFUSED",
}

def get_error_name(retval):
    """Convert return value to error name"""
    if retval in ERRNO_MAP:
        return ERRNO_MAP[retval]
    if retval < 0:
        return "ERR(%d)" % retval
    return "OK(%d)" % retval

def print_event(cpu, data, size, filter_error=False):
    """Print event callback"""
    import ctypes

    class Event(ctypes.Structure):
        _fields_ = [
            ("timestamp", ctypes.c_ulonglong),
            ("pid", ctypes.c_uint),
            ("retval", ctypes.c_int),
            ("comm", ctypes.c_char * 16),
        ]

    event = ctypes.cast(data, ctypes.POINTER(Event)).contents

    if filter_error and event.retval == 0:
        return

    error_name = get_error_name(event.retval)
    comm = event.comm.decode('utf-8', 'replace')

    print("[%s] PID:%-6d COMM:%-16s RET:%-4d (%s)" % (
        strftime("%H:%M:%S"),
        event.pid,
        comm,
        event.retval,
        error_name
    ))

def print_stats(b):
    """Print statistics summary"""
    stats = b["stats"]

    print("\n" + "=" * 60)
    print("Statistics Summary")
    print("=" * 60)

    stat_names = [
        (0, "Total calls"),
        (1, "Success (0)"),
        (2, "ENODEV (-19)"),
        (3, "ENOMEM (-12)"),
        (4, "EFBIG (-27)"),
        (5, "EINVAL (-22)"),
        (6, "EMSGSIZE (-90)"),
        (7, "ENOBUFS (-105)"),
        (8, "ENOTCONN (-107)"),
        (9, "ECONNREFUSED (-111)"),
        (10, "Other errors"),
    ]

    total = stats[0].value

    for idx, name in stat_names:
        val = stats[idx].value
        if val > 0 or idx == 0:
            if idx == 0:
                print("  %-25s: %d" % (name, val))
            else:
                pct = (val * 100.0 / total) if total > 0 else 0
                print("  %-25s: %d (%.1f%%)" % (name, val, pct))

    print("=" * 60)

def main():
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Trace queue_userspace_packet return values",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Return value meanings:
  0           Success - upcall sent to userspace
  -ENODEV     Datapath interface index not found
  -ENOMEM     Memory allocation failed
  -EFBIG      SKB too large
  -EINVAL     genlmsg_put failed
  -EMSGSIZE   Netlink message too large
  -ENOBUFS    Netlink buffer full
  -ENOTCONN   Netlink socket not connected (no ovs-vswitchd?)
  -ECONNREFUSED  Connection refused

Examples:
  %(prog)s                     # Trace all calls
  %(prog)s --filter-error      # Only show errors (non-zero returns)
"""
    )

    parser.add_argument('--filter-error', '-e', action='store_true',
                        help='Only show error returns (retval != 0)')

    args = parser.parse_args()

    print("=== OVS queue_userspace_packet Return Value Tracer ===")
    print("Tracing queue_userspace_packet returns...")
    if args.filter_error:
        print("Filter: Only showing errors (retval != 0)")
    print("Hit Ctrl-C to end.\n")

    # Load BPF program
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print("Error loading BPF program: %s" % e)
        sys.exit(1)

    # Attach kretprobe
    func_name = "queue_userspace_packet"
    try:
        b.attach_kretprobe(event=func_name, fn_name="trace_queue_userspace_packet_return")
        print("Attached kretprobe to %s" % func_name)
    except Exception as e:
        print("Error: Cannot attach to %s: %s" % (func_name, e))
        print("Make sure openvswitch kernel module is loaded")
        sys.exit(1)

    print("\n%-10s %-10s %-18s %-6s %s" % ("TIME", "PID", "COMM", "RET", "ERROR"))
    print("-" * 60)

    # Setup event callback with filter
    def event_callback(cpu, data, size):
        print_event(cpu, data, size, args.filter_error)

    b["events"].open_perf_buffer(event_callback)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    finally:
        print_stats(b)
        print("\nExiting...")

if __name__ == "__main__":
    main()
