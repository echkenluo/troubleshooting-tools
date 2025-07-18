#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
vhost_basic_monitor.py - Basic vhost signal monitor

This tool monitors vhost_add_used_and_signal_n function calls to provide
basic analysis of vhost activity and batch processing patterns.
"""

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
import ctypes as ct
from bcc import BPF

# BPF program for basic vhost monitoring
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>
#include <uapi/linux/virtio_ring.h>

#define IFNAMSIZ 16

// Basic event structure for vhost signal analysis
struct vhost_basic_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    // Function parameters
    u64 dev_ptr;
    u64 vq_ptr;
    u64 heads_ptr;
    u32 heads_count;
    
    // Basic extracted information (safely accessible)
    u16 last_avail_idx;
    u16 avail_idx;
    u16 last_used_idx;
    u16 used_flags;
    u16 signalled_used;
    u8 signalled_used_valid;
    u32 vq_num;
    u64 call_ctx_ptr;
    u32 busyloop_timeout;
    u8 log_used;
    
    // Error tracking
    u32 read_failures;
};

// Maps
BPF_PERF_OUTPUT(events);

// Device filter
struct filter_config {
    char device[IFNAMSIZ];
    u32 queue;
    u8 enabled;
};
BPF_ARRAY(filter_settings, struct filter_config, 1);

// Helper function to safely read vhost_virtqueue basic fields
static inline void extract_basic_vq_info(void *vq_ptr, struct vhost_basic_event *event) {
    if (!vq_ptr) return;
    
    // Try to read basic fields that are likely to be accessible
    // Based on vhost_virtqueue structure offsets
    
    // Read num (offset around 40-48 bytes typically)
    if (bpf_probe_read_kernel(&event->vq_num, sizeof(event->vq_num), 
                             (char*)vq_ptr + 40) != 0) {
        event->read_failures++;
    }
    
    // Read last_avail_idx (offset around 100-120 bytes)
    if (bpf_probe_read_kernel(&event->last_avail_idx, sizeof(event->last_avail_idx), 
                             (char*)vq_ptr + 108) != 0) {
        event->read_failures++;
    }
    
    // Read avail_idx
    if (bpf_probe_read_kernel(&event->avail_idx, sizeof(event->avail_idx), 
                             (char*)vq_ptr + 110) != 0) {
        event->read_failures++;
    }
    
    // Read last_used_idx
    if (bpf_probe_read_kernel(&event->last_used_idx, sizeof(event->last_used_idx), 
                             (char*)vq_ptr + 112) != 0) {
        event->read_failures++;
    }
    
    // Read used_flags
    if (bpf_probe_read_kernel(&event->used_flags, sizeof(event->used_flags), 
                             (char*)vq_ptr + 114) != 0) {
        event->read_failures++;
    }
    
    // Read signalled_used
    if (bpf_probe_read_kernel(&event->signalled_used, sizeof(event->signalled_used), 
                             (char*)vq_ptr + 116) != 0) {
        event->read_failures++;
    }
    
    // Read signalled_used_valid
    if (bpf_probe_read_kernel(&event->signalled_used_valid, sizeof(event->signalled_used_valid), 
                             (char*)vq_ptr + 118) != 0) {
        event->read_failures++;
    }
    
    // Read call_ctx pointer (eventfd for signaling)
    if (bpf_probe_read_kernel(&event->call_ctx_ptr, sizeof(event->call_ctx_ptr), 
                             (char*)vq_ptr + 72) != 0) {
        event->read_failures++;
    }
    
    // Read log_used flag
    if (bpf_probe_read_kernel(&event->log_used, sizeof(event->log_used), 
                             (char*)vq_ptr + 119) != 0) {
        event->read_failures++;
    }
    
    // Read busyloop_timeout
    if (bpf_probe_read_kernel(&event->busyloop_timeout, sizeof(event->busyloop_timeout), 
                             (char*)vq_ptr + 216) != 0) {
        event->read_failures++;
    }
}

// Main probe function for vhost_add_used_and_signal_n
int trace_vhost_add_used_and_signal_n(struct pt_regs *ctx) {
    struct vhost_dev *dev = (struct vhost_dev *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    void *heads = (void *)PT_REGS_PARM3(ctx);
    unsigned count = (unsigned)PT_REGS_PARM4(ctx);
    
    if (!dev || !vq) return 0;
    
    // Create basic event
    struct vhost_basic_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Basic identification
    event.dev_ptr = (u64)dev;
    event.vq_ptr = (u64)vq;
    event.heads_ptr = (u64)heads;
    event.heads_count = count;
    
    // Extract basic virtqueue information
    extract_basic_vq_info(vq, &event);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Event structure matching BPF program
class VhostBasicEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_ptr", ct.c_uint64),
        ("vq_ptr", ct.c_uint64),
        ("heads_ptr", ct.c_uint64),
        ("heads_count", ct.c_uint32),
        ("last_avail_idx", ct.c_uint16),
        ("avail_idx", ct.c_uint16),
        ("last_used_idx", ct.c_uint16),
        ("used_flags", ct.c_uint16),
        ("signalled_used", ct.c_uint16),
        ("signalled_used_valid", ct.c_uint8),
        ("vq_num", ct.c_uint32),
        ("call_ctx_ptr", ct.c_uint64),
        ("busyloop_timeout", ct.c_uint32),
        ("log_used", ct.c_uint8),
        ("read_failures", ct.c_uint32),
    ]

def format_hex_ptr(ptr_val):
    """Format pointer as hex or 'NULL' if zero"""
    return "0x{:x}".format(ptr_val) if ptr_val else "NULL"

def format_bool(bool_val):
    """Format boolean as YES/NO"""
    return "YES" if bool_val else "NO"

def print_basic_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(VhostBasicEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    print("=" * 80)
    print("🔍 VHOST SIGNAL EVENT | Time: {}".format(timestamp_str))
    print("=" * 80)
    
    # Basic Info
    print("📍 Process: {} (PID: {}, TID: {})".format(event.comm.decode('utf-8', 'replace'), event.pid, event.tid))
    print("🎯 Batch Size: {} descriptors".format(event.heads_count))
    print("🔗 Pointers: dev={} vq={} heads={}".format(
        format_hex_ptr(event.dev_ptr), 
        format_hex_ptr(event.vq_ptr), 
        format_hex_ptr(event.heads_ptr)
    ))
    
    # Virtqueue State
    print("\n🔄 VIRTQUEUE STATE:")
    print("   Ring Size: {}".format(event.vq_num))
    print("   Ring Indices: last_avail={} avail_idx={} last_used={}".format(
        event.last_avail_idx, event.avail_idx, event.last_used_idx
    ))
    print("   Ring Flags: used_flags=0x{:x}".format(event.used_flags))
    print("   Signaling: signalled_used={} valid={}".format(
        event.signalled_used, format_bool(event.signalled_used_valid)
    ))
    
    # Configuration
    print("\n⚙️  CONFIGURATION:")
    print("   Event FD: call_ctx={}".format(format_hex_ptr(event.call_ctx_ptr)))
    print("   Logging: enabled={}".format(format_bool(event.log_used)))
    print("   Busyloop Timeout: {}us".format(event.busyloop_timeout))
    
    # Debug Info
    print("\n🐛 DEBUG INFO:")
    print("   Memory Read Failures: {}".format(event.read_failures))
    
    print("=" * 80)
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Basic vhost signal monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool monitors vhost_add_used_and_signal_n function calls to provide
basic analysis of vhost activity and batch processing patterns.

Examples:
  # Monitor all vhost activity
  sudo %(prog)s
  
  # Monitor with verbose output
  sudo %(prog)s --verbose
        """
    )
    
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading basic vhost monitor BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach probe
        b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_add_used_and_signal_n")
        
        if args.verbose:
            print("✅ Probe attached successfully")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        return
    
    print("🔍 Basic VHOST Signal Monitor Started")
    print("📊 Monitoring vhost_add_used_and_signal_n with basic analysis")
    print("⏳ Waiting for events... Press Ctrl+C to stop\n")
    
    try:
        b["events"].open_perf_buffer(print_basic_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\n👋 Basic monitoring stopped.")

if __name__ == "__main__":
    main()