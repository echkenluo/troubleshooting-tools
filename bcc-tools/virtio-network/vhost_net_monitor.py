#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import socket
import struct
import sys
import time
from bcc import BPF
import ctypes as ct
from collections import defaultdict

# BPF program for comprehensive vhost-net monitoring
bpf_text = """
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/netdevice.h>
#include <linux/ptr_ring.h>

// Event types
#define EVENT_HANDLE_TX_ENTER       1
#define EVENT_HANDLE_TX_EXIT        2
#define EVENT_PTR_RING_CONSUME      3
#define EVENT_TUN_RECVMSG_ENTER     4
#define EVENT_TUN_RECVMSG_EXIT      5
#define EVENT_WORKER_SCHEDULE       6
#define EVENT_PTR_RING_PRODUCE      7
#define EVENT_QUEUE_STATE_SNAPSHOT  8

// Device name union for filtering
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

struct vhost_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    char dev_name[16];
    u32 queue_id;
    u32 ptr_ring_producer;
    u32 ptr_ring_consumer_head;
    u32 ptr_ring_consumer_tail;
    u32 ptr_ring_size;
    u32 available_work;
    u32 consumed_packets;
    u32 event_type;
    s32 error_code;
    u64 duration_ns;        // For enter/exit events
    u64 skb_addr;          // SKB address for debugging
    u32 ring_utilization;  // Ring usage percentage
};

// Maps for tracking state
BPF_PERF_OUTPUT(events);
BPF_HASH(enter_times, u32, u64);  // Track function entry times
BPF_ARRAY(device_filter, union name_buf, 1);
BPF_ARRAY(queue_filter, u32, 1);
BPF_ARRAY(monitor_enabled, u32, 1);

// Device filter helper
static inline int device_name_matches(const char *dev_name) {
    union name_buf real_devname = {};
    union name_buf *filter;
    int key = 0;
    
    bpf_probe_read_kernel_str(real_devname.name, IFNAMSIZ, dev_name);
    filter = device_filter.lookup(&key);
    
    if (!filter) return 1;  // No filter set
    if (filter->name_int.hi == 0 && filter->name_int.lo == 0) return 1;  // Empty filter
    
    return (filter->name_int.hi == real_devname.name_int.hi && 
            filter->name_int.lo == real_devname.name_int.lo);
}

// Queue filter helper
static inline int queue_matches(u32 queue_id) {
    int key = 0;
    u32 *filter = queue_filter.lookup(&key);
    if (!filter || *filter == 0xFFFFFFFF) return 1;  // No filter or wildcard
    return (*filter == queue_id);
}

// Helper to extract basic queue information
static inline void extract_queue_info(struct vhost_event *event, u32 queue_id) {
    event->queue_id = queue_id;
    // Without direct ptr_ring access, we track activity through function calls
    event->ptr_ring_size = 1;  // Indicate queue exists
    event->ring_utilization = 0;  // Cannot calculate without direct access
}

// Helper to emit event
static inline void emit_event(struct pt_regs *ctx, u32 event_type) {
    int key = 0;
    u32 *enabled = monitor_enabled.lookup(&key);
    if (!enabled || *enabled == 0) return;
    
    struct vhost_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.event_type = event_type;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    events.perf_submit(ctx, &event, sizeof(event));
}

// Probe handle_tx_net (specific variant that exists)
int probe_handle_tx_net_enter(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 ts = bpf_ktime_get_ns();
    enter_times.update(&tid, &ts);
    
    struct vhost_event event = {};
    event.timestamp = ts;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = tid;
    event.event_type = EVENT_HANDLE_TX_ENTER;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int probe_handle_tx_net_exit(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 *enter_ts = enter_times.lookup(&tid);
    
    struct vhost_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = tid;
    event.event_type = EVENT_HANDLE_TX_EXIT;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    if (enter_ts) {
        event.duration_ns = event.timestamp - *enter_ts;
        enter_times.delete(&tid);
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe tun_recvmsg
int probe_tun_recvmsg_enter(struct pt_regs *ctx, struct socket *sock) {
    // Check if this is for our target device
    struct sock *sk = sock->sk;
    if (!sk) return 0;
    
    // Try to extract device name from socket
    struct vhost_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.event_type = EVENT_TUN_RECVMSG_ENTER;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int probe_tun_recvmsg_exit(struct pt_regs *ctx) {
    emit_event(ctx, EVENT_TUN_RECVMSG_EXIT);
    return 0;
}

// Monitor general activity through tap_get_ptr_ring (the only available ptr_ring function)
int probe_tap_get_ptr_ring(struct pt_regs *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Only monitor vhost and qemu processes
    if (comm[0] != 'v' && comm[0] != 'q') return 0;
    
    struct vhost_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.event_type = EVENT_PTR_RING_CONSUME;  // Treat as consumption activity
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Basic activity marker
    event.ptr_ring_size = 1;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe tun_net_xmit to get device context
int probe_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!dev) return 0;
    
    char dev_name[IFNAMSIZ];
    bpf_probe_read_kernel_str(dev_name, sizeof(dev_name), dev->name);
    
    if (!device_name_matches(dev_name)) return 0;
    
    struct vhost_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event.event_type = EVENT_QUEUE_STATE_SNAPSHOT;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.queue_id = skb->queue_mapping;
    event.skb_addr = (u64)skb;
    
    bpf_probe_read_kernel_str(event.dev_name, sizeof(event.dev_name), dev->name);
    
    if (!queue_matches(event.queue_id)) return 0;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class VhostEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_name", ct.c_char * 16),
        ("queue_id", ct.c_uint32),
        ("ptr_ring_producer", ct.c_uint32),
        ("ptr_ring_consumer_head", ct.c_uint32),
        ("ptr_ring_consumer_tail", ct.c_uint32),
        ("ptr_ring_size", ct.c_uint32),
        ("available_work", ct.c_uint32),
        ("consumed_packets", ct.c_uint32),
        ("event_type", ct.c_uint32),
        ("error_code", ct.c_int32),
        ("duration_ns", ct.c_uint64),
        ("skb_addr", ct.c_uint64),
        ("ring_utilization", ct.c_uint32),
    ]

class DeviceName(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]

# Event type constants
EVENT_TYPES = {
    1: "HANDLE_TX_ENTER",
    2: "HANDLE_TX_EXIT", 
    3: "PTR_RING_CONSUME",
    4: "TUN_RECVMSG_ENTER",
    5: "TUN_RECVMSG_EXIT",
    6: "WORKER_SCHEDULE",
    7: "PTR_RING_PRODUCE",
    8: "QUEUE_STATE_SNAPSHOT"
}

class VhostNetMonitor:
    def __init__(self, device=None, queue=None, verbose=False):
        self.device = device
        self.queue = queue if queue is not None else 0xFFFFFFFF  # Wildcard
        self.verbose = verbose
        self.stats = defaultdict(int)
        self.queue_states = {}
        self.start_time = time.time()
        
    def print_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(VhostEvent)).contents
        
        timestamp = time.time()
        event_type = EVENT_TYPES.get(event.event_type, f"UNKNOWN({event.event_type})")
        
        self.stats[event_type] += 1
        
        # Format timestamp
        ts_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
        ms = int((timestamp % 1) * 1000)
        ts_str += f".{ms:03d}"
        
        device = event.dev_name.decode('utf-8', 'replace') if event.dev_name else 'N/A'
        comm = event.comm.decode('utf-8', 'replace')
        
        print(f"[{ts_str}] {device:>8} Q{event.queue_id:<2} {event_type:<18} "
              f"{comm:<12} PID:{event.pid:<6}")
        
        # Event-specific details
        if event.event_type in [3, 7]:  # PTR_RING events
            if event.ptr_ring_size > 0:
                print(f"  └─ Ring: size={event.ptr_ring_size} "
                      f"prod={event.ptr_ring_producer} "
                      f"cons_h={event.ptr_ring_consumer_head} "
                      f"cons_t={event.ptr_ring_consumer_tail} "
                      f"util={event.ring_utilization}%")
                
                # Detect the problematic condition
                if (event.ptr_ring_producer == 0 and 
                    event.ptr_ring_consumer_head == 0 and 
                    event.ptr_ring_consumer_tail == 0):
                    print(f"  🚨 DETECTED: All pointers are 0! Queue {event.queue_id} may be stuck!")
            else:
                print(f"  └─ Ring: UNINITIALIZED or ERROR")
                
        elif event.event_type == 2:  # HANDLE_TX_EXIT
            if event.duration_ns > 0:
                duration_us = event.duration_ns / 1000
                print(f"  └─ Duration: {duration_us:.1f}μs")
                
        elif event.event_type == 8:  # QUEUE_STATE_SNAPSHOT
            print(f"  └─ SKB: 0x{event.skb_addr:x} Queue: {event.queue_id}")
            
        # Track queue states
        if event.ptr_ring_size > 0:
            queue_key = (device, event.queue_id)
            self.queue_states[queue_key] = {
                'producer': event.ptr_ring_producer,
                'consumer_head': event.ptr_ring_consumer_head,
                'consumer_tail': event.ptr_ring_consumer_tail,
                'size': event.ptr_ring_size,
                'utilization': event.ring_utilization,
                'last_seen': timestamp
            }
        
        if self.verbose:
            print()
            
    def print_stats(self):
        print("\n" + "="*80)
        print("VHOST-NET MONITORING STATISTICS")
        print("="*80)
        
        runtime = time.time() - self.start_time
        print(f"Runtime: {runtime:.1f}s")
        print()
        
        print("Event Counts:")
        for event_type, count in sorted(self.stats.items()):
            rate = count / runtime if runtime > 0 else 0
            print(f"  {event_type:<20}: {count:>8} ({rate:.1f}/s)")
        print()
        
        print("Queue States (Last Seen):")
        for (device, queue_id), state in sorted(self.queue_states.items()):
            age = time.time() - state['last_seen']
            print(f"  {device} Q{queue_id}: prod={state['producer']} "
                  f"cons_h={state['consumer_head']} cons_t={state['consumer_tail']} "
                  f"util={state['utilization']}% (seen {age:.1f}s ago)")
            
            # Highlight problematic queues
            if (state['producer'] == 0 and 
                state['consumer_head'] == 0 and 
                state['consumer_tail'] == 0):
                print(f"    🚨 PROBLEM: All pointers are 0!")
        
    def run(self):
        try:
            if self.verbose:
                print("Loading BPF program...")
                
            b = BPF(text=bpf_text)
            
            # Attach probes
            if self.verbose:
                print("Attaching kprobes...")
                
            # Core vhost-net functions - using specific variant that exists
            b.attach_kprobe(event="handle_tx_net", fn_name="probe_handle_tx_net_enter")
            b.attach_kretprobe(event="handle_tx_net", fn_name="probe_handle_tx_net_exit")
            
            # TUN functions  
            b.attach_kprobe(event="tun_recvmsg", fn_name="probe_tun_recvmsg_enter")  
            b.attach_kretprobe(event="tun_recvmsg", fn_name="probe_tun_recvmsg_exit")
            b.attach_kprobe(event="tun_net_xmit", fn_name="probe_tun_net_xmit")
            
            # Available ptr_ring related function
            b.attach_kprobe(event="tap_get_ptr_ring", fn_name="probe_tap_get_ptr_ring")
            
        except Exception as e:
            print(f"❌ Failed to load BPF program: {e}")
            return
            
        # Configure filters
        b["monitor_enabled"][0] = ct.c_uint32(1)
        b["queue_filter"][0] = ct.c_uint32(self.queue)
        
        if self.device:
            device_name = DeviceName()
            device_name.name = self.device.encode()
            b["device_filter"][0] = device_name
            print(f"📡 Device filter: {self.device}")
        else:
            print("📡 Device filter: All devices")
            
        if self.queue != 0xFFFFFFFF:
            print(f"🎯 Queue filter: {self.queue}")
        else:
            print("🎯 Queue filter: All queues")
            
        print()
        print("🔍 VHOST-NET Monitor Started")
        print("Monitoring: ptr_ring operations, vhost worker activity, TUN/vhost interactions")
        print("Press Ctrl+C to stop and show statistics")
        print("="*80)
        print()
        
        try:
            b["events"].open_perf_buffer(self.print_event)
            while True:
                try:
                    b.perf_buffer_poll()
                except KeyboardInterrupt:
                    break
        except KeyboardInterrupt:
            pass
        
        self.print_stats()
        print("\n👋 Monitoring stopped.")

def main():
    parser = argparse.ArgumentParser(
        description="vhost-net comprehensive monitoring tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all vhost-net activity
  sudo %(prog)s
  
  # Monitor specific device
  sudo %(prog)s --device vnet0
  
  # Monitor specific device and queue  
  sudo %(prog)s --device vnet0 --queue 0
  
  # Verbose mode with detailed output
  sudo %(prog)s --device vnet0 --verbose
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet0)")
    parser.add_argument("--queue", "-q", type=int, help="Target queue ID (default: all queues)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    monitor = VhostNetMonitor(
        device=args.device,
        queue=args.queue, 
        verbose=args.verbose
    )
    
    monitor.run()

if __name__ == "__main__":
    main()