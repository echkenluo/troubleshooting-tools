#!/usr/bin/env python2
"""
ptr_ring_monitor.py - Monitor TUN ptr_ring operations and vhost-net interactions

This tool tracks ptr_ring operations between TUN and vhost-net to help diagnose
cases where queue 0 ptr_ring shows all zeros.

Usage:
    sudo python2 ptr_ring_monitor.py [options]

Examples:
    # Monitor all ptr_ring operations
    sudo python2 ptr_ring_monitor.py

    # Monitor specific TUN interface
    sudo python2 ptr_ring_monitor.py --interface tun0

    # Monitor with detailed queue state
    sudo python2 ptr_ring_monitor.py --verbose --log-file ptr_ring.log
"""

from __future__ import print_function
from bcc import BPF
import argparse
import sys
import signal
from time import strftime, time

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_tun.h>
#include <linux/ptr_ring.h>

// Data structure for ptr_ring operations
struct ptr_ring_event {
    u64 ts;
    u32 pid;
    u32 tgid;
    u64 ptr_ring_addr;
    u32 queue_index;
    u32 operation;  // 0=produce, 1=consume
    s32 result;     // return value
    u32 ring_size;
    u32 producer;
    u32 consumer_head;
    char comm[TASK_COMM_LEN];
    char dev_name[IFNAMSIZ];
};

// Data structure for queue state
struct queue_state {
    u64 ts;
    u64 ptr_ring_addr;
    u32 queue_index;
    u32 ring_size;
    u32 producer;
    u32 consumer_head;
    u32 consumer_tail;
    u32 queue_depth;
    char dev_name[IFNAMSIZ];
};

// Ring buffer for events
BPF_PERF_OUTPUT(ptr_ring_events);
BPF_PERF_OUTPUT(queue_states);

// Hash maps for tracking
BPF_HASH(ptr_ring_to_tfile, u64, u64);  // ptr_ring addr -> tfile addr
BPF_HASH(tfile_to_queue, u64, u32);     // tfile addr -> queue_index

// Probe tun_net_xmit to track when packets are sent to ptr_ring
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    // This will be followed by ptr_ring_produce
    return 0;
}

// Probe ptr_ring_produce - packets being added to ring
int trace_ptr_ring_produce_entry(struct pt_regs *ctx, struct ptr_ring *ring, void *ptr) {
    struct ptr_ring_event event = {};
    
    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid();
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.ptr_ring_addr = (u64)ring;
    event.operation = 0; // produce
    
    // Read ptr_ring state
    bpf_probe_read(&event.ring_size, sizeof(event.ring_size), &ring->size);
    bpf_probe_read(&event.producer, sizeof(event.producer), &ring->producer);
    bpf_probe_read(&event.consumer_head, sizeof(event.consumer_head), &ring->consumer_head);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    ptr_ring_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe ptr_ring_produce return
int trace_ptr_ring_produce_return(struct pt_regs *ctx) {
    struct ptr_ring_event event = {};
    
    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid();
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.operation = 0; // produce
    event.result = PT_REGS_RC(ctx);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    ptr_ring_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe ptr_ring_consume - packets being read from ring
int trace_ptr_ring_consume_entry(struct pt_regs *ctx, struct ptr_ring *ring) {
    struct ptr_ring_event event = {};
    
    event.ts = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid();
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.ptr_ring_addr = (u64)ring;
    event.operation = 1; // consume
    
    // Read ptr_ring state
    bpf_probe_read(&event.ring_size, sizeof(event.ring_size), &ring->size);
    bpf_probe_read(&event.producer, sizeof(event.producer), &ring->producer);
    bpf_probe_read(&event.consumer_head, sizeof(event.consumer_head), &ring->consumer_head);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    ptr_ring_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe tun_ring_recv to see vhost-net reading from TUN
int trace_tun_ring_recv(struct pt_regs *ctx, struct tun_file *tfile, int noblock, int *err) {
    // This will be followed by ptr_ring_consume
    return 0;
}

// Periodic timer to check queue states
int check_queue_state(struct pt_regs *ctx) {
    // This would need to iterate through known ptr_rings
    // For now, we'll rely on the operation tracing
    return 0;
}
"""

class PtrRingMonitor:
    def __init__(self, args):
        self.args = args
        self.b = BPF(text=bpf_text)
        self.start_time = time()
        self.setup_probes()
        
    def setup_probes(self):
        # Attach kprobes
        self.b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        self.b.attach_kprobe(event="__ptr_ring_produce", fn_name="trace_ptr_ring_produce_entry")
        self.b.attach_kretprobe(event="__ptr_ring_produce", fn_name="trace_ptr_ring_produce_return")
        self.b.attach_kprobe(event="__ptr_ring_consume", fn_name="trace_ptr_ring_consume_entry")
        self.b.attach_kprobe(event="tun_ring_recv", fn_name="trace_tun_ring_recv")
        
        # Open perf buffers
        self.b["ptr_ring_events"].open_perf_buffer(self.print_ptr_ring_event)
        self.b["queue_states"].open_perf_buffer(self.print_queue_state)
        
    def print_ptr_ring_event(self, cpu, data, size):
        event = self.b["ptr_ring_events"].event(data)
        
        ts = (event.ts - self.start_time) / 1000000000.0
        operation = "PRODUCE" if event.operation == 0 else "CONSUME"
        
        output = "[%8.3f] %-7s PID=%-6d TID=%-6d COMM=%-16s " % (
            ts, operation, event.tgid, event.pid, event.comm.decode('utf-8', 'replace'))
        
        if hasattr(event, 'result') and event.operation == 0:  # produce return
            if event.result == 0:
                output += "SUCCESS"
            elif event.result == -28:  # -ENOSPC
                output += "FAILED (QUEUE FULL)"
            else:
                output += "FAILED (ret=%d)" % event.result
        else:
            output += "ring=0x%x size=%d prod=%d cons=%d depth=%d" % (
                event.ptr_ring_addr, event.ring_size, event.producer, 
                event.consumer_head, 
                (event.producer - event.consumer_head) % event.ring_size if event.ring_size > 0 else 0)
        
        print(output)
        
        if self.args.log_file:
            with open(self.args.log_file, 'a') as f:
                f.write("%s %s\n" % (strftime("%H:%M:%S"), output))
    
    def print_queue_state(self, cpu, data, size):
        state = self.b["queue_states"].event(data)
        
        ts = (state.ts - self.start_time) / 1000000000.0
        
        output = "[%8.3f] QUEUE_STATE dev=%-8s queue=%d ring=0x%x size=%d prod=%d cons_h=%d cons_t=%d depth=%d" % (
            ts, state.dev_name.decode('utf-8', 'replace'), state.queue_index,
            state.ptr_ring_addr, state.ring_size, state.producer, 
            state.consumer_head, state.consumer_tail, state.queue_depth)
        
        if self.args.verbose:
            print(output)
        
        if self.args.log_file:
            with open(self.args.log_file, 'a') as f:
                f.write("%s %s\n" % (strftime("%H:%M:%S"), output))
    
    def run(self):
        print("Monitoring TUN ptr_ring operations... Press Ctrl-C to stop")
        print("TIME     OP      PID    TID    COMM             DETAILS")
        print("-" * 80)
        
        try:
            while True:
                self.b.perf_buffer_poll()
        except KeyboardInterrupt:
            pass

def signal_handler(sig, frame):
    print("\nStopping...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="Monitor TUN ptr_ring operations and vhost-net interactions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Monitor all ptr_ring operations
    sudo python2 ptr_ring_monitor.py

    # Monitor with verbose output
    sudo python2 ptr_ring_monitor.py --verbose

    # Log to file
    sudo python2 ptr_ring_monitor.py --log-file ptr_ring.log

This tool helps diagnose cases where queue 0 ptr_ring shows all zeros by
tracking the producer/consumer operations and queue states.
        """)
    
    parser.add_argument("--interface", help="Monitor specific TUN interface")
    parser.add_argument("--verbose", action="store_true", 
                       help="Show detailed queue state information")
    parser.add_argument("--log-file", help="Log output to file")
    parser.add_argument("--queue", type=int, help="Monitor specific queue index")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script requires root privileges")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    monitor = PtrRingMonitor(args)
    monitor.run()

if __name__ == "__main__":
    import os
    main()