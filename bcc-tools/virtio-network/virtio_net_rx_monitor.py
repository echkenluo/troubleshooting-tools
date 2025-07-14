#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import time
import sys
from bcc import BPF
import ctypes as ct
from collections import defaultdict

# BPF program for virtio-net RX monitoring
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>

// Event types
#define RX_NAPI_POLL_ENTER      1
#define RX_NAPI_POLL_EXIT       2
#define RX_VIRTQUEUE_GET_BUF    3
#define RX_RECEIVE_BUF          4
#define RX_NETIF_RECEIVE        5
#define RX_INTERRUPT            6
#define RX_QUEUE_REFILL         7

// Device name union for filtering
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

struct virtio_rx_event {
    u64 timestamp;
    u32 queue_id;
    char dev_name[16];
    u32 event_type;
    u32 budget;
    u32 received;
    u64 duration_ns;
    u32 vq_num_free;
    u32 packet_len;
    s32 error_code;
    u64 skb_addr;
    u32 cpu_id;
};

// Maps for tracking state
BPF_PERF_OUTPUT(events);
BPF_HASH(napi_start_times, void*, u64);
BPF_ARRAY(device_filter, union name_buf, 1);
BPF_ARRAY(queue_filter, u32, 1);
BPF_HASH(queue_stats, u32, u64);

// Device filter helper
static inline int device_name_matches(const char *dev_name) {
    union name_buf real_devname = {};
    union name_buf *filter;
    int key = 0;
    
    bpf_probe_read_kernel_str(real_devname.name, IFNAMSIZ, dev_name);
    filter = device_filter.lookup(&key);
    
    if (!filter) return 1;
    if (filter->name_int.hi == 0 && filter->name_int.lo == 0) return 1;
    
    return (filter->name_int.hi == real_devname.name_int.hi && 
            filter->name_int.lo == real_devname.name_int.lo);
}

// Queue filter helper
static inline int queue_matches(u32 queue_id) {
    int key = 0;
    u32 *filter = queue_filter.lookup(&key);
    if (!filter || *filter == 0xFFFFFFFF) return 1;
    return (*filter == queue_id);
}

// Helper to get queue ID from receive_queue structure
static inline u32 get_queue_id_from_rq(void *rq_ptr, void *vi_base) {
    // Assuming receive_queue is in an array, calculate offset
    // This may need adjustment based on actual kernel structure layout
    u64 offset = (u64)rq_ptr - (u64)vi_base;
    u32 queue_id = offset / sizeof(struct receive_queue); // Approximate
    
    // Bounds check
    if (queue_id >= 256) queue_id = 0;
    
    return queue_id;
}

// Helper to emit event
static inline void emit_event(struct pt_regs *ctx, u32 event_type, u32 queue_id, 
                             const char *dev_name, u32 extra_data) {
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.queue_id = queue_id;
    event.event_type = event_type;
    event.cpu_id = bpf_get_smp_processor_id();
    
    if (dev_name) {
        bpf_probe_read_kernel_str(event.dev_name, sizeof(event.dev_name), dev_name);
        if (!device_name_matches(dev_name)) return;
    }
    
    if (!queue_matches(queue_id)) return;
    
    event.error_code = extra_data;
    
    events.perf_submit(ctx, &event, sizeof(event));
}

// Probe virtnet_poll entry
int probe_virtnet_poll_enter(struct pt_regs *ctx) {
    // virtnet_poll(struct napi_struct *napi, int budget)
    struct napi_struct *napi = (struct napi_struct *)PT_REGS_PARM1(ctx);
    int budget = (int)PT_REGS_PARM2(ctx);
    
    if (!napi) return 0;
    
    // Store start time for duration calculation
    u64 ts = bpf_ktime_get_ns();
    napi_start_times.update(&napi, &ts);
    
    struct virtio_rx_event event = {};
    event.timestamp = ts;
    event.event_type = RX_NAPI_POLL_ENTER;
    event.budget = budget;
    event.cpu_id = bpf_get_smp_processor_id();
    
    // Try to get device name through net_device
    // This requires careful structure traversal
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe virtnet_poll exit
int probe_virtnet_poll_exit(struct pt_regs *ctx) {
    int retval = PT_REGS_RC(ctx);
    
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = RX_NAPI_POLL_EXIT;
    event.received = retval;
    event.cpu_id = bpf_get_smp_processor_id();
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe virtnet_receive
int probe_virtnet_receive(struct pt_regs *ctx) {
    // virtnet_receive(struct receive_queue *rq, int budget, unsigned int *xdp_xmit)
    void *rq = (void *)PT_REGS_PARM1(ctx);
    int budget = (int)PT_REGS_PARM2(ctx);
    
    if (!rq) return 0;
    
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = RX_VIRTQUEUE_GET_BUF;
    event.budget = budget;
    event.cpu_id = bpf_get_smp_processor_id();
    
    // Queue ID calculation would need kernel structure knowledge
    event.queue_id = 0; // Placeholder
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe receive_buf
int probe_receive_buf(struct pt_regs *ctx) {
    // receive_buf(struct virtnet_info *vi, struct receive_queue *rq, 
    //             void *buf, unsigned int len, void **ctx, 
    //             unsigned int *xdp_xmit, struct virtnet_rq_stats *stats)
    void *buf = (void *)PT_REGS_PARM3(ctx);
    u32 len = (u32)PT_REGS_PARM4(ctx);
    
    if (!buf) return 0;
    
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = RX_RECEIVE_BUF;
    event.packet_len = len;
    event.cpu_id = bpf_get_smp_processor_id();
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe netif_receive_skb
int probe_netif_receive_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    if (!skb) return 0;
    
    // Check if this is from virtio_net device
    struct net_device *dev = skb->dev;
    if (!dev) return 0;
    
    char dev_name[IFNAMSIZ];
    bpf_probe_read_kernel_str(dev_name, sizeof(dev_name), dev->name);
    
    // Simple check for virtio-net devices (usually eth0, eth1, etc. in VMs)
    if (dev_name[0] != 'e' || dev_name[1] != 't' || dev_name[2] != 'h') 
        return 0;
    
    if (!device_name_matches(dev_name)) return 0;
    
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = RX_NETIF_RECEIVE;
    event.packet_len = skb->len;
    event.skb_addr = (u64)skb;
    event.cpu_id = bpf_get_smp_processor_id();
    bpf_probe_read_kernel_str(event.dev_name, sizeof(event.dev_name), dev_name);
    
    // Update packet counter
    u64 *counter = queue_stats.lookup(&event.queue_id);
    if (counter) {
        (*counter)++;
    } else {
        u64 init_val = 1;
        queue_stats.update(&event.queue_id, &init_val);
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe try_fill_recv for buffer refill monitoring
int probe_try_fill_recv(struct pt_regs *ctx) {
    emit_event(ctx, RX_QUEUE_REFILL, 0, NULL, 0);
    return 0;
}
"""

class VirtioRxEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("queue_id", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("event_type", ct.c_uint32),
        ("budget", ct.c_uint32),
        ("received", ct.c_uint32),
        ("duration_ns", ct.c_uint64),
        ("vq_num_free", ct.c_uint32),
        ("packet_len", ct.c_uint32),
        ("error_code", ct.c_int32),
        ("skb_addr", ct.c_uint64),
        ("cpu_id", ct.c_uint32),
    ]

class DeviceName(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]

# Event type constants
EVENT_TYPES = {
    1: "NAPI_POLL_ENTER",
    2: "NAPI_POLL_EXIT",
    3: "VIRTQUEUE_GET_BUF",
    4: "RECEIVE_BUF",
    5: "NETIF_RECEIVE",
    6: "INTERRUPT",
    7: "QUEUE_REFILL"
}

class VirtioNetRxMonitor:
    def __init__(self, device=None, queue=None, verbose=False, show_packets=False):
        self.device = device
        self.queue = queue if queue is not None else 0xFFFFFFFF
        self.verbose = verbose
        self.show_packets = show_packets
        self.stats = defaultdict(int)
        self.queue_stats = defaultdict(lambda: defaultdict(int))
        self.start_time = time.time()
        self.last_summary = 0
        
    def print_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(VirtioRxEvent)).contents
        
        timestamp = time.time()
        event_type = EVENT_TYPES.get(event.event_type, f"UNKNOWN({event.event_type})")
        device = event.dev_name.decode('utf-8', 'replace') if event.dev_name else 'N/A'
        
        self.stats[event_type] += 1
        self.queue_stats[event.queue_id]['total_events'] += 1
        
        # Update queue-specific statistics
        if event.event_type == 4:  # RECEIVE_BUF
            self.queue_stats[event.queue_id]['packets'] += 1
            self.queue_stats[event.queue_id]['bytes'] += event.packet_len
        elif event.event_type == 5:  # NETIF_RECEIVE
            self.queue_stats[event.queue_id]['delivered'] += 1
            
        # Format timestamp
        ts_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
        ms = int((timestamp % 1) * 1000)
        ts_str += f".{ms:03d}"
        
        # Print event based on verbosity
        if self.show_packets and event.event_type in [4, 5]:  # Packet events
            print(f"[{ts_str}] {device:>8} Q{event.queue_id:<2} {event_type:<18} "
                  f"len={event.packet_len:<4} CPU{event.cpu_id} "
                  f"skb=0x{event.skb_addr:x}")
        elif self.verbose:
            if event.event_type == 1:  # NAPI_POLL_ENTER
                print(f"[{ts_str}] {device:>8} Q{event.queue_id:<2} {event_type:<18} "
                      f"budget={event.budget} CPU{event.cpu_id}")
            elif event.event_type == 2:  # NAPI_POLL_EXIT
                print(f"[{ts_str}] {device:>8} Q{event.queue_id:<2} {event_type:<18} "
                      f"received={event.received} CPU{event.cpu_id}")
            else:
                print(f"[{ts_str}] {device:>8} Q{event.queue_id:<2} {event_type:<18} CPU{event.cpu_id}")
        
        # Periodic summary
        if (timestamp - self.last_summary) >= 5.0:
            self.print_queue_summary()
            self.last_summary = timestamp
            
    def print_queue_summary(self):
        print("\n" + "="*80)
        print("VIRTIO-NET RX QUEUE SUMMARY (Last 5s)")
        print("="*80)
        
        print(f"{'Queue':<6} {'Packets':<8} {'Bytes':<10} {'Delivered':<10} {'Events':<8} {'PPS':<8}")
        print("-" * 80)
        
        now = time.time()
        interval = now - self.last_summary if self.last_summary > 0 else 5.0
        
        total_packets = 0
        active_queues = []
        
        for queue_id in sorted(self.queue_stats.keys()):
            stats = self.queue_stats[queue_id]
            packets = stats['packets']
            bytes_count = stats['bytes']
            delivered = stats['delivered']
            events = stats['total_events']
            pps = packets / interval if interval > 0 else 0
            
            if packets > 0:
                active_queues.append(queue_id)
                
            total_packets += packets
            
            print(f"Q{queue_id:<5} {packets:<8} {bytes_count:<10} {delivered:<10} "
                  f"{events:<8} {pps:<8.1f}")
        
        print(f"\nTotal packets: {total_packets}")
        print(f"Active queues: {active_queues}")
        
        # Check for queue 0 issues
        if len(active_queues) > 1 and 0 not in active_queues:
            print("🚨 WARNING: Queue 0 inactive while other queues are active!")
        elif len(active_queues) == 0:
            print("⚠️  WARNING: No queue activity detected!")
            
        # Reset counters for next interval
        for queue_id in self.queue_stats:
            self.queue_stats[queue_id] = defaultdict(int)
            
        print("="*80)
        print()
        
    def print_final_stats(self):
        print("\n" + "="*80)
        print("VIRTIO-NET RX MONITORING FINAL STATISTICS")
        print("="*80)
        
        runtime = time.time() - self.start_time
        print(f"Runtime: {runtime:.1f}s")
        print()
        
        print("Event Counts:")
        for event_type, count in sorted(self.stats.items()):
            rate = count / runtime if runtime > 0 else 0
            print(f"  {event_type:<20}: {count:>8} ({rate:.1f}/s)")
            
    def run(self):
        try:
            print("Loading BPF program for virtio-net RX monitoring...")
            b = BPF(text=bpf_text)
            
            # Attach probes
            print("Attaching kprobes...")
            b.attach_kprobe(event="virtnet_poll", fn_name="probe_virtnet_poll_enter")
            b.attach_kretprobe(event="virtnet_poll", fn_name="probe_virtnet_poll_exit")
            b.attach_kprobe(event="virtnet_receive", fn_name="probe_virtnet_receive")
            b.attach_kprobe(event="receive_buf", fn_name="probe_receive_buf")
            b.attach_kprobe(event="netif_receive_skb", fn_name="probe_netif_receive_skb")
            b.attach_kprobe(event="try_fill_recv", fn_name="probe_try_fill_recv")
            
        except Exception as e:
            print(f"❌ Failed to load BPF program: {e}")
            return
            
        # Configure filters
        b["queue_filter"][0] = ct.c_uint32(self.queue)
        
        if self.device:
            device_name = DeviceName()
            device_name.name = self.device.encode()
            b["device_filter"][0] = device_name
            print(f"📡 Device filter: {self.device}")
        else:
            print("📡 Device filter: All virtio-net devices")
            
        if self.queue != 0xFFFFFFFF:
            print(f"🎯 Queue filter: {self.queue}")
        else:
            print("🎯 Queue filter: All queues")
            
        if self.show_packets:
            print("📦 Packet details: ENABLED")
            
        print("\n🔍 virtio-net RX Monitor Started")
        print("Monitoring: NAPI polling, packet reception, queue balance")
        print("Press Ctrl+C to stop and show final statistics")
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
        
        self.print_final_stats()
        print("\n👋 Monitoring stopped.")

def main():
    parser = argparse.ArgumentParser(
        description="virtio-net RX queue monitoring tool for VM-side diagnostics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all virtio-net RX activity
  sudo %(prog)s
  
  # Monitor specific device
  sudo %(prog)s --device eth0
  
  # Monitor specific device and queue with packet details
  sudo %(prog)s --device eth0 --queue 0 --show-packets
  
  # Verbose mode with detailed event tracing
  sudo %(prog)s --verbose
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., eth0)")
    parser.add_argument("--queue", "-q", type=int, help="Target queue ID (default: all queues)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose event output")
    parser.add_argument("--show-packets", "-p", action="store_true", help="Show individual packet events")
    
    args = parser.parse_args()
    
    monitor = VirtioNetRxMonitor(
        device=args.device,
        queue=args.queue,
        verbose=args.verbose,
        show_packets=args.show_packets
    )
    
    monitor.run()

if __name__ == "__main__":
    main()