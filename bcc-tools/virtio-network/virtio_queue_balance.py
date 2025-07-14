#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import time
import sys
from bcc import BPF
import ctypes as ct
from collections import defaultdict, OrderedDict

# BPF program for virtio-net queue balance analysis
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/sched.h>

// Device name union for filtering
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

struct queue_activity {
    u64 timestamp;
    char dev_name[16];
    u32 queue_id;
    u32 cpu_id;
    u32 activity_type;  // 1=NAPI, 2=packet_rx, 3=interrupt
    u32 packet_count;
    u64 bytes_count;
    u32 budget_used;
    u64 duration_ns;
    u32 irq_count;
};

// Maps
BPF_PERF_OUTPUT(activities);
BPF_ARRAY(device_filter, union name_buf, 1);
BPF_HASH(queue_packet_count, u32, u64);
BPF_HASH(queue_byte_count, u32, u64);
BPF_HASH(queue_napi_count, u32, u64);
BPF_HASH(queue_cpu_affinity, u32, u32);  // queue_id -> cpu_id
BPF_HASH(napi_start_time, u32, u64);     // for duration calculation

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

// Helper to extract queue ID from skb or context
static inline u32 get_queue_id_from_skb(struct sk_buff *skb) {
    if (!skb) return 0;
    
    // For virtio-net, queue_mapping should be set correctly
    u32 queue_id = skb->queue_mapping;
    
    // Bounds check
    if (queue_id >= 64) queue_id = 0;  // Max 64 queues
    
    return queue_id;
}

// Probe netif_receive_skb for packet reception tracking
int probe_netif_receive_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    if (!skb || !skb->dev) return 0;
    
    char dev_name[IFNAMSIZ];
    bpf_probe_read_kernel_str(dev_name, sizeof(dev_name), skb->dev->name);
    
    // Filter for ethernet devices (virtio-net usually appears as ethX)
    if (dev_name[0] != 'e' || dev_name[1] != 't' || dev_name[2] != 'h') 
        return 0;
        
    if (!device_name_matches(dev_name)) return 0;
    
    u32 queue_id = get_queue_id_from_skb(skb);
    u32 cpu_id = bpf_get_smp_processor_id();
    
    // Update counters
    u64 *packet_count = queue_packet_count.lookup(&queue_id);
    if (packet_count) {
        (*packet_count)++;
    } else {
        u64 init_val = 1;
        queue_packet_count.update(&queue_id, &init_val);
    }
    
    u64 bytes = skb->len;
    u64 *byte_count = queue_byte_count.lookup(&queue_id);
    if (byte_count) {
        (*byte_count) += bytes;
    } else {
        queue_byte_count.update(&queue_id, &bytes);
    }
    
    // Track CPU affinity
    queue_cpu_affinity.update(&queue_id, &cpu_id);
    
    // Emit activity event
    struct queue_activity activity = {};
    activity.timestamp = bpf_ktime_get_ns();
    activity.queue_id = queue_id;
    activity.cpu_id = cpu_id;
    activity.activity_type = 2;  // packet_rx
    activity.packet_count = 1;
    activity.bytes_count = bytes;
    bpf_probe_read_kernel_str(activity.dev_name, sizeof(activity.dev_name), dev_name);
    
    activities.perf_submit(ctx, &activity, sizeof(activity));
    return 0;
}

// Probe virtnet_poll for NAPI activity
int probe_virtnet_poll_enter(struct pt_regs *ctx) {
    u32 cpu_id = bpf_get_smp_processor_id();
    u64 ts = bpf_ktime_get_ns();
    
    // Store start time for duration calculation
    napi_start_time.update(&cpu_id, &ts);
    
    // We can't easily get queue_id from napi_struct without more complex parsing
    // So we'll track this as general NAPI activity
    struct queue_activity activity = {};
    activity.timestamp = ts;
    activity.queue_id = 0;  // Will need to correlate with subsequent packet events
    activity.cpu_id = cpu_id;
    activity.activity_type = 1;  // NAPI
    
    activities.perf_submit(ctx, &activity, sizeof(activity));
    return 0;
}

int probe_virtnet_poll_exit(struct pt_regs *ctx) {
    u32 cpu_id = bpf_get_smp_processor_id();
    int received = PT_REGS_RC(ctx);
    u64 now = bpf_ktime_get_ns();
    
    u64 *start_time = napi_start_time.lookup(&cpu_id);
    u64 duration = 0;
    if (start_time) {
        duration = now - *start_time;
        napi_start_time.delete(&cpu_id);
    }
    
    struct queue_activity activity = {};
    activity.timestamp = now;
    activity.queue_id = 0;  // General NAPI activity
    activity.cpu_id = cpu_id;
    activity.activity_type = 1;  // NAPI
    activity.packet_count = received;
    activity.duration_ns = duration;
    
    activities.perf_submit(ctx, &activity, sizeof(activity));
    return 0;
}

// Track software interrupts for interrupt distribution analysis
int probe_do_softirq_entry(struct pt_regs *ctx) {
    u32 cpu_id = bpf_get_smp_processor_id();
    
    struct queue_activity activity = {};
    activity.timestamp = bpf_ktime_get_ns();
    activity.cpu_id = cpu_id;
    activity.activity_type = 3;  // interrupt/softirq
    activity.irq_count = 1;
    
    activities.perf_submit(ctx, &activity, sizeof(activity));
    return 0;
}
"""

class QueueActivity(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("dev_name", ct.c_char * 16),
        ("queue_id", ct.c_uint32),
        ("cpu_id", ct.c_uint32),
        ("activity_type", ct.c_uint32),
        ("packet_count", ct.c_uint32),
        ("bytes_count", ct.c_uint64),
        ("budget_used", ct.c_uint32),
        ("duration_ns", ct.c_uint64),
        ("irq_count", ct.c_uint32),
    ]

class DeviceName(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]

ACTIVITY_TYPES = {
    1: "NAPI",
    2: "PACKET_RX", 
    3: "INTERRUPT"
}

class VirtioQueueBalanceMonitor:
    def __init__(self, device=None, compare_interval=10, detailed=False):
        self.device = device
        self.compare_interval = compare_interval
        self.detailed = detailed
        self.start_time = time.time()
        self.last_comparison = 0
        
        # Statistics tracking
        self.queue_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'napi_calls': 0,
            'cpu_usage': defaultdict(int),
            'last_activity': 0,
            'interrupt_count': 0
        })
        
        self.interval_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'napi_calls': 0,
            'duration_total': 0
        })
        
    def print_event(self, cpu, data, size):
        activity = ct.cast(data, ct.POINTER(QueueActivity)).contents
        
        timestamp = time.time()
        activity_type = ACTIVITY_TYPES.get(activity.activity_type, f"UNKNOWN({activity.activity_type})")
        device = activity.dev_name.decode('utf-8', 'replace') if activity.dev_name else 'N/A'
        
        # Update statistics
        queue_id = activity.queue_id
        stats = self.queue_stats[queue_id]
        interval_stats = self.interval_stats[queue_id]
        
        if activity.activity_type == 2:  # PACKET_RX
            stats['packets'] += activity.packet_count
            stats['bytes'] += activity.bytes_count
            stats['last_activity'] = timestamp
            stats['cpu_usage'][activity.cpu_id] += 1
            
            interval_stats['packets'] += activity.packet_count
            interval_stats['bytes'] += activity.bytes_count
            
        elif activity.activity_type == 1:  # NAPI
            stats['napi_calls'] += 1
            interval_stats['napi_calls'] += 1
            if activity.duration_ns > 0:
                interval_stats['duration_total'] += activity.duration_ns
                
        elif activity.activity_type == 3:  # INTERRUPT
            stats['interrupt_count'] += activity.irq_count
            
        # Detailed output
        if self.detailed:
            ts_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
            ms = int((timestamp % 1) * 1000)
            ts_str += f".{ms:03d}"
            
            if activity.activity_type == 2:
                print(f"[{ts_str}] {device:>8} Q{queue_id:<2} {activity_type:<10} "
                      f"CPU{activity.cpu_id} pkts={activity.packet_count} "
                      f"bytes={activity.bytes_count}")
            elif activity.activity_type == 1 and activity.duration_ns > 0:
                duration_us = activity.duration_ns / 1000
                print(f"[{ts_str}] {device:>8} Q{queue_id:<2} {activity_type:<10} "
                      f"CPU{activity.cpu_id} processed={activity.packet_count} "
                      f"duration={duration_us:.1f}μs")
        
        # Periodic comparison
        if (timestamp - self.last_comparison) >= self.compare_interval:
            self.print_queue_comparison()
            self.last_comparison = timestamp
            
    def print_queue_comparison(self):
        print("\n" + "="*100)
        print("VIRTIO-NET QUEUE BALANCE ANALYSIS")
        print("="*100)
        
        now = time.time()
        interval = now - self.last_comparison if self.last_comparison > 0 else self.compare_interval
        
        # Header
        print(f"{'Queue':<6} {'Status':<10} {'Packets':<8} {'PPS':<8} {'Bytes':<10} {'BPS':<10} "
              f"{'NAPI':<6} {'CPU Dist':<15} {'Last Seen':<10}")
        print("-" * 100)
        
        total_packets = 0
        active_queues = []
        stale_queues = []
        
        # Analyze each queue
        for queue_id in sorted(self.queue_stats.keys()):
            stats = self.queue_stats[queue_id]
            interval_stats = self.interval_stats[queue_id]
            
            packets = interval_stats['packets']
            bytes_count = interval_stats['bytes']
            napi_calls = interval_stats['napi_calls']
            
            pps = packets / interval if interval > 0 else 0
            bps = bytes_count / interval if interval > 0 else 0
            
            last_activity = stats['last_activity']
            age = now - last_activity if last_activity > 0 else float('inf')
            
            # Determine status
            if age > 10.0:  # No activity for 10+ seconds
                status = "🚨 STALE"
                stale_queues.append(queue_id)
            elif packets > 0:
                status = "✅ ACTIVE"
                active_queues.append(queue_id)
            else:
                status = "💤 IDLE"
                
            total_packets += packets
            
            # CPU distribution
            cpu_dist = stats['cpu_usage']
            if cpu_dist:
                dominant_cpu = max(cpu_dist.keys(), key=lambda k: cpu_dist[k])
                cpu_str = f"CPU{dominant_cpu}"
                if len(cpu_dist) > 1:
                    cpu_str += f"(+{len(cpu_dist)-1})"
            else:
                cpu_str = "N/A"
                
            age_str = f"{age:.1f}s" if age < float('inf') else "Never"
            
            print(f"Q{queue_id:<5} {status:<10} {packets:<8} {pps:<8.1f} "
                  f"{bytes_count:<10} {bps:<10.1f} {napi_calls:<6} "
                  f"{cpu_str:<15} {age_str:<10}")
        
        # Analysis
        print(f"\n📊 Summary:")
        print(f"  Total packets this interval: {total_packets}")
        print(f"  Active queues: {active_queues}")
        print(f"  Stale queues: {stale_queues}")
        
        # Check for queue 0 specific issues
        if 0 in stale_queues and len(active_queues) > 0:
            print(f"  🚨 CRITICAL: Queue 0 is stale while other queues are active!")
            print(f"     This matches the reported vhost-net queue 0 issue pattern.")
            
        # Check for load imbalance
        if len(active_queues) > 1:
            queue_loads = [(q, self.interval_stats[q]['packets']) for q in active_queues]
            queue_loads.sort(key=lambda x: x[1], reverse=True)
            
            if queue_loads[0][1] > 0 and queue_loads[-1][1] > 0:
                imbalance_ratio = queue_loads[0][1] / queue_loads[-1][1]
                if imbalance_ratio > 3.0:
                    print(f"  ⚠️  Load imbalance detected: Q{queue_loads[0][0]} has {imbalance_ratio:.1f}x "
                          f"more traffic than Q{queue_loads[-1][0]}")
        
        # CPU distribution analysis
        overall_cpu_dist = defaultdict(int)
        for stats in self.queue_stats.values():
            for cpu, count in stats['cpu_usage'].items():
                overall_cpu_dist[cpu] += count
                
        if overall_cpu_dist:
            print(f"  💻 CPU Distribution: ", end="")
            cpu_list = [(cpu, count) for cpu, count in overall_cpu_dist.items()]
            cpu_list.sort(key=lambda x: x[1], reverse=True)
            for i, (cpu, count) in enumerate(cpu_list[:3]):  # Top 3 CPUs
                if i > 0: print(", ", end="")
                print(f"CPU{cpu}({count})", end="")
            if len(cpu_list) > 3:
                print(f" +{len(cpu_list)-3} more")
            else:
                print()
        
        # Reset interval counters
        self.interval_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'napi_calls': 0,
            'duration_total': 0
        })
        
        print("="*100)
        print()
        
    def print_final_summary(self):
        print("\n" + "="*100)
        print("VIRTIO-NET QUEUE BALANCE FINAL SUMMARY")
        print("="*100)
        
        runtime = time.time() - self.start_time
        print(f"Runtime: {runtime:.1f}s")
        print()
        
        # Overall queue statistics
        print("Overall Queue Statistics:")
        print(f"{'Queue':<6} {'Total Pkts':<12} {'Total Bytes':<12} {'NAPI Calls':<10} {'Avg CPU':<8}")
        print("-" * 60)
        
        for queue_id in sorted(self.queue_stats.keys()):
            stats = self.queue_stats[queue_id]
            
            # Calculate average CPU
            cpu_dist = stats['cpu_usage']
            if cpu_dist:
                avg_cpu = sum(cpu * count for cpu, count in cpu_dist.items()) / sum(cpu_dist.values())
            else:
                avg_cpu = 0
                
            print(f"Q{queue_id:<5} {stats['packets']:<12} {stats['bytes']:<12} "
                  f"{stats['napi_calls']:<10} {avg_cpu:<8.1f}")
        
        # Recommendations
        print("\n💡 Recommendations:")
        
        active_queues = [q for q, s in self.queue_stats.items() if s['packets'] > 0]
        stale_queues = [q for q, s in self.queue_stats.items() 
                       if s['packets'] == 0 and q in self.queue_stats]
        
        if 0 in stale_queues and len(active_queues) > 0:
            print("  🚨 Queue 0 Issue Confirmed:")
            print("    - Queue 0 shows no packet activity")
            print("    - Other queues are functioning normally")
            print("    - This confirms the vhost-net queue 0 problem")
            print("    - Run host-side vhost_net_monitor.py to correlate with ptr_ring status")
        elif len(stale_queues) == 0:
            print("  ✅ All queues show activity - no obvious balance issues")
        else:
            print(f"  ⚠️  Multiple stale queues detected: {stale_queues}")
            
    def run(self):
        try:
            print("Loading BPF program for virtio-net queue balance analysis...")
            b = BPF(text=bpf_text)
            
            # Attach probes
            print("Attaching kprobes...")
            b.attach_kprobe(event="netif_receive_skb", fn_name="probe_netif_receive_skb")
            b.attach_kprobe(event="virtnet_poll", fn_name="probe_virtnet_poll_enter")
            b.attach_kretprobe(event="virtnet_poll", fn_name="probe_virtnet_poll_exit")
            b.attach_kprobe(event="do_softirq", fn_name="probe_do_softirq_entry")
            
        except Exception as e:
            print(f"❌ Failed to load BPF program: {e}")
            return
            
        # Configure device filter
        if self.device:
            device_name = DeviceName()
            device_name.name = self.device.encode()
            b["device_filter"][0] = device_name
            print(f"📡 Device filter: {self.device}")
        else:
            print("📡 Device filter: All virtio-net devices")
            
        print(f"⏱️  Comparison interval: {self.compare_interval}s")
        
        if self.detailed:
            print("🔍 Detailed events: ENABLED")
        
        print("\n🔍 virtio-net Queue Balance Monitor Started")
        print("Monitoring: Queue activity distribution, CPU affinity, load balance")
        print("Press Ctrl+C to stop and show final summary")
        print("="*100)
        print()
        
        try:
            b["activities"].open_perf_buffer(self.print_event)
            while True:
                try:
                    b.perf_buffer_poll()
                except KeyboardInterrupt:
                    break
        except KeyboardInterrupt:
            pass
        
        self.print_final_summary()
        print("\n👋 Monitoring stopped.")

def main():
    parser = argparse.ArgumentParser(
        description="virtio-net queue balance analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor queue balance with 10s comparison intervals
  sudo %(prog)s
  
  # Monitor specific device with 5s intervals
  sudo %(prog)s --device eth0 --interval 5
  
  # Detailed event output for debugging
  sudo %(prog)s --detailed
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., eth0)")
    parser.add_argument("--interval", "-i", type=int, default=10,
                       help="Comparison interval in seconds (default: 10)")
    parser.add_argument("--detailed", action="store_true", 
                       help="Show detailed event output")
    
    args = parser.parse_args()
    
    monitor = VirtioQueueBalanceMonitor(
        device=args.device,
        compare_interval=args.interval,
        detailed=args.detailed
    )
    
    monitor.run()

if __name__ == "__main__":
    main()