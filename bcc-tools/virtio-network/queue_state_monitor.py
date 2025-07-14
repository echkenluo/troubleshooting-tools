#!/usr/bin/env python2

# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import time
import sys
from bcc import BPF
import ctypes as ct
from collections import defaultdict, OrderedDict

# BPF program for queue state comparison (simplified version)
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>

// Device name union for filtering
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

struct queue_state {
    u64 timestamp;
    char dev_name[16];
    u32 queue_id;
    u64 skb_count;
    u64 skb_addr;
    u32 skb_len;
    u32 is_active;  // 1 if queue is processing packets
    u64 last_seen;
};

// Maps
BPF_PERF_OUTPUT(queue_states);
BPF_ARRAY(device_filter, union name_buf, 1);
BPF_HASH(queue_counters, u32, u64);  // Per-queue packet counters
BPF_HASH(queue_last_seen, u32, u64);  // Last activity per queue

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

// Probe tun_net_xmit to capture queue activity
int probe_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!dev || !skb) return 0;
    
    char dev_name[IFNAMSIZ];
    bpf_probe_read_kernel_str(dev_name, sizeof(dev_name), dev->name);
    
    if (!device_name_matches(dev_name)) return 0;
    
    u32 queue_id = skb->queue_mapping;
    u64 now = bpf_ktime_get_ns();
    
    // Update counters
    u64 *counter = queue_counters.lookup(&queue_id);
    if (counter) {
        (*counter)++;
    } else {
        u64 init_val = 1;
        queue_counters.update(&queue_id, &init_val);
    }
    
    // Update last seen time
    queue_last_seen.update(&queue_id, &now);
    
    // Create state event
    struct queue_state state = {};
    state.timestamp = now;
    state.queue_id = queue_id;
    state.skb_count = counter ? *counter : 1;
    state.skb_addr = (u64)skb;
    state.skb_len = skb->len;
    state.is_active = 1;
    state.last_seen = now;
    bpf_probe_read_kernel_str(state.dev_name, sizeof(state.dev_name), dev->name);
    
    queue_states.perf_submit(ctx, &state, sizeof(state));
    return 0;
}

// Probe tun_recvmsg to detect consumption activity
int probe_tun_recvmsg(struct pt_regs *ctx) {
    // This helps us detect when vhost is consuming from the ring
    u64 now = bpf_ktime_get_ns();
    u32 queue_id = 0; // Cannot easily determine queue from tun_recvmsg alone
    
    struct queue_state state = {};
    state.timestamp = now;
    state.queue_id = queue_id;
    state.is_active = 2;  // Mark as consumer activity
    bpf_get_current_comm(&state.dev_name, sizeof(state.dev_name));
    
    queue_states.perf_submit(ctx, &state, sizeof(state));
    return 0;
}
"""

class QueueState(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("dev_name", ct.c_char * 16),
        ("queue_id", ct.c_uint32),
        ("skb_count", ct.c_uint64),
        ("skb_addr", ct.c_uint64),
        ("skb_len", ct.c_uint32),
        ("is_active", ct.c_uint32),
        ("last_seen", ct.c_uint64),
    ]

class DeviceName(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]

class QueueStateMonitor:
    def __init__(self, device=None, compare_queues=False, snapshot_interval=5):
        self.device = device
        self.compare_queues = compare_queues
        self.snapshot_interval = snapshot_interval
        self.queue_states = defaultdict(list)  # device_queue -> [states]
        self.queue_stats = defaultdict(lambda: defaultdict(int))
        self.start_time = time.time()
        self.last_snapshot = 0
        
    def print_event(self, cpu, data, size):
        state = ct.cast(data, ct.POINTER(QueueState)).contents
        
        timestamp = time.time()
        device = state.dev_name.decode('utf-8', 'replace')
        queue_key = f"{device}_Q{state.queue_id}"
        
        # Store state for analysis
        state_data = {
            'timestamp': timestamp,
            'skb_count': state.skb_count,
            'skb_addr': state.skb_addr,
            'skb_len': state.skb_len,
            'is_active': state.is_active,
            'last_seen': state.last_seen
        }
        
        self.queue_states[queue_key].append(state_data)
        
        # Keep only recent states (last 1000 entries)
        if len(self.queue_states[queue_key]) > 1000:
            self.queue_states[queue_key] = self.queue_states[queue_key][-1000:]
            
        # Update statistics
        self.queue_stats[queue_key]['total_packets'] = state.skb_count
        self.queue_stats[queue_key]['last_activity'] = timestamp
        
        # Detect inactive queues (no activity for 5+ seconds)
        now = timestamp
        is_stale = (now - (state.last_seen / 1e9)) > 5.0 if state.last_seen > 0 else False
        
        # Print real-time status
        ts_str = time.strftime("%H:%M:%S", time.localtime(timestamp))
        
        if state.is_active == 1:  # Producer activity
            activity = "TX"
        elif state.is_active == 2:  # Consumer activity
            activity = "RX"
        else:
            activity = "??"
            
        status = "🚨 STALE" if is_stale else "✅ ACTIVE"
        
        print(f"[{ts_str}] {device} Q{state.queue_id:<2} {activity} {status} "
              f"len={state.skb_len:<4} pkts={state.skb_count} "
              f"skb=0x{state.skb_addr:x}")
              
        # Periodic comparison if enabled
        if self.compare_queues and (timestamp - self.last_snapshot) >= self.snapshot_interval:
            self.print_queue_comparison()
            self.last_snapshot = timestamp
            
    def print_queue_comparison(self):
        print("\n" + "="*100)
        print("QUEUE STATE COMPARISON")
        print("="*100)
        
        # Group by device
        devices = defaultdict(list)
        for queue_key in self.queue_states.keys():
            device, queue = queue_key.split('_Q')
            devices[device].append(int(queue))
            
        for device, queues in devices.items():
            queues.sort()
            print(f"\nDevice: {device}")
            print("-" * 80)
            
            # Header
            print(f"{'Queue':<6} {'Status':<10} {'Activity':<8} {'Packets':<10} {'Last Seen':<12} {'Avg Len':<8}")
            print("-" * 80)
            
            # Compare each queue
            active_queues = []
            stale_queues = []
            
            for queue_id in queues:
                queue_key = f"{device}_Q{queue_id}"
                if queue_key not in self.queue_states:
                    continue
                    
                # Get latest state
                latest = self.queue_states[queue_key][-1] if self.queue_states[queue_key] else None
                if not latest:
                    continue
                    
                stats = self.queue_stats[queue_key]
                now = time.time()
                last_activity = stats.get('last_activity', 0)
                age = now - last_activity
                
                # Calculate average packet length
                recent_states = self.queue_states[queue_key][-10:]  # Last 10 events
                avg_len = sum(s.get('skb_len', 0) for s in recent_states) / len(recent_states) if recent_states else 0
                
                status = "🚨 STALE" if age > 5.0 else "✅ ACTIVE"
                activity = "TX/RX" if latest.get('is_active', 0) > 0 else "IDLE"
                
                print(f"Q{queue_id:<5} {status:<10} {activity:<8} "
                      f"{stats['total_packets']:<10} {age:<12.1f} {avg_len:<8.1f}")
                
                if age > 5.0:
                    stale_queues.append(queue_id)
                else:
                    active_queues.append(queue_id)
                    
            # Analysis
            print("\n📊 Analysis:")
            print(f"  Active queues: {active_queues}")
            print(f"  Stale queues: {stale_queues}")
            
            if stale_queues and active_queues:
                print("\n🔍 Key Differences:")
                active_queue = active_queues[0]
                stale_queue = stale_queues[0]
                
                active_key = f"{device}_Q{active_queue}"
                stale_key = f"{device}_Q{stale_queue}"
                
                if (active_key in self.queue_states and stale_key in self.queue_states):
                    active_state = self.queue_states[active_key][-1]
                    stale_state = self.queue_states[stale_key][-1]
                    
                    print(f"  Active Q{active_queue}: pkts={self.queue_stats[active_key]['total_packets']} "
                          f"avg_len={sum(s.get('skb_len', 0) for s in self.queue_states[active_key][-10:]) / min(10, len(self.queue_states[active_key])):.1f}")
                    print(f"  Stale Q{stale_queue}: pkts={self.queue_stats[stale_key]['total_packets']} "
                          f"age={time.time() - self.queue_stats[stale_key].get('last_activity', 0):.1f}s")
                    
                    if len(self.queue_states[stale_key]) == 0:
                        print("  ⚠️  Stale queue has no recent activity!")
                    else:
                        last_stale = self.queue_states[stale_key][-1]
                        if last_stale.get('is_active', 0) == 0:
                            print("  ⚠️  Stale queue showing no activity markers!")
        
        print("="*100)
        print()
        
    def print_final_summary(self):
        print("\n" + "="*100) 
        print("FINAL MONITORING SUMMARY")
        print("="*100)
        
        runtime = time.time() - self.start_time
        print(f"Runtime: {runtime:.1f}s")
        print()
        
        # Overall statistics
        total_queues = len(self.queue_states)
        now = time.time()
        stale_queues = sum(1 for stats in self.queue_stats.values() 
                          if (now - stats.get('last_activity', 0)) > 5.0)
        
        print(f"Total queues monitored: {total_queues}")
        print(f"Stale queues (>5s no activity): {stale_queues}")
        print()
        
        # Queue activity summary
        activity_list = []
        for key, stats in self.queue_stats.items():
            last_activity = stats.get('last_activity', 0)
            age = now - last_activity
            activity_list.append((key, stats['total_packets'], age))
        
        activity_list.sort(key=lambda x: x[1], reverse=True)  # Sort by packet count
        
        if activity_list:
            print("Queue Activity Summary:")
            for queue_key, packet_count, age in activity_list[:10]:
                status = "STALE" if age > 5.0 else "ACTIVE"
                print(f"  {queue_key}: {packet_count} packets, {status} (last seen {age:.1f}s ago)")
        
        # Recommendations
        print("\n💡 Recommendations:")
        if stale_queues == 0:
            print("  ✅ All queues active. System appears healthy.")
        else:
            print("  🚨 Stale queues detected! Investigation needed:")
            print("  1. Check if stale queues correspond to the problematic queue 0")
            print("  2. Monitor vhost worker threads for affected queues")
            print("  3. Verify TUN device and queue initialization")
            print("  4. Check for worker thread scheduling issues")
            
    def run(self):
        try:
            print("Loading BPF program...")
            b = BPF(text=bpf_text)
            
            # Attach probes - using verified available probe points
            b.attach_kprobe(event="tun_net_xmit", fn_name="probe_tun_net_xmit")
            b.attach_kprobe(event="tun_recvmsg", fn_name="probe_tun_recvmsg")
            
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
            print("📡 Device filter: All devices")
            
        print(f"⏱️  Snapshot interval: {self.snapshot_interval}s")
        if self.compare_queues:
            print("🔍 Queue comparison: ENABLED")
        
        print("\n🔍 Queue State Monitor Started")
        print("Monitoring all queue states and comparing for anomalies...")
        print("Press Ctrl+C to stop and show final summary")
        print("="*100)
        print()
        
        try:
            b["queue_states"].open_perf_buffer(self.print_event)
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
        description="Queue state monitoring and comparison tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all queues for anomalies
  sudo %(prog)s
  
  # Monitor specific device with queue comparison
  sudo %(prog)s --device vnet0 --compare-queues
  
  # Monitor with custom snapshot interval
  sudo %(prog)s --device vnet0 --compare-queues --interval 2
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet0)")
    parser.add_argument("--compare-queues", action="store_true", 
                       help="Enable periodic queue comparison analysis")
    parser.add_argument("--interval", "-i", type=int, default=5,
                       help="Snapshot interval in seconds (default: 5)")
    
    args = parser.parse_args()
    
    monitor = QueueStateMonitor(
        device=args.device,
        compare_queues=args.compare_queues,
        snapshot_interval=args.interval
    )
    
    monitor.run()

if __name__ == "__main__":
    main()