#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
virtnet_poll_monitor.py - Monitor virtnet_poll function with filtering

This script traces the virtnet_poll function in the Linux kernel's virtio-net driver,
with filtering by interface name and RX queue index.

Implementation details:
- Uses container_of to get receive_queue from napi_struct
- Calculates RX queue using vq2rxq formula: vq->index / 2
- Filters by interface name and queue number
"""

from __future__ import print_function
import argparse
import sys
import datetime
try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF
import ctypes as ct

# BPF program for virtnet_poll monitoring
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>

#define IFNAMSIZ 16

// virtqueue structure is already defined in linux/virtio.h

// Receive queue structure definition (simplified)
struct receive_queue {
    struct virtqueue *vq;
    struct napi_struct napi;
    // Other fields omitted for simplicity
};

// Event structure for virtnet_poll monitoring
struct virtnet_poll_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    // Device and queue info
    char dev_name[IFNAMSIZ];
    u32 queue_index;
    u32 vq_index;
    
    // Poll parameters
    u32 budget;
    u32 processed;  // For return probe
    
    // Pointers for debugging
    u64 napi_ptr;
    u64 rq_ptr;
    u64 vq_ptr;
    u64 netdev_ptr;
    
    // Event type: 0=entry, 1=exit
    u8 event_type;
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_HASH(poll_tracking, u64, struct virtnet_poll_event);

// Filter settings
struct device_filter {
    char name[IFNAMSIZ];
};
BPF_ARRAY(filter_device, struct device_filter, 1);
BPF_ARRAY(filter_queue_enabled, u32, 1);
BPF_ARRAY(filter_queue_index, u32, 1);

// Helper function to get queue index from virtqueue
static inline u32 vq2rxq(struct virtqueue *vq) {
    if (!vq) return 0;
    return vq->index / 2;
}

// Check if device name matches filter
static inline int check_device_filter(struct net_device *dev) {
    if (!dev) return 0;
    
    char real_devname[IFNAMSIZ] = {};
    int ret = bpf_probe_read_kernel_str(real_devname, IFNAMSIZ, dev->name);
    if (ret < 0) {
        return 0;  // Cannot read device name
    }
    
    // Get filter device structure
    int key = 0;
    struct device_filter *filter = filter_device.lookup(&key);
    if (!filter) {
        return 1;  // No filter set, accept all
    }
    
    // Check if filter is empty (accept all)
    if (filter->name[0] == 0) {
        return 1;
    }
    
    // Compare device names
    #pragma unroll
    for (int i = 0; i < IFNAMSIZ; i++) {
        if (real_devname[i] != filter->name[i]) {
            return 0;  // Names don't match
        }
        if (real_devname[i] == 0) {
            break;  // End of string
        }
    }
    
    return 1;  // Names match
}

// Check if queue index matches filter
static inline int check_queue_filter(u32 queue_index) {
    u32 *enabled = filter_queue_enabled.lookup(&(int){0});
    if (!enabled || *enabled == 0) {
        return 1;  // Queue filter not enabled, accept all
    }
    
    u32 *target_queue = filter_queue_index.lookup(&(int){0});
    if (!target_queue) {
        return 1;  // No target queue set, accept all
    }
    
    return (queue_index == *target_queue);
}

// Probe for virtnet_poll entry
int trace_virtnet_poll_entry(struct pt_regs *ctx, struct napi_struct *napi, int budget) {
    if (!napi) return 0;
    
    // Calculate receive_queue pointer using container_of
    // rq = container_of(napi, struct receive_queue, napi)
    // Offset of napi field in receive_queue is 8 bytes
    struct receive_queue *rq = (struct receive_queue *)((u64)napi - 8);
    
    // Get virtqueue pointer from rq->vq
    struct virtqueue *vq = NULL;
    if (bpf_probe_read_kernel(&vq, sizeof(vq), &rq->vq) != 0 || !vq) {
        return 0;
    }
    
    // Get queue index
    u32 vq_index = 0;
    if (bpf_probe_read_kernel(&vq_index, sizeof(vq_index), &vq->index) != 0) {
        return 0;
    }
    u32 queue_index = vq_index / 2;
    
    // Check queue filter
    if (!check_queue_filter(queue_index)) {
        return 0;
    }
    
    // Get net_device from napi->dev
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &napi->dev) != 0 || !dev) {
        return 0;
    }
    
    // Check device filter
    if (!check_device_filter(dev)) {
        return 0;
    }
    
    // Create event
    struct virtnet_poll_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Fill device info
    bpf_probe_read_kernel_str(event.dev_name, sizeof(event.dev_name), dev->name);
    event.queue_index = queue_index;
    event.vq_index = vq_index;
    event.budget = budget;
    
    // Fill pointers for debugging
    event.napi_ptr = (u64)napi;
    event.rq_ptr = (u64)rq;
    event.vq_ptr = (u64)vq;
    event.netdev_ptr = (u64)dev;
    
    event.event_type = 0;  // Entry event
    
    // Store event for correlation with return probe
    u64 key = (u64)napi;
    poll_tracking.update(&key, &event);
    
    // Submit event
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

// Probe for virtnet_poll return
int trace_virtnet_poll_return(struct pt_regs *ctx) {
    u64 key = (u64)PT_REGS_PARM1(ctx);  // napi pointer from entry
    
    struct virtnet_poll_event *entry_event = poll_tracking.lookup(&key);
    if (!entry_event) {
        return 0;  // No matching entry event
    }
    
    // Create exit event based on entry event
    struct virtnet_poll_event event = *entry_event;
    event.timestamp = bpf_ktime_get_ns();
    event.processed = PT_REGS_RC(ctx);  // Return value
    event.event_type = 1;  // Exit event
    
    // Submit event
    events.perf_submit(ctx, &event, sizeof(event));
    
    // Clean up tracking
    poll_tracking.delete(&key);
    
    return 0;
}

// Probe for skb_recv_done - virtio-net RX interrupt handler
int trace_skb_recv_done(struct pt_regs *ctx, struct virtqueue *rvq) {
    if (!rvq) return 0;
    
    // Get vq->index to calculate queue index
    u32 vq_index = 0;
    if (bpf_probe_read_kernel(&vq_index, sizeof(vq_index), &rvq->index) != 0) {
        return 0;
    }
    u32 queue_index = vq_index / 2;  // vq2rxq
    
    // Check queue filter first (cheaper check)
    if (!check_queue_filter(queue_index)) {
        return 0;
    }
    
    // Get virtio_device from virtqueue
    struct virtio_device *vdev = NULL;
    if (bpf_probe_read_kernel(&vdev, sizeof(vdev), &rvq->vdev) != 0 || !vdev) {
        return 0;
    }
    
    // Get virtnet_info from vdev->priv
    void *vi = NULL;
    if (bpf_probe_read_kernel(&vi, sizeof(vi), &vdev->priv) != 0 || !vi) {
        return 0;
    }
    
    // virtnet_info structure has these fields at the beginning:
    // struct virtio_device *vdev;
    // struct virtqueue *cvq;
    // struct net_device *dev;
    // So dev is at offset 16 (0x10)
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), vi + 16) != 0 || !dev) {
        return 0;
    }
    
    // Check device filter
    if (!check_device_filter(dev)) {
        return 0;
    }
    
    // Create event for skb_recv_done
    struct virtnet_poll_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Fill device info
    bpf_probe_read_kernel_str(event.dev_name, sizeof(event.dev_name), dev->name);
    event.queue_index = queue_index;
    event.vq_index = vq_index;
    
    // Fill pointers
    event.vq_ptr = (u64)rvq;
    event.netdev_ptr = (u64)dev;
    
    // Use event_type = 2 to distinguish from virtnet_poll
    event.event_type = 2;  // skb_recv_done event
    
    // Submit event
    events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}
"""

# Device filter structure
class DeviceFilter(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]

# Event structure matching the BPF program
class VirtnetPollEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_name", ct.c_char * 16),
        ("queue_index", ct.c_uint32),
        ("vq_index", ct.c_uint32),
        ("budget", ct.c_uint32),
        ("processed", ct.c_uint32),
        ("napi_ptr", ct.c_uint64),
        ("rq_ptr", ct.c_uint64),
        ("vq_ptr", ct.c_uint64),
        ("netdev_ptr", ct.c_uint64),
        ("event_type", ct.c_uint8),
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(VirtnetPollEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    if event.event_type == 0:  # virtnet_poll entry
        print("{} [{}] virtnet_poll ENTRY: dev={} queue={} budget={} vq_idx={} napi={:#x}".format(
            timestamp_str,
            event.pid,
            event.dev_name.decode('utf-8', 'replace'),
            event.queue_index,
            event.budget,
            event.vq_index,
            event.napi_ptr
        ))
    elif event.event_type == 1:  # virtnet_poll exit
        efficiency = (event.processed * 100.0 / event.budget) if event.budget > 0 else 0
        print("{} [{}] virtnet_poll EXIT:  dev={} queue={} processed={}/{} ({:.1f}%)".format(
            timestamp_str,
            event.pid,
            event.dev_name.decode('utf-8', 'replace'),
            event.queue_index,
            event.processed,
            event.budget,
            efficiency
        ))
    elif event.event_type == 2:  # skb_recv_done
        print("{} [{}] skb_recv_done:     dev={} queue={} vq_idx={} vq={:#x}".format(
            timestamp_str,
            event.pid,
            event.dev_name.decode('utf-8', 'replace'),
            event.queue_index,
            event.vq_index,
            event.vq_ptr
        ))

def main():
    parser = argparse.ArgumentParser(
        description="Monitor virtio-net RX functions (virtnet_poll and skb_recv_done) with filtering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all devices and queues
  sudo %(prog)s
  
  # Monitor specific device
  sudo %(prog)s --device eth0
  
  # Monitor specific device and queue
  sudo %(prog)s --device eth0 --queue 0
  
  # Monitor specific queue on all devices
  sudo %(prog)s --queue 0
        """
    )
    
    parser.add_argument("--device", "-d", help="Filter by device name (e.g., eth0, enp1s0)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by RX queue index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach probes
        b.attach_kprobe(event="virtnet_poll", fn_name="trace_virtnet_poll_entry")
        b.attach_kretprobe(event="virtnet_poll", fn_name="trace_virtnet_poll_return")
        b.attach_kprobe(event="skb_recv_done", fn_name="trace_skb_recv_done")
        
        if args.verbose:
            print("✅ Probes attached successfully")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        print("Make sure you're running as root and virtnet_poll function exists")
        return
    
    # Set device filter
    filter_device = b["filter_device"]
    device_filter = DeviceFilter()
    if args.device:
        device_bytes = args.device.encode('utf-8')
        if len(device_bytes) >= 16:
            print("❌ Device name too long (max 15 characters)")
            return
        # Set device name in structure
        device_filter.name = device_bytes
        filter_device[0] = device_filter
        print("📡 Device filter: {}".format(args.device))
    else:
        # Clear device filter (accept all)
        device_filter.name = b""
        filter_device[0] = device_filter
        print("📡 Device filter: All devices")
    
    # Set queue filter
    if args.queue is not None:
        b["filter_queue_enabled"][0] = ct.c_uint32(1)
        b["filter_queue_index"][0] = ct.c_uint32(args.queue)
        print("🔍 Queue filter: {}".format(args.queue))
    else:
        b["filter_queue_enabled"][0] = ct.c_uint32(0)
        print("🔍 Queue filter: All queues")
    
    print("\n🚀 Virtio-net RX Monitor Started")
    print("📊 Monitoring virtnet_poll and skb_recv_done events")
    print("⏳ Waiting for events... Press Ctrl+C to stop\n")
    
    try:
        b["events"].open_perf_buffer(print_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\n👋 Monitoring stopped.")

if __name__ == "__main__":
    main()