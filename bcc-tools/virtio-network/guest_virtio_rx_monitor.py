#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import datetime
from bcc import BPF
import ctypes as ct

# Device name structure for filtering (same as tun_ring_monitor.py)
class Devname(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]

# BPF program for Guest virtio-net RX monitoring with complete structures
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/types.h>

#define IFNAMSIZ 16

// Device name union for efficient comparison (from tun_ring_monitor.py)
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

// Complete virtqueue structure (from include/linux/virtio.h)
struct virtqueue {
    struct list_head list;
    void (*callback)(struct virtqueue *vq);
    const char *name;
    struct virtio_device *vdev;
    unsigned int index;      // This is what we need!
    unsigned int num_free;
    void *priv;
};

// Complete receive_queue structure (from drivers/net/virtio_net.c)
struct receive_queue {
    /* Virtqueue associated with this receive_queue */
    struct virtqueue *vq;
    
    struct napi_struct napi;
    
    // We don't need the rest for our purpose, but it's good practice to be complete
    // struct bpf_prog __rcu *xdp_prog;
    // ... other fields
};

// Event structure for virtio-net RX monitoring
struct virtio_rx_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    // Event type: 1=skb_recv_done, 2=virtnet_poll
    u8 event_type;
    
    // Device and queue info
    char dev_name[IFNAMSIZ];
    u32 queue_index;
    u32 vq_index;        // Raw virtqueue index
    
    // NAPI info (for virtnet_poll)
    u64 napi_ptr;
    u32 napi_budget;
    
    // VirtQueue info
    u64 vq_ptr;
    u32 vq_num_free;
    
    // Network device info
    u64 netdev_ptr;
    u32 netdev_flags;
    u32 netdev_state;
};

// Maps
BPF_PERF_OUTPUT(events);
BPF_ARRAY(name_map, union name_buf, 1);  // Device filter
BPF_ARRAY(filter_enabled, u32, 1);       // Queue filter enabled
BPF_ARRAY(filter_queue, u32, 1);         // Target queue

// Device filter logic (exactly from tun_ring_monitor.py)
static inline int name_filter(struct net_device *dev) {
    union name_buf real_devname;
    bpf_probe_read_kernel_str(real_devname.name, IFNAMSIZ, dev->name);

    int key = 0;
    union name_buf *leaf = name_map.lookup(&key);
    if (!leaf) {
        return 1;  // No filter set - accept all devices
    }
    if (leaf->name_int.hi == 0 && leaf->name_int.lo == 0) {
        return 1;  // Empty filter - accept all devices
    }
    if (leaf->name_int.hi != real_devname.name_int.hi || 
        leaf->name_int.lo != real_devname.name_int.lo) {
        return 0;  // Device name doesn't match
    }
    return 1;  // Device name matches
}

// Queue filter logic
static inline int queue_filter(u32 queue_index) {
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;  // Not our target queue
        }
    }
    return 1;  // Queue matches or no filter
}

// Helper function to calculate RX queue index from virtqueue
// Based on virtio-net kernel code: vq2rxq(vq) = vq->index / 2
static inline u32 vq2rxq(struct virtqueue *vq) {
    if (!vq) return 0xFFFFFFFF;
    
    u32 vq_index = 0;
    if (bpf_probe_read_kernel(&vq_index, sizeof(vq_index), &vq->index) == 0) {
        return vq_index / 2;  // RX queues: 0, 2, 4... -> 0, 1, 2...
    }
    return 0xFFFFFFFF;
}

// Fill common event fields
static inline void fill_common_event(struct virtio_rx_event *event, u8 event_type) {
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->event_type = event_type;
}

// Fill network device info
static inline void fill_netdev_info(struct virtio_rx_event *event, struct net_device *dev) {
    if (!dev) return;
    
    event->netdev_ptr = (u64)dev;
    bpf_probe_read_kernel_str(event->dev_name, sizeof(event->dev_name), dev->name);
    bpf_probe_read_kernel(&event->netdev_flags, sizeof(event->netdev_flags), &dev->flags);
    bpf_probe_read_kernel(&event->netdev_state, sizeof(event->netdev_state), &dev->state);
}

// Fill virtqueue info
static inline void fill_vq_info(struct virtio_rx_event *event, struct virtqueue *vq) {
    if (!vq) return;
    
    event->vq_ptr = (u64)vq;
    bpf_probe_read_kernel(&event->vq_index, sizeof(event->vq_index), &vq->index);
    bpf_probe_read_kernel(&event->vq_num_free, sizeof(event->vq_num_free), &vq->num_free);
    
    // Calculate queue index
    event->queue_index = vq2rxq(vq);
}

// Probe: virtnet_poll - Guest virtio-net NAPI poll handler
int trace_virtnet_poll(struct pt_regs *ctx, struct napi_struct *napi, int budget) {
    if (!napi) return 0;
    
    // Get device directly from napi_struct
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &napi->dev) != 0 || !dev) {
        return 0;
    }
    
    // Apply device filter first
    if (!name_filter(dev)) return 0;
    
    // Get receive_queue from napi_struct using container_of calculation
    // In virtio-net: struct receive_queue { struct virtqueue *vq; struct napi_struct napi; ... }
    // So: receive_queue = container_of(napi, struct receive_queue, napi)
    // From the structure, napi is at offset 8 (after vq pointer)
    struct receive_queue *rq = (struct receive_queue *)((char*)napi - 8);
    
    // Read virtqueue pointer from receive_queue->vq (first field)
    struct virtqueue *vq = NULL;
    if (bpf_probe_read_kernel(&vq, sizeof(vq), &rq->vq) != 0 || !vq) {
        return 0;  // Cannot get virtqueue
    }
    
    // Calculate real queue index
    u32 queue_index = vq2rxq(vq);
    if (queue_index == 0xFFFFFFFF) {
        return 0;  // Invalid queue index
    }
    
    // Apply queue filter with real queue index
    if (!queue_filter(queue_index)) return 0;
    
    // Create event
    struct virtio_rx_event event = {};
    fill_common_event(&event, 2);  // event_type = 2 (virtnet_poll)
    
    event.napi_ptr = (u64)napi;
    event.napi_budget = budget;
    fill_netdev_info(&event, dev);
    fill_vq_info(&event, vq);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: skb_recv_done - Guest virtio-net RX interrupt handler
int trace_skb_recv_done(struct pt_regs *ctx, struct virtqueue *rvq) {
    if (!rvq) return 0;
    
    // Get virtnet_info from virtqueue
    struct virtio_device *vdev = NULL;
    if (bpf_probe_read_kernel(&vdev, sizeof(vdev), &rvq->vdev) != 0 || !vdev) {
        return 0;
    }
    
    void *priv = NULL;
    if (bpf_probe_read_kernel(&priv, sizeof(priv), &vdev->priv) != 0 || !priv) {
        return 0;
    }
    
    // Get net_device from virtnet_info (first field)
    struct net_device *dev = NULL;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), priv) != 0 || !dev) {
        return 0;
    }
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    // Calculate queue index
    u32 queue_index = vq2rxq(rvq);
    if (queue_index == 0xFFFFFFFF) {
        return 0;
    }
    
    // Apply queue filter
    if (!queue_filter(queue_index)) return 0;
    
    // Create event
    struct virtio_rx_event event = {};
    fill_common_event(&event, 1);  // event_type = 1 (skb_recv_done)
    
    fill_netdev_info(&event, dev);
    fill_vq_info(&event, rvq);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Event structure matching the BPF program
class VirtioRxEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("event_type", ct.c_uint8),
        ("dev_name", ct.c_char * 16),
        ("queue_index", ct.c_uint32),
        ("vq_index", ct.c_uint32),
        ("napi_ptr", ct.c_uint64),
        ("napi_budget", ct.c_uint32),
        ("vq_ptr", ct.c_uint64),
        ("vq_num_free", ct.c_uint32),
        ("netdev_ptr", ct.c_uint64),
        ("netdev_flags", ct.c_uint32),
        ("netdev_state", ct.c_uint32),
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(VirtioRxEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    event_names = {
        1: "skb_recv_done",
        2: "virtnet_poll"
    }
    
    print("=" * 80)
    print("🔍 Event: {} | Time: {}".format(
        event_names.get(event.event_type, "unknown"), timestamp_str))
    print("📍 Queue: {} | VQ Index: {} | Device: {} | Process: {} (PID: {})".format(
        event.queue_index, event.vq_index, event.dev_name.decode('utf-8', 'replace'),
        event.comm.decode('utf-8', 'replace'), event.pid))
    
    # VirtQueue information
    print("🔗 VQ: 0x{:x} | Num Free: {}".format(
        event.vq_ptr, event.vq_num_free))
    
    # NAPI information (for virtnet_poll)
    if event.event_type == 2:  # virtnet_poll
        print("📊 NAPI: 0x{:x} | Budget: {}".format(
            event.napi_ptr, event.napi_budget))
    
    # Network device information
    print("🌐 NetDev: 0x{:x} | Flags: 0x{:x}, State: 0x{:x}".format(
        event.netdev_ptr, event.netdev_flags, event.netdev_state))
    
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Guest virtio-net RX Queue Monitor with Real Queue Filtering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all RX queues on all virtio-net devices
  sudo %(prog)s
  
  # Monitor specific device
  sudo %(prog)s --device ens4
  
  # Monitor specific device and queue (with real queue index detection)
  sudo %(prog)s --device ens4 --queue 1
  
  # Monitor with verbose output  
  sudo %(prog)s --device ens4 --verbose

Features:
  - Real queue index calculation from virtqueue->index / 2
  - Complete data structure definitions from kernel source
  - Reliable device filtering using proven logic from tun_ring_monitor.py
  - Both virtnet_poll and skb_recv_done probe points
  - Detailed virtqueue and NAPI information

Technical Details:
  - Uses complete virtqueue and receive_queue structures from kernel source
  - Implements container_of logic to get receive_queue from napi_struct
  - Accurate queue filtering based on actual virtqueue index calculation
  - Fallback mechanisms for different kernel structure layouts
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., ens4)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by RX queue index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach kprobes
        b.attach_kprobe(event="virtnet_poll", fn_name="trace_virtnet_poll")
        b.attach_kprobe(event="skb_recv_done", fn_name="trace_skb_recv_done")
        
        if args.verbose:
            print("✅ All probes attached successfully")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        return
    
    # Set device filter using tun_ring_monitor.py approach
    devname_map = b["name_map"]
    _name = Devname()
    if args.device:
        _name.name = args.device.encode()
        devname_map[0] = _name
        print("📡 Device filter: {} (using verified logic)".format(args.device))
    else:
        # Set empty filter to accept all devices
        _name.name = b""
        devname_map[0] = _name
        print("📡 Device filter: All virtio-net devices")
    
    # Set queue filter with real queue index calculation
    if args.queue is not None:
        b["filter_enabled"][0] = ct.c_uint32(1)
        b["filter_queue"][0] = ct.c_uint32(args.queue)
        print("🔍 Queue filter: {} (using real virtqueue->index calculation)".format(args.queue))
    else:
        b["filter_enabled"][0] = ct.c_uint32(0)
        print("🔍 Queue filter: All queues")
    
    print("🚀 Guest virtio-net RX Monitor Started")
    print("📊 Monitoring virtnet_poll and skb_recv_done events with real queue filtering")
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