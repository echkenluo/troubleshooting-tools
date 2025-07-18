#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
vhost_queue_debug.py - Debug vhost queue 0 initialization and state issues

This tool helps diagnose why vhost queue 0 is not processing packets while
other queues work normally. It traces key vhost-net functions to identify
initialization failures and runtime issues.
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

# BPF program for vhost queue debugging
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <net/sock.h>

#define IFNAMSIZ 16

// Event types for different probe points
#define EVENT_VHOST_NET_ENABLE_VQ    1
#define EVENT_VHOST_NET_DISABLE_VQ   2
#define EVENT_GET_TAP_PTR_RING       3
#define EVENT_VHOST_VQ_ACCESS_OK     4
#define EVENT_VQ_IOTLB_PREFETCH      5
#define EVENT_HANDLE_RX_KICK         6
#define EVENT_HANDLE_RX_NET          7
#define EVENT_VHOST_NET_RX_PEEK      8
#define EVENT_VHOST_ADD_USED         9
#define EVENT_VHOST_SIGNAL          10

// Debug event structure
struct vhost_debug_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    u8 event_type;
    u32 queue_index;
    char dev_name[IFNAMSIZ];
    
    // Function-specific data
    union {
        struct {
            u64 vq_ptr;
            u64 sock_ptr;
            u64 file_ptr;
            int ret_code;
        } enable_vq;
        
        struct {
            u64 vq_ptr;
            u64 ptr_ring;
            u64 sock_file;
            int success;
        } ptr_ring;
        
        struct {
            u64 vq_ptr;
            u64 desc_ptr;
            u64 avail_ptr;
            u64 used_ptr;
            int access_ok;
        } access_check;
        
        struct {
            u64 vq_ptr;
            u16 avail_idx;
            u16 last_avail;
            u16 last_used;
            u16 num_heads;
        } vq_state;
        
        struct {
            u64 vq_ptr;
            u32 head;
            u32 len;
            int ret_val;
        } rx_data;
    } data;
};

// Maps
BPF_PERF_OUTPUT(events);

// Device and queue filter
struct filter_key {
    char device[IFNAMSIZ];
    u32 queue;
};
BPF_ARRAY(target_filter, struct filter_key, 1);

// Helper to get device name from socket
static inline int get_device_name(struct socket *sock, char *name) {
    if (!sock || !sock->file) return -1;
    
    struct file *file = sock->file;
    if (!file->f_op) return -1;
    
    // For TUN/TAP devices, try to get the device name
    // This is a simplified approach - actual implementation depends on device type
    __builtin_memcpy(name, "unknown", 8);
    return 0;
}

// Check if event matches filter
static inline int check_filter(u32 queue_index, const char *dev_name) {
    int key = 0;
    struct filter_key *filter = target_filter.lookup(&key);
    if (!filter) return 1;  // No filter, accept all
    
    // Check queue filter
    if (filter->queue != 0xFFFFFFFF && filter->queue != queue_index) {
        return 0;
    }
    
    // Check device filter
    if (filter->device[0] != 0) {
        for (int i = 0; i < IFNAMSIZ; i++) {
            if (dev_name[i] != filter->device[i]) {
                return 0;
            }
            if (dev_name[i] == 0) break;
        }
    }
    
    return 1;
}

// Fill common event fields
static inline void fill_common_event(struct vhost_debug_event *event, u8 event_type, u32 queue_index) {
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->event_type = event_type;
    event->queue_index = queue_index;
    __builtin_memcpy(event->dev_name, "vhost", 6);
}

// Probe: vhost_net_enable_vq
int trace_vhost_net_enable_vq(struct pt_regs *ctx, struct vhost_net *net, struct vhost_virtqueue *vq) {
    u32 queue_index = 0;
    
    // Try to determine queue index from virtqueue pointer
    // This is approximate - exact calculation depends on vhost_net structure layout
    if (vq) {
        // Queue index calculation based on virtqueue array offset
        // vq should be either &net->vqs[0].vq or &net->vqs[1].vq
        // This is a simplified approach
        queue_index = 0;  // Will be refined based on actual structure
    }
    
    if (!check_filter(queue_index, "vhost")) return 0;
    
    struct vhost_debug_event event = {};
    fill_common_event(&event, EVENT_VHOST_NET_ENABLE_VQ, queue_index);
    
    event.data.enable_vq.vq_ptr = (u64)vq;
    event.data.enable_vq.sock_ptr = 0;  // Will be populated if available
    event.data.enable_vq.file_ptr = 0;
    event.data.enable_vq.ret_code = 0;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Return probe: vhost_net_enable_vq
int trace_vhost_net_enable_vq_return(struct pt_regs *ctx) {
    u32 queue_index = 0;
    int ret = PT_REGS_RC(ctx);
    
    if (!check_filter(queue_index, "vhost")) return 0;
    
    struct vhost_debug_event event = {};
    fill_common_event(&event, EVENT_VHOST_NET_ENABLE_VQ, queue_index);
    
    event.data.enable_vq.ret_code = ret;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: vhost_vq_access_ok
int trace_vhost_vq_access_ok(struct pt_regs *ctx, struct vhost_virtqueue *vq) {
    if (!vq) return 0;
    
    u32 queue_index = 0;
    if (!check_filter(queue_index, "vhost")) return 0;
    
    struct vhost_debug_event event = {};
    fill_common_event(&event, EVENT_VHOST_VQ_ACCESS_OK, queue_index);
    
    event.data.access_check.vq_ptr = (u64)vq;
    // Read descriptor, available, and used ring pointers
    bpf_probe_read_kernel(&event.data.access_check.desc_ptr, sizeof(u64), &vq->desc);
    bpf_probe_read_kernel(&event.data.access_check.avail_ptr, sizeof(u64), &vq->avail);
    bpf_probe_read_kernel(&event.data.access_check.used_ptr, sizeof(u64), &vq->used);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Return probe: vhost_vq_access_ok
int trace_vhost_vq_access_ok_return(struct pt_regs *ctx) {
    u32 queue_index = 0;
    int ret = PT_REGS_RC(ctx);
    
    if (!check_filter(queue_index, "vhost")) return 0;
    
    struct vhost_debug_event event = {};
    fill_common_event(&event, EVENT_VHOST_VQ_ACCESS_OK, queue_index);
    
    event.data.access_check.access_ok = ret;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: handle_rx_kick
int trace_handle_rx_kick(struct pt_regs *ctx, struct vhost_virtqueue *vq) {
    if (!vq) return 0;
    
    u32 queue_index = 0;  // RX queue is typically index 0
    if (!check_filter(queue_index, "vhost")) return 0;
    
    struct vhost_debug_event event = {};
    fill_common_event(&event, EVENT_HANDLE_RX_KICK, queue_index);
    
    event.data.vq_state.vq_ptr = (u64)vq;
    // Read virtqueue state
    bpf_probe_read_kernel(&event.data.vq_state.avail_idx, sizeof(u16), &vq->avail_idx);
    bpf_probe_read_kernel(&event.data.vq_state.last_avail, sizeof(u16), &vq->last_avail_idx);
    bpf_probe_read_kernel(&event.data.vq_state.last_used, sizeof(u16), &vq->last_used_idx);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: handle_rx_net
int trace_handle_rx_net(struct pt_regs *ctx, struct vhost_net *net) {
    u32 queue_index = 0;  // RX queue
    if (!check_filter(queue_index, "vhost")) return 0;
    
    struct vhost_debug_event event = {};
    fill_common_event(&event, EVENT_HANDLE_RX_NET, queue_index);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe: vhost_signal
int trace_vhost_signal(struct pt_regs *ctx, struct vhost_dev *dev, struct vhost_virtqueue *vq) {
    if (!vq) return 0;
    
    u32 queue_index = 0;
    if (!check_filter(queue_index, "vhost")) return 0;
    
    struct vhost_debug_event event = {};
    fill_common_event(&event, EVENT_VHOST_SIGNAL, queue_index);
    
    event.data.vq_state.vq_ptr = (u64)vq;
    bpf_probe_read_kernel(&event.data.vq_state.avail_idx, sizeof(u16), &vq->avail_idx);
    bpf_probe_read_kernel(&event.data.vq_state.last_avail, sizeof(u16), &vq->last_avail_idx);
    bpf_probe_read_kernel(&event.data.vq_state.last_used, sizeof(u16), &vq->last_used_idx);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Event structure matching BPF program
class VhostDebugEvent(ct.Structure):
    class EnableVqData(ct.Structure):
        _fields_ = [
            ("vq_ptr", ct.c_uint64),
            ("sock_ptr", ct.c_uint64),
            ("file_ptr", ct.c_uint64),
            ("ret_code", ct.c_int32),
        ]
    
    class PtrRingData(ct.Structure):
        _fields_ = [
            ("vq_ptr", ct.c_uint64),
            ("ptr_ring", ct.c_uint64),
            ("sock_file", ct.c_uint64),
            ("success", ct.c_int32),
        ]
    
    class AccessCheckData(ct.Structure):
        _fields_ = [
            ("vq_ptr", ct.c_uint64),
            ("desc_ptr", ct.c_uint64),
            ("avail_ptr", ct.c_uint64),
            ("used_ptr", ct.c_uint64),
            ("access_ok", ct.c_int32),
        ]
    
    class VqStateData(ct.Structure):
        _fields_ = [
            ("vq_ptr", ct.c_uint64),
            ("avail_idx", ct.c_uint16),
            ("last_avail", ct.c_uint16),
            ("last_used", ct.c_uint16),
            ("num_heads", ct.c_uint16),
        ]
    
    class RxData(ct.Structure):
        _fields_ = [
            ("vq_ptr", ct.c_uint64),
            ("head", ct.c_uint32),
            ("len", ct.c_uint32),
            ("ret_val", ct.c_int32),
        ]
    
    class EventData(ct.Union):
        _fields_ = [
            ("enable_vq", EnableVqData),
            ("ptr_ring", PtrRingData),
            ("access_check", AccessCheckData),
            ("vq_state", VqStateData),
            ("rx_data", RxData),
        ]
    
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("event_type", ct.c_uint8),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("data", EventData),
    ]

# Event type names
EVENT_NAMES = {
    1: "vhost_net_enable_vq",
    2: "vhost_net_disable_vq", 
    3: "get_tap_ptr_ring",
    4: "vhost_vq_access_ok",
    5: "vq_iotlb_prefetch",
    6: "handle_rx_kick",
    7: "handle_rx_net",
    8: "vhost_net_rx_peek",
    9: "vhost_add_used",
    10: "vhost_signal",
}

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(VhostDebugEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    event_name = EVENT_NAMES.get(event.event_type, f"unknown_{event.event_type}")
    
    print(f"{timestamp_str} [{event.pid}] {event_name}: queue={event.queue_index} dev={event.dev_name.decode('utf-8', 'replace')}")
    
    # Print event-specific data
    if event.event_type == 1:  # vhost_net_enable_vq
        print(f"  VQ: {event.data.enable_vq.vq_ptr:#x} sock: {event.data.enable_vq.sock_ptr:#x} ret: {event.data.enable_vq.ret_code}")
    elif event.event_type == 4:  # vhost_vq_access_ok
        print(f"  VQ: {event.data.access_check.vq_ptr:#x} desc: {event.data.access_check.desc_ptr:#x}")
        print(f"  avail: {event.data.access_check.avail_ptr:#x} used: {event.data.access_check.used_ptr:#x}")
        print(f"  access_ok: {event.data.access_check.access_ok}")
    elif event.event_type in [6, 10]:  # handle_rx_kick, vhost_signal
        print(f"  VQ: {event.data.vq_state.vq_ptr:#x} avail_idx: {event.data.vq_state.avail_idx}")
        print(f"  last_avail: {event.data.vq_state.last_avail} last_used: {event.data.vq_state.last_used}")
    
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Debug vhost queue initialization and runtime issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Debug all vhost queues
  sudo %(prog)s
  
  # Debug specific queue
  sudo %(prog)s --queue 0
  
  # Debug specific device and queue
  sudo %(prog)s --device vnet26 --queue 0
        """
    )
    
    parser.add_argument("--device", "-d", help="Filter by device name")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach probes
        b.attach_kprobe(event="vhost_net_enable_vq", fn_name="trace_vhost_net_enable_vq")
        b.attach_kretprobe(event="vhost_net_enable_vq", fn_name="trace_vhost_net_enable_vq_return")
        b.attach_kprobe(event="vhost_vq_access_ok", fn_name="trace_vhost_vq_access_ok")
        b.attach_kretprobe(event="vhost_vq_access_ok", fn_name="trace_vhost_vq_access_ok_return")
        b.attach_kprobe(event="handle_rx_kick", fn_name="trace_handle_rx_kick")
        b.attach_kprobe(event="handle_rx_net", fn_name="trace_handle_rx_net")
        b.attach_kprobe(event="vhost_signal", fn_name="trace_vhost_signal")
        
        if args.verbose:
            print("✅ Probes attached successfully")
        
    except Exception as e:
        print(f"❌ Failed to load BPF program: {e}")
        return
    
    # Set filter
    filter_key = b["target_filter"]
    filter_data = filter_key.Leaf()
    
    if args.device:
        device_bytes = args.device.encode('utf-8')[:15]
        for i in range(len(device_bytes)):
            filter_data.device[i] = device_bytes[i]
    
    if args.queue is not None:
        filter_data.queue = args.queue
    else:
        filter_data.queue = 0xFFFFFFFF  # Accept all queues
    
    filter_key[0] = filter_data
    
    print("🔍 Vhost Queue Debug Monitor Started")
    print("📊 Tracing vhost queue initialization and runtime")
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
    
    print("\n👋 Debugging stopped.")

if __name__ == "__main__":
    main()