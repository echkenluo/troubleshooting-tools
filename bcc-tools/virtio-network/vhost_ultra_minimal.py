#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
vhost_ultra_minimal.py - Ultra-minimal comprehensive vhost monitor for testing

This tool tests the embedded vhost structures for signal analysis.
"""

from __future__ import print_function
import argparse
import sys
import datetime
import ctypes as ct
from bcc import BPF

# BPF program with minimal structure test
bpf_text = """
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/virtio_net.h>
#include <linux/virtio_ring.h>
#include <linux/file.h>
#include <linux/eventfd.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/uio.h>
#include <linux/atomic.h>
#include <linux/llist.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/sched.h>

#define UIO_MAXIOV 1024

// Forward declarations
struct vhost_work;
struct vhost_dev;
struct vhost_virtqueue;
typedef void (*vhost_work_fn_t)(struct vhost_work *work);

// Essential vhost structures - minimal set for testing
struct vhost_work {
	struct llist_node	  node;
	vhost_work_fn_t		  fn;
	unsigned long		  flags;
};

struct vhost_poll {
	poll_table                table;
	wait_queue_head_t        *wqh;
	wait_queue_entry_t              wait;
	struct vhost_work	  work;
	__poll_t		  mask;
	struct vhost_dev	 *dev;
};

struct vhost_umem_node {
	struct rb_node rb;
	struct list_head link;
	__u64 start;
	__u64 last;
	__u64 size;
	__u64 userspace_addr;
	__u32 perm;
	__u32 flags_padding;
	__u64 __subtree_last;
};

struct vhost_umem {
	struct rb_root_cached umem_tree;
	struct list_head umem_list;
	int numem;
};

/* The virtqueue structure - key structure for analysis */
struct vhost_virtqueue {
	struct vhost_dev *dev;

	/* The actual ring of buffers. */
	struct mutex mutex;
	unsigned int num;
	struct vring_desc __user *desc;
	struct vring_avail __user *avail;
	struct vring_used __user *used;
	const struct vhost_umem_node *meta_iotlb[3];  // VHOST_NUM_ADDRS = 3
	struct file *kick;
	struct eventfd_ctx *call_ctx;
	struct eventfd_ctx *error_ctx;
	struct eventfd_ctx *log_ctx;

	struct vhost_poll poll;

	/* The routine to call when the Guest pings us, or timeout. */
	vhost_work_fn_t handle_kick;

	/* Last available index we saw. */
	u16 last_avail_idx;

	/* Caches available index value from user. */
	u16 avail_idx;

	/* Last index we used. */
	u16 last_used_idx;

	/* Used flags */
	u16 used_flags;

	/* Last used index value we have signalled on */
	u16 signalled_used;

	/* Last used index value we have signalled on */
	bool signalled_used_valid;

	/* Log writes to used structure. */
	bool log_used;
	u64 log_addr;

	struct iovec iov[UIO_MAXIOV];
	struct iovec iotlb_iov[64];
	struct iovec *indirect;
	struct vring_used_elem *heads;
	/* Protected by virtqueue mutex. */
	struct vhost_umem *umem;
	struct vhost_umem *iotlb;
	void *private_data;
	u64 acked_features;
	u64 acked_backend_features;
	/* Log write descriptors */
	void __user *log_base;
	void *log;  // Simplified

	/* Ring endianness. Defaults to legacy native endianness.
	 * Set to true when starting a modern virtio device. */
	bool is_le;
#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
	/* Ring endianness requested by userspace for cross-endian support. */
	bool user_be;
#endif
	u32 busyloop_timeout;
};

struct vhost_dev {
	struct mm_struct *mm;
	struct mutex mutex;
	struct vhost_virtqueue **vqs;
	int nvqs;
	struct eventfd_ctx *log_ctx;
	struct llist_head work_list;
	struct task_struct *worker;
	struct vhost_umem *umem;
	struct vhost_umem *iotlb;
	spinlock_t iotlb_lock;
	struct list_head read_list;
	struct list_head pending_list;
	wait_queue_head_t wait;
	int iov_limit;
	int weight;
	int byte_weight;
};

// Ultra minimal event structure for testing
struct vhost_ultra_minimal_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    // Basic identification
    u64 dev_ptr;
    u64 vq_ptr;
    u32 heads_count;
    u8 queue_index;
    
    // Core vhost_virtqueue fields
    u32 ring_num;
    u64 desc_ptr;
    u64 avail_ptr;
    u64 used_ptr;
    u16 last_avail_idx;
    u16 avail_idx;
    u16 last_used_idx;
    u16 used_flags;
    u16 signalled_used;
    u8 signalled_used_valid;
    u32 busyloop_timeout;
    u64 call_ctx_ptr;
    u8 log_used;
    
    // Core vhost_dev fields
    u64 mm_ptr;
    u64 vqs_ptr;
    int nvqs;
    u64 worker_ptr;
    int iov_limit;
    int weight;
    int byte_weight;
    
    // Network queue detection
    u64 private_data_ptr;
    u8 is_net_vq;
    
    // Memory management
    u64 umem_ptr;
    u64 iotlb_ptr;
    u32 umem_numem;
    u32 iotlb_numem;
    
    // Debug info
    u32 read_failures;
    u8 structure_valid;
};

// Maps
BPF_PERF_OUTPUT(events);

// Safe memory read helper
static inline int safe_read_kernel(void *dst, int size, const void *src) {
    return bpf_probe_read_kernel(dst, size, src);
}

// Main probe function for vhost_add_used_and_signal_n
int trace_vhost_add_used_and_signal_n(struct pt_regs *ctx) {
    struct vhost_dev *dev = (struct vhost_dev *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    void *heads = (void *)PT_REGS_PARM3(ctx);
    unsigned count = (unsigned)PT_REGS_PARM4(ctx);
    
    if (!dev || !vq) return 0;
    
    // Create minimal event
    struct vhost_ultra_minimal_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Basic identification
    event.dev_ptr = (u64)dev;
    event.vq_ptr = (u64)vq;
    event.heads_count = count;
    
    // Extract core vhost_virtqueue fields
    if (safe_read_kernel(&event.ring_num, sizeof(event.ring_num), &vq->num) != 0) event.read_failures++;
    if (safe_read_kernel(&event.desc_ptr, sizeof(event.desc_ptr), &vq->desc) != 0) event.read_failures++;
    if (safe_read_kernel(&event.avail_ptr, sizeof(event.avail_ptr), &vq->avail) != 0) event.read_failures++;
    if (safe_read_kernel(&event.used_ptr, sizeof(event.used_ptr), &vq->used) != 0) event.read_failures++;
    if (safe_read_kernel(&event.last_avail_idx, sizeof(event.last_avail_idx), &vq->last_avail_idx) != 0) event.read_failures++;
    if (safe_read_kernel(&event.avail_idx, sizeof(event.avail_idx), &vq->avail_idx) != 0) event.read_failures++;
    if (safe_read_kernel(&event.last_used_idx, sizeof(event.last_used_idx), &vq->last_used_idx) != 0) event.read_failures++;
    if (safe_read_kernel(&event.used_flags, sizeof(event.used_flags), &vq->used_flags) != 0) event.read_failures++;
    if (safe_read_kernel(&event.signalled_used, sizeof(event.signalled_used), &vq->signalled_used) != 0) event.read_failures++;
    if (safe_read_kernel(&event.signalled_used_valid, sizeof(event.signalled_used_valid), &vq->signalled_used_valid) != 0) event.read_failures++;
    if (safe_read_kernel(&event.busyloop_timeout, sizeof(event.busyloop_timeout), &vq->busyloop_timeout) != 0) event.read_failures++;
    if (safe_read_kernel(&event.call_ctx_ptr, sizeof(event.call_ctx_ptr), &vq->call_ctx) != 0) event.read_failures++;
    if (safe_read_kernel(&event.log_used, sizeof(event.log_used), &vq->log_used) != 0) event.read_failures++;
    if (safe_read_kernel(&event.private_data_ptr, sizeof(event.private_data_ptr), &vq->private_data) != 0) event.read_failures++;
    
    // Extract core vhost_dev fields
    if (safe_read_kernel(&event.mm_ptr, sizeof(event.mm_ptr), &dev->mm) != 0) event.read_failures++;
    if (safe_read_kernel(&event.vqs_ptr, sizeof(event.vqs_ptr), &dev->vqs) != 0) event.read_failures++;
    if (safe_read_kernel(&event.nvqs, sizeof(event.nvqs), &dev->nvqs) != 0) event.read_failures++;
    if (safe_read_kernel(&event.worker_ptr, sizeof(event.worker_ptr), &dev->worker) != 0) event.read_failures++;
    if (safe_read_kernel(&event.iov_limit, sizeof(event.iov_limit), &dev->iov_limit) != 0) event.read_failures++;
    if (safe_read_kernel(&event.weight, sizeof(event.weight), &dev->weight) != 0) event.read_failures++;
    if (safe_read_kernel(&event.byte_weight, sizeof(event.byte_weight), &dev->byte_weight) != 0) event.read_failures++;
    
    // Extract memory management info
    if (safe_read_kernel(&event.umem_ptr, sizeof(event.umem_ptr), &vq->umem) != 0) event.read_failures++;
    if (safe_read_kernel(&event.iotlb_ptr, sizeof(event.iotlb_ptr), &vq->iotlb) != 0) event.read_failures++;
    
    // Try to read umem/iotlb details if pointers are valid
    struct vhost_umem *umem = NULL;
    if (safe_read_kernel(&umem, sizeof(umem), &vq->umem) == 0 && umem) {
        if (safe_read_kernel(&event.umem_numem, sizeof(event.umem_numem), &umem->numem) != 0) event.read_failures++;
    }
    
    struct vhost_umem *iotlb = NULL;
    if (safe_read_kernel(&iotlb, sizeof(iotlb), &vq->iotlb) == 0 && iotlb) {
        if (safe_read_kernel(&event.iotlb_numem, sizeof(event.iotlb_numem), &iotlb->numem) != 0) event.read_failures++;
    }
    
    // Detect if this is a network virtqueue
    event.is_net_vq = event.private_data_ptr ? 1 : 0;
    
    // Try to determine queue index
    struct vhost_virtqueue **vqs = NULL;
    if (safe_read_kernel(&vqs, sizeof(vqs), &dev->vqs) == 0 && vqs) {
        struct vhost_virtqueue *vq0 = NULL, *vq1 = NULL;
        if (safe_read_kernel(&vq0, sizeof(vq0), &vqs[0]) == 0 && vq0 == vq) {
            event.queue_index = 0;
        } else if (safe_read_kernel(&vq1, sizeof(vq1), &vqs[1]) == 0 && vq1 == vq) {
            event.queue_index = 1;
        } else {
            event.queue_index = 255; // Unknown
        }
    }
    
    // Set structure validity
    event.structure_valid = (event.read_failures < 5) ? 1 : 0;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Event structure matching BPF program
class VhostUltraMinimalEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_ptr", ct.c_uint64),
        ("vq_ptr", ct.c_uint64),
        ("heads_count", ct.c_uint32),
        ("queue_index", ct.c_uint8),
        ("ring_num", ct.c_uint32),
        ("desc_ptr", ct.c_uint64),
        ("avail_ptr", ct.c_uint64),
        ("used_ptr", ct.c_uint64),
        ("last_avail_idx", ct.c_uint16),
        ("avail_idx", ct.c_uint16),
        ("last_used_idx", ct.c_uint16),
        ("used_flags", ct.c_uint16),
        ("signalled_used", ct.c_uint16),
        ("signalled_used_valid", ct.c_uint8),
        ("busyloop_timeout", ct.c_uint32),
        ("call_ctx_ptr", ct.c_uint64),
        ("log_used", ct.c_uint8),
        ("mm_ptr", ct.c_uint64),
        ("vqs_ptr", ct.c_uint64),
        ("nvqs", ct.c_int32),
        ("worker_ptr", ct.c_uint64),
        ("iov_limit", ct.c_int32),
        ("weight", ct.c_int32),
        ("byte_weight", ct.c_int32),
        ("private_data_ptr", ct.c_uint64),
        ("is_net_vq", ct.c_uint8),
        ("umem_ptr", ct.c_uint64),
        ("iotlb_ptr", ct.c_uint64),
        ("umem_numem", ct.c_uint32),
        ("iotlb_numem", ct.c_uint32),
        ("read_failures", ct.c_uint32),
        ("structure_valid", ct.c_uint8),
    ]

def format_hex_ptr(ptr_val):
    """Format pointer as hex or 'NULL' if zero"""
    return "0x{:x}".format(ptr_val) if ptr_val else "NULL"

def format_bool(bool_val):
    """Format boolean as YES/NO"""
    return "YES" if bool_val else "NO"

def print_ultra_minimal_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(VhostUltraMinimalEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    print("=" * 100)
    print("🔍 ULTRA-MINIMAL VHOST ANALYSIS | Time: {}".format(timestamp_str))
    print("=" * 100)
    
    # Basic Info
    print("📍 Process: {} (PID: {}, TID: {})".format(event.comm.decode('utf-8', 'replace'), event.pid, event.tid))
    print("🎯 Queue: {} | Batch Size: {} | Network: {}".format(event.queue_index, event.heads_count, format_bool(event.is_net_vq)))
    print("🔗 Pointers: dev={} vq={}".format(format_hex_ptr(event.dev_ptr), format_hex_ptr(event.vq_ptr)))
    
    # === VHOST_VIRTQUEUE CORE ===
    print("\n🔄 VHOST_VIRTQUEUE CORE:")
    print("   Ring: size={} desc={} avail={} used={}".format(
        event.ring_num, format_hex_ptr(event.desc_ptr), format_hex_ptr(event.avail_ptr), format_hex_ptr(event.used_ptr)))
    print("   Indices: last_avail={} avail_idx={} last_used={}".format(
        event.last_avail_idx, event.avail_idx, event.last_used_idx))
    print("   Flags: used_flags=0x{:x}".format(event.used_flags))
    print("   Signaling: signalled_used={} valid={}".format(event.signalled_used, format_bool(event.signalled_used_valid)))
    print("   Config: busyloop_timeout={}us call_ctx={} log_used={}".format(
        event.busyloop_timeout, format_hex_ptr(event.call_ctx_ptr), format_bool(event.log_used)))
    
    # === VHOST_DEV CORE ===
    print("\n📋 VHOST_DEV CORE:")
    print("   Memory: mm={} vqs={} nvqs={}".format(format_hex_ptr(event.mm_ptr), format_hex_ptr(event.vqs_ptr), event.nvqs))
    print("   Worker: {}".format(format_hex_ptr(event.worker_ptr)))
    print("   Limits: iov={} weight={} byte_weight={}".format(event.iov_limit, event.weight, event.byte_weight))
    
    # === MEMORY MANAGEMENT ===
    print("\n🧠 MEMORY MANAGEMENT:")
    print("   UMEM: {} (regions={})".format(format_hex_ptr(event.umem_ptr), event.umem_numem))
    print("   IOTLB: {} (regions={})".format(format_hex_ptr(event.iotlb_ptr), event.iotlb_numem))
    
    # === DEBUG ===
    print("\n🐛 DEBUG:")
    print("   Read Failures: {} | Structure Valid: {}".format(event.read_failures, format_bool(event.structure_valid)))
    
    print("=" * 100)
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Ultra-minimal comprehensive vhost monitor for testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool tests the embedded vhost structures for signal analysis.

Examples:
  # Monitor all vhost activity
  sudo %(prog)s
        """
    )
    
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading ultra-minimal vhost monitor BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach probe
        b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_add_used_and_signal_n")
        
        if args.verbose:
            print("✅ Probe attached successfully")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        return
    
    print("🔍 Ultra-Minimal VHOST Monitor Started")
    print("📊 Testing embedded vhost structures")
    print("⏳ Waiting for events... Press Ctrl+C to stop\n")
    
    try:
        b["events"].open_perf_buffer(print_ultra_minimal_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\n👋 Ultra-minimal monitoring stopped.")

if __name__ == "__main__":
    main()