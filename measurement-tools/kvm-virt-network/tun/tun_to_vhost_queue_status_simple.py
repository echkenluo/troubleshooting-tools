#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
import re
import platform
# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)
import ctypes as ct
from time import sleep, strftime

# Devname structure for device filtering
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

def find_kernel_function(base_name, verbose=False):
    """
    Find actual kernel function name, handling GCC clone suffixes.
    GCC may generate optimized clones with suffixes like:
      .isra.N     - Inter-procedural Scalar Replacement of Aggregates
      .constprop.N - Constant Propagation
      .part.N     - Partial inlining
      .cold/.hot  - Code path optimization
    Returns the actual symbol name or None if not found.
    """
    # Pattern handles both vmlinux and module symbols:
    #   vmlinux: "ffffffff81234567 t func_name"
    #   module:  "ffffffffc1234567 t func_name\t[module_name]"
    pattern = re.compile(
        r'^[0-9a-f]+\s+[tT]\s+(' + re.escape(base_name) +
        r'(?:\.(?:isra|constprop|part|cold|hot)\.\d+)*)(?:\s+\[\w+\])?$'
    )

    candidates = []
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                match = pattern.match(line.strip())
                if match:
                    candidates.append(match.group(1))
    except Exception as e:
        if verbose:
            print("Warning: Failed to read /proc/kallsyms: {}".format(e))
        return None

    if not candidates:
        if verbose:
            print("Warning: Function {} not found in /proc/kallsyms".format(base_name))
        return None

    # Prefer exact match, then shortest name (fewer suffixes)
    if base_name in candidates:
        return base_name
    return min(candidates, key=len)

def get_kernel_version():
    """
    Get kernel major.minor version tuple.
    Returns (major, minor) or (0, 0) on error.
    """
    try:
        version_str = platform.release()
        # Extract version numbers (e.g., "5.10.0-247.0.0.el7.v72.x86_64" -> (5, 10))
        parts = version_str.split('-')[0].split('.')
        return (int(parts[0]), int(parts[1]))
    except Exception:
        return (0, 0)

def get_distro_id():
    """
    Get distribution ID from /etc/os-release.
    Returns lowercase distro ID (e.g., 'openeuler', 'centos', 'anolis') or 'unknown'.
    """
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('ID='):
                    # Remove quotes and newline, convert to lowercase
                    distro_id = line.split('=')[1].strip().strip('"').lower()
                    return distro_id
    except Exception:
        pass
    return 'unknown'

def has_irqbypass_module():
    """
    Check if irqbypass kernel module is loaded/available.
    This indicates the kernel has IRQ bypass support for vhost.
    """
    import os
    return os.path.exists('/sys/module/irqbypass')

def needs_5x_vhost_layout():
    """
    Check if kernel needs 5.x vhost structure layout.

    The vhost_virtqueue structure changed in kernels with IRQ bypass support:
    - Old (4.x): call_ctx is struct eventfd_ctx* (8 bytes pointer)
    - New (5.x with irqbypass): call_ctx is struct vhost_vring_call (72 bytes)
      containing eventfd_ctx* + irq_bypass_producer (64 bytes)

    This 64-byte difference affects private_data offset calculation.

    Detection method: Check if irqbypass module exists in /sys/module/
    This is more reliable than distro detection as it directly reflects
    the actual kernel configuration.

    Returns True if 5.x layout (with vhost_vring_call) is needed.
    """
    major, minor = get_kernel_version()
    if major < 5:
        return False

    # Primary detection: check if irqbypass module is loaded
    # This directly indicates whether kernel has IRQ bypass support
    if has_irqbypass_module():
        return True

    # Fallback: openEuler 5.x without irqbypass uses 4.x layout
    distro = get_distro_id()
    if distro == 'openeuler':
        return False

    # Other 5.x kernels typically use 5.x layout
    return True

# Simple BPF program for queue statistics - only tun_net_xmit and vhost_signal
bpf_text = """
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/ptr_ring.h>
#include <linux/if_tun.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h>

#define NETDEV_ALIGN 32
#define MAX_QUEUES 256
#define IFNAMSIZ 16

// Device name union for efficient comparison
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

// Key structure for histograms - includes queue identification
typedef struct hist_key {
    u32 queue_index;
    char dev_name[16];
    u64 slot;
} hist_key_t;

// Use proven macros from tun_ring_monitor.py (avoiding BCC macro expansion issues)
#define member_address(source_struct, source_member)            \
        ({                                                      \
                void* __ret;                                    \
                __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
                __ret;                                          \
})

#define member_read(destination, source_struct, source_member)  \
        do{                                                      \
                bpf_probe_read_kernel(                           \
                destination,                                     \
                sizeof(source_struct->source_member),            \
                member_address(source_struct, source_member)     \
                );                                               \
} while(0)

#define READ_FIELD(dst, ptr, field)                                   \
    do {                                                              \
        typeof(ptr->field) __tmp;                                     \
        bpf_probe_read_kernel(&__tmp, sizeof(__tmp), &ptr->field);    \
        *(dst) = __tmp;                                               \
    } while (0)

// Proven TUN structures from tun_ring_monitor.py
struct tun_struct {
	struct tun_file __rcu	*tfiles[256];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;
	struct net_device	*dev;
	netdev_features_t	set_features;
	int			align;
	int			vnet_hdr_sz;
	int			sndbuf;
	struct sock_fprog	fprog;
	bool			filter_attached;
	int debug;
	spinlock_t lock;
	struct timer_list flow_gc_timer;
	unsigned long ageing_time;
	unsigned int numdisabled;
	struct list_head disabled;
	void *security;
	u32 flow_count;
	u32 rx_batched;
	struct tun_pcpu_stats __percpu *pcpu_stats;
	struct bpf_prog __rcu *xdp_prog;
	struct tun_prog __rcu *steering_prog;
	struct tun_prog __rcu *filter_prog;
};

struct tun_file {
	struct sock sk;
	struct socket socket;
	struct socket_wq wq;
	struct tun_struct __rcu *tun;
	struct fasync_struct *fasync;
	unsigned int flags;
	union {
		u16 queue_index;
		unsigned int ifindex;
	};
	struct napi_struct napi;
	bool napi_enabled;
	bool napi_frags_enabled;
	struct mutex napi_mutex;
	struct list_head next;
	struct tun_struct *detached;
	struct ptr_ring tx_ring;
	struct xdp_rxq_info xdp_rxq;
};

// Complete vhost structures from kernel headers (drivers/vhost/vhost.h)
struct vhost_work {
    struct llist_node node;
    void *fn;  // vhost_work_fn_t
    unsigned long flags;
};

struct vhost_poll {
    poll_table table;
    wait_queue_head_t *wqh;
    wait_queue_entry_t wait;
    struct vhost_work work;
    __poll_t mask;
    struct vhost_dev *dev;
};

// KERNEL_VERSION_5X controls which structure layout to use
// Set via Python based on kernel version detection
#ifndef KERNEL_VERSION_5X
#define KERNEL_VERSION_5X 0
#endif

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
#if KERNEL_VERSION_5X
    // Kernel 5.x added fields - padding to match actual structure size
    // Required for correct vqs[0].vq offset: 0xc8 (200 bytes) vs 4.x: 0xb0 (176 bytes)
    bool use_worker;                        // 1 byte + 7 padding = 8 bytes
    void *msg_handler;                      // 8 bytes (function pointer)
    char __padding_dev[16];                 // Additional padding: 16 bytes
#endif
};

// Kernel 5.x introduced vhost_vring_call structure for IRQ bypass
// Total size: 72 bytes on x86_64
struct vhost_vring_call {
    struct eventfd_ctx *ctx;                // 8 bytes (0x00-0x07)
    char irq_bypass_producer[64];           // 64 bytes (0x08-0x47) - struct irq_bypass_producer
};  // Total: 72 bytes

struct vhost_virtqueue {
    struct vhost_dev *dev;

    // The actual ring of buffers
    struct mutex mutex;
    unsigned int num;
    struct vring_desc *desc;       // __user pointer
    struct vring_avail *avail;     // __user pointer
    struct vring_used *used;       // __user pointer
    void *meta_iotlb[3];           // VHOST_NUM_ADDRS = 3
    struct file *kick;

#if KERNEL_VERSION_5X
    // Kernel 5.x+: call_ctx is a struct containing irq_bypass_producer
    struct vhost_vring_call call_ctx;
#else
    // Kernel 4.x: call_ctx is just a pointer
    struct eventfd_ctx *call_ctx;
#endif

    struct eventfd_ctx *error_ctx;
    struct eventfd_ctx *log_ctx;

    struct vhost_poll poll;
    
    // The routine to call when the Guest pings us, or timeout
    void *handle_kick;  // vhost_work_fn_t
    
    // Last available index we saw
    u16 last_avail_idx;
    
    // Caches available index value from user
    u16 avail_idx;
    
    // Last index we used
    u16 last_used_idx;
    
    // Used flags
    u16 used_flags;
    
    // Last used index value we have signalled on
    u16 signalled_used;
    
    // Last used index value we have signalled on
    bool signalled_used_valid;
    
    // Log writes to used structure
    bool log_used;
    u64 log_addr;
    
    struct iovec iov[1024];        // UIO_MAXIOV = 1024
    struct iovec iotlb_iov[64];
    struct iovec *indirect;
    struct vring_used_elem *heads;
    
    // Protected by virtqueue mutex
    struct vhost_umem *umem;
    struct vhost_umem *iotlb;
    void *private_data;            // This is the socket pointer we need!
    u64 acked_features;
    u64 acked_backend_features;
    
    // Is this vq being used by a worker?
    bool is_le;
    
    // Eventfd file descriptor
    bool log_used_valid;
    
    // Last time we wrote to used flags
    u64 log_used_offset;
    
    // Used ring length
    u16 used_idx;
    
    // Used ring shadow
    u16 shadow_used_idx;
    
    // Callback to handle notifications
    int busyloop_timeout;
    
    // Callback to handle notifications
    struct task_struct *worker;
    
    // Memory mapping
    struct mm_struct *mm;
};

// Complete vhost_net structures from kernel headers
struct vhost_net_buf {
    void **queue;
    int tail;
    int head;
};

struct vhost_net_virtqueue {
    struct vhost_virtqueue vq;
    size_t vhost_hlen;
    size_t sock_hlen;
    
    // vhost zerocopy support fields
    int upend_idx;
    int done_idx;
    struct vhost_net_ubuf_ref *ubufs;
    struct ptr_ring *rx_ring;
    struct vhost_net_buf rxq;
};

#define VHOST_NET_VQ_MAX 2

struct vhost_net {
    struct vhost_dev dev;
    struct vhost_net_virtqueue vqs[VHOST_NET_VQ_MAX];
    struct vhost_poll poll[VHOST_NET_VQ_MAX];
    unsigned tx_packets;
    unsigned tx_zcopy_err;
    bool tx_flush;
};

// Key structure to track queue using sock pointer
struct queue_key {
    u64 sock_ptr;        // Unique sock pointer for this queue
    u32 queue_index;     // Queue index
    char dev_name[16];   // Device name
};



// Maps
BPF_HASH(target_queues, u64, struct queue_key, 256);  // Track target queue sock pointers
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);

// Per-queue last_used_idx value tracking
struct idx_value_key {
    u32 queue_index;
    char dev_name[16];
};
BPF_HASH(last_used_idx_values, struct idx_value_key, u16, 256);  // Track actual last_used_idx values
BPF_HASH(last_used_idx_counts, struct idx_value_key, u64, 256);  // Track how many times we've seen this queue

// NAPI status tracking
struct napi_status {
    bool napi_enabled;
    bool napi_frags_enabled;
};
BPF_HASH(napi_status_values, struct idx_value_key, struct napi_status, 256);  // Track NAPI status per queue

// Histograms for statistics - only vhost_signal stats
BPF_HISTOGRAM(vq_last_used_idx_vhost_signal, hist_key_t);      // last_used_idx value distribution at vhost_signal
BPF_HISTOGRAM(ptr_ring_depth_xmit, hist_key_t);       // PTR ring depth at tun_net_xmit

// Device filter logic - fixed to use bpf_probe_read_kernel like iface_netstat.c
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname = {};  // Initialize to zero
    bpf_probe_read_kernel(&real_devname, IFNAMSIZ, dev->name);  // Read full 16 bytes

    int key=0;
    union name_buf *leaf = name_map.lookup(&key);
    if(!leaf){
        return 1;  // No filter set - accept all devices
    }
    if(leaf->name_int.hi == 0 && leaf->name_int.lo == 0){
        return 1;  // Empty filter - accept all devices
    }
    if(leaf->name_int.hi != real_devname.name_int.hi || leaf->name_int.lo != real_devname.name_int.lo){
        return 0;  // Device name doesn't match
    }
    return 1;  // Device name matches
}

// Extract ptr_ring state using proven member_read approach from tun_ring_monitor.py
static inline u32 get_ptr_ring_depth(struct tun_file *tfile) {
    if (!tfile) return 0;
    
    struct ptr_ring *tx_ring = &tfile->tx_ring;
    
    u32 producer, consumer_head, consumer_tail, size;
    
    member_read(&producer, tx_ring, producer);
    member_read(&consumer_head, tx_ring, consumer_head);
    member_read(&consumer_tail, tx_ring, consumer_tail);
    member_read(&size, tx_ring, size);
    
    if (size == 0) return 0;
    
    // Calculate ring utilization
    u32 used;
    if (producer >= consumer_tail) {
        used = producer - consumer_tail;
    } else {
        used = size - consumer_tail + producer;
    }
    
    return used;
}

// Stage 1: tun_net_xmit - Track PTR ring depth
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !dev) return 0;
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    // Get queue index from skb
    u32 queue_index = skb->queue_mapping;
    
    // Check queue filter
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;  // Not our target queue
        }
    }
    
    // Get TUN structure using proven approach from tun_ring_monitor.py
    u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    struct tun_struct *tun = (struct tun_struct *)((char *)dev + aligned_size);
    
    u32 tun_numqueues = 0;
    READ_FIELD(&tun_numqueues, tun, numqueues);
    
    if (queue_index >= tun_numqueues || queue_index >= 256) {
        return 0;
    }
    
    // Get tfile for this queue
    struct tun_file *tfile = NULL;
    if (queue_index < tun_numqueues && tun_numqueues > 0 && queue_index < 256) {
        // Access tun->tfiles[queue_index] - tfiles array starts at offset 0 of tun_struct
        void **tfile_ptr_addr = (void**)((char*)tun + offsetof(struct tun_struct, tfiles) + queue_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL;
        }
    }
    if (!tfile) {
        return 0;
    }
    
    // Get socket pointer from tfile
    u64 sock_ptr = (u64)&tfile->socket;
    
    // Track this queue's sock pointer
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_index;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), dev->name);
    target_queues.update(&sock_ptr, &qkey);
    
    // Get NAPI status from tfile
    bool napi_enabled = false;
    bool napi_frags_enabled = false;
    READ_FIELD(&napi_enabled, tfile, napi_enabled);
    READ_FIELD(&napi_frags_enabled, tfile, napi_frags_enabled);
    
    // Store NAPI status
    struct idx_value_key napi_key = {};
    napi_key.queue_index = queue_index;
    bpf_probe_read_kernel_str(napi_key.dev_name, sizeof(napi_key.dev_name), dev->name);
    
    struct napi_status napi_status = {};
    napi_status.napi_enabled = napi_enabled;
    napi_status.napi_frags_enabled = napi_frags_enabled;
    napi_status_values.update(&napi_key, &napi_status);
    
    // Get PTR ring depth and record in histogram
    u32 depth = get_ptr_ring_depth(tfile);
    hist_key_t hist_key = {};
    hist_key.queue_index = queue_index;
    bpf_probe_read_kernel_str(hist_key.dev_name, sizeof(hist_key.dev_name), dev->name);
    
    // Handle depth=0 case properly - bpf_log2l(0) returns a large value
    if (depth == 0) {
        hist_key.slot = 0;  // Put 0 in slot 0
    } else {
        hist_key.slot = bpf_log2l(depth);  // Use log2 scale for histogram
    }
    
    ptr_ring_depth_xmit.increment(hist_key);
    
    return 0;
}

// Stage 2: vhost_signal - Track VQ state at signal time
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    
    if (!vq) return 0;
    
    // Get sock pointer from private_data using READ_FIELD  
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Get VQ indices for statistics
    u16 last_used_idx;
    READ_FIELD(&last_used_idx, vq, last_used_idx);
    
    // Record in histograms for vhost_signal
    hist_key_t hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    
    // VQ last_used_idx value histogram at vhost_signal
    // Use log2 scale for histogram compatibility
    // Force proper 0 handling since bpf_log2l(0) returns anomalous values
    if (last_used_idx == 0 || last_used_idx > 65535) {
        hist_key.slot = 0;  // Handle 0 and any anomalous values
    } else if (last_used_idx == 1) {
        hist_key.slot = 0;  // log2(1) = 0
    } else {
        u64 log_result = bpf_log2l(last_used_idx);
        hist_key.slot = (log_result > 15) ? 15 : log_result;  // Cap at slot 15
    }
    vq_last_used_idx_vhost_signal.increment(hist_key);
    
    // Track actual last_used_idx values for periodic display
    struct idx_value_key idx_key = {};
    idx_key.queue_index = qkey->queue_index;
    __builtin_memcpy(idx_key.dev_name, qkey->dev_name, sizeof(idx_key.dev_name));
    
    // Update the current last_used_idx value for this queue
    last_used_idx_values.update(&idx_key, &last_used_idx);
    
    // Increment count for this queue
    u64 *count = last_used_idx_counts.lookup(&idx_key);
    if (count) {
        (*count)++;
    } else {
        u64 init_count = 1;
        last_used_idx_counts.update(&idx_key, &init_count);
    }
    
    return 0;
}
"""

def print_histogram(hist_table, unit):
    """Print histogram with queue information"""
    if len(hist_table) == 0:
        print("    No data")
        return
    
    # Group by queue and device - kernel filtering already applied
    queue_data = {}
    for k, v in hist_table.items():
        dev_name = k.dev_name.decode('utf-8', 'replace')
        queue_index = k.queue_index
        queue_key = "{}:q{}".format(dev_name, queue_index)
        if queue_key not in queue_data:
            queue_data[queue_key] = {}
        slot = k.slot
        queue_data[queue_key][slot] = v.value
    
    for queue_name in sorted(queue_data.keys()):
        print("  Queue: {}".format(queue_name))
        slots = queue_data[queue_name]
        if not slots:
            print("    No data")
            continue
            
        max_slot = max(slots.keys())
        total_count = sum(slots.values())
        
        print("    Total: {}".format(total_count))
        
        # For last_used_idx histograms, show actual value ranges
        if "last_used_idx" in unit:
            min_slot = min(slots.keys())
            if min_slot == 0 and len(slots) > 1:
                actual_min_slot = min(s for s in slots.keys() if s > 0)
                min_val = 1 << actual_min_slot
            elif min_slot == 0:
                min_val = 0
            else:
                min_val = 1 << min_slot
            
            if max_slot > 15:  # u16 max should be slot 15
                max_val = 65535  # Cap at u16 max
                print("    WARNING: Detected slot {} (>15), capping display at u16 max".format(max_slot))
            else:
                max_val = min(65535, (1 << (max_slot + 1)) - 1)
            
            print("    Actual value range in this period: {} - {}".format(min_val, max_val))
        
        for slot in range(max_slot + 1):
            count = slots.get(slot, 0)
            if count > 0:
                if slot > 15:  # Beyond u16 range, show as anomaly
                    range_str = "ANOMALY-{}".format(slot)
                elif slot == 0:
                    range_str = "0-1"
                else:
                    low = 1 << slot
                    high = min(65535, (1 << (slot + 1)) - 1)  # Cap at u16 max
                    range_str = "{}-{}".format(low, high)
                
                pct = (count * 100) // total_count if total_count > 0 else 0
                print("    {:>10} : {:>8} ({}%)".format(range_str, count, pct))


def main():
    parser = argparse.ArgumentParser(
        description="Simple VHOST-NET Queue Monitor - tracks tun_net_xmit and vhost_signal only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all queues with 1-second interval
  sudo %(prog)s
  
  # Monitor specific device with 5-second interval
  sudo %(prog)s --device vnet33 --interval 5
  
  # Monitor specific device and queue with 10 outputs
  sudo %(prog)s --device vnet33 --queue 0 --interval 1 10
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet33)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--interval", "-i", type=int, default=1, help="Output interval in seconds (default: 1)")
    parser.add_argument("outputs", nargs="?", type=int, default=99999999, help="Number of outputs (default: unlimited)")
    parser.add_argument("--timestamp", "-T", action="store_true", help="Include timestamp on output")
    
    args = parser.parse_args()
    countdown = args.outputs

    # Detect kernel version, distro and find functions dynamically
    kernel_5x = needs_5x_vhost_layout()
    major, minor = get_kernel_version()
    distro = get_distro_id()
    print("Kernel version: {}.{}, Distro: {} (5.x vhost layout: {})".format(major, minor, distro, kernel_5x))

    # Find vhost_add_used_and_signal_n function (handles module symbols and GCC suffixes)
    vhost_signal_func = find_kernel_function("vhost_add_used_and_signal_n", verbose=True)
    if vhost_signal_func:
        print("Found vhost signal function: {}".format(vhost_signal_func))
    else:
        print("Warning: vhost_add_used_and_signal_n not found, signal stats will be unavailable")

    # Load BPF program with kernel version defines
    try:
        bpf_program = bpf_text
        defines = []
        if kernel_5x:
            defines.append("#define KERNEL_VERSION_5X 1")

        if defines:
            bpf_program = "\n".join(defines) + "\n" + bpf_program

        b = BPF(text=bpf_program)

        # Attach kprobes - only tun_net_xmit and vhost_signal
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")

        # Attach vhost_add_used_and_signal_n with dynamic function name
        vhost_signal_attached = False
        if vhost_signal_func:
            try:
                b.attach_kprobe(event=vhost_signal_func, fn_name="trace_vhost_signal")
                vhost_signal_attached = True
                print("Attached to {}".format(vhost_signal_func))
            except Exception as e:
                print("Warning: Failed to attach to {}: {}".format(vhost_signal_func, e))

        if not vhost_signal_attached:
            print("Warning: vhost_signal probe not attached, signal stats will be unavailable")

    except Exception as e:
        print("Failed to load BPF program: {}".format(e))
        return
    
    devname_map = b["name_map"]
    _name = Devname()
    if args.device:
        _name.name = args.device.encode()
        devname_map[0] = _name
        print("Device filter: {}".format(args.device))
    else:
        _name.name = b""
        devname_map[0] = _name
        print("Device filter: All TUN devices")
    
    if args.queue is not None:
        b["filter_enabled"][0] = ct.c_uint32(1)
        b["filter_queue"][0] = ct.c_uint32(args.queue)
        print("Queue filter: {}".format(args.queue))
    else:
        b["filter_enabled"][0] = ct.c_uint32(0)
        print("Queue filter: All queues")
    
    print("Simple VHOST-NET Queue Monitor Started")
    print("Tracking: tun_net_xmit and vhost_signal only")
    print("Interval: {}s | Outputs: {}".format(args.interval, "unlimited" if args.outputs == 99999999 else args.outputs))
    print("Collecting statistics... Press Ctrl+C to stop\n")
    
    # Clear maps to avoid stale entries - CRITICAL for correct filtering
    target_queues_map = b["target_queues"]
    
    print("Clearing all maps to ensure clean state...")
    target_queues_map.clear()
    
    # Also clear histogram maps to ensure clean start
    vq_last_used_idx_vhost_signal = b.get_table("vq_last_used_idx_vhost_signal")
    ptr_xmit = b.get_table("ptr_ring_depth_xmit")
    last_used_idx_values = b.get_table("last_used_idx_values")
    last_used_idx_counts = b.get_table("last_used_idx_counts")
    napi_status_values = b.get_table("napi_status_values")
    
    vq_last_used_idx_vhost_signal.clear()
    ptr_xmit.clear()
    last_used_idx_values.clear()
    last_used_idx_counts.clear()
    napi_status_values.clear()
    
    print("All maps cleared.")
    
    exiting = 0
    try:
        while countdown > 0:
            try:
                sleep(args.interval)
            except KeyboardInterrupt:
                exiting = 1
            
            print("\n" + "="*80)
            if args.timestamp:
                import datetime
                now = datetime.datetime.now()
                print("Time: {}".format(now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]))
            
            # Print VQ last_used_idx values for this period
            print("\nVQ last_used_idx Values at vhost_signal (this period):")
            print("Shows actual last_used_idx values when VHOST signals guest")
            if len(last_used_idx_values) == 0:
                print("    No data")
            else:
                # Group by queue and device
                queue_data = {}
                for k, v in last_used_idx_values.items():
                    dev_name = k.dev_name.decode('utf-8', 'replace')
                    queue_index = k.queue_index
                    queue_key = "{}:q{}".format(dev_name, queue_index)
                    queue_data[queue_key] = v.value
                
                for queue_name in sorted(queue_data.keys()):
                    idx_value = queue_data[queue_name]
                    # Get call count for this queue
                    call_count = 0
                    for k, v in last_used_idx_counts.items():
                        dev_name = k.dev_name.decode('utf-8', 'replace')
                        queue_index = k.queue_index
                        q_key = "{}:q{}".format(dev_name, queue_index)
                        if q_key == queue_name:
                            call_count = v.value
                            break
                    # Get napi_enabled status for this queue's tfile
                    napi_enabled_status = "N/A"
                    napi_frags_enabled_status = "N/A"
                    
                    # Find the NAPI status for this queue
                    for k, v in napi_status_values.items():
                        napi_dev_name = k.dev_name.decode('utf-8', 'replace')
                        napi_queue_index = k.queue_index
                        napi_queue_name = "{}:q{}".format(napi_dev_name, napi_queue_index)
                        if napi_queue_name == queue_name:
                            napi_enabled_status = "True" if v.napi_enabled else "False"
                            napi_frags_enabled_status = "True" if v.napi_frags_enabled else "False"
                            break
                    
                    print("  Queue: {} | last_used_idx: {} | calls: {} | napi_enabled: {} | napi_frags_enabled: {}".format(
                        queue_name, idx_value, call_count, napi_enabled_status, napi_frags_enabled_status))
            
            # Print VQ last_used_idx Value Distribution from vhost_signal
            print("\nVQ last_used_idx Value Distribution at vhost_signal:")
            print("Shows last_used_idx value ranges when VHOST signals guest")
            print_histogram(vq_last_used_idx_vhost_signal, "last_used_idx")
            
            # Print PTR Ring Depth at tun_net_xmit
            print("\nPTR Ring Depth Distribution at tun_net_xmit:")
            print("Shows ring buffer utilization when packets are transmitted")
            print_histogram(ptr_xmit, "entries")
            
            # Clear histograms for next interval
            vq_last_used_idx_vhost_signal.clear()
            ptr_xmit.clear()
            last_used_idx_values.clear()
            last_used_idx_counts.clear()
            napi_status_values.clear()
            
            countdown -= 1
            if exiting:
                break
                
    except KeyboardInterrupt:
        pass
    
    print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()