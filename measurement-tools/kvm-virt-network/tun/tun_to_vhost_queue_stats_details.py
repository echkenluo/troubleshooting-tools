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

def is_kernel_5x_or_later():
    """
    Check if kernel is 5.x or later.
    vhost_vring_call structure changed in kernel 5.x (call_ctx became a struct).
    """
    major, minor = get_kernel_version()
    return major >= 5

# BPF program for queue statistics using histograms
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

// DEBUG_ENABLED controls debug instrumentation compilation
// Set via Python based on --debug flag
#ifndef DEBUG_ENABLED
#define DEBUG_ENABLED 0
#endif

#if DEBUG_ENABLED
// Debug framework - stage_id + code_point encoding
BPF_HISTOGRAM(debug_stage_stats, u32);

static __always_inline void debug_inc(u8 stage_id, u8 code_point) {
    u32 key = ((u32)stage_id << 8) | code_point;
    debug_stage_stats.increment(key);
}
#else
// No-op when debug disabled
#define debug_inc(stage_id, code_point) do {} while(0)
#endif

// Stage IDs
#define STAGE_TUN_XMIT      0
#define STAGE_HANDLE_RX     1
#define STAGE_TUN_RECVMSG   2
#define STAGE_VHOST_SIGNAL  3

// Code points
#define CODE_PROBE_ENTRY        1
#define CODE_NULL_CHECK_FAIL    2
#define CODE_SOCK_LOOKUP        3
#define CODE_SOCK_FOUND         4
#define CODE_SOCK_NOT_FOUND     5
#define CODE_VQ_READ            6
#define CODE_HISTOGRAM_UPDATE   7

#if DEBUG_ENABLED
// Debug: track sock pointers seen in handle_rx
BPF_HASH(debug_handle_rx_socks, u64, u64, 256);  // sock_ptr -> count
BPF_HASH(debug_vq_ptrs, u64, u64, 256);  // vq_ptr -> private_data
BPF_HASH(debug_signal_vq_ptrs, u64, u64, 256);  // vq_ptr -> private_data from vhost_signal
#endif

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

// Signal idx frequency tracking key structure
struct idx_freq_key {
    u64 sock_ptr;       // Queue identifier
    u16 last_used_idx;  // The idx value
};

// Maps
BPF_HASH(target_queues, u64, struct queue_key, 256);  // Track target queue sock pointers
BPF_HASH(handle_rx_vqs, u64, u64, 256);  // Track handle_rx VQ pointers for signal filtering
BPF_HASH(signal_idx_freq, struct idx_freq_key, u32, 8192);  // Track idx frequency per queue (increased size)
BPF_HASH(signal_total_count, u64, u32, 256);  // Track total signal count per sock_ptr for verification
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);

// Histograms for statistics
BPF_HISTOGRAM(vq_consumption_progress_handle_rx, hist_key_t);    // avail_idx - last_avail_idx at handle_rx
BPF_HISTOGRAM(vq_processing_delay_handle_rx, hist_key_t);       // last_avail_idx - last_used_idx at handle_rx
BPF_HISTOGRAM(vq_consumption_progress_vhost_signal, hist_key_t); // avail_idx - last_avail_idx at vhost_signal  
BPF_HISTOGRAM(vq_processing_delay_vhost_signal, hist_key_t);    // last_avail_idx - last_used_idx at vhost_signal
BPF_HISTOGRAM(vq_last_used_idx_handle_rx, hist_key_t);         // last_used_idx value distribution at handle_rx
BPF_HISTOGRAM(vq_last_used_idx_vhost_signal, hist_key_t);      // last_used_idx value distribution at vhost_signal
// Remove old duplicate signal count histogram
BPF_HISTOGRAM(ptr_ring_depth_xmit, hist_key_t);       // PTR ring depth at tun_net_xmit
BPF_HISTOGRAM(ptr_ring_depth_recv, hist_key_t);       // PTR ring depth at tun_recvmsg

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

// Check if this sock pointer belongs to our target queue
static inline int is_target_queue_sock(u64 sock_ptr) {
    struct queue_key *key = target_queues.lookup(&sock_ptr);
    return key ? 1 : 0;
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

#if DEBUG_ENABLED
// Debug: track computed offsets
BPF_HASH(debug_handle_rx_net_ptrs, u64, u64, 64);  // net_ptr -> vq_ptr computed
#endif

// Stage 2: handle_rx - Track VQ state
int trace_handle_rx(struct pt_regs *ctx) {
    debug_inc(STAGE_HANDLE_RX, CODE_PROBE_ENTRY);

    struct vhost_net *net = (struct vhost_net *)PT_REGS_PARM1(ctx);
    if (!net) {
        debug_inc(STAGE_HANDLE_RX, CODE_NULL_CHECK_FAIL);
        return 0;
    }

    // Get RX virtqueue (vqs[0].vq) using member_read
    struct vhost_net_virtqueue *nvq = &net->vqs[0];
    struct vhost_virtqueue *vq = &nvq->vq;

#if DEBUG_ENABLED
    // Debug: track net pointer and computed VQ pointer
    u64 net_ptr_val = (u64)net;
    u64 vq_ptr_val = (u64)vq;
    debug_handle_rx_net_ptrs.update(&net_ptr_val, &vq_ptr_val);
#endif

    // Get VQ pointer and its private_data
    u64 vq_ptr = (u64)vq;
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    u64 pd_val = (u64)private_data;

#if DEBUG_ENABLED
    // Debug: track VQ pointer and its private_data
    debug_vq_ptrs.update(&vq_ptr, &pd_val);
#endif

    u64 sock_ptr = pd_val;
    debug_inc(STAGE_HANDLE_RX, CODE_SOCK_LOOKUP);

#if DEBUG_ENABLED
    // Debug: track this sock pointer
    u64 one = 1;
    u64 *cnt = debug_handle_rx_socks.lookup(&sock_ptr);
    if (cnt) {
        (*cnt)++;
    } else {
        debug_handle_rx_socks.update(&sock_ptr, &one);
    }
#endif

    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        debug_inc(STAGE_HANDLE_RX, CODE_SOCK_NOT_FOUND);
        return 0;  // Not our target queue
    }
    debug_inc(STAGE_HANDLE_RX, CODE_SOCK_FOUND);

    // Track this VQ for signal filtering
    u64 vq_addr = (u64)vq;
    handle_rx_vqs.update(&sock_ptr, &vq_addr);
    
    // Get VQ indices
    u16 last_avail_idx, avail_idx, last_used_idx;
    READ_FIELD(&last_avail_idx, vq, last_avail_idx);
    READ_FIELD(&avail_idx, vq, avail_idx);
    READ_FIELD(&last_used_idx, vq, last_used_idx);
    
    // Calculate consumption progress (how much is available to consume)
    u16 consumption_progress = 0;
    if (avail_idx >= last_avail_idx) {
        consumption_progress = avail_idx - last_avail_idx;
    } else {
        // Handle wraparound - assuming 16-bit indices
        consumption_progress = (u16)(65536 + avail_idx - last_avail_idx);
    }
    
    // Calculate processing delay (how much is in-flight)
    u16 processing_delay = 0;
    if (last_avail_idx >= last_used_idx) {
        processing_delay = last_avail_idx - last_used_idx;
    } else {
        // Handle wraparound
        processing_delay = (u16)(65536 + last_avail_idx - last_used_idx);
    }
    
    // Record in histograms for handle_rx
    hist_key_t hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    
    // VQ consumption progress histogram at handle_rx
    hist_key.slot = bpf_log2l(consumption_progress);
    vq_consumption_progress_handle_rx.increment(hist_key);
    
    // VQ processing delay histogram at handle_rx
    hist_key.slot = bpf_log2l(processing_delay);
    vq_processing_delay_handle_rx.increment(hist_key);
    
    // VQ last_used_idx value histogram at handle_rx
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
    vq_last_used_idx_handle_rx.increment(hist_key);
    
    return 0;
}

// Stage 3: tun_recvmsg - Track PTR ring depth
int trace_tun_recvmsg_entry(struct pt_regs *ctx, struct socket *sock, struct msghdr *m, size_t total_len, int flags) {
    if (!sock) return 0;
    
    // Get tun_file from socket using proper calculation
    struct tun_file *tfile = (struct tun_file *)((char *)sock - offsetof(struct tun_file, socket));
    if (!tfile) return 0;
    
    // Get socket pointer directly from parameter
    u64 sock_ptr = (u64)sock;
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Get PTR ring depth and record in histogram
    u32 depth = get_ptr_ring_depth(tfile);
    hist_key_t hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    
    // Handle depth=0 case properly - bpf_log2l(0) returns a large value
    if (depth == 0) {
        hist_key.slot = 0;  // Put 0 in slot 0
    } else {
        hist_key.slot = bpf_log2l(depth);  // Use log2 scale for histogram
    }
    
    ptr_ring_depth_recv.increment(hist_key);
    
    return 0;
}

#if DEBUG_ENABLED
// Debug: track vhost_signal dev and vq pointers
BPF_HASH(debug_signal_dev_vq, u64, u64, 64);  // dev_ptr -> vq_ptr from vhost_signal
#endif

// Stage 4: vhost_signal - Track VQ state at signal time
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);

    if (!vq) return 0;

    debug_inc(STAGE_VHOST_SIGNAL, CODE_PROBE_ENTRY);

#if DEBUG_ENABLED
    // Debug: track dev and vq from signal
    u64 dev_ptr_val = (u64)dev;
    u64 vq_ptr_val = (u64)vq;
    debug_signal_dev_vq.update(&dev_ptr_val, &vq_ptr_val);
#endif

    // Get sock pointer from private_data using READ_FIELD
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);

    u64 sock_ptr = (u64)private_data;

#if DEBUG_ENABLED
    // Debug: track VQ pointer and its private_data in vhost_signal
    u64 vq_ptr = (u64)vq;
    debug_signal_vq_ptrs.update(&vq_ptr, &sock_ptr);
#endif
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Filter VQ: only allow signals from handle_rx VQs
    u64 expected_vq_addr = 0;
    u64 *expected_vq_ptr = handle_rx_vqs.lookup(&sock_ptr);
    if (expected_vq_ptr) {
        expected_vq_addr = *expected_vq_ptr;
    }
    
    u64 current_vq_addr = (u64)vq;
    if (expected_vq_addr != 0 && current_vq_addr != expected_vq_addr) {
        return 0;  // Filter out signals from different VQ (likely TX direction)
    }
    
    // Get VQ indices for additional statistics
    u16 last_avail_idx, avail_idx, last_used_idx;
    READ_FIELD(&last_avail_idx, vq, last_avail_idx);
    READ_FIELD(&avail_idx, vq, avail_idx);
    READ_FIELD(&last_used_idx, vq, last_used_idx);
    
    // Calculate consumption progress and processing delay at signal time
    u16 consumption_progress = 0;
    if (avail_idx >= last_avail_idx) {
        consumption_progress = avail_idx - last_avail_idx;
    } else {
        // Handle wraparound
        consumption_progress = (u16)(65536 + avail_idx - last_avail_idx);
    }
    
    u16 processing_delay = 0;
    if (last_avail_idx >= last_used_idx) {
        processing_delay = last_avail_idx - last_used_idx;
    } else {
        // Handle wraparound
        processing_delay = (u16)(65536 + last_avail_idx - last_used_idx);
    }
    
    // Record in histograms for vhost_signal
    hist_key_t hist_key = {};
    hist_key.queue_index = qkey->queue_index;
    __builtin_memcpy(hist_key.dev_name, qkey->dev_name, sizeof(hist_key.dev_name));
    
    // VQ consumption progress histogram at vhost_signal
    hist_key.slot = bpf_log2l(consumption_progress);
    vq_consumption_progress_vhost_signal.increment(hist_key);
    
    // VQ processing delay histogram at vhost_signal
    hist_key.slot = bpf_log2l(processing_delay);
    vq_processing_delay_vhost_signal.increment(hist_key);
    
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
    
    // Track total signal count per sock_ptr for verification
    u32 *total_count = signal_total_count.lookup(&sock_ptr);
    if (total_count) {
        (*total_count)++;
    } else {
        u32 init_total = 1;
        signal_total_count.update(&sock_ptr, &init_total);
    }
    
    // Track signal idx frequency - simple hash counting
    struct idx_freq_key freq_key = {};
    freq_key.sock_ptr = sock_ptr;
    freq_key.last_used_idx = last_used_idx;
    
    u32 *count = signal_idx_freq.lookup(&freq_key);
    if (count) {
        (*count)++;  // Increment existing count
    } else {
        u32 init_count = 1;
        signal_idx_freq.update(&freq_key, &init_count);  // Initialize to 1
    }
    
    return 0;
}
"""

def print_index_histogram(hist_table):
    """Print histogram for u16 index values (0-65535)"""
    if len(hist_table) == 0:
        print("    No data")
        return
    
    # Group by queue and device
    queue_data = {}
    for k, v in hist_table.items():
        dev_name = k.dev_name.decode('utf-8', 'replace')
        queue_index = k.queue_index
        queue_key = "{}:q{}".format(dev_name, queue_index)
        if queue_key not in queue_data:
            queue_data[queue_key] = {}
        slot = k.slot  # This is now the original u16 value (0-65535)
        queue_data[queue_key][slot] = v.value
    
    for queue_name in sorted(queue_data.keys()):
        print("  Queue: {}".format(queue_name))
        slots = queue_data[queue_name]
        if not slots:
            print("    No data")
            continue
            
        total_count = sum(slots.values())
        print("    Total: {} events".format(total_count))
        
        # Find min and max slot values (original u16 values)
        min_slot = min(slots.keys())
        max_slot = max(slots.keys())
        
        # Show distribution range for u16 values (0-65535)
        print("    Index value distribution (u16 range 0-65535):")
        print("    Min: {}, Max: {}, Range: {}".format(min_slot, max_slot, max_slot - min_slot))
        
        # Count how many index values appeared more than once (duplicates)
        duplicate_count = sum(1 for count in slots.values() if count > 1)
        unique_count = len(slots)
        print("    Unique indices: {}, Duplicate indices: {} ({:.1f}%)".format(
            unique_count, duplicate_count, 
            (duplicate_count * 100.0 / unique_count) if unique_count > 0 else 0))
        
        # Only show top list if there are duplicate indices
        if duplicate_count > 0:
            # Show top 20 most frequent values (focus on duplicates)
            sorted_slots = sorted(slots.items(), key=lambda x: x[1], reverse=True)[:20]
            print("    Top 20 most frequent index values:")
            for slot, count in sorted_slots:
                pct = (count * 100.0 / total_count) if total_count > 0 else 0
                status = "DUPLICATE" if count > 1 else "normal"
                print("      idx {:>5}: {:>3} times ({:>5.1f}%) [{}]".format(slot, count, pct, status))

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
        
        # For duplicate signals, show interpretation
        elif "duplicate_signals" in unit:
            max_duplicates = max_slot
            total_events = sum(slots.values())
            unique_idx_sequences = len([s for s in slots.keys() if slots[s] > 0])
            print("    Max consecutive duplicates: {} signals".format(max_duplicates))
            print("    Total duplicate events: {} (across {} different sequences)".format(total_events, unique_idx_sequences))
        
        for slot in range(max_slot + 1):
            count = slots.get(slot, 0)
            if count > 0:
                if "duplicate_signals" in unit:
                    # For duplicate signals, slot directly represents count
                    range_str = "{} repeats".format(slot)
                elif slot > 15:  # Beyond u16 range, show as anomaly
                    range_str = "ANOMALY-{}".format(slot)
                elif slot == 0:
                    range_str = "0-1"
                else:
                    low = 1 << slot
                    high = min(65535, (1 << (slot + 1)) - 1)  # Cap at u16 max
                    range_str = "{}-{}".format(low, high)
                
                pct = (count * 100) // total_count if total_count > 0 else 0
                print("    {:>10} : {:>8} ({}%)".format(range_str, count, pct))

def print_signal_idx_frequency(signal_freq_table, target_queues_map, signal_total_count_table):
    """Print top 10 most frequent last_used_idx values in vhost_signal"""
    if len(signal_freq_table) == 0:
        print("    No data")
        return
    
    # Build sock_ptr to queue info mapping
    sock_to_queue = {}
    for sock_ptr, qkey in target_queues_map.items():
        sock_to_queue[sock_ptr.value] = {
            'dev_name': qkey.dev_name.decode('utf-8', 'replace'),
            'queue_index': qkey.queue_index
        }
    
    # Get total count verification data
    total_count_verification = {}
    for sock_ptr, count in signal_total_count_table.items():
        total_count_verification[sock_ptr.value] = count.value
    
    # Group by queue (sock_ptr)
    queue_data = {}
    for k, v in signal_freq_table.items():
        sock_ptr = k.sock_ptr
        last_used_idx = k.last_used_idx
        count = v.value
        
        if sock_ptr not in queue_data:
            queue_data[sock_ptr] = {}
        queue_data[sock_ptr][last_used_idx] = count
    
    for sock_ptr in sorted(queue_data.keys()):
        idx_counts = queue_data[sock_ptr]
        if not idx_counts:
            continue
            
        # Sort by count (descending) and take top 10
        sorted_items = sorted(idx_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        total_signals = sum(idx_counts.values())
        unique_indices = len(idx_counts)
        
        # Get verification count
        verification_count = total_count_verification.get(sock_ptr, 0)
        
        # Get queue name from mapping
        if sock_ptr in sock_to_queue:
            qinfo = sock_to_queue[sock_ptr]
            queue_name = "{}:q{}".format(qinfo['dev_name'], qinfo['queue_index'])
            print("  Queue: {} (sock: 0x{:x})".format(queue_name, sock_ptr))
        else:
            print("  Sock: 0x{:x} (queue info not found)".format(sock_ptr))
            
        print("    Total signals: {} (verification: {}), Unique indices: {}".format(
            total_signals, verification_count, unique_indices))
        
        # Discrepancy check removed as requested
        
        if unique_indices < total_signals:
            duplicate_signals = total_signals - unique_indices
            print("    Duplicate signals: {} ({:.1f}%)".format(
                duplicate_signals, (duplicate_signals * 100.0 / total_signals)))
        
        print("    Top 10 most frequent last_used_idx values:")
        print("    {:>8} : {:>6} {:>7}".format("idx", "count", "percent"))
        print("    " + "-" * 23)
        
        for idx, count in sorted_items:
            pct = (count * 100.0 / total_signals) if total_signals > 0 else 0
            status = "DUP" if count > 1 else ""
            print("    {:>8} : {:>6} {:>6.1f}% {}".format(idx, count, pct, status))

def main():
    parser = argparse.ArgumentParser(
        description="VHOST-NET Queue Statistics Monitor with periodic distribution output",
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
    parser.add_argument("--debug", action="store_true", help="Enable debug output (sock pointers, VQ offsets)")
    
    args = parser.parse_args()
    countdown = args.outputs

    # Detect kernel version and find functions dynamically
    kernel_5x = is_kernel_5x_or_later()
    major, minor = get_kernel_version()
    print("Kernel version: {}.{} (5.x structure layout: {})".format(major, minor, kernel_5x))

    # Find vhost_add_used_and_signal_n function (handles module symbols and GCC suffixes)
    vhost_signal_func = find_kernel_function("vhost_add_used_and_signal_n", verbose=True)
    if vhost_signal_func:
        print("Found vhost signal function: {}".format(vhost_signal_func))
    else:
        print("Warning: vhost_add_used_and_signal_n not found, signal stats will be unavailable")

    # Find handle_rx function (in vhost_net module)
    handle_rx_func = find_kernel_function("handle_rx", verbose=True)
    if handle_rx_func:
        print("Found handle_rx function: {}".format(handle_rx_func))
    else:
        print("Warning: handle_rx not found, handle_rx stats will be unavailable")

    # Load BPF program with kernel version and debug defines
    try:
        bpf_program = bpf_text
        defines = []
        if kernel_5x:
            defines.append("#define KERNEL_VERSION_5X 1")
        if args.debug:
            defines.append("#define DEBUG_ENABLED 1")

        if defines:
            bpf_program = "\n".join(defines) + "\n" + bpf_program

        b = BPF(text=bpf_program)

        # Attach kprobes
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        b.attach_kprobe(event="tun_recvmsg", fn_name="trace_tun_recvmsg_entry")

        # Attach handle_rx with dynamic function name
        handle_rx_attached = False
        if handle_rx_func:
            try:
                b.attach_kprobe(event=handle_rx_func, fn_name="trace_handle_rx")
                handle_rx_attached = True
                print("Attached to {}".format(handle_rx_func))
            except Exception as e:
                print("Warning: Failed to attach to {}: {}".format(handle_rx_func, e))

        if not handle_rx_attached:
            print("Warning: handle_rx probe not attached, handle_rx stats will be unavailable")

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
    
    print("VHOST-NET Queue Statistics Monitor Started")
    print("Interval: {}s | Outputs: {}".format(args.interval, "unlimited" if args.outputs == 99999999 else args.outputs))
    print("Collecting statistics... Press Ctrl+C to stop\n")
    
    # Clear maps to avoid stale entries - CRITICAL for correct filtering
    target_queues_map = b["target_queues"]
    handle_rx_vqs_map = b["handle_rx_vqs"]
    signal_idx_freq_map = b["signal_idx_freq"]
    signal_total_count_map = b["signal_total_count"]
    
    print("Clearing all maps to ensure clean state...")
    target_queues_map.clear()
    handle_rx_vqs_map.clear()
    signal_idx_freq_map.clear()
    signal_total_count_map.clear()
    
    # Also clear histogram maps to ensure clean start
    vq_consumption_handle_rx = b.get_table("vq_consumption_progress_handle_rx")
    vq_delay_handle_rx = b.get_table("vq_processing_delay_handle_rx")
    vq_consumption_vhost_signal = b.get_table("vq_consumption_progress_vhost_signal")
    vq_delay_vhost_signal = b.get_table("vq_processing_delay_vhost_signal")
    vq_last_used_idx_handle_rx = b.get_table("vq_last_used_idx_handle_rx")
    vq_last_used_idx_vhost_signal = b.get_table("vq_last_used_idx_vhost_signal")
    ptr_xmit = b.get_table("ptr_ring_depth_xmit")
    ptr_recv = b.get_table("ptr_ring_depth_recv")
    
    vq_consumption_handle_rx.clear()
    vq_delay_handle_rx.clear()
    vq_consumption_vhost_signal.clear()
    vq_delay_vhost_signal.clear()
    vq_last_used_idx_handle_rx.clear()
    vq_last_used_idx_vhost_signal.clear()
    ptr_xmit.clear()
    ptr_recv.clear()
    
    print("All maps cleared.")
    
# Maps already obtained above
    
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

            # Print debug statistics (only with --debug flag)
            if args.debug:
                print("\n[DEBUG] Stage Statistics:")
                stage_names = {0: "TUN_XMIT", 1: "HANDLE_RX", 2: "TUN_RECVMSG", 3: "VHOST_SIGNAL"}
                code_names = {1: "PROBE_ENTRY", 2: "NULL_CHECK_FAIL", 3: "SOCK_LOOKUP",
                             4: "SOCK_FOUND", 5: "SOCK_NOT_FOUND", 6: "VQ_READ", 7: "HISTOGRAM_UPDATE"}
                debug_stats = b.get_table("debug_stage_stats")
                for k, v in sorted(debug_stats.items(), key=lambda x: x[0].value):
                    if v.value > 0:
                        stage_id = k.value >> 8
                        code_point = k.value & 0xFF
                        stage_name = stage_names.get(stage_id, "STAGE_%d" % stage_id)
                        code_name = code_names.get(code_point, "CODE_%d" % code_point)
                        print("  {}.{}: {}".format(stage_name, code_name, v.value))
                debug_stats.clear()

                print("\n[DEBUG] Sock Pointers from tun_net_xmit (target_queues):")
                for sock_ptr, qkey in target_queues_map.items():
                    print("  sock: 0x{:x} -> {}:q{}".format(sock_ptr.value,
                        qkey.dev_name.decode('utf-8', 'replace'), qkey.queue_index))

                print("\n[DEBUG] Sock Pointers from handle_rx (top 10):")
                debug_rx_socks = b.get_table("debug_handle_rx_socks")
                rx_socks = sorted(debug_rx_socks.items(), key=lambda x: x[1].value, reverse=True)[:10]
                for sock_ptr, cnt in rx_socks:
                    print("  sock: 0x{:x} -> count: {}".format(sock_ptr.value, cnt.value))
                debug_rx_socks.clear()

                print("\n[DEBUG] handle_rx net -> computed VQ (top 10):")
                debug_net_vq = b.get_table("debug_handle_rx_net_ptrs")
                net_vq_list = list(debug_net_vq.items())[:10]
                for net_ptr, vq_ptr in net_vq_list:
                    offset = vq_ptr.value - net_ptr.value if vq_ptr.value > net_ptr.value else 0
                    print("  net: 0x{:x} -> vq: 0x{:x} (offset: 0x{:x} = {} bytes)".format(
                        net_ptr.value, vq_ptr.value, offset, offset))
                debug_net_vq.clear()

                print("\n[DEBUG] VQ Pointers -> private_data (handle_rx, top 10):")
                debug_vq = b.get_table("debug_vq_ptrs")
                vq_list = list(debug_vq.items())[:10]
                for vq_ptr, pd in vq_list:
                    print("  vq: 0x{:x} -> private_data: 0x{:x}".format(vq_ptr.value, pd.value))
                debug_vq.clear()

                print("\n[DEBUG] vhost_signal dev -> VQ (top 10):")
                debug_dev_vq = b.get_table("debug_signal_dev_vq")
                dev_vq_list = list(debug_dev_vq.items())[:10]
                for dev_ptr, vq_ptr in dev_vq_list:
                    print("  dev: 0x{:x} -> vq: 0x{:x}".format(dev_ptr.value, vq_ptr.value))
                debug_dev_vq.clear()

                print("\n[DEBUG] VQ Pointers -> private_data (vhost_signal, top 10):")
                debug_signal_vq = b.get_table("debug_signal_vq_ptrs")
                signal_vq_list = list(debug_signal_vq.items())[:10]
                for vq_ptr, pd in signal_vq_list:
                    match_status = "MATCH" if any(sp.value == pd.value for sp in target_queues_map.keys()) else "NO MATCH"
                    print("  vq: 0x{:x} -> private_data: 0x{:x} [{}]".format(vq_ptr.value, pd.value, match_status))
                debug_signal_vq.clear()

            # Print VQ Consumption Progress Distribution from handle_rx
            print("\nVQ Consumption Progress Distribution at handle_rx (avail_idx - last_avail_idx):")
            print("Shows how many descriptors are available for consumption when VHOST handles RX")
            print_histogram(vq_consumption_handle_rx, "descriptors")
            
            # Print VQ Processing Delay Distribution from handle_rx
            print("\nVQ Processing Delay Distribution at handle_rx (last_avail_idx - last_used_idx):")
            print("Shows how many descriptors are in-flight when VHOST handles RX")
            print_histogram(vq_delay_handle_rx, "descriptors")
            
            # Print VQ Consumption Progress Distribution from vhost_signal
            print("\nVQ Consumption Progress Distribution at vhost_signal (avail_idx - last_avail_idx):")
            print("Shows how many descriptors are available for consumption when VHOST signals guest")
            print_histogram(vq_consumption_vhost_signal, "descriptors")
            
            # Print VQ Processing Delay Distribution from vhost_signal
            print("\nVQ Processing Delay Distribution at vhost_signal (last_avail_idx - last_used_idx):")
            print("Shows how many descriptors are in-flight when VHOST signals guest")
            print_histogram(vq_delay_vhost_signal, "descriptors")
            
            # Print VQ last_used_idx Value Distribution from handle_rx
            print("\nVQ last_used_idx Value Distribution at handle_rx:")
            print("Shows last_used_idx value ranges when VHOST handles RX")
            print_histogram(vq_last_used_idx_handle_rx, "last_used_idx")
            
            # Print VQ last_used_idx Value Distribution from vhost_signal
            print("\nVQ last_used_idx Value Distribution at vhost_signal:")
            print("Shows last_used_idx value ranges when VHOST signals guest")
            print_histogram(vq_last_used_idx_vhost_signal, "last_used_idx")
            
            # Print Signal Index Frequency Analysis
            print("\nSignal Index Frequency Analysis at vhost_signal:")
            print("Shows most frequently used last_used_idx values and their call counts")
            print_signal_idx_frequency(signal_idx_freq_map, target_queues_map, signal_total_count_map)
            
            # Print PTR Ring Depth at tun_net_xmit
            print("\nPTR Ring Depth Distribution at tun_net_xmit:")
            print("Shows ring buffer utilization when packets are transmitted")
            print_histogram(ptr_xmit, "entries")
            
            # Print PTR Ring Depth at tun_recvmsg
            print("\nPTR Ring Depth Distribution at tun_recvmsg:")
            print("Shows ring buffer utilization when packets are received")
            print_histogram(ptr_recv, "entries")
            
            # Clear histograms for next interval
            vq_consumption_handle_rx.clear()
            vq_delay_handle_rx.clear()
            vq_consumption_vhost_signal.clear()
            vq_delay_vhost_signal.clear()
            vq_last_used_idx_handle_rx.clear()
            vq_last_used_idx_vhost_signal.clear()
            signal_idx_freq_map.clear()  # Clear frequency map each cycle
            signal_total_count_map.clear()  # Clear verification map each cycle
            ptr_xmit.clear()
            ptr_recv.clear()
            
            countdown -= 1
            if exiting:
                break
                
    except KeyboardInterrupt:
        pass
    
    print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()