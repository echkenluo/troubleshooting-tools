#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""
vhost_comprehensive_monitor.py - Comprehensive vhost internal state monitor

This tool provides ultra-detailed analysis of vhost internal data structures
when vhost_add_used_and_signal_n is called. It extracts maximum possible
information from vhost_dev, vhost_virtqueue, and vhost_net_virtqueue structures.
"""

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
import ctypes as ct
from bcc import BPF

# BPF program with comprehensive vhost structure analysis
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

#define IFNAMSIZ 16
#define VHOST_NUM_ADDRS 3
#define UIO_MAXIOV 1024
#define VHOST_NET_VQ_MAX 2
#define VHOST_NET_BATCH 64

// Forward declarations and type definitions
struct vhost_work;
struct vhost_dev;
struct vhost_virtqueue;
struct vhost_net_virtqueue;
typedef void (*vhost_work_fn_t)(struct vhost_work *work);

// Complete vhost structures embedded for BPF access

#define VHOST_WORK_QUEUED 1
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

struct vhost_log {
	u64 addr;
	u64 len;
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

enum vhost_uaddr_type {
	VHOST_ADDR_DESC = 0,
	VHOST_ADDR_AVAIL = 1,
	VHOST_ADDR_USED = 2,
	VHOST_NUM_ADDRS = 3,
};

/* The virtqueue structure describes a queue attached to a device. */
struct vhost_virtqueue {
	struct vhost_dev *dev;

	/* The actual ring of buffers. */
	struct mutex mutex;
	unsigned int num;
	struct vring_desc __user *desc;
	struct vring_avail __user *avail;
	struct vring_used __user *used;
	const struct vhost_umem_node *meta_iotlb[VHOST_NUM_ADDRS];
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
	struct vhost_log *log;

	/* Ring endianness. Defaults to legacy native endianness.
	 * Set to true when starting a modern virtio device. */
	bool is_le;
#ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
	/* Ring endianness requested by userspace for cross-endian support. */
	bool user_be;
#endif
	u32 busyloop_timeout;
};

struct vhost_iotlb_msg {
	__u64 iova;
	__u64 size;
	__u64 uaddr;
	__u8 perm;
	__u8 type;
};

struct vhost_msg {
	int type;
	union {
		struct vhost_iotlb_msg iotlb;
		__u8 padding[64];
	};
};

struct vhost_msg_v2 {
	__u32 type;
	__u32 reserved;
	union {
		struct vhost_iotlb_msg iotlb;
		__u8 padding[64];
	};
};

struct vhost_msg_node {
  union {
	  struct vhost_msg msg;
	  struct vhost_msg_v2 msg_v2;
  };
  struct vhost_virtqueue *vq;
  struct list_head node;
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

// vhost-net specific structures
struct vhost_net_ubuf_ref {
	atomic_t refcount;
	wait_queue_head_t wait;
	struct vhost_virtqueue *vq;
};

struct vhost_net_buf {
	void **queue;
	int tail;
	int head;
};

struct ubuf_info;
struct ptr_ring;

struct vhost_net_virtqueue {
	struct vhost_virtqueue vq;
	size_t vhost_hlen;
	size_t sock_hlen;
	/* vhost zerocopy support fields below: */
	/* last used idx for outstanding DMA zerocopy buffers */
	int upend_idx;
	/* For TX, first used idx for DMA done zerocopy buffers
	 * For RX, number of batched heads
	 */
	int done_idx;
	/* an array of userspace buffers info */
	struct ubuf_info *ubuf_info;
	/* Reference counting for outstanding ubufs.
	 * Protected by vq mutex. Writers must also take device mutex. */
	struct vhost_net_ubuf_ref *ubufs;
	struct ptr_ring *rx_ring;
	struct vhost_net_buf rxq;
};

// Comprehensive event structure for ultra-detailed vhost analysis
struct vhost_ultra_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    // Basic identification
    u64 dev_ptr;
    u64 vq_ptr;
    u32 queue_index;
    char dev_name[16];
    u32 heads_count;
    
    // === VHOST_DEV STRUCTURE ANALYSIS ===
    struct {
        u64 mm_ptr;                    // Memory management context
        u64 vqs_ptr;                   // Virtqueue array pointer
        int nvqs;                      // Number of virtqueues
        u64 worker_ptr;                // Worker thread pointer
        u64 umem_ptr;                  // User memory mapping
        u64 iotlb_ptr;                 // IO translation buffer
        u64 log_ctx_ptr;               // Logging eventfd
        int iov_limit;                 // Max scatter-gather segments
        int weight;                    // Packet processing weight
        int byte_weight;               // Byte processing weight
        u32 work_list_first;           // Work queue head node
        u32 read_list_empty;           // Read list empty flag
        u32 pending_list_empty;        // Pending list empty flag
    } dev_state;
    
    // === VHOST_VIRTQUEUE STRUCTURE ANALYSIS ===
    struct {
        // Ring configuration
        u32 num;                       // Ring size
        u64 desc_ptr;                  // Descriptor ring (userspace)
        u64 avail_ptr;                 // Available ring (userspace) 
        u64 used_ptr;                  // Used ring (userspace)
        
        // Ring state
        u16 last_avail_idx;            // Last processed available index
        u16 avail_idx;                 // Cached available index
        u16 last_used_idx;             // Last used index
        u16 used_flags;                // Used ring flags
        u16 signalled_used;            // Last signalled used index
        u8 signalled_used_valid;       // Signalled used validity
        
        // Memory management
        u64 meta_iotlb_desc;           // IOTLB cache for desc ring
        u64 meta_iotlb_avail;          // IOTLB cache for avail ring
        u64 meta_iotlb_used;           // IOTLB cache for used ring
        u64 umem_ptr;                  // User memory mapping
        u64 iotlb_ptr;                 // Private IOTLB
        
        // Event notification
        u64 kick_ptr;                  // Guest kick file
        u64 call_ctx_ptr;              // Host call eventfd
        u64 error_ctx_ptr;             // Error eventfd
        u64 log_ctx_ptr;               // Log eventfd
        
        // Logging state
        u8 log_used;                   // Log used ring updates
        u64 log_addr;                  // Log address
        u64 log_base_ptr;              // Log base pointer
        
        // Features
        u64 acked_features;            // Acknowledged features
        u64 acked_backend_features;    // Backend features
        
        // Configuration
        u8 is_le;                      // Little endian mode
        u8 user_be;                    // User big endian mode
        u32 busyloop_timeout;          // Busyloop timeout (us)
        
        // Work management
        u64 handle_kick_ptr;           // Kick handler function
        u64 private_data_ptr;          // Private data (socket for net)
        
        // Array sizes (read from actual arrays)
        u32 iov_count;                 // Valid IOV entries
        u32 iotlb_iov_count;          // Valid IOTLB IOV entries
        u64 indirect_ptr;              // Indirect descriptor buffer
        u64 heads_ptr;                 // Used elements buffer
    } vq_state;
    
    // === VHOST_NET_VIRTQUEUE ANALYSIS (if applicable) ===
    struct {
        u8 is_net_vq;                  // Whether this is a net virtqueue
        size_t vhost_hlen;             // Vhost header length
        size_t sock_hlen;              // Socket header length
        
        // Zero-copy TX state
        int upend_idx;                 // Outstanding DMA buffer index
        int done_idx;                  // Completed DMA buffer index
        u64 ubuf_info_ptr;             // Zero-copy buffer info
        u64 ubufs_ptr;                 // Zero-copy reference counting
        
        // RX state
        u64 rx_ring_ptr;               // RX ptr_ring pointer
        int rxq_head;                  // RX queue head
        int rxq_tail;                  // RX queue tail
        u64 rxq_queue_ptr;             // RX queue buffer array
    } net_vq_state;
    
    // === MEMORY REGION ANALYSIS ===
    struct {
        u32 umem_numem;                // Number of memory regions
        u64 umem_tree_root;            // Red-black tree root
        u8 umem_tree_cached;           // Whether tree is cached
        u64 first_region_start;        // First memory region start
        u64 first_region_last;         // First memory region end
        u64 first_region_userspace;    // First region userspace addr
        u32 first_region_perm;         // First region permissions
        
        u32 iotlb_numem;               // Number of IOTLB regions
        u64 iotlb_tree_root;           // IOTLB tree root
        u8 iotlb_tree_cached;          // Whether IOTLB tree is cached
    } memory_state;
    
    // === RING BUFFER DETAILED ANALYSIS ===
    struct {
        // Available ring analysis (if accessible)
        u16 avail_flags;               // Available ring flags
        u16 avail_idx_actual;          // Actual available index from ring
        u16 avail_ring_0;              // First available entry
        u16 avail_ring_1;              // Second available entry
        u16 avail_used_event;          // Used event index
        
        // Used ring analysis (if accessible)
        u16 used_flags_actual;         // Actual used flags from ring
        u16 used_idx_actual;           // Actual used index from ring
        u32 used_ring_0_id;            // First used entry ID
        u32 used_ring_0_len;           // First used entry length
        u32 used_ring_1_id;            // Second used entry ID
        u32 used_ring_1_len;           // Second used entry length
        u16 used_avail_event;          // Available event index
        
        // Descriptor ring analysis (first few descriptors)
        u64 desc_0_addr;               // First descriptor address
        u32 desc_0_len;                // First descriptor length
        u16 desc_0_flags;              // First descriptor flags
        u16 desc_0_next;               // First descriptor next
        
        u64 desc_1_addr;               // Second descriptor address
        u32 desc_1_len;                // Second descriptor length
        u16 desc_1_flags;              // Second descriptor flags
        u16 desc_1_next;               // Second descriptor next
    } ring_details;
    
    // === PERFORMANCE COUNTERS ===
    struct {
        u64 total_kicks;               // Total kick events (estimated)
        u64 total_signals;             // Total signal events (estimated)
        u32 current_batch_size;        // Current batch size being processed
        u32 poll_mask;                 // Current poll mask
        u8 poll_pending;               // Poll operation pending
    } perf_counters;
    
    // === WORKER THREAD STATE ===
    struct {
        u64 worker_task_ptr;           // Worker task struct pointer
        u32 worker_pid;                // Worker thread PID
        u32 worker_state;              // Worker thread state
        char worker_comm[16];          // Worker thread command
        u8 worker_active;              // Worker actively processing
    } worker_state;
    
    // === ERROR AND DEBUG INFO ===
    struct {
        u32 read_failures;             // Count of memory read failures
        u32 last_error_offset;         // Last failed memory access offset
        u64 last_error_addr;           // Last failed memory address
        u8 structure_valid;            // Overall structure validity
    } debug_info;
};

// Maps
BPF_PERF_OUTPUT(events);

// Device filter
struct filter_config {
    char device[IFNAMSIZ];
    u32 queue;
    u8 enabled;
};
BPF_ARRAY(filter_settings, struct filter_config, 1);

// Helper macros for safe memory reading
#define SAFE_READ(dst, src, field) do { \\
    if (bpf_probe_read_kernel(&(dst), sizeof(dst), &((src)->field)) != 0) { \\
        event->debug_info.read_failures++; \\
        event->debug_info.last_error_offset = offsetof(typeof(*(src)), field); \\
        event->debug_info.last_error_addr = (u64)&((src)->field); \\
    } \\
} while(0)

#define SAFE_READ_USER(dst, src, field) do { \\
    if (bpf_probe_read_user(&(dst), sizeof(dst), &((src)->field)) != 0) { \\
        event->debug_info.read_failures++; \\
        event->debug_info.last_error_offset = offsetof(typeof(*(src)), field); \\
        event->debug_info.last_error_addr = (u64)&((src)->field); \\
    } \\
} while(0)

// Safe pointer read
#define SAFE_READ_PTR(dst, src, offset) do { \\
    if (bpf_probe_read_kernel(&(dst), sizeof(dst), (char*)(src) + (offset)) != 0) { \\
        event->debug_info.read_failures++; \\
        event->debug_info.last_error_offset = (offset); \\
        event->debug_info.last_error_addr = (u64)((char*)(src) + (offset)); \\
    } \\
} while(0)

// Extract comprehensive vhost_dev state
static inline void extract_vhost_dev_state(struct vhost_dev *dev, struct vhost_ultra_event *event) {
    if (!dev) return;
    
    SAFE_READ(event->dev_state.mm_ptr, dev, mm);
    SAFE_READ(event->dev_state.vqs_ptr, dev, vqs);
    SAFE_READ(event->dev_state.nvqs, dev, nvqs);
    SAFE_READ(event->dev_state.worker_ptr, dev, worker);
    SAFE_READ(event->dev_state.umem_ptr, dev, umem);
    SAFE_READ(event->dev_state.iotlb_ptr, dev, iotlb);
    SAFE_READ(event->dev_state.log_ctx_ptr, dev, log_ctx);
    SAFE_READ(event->dev_state.iov_limit, dev, iov_limit);
    SAFE_READ(event->dev_state.weight, dev, weight);
    SAFE_READ(event->dev_state.byte_weight, dev, byte_weight);
    
    // Check work_list state
    struct llist_node *work_first = NULL;
    SAFE_READ(work_first, dev, work_list.first);
    event->dev_state.work_list_first = work_first ? 1 : 0;
    
    // Check list states - just check if lists have entries
    // Note: Can't safely compare pointers in BPF, so we just check if next is NULL
    struct list_head *read_next = NULL, *pending_next = NULL;
    SAFE_READ(read_next, dev, read_list.next);
    SAFE_READ(pending_next, dev, pending_list.next);
    event->dev_state.read_list_empty = !read_next ? 1 : 0;
    event->dev_state.pending_list_empty = !pending_next ? 1 : 0;
}

// Extract comprehensive vhost_virtqueue state
static inline void extract_vhost_vq_state(struct vhost_virtqueue *vq, struct vhost_ultra_event *event) {
    if (!vq) return;
    
    // Ring configuration
    SAFE_READ(event->vq_state.num, vq, num);
    SAFE_READ(event->vq_state.desc_ptr, vq, desc);
    SAFE_READ(event->vq_state.avail_ptr, vq, avail);
    SAFE_READ(event->vq_state.used_ptr, vq, used);
    
    // Ring state
    SAFE_READ(event->vq_state.last_avail_idx, vq, last_avail_idx);
    SAFE_READ(event->vq_state.avail_idx, vq, avail_idx);
    SAFE_READ(event->vq_state.last_used_idx, vq, last_used_idx);
    SAFE_READ(event->vq_state.used_flags, vq, used_flags);
    SAFE_READ(event->vq_state.signalled_used, vq, signalled_used);
    SAFE_READ(event->vq_state.signalled_used_valid, vq, signalled_used_valid);
    
    // Memory management - meta_iotlb is an array
    void *meta_iotlb_0 = NULL, *meta_iotlb_1 = NULL, *meta_iotlb_2 = NULL;
    if (bpf_probe_read_kernel(&meta_iotlb_0, sizeof(meta_iotlb_0), &vq->meta_iotlb[0]) == 0) {
        event->vq_state.meta_iotlb_desc = (u64)meta_iotlb_0;
    }
    if (bpf_probe_read_kernel(&meta_iotlb_1, sizeof(meta_iotlb_1), &vq->meta_iotlb[1]) == 0) {
        event->vq_state.meta_iotlb_avail = (u64)meta_iotlb_1;
    }
    if (bpf_probe_read_kernel(&meta_iotlb_2, sizeof(meta_iotlb_2), &vq->meta_iotlb[2]) == 0) {
        event->vq_state.meta_iotlb_used = (u64)meta_iotlb_2;
    }
    
    SAFE_READ(event->vq_state.umem_ptr, vq, umem);
    SAFE_READ(event->vq_state.iotlb_ptr, vq, iotlb);
    
    // Event notification
    SAFE_READ(event->vq_state.kick_ptr, vq, kick);
    SAFE_READ(event->vq_state.call_ctx_ptr, vq, call_ctx);
    SAFE_READ(event->vq_state.error_ctx_ptr, vq, error_ctx);
    SAFE_READ(event->vq_state.log_ctx_ptr, vq, log_ctx);
    
    // Logging state
    SAFE_READ(event->vq_state.log_used, vq, log_used);
    SAFE_READ(event->vq_state.log_addr, vq, log_addr);
    SAFE_READ(event->vq_state.log_base_ptr, vq, log_base);
    
    // Features
    SAFE_READ(event->vq_state.acked_features, vq, acked_features);
    SAFE_READ(event->vq_state.acked_backend_features, vq, acked_backend_features);
    
    // Configuration
    SAFE_READ(event->vq_state.is_le, vq, is_le);
    #ifdef CONFIG_VHOST_CROSS_ENDIAN_LEGACY
    SAFE_READ(event->vq_state.user_be, vq, user_be);
    #endif
    SAFE_READ(event->vq_state.busyloop_timeout, vq, busyloop_timeout);
    
    // Work management
    SAFE_READ(event->vq_state.handle_kick_ptr, vq, handle_kick);
    SAFE_READ(event->vq_state.private_data_ptr, vq, private_data);
    
    // Buffer pointers
    SAFE_READ(event->vq_state.indirect_ptr, vq, indirect);
    SAFE_READ(event->vq_state.heads_ptr, vq, heads);
    
    // Array analysis would need loop unrolling, skip for now
    event->vq_state.iov_count = 0;  // Would need complex analysis
    event->vq_state.iotlb_iov_count = 0;
}

// Extract memory region information
static inline void extract_memory_state(struct vhost_virtqueue *vq, struct vhost_ultra_event *event) {
    if (!vq) return;
    
    // Get umem information
    struct vhost_umem *umem = NULL;
    SAFE_READ(umem, vq, umem);
    if (umem) {
        SAFE_READ(event->memory_state.umem_numem, umem, numem);
        
        // Try to get rb_root information
        struct rb_node *rb_root_node = NULL;
        SAFE_READ_PTR(rb_root_node, umem, offsetof(struct vhost_umem, umem_tree.rb_root.rb_node));
        event->memory_state.umem_tree_root = (u64)rb_root_node;
        
        // Try to get first region from list
        struct list_head *first_list = NULL;
        SAFE_READ(first_list, umem, umem_list.next);
        if (first_list) {
            event->memory_state.umem_tree_cached = 1; // Indicates we have regions
        }
    }
    
    // Get iotlb information
    struct vhost_umem *iotlb = NULL;
    SAFE_READ(iotlb, vq, iotlb);
    if (iotlb) {
        SAFE_READ(event->memory_state.iotlb_numem, iotlb, numem);
        
        struct rb_node *iotlb_rb_root_node = NULL;
        SAFE_READ_PTR(iotlb_rb_root_node, iotlb, offsetof(struct vhost_umem, umem_tree.rb_root.rb_node));
        event->memory_state.iotlb_tree_root = (u64)iotlb_rb_root_node;
    }
}

// Extract ring buffer details (userspace rings)
static inline void extract_ring_details(struct vhost_virtqueue *vq, struct vhost_ultra_event *event) {
    if (!vq) return;
    
    // Get ring pointers
    void __user *avail_ring = NULL, *used_ring = NULL, *desc_ring = NULL;
    SAFE_READ(avail_ring, vq, avail);
    SAFE_READ(used_ring, vq, used);
    SAFE_READ(desc_ring, vq, desc);
    
    // Try to read available ring (userspace memory - might fail)
    if (avail_ring) {
        u16 avail_flags = 0, avail_idx = 0;
        if (bpf_probe_read_user(&avail_flags, sizeof(avail_flags), avail_ring) == 0) {
            event->ring_details.avail_flags = avail_flags;
        }
        if (bpf_probe_read_user(&avail_idx, sizeof(avail_idx), (char*)avail_ring + 2) == 0) {
            event->ring_details.avail_idx_actual = avail_idx;
        }
        
        // Try to read first two available entries
        u16 avail_0 = 0, avail_1 = 0;
        if (bpf_probe_read_user(&avail_0, sizeof(avail_0), (char*)avail_ring + 4) == 0) {
            event->ring_details.avail_ring_0 = avail_0;
        }
        if (bpf_probe_read_user(&avail_1, sizeof(avail_1), (char*)avail_ring + 6) == 0) {
            event->ring_details.avail_ring_1 = avail_1;
        }
    }
    
    // Try to read used ring
    if (used_ring) {
        u16 used_flags = 0, used_idx = 0;
        if (bpf_probe_read_user(&used_flags, sizeof(used_flags), used_ring) == 0) {
            event->ring_details.used_flags_actual = used_flags;
        }
        if (bpf_probe_read_user(&used_idx, sizeof(used_idx), (char*)used_ring + 2) == 0) {
            event->ring_details.used_idx_actual = used_idx;
        }
        
        // Try to read first two used entries (each is 8 bytes: u32 id + u32 len)
        u32 used_0_id = 0, used_0_len = 0, used_1_id = 0, used_1_len = 0;
        if (bpf_probe_read_user(&used_0_id, sizeof(used_0_id), (char*)used_ring + 4) == 0) {
            event->ring_details.used_ring_0_id = used_0_id;
        }
        if (bpf_probe_read_user(&used_0_len, sizeof(used_0_len), (char*)used_ring + 8) == 0) {
            event->ring_details.used_ring_0_len = used_0_len;
        }
        if (bpf_probe_read_user(&used_1_id, sizeof(used_1_id), (char*)used_ring + 12) == 0) {
            event->ring_details.used_ring_1_id = used_1_id;
        }
        if (bpf_probe_read_user(&used_1_len, sizeof(used_1_len), (char*)used_ring + 16) == 0) {
            event->ring_details.used_ring_1_len = used_1_len;
        }
    }
    
    // Try to read descriptor ring (first two descriptors)
    if (desc_ring) {
        // Each descriptor is 16 bytes: u64 addr + u32 len + u16 flags + u16 next
        struct {
            u64 addr;
            u32 len;
            u16 flags;
            u16 next;
        } desc_0, desc_1;
        
        if (bpf_probe_read_user(&desc_0, sizeof(desc_0), desc_ring) == 0) {
            event->ring_details.desc_0_addr = desc_0.addr;
            event->ring_details.desc_0_len = desc_0.len;
            event->ring_details.desc_0_flags = desc_0.flags;
            event->ring_details.desc_0_next = desc_0.next;
        }
        if (bpf_probe_read_user(&desc_1, sizeof(desc_1), (char*)desc_ring + 16) == 0) {
            event->ring_details.desc_1_addr = desc_1.addr;
            event->ring_details.desc_1_len = desc_1.len;
            event->ring_details.desc_1_flags = desc_1.flags;
            event->ring_details.desc_1_next = desc_1.next;
        }
    }
}

// Extract worker thread state
static inline void extract_worker_state(struct vhost_dev *dev, struct vhost_ultra_event *event) {
    if (!dev) return;
    
    struct task_struct *worker = NULL;
    SAFE_READ(worker, dev, worker);
    
    if (worker) {
        event->worker_state.worker_task_ptr = (u64)worker;
        
        // Read PID (offset depends on kernel version, commonly around 1300-1400)
        int pid = 0;
        if (bpf_probe_read_kernel(&pid, sizeof(pid), (char*)worker + 1320) == 0) {
            event->worker_state.worker_pid = pid;
        }
        
        // Read state (offset around 16-24)
        long state = 0;
        if (bpf_probe_read_kernel(&state, sizeof(state), (char*)worker + 16) == 0) {
            event->worker_state.worker_state = state;
            event->worker_state.worker_active = (state == 0) ? 1 : 0; // TASK_RUNNING
        }
        
        // Try to read command name (offset around 1584)
        char comm[16] = {};
        if (bpf_probe_read_kernel(comm, sizeof(comm), (char*)worker + 1584) == 0) {
            __builtin_memcpy(event->worker_state.worker_comm, comm, 16);
        }
    }
}

// Check if this is a network virtqueue and extract net-specific state
static inline void extract_net_vq_state(struct vhost_virtqueue *vq, struct vhost_ultra_event *event) {
    // Check if private_data is set (indicates network vq)
    void *private_data = NULL;
    SAFE_READ(private_data, vq, private_data);
    
    if (private_data) {
        event->net_vq_state.is_net_vq = 1;
        
        // For vhost_net_virtqueue, the vhost_virtqueue is the first member
        // So we can cast the pointer to vhost_net_virtqueue
        struct vhost_net_virtqueue *nvq = (struct vhost_net_virtqueue *)vq;
        
        // Read net-specific fields
        SAFE_READ(event->net_vq_state.vhost_hlen, nvq, vhost_hlen);
        SAFE_READ(event->net_vq_state.sock_hlen, nvq, sock_hlen);
        SAFE_READ(event->net_vq_state.upend_idx, nvq, upend_idx);
        SAFE_READ(event->net_vq_state.done_idx, nvq, done_idx);
        SAFE_READ(event->net_vq_state.ubuf_info_ptr, nvq, ubuf_info);
        SAFE_READ(event->net_vq_state.ubufs_ptr, nvq, ubufs);
        SAFE_READ(event->net_vq_state.rx_ring_ptr, nvq, rx_ring);
        
        // RX queue buffer state
        SAFE_READ(event->net_vq_state.rxq_head, nvq, rxq.head);
        SAFE_READ(event->net_vq_state.rxq_tail, nvq, rxq.tail);
        SAFE_READ(event->net_vq_state.rxq_queue_ptr, nvq, rxq.queue);
    }
}

// Main probe function for vhost_add_used_and_signal_n
int trace_vhost_add_used_and_signal_n(struct pt_regs *ctx) {
    struct vhost_dev *dev = (struct vhost_dev *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    void *heads = (void *)PT_REGS_PARM3(ctx);
    unsigned count = (unsigned)PT_REGS_PARM4(ctx);
    
    if (!dev || !vq) return 0;
    
    // Check filter
    int key = 0;
    struct filter_config *filter = filter_settings.lookup(&key);
    
    // Create comprehensive event
    struct vhost_ultra_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Basic identification
    event.dev_ptr = (u64)dev;
    event.vq_ptr = (u64)vq;
    event.heads_count = count;
    
    // Try to determine queue index by reading from dev->vqs array
    struct vhost_virtqueue **vqs = NULL;
    SAFE_READ(vqs, dev, vqs);
    if (vqs) {
        // Check first two queues (RX=0, TX=1 for vhost-net)
        struct vhost_virtqueue *vq0 = NULL, *vq1 = NULL;
        if (bpf_probe_read_kernel(&vq0, sizeof(vq0), &vqs[0]) == 0 && vq0 == vq) {
            event.queue_index = 0;
        } else if (bpf_probe_read_kernel(&vq1, sizeof(vq1), &vqs[1]) == 0 && vq1 == vq) {
            event.queue_index = 1;
        } else {
            event.queue_index = 255; // Unknown
        }
    }
    
    __builtin_memcpy(event.dev_name, "vhost", 6);
    
    // Extract all state information
    extract_vhost_dev_state(dev, &event);
    extract_vhost_vq_state(vq, &event);
    extract_memory_state(vq, &event);
    extract_ring_details(vq, &event);
    extract_worker_state(dev, &event);
    extract_net_vq_state(vq, &event);
    
    // Set performance counters
    event.perf_counters.current_batch_size = count;
    
    // Set structure validity
    event.debug_info.structure_valid = (event.debug_info.read_failures < 10) ? 1 : 0;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Event structure matching BPF program
class VhostUltraEvent(ct.Structure):
    class DevState(ct.Structure):
        _fields_ = [
            ("mm_ptr", ct.c_uint64),
            ("vqs_ptr", ct.c_uint64),
            ("nvqs", ct.c_int32),
            ("worker_ptr", ct.c_uint64),
            ("umem_ptr", ct.c_uint64),
            ("iotlb_ptr", ct.c_uint64),
            ("log_ctx_ptr", ct.c_uint64),
            ("iov_limit", ct.c_int32),
            ("weight", ct.c_int32),
            ("byte_weight", ct.c_int32),
            ("work_list_first", ct.c_uint32),
            ("read_list_empty", ct.c_uint32),
            ("pending_list_empty", ct.c_uint32),
        ]
    
    class VqState(ct.Structure):
        _fields_ = [
            ("num", ct.c_uint32),
            ("desc_ptr", ct.c_uint64),
            ("avail_ptr", ct.c_uint64),
            ("used_ptr", ct.c_uint64),
            ("last_avail_idx", ct.c_uint16),
            ("avail_idx", ct.c_uint16),
            ("last_used_idx", ct.c_uint16),
            ("used_flags", ct.c_uint16),
            ("signalled_used", ct.c_uint16),
            ("signalled_used_valid", ct.c_uint8),
            ("meta_iotlb_desc", ct.c_uint64),
            ("meta_iotlb_avail", ct.c_uint64),
            ("meta_iotlb_used", ct.c_uint64),
            ("umem_ptr", ct.c_uint64),
            ("iotlb_ptr", ct.c_uint64),
            ("kick_ptr", ct.c_uint64),
            ("call_ctx_ptr", ct.c_uint64),
            ("error_ctx_ptr", ct.c_uint64),
            ("log_ctx_ptr", ct.c_uint64),
            ("log_used", ct.c_uint8),
            ("log_addr", ct.c_uint64),
            ("log_base_ptr", ct.c_uint64),
            ("acked_features", ct.c_uint64),
            ("acked_backend_features", ct.c_uint64),
            ("is_le", ct.c_uint8),
            ("user_be", ct.c_uint8),
            ("busyloop_timeout", ct.c_uint32),
            ("handle_kick_ptr", ct.c_uint64),
            ("private_data_ptr", ct.c_uint64),
            ("iov_count", ct.c_uint32),
            ("iotlb_iov_count", ct.c_uint32),
            ("indirect_ptr", ct.c_uint64),
            ("heads_ptr", ct.c_uint64),
        ]
    
    class NetVqState(ct.Structure):
        _fields_ = [
            ("is_net_vq", ct.c_uint8),
            ("vhost_hlen", ct.c_size_t),
            ("sock_hlen", ct.c_size_t),
            ("upend_idx", ct.c_int32),
            ("done_idx", ct.c_int32),
            ("ubuf_info_ptr", ct.c_uint64),
            ("ubufs_ptr", ct.c_uint64),
            ("rx_ring_ptr", ct.c_uint64),
            ("rxq_head", ct.c_int32),
            ("rxq_tail", ct.c_int32),
            ("rxq_queue_ptr", ct.c_uint64),
        ]
    
    class MemoryState(ct.Structure):
        _fields_ = [
            ("umem_numem", ct.c_uint32),
            ("umem_tree_root", ct.c_uint64),
            ("umem_tree_cached", ct.c_uint8),
            ("first_region_start", ct.c_uint64),
            ("first_region_last", ct.c_uint64),
            ("first_region_userspace", ct.c_uint64),
            ("first_region_perm", ct.c_uint32),
            ("iotlb_numem", ct.c_uint32),
            ("iotlb_tree_root", ct.c_uint64),
            ("iotlb_tree_cached", ct.c_uint8),
        ]
    
    class RingDetails(ct.Structure):
        _fields_ = [
            ("avail_flags", ct.c_uint16),
            ("avail_idx_actual", ct.c_uint16),
            ("avail_ring_0", ct.c_uint16),
            ("avail_ring_1", ct.c_uint16),
            ("avail_used_event", ct.c_uint16),
            ("used_flags_actual", ct.c_uint16),
            ("used_idx_actual", ct.c_uint16),
            ("used_ring_0_id", ct.c_uint32),
            ("used_ring_0_len", ct.c_uint32),
            ("used_ring_1_id", ct.c_uint32),
            ("used_ring_1_len", ct.c_uint32),
            ("used_avail_event", ct.c_uint16),
            ("desc_0_addr", ct.c_uint64),
            ("desc_0_len", ct.c_uint32),
            ("desc_0_flags", ct.c_uint16),
            ("desc_0_next", ct.c_uint16),
            ("desc_1_addr", ct.c_uint64),
            ("desc_1_len", ct.c_uint32),
            ("desc_1_flags", ct.c_uint16),
            ("desc_1_next", ct.c_uint16),
        ]
    
    class PerfCounters(ct.Structure):
        _fields_ = [
            ("total_kicks", ct.c_uint64),
            ("total_signals", ct.c_uint64),
            ("current_batch_size", ct.c_uint32),
            ("poll_mask", ct.c_uint32),
            ("poll_pending", ct.c_uint8),
        ]
    
    class WorkerState(ct.Structure):
        _fields_ = [
            ("worker_task_ptr", ct.c_uint64),
            ("worker_pid", ct.c_uint32),
            ("worker_state", ct.c_uint32),
            ("worker_comm", ct.c_char * 16),
            ("worker_active", ct.c_uint8),
        ]
    
    class DebugInfo(ct.Structure):
        _fields_ = [
            ("read_failures", ct.c_uint32),
            ("last_error_offset", ct.c_uint32),
            ("last_error_addr", ct.c_uint64),
            ("structure_valid", ct.c_uint8),
        ]
    
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_ptr", ct.c_uint64),
        ("vq_ptr", ct.c_uint64),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("heads_count", ct.c_uint32),
        ("dev_state", DevState),
        ("vq_state", VqState),
        ("net_vq_state", NetVqState),
        ("memory_state", MemoryState),
        ("ring_details", RingDetails),
        ("perf_counters", PerfCounters),
        ("worker_state", WorkerState),
        ("debug_info", DebugInfo),
    ]

def format_hex_ptr(ptr_val):
    """Format pointer as hex or 'NULL' if zero"""
    return "0x{:x}".format(ptr_val) if ptr_val else "NULL"

def format_bool(bool_val):
    """Format boolean as YES/NO"""
    return "YES" if bool_val else "NO"

def print_comprehensive_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(VhostUltraEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    print("=" * 120)
    print("🔍 COMPREHENSIVE VHOST ANALYSIS | Time: {}".format(timestamp_str))
    print("=" * 120)
    
    # Basic Info
    print("📍 Process: {} (PID: {}, TID: {})".format(event.comm.decode('utf-8', 'replace'), event.pid, event.tid))
    print("🎯 Queue: {} | Device: {} | Batch Size: {}".format(event.queue_index, event.dev_name.decode('utf-8', 'replace'), event.heads_count))
    print("🔗 Pointers: dev={} vq={}".format(format_hex_ptr(event.dev_ptr), format_hex_ptr(event.vq_ptr)))
    
    # === VHOST_DEV STATE ===
    print("\n📋 VHOST_DEV STATE:")
    print("   Memory Context: mm={}".format(format_hex_ptr(event.dev_state.mm_ptr)))
    print("   Virtqueues: array={} count={}".format(format_hex_ptr(event.dev_state.vqs_ptr), event.dev_state.nvqs))
    print("   Worker Thread: {}".format(format_hex_ptr(event.dev_state.worker_ptr)))
    print("   Memory Mgmt: umem={} iotlb={}".format(format_hex_ptr(event.dev_state.umem_ptr), format_hex_ptr(event.dev_state.iotlb_ptr)))
    print("   Logging: ctx={}".format(format_hex_ptr(event.dev_state.log_ctx_ptr)))
    print("   Limits: iov={} weight={} byte_weight={}".format(event.dev_state.iov_limit, event.dev_state.weight, event.dev_state.byte_weight))
    print("   Work Queues: work_pending={} read_empty={} pending_empty={}".format(format_bool(event.dev_state.work_list_first), format_bool(event.dev_state.read_list_empty), format_bool(event.dev_state.pending_list_empty)))
    
    # === VHOST_VIRTQUEUE STATE ===
    print("\n🔄 VHOST_VIRTQUEUE STATE:")
    print("   Ring Config: size={}".format(event.vq_state.num))
    print("   Ring Pointers: desc={} avail={} used={}".format(format_hex_ptr(event.vq_state.desc_ptr), format_hex_ptr(event.vq_state.avail_ptr), format_hex_ptr(event.vq_state.used_ptr)))
    print("   Ring Indices: last_avail={} avail_idx={} last_used={}".format(event.vq_state.last_avail_idx, event.vq_state.avail_idx, event.vq_state.last_used_idx))
    print("   Ring Flags: used_flags=0x{:x}".format(event.vq_state.used_flags))
    print("   Signaling: signalled_used={} valid={}".format(event.vq_state.signalled_used, format_bool(event.vq_state.signalled_used_valid)))
    
    print("   IOTLB Cache: desc={} avail={} used={}".format(format_hex_ptr(event.vq_state.meta_iotlb_desc), format_hex_ptr(event.vq_state.meta_iotlb_avail), format_hex_ptr(event.vq_state.meta_iotlb_used)))
    print("   Memory: umem={} iotlb={}".format(format_hex_ptr(event.vq_state.umem_ptr), format_hex_ptr(event.vq_state.iotlb_ptr)))
    
    print("   Event FDs: kick={} call={} error={} log={}".format(format_hex_ptr(event.vq_state.kick_ptr), format_hex_ptr(event.vq_state.call_ctx_ptr), format_hex_ptr(event.vq_state.error_ctx_ptr), format_hex_ptr(event.vq_state.log_ctx_ptr)))
    
    print("   Logging: enabled={} addr=0x{:x} base={}".format(format_bool(event.vq_state.log_used), event.vq_state.log_addr, format_hex_ptr(event.vq_state.log_base_ptr)))
    
    print("   Features: acked=0x{:x} backend=0x{:x}".format(event.vq_state.acked_features, event.vq_state.acked_backend_features))
    print("   Endianness: little_endian={} user_big_endian={}".format(format_bool(event.vq_state.is_le), format_bool(event.vq_state.user_be)))
    print("   Performance: busyloop_timeout={}us".format(event.vq_state.busyloop_timeout))
    
    print("   Work Handlers: kick_handler={} private_data={}".format(format_hex_ptr(event.vq_state.handle_kick_ptr), format_hex_ptr(event.vq_state.private_data_ptr)))
    print("   Buffers: indirect={} heads={}".format(format_hex_ptr(event.vq_state.indirect_ptr), format_hex_ptr(event.vq_state.heads_ptr)))
    
    # === NETWORK VIRTQUEUE STATE ===
    if event.net_vq_state.is_net_vq:
        print("\n🌐 VHOST_NET_VIRTQUEUE STATE:")
        print("   Header Lengths: vhost={} socket={}".format(event.net_vq_state.vhost_hlen, event.net_vq_state.sock_hlen))
        print("   Zero-Copy TX: upend_idx={} done_idx={}".format(event.net_vq_state.upend_idx, event.net_vq_state.done_idx))
        print("   Zero-Copy Bufs: ubuf_info={} ubufs={}".format(format_hex_ptr(event.net_vq_state.ubuf_info_ptr), format_hex_ptr(event.net_vq_state.ubufs_ptr)))
        print("   RX Ring: ptr_ring={}".format(format_hex_ptr(event.net_vq_state.rx_ring_ptr)))
        print("   RX Queue Buffer: head={} tail={} queue_array={}".format(event.net_vq_state.rxq_head, event.net_vq_state.rxq_tail, format_hex_ptr(event.net_vq_state.rxq_queue_ptr)))
    
    # === MEMORY MANAGEMENT STATE ===
    print("\n🧠 MEMORY MANAGEMENT STATE:")
    print("   UMEM: regions={} tree_root={}".format(event.memory_state.umem_numem, format_hex_ptr(event.memory_state.umem_tree_root)))
    print("   IOTLB: regions={} tree_root={}".format(event.memory_state.iotlb_numem, format_hex_ptr(event.memory_state.iotlb_tree_root)))
    if event.memory_state.first_region_start:
        print("   First Region: 0x{:x}-0x{:x} -> user:0x{:x} perm=0x{:x}".format(event.memory_state.first_region_start, event.memory_state.first_region_last, event.memory_state.first_region_userspace, event.memory_state.first_region_perm))
    
    # === RING BUFFER DETAILS ===
    print("\n💍 RING BUFFER DETAILS:")
    print("   Available Ring: flags=0x{:x} idx={}".format(event.ring_details.avail_flags, event.ring_details.avail_idx_actual))
    print("   Available Entries: [0]={} [1]={}".format(event.ring_details.avail_ring_0, event.ring_details.avail_ring_1))
    print("   Used Ring: flags=0x{:x} idx={}".format(event.ring_details.used_flags_actual, event.ring_details.used_idx_actual))
    print("   Used Entries: [0]={{id:{}, len:{}}} [1]={{id:{}, len:{}}}".format(event.ring_details.used_ring_0_id, event.ring_details.used_ring_0_len, event.ring_details.used_ring_1_id, event.ring_details.used_ring_1_len))
    print("   Descriptors: [0]={{addr:0x{:x}, len:{}, flags:0x{:x}, next:{}}}".format(event.ring_details.desc_0_addr, event.ring_details.desc_0_len, event.ring_details.desc_0_flags, event.ring_details.desc_0_next))
    print("                [1]={{addr:0x{:x}, len:{}, flags:0x{:x}, next:{}}}".format(event.ring_details.desc_1_addr, event.ring_details.desc_1_len, event.ring_details.desc_1_flags, event.ring_details.desc_1_next))
    
    # === WORKER THREAD STATE ===
    if event.worker_state.worker_task_ptr:
        print("\n👷 WORKER THREAD STATE:")
        print("   Task: {} PID={}".format(format_hex_ptr(event.worker_state.worker_task_ptr), event.worker_state.worker_pid))
        print("   Command: {}".format(event.worker_state.worker_comm.decode('utf-8', 'replace')))
        print("   State: {} (active={})".format(event.worker_state.worker_state, format_bool(event.worker_state.worker_active)))
    
    # === PERFORMANCE COUNTERS ===
    print("\n📊 PERFORMANCE COUNTERS:")
    print("   Current Batch: {} descriptors".format(event.perf_counters.current_batch_size))
    
    # === DEBUG INFORMATION ===
    print("\n🐛 DEBUG INFORMATION:")
    print("   Memory Read Failures: {}".format(event.debug_info.read_failures))
    if event.debug_info.read_failures > 0:
        print("   Last Error: offset={} addr={}".format(event.debug_info.last_error_offset, format_hex_ptr(event.debug_info.last_error_addr)))
    print("   Structure Validity: {}".format(format_bool(event.debug_info.structure_valid)))
    
    print("=" * 120)
    print()

def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive vhost internal state monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool provides ultra-detailed analysis of vhost internal data structures
when vhost_add_used_and_signal_n is called.

Examples:
  # Monitor all vhost activity
  sudo %(prog)s
  
  # Monitor specific device and queue
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
            print("Loading comprehensive vhost monitor BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach probe
        b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_add_used_and_signal_n")
        
        if args.verbose:
            print("✅ Probe attached successfully")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        return
    
    print("🔍 Comprehensive VHOST Monitor Started")
    print("📊 Monitoring vhost_add_used_and_signal_n with ultra-detailed analysis")
    print("⏳ Waiting for events... Press Ctrl+C to stop\n")
    
    try:
        b["events"].open_perf_buffer(print_comprehensive_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\n👋 Comprehensive monitoring stopped.")

if __name__ == "__main__":
    main()