#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
import re

# BCC module import with fallback
try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)
import ctypes as ct

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
            print("Warning: No symbol matching '{}' found in kallsyms".format(base_name))
        return None

    # Prefer exact match, then shortest suffix
    if base_name in candidates:
        return base_name

    result = min(candidates, key=len)
    if verbose:
        print("Found '{}' as '{}' in kallsyms".format(base_name, result))
    return result

def get_kernel_version():
    """
    Get kernel major.minor version tuple.
    Returns (major, minor) or (0, 0) on error.
    """
    try:
        import platform
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

# BPF program for queue correlation using sock pointer
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
#include <linux/virtio_ring.h>

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
// Need complete definition for correct field offsets

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

// irq_bypass_producer structure (kernel 5.x+)
// Used in vhost_vring_call for IRQ bypass support
struct irq_bypass_producer {
    struct list_head node;          // 16 bytes
    void *token;                    // 8 bytes
    int irq;                        // 4 bytes
    int padding;                    // 4 bytes alignment
    void *add_consumer;             // 8 bytes (function pointer)
    void *del_consumer;             // 8 bytes
    void *stop;                     // 8 bytes
    void *start;                    // 8 bytes
};  // Total: 64 bytes

// vhost_vring_call structure (kernel 5.x+)
// Replaced simple eventfd_ctx* in newer kernels
struct vhost_vring_call {
    struct eventfd_ctx *ctx;                // 8 bytes
    struct irq_bypass_producer producer;    // 64 bytes
};  // Total: 72 bytes

// KERNEL_VERSION_5X controls which structure layout to use
// Set via Python based on kernel version detection
#ifndef KERNEL_VERSION_5X
#define KERNEL_VERSION_5X 0
#endif

// VHOST_NOTIFY_CONSTPROP indicates if vhost_notify is a .constprop variant
// GCC constprop optimization may eliminate the first parameter (vhost_dev*)
// and only pass vhost_virtqueue* as arg0 instead of arg1
#ifndef VHOST_NOTIFY_CONSTPROP
#define VHOST_NOTIFY_CONSTPROP 0
#endif

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

// Event data structure
struct queue_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    
    // Queue identification
    u64 sock_ptr;
    u32 queue_index;
    char dev_name[16];
    
    // Event type
    u8 event_type;  // 1=tun_xmit, 2=handle_rx, 3=tun_recvmsg, 4=vhost_signal, 5=vhost_notify
    
    // Event-specific data
    u64 skb_ptr;
    u64 tfile_ptr;
    u64 vq_ptr;
    u64 nvq_ptr;
    u64 tx_nvq_ptr;
    int rx_busyloop_timeout;
    int tx_busyloop_timeout;
    
    // Packet info (from tun_xmit)
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    
    // PTR ring state
    u32 ptr_ring_size;
    u32 producer;
    u32 consumer_head;
    u32 consumer_tail;
    u32 ring_full;
    
    // Return values
    int ret_val;
    
    // vhost_notify specific
    bool has_event_idx_feature;
    u16 avail_flags;        // Guest avail ring flags (from guest memory)
    u16 used_event_idx;     // Guest used event index (from guest memory, if EVENT_IDX enabled)
    bool guest_flags_valid; // Whether we successfully read guest flags
    bool guest_event_valid; // Whether we successfully read event idx
    
    // VHOST virtqueue state (for handle_rx and vhost_signal)
    u16 last_avail_idx;
    u16 avail_idx;
    u16 last_used_idx;
    u16 used_flags;
    u16 signalled_used;
    bool signalled_used_valid;
    bool log_used;
    u64 log_addr;
    u64 acked_features;
    u64 acked_backend_features;
    
    // VHOST net virtqueue state
    u64 rx_ring_ptr;
    int upend_idx;
    int done_idx;
    size_t vhost_hlen;
    size_t sock_hlen;
    
    // RX buffer state
    int rxq_head;
    int rxq_tail;
};

// Maps
BPF_HASH(target_queues, u64, struct queue_key, 256);  // Track target queue sock pointers
BPF_HASH(handle_rx_vqs, u64, u64, 256);  // Track handle_rx VQ pointers for signal filtering
BPF_PERF_OUTPUT(events);
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);

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

// Get vhost_virtqueue state information
static inline void get_vhost_vq_state(struct vhost_virtqueue *vq, struct queue_event *event) {
    if (!vq) return;
    
    READ_FIELD(&event->last_avail_idx, vq, last_avail_idx);
    READ_FIELD(&event->avail_idx, vq, avail_idx);
    READ_FIELD(&event->last_used_idx, vq, last_used_idx);
    READ_FIELD(&event->used_flags, vq, used_flags);
    READ_FIELD(&event->signalled_used, vq, signalled_used);
    READ_FIELD(&event->signalled_used_valid, vq, signalled_used_valid);
    READ_FIELD(&event->log_used, vq, log_used);
    READ_FIELD(&event->log_addr, vq, log_addr);
    READ_FIELD(&event->acked_features, vq, acked_features);
    READ_FIELD(&event->acked_backend_features, vq, acked_backend_features);
}

// Get vhost_net_virtqueue state information
static inline void get_vhost_nvq_state(struct vhost_net_virtqueue *nvq, struct queue_event *event) {
    if (!nvq) return;
    
    READ_FIELD(&event->vhost_hlen, nvq, vhost_hlen);
    READ_FIELD(&event->sock_hlen, nvq, sock_hlen);
    READ_FIELD(&event->upend_idx, nvq, upend_idx);
    READ_FIELD(&event->done_idx, nvq, done_idx);
    
    // Get rx_ring pointer - nvq->rx_ring is a pointer to the actual ring
    struct ptr_ring *rx_ring_ptr = NULL;
    READ_FIELD(&rx_ring_ptr, nvq, rx_ring);
    event->rx_ring_ptr = (u64)rx_ring_ptr;
    
    // Get rxq buffer state (rxq is a struct, not a pointer)
    struct vhost_net_buf *rxq = &nvq->rxq;
    READ_FIELD(&event->rxq_head, rxq, head);
    READ_FIELD(&event->rxq_tail, rxq, tail);
}

// Extract ptr_ring state using proven member_read approach from tun_ring_monitor.py
static inline void get_ptr_ring_state_from_tfile(struct tun_file *tfile, struct queue_event *event) {
    if (!tfile) return;
    
    struct ptr_ring *tx_ring = &tfile->tx_ring;
    
    u32 producer, consumer_head, consumer_tail, size;
    void **queue;
    
    member_read(&producer, tx_ring, producer);
    member_read(&consumer_head, tx_ring, consumer_head);
    member_read(&consumer_tail, tx_ring, consumer_tail);
    member_read(&size, tx_ring, size);
    member_read(&queue, tx_ring, queue);
    
    event->producer = producer;
    event->consumer_head = consumer_head;
    event->consumer_tail = consumer_tail;
    event->ptr_ring_size = size;
    
    // Check if ring is full
    if (queue && size > 0) {
        void *queue_entry = NULL;
        if (producer < size && 
            bpf_probe_read_kernel(&queue_entry, sizeof(queue_entry), &queue[producer]) == 0) {
            event->ring_full = (queue_entry != NULL) ? 1 : 0;
        }
    }
}

// Parse packet headers
static inline int parse_packet_headers(struct sk_buff *skb, struct queue_event *event) {
    if (!skb) return 0;
    
    unsigned char *head;
    u16 network_header_offset;
    u16 transport_header_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0 ||
        bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0 ||
        bpf_probe_read_kernel(&transport_header_offset, sizeof(transport_header_offset), &skb->transport_header) < 0) {
        return 0;
    }

    if (network_header_offset == (u16)~0U || network_header_offset > 2048) {
        return 0;
    }

    struct iphdr ip;
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0) {
        return 0;
    }

    event->saddr = ip.saddr;
    event->daddr = ip.daddr;
    event->protocol = ip.protocol;

    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) return 0;
    
    if (transport_header_offset == 0 || transport_header_offset == (u16)~0U || 
        transport_header_offset == network_header_offset) {
        transport_header_offset = network_header_offset + (ip_ihl * 4);
    }

    if (ip.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + transport_header_offset) < 0) {
            return 0;
        }
        event->sport = bpf_ntohs(tcph.source);
        event->dport = bpf_ntohs(tcph.dest);
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header_offset) < 0) {
            return 0;
        }
        event->sport = bpf_ntohs(udph.source);
        event->dport = bpf_ntohs(udph.dest);
    }

    return 1;
}

// Stage 1: tun_net_xmit - Identify and track target queue
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !dev) return 0;
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    u32 queue_index = skb->queue_mapping;
    
    // Check queue filter - THIS IS THE KEY FILTER POINT
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
    //member_read(&tun_numqueues, tun, numqueues);
    //if (bpf_probe_read_kernel(&tun_numqueues, sizeof(tun_numqueues), &tun->numqueues) != 0) {
    //    return 0;
    //}
    //BPF_PROBE_READ(&tun_numqueues, &tun->numqueues);
    READ_FIELD(&tun_numqueues, tun, numqueues);
    
    if (queue_index >= tun_numqueues || queue_index >= 256) {
        return 0;
    }
    
    // Get tfile for this queue using pointer arithmetic (proven approach from tun_ring_monitor.py)
    struct tun_file *tfile = NULL;
    if (queue_index < tun_numqueues && tun_numqueues > 0 && queue_index < 256) {
        // Use pointer arithmetic to calculate the exact offset of tfiles[index]
        // tfiles is at the beginning of tun_struct, so:
        // tun_struct + index * sizeof(void*) gives us &tfiles[index]
        void **tfile_ptr_addr = (void**)((char*)tun + queue_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL; // Read failed
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
    
    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 1;  // tun_xmit
    
    event.sock_ptr = sock_ptr;
    event.queue_index = queue_index;
    bpf_probe_read_kernel_str(event.dev_name, sizeof(event.dev_name), dev->name);
    event.skb_ptr = (u64)skb;
    event.tfile_ptr = (u64)tfile;
    
    // Get packet info
    parse_packet_headers(skb, &event);
    
    // Get ptr_ring state and pointer
    get_ptr_ring_state_from_tfile(tfile, &event);
    
    // Get ptr_ring pointer address
    struct ptr_ring *tx_ring = &tfile->tx_ring;
    event.rx_ring_ptr = (u64)tx_ring;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 2: handle_rx - Track using sock pointer with member_read
int trace_handle_rx(struct pt_regs *ctx) {
    struct vhost_net *net = (struct vhost_net *)PT_REGS_PARM1(ctx);
    if (!net) return 0;
    
    // Get RX virtqueue (vqs[0].vq) using member_read
    struct vhost_net_virtqueue *nvq = &net->vqs[0];
    struct vhost_virtqueue *vq = &nvq->vq;
    
    // Get TX virtqueue (vqs[1].vq)
    struct vhost_net_virtqueue *tx_nvq = &net->vqs[1];
    
    // Get sock pointer from private_data using READ_FIELD  
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 2;  // handle_rx
    
    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq;
    event.nvq_ptr = (u64)nvq;
    event.tx_nvq_ptr = (u64)tx_nvq;
    
    // Get busyloop_timeout for RX and TX
    READ_FIELD(&event.rx_busyloop_timeout, vq, busyloop_timeout);
    
    struct vhost_virtqueue *tx_vq = &tx_nvq->vq;
    READ_FIELD(&event.tx_busyloop_timeout, tx_vq, busyloop_timeout);
    
    // Get vhost virtqueue state
    get_vhost_vq_state(vq, &event);
    
    // Get vhost net virtqueue state
    get_vhost_nvq_state(nvq, &event);
    
    // Track this VQ for signal filtering
    u64 vq_addr = (u64)vq;
    handle_rx_vqs.update(&sock_ptr, &vq_addr);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 3: tun_recvmsg - Track using socket -> sock (NO device filtering here)
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
    
    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 3;  // tun_recvmsg
    
    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.tfile_ptr = (u64)tfile;
    
    // Get ptr_ring state using proven approach
    get_ptr_ring_state_from_tfile(tfile, &event);
    
    // Get ptr_ring pointer address
    struct ptr_ring *tx_ring = &tfile->tx_ring;
    event.rx_ring_ptr = (u64)tx_ring;
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 4: tun_recvmsg return
int trace_tun_recvmsg_return(struct pt_regs *ctx) {
    // We need to match this with the entry - for now skip
    return 0;
}

// Stage 5: vhost_add_used_and_signal_n - Track using vq -> sock with member_read
// Note: vhost_signal() is typically inlined, so we probe vhost_add_used_and_signal_n
// which is the actual function called when packets are added to used ring and signaled
// Signature: void vhost_add_used_and_signal_n(struct vhost_dev *dev,
//                                             struct vhost_virtqueue *vq,
//                                             struct vring_used_elem *heads,
//                                             unsigned count)
int trace_vhost_add_used_and_signal_n(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
    // heads = PT_REGS_PARM3, count = PT_REGS_PARM4
    
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
    
    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 4;  // vhost_signal
    
    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq;
    
    // Get vhost virtqueue state
    get_vhost_vq_state(vq, &event);
    
    // Try to get the container vhost_net_virtqueue (this is tricky)
    // For now, we'll skip nvq state since we don't have easy access to it
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 6: vhost_notify - Track notification decisions
#define VIRTIO_RING_F_EVENT_IDX 29

int trace_vhost_notify_return(struct pt_regs *ctx) {
    // Get return value (bool)
    int ret = PT_REGS_RC(ctx);
    
    // Need to get the vq pointer from entry probe
    // For simplicity, we'll use a map to track entry parameters
    return 0;
}

// Map to store vhost_notify entry parameters
BPF_HASH(vhost_notify_params, u64, struct vhost_virtqueue*, 256);

int trace_vhost_notify_entry(struct pt_regs *ctx) {
    // GCC constprop optimization may change parameter layout:
    // Original: vhost_notify(struct vhost_dev *dev, struct vhost_virtqueue *vq)
    // constprop: vhost_notify.constprop.0(struct vhost_virtqueue *vq)
    //            (dev parameter eliminated, accessed via vq->dev internally)
#if VHOST_NOTIFY_CONSTPROP
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM1(ctx);
#else
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);
#endif

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
    
    // Store vq pointer for return probe
    u64 tid = bpf_get_current_pid_tgid();
    vhost_notify_params.update(&tid, &vq);
    
    return 0;
}

int trace_vhost_notify_return2(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    
    // Get vq from entry probe
    struct vhost_virtqueue **vq_ptr = vhost_notify_params.lookup(&tid);
    if (!vq_ptr || !*vq_ptr) {
        return 0;
    }
    
    struct vhost_virtqueue *vq = *vq_ptr;
    vhost_notify_params.delete(&tid);
    
    // Get sock pointer from private_data using READ_FIELD  
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);
    
    u64 sock_ptr = (u64)private_data;
    
    // Check if this is our target queue (ONLY sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }
    
    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = tid >> 32;
    event.tid = tid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 5;  // vhost_notify
    
    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq;
    
    // Get return value
    event.ret_val = PT_REGS_RC(ctx);
    
    // Get vhost virtqueue state
    get_vhost_vq_state(vq, &event);
    
    // Check if VIRTIO_RING_F_EVENT_IDX is supported
    u64 acked_features = 0;
    READ_FIELD(&acked_features, vq, acked_features);
    event.has_event_idx_feature = (acked_features & (1ULL << VIRTIO_RING_F_EVENT_IDX)) != 0;
    
    // Try to read avail flags from guest memory
    struct vring_avail *avail = NULL;
    READ_FIELD(&avail, vq, avail);
    if (avail) {
        __virtio16 flags = 0;
        // Read from user space (guest memory)
        if (bpf_probe_read_user(&flags, sizeof(flags), &avail->flags) == 0) {
            event.avail_flags = flags;
            event.guest_flags_valid = true;
        }
    }
    
    // If EVENT_IDX is enabled, try to read used_event_idx from guest memory
    if (event.has_event_idx_feature) {
        // vhost_used_event(vq) = &vq->avail->ring[vq->num]
        // This is the used_event field in the avail ring
        unsigned int num = 0;
        READ_FIELD(&num, vq, num);
        
        if (avail && num > 0) {
            // Calculate the address of used_event_idx
            // It's located after the ring array: avail->ring[num]
            __virtio16 *used_event_ptr = (__virtio16 *)((char *)avail + 
                                          offsetof(struct vring_avail, ring) + 
                                          num * sizeof(__virtio16));
            __virtio16 used_event = 0;
            if (bpf_probe_read_user(&used_event, sizeof(used_event), used_event_ptr) == 0) {
                event.used_event_idx = used_event;
                event.guest_event_valid = true;
            }
        }
    }
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

class QueueKey(ct.Structure):
    _fields_ = [
        ("sock_ptr", ct.c_uint64),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
    ]

class QueueEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("sock_ptr", ct.c_uint64),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("event_type", ct.c_uint8),
        ("skb_ptr", ct.c_uint64),
        ("tfile_ptr", ct.c_uint64),
        ("vq_ptr", ct.c_uint64),
        ("nvq_ptr", ct.c_uint64),
        ("tx_nvq_ptr", ct.c_uint64),
        ("rx_busyloop_timeout", ct.c_int),
        ("tx_busyloop_timeout", ct.c_int),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("protocol", ct.c_uint8),
        ("ptr_ring_size", ct.c_uint32),
        ("producer", ct.c_uint32),
        ("consumer_head", ct.c_uint32),
        ("consumer_tail", ct.c_uint32),
        ("ring_full", ct.c_uint32),
        ("ret_val", ct.c_int),
        ("has_event_idx_feature", ct.c_bool),
        ("avail_flags", ct.c_uint16),
        ("used_event_idx", ct.c_uint16),
        ("guest_flags_valid", ct.c_bool),
        ("guest_event_valid", ct.c_bool),
        # VHOST virtqueue state
        ("last_avail_idx", ct.c_uint16),
        ("avail_idx", ct.c_uint16),
        ("last_used_idx", ct.c_uint16),
        ("used_flags", ct.c_uint16),
        ("signalled_used", ct.c_uint16),
        ("signalled_used_valid", ct.c_bool),
        ("log_used", ct.c_bool),
        ("log_addr", ct.c_uint64),
        ("acked_features", ct.c_uint64),
        ("acked_backend_features", ct.c_uint64),
        # VHOST net virtqueue state
        ("rx_ring_ptr", ct.c_uint64),
        ("upend_idx", ct.c_int),
        ("done_idx", ct.c_int),
        ("vhost_hlen", ct.c_size_t),
        ("sock_hlen", ct.c_size_t),
        ("rxq_head", ct.c_int),
        ("rxq_tail", ct.c_int),
    ]

def ip_to_str(addr):
    if addr == 0:
        return "N/A"
    return socket.inet_ntoa(struct.pack("I", addr))

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(QueueEvent)).contents
    
    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    event_names = {
        1: "tun_net_xmit",
        2: "handle_rx",
        3: "tun_recvmsg",
        4: "vhost_signal",
        5: "vhost_notify"
    }
    
    print("="*80)
    print("Event: {} | Time: {}".format(
        event_names.get(event.event_type, "unknown"), timestamp_str))
    print("Queue: {} | Device: {} | Process: {} (PID: {})".format(
        event.queue_index, event.dev_name.decode('utf-8', 'replace'),
        event.comm.decode('utf-8', 'replace'), event.pid))
    print("Sock: 0x{:x}".format(event.sock_ptr))
    
    # Event-specific information
    if event.event_type == 1:  # tun_net_xmit
        print("SKB: 0x{:x} | TFile: 0x{:x}".format(event.skb_ptr, event.tfile_ptr))
        if event.saddr != 0:
            print("Flow: {}:{} -> {}:{} ({})".format(
                ip_to_str(event.saddr), event.sport,
                ip_to_str(event.daddr), event.dport,
                "TCP" if event.protocol == 6 else "UDP" if event.protocol == 17 else str(event.protocol)))
        if event.rx_ring_ptr:
            print("PTR Ring: 0x{:x}".format(event.rx_ring_ptr))
    elif event.event_type == 2:  # handle_rx
        print("VQ: 0x{:x} | NVQ: 0x{:x} | TX_NVQ: 0x{:x}".format(event.vq_ptr, event.nvq_ptr, event.tx_nvq_ptr))
        print("Busyloop: RX={}, TX={}".format(event.rx_busyloop_timeout, event.tx_busyloop_timeout))
        print("VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("Signal: signalled_used={}, valid={}, log_used={}".format(
            event.signalled_used, "YES" if event.signalled_used_valid else "NO", 
            "YES" if event.log_used else "NO"))
        print("Features: acked=0x{:x}, backend=0x{:x}".format(
            event.acked_features, event.acked_backend_features))
        if event.rx_ring_ptr:
            print("RX Ring: 0x{:x}, upend_idx={}, done_idx={}".format(
                event.rx_ring_ptr, event.upend_idx, event.done_idx))
        print("Hdr Len: vhost={}, sock={}, rxq_buf={}{}".format(
            event.vhost_hlen, event.sock_hlen, event.rxq_head, event.rxq_tail))
    elif event.event_type == 3:  # tun_recvmsg
        print("TFile: 0x{:x}".format(event.tfile_ptr))
        if event.rx_ring_ptr:
            print("PTR Ring: 0x{:x}".format(event.rx_ring_ptr))
    elif event.event_type == 4:  # vhost_signal
        print("VQ: 0x{:x}".format(event.vq_ptr))
        print("VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("Signal: signalled_used={}, valid={}, log_used={}".format(
            event.signalled_used, "YES" if event.signalled_used_valid else "NO", 
            "YES" if event.log_used else "NO"))
        print("Features: acked=0x{:x}, backend=0x{:x}".format(
            event.acked_features, event.acked_backend_features))
        if event.log_used and event.log_addr:
            print("Log: addr=0x{:x}".format(event.log_addr))
    elif event.event_type == 5:  # vhost_notify
        print("VQ: 0x{:x} | Return: {} (notify={})".format(
            event.vq_ptr, event.ret_val, "YES" if event.ret_val else "NO"))
        print("VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("Features: acked=0x{:x}, backend=0x{:x}, EVENT_IDX={}".format(
            event.acked_features, event.acked_backend_features,
            "ENABLED" if event.has_event_idx_feature else "DISABLED"))
        # Guest memory fields
        if event.guest_flags_valid:
            no_interrupt = (event.avail_flags & 0x1) != 0  # VRING_AVAIL_F_NO_INTERRUPT = 1
            print("Guest avail_flags: 0x{:x} (NO_INTERRUPT={})".format(
                event.avail_flags, "YES" if no_interrupt else "NO"))
        else:
            print("Guest avail_flags: <failed to read>")
        
        if event.has_event_idx_feature and event.guest_event_valid:
            print("Guest used_event_idx: {} (host last_used={})".format(
                event.used_event_idx, event.last_used_idx))
        elif event.has_event_idx_feature:
            print("Guest used_event_idx: <failed to read>")
    
    # Show ptr_ring state if available
    if event.ptr_ring_size > 0:
        print("PTR Ring: size={}, producer={}, consumer_h={}, consumer_t={}, full={}".format(
            event.ptr_ring_size, event.producer, 
            event.consumer_head, event.consumer_tail,
            "YES" if event.ring_full else "NO"))
        
        if event.producer >= event.consumer_tail:
            used = event.producer - event.consumer_tail
        else:
            used = event.ptr_ring_size - event.consumer_tail + event.producer
        utilization = (used * 100) // event.ptr_ring_size if event.ptr_ring_size > 0 else 0
        print("   Utilization: {}%".format(utilization))
    
    print()

def main():
    parser = argparse.ArgumentParser(
        description="VHOST-NET Queue Correlation Monitor using sock pointer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all queues on all TUN devices
  sudo %(prog)s
  
  # Monitor specific device and queue
  sudo %(prog)s --device vnet33 --queue 0
  
  # Monitor specific device with verbose output  
  sudo %(prog)s --device vnet33 --verbose
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet33)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()

    # Detect kernel version, distro and set appropriate structure layout
    kernel_5x = needs_5x_vhost_layout()
    major, minor = get_kernel_version()
    distro = get_distro_id()

    # Pre-scan for vhost_notify function name to detect constprop variant
    # This must happen before BPF loading to set the correct compile-time flags
    vhost_notify_func = find_kernel_function("vhost_notify", verbose=args.verbose)
    is_constprop = vhost_notify_func and ".constprop" in vhost_notify_func

    # Pre-scan for vhost_add_used_and_signal_n (may be in vhost module)
    vhost_signal_func = find_kernel_function("vhost_add_used_and_signal_n", verbose=args.verbose)

    # Check irqbypass module status for verbose output
    irqbypass_loaded = has_irqbypass_module()

    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program...")
            print("Detected kernel version: {}.{}, distro: {}".format(major, minor, distro))
            print("IRQ bypass module: {}".format("loaded" if irqbypass_loaded else "not loaded"))
            print("Using {} vhost structure layout".format(
                "5.x (with vhost_vring_call, 72 bytes)" if kernel_5x else "4.x (pointer only, 8 bytes)"))
            if vhost_notify_func:
                print("vhost_notify function: {} (constprop={})".format(
                    vhost_notify_func, "YES" if is_constprop else "NO"))
            if vhost_signal_func:
                print("vhost_add_used_and_signal_n function: {}".format(vhost_signal_func))

        # Set compile-time macros for correct structure/parameter handling
        bpf_program = bpf_text
        defines = []
        if kernel_5x:
            defines.append("#define KERNEL_VERSION_5X 1")
        if is_constprop:
            defines.append("#define VHOST_NOTIFY_CONSTPROP 1")

        if defines:
            bpf_program = "\n".join(defines) + "\n" + bpf_program

        b = BPF(text=bpf_program)

        # Attach kprobes
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        b.attach_kprobe(event="handle_rx", fn_name="trace_handle_rx")
        b.attach_kprobe(event="tun_recvmsg", fn_name="trace_tun_recvmsg_entry")
        b.attach_kretprobe(event="tun_recvmsg", fn_name="trace_tun_recvmsg_return")

        # Attach vhost_add_used_and_signal_n (vhost_signal is typically inlined)
        vhost_signal_attached = False
        if vhost_signal_func:
            try:
                b.attach_kprobe(event=vhost_signal_func, fn_name="trace_vhost_add_used_and_signal_n")
                vhost_signal_attached = True
                if args.verbose:
                    print("Attached to {}".format(vhost_signal_func))
            except Exception as e:
                if args.verbose:
                    print("Failed to attach to {}: {}".format(vhost_signal_func, e))

        if not vhost_signal_attached:
            print("Warning: Could not attach to vhost_add_used_and_signal_n (function not found or attach failed)")
            print("vhost_signal events will not be captured")

        # Try to attach vhost_notify
        vhost_notify_attached = False
        if vhost_notify_func:
            try:
                b.attach_kprobe(event=vhost_notify_func, fn_name="trace_vhost_notify_entry")
                b.attach_kretprobe(event=vhost_notify_func, fn_name="trace_vhost_notify_return2")
                vhost_notify_attached = True
                if args.verbose:
                    print("Attached to {}".format(vhost_notify_func))
            except Exception as e:
                if args.verbose:
                    print("Failed to attach to {}: {}".format(vhost_notify_func, e))

        if not vhost_notify_attached:
            print("Warning: Could not attach to vhost_notify (function not found or attach failed)")
            print("Continuing without vhost_notify monitoring...")
        
        if args.verbose:
            print("All probes attached successfully")
        
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
        print("Queue filter: {} (enforced at tun_net_xmit)".format(args.queue))
    else:
        b["filter_enabled"][0] = ct.c_uint32(0)
        print("Queue filter: All queues")
    
    print("VHOST-NET Queue Correlation Monitor Started")
    print("Using sock pointer (0x...) to correlate events across stages")
    print("Clearing maps to avoid stale entries")
    
    # Clear target_queues map to avoid stale entries
    target_queues_map = b["target_queues"]
    target_queues_map.clear()
    
    # Clear handle_rx_vqs map to avoid stale entries
    handle_rx_vqs_map = b["handle_rx_vqs"]
    handle_rx_vqs_map.clear()
    
    # Clear vhost_notify_params map to avoid stale entries (if it exists)
    if "vhost_notify_params" in b:
        vhost_notify_params_map = b["vhost_notify_params"]
        vhost_notify_params_map.clear()
    
    print("Waiting for events... Press Ctrl+C to stop\n")
    
    try:
        b["events"].open_perf_buffer(print_event)
        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    
    print("\nMonitoring stopped.")

if __name__ == "__main__":
    main()