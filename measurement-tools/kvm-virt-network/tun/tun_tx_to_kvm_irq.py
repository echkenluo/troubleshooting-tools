#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TUN TX Queue Interrupt Trace Tool

Traces the complete interrupt chain for specified TUN TX queue:

Kernel call chain:
  tun_net_xmit -> vhost_signal -> eventfd_signal -> irqfd_wakeup -> posted_int

Stage definitions (ordered by execution sequence):
  Stage 1: tun_net_xmit       - Packet enters TUN device
  Stage 2: vhost_signal       - vhost signals eventfd to notify KVM
  Stage 3: eventfd_signal     - eventfd entry point (called by vhost_signal)
  Stage 4: irqfd_wakeup       - KVM interrupt injection (key correlation point)
  Stage 5: posted_int         - Hardware posted interrupt delivery to vCPU

Correlation mechanism:
  - Stage 1->2: socket pointer (vq->private_data == &tfile->socket)
  - Stage 2->3->4: eventfd_ctx pointer (vq->call_ctx.ctx == eventfd == irqfd->eventfd)
  - Stage 4->5: GSI/vector (irqfd->gsi == vmx_deliver_posted_interrupt vector param)

Note: For MSI-X interrupts, QEMU typically configures GSI == Vector in the routing
table, enabling direct correlation between Stage 4 (irqfd_wakeup) and Stage 5
(vmx_deliver_posted_interrupt).

Based on proven implementation from vhost_queue_correlation_monitor.py.
"""

from __future__ import print_function
import argparse
import datetime
import json
import re
import socket
import struct
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
from time import sleep

# Kernel version detection and compatibility functions
def get_kernel_version():
    """
    Get kernel major.minor version tuple.
    Returns (major, minor) or (0, 0) on error.
    """
    try:
        import platform
        version_str = platform.release()
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

    This 64-byte difference affects call_ctx/error_ctx/log_ctx offset calculation.

    Detection method: Check if irqbypass module exists in /sys/module/
    This is more reliable than distro detection as it directly reflects
    the actual kernel configuration.

    Returns True if 5.x layout (with vhost_vring_call) is needed.
    """
    major, minor = get_kernel_version()
    if major < 5:
        return False

    # Primary detection: check if irqbypass module is loaded
    if has_irqbypass_module():
        return True

    # Fallback: openEuler 5.x without irqbypass uses 4.x layout
    distro = get_distro_id()
    if distro == 'openeuler':
        return False

    # Other 5.x kernels typically use 5.x layout
    return True

# Data structures based on vhost_queue_correlation_monitor.py
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

class QueueKey(ct.Structure):
    _fields_ = [
        ("sock_ptr", ct.c_uint64),
        ("queue_index", ct.c_uint32),
        ("dev_name", ct.c_char * 16),
        ("timestamp", ct.c_uint64),
    ]

class InterruptTraceEvent(ct.Structure):
    _fields_ = [
        ("timestamp", ct.c_uint64),
        ("stage", ct.c_uint8),
        ("cpu_id", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_name", ct.c_char * 16),
        ("queue_index", ct.c_uint32),
        ("sock_ptr", ct.c_uint64),
        ("eventfd_ctx", ct.c_uint64),
        ("vq_ptr", ct.c_uint64),
        ("gsi", ct.c_uint32),
        ("delay_ns", ct.c_uint64),
        # Packet info from tun_net_xmit
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("protocol", ct.c_uint8),
        # ICMP fields
        ("icmp_id", ct.c_uint16),
        ("icmp_seq", ct.c_uint16),
        ("icmp_type", ct.c_uint8),
        ("icmp_code", ct.c_uint8),
    ]

# BPF program with proven structures and implementation
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
#include <linux/eventfd.h>
#include <linux/wait.h>
#include <linux/kvm_host.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <linux/icmp.h>

// Packet filter macros (set via Python string substitution)
#define FILTER_SRC_IP 0x%x
#define FILTER_DST_IP 0x%x
#define FILTER_SRC_PORT %d
#define FILTER_DST_PORT %d
#define FILTER_PROTOCOL %d   // 0=all, 6=TCP, 17=UDP, 1=ICMP
#define FILTER_ICMP_ID %d    // 0=any
#define FILTER_ICMP_SEQ %d   // 0=any

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

// Proven macros from vhost_queue_correlation_monitor.py
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

// Proven TUN structures from vhost_queue_correlation_monitor.py
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

// Proven VHOST structures from vhost_queue_correlation_monitor.py
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
// Renamed to avoid conflict with kernel header
struct bpf_irq_bypass_producer {
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
// Renamed to avoid conflict with kernel header
struct bpf_vhost_vring_call {
    struct eventfd_ctx *ctx;                // 8 bytes
    struct bpf_irq_bypass_producer producer;    // 64 bytes
};  // Total: 72 bytes

// KERNEL_VERSION_5X controls which structure layout to use
// Set via Python based on kernel version detection
#ifndef KERNEL_VERSION_5X
#define KERNEL_VERSION_5X 0
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
    struct bpf_vhost_vring_call call_ctx;
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
};

// Complete kvm_kernel_irqfd structure definition - based on include/linux/kvm_irqfd.h
// Note: Fixed layout for CentOS 7 / kernel 4.19.90 - removed non-existent irq_entry_cache field
struct kvm_kernel_irqfd {
    /* Used for MSI fast-path */
    struct kvm *kvm;
    wait_queue_entry_t wait;
    /* Update side is protected by irqfds.lock */
    struct kvm_kernel_irq_routing_entry irq_entry;
    seqcount_t irq_entry_sc;
    /* Used for level IRQ fast-path */
    int gsi;
    struct work_struct inject;
    /* The resampler used by this irqfd (resampler-only) */
    void *resampler;  // struct kvm_kernel_irqfd_resampler *
    /* Eventfd notified on resample (resampler-only) */
    struct eventfd_ctx *resamplefd;
    /* Entry in list of irqfds for a resampler (resampler-only) */
    struct list_head resampler_link;
    /* Used for setup/shutdown */
    struct eventfd_ctx *eventfd;
    struct list_head list;
    poll_table pt;
    struct work_struct shutdown;
    void *consumer;   // struct irq_bypass_consumer
    void *producer;   // struct irq_bypass_producer *
};

// Data structures for interrupt chain tracking
struct queue_key {
    u64 sock_ptr;        // Unique sock pointer for this queue
    u32 queue_index;     // Queue index
    char dev_name[16];   // Device name
    u64 timestamp;       // Timestamp from Stage 1 for delay calculation
};

struct interrupt_connection {
    u64 sock_ptr;        // TUN -> VHOST connection
    u64 eventfd_ctx;     // VHOST -> IRQFD connection
    char dev_name[16];   // Device name
    u32 queue_index;     // Queue index
    u64 timestamp;       // Timestamp for sequence validation
};

// GSI to queue mapping for Stage 4 -> Stage 5 correlation
struct gsi_queue_info {
    u64 eventfd_ctx;     // eventfd_ctx from Stage 4
    u64 sock_ptr;        // sock_ptr for queue identification
    char dev_name[16];   // Device name
    u32 queue_index;     // Queue index
    u64 timestamp;       // Timestamp from Stage 4
};

struct interrupt_trace_event {
    u64 timestamp;
    u8 stage;
    u32 cpu_id;
    u32 pid;
    char comm[16];
    char dev_name[16];
    u32 queue_index;
    u64 sock_ptr;
    u64 eventfd_ctx;
    u64 vq_ptr;
    u32 gsi;
    u64 delay_ns;
    // Packet info from tun_net_xmit
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    // ICMP fields
    u16 icmp_id;
    u16 icmp_seq;
    u8 icmp_type;
    u8 icmp_code;
};

// BPF Maps for interrupt chain tracking
BPF_HASH(target_queues, u64, struct queue_key, 256);           // sock_ptr -> queue info
BPF_HASH(interrupt_chains, u64, struct interrupt_connection, 256); // eventfd_ctx -> connection
BPF_HASH(sequence_check, u64, u64, 256);                       // eventfd_ctx -> last_stage
BPF_HASH(gsi_to_queue, u32, struct gsi_queue_info, 256);       // gsi -> queue info (Stage 4->5 correlation)

// Device and queue filtering
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);

// Event output
BPF_PERF_OUTPUT(interrupt_events);

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

// Helper function to submit events
static inline void submit_interrupt_event(struct pt_regs *ctx, struct interrupt_trace_event *event) {
    event->timestamp = bpf_ktime_get_ns();
    event->cpu_id = bpf_get_smp_processor_id();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    interrupt_events.perf_submit(ctx, event, sizeof(*event));
}

// Packet filter function - returns 1 if packet matches filter, 0 otherwise
static inline int packet_filter(u32 saddr, u32 daddr, u8 protocol,
                                u16 sport, u16 dport,
                                u16 icmp_id, u16 icmp_seq) {
    // Protocol filter
    if (FILTER_PROTOCOL != 0 && protocol != FILTER_PROTOCOL)
        return 0;

    // IP filter
    if (FILTER_SRC_IP != 0 && saddr != FILTER_SRC_IP)
        return 0;
    if (FILTER_DST_IP != 0 && daddr != FILTER_DST_IP)
        return 0;

    // Port filter (TCP/UDP)
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        if (FILTER_SRC_PORT != 0 && sport != htons(FILTER_SRC_PORT))
            return 0;
        if (FILTER_DST_PORT != 0 && dport != htons(FILTER_DST_PORT))
            return 0;
    }

    // ICMP filter
    if (protocol == IPPROTO_ICMP) {
        if (FILTER_ICMP_ID != 0 && icmp_id != htons(FILTER_ICMP_ID))
            return 0;
        if (FILTER_ICMP_SEQ != 0 && icmp_seq != htons(FILTER_ICMP_SEQ))
            return 0;
    }

    return 1;
}

// Stage 1: tun_net_xmit - Based on proven implementation
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !dev) return 0;
    
    // Apply device filter
    if (!name_filter(dev)) return 0;
    
    u32 queue_index = skb->queue_mapping;
    
    // Check queue filter - KEY FILTER POINT from vhost_queue_correlation_monitor.py
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;  // Not our target queue
        }
    }
    
    // Get TUN structure using proven approach
    u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    struct tun_struct *tun = (struct tun_struct *)((char *)dev + aligned_size);
    
    u32 tun_numqueues = 0;
    READ_FIELD(&tun_numqueues, tun, numqueues);
    
    if (queue_index >= tun_numqueues || queue_index >= 256) {
        return 0;
    }
    
    // Get tfile for this queue using proven pointer arithmetic
    struct tun_file *tfile = NULL;
    if (queue_index < tun_numqueues && tun_numqueues > 0 && queue_index < 256) {
        void **tfile_ptr_addr = (void**)((char*)tun + queue_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL;
        }
    }
    if (!tfile) {
        return 0;
    }
    
    // Get socket pointer from tfile - PROVEN APPROACH
    u64 sock_ptr = (u64)&tfile->socket;

    // Extract packet information using skb->head + offset approach (more reliable)
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    u8 protocol = 0;
    u16 icmp_id = 0, icmp_seq = 0;
    u8 icmp_type = 0, icmp_code = 0;

    unsigned char *head = NULL;
    u16 network_header_offset = 0;
    u16 transport_header_offset = 0;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) < 0)
        goto skip_packet_info;
    if (bpf_probe_read_kernel(&network_header_offset, sizeof(network_header_offset), &skb->network_header) < 0)
        goto skip_packet_info;

    if (network_header_offset == (u16)~0U || network_header_offset > 2048)
        goto skip_packet_info;

    // Read IP header
    struct iphdr ip = {};
    if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header_offset) < 0)
        goto skip_packet_info;

    saddr = ip.saddr;
    daddr = ip.daddr;
    protocol = ip.protocol;

    // Calculate transport header offset
    u8 ip_ihl = ip.ihl & 0x0F;
    if (ip_ihl < 5) ip_ihl = 5;
    u16 ip_hdr_len = ip_ihl * 4;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr tcp = {};
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), head + network_header_offset + ip_hdr_len) == 0) {
            sport = tcp.source;
            dport = tcp.dest;
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr udp = {};
        if (bpf_probe_read_kernel(&udp, sizeof(udp), head + network_header_offset + ip_hdr_len) == 0) {
            sport = udp.source;
            dport = udp.dest;
        }
    } else if (protocol == IPPROTO_ICMP) {
        struct icmphdr icmp = {};
        if (bpf_probe_read_kernel(&icmp, sizeof(icmp), head + network_header_offset + ip_hdr_len) == 0) {
            icmp_type = icmp.type;
            icmp_code = icmp.code;
            icmp_id = icmp.un.echo.id;
            icmp_seq = icmp.un.echo.sequence;
        }
    }

skip_packet_info:

    // Apply packet filter
    if (!packet_filter(saddr, daddr, protocol, sport, dport, icmp_id, icmp_seq))
        return 0;

    // Register this queue as target AFTER filter passes (for Stage 2-5 correlation)
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_index;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), dev->name);
    qkey.timestamp = bpf_ktime_get_ns();  // Store timestamp for Stage 2 delay calculation
    target_queues.update(&sock_ptr, &qkey);

    // Emit Stage 1 event
    struct interrupt_trace_event event = {};
    event.stage = 1;  // tun_net_xmit
    // Manual copy instead of __builtin_memcpy to avoid BPF issues
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = qkey.dev_name[i];
    }
    event.queue_index = queue_index;
    event.sock_ptr = sock_ptr;
    event.saddr = saddr;
    event.daddr = daddr;
    event.sport = sport;
    event.dport = dport;
    event.protocol = protocol;
    event.delay_ns = 0;
    event.icmp_id = icmp_id;
    event.icmp_seq = icmp_seq;
    event.icmp_type = icmp_type;
    event.icmp_code = icmp_code;

    submit_interrupt_event(ctx, &event);
    return 0;
}

// Stage 2: vhost_add_used_and_signal_n - Based on proven implementation
// Note: vhost_signal is inlined into vhost_add_used_and_signal_n on kernel 5.x
// Function signature: vhost_add_used_and_signal_n(dev, vq, heads, count)
// Same parameters as vhost_signal(dev, vq) in first two positions
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = (struct vhost_virtqueue *)PT_REGS_PARM2(ctx);

    if (!vq) return 0;

    // Get sock pointer from private_data using proven approach
    void *private_data = NULL;
    READ_FIELD(&private_data, vq, private_data);

    u64 sock_ptr = (u64)private_data;

    // Check if this is our target queue (sock-based filtering)
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;  // Not our target queue
    }

    // Get eventfd_ctx for chain connection
    // Use hardcoded offset because struct mutex size varies between kernel configs
    // Measured offset on CentOS 5.10: call_ctx.ctx is at offset 104
    // Measured offset on openEuler 4.19: call_ctx is at offset 104
    struct eventfd_ctx *eventfd_ptr = NULL;
#if KERNEL_VERSION_5X
    // Kernel 5.x: call_ctx.ctx at offset 104 (measured)
    bpf_probe_read_kernel(&eventfd_ptr, sizeof(eventfd_ptr), (char *)vq + 104);
#else
    // Kernel 4.x: call_ctx at offset 104 (same offset, direct pointer)
    bpf_probe_read_kernel(&eventfd_ptr, sizeof(eventfd_ptr), (char *)vq + 104);
#endif
    u64 eventfd_ctx = (u64)eventfd_ptr;

    // Validate eventfd_ctx is a valid kernel pointer
    // Note: ARM64 kernel pointers can start with 0xff3f... not just 0xffff...
    if (!eventfd_ptr || eventfd_ctx < 0xff00000000000000ULL) return 0;
    
    // Calculate delay from Stage 1 (tun_net_xmit)
    u64 timestamp = bpf_ktime_get_ns();
    u64 delay_from_stage1 = timestamp - qkey->timestamp;

    // Save interrupt chain connection for irqfd_inject to use
    struct interrupt_connection ic_info = {};
    ic_info.sock_ptr = sock_ptr;
    ic_info.eventfd_ctx = eventfd_ctx;
    // Manual copy instead of __builtin_memcpy
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        ic_info.dev_name[i] = qkey->dev_name[i];
    }
    ic_info.queue_index = qkey->queue_index;
    ic_info.timestamp = timestamp;
    interrupt_chains.update(&eventfd_ctx, &ic_info);

    // Update sequence check - Stage 2 should come after Stage 1
    u64 current_stage = 2;
    sequence_check.update(&eventfd_ctx, &current_stage);

    // Delete target_queues entry for one-shot correlation
    // This ensures Stage 2-5 only fire for filtered packets
    target_queues.delete(&sock_ptr);

    // Emit Stage 2 event with delay from Stage 1
    struct interrupt_trace_event event = {};
    event.stage = 2;  // vhost_signal
    // Manual copy instead of __builtin_memcpy to avoid BPF issues
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = qkey->dev_name[i];
    }
    event.queue_index = qkey->queue_index;
    event.sock_ptr = sock_ptr;
    event.eventfd_ctx = eventfd_ctx;
    event.vq_ptr = (u64)vq;
    event.delay_ns = delay_from_stage1;  // Delay from Stage 1 (tun_net_xmit)

    submit_interrupt_event(ctx, &event);
    return 0;
}

// Stage 4: irqfd_wakeup - KVM interrupt injection triggered by eventfd
// Called from within eventfd_signal via wake_up_locked_poll
// This is the key correlation point with GSI information
//
// ============================================================================
// kvm_kernel_irqfd Structure Layout and Offset Calculation
// ============================================================================
// Source: include/linux/kvm_irqfd.h
//
// struct kvm_kernel_irqfd {
//     struct kvm *kvm;                                // offset 0,  size 8
//     wait_queue_entry_t wait;                        // offset 8,  size 40
//     struct kvm_kernel_irq_routing_entry irq_entry;  // offset 48, size 24
//     [seqcount field - TYPE DIFFERS BY VERSION]      // offset 72, size varies!
//     int gsi;                                        // after seqcount
//     struct work_struct inject;                      // size 32
//     struct kvm_kernel_irqfd_resampler *resampler;   // size 8
//     struct eventfd_ctx *resamplefd;                 // size 8
//     struct list_head resampler_link;                // size 16
//     struct eventfd_ctx *eventfd;                    // <-- TARGET FIELD
//     ...
// };
//
// ROOT CAUSE OF OFFSET DIFFERENCE:
// --------------------------------
// The seqcount field type changed between kernel versions:
//
//   4.19: seqcount_t irq_entry_sc;
//         - seqcount_t = { unsigned sequence; } = 4 bytes
//
//   5.10: seqcount_spinlock_t irq_entry_sc;
//         - seqcount_spinlock_t = { seqcount_t seqcount; spinlock_t *lock; }
//         - Size = 4 + 8 = 12 bytes, aligned to 16 bytes
//         - The lock pointer is included when CONFIG_LOCKDEP || CONFIG_PREEMPT_RT
//
// This 16-byte size difference (seqcount_spinlock_t vs seqcount_t) causes
// all subsequent fields (gsi, inject, eventfd, etc.) to shift by 16 bytes.
//
// Verified offsets (via BPF runtime probing on actual kernels):
//   openEuler 4.19: eventfd at offset 216, gsi at offset 72
//   openEuler 5.10: eventfd at offset 232, gsi at offset 72
//   Difference: 232 - 216 = 16 bytes (matches seqcount type size difference)
//
// Note: gsi is at the same offset (72) because it comes BEFORE the size
// difference takes effect in the structure layout.
// ============================================================================
int trace_irqfd_wakeup(struct pt_regs *ctx) {
    wait_queue_entry_t *wait = (wait_queue_entry_t *)PT_REGS_PARM1(ctx);
    void *key = (void *)PT_REGS_PARM4(ctx);

    if (!wait) return 0;

    // Check EPOLLIN flag - irqfd_wakeup checks (flags & EPOLLIN) before injecting
    u64 flags = (u64)key;
    if (!(flags & 0x1)) return 0;

    // Get kvm_kernel_irqfd structure pointer using container_of logic
    // container_of(wait, struct kvm_kernel_irqfd, wait)
    // wait field is at offset 8 in kvm_kernel_irqfd (after struct kvm *kvm)
    void *irqfd = (void *)((char *)wait - 8);

    if (!irqfd) return 0;

    // Read eventfd_ctx and gsi using kernel-version-specific offsets
    struct eventfd_ctx *eventfd = NULL;
    int gsi = 0;

#if KERNEL_VERSION_5X
    // 5.10: seqcount_spinlock_t (16 bytes) shifts eventfd to offset 232
    bpf_probe_read_kernel(&eventfd, sizeof(eventfd), (char *)irqfd + 232);
    bpf_probe_read_kernel(&gsi, sizeof(gsi), (char *)irqfd + 72);
#else
    // 4.19: seqcount_t (4 bytes), eventfd at offset 216
    bpf_probe_read_kernel(&eventfd, sizeof(eventfd), (char *)irqfd + 216);
    bpf_probe_read_kernel(&gsi, sizeof(gsi), (char *)irqfd + 72);
#endif

    u64 eventfd_ctx = (u64)eventfd;

    // Validate eventfd_ctx is a valid kernel pointer
    // Note: ARM64 kernel pointers can start with 0xff3f... not just 0xffff...
    // Use 0xff00000000000000 as threshold for broader compatibility
    if (!eventfd || eventfd_ctx < 0xff00000000000000ULL) {
        return 0;
    }

    // Chain validation: only fire Stage 4 if Stage 3 created matching eventfd_ctx entry
    struct interrupt_connection *ic_info = interrupt_chains.lookup(&eventfd_ctx);
    if (!ic_info) {
        return 0;  // No matching chain - not our target
    }

    // Check sequence - should be 3 (from eventfd_signal)
    u64 *last_stage = sequence_check.lookup(&eventfd_ctx);
    if (!last_stage || *last_stage != 3) {
        return 0;  // Only emit if we have a valid Stage 3 entry
    }

    // Validate GSI range for MSI interrupts (typically 24-255)
    if (gsi < 24 || gsi > 255) {
        return 0;
    }

    u64 timestamp = bpf_ktime_get_ns();
    u64 delay_ns = timestamp - ic_info->timestamp;

    // Update sequence to Stage 4
    u64 current_stage = 4;
    sequence_check.update(&eventfd_ctx, &current_stage);

    // Update gsi_to_queue map for Stage 5 correlation
    // Key: GSI (which equals vector in vmx_deliver_posted_interrupt)
    u32 gsi_key = (u32)gsi;
    struct gsi_queue_info gsi_info = {};
    gsi_info.eventfd_ctx = eventfd_ctx;
    gsi_info.sock_ptr = ic_info->sock_ptr;
    gsi_info.queue_index = ic_info->queue_index;
    gsi_info.timestamp = timestamp;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        gsi_info.dev_name[i] = ic_info->dev_name[i];
    }
    gsi_to_queue.update(&gsi_key, &gsi_info);

    // Emit Stage 4 event - irqfd_wakeup
    struct interrupt_trace_event event = {};
    event.stage = 4;  // irqfd_wakeup
    // Copy device name and queue info from interrupt chain
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = ic_info->dev_name[i];
    }
    event.queue_index = ic_info->queue_index;
    event.sock_ptr = ic_info->sock_ptr;
    event.eventfd_ctx = eventfd_ctx;
    event.gsi = (u32)gsi;
    event.delay_ns = delay_ns;

    submit_interrupt_event(ctx, &event);

    return 0;
}

// Stage 4 Alternative: kvm_set_irq - Called by irqfd_inject
int trace_kvm_set_irq(struct pt_regs *ctx) {
    struct kvm *kvm = (struct kvm *)PT_REGS_PARM1(ctx);
    int irq_source_id = (int)PT_REGS_PARM2(ctx);
    u32 gsi = (u32)PT_REGS_PARM3(ctx);
    int level = (int)PT_REGS_PARM4(ctx);

    if (!kvm || gsi == 0) return 0;  // Filter out invalid calls

    // We need to find a way to match this with our interrupt chains
    // Since kvm_set_irq is called by irqfd_inject, we'll check all active chains
    // and see if any have recent vhost_signal activity

    u64 timestamp = bpf_ktime_get_ns();

    // Check all active interrupt chains
    u64 eventfd_ctx = 0;
    struct interrupt_connection *ic_info = NULL;

    // We'll emit events for any kvm_set_irq with level=1 (interrupt assertion)
    // that matches a known GSI range (typically 24-31 for MSI)
    if (level == 1 && gsi >= 24 && gsi <= 255) {
        // Try to find a matching interrupt chain by searching active chains
        // For now, emit the event and let user-space correlate

        struct interrupt_trace_event event = {};
        event.stage = 4;  // kvm_set_irq (alternative to irqfd_wakeup)
        event.gsi = gsi;
        event.delay_ns = 0;  // Cannot calculate without eventfd_ctx match

        submit_interrupt_event(ctx, &event);
    }

    return 0;
}

// Stage 3: eventfd_signal - Called by vhost_signal
// Call chain: vhost_signal -> eventfd_signal -> wake_up_locked_poll -> irqfd_wakeup
// eventfd_signal(struct eventfd_ctx *ctx, __u64 n)
int trace_eventfd_signal(struct pt_regs *ctx) {
    struct eventfd_ctx *eventfd = (struct eventfd_ctx *)PT_REGS_PARM1(ctx);

    if (!eventfd) return 0;

    u64 eventfd_ctx = (u64)eventfd;

    // Only emit event if this eventfd matches our interrupt chain
    struct interrupt_connection *ic_info = interrupt_chains.lookup(&eventfd_ctx);
    if (!ic_info) {
        return 0;  // Not our target eventfd
    }

    u64 timestamp = bpf_ktime_get_ns();
    u64 delay_ns = timestamp - ic_info->timestamp;

    // Check current stage - should be 2 (from vhost_signal)
    u64 *last_stage = sequence_check.lookup(&eventfd_ctx);
    if (!last_stage || *last_stage != 2) {
        return 0;  // Only emit if we have a valid Stage 2 entry
    }

    // Update sequence to Stage 3
    u64 current_stage = 3;
    sequence_check.update(&eventfd_ctx, &current_stage);

    // Emit Stage 3 event - eventfd_signal
    struct interrupt_trace_event event = {};
    event.stage = 3;  // eventfd_signal
    // Copy device name and queue info from interrupt chain
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = ic_info->dev_name[i];
    }
    event.queue_index = ic_info->queue_index;
    event.sock_ptr = ic_info->sock_ptr;
    event.eventfd_ctx = eventfd_ctx;
    event.delay_ns = delay_ns;

    submit_interrupt_event(ctx, &event);
    return 0;
}

// Stage 5: vmx_deliver_posted_interrupt - IRQ bypass hardware path
// Called when using IRQ bypass (irqbypass module) for posted interrupts
// This is the hardware fast path for MSI-X interrupt delivery with APICv enabled
// Correlation: vector == GSI, lookup gsi_to_queue map populated by Stage 4
// Sequence check: only emit if Stage 4 just happened (sequence_check == 4)
int trace_vmx_deliver_posted_interrupt(struct pt_regs *ctx) {
    // vmx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
    void *vcpu = (void *)PT_REGS_PARM1(ctx);
    int vector = (int)PT_REGS_PARM2(ctx);

    if (!vcpu) return 0;

    // Filter for MSI interrupt vectors (typically >= 0x20)
    if (vector < 0x20) return 0;

    // Correlate with Stage 4 via vector (vector == GSI for MSI-X)
    u32 gsi_key = (u32)vector;
    struct gsi_queue_info *gsi_info = gsi_to_queue.lookup(&gsi_key);
    if (!gsi_info) {
        return 0;  // Not our target - no matching GSI from Stage 4
    }

    // Sequence check: only emit if Stage 4 just happened for this eventfd_ctx
    u64 eventfd_ctx = gsi_info->eventfd_ctx;
    u64 *last_stage = sequence_check.lookup(&eventfd_ctx);
    if (!last_stage || *last_stage != 4) {
        return 0;  // Only emit if Stage 4 was the previous stage
    }

    u64 timestamp = bpf_ktime_get_ns();
    u64 delay_ns = timestamp - gsi_info->timestamp;

    // Update sequence to Stage 5 (marks this chain as complete)
    u64 current_stage = 5;
    sequence_check.update(&eventfd_ctx, &current_stage);

    // Emit Stage 5 event - correlated with our interrupt chain
    struct interrupt_trace_event event = {};
    event.stage = 5;  // Stage 5: vmx_deliver_posted_interrupt (hardware path)
    // Copy device name and queue info from gsi_to_queue
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        event.dev_name[i] = gsi_info->dev_name[i];
    }
    event.queue_index = gsi_info->queue_index;
    event.sock_ptr = gsi_info->sock_ptr;
    event.eventfd_ctx = eventfd_ctx;
    event.gsi = (u32)vector;  // vector == GSI
    event.delay_ns = delay_ns;
    event.vq_ptr = (u64)vcpu;

    submit_interrupt_event(ctx, &event);

    // Clean up correlation entries after chain completes (one-shot correlation)
    gsi_to_queue.delete(&gsi_key);
    interrupt_chains.delete(&eventfd_ctx);
    sequence_check.delete(&eventfd_ctx);

    return 0;
}
"""

# Global variables for event processing
interrupt_traces = []
chain_stats = {}
sequence_errors = 0
# Track in-flight chain delays for per-packet total calculation
# eventfd_ctx -> {stage: delay_ns}
inflight_chain_delays = {}
# Stage names ordered by execution sequence
stage_names = {
    1: "tun_net_xmit",
    2: "vhost_signal",
    3: "eventfd_signal",   # Called by vhost_signal
    4: "irqfd_wakeup",     # Key correlation point - KVM interrupt injection
    5: "posted_int"        # vmx_deliver_posted_interrupt (hardware path, may not correlate)
}

def process_interrupt_event(cpu, data, size):
    """Process interrupt trace events with enhanced correlation"""
    global sequence_errors
    
    event = ct.cast(data, ct.POINTER(InterruptTraceEvent)).contents
    
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    # Simplified correlation - BPF now handles the correlation properly
    if event.dev_name and event.queue_index < 256:
        queue_key = "{}:q{}".format(event.dev_name.decode('utf-8'), event.queue_index)
    else:
        queue_key = "unknown"
    calculated_delay = event.delay_ns
    
    event_data = {
        'timestamp': event.timestamp,
        'stage': event.stage,
        'stage_name': stage_names.get(event.stage, 'unknown'),
        'cpu_id': event.cpu_id,
        'pid': event.pid,
        'comm': event.comm.decode('utf-8', 'replace'),
        'queue_key': queue_key,
        'sock_ptr': event.sock_ptr,
        'eventfd_ctx': event.eventfd_ctx,
        'vq_ptr': event.vq_ptr,
        'gsi': event.gsi,
        'delay_ns': calculated_delay,
        'saddr': event.saddr,
        'daddr': event.daddr,
        'sport': event.sport,
        'dport': event.dport,
        'protocol': event.protocol,
        'icmp_id': event.icmp_id,
        'icmp_seq': event.icmp_seq,
        'icmp_type': event.icmp_type,
        'icmp_code': event.icmp_code
    }
    
    interrupt_traces.append(event_data)
    
    if queue_key not in chain_stats:
        chain_stats[queue_key] = {}
    stage = event.stage
    if stage not in chain_stats[queue_key]:
        chain_stats[queue_key][stage] = 0
    chain_stats[queue_key][stage] += 1
    
    # Real-time output with packet info
    delay_ms = calculated_delay / 1000000.0 if calculated_delay > 0 else 0
    
    packet_info = ""
    if event.stage == 1 and event.saddr > 0:  # tun_net_xmit with packet info
        try:
            # IP stored in network byte order, read as native int on little-endian
            # Use '<I' to pack back to original network byte order
            src_ip = socket.inet_ntoa(struct.pack('<I', event.saddr))
            dst_ip = socket.inet_ntoa(struct.pack('<I', event.daddr))
            if event.protocol == 6:  # TCP
                packet_info = " TCP {}:{} -> {}:{}".format(
                    src_ip, socket.ntohs(event.sport), dst_ip, socket.ntohs(event.dport))
            elif event.protocol == 17:  # UDP
                packet_info = " UDP {}:{} -> {}:{}".format(
                    src_ip, socket.ntohs(event.sport), dst_ip, socket.ntohs(event.dport))
            elif event.protocol == 1:  # ICMP
                packet_info = " ICMP {} -> {} type={} code={} id={} seq={}".format(
                    src_ip, dst_ip, event.icmp_type, event.icmp_code,
                    socket.ntohs(event.icmp_id), socket.ntohs(event.icmp_seq))
            else:
                packet_info = " IP {} -> {} proto={}".format(src_ip, dst_ip, event.protocol)
        except:
            packet_info = " [packet info parse error]"
    
    # Format output based on stage - only show relevant fields for each stage
    stage = event.stage
    base_info = "TUN TX INTERRUPT [{}] Stage {} [{}]: Time={}".format(
        queue_key, stage, stage_names.get(stage, 'unknown'), timestamp_str)

    if stage == 1:
        # Stage 1: tun_net_xmit - sock from tfile->socket, queue from skb->queue_mapping
        detail = " Queue={} Sock(tfile)=0x{:x}".format(event.queue_index, event.sock_ptr)
    elif stage == 2:
        # Stage 2: vhost_signal - sock from vq->private_data, eventfd from vq->call_ctx.ctx
        detail = " Sock(vq)=0x{:x} EventFD(vq)=0x{:x} VQ=0x{:x} Delay={:.3f}ms".format(
            event.sock_ptr, event.eventfd_ctx, event.vq_ptr, delay_ms)
    elif stage == 3:
        # Stage 3: eventfd_signal - eventfd is function parameter
        detail = " EventFD(arg)=0x{:x} Delay={:.3f}ms".format(
            event.eventfd_ctx, delay_ms)
    elif stage == 4:
        # Stage 4: irqfd_wakeup - eventfd and gsi from irqfd structure
        detail = " EventFD(irqfd)=0x{:x} GSI(irqfd)={} Delay={:.3f}ms".format(
            event.eventfd_ctx, event.gsi, delay_ms)
    elif stage == 5:
        # Stage 5: vmx_deliver_posted_interrupt - correlated via GSI/vector from Stage 4
        detail = " Vector(arg)={} VCPU=0x{:x} Delay={:.3f}ms".format(event.gsi, event.vq_ptr, delay_ms)
    else:
        detail = " Sock=0x{:x} EventFD=0x{:x} GSI={} VQ=0x{:x} Delay={:.3f}ms".format(
            event.sock_ptr, event.eventfd_ctx, event.gsi, event.vq_ptr, delay_ms)

    common_info = " CPU={} PID={} COMM={}{}".format(
        event.cpu_id, event.pid, event.comm.decode('utf-8', 'replace'), packet_info)

    print(base_info + detail + common_info)

    # Track per-packet chain delays and print total when chain completes
    if event.stage >= 2 and event.eventfd_ctx > 0:
        key = event.eventfd_ctx
        if key not in inflight_chain_delays:
            inflight_chain_delays[key] = {}
        if calculated_delay > 0:
            inflight_chain_delays[key][event.stage] = calculated_delay

        # When Stage 5 completes, print per-packet total delay
        if event.stage == 5:
            chain = inflight_chain_delays.get(key, {})
            if 2 in chain and 3 in chain and 4 in chain and 5 in chain:
                total_delay_ns = chain[2] + chain[3] + chain[4] + chain[5]
                total_delay_ms = total_delay_ns / 1000000.0
                print("  -> Total(S1->S5): {:.3f}ms".format(total_delay_ms))
            # Clean up completed chain
            if key in inflight_chain_delays:
                del inflight_chain_delays[key]

def analyze_interrupt_chains():
    """Analyze interrupt chain completeness and sequence"""
    if not chain_stats:
        print("\nNo chain data collected yet.")
        return
    
    print("\n" + "="*80)
    print("TUN TX INTERRUPT CHAIN ANALYSIS")
    print("="*80)
    
    for queue, stages in chain_stats.items():
        print("\nQueue: {}".format(queue))
        print("-" * 50)
        
        # Count by stage
        print("Stage Event Counts:")
        for stage in sorted(stages.keys()):
            print("  Stage {} [{}]: {} events".format(stage, stage_names.get(stage, 'unknown'), stages[stage]))
        
        # Chain completeness analysis
        if len(stages) > 1:
            stage_counts = list(stages.values())
            min_count = min(stage_counts)
            max_count = max(stage_counts)
            completeness = (min_count / max_count * 100) if max_count > 0 else 0
            print("  Chain Completeness: {:.1f}% (min {} / max {} events)".format(
                completeness, min_count, max_count))
            
            # Expected chain: Stage 1 -> Stage 2 -> Stage 3 -> Stage 4 -> Stage 5
            if 1 in stages and 2 in stages and 3 in stages and 4 in stages and 5 in stages:
                print("  COMPLETE CHAIN: tun_net_xmit -> vhost_signal -> eventfd_signal -> irqfd_wakeup -> posted_int")
            elif 1 in stages and 2 in stages and 3 in stages and 4 in stages:
                print("  PARTIAL CHAIN: tun_net_xmit -> vhost_signal -> eventfd_signal -> irqfd_wakeup (missing posted_int)")
            elif 1 in stages and 2 in stages and 3 in stages:
                print("  PARTIAL CHAIN: tun_net_xmit -> vhost_signal -> eventfd_signal (missing irqfd_wakeup)")
            elif 1 in stages and 2 in stages:
                print("  PARTIAL CHAIN: tun_net_xmit -> vhost_signal (missing eventfd_signal)")
            elif 1 in stages:
                print("  INCOMPLETE: only tun_net_xmit detected")
            elif 2 in stages:
                print("  INCOMPLETE: only vhost_signal detected (missing tun_net_xmit)")
            else:
                print("  NO PROPER CHAIN DETECTED")
    
    if sequence_errors > 0:
        print("\nSEQUENCE ERRORS: {} out-of-order events detected".format(sequence_errors))

def print_statistics_summary():
    """Print comprehensive statistics"""
    if not interrupt_traces:
        print("\nNo interrupt traces collected yet.")
        return
    
    print("\n" + "="*80)
    print("TUN TX QUEUE INTERRUPT TRACING STATISTICS")
    print("="*80)
    
    # Overall stage distribution
    stage_counts = {}
    for trace in interrupt_traces:
        stage = trace['stage']
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
    
    print("\nOverall Stage Distribution:")
    for stage in sorted(stage_counts.keys()):
        print("  Stage {} [{}]: {} events".format(stage, stage_names.get(stage, 'unknown'), stage_counts[stage]))
    
    # Analyze interrupt chains
    analyze_interrupt_chains()
    
    # Show timing analysis for complete chains
    if len(stage_counts) >= 2:
        # Calculate average delays
        delays = [trace['delay_ns'] for trace in interrupt_traces if trace['delay_ns'] > 0]
        if delays:
            delays.sort()
            count = len(delays)
            avg_delay = sum(delays) / count / 1000.0  # Convert to microseconds
            p50_delay = delays[count//2] / 1000.0
            p90_delay = delays[int(count*0.9)] / 1000.0
            p99_delay = delays[int(count*0.99)] / 1000.0
            
            print("\nInterrupt Latency Analysis:")
            print("  Average delay: {:.1f}μs (from {} samples)".format(avg_delay, count))
            print("  P50 delay: {:.1f}μs".format(p50_delay))
            print("  P90 delay: {:.1f}μs".format(p90_delay))
            print("  P99 delay: {:.1f}μs".format(p99_delay))
    
    # Show packet type analysis
    protocols = {}
    for trace in interrupt_traces:
        if trace['stage'] == 1 and trace['protocol'] > 0:  # tun_net_xmit with valid protocol
            proto = trace['protocol']
            protocols[proto] = protocols.get(proto, 0) + 1
    
    if protocols:
        print("\nPacket Type Distribution:")
        proto_names = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            proto_name = proto_names.get(proto, 'Unknown({})'.format(proto))
            print("  {}: {} packets".format(proto_name, count))


def main():
    parser = argparse.ArgumentParser(
        description="TUN TX Queue Interrupt Trace Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Traces the complete interrupt chain for specified TUN TX queue:
  Stage 1: tun_net_xmit       - Packet enters TUN device (socket correlation)
  Stage 2: vhost_signal       - vhost signals eventfd (eventfd_ctx correlation)
  Stage 3: eventfd_signal     - eventfd entry point (called by vhost_signal)
  Stage 4: irqfd_wakeup       - KVM interrupt injection (key correlation point)
  Stage 5: posted_int         - Hardware posted interrupt (no correlation)

Kernel call chain:
  tun_net_xmit -> vhost_signal -> eventfd_signal -> irqfd_wakeup -> KVM

Correlation mechanism:
  - Stage 1->2: socket pointer (vq->private_data == &tfile->socket)
  - Stage 2->3->4: eventfd_ctx pointer (vq->call_ctx.ctx == eventfd == irqfd->eventfd)
  - Stage 4+: GSI for interrupt identification

Based on proven implementation from vhost_queue_correlation_monitor.py.

Examples:
  # Trace specific device and queue
  sudo %(prog)s --device vnet0 --queue 0

  # Enable detailed chain analysis with statistics
  sudo %(prog)s --device vnet0 --queue 0 --analyze-chains --stats-interval 5

  # Generate network traffic and trace
  sudo %(prog)s --device vnet0 --queue 0 --generate-traffic
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet0)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--analyze-chains", action="store_true", help="Enable interrupt chain analysis")
    parser.add_argument("--stats-interval", type=int, default=10, help="Statistics output interval in seconds (default: 10)")
    parser.add_argument("--output", "-o", help="Output JSON file for trace data")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--generate-traffic", action="store_true", help="Suggest commands to generate network traffic")
    # Packet filter arguments
    parser.add_argument("--src-ip", type=str, help="Filter by source IP address")
    parser.add_argument("--dst-ip", type=str, help="Filter by destination IP address")
    parser.add_argument("--protocol", type=str, choices=['tcp', 'udp', 'icmp', 'all'],
                        default='all', help="Filter by protocol (default: all)")
    parser.add_argument("--src-port", type=int, help="Filter by source port (TCP/UDP)")
    parser.add_argument("--dst-port", type=int, help="Filter by destination port (TCP/UDP)")
    parser.add_argument("--icmp-id", type=int, help="Filter by ICMP echo ID")
    parser.add_argument("--icmp-seq", type=int, help="Filter by ICMP echo sequence")

    args = parser.parse_args()
    
    if args.generate_traffic:
        print("Network Traffic Generation Commands:")
        print("# Generate ICMP traffic:")
        print("ping -c 10 <target_ip>")
        print("# Generate TCP traffic:")
        print("curl http://<target_ip>")
        print("# Generate UDP traffic:")
        print("nc -u <target_ip> 53")
        print("\nRun the trace tool in another terminal and then execute these commands.")
        return
    
    # Detect kernel version and set appropriate structure layout
    kernel_5x = needs_5x_vhost_layout()
    major, minor = get_kernel_version()
    distro = get_distro_id()
    irqbypass_loaded = has_irqbypass_module()

    print("Detected kernel version: {}.{}, distro: {}".format(major, minor, distro))
    print("IRQ bypass module: {}".format("loaded" if irqbypass_loaded else "not loaded"))
    print("Using {} vhost structure layout".format(
        "5.x (with vhost_vring_call, 72 bytes)" if kernel_5x else "4.x (pointer only, 8 bytes)"))

    # Load BPF program with kernel version macro
    try:
        bpf_program = bpf_text
        if kernel_5x:
            bpf_program = "#define KERNEL_VERSION_5X 1\n" + bpf_program

        # Convert IP address string to network byte order integer
        def ip_to_int(ip_str):
            if not ip_str:
                return 0
            # Use '<I' (little-endian) to match BPF's interpretation of network bytes
            return struct.unpack("<I", socket.inet_aton(ip_str))[0]

        # Protocol string to number mapping
        proto_map = {'all': 0, 'tcp': 6, 'udp': 17, 'icmp': 1}

        # Substitute filter values in BPF text
        filter_src_ip = ip_to_int(args.src_ip)
        filter_dst_ip = ip_to_int(args.dst_ip)
        filter_src_port = args.src_port if args.src_port else 0
        filter_dst_port = args.dst_port if args.dst_port else 0
        filter_protocol = proto_map.get(args.protocol, 0)
        filter_icmp_id = args.icmp_id if args.icmp_id else 0
        filter_icmp_seq = args.icmp_seq if args.icmp_seq else 0

        bpf_program = bpf_program % (
            filter_src_ip,
            filter_dst_ip,
            filter_src_port,
            filter_dst_port,
            filter_protocol,
            filter_icmp_id,
            filter_icmp_seq,
        )

        # Print active filters
        if any([args.src_ip, args.dst_ip, args.protocol != 'all',
                args.src_port, args.dst_port, args.icmp_id, args.icmp_seq]):
            print("Packet filters:")
            if args.protocol != 'all':
                print("  Protocol: {}".format(args.protocol.upper()))
            if args.src_ip:
                print("  Source IP: {}".format(args.src_ip))
            if args.dst_ip:
                print("  Destination IP: {}".format(args.dst_ip))
            if args.src_port:
                print("  Source Port: {}".format(args.src_port))
            if args.dst_port:
                print("  Destination Port: {}".format(args.dst_port))
            if args.icmp_id:
                print("  ICMP ID: {}".format(args.icmp_id))
            if args.icmp_seq:
                print("  ICMP Seq: {}".format(args.icmp_seq))

        b = BPF(text=bpf_program)

        # Attach proven probe points
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        print("Successfully attached to tun_net_xmit")

        b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_signal")
        print("Successfully attached to vhost_add_used_and_signal_n")
        
        # Stage 3: eventfd_signal - Called by vhost_signal
        try:
            b.attach_kprobe(event="eventfd_signal", fn_name="trace_eventfd_signal")
            print("Successfully attached to eventfd_signal")
        except Exception as e:
            print("Warning: eventfd_signal not available: {}".format(e))

        # Stage 4: irqfd_wakeup - KVM interrupt injection
        try:
            b.attach_kprobe(event="irqfd_wakeup", fn_name="trace_irqfd_wakeup")
            print("Successfully attached to irqfd_wakeup (KVM interrupt injection)")
        except Exception as e:
            if args.debug:
                print("Note: irqfd_wakeup not available: {}".format(e))

        # Stage 5: vmx_deliver_posted_interrupt - IRQ bypass hardware path (optional)
        # Note: This function doesn't have eventfd_ctx, so correlation may not work
        try:
            b.attach_kprobe(event="vmx_deliver_posted_interrupt", fn_name="trace_vmx_deliver_posted_interrupt")
            print("Successfully attached to vmx_deliver_posted_interrupt (IRQ bypass hardware path)")
        except Exception as e:
            if args.debug:
                print("Note: vmx_deliver_posted_interrupt not available: {}".format(e))
        
    except Exception as e:
        print("Failed to load BPF program: {}".format(e))
        if args.debug:
            print("BPF program source:")
            print(bpf_text)
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
    
    print("\n" + "="*80)
    print("TUN TX QUEUE INTERRUPT TRACING STARTED")
    print("="*80)
    print("Tracing: tun_net_xmit -> vhost_signal -> eventfd_signal -> irqfd_wakeup -> posted_int")
    print("Correlation: Stage 2->3->4 via eventfd_ctx, Stage 4->5 via GSI/vector")
    if args.analyze_chains:
        print("Chain analysis: ENABLED (interval: {}s)".format(args.stats_interval))
    print("Press Ctrl+C to stop\n")
    
    # Clear all maps for clean start
    print("Clearing BPF maps for clean state...")
    b["target_queues"].clear()
    b["interrupt_chains"].clear()
    b["sequence_check"].clear()
    b["gsi_to_queue"].clear()
    print("Maps cleared. Ready for tracing.\n")
    
    # Open perf buffer for events
    b["interrupt_events"].open_perf_buffer(process_interrupt_event)
    
    # Main event loop
    try:
        import time
        last_stats_time = time.time()
        
        while True:
            try:
                b.perf_buffer_poll(timeout=1000)  # Poll for 1 second
                
                # Print statistics periodically if chain analysis is enabled
                if args.analyze_chains:
                    current_time = time.time()
                    if current_time - last_stats_time >= args.stats_interval:
                        print_statistics_summary()
                        last_stats_time = current_time
                        
            except KeyboardInterrupt:
                break
                
    except KeyboardInterrupt:
        pass
    
    # Final statistics and output
    print("\n" + "="*80)
    print("TUN TX INTERRUPT TRACING STOPPED - FINAL SUMMARY")
    print("="*80)

    if args.analyze_chains:
        print_statistics_summary()

    # Output to JSON file if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(interrupt_traces, f, indent=2, default=str)
            print("\nTrace data saved to: {}".format(args.output))
        except Exception as e:
            print("Failed to save trace data: {}".format(e))
    
    print("\nTUN TX Queue Interrupt Tracing completed.")
    print("Total events collected: {}".format(len(interrupt_traces)))

if __name__ == "__main__":
    main()