#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vhost_queue_correlation_simple_k510.py - Kernel 5.10 compatible version
# This version handles the vhost_virtqueue structure changes in kernel 5.10+
# Key change: call_ctx changed from pointer to struct vhost_vring_call

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
import os
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

def get_kernel_version():
    """Get kernel version as tuple (major, minor, patch)"""
    release = os.uname()[2]
    match = re.match(r'(\d+)\.(\d+)\.?(\d*)', release)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        return (major, minor, patch)
    return (0, 0, 0)

def find_vhost_notify_symbol():
    """Find the actual vhost_notify function symbol (handles .isra suffix)"""
    try:
        with open('/proc/kallsyms', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    symbol = parts[2]
                    # Match vhost_notify or vhost_notify.isra.XX
                    if symbol == 'vhost_notify' or symbol.startswith('vhost_notify.isra.'):
                        return symbol
    except:
        pass
    return None

# BPF program for kernel 5.10+ (changed vhost_virtqueue structure)
bpf_text_k510 = """
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
#define VIRTIO_RING_F_EVENT_IDX 29

// Device name union for efficient comparison
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

// Use proven macros for field access
#define member_address(source_struct, source_member)            \\
        ({                                                      \\
                void* __ret;                                    \\
                __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \\
                __ret;                                          \\
})

#define member_read(destination, source_struct, source_member)  \\
        do{                                                      \\
                bpf_probe_read_kernel(                           \\
                destination,                                     \\
                sizeof(source_struct->source_member),            \\
                member_address(source_struct, source_member)     \\
                );                                               \\
} while(0)

#define READ_FIELD(dst, ptr, field)                                   \\
    do {                                                              \\
        typeof(ptr->field) __tmp;                                     \\
        bpf_probe_read_kernel(&__tmp, sizeof(__tmp), &ptr->field);    \\
        *(dst) = __tmp;                                               \\
    } while (0)


// TUN structures (unchanged between kernel versions)
struct tun_struct {
    struct tun_file __rcu   *tfiles[256];
    unsigned int            numqueues;
    unsigned int            flags;
    kuid_t                  owner;
    kgid_t                  group;
    struct net_device       *dev;
    netdev_features_t       set_features;
    int                     align;
    int                     vnet_hdr_sz;
    int                     sndbuf;
    struct sock_fprog       fprog;
    bool                    filter_attached;
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

// Kernel 5.10+ vhost structures with vhost_vring_call
// In 5.10, call_ctx changed from "struct eventfd_ctx *" to "struct vhost_vring_call"

struct vhost_vring_call {
    struct eventfd_ctx *ctx;
    // irq_bypass_producer follows but we don't need it
    // Size varies but we read ctx directly
};

struct vhost_work {
    struct llist_node node;
    void *fn;
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

// For kernel 5.10+, we use direct offset reading for vhost_virtqueue
// because the structure layout changed significantly with call_ctx becoming a struct

// Key structure to track queue
struct queue_key {
    u64 sock_ptr;
    u32 queue_index;
    char dev_name[16];
};

// Event data structure
struct queue_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];

    u64 sock_ptr;
    u32 queue_index;
    char dev_name[16];

    u8 event_type;  // 1=vhost_signal, 2=vhost_notify

    // VQ state
    u64 vq_ptr;
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

    // vhost_notify specific
    int ret_val;
    bool has_event_idx_feature;
    u16 avail_flags;
    u16 used_event_idx;
    bool guest_flags_valid;
    bool guest_event_valid;
};

// Maps
BPF_HASH(target_queues, u64, struct queue_key, 256);
BPF_PERF_OUTPUT(events);
BPF_ARRAY(name_map, union name_buf, 1);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_queue, u32, 1);
BPF_HASH(vhost_notify_params, u64, u64, 256);

// Device filter logic
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname = {};
    bpf_probe_read_kernel(&real_devname, IFNAMSIZ, dev->name);

    int key=0;
    union name_buf *leaf = name_map.lookup(&key);
    if(!leaf){
        return 1;
    }
    if(leaf->name_int.hi == 0 && leaf->name_int.lo == 0){
        return 1;
    }
    if(leaf->name_int.hi != real_devname.name_int.hi || leaf->name_int.lo != real_devname.name_int.lo){
        return 0;
    }
    return 1;
}

// Read private_data from vhost_virtqueue using BTF or fixed offset
// On kernel 5.10 with BTF, we can read directly using CO-RE
// Without BTF, use offset calculated from structure analysis
static inline void *get_vq_private_data(void *vq_ptr) {
    void *private_data = NULL;
    // Use bpf_probe_read_kernel to read private_data field
    // Offset needs to be determined at runtime or via BTF
    // For now, use direct field access which BCC will resolve
    bpf_probe_read_kernel(&private_data, sizeof(private_data),
                          (void *)vq_ptr + PRIVATE_DATA_OFFSET);
    return private_data;
}

// Read vhost_virtqueue state fields using offsets
static inline void get_vhost_vq_state_k510(void *vq_ptr, struct queue_event *event) {
    if (!vq_ptr) return;

    // Read fields at calculated offsets for kernel 5.10+
    bpf_probe_read_kernel(&event->last_avail_idx, sizeof(u16),
                          (void *)vq_ptr + LAST_AVAIL_IDX_OFFSET);
    bpf_probe_read_kernel(&event->avail_idx, sizeof(u16),
                          (void *)vq_ptr + AVAIL_IDX_OFFSET);
    bpf_probe_read_kernel(&event->last_used_idx, sizeof(u16),
                          (void *)vq_ptr + LAST_USED_IDX_OFFSET);
    bpf_probe_read_kernel(&event->used_flags, sizeof(u16),
                          (void *)vq_ptr + USED_FLAGS_OFFSET);
    bpf_probe_read_kernel(&event->signalled_used, sizeof(u16),
                          (void *)vq_ptr + SIGNALLED_USED_OFFSET);
    bpf_probe_read_kernel(&event->signalled_used_valid, sizeof(bool),
                          (void *)vq_ptr + SIGNALLED_USED_VALID_OFFSET);
    bpf_probe_read_kernel(&event->log_used, sizeof(bool),
                          (void *)vq_ptr + LOG_USED_OFFSET);
    bpf_probe_read_kernel(&event->log_addr, sizeof(u64),
                          (void *)vq_ptr + LOG_ADDR_OFFSET);
    bpf_probe_read_kernel(&event->acked_features, sizeof(u64),
                          (void *)vq_ptr + ACKED_FEATURES_OFFSET);
    bpf_probe_read_kernel(&event->acked_backend_features, sizeof(u64),
                          (void *)vq_ptr + ACKED_BACKEND_FEATURES_OFFSET);
}

// Stage 1: tun_net_xmit - Only track queue, no output
int trace_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    if (!skb || !dev) return 0;

    // Apply device filter
    if (!name_filter(dev)) return 0;

    u32 queue_index = skb->queue_mapping;

    // Check queue filter
    int key = 0;
    u32 *filter_en = filter_enabled.lookup(&key);
    if (filter_en && *filter_en) {
        u32 *f_queue = filter_queue.lookup(&key);
        if (f_queue && *f_queue != queue_index) {
            return 0;
        }
    }

    // Get TUN structure
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
        void **tfile_ptr_addr = (void**)((char*)tun + queue_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL;
        }
    }
    if (!tfile) {
        return 0;
    }

    // Get socket pointer
    u64 sock_ptr = (u64)&tfile->socket;

    // Track this queue's sock pointer
    struct queue_key qkey = {};
    qkey.sock_ptr = sock_ptr;
    qkey.queue_index = queue_index;
    bpf_probe_read_kernel_str(qkey.dev_name, sizeof(qkey.dev_name), dev->name);
    target_queues.update(&sock_ptr, &qkey);

    return 0;
}

// Stage 2: vhost_signal
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    void *vq_ptr = (void *)PT_REGS_PARM2(ctx);

    if (!vq_ptr) return 0;

    // Get sock pointer using offset for private_data
    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data),
                          (void *)vq_ptr + PRIVATE_DATA_OFFSET);
    u64 sock_ptr = (u64)private_data;

    // Check if this is our target queue
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;
    }

    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 1;  // vhost_signal

    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq_ptr;

    // Get vhost virtqueue state
    get_vhost_vq_state_k510(vq_ptr, &event);

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 3: vhost_notify entry
int trace_vhost_notify_entry(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    void *vq_ptr = (void *)PT_REGS_PARM2(ctx);

    if (!vq_ptr) return 0;

    // Get sock pointer using offset for private_data
    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data),
                          (void *)vq_ptr + PRIVATE_DATA_OFFSET);
    u64 sock_ptr = (u64)private_data;

    // Check if this is our target queue
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;
    }

    // Store vq pointer for return probe
    u64 tid = bpf_get_current_pid_tgid();
    u64 vq_u64 = (u64)vq_ptr;
    vhost_notify_params.update(&tid, &vq_u64);

    return 0;
}

// Stage 4: vhost_notify return
int trace_vhost_notify_return(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();

    // Get vq from entry probe
    u64 *vq_ptr_stored = vhost_notify_params.lookup(&tid);
    if (!vq_ptr_stored || !*vq_ptr_stored) {
        return 0;
    }

    void *vq_ptr = (void *)*vq_ptr_stored;
    vhost_notify_params.delete(&tid);

    // Get sock pointer using offset for private_data
    void *private_data = NULL;
    bpf_probe_read_kernel(&private_data, sizeof(private_data),
                          (void *)vq_ptr + PRIVATE_DATA_OFFSET);
    u64 sock_ptr = (u64)private_data;

    // Check if this is our target queue
    struct queue_key *qkey = target_queues.lookup(&sock_ptr);
    if (!qkey) {
        return 0;
    }

    // Create event
    struct queue_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = tid >> 32;
    event.tid = tid & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.event_type = 2;  // vhost_notify

    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq_ptr;

    // Get return value
    event.ret_val = PT_REGS_RC(ctx);

    // Get vhost virtqueue state
    get_vhost_vq_state_k510(vq_ptr, &event);

    // Check if VIRTIO_RING_F_EVENT_IDX is supported
    event.has_event_idx_feature = (event.acked_features & (1ULL << VIRTIO_RING_F_EVENT_IDX)) != 0;

    // Try to read avail flags from guest memory
    void *avail = NULL;
    bpf_probe_read_kernel(&avail, sizeof(avail), (void *)vq_ptr + AVAIL_OFFSET);
    if (avail) {
        __virtio16 flags = 0;
        if (bpf_probe_read_user(&flags, sizeof(flags), avail) == 0) {
            event.avail_flags = flags;
            event.guest_flags_valid = true;
        }
    }

    // If EVENT_IDX is enabled, try to read used_event_idx
    if (event.has_event_idx_feature) {
        unsigned int num = 0;
        bpf_probe_read_kernel(&num, sizeof(num), (void *)vq_ptr + NUM_OFFSET);

        if (avail && num > 0) {
            __virtio16 *used_event_ptr = (__virtio16 *)((char *)avail +
                                          4 + // offsetof(struct vring_avail, ring) = flags(2) + idx(2)
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
        ("vq_ptr", ct.c_uint64),
        # VQ state
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
        # vhost_notify specific
        ("ret_val", ct.c_int),
        ("has_event_idx_feature", ct.c_bool),
        ("avail_flags", ct.c_uint16),
        ("used_event_idx", ct.c_uint16),
        ("guest_flags_valid", ct.c_bool),
        ("guest_event_valid", ct.c_bool),
    ]

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(QueueEvent)).contents

    # Format timestamp
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]

    event_names = {
        1: "vhost_signal",
        2: "vhost_notify"
    }

    print("="*80)
    print("Event: {} | Time: {} | Timestamp: {}ns".format(
        event_names.get(event.event_type, "unknown"), timestamp_str, event.timestamp))
    print("Queue: {} | Device: {} | Process: {} (PID: {})".format(
        event.queue_index, event.dev_name.decode('utf-8', 'replace'),
        event.comm.decode('utf-8', 'replace'), event.pid))
    print("Sock: 0x{:x}".format(event.sock_ptr))

    if event.event_type == 1:  # vhost_signal
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
    elif event.event_type == 2:  # vhost_notify
        print("VQ: 0x{:x} | Return: {} (notify={})".format(
            event.vq_ptr, event.ret_val, "YES" if event.ret_val else "NO"))
        print("VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("Features: acked=0x{:x}, backend=0x{:x}, EVENT_IDX={}".format(
            event.acked_features, event.acked_backend_features,
            "ENABLED" if event.has_event_idx_feature else "DISABLED"))
        # Guest memory fields
        if event.guest_flags_valid:
            no_interrupt = (event.avail_flags & 0x1) != 0
            print("Guest avail_flags: 0x{:x} (NO_INTERRUPT={})".format(
                event.avail_flags, "YES" if no_interrupt else "NO"))
        else:
            print("Guest avail_flags: <failed to read>")

        if event.has_event_idx_feature and event.guest_event_valid:
            print("Guest used_event_idx: {} (host last_used={})".format(
                event.used_event_idx, event.last_used_idx))
        elif event.has_event_idx_feature:
            print("Guest used_event_idx: <failed to read>")

    print()


def get_vhost_vq_offsets_from_btf():
    """Try to get vhost_virtqueue field offsets from BTF"""
    try:
        # Check if BTF is available
        if not os.path.exists('/sys/kernel/btf/vmlinux'):
            return None

        # Use pahole or bpftool to get offsets
        import subprocess
        result = subprocess.run(
            ['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux',
             'format', 'c', '-p'],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return None

        # Parse output to find vhost_virtqueue
        # This is a simplified approach - in production, use proper BTF parsing
        return None
    except:
        return None


def get_vhost_vq_offsets_manual(kernel_version):
    """
    Get vhost_virtqueue field offsets based on kernel version.
    These offsets were determined by analyzing kernel headers.

    Kernel 5.10 vhost_virtqueue layout (approximate):
    - dev: offset 0 (8 bytes)
    - mutex: offset 8 (variable size ~32 bytes)
    - num: offset ~40 (4 bytes)
    - desc: offset ~48 (8 bytes)
    - avail: offset ~56 (8 bytes)
    - used: offset ~64 (8 bytes)
    - meta_iotlb[3]: offset ~72 (24 bytes)
    - kick: offset ~96 (8 bytes)
    - call_ctx: offset ~104 (struct vhost_vring_call ~56 bytes on 5.10)
    - error_ctx: offset ~160 (8 bytes)
    - log_ctx: offset ~168 (8 bytes)
    - poll: offset ~176 (struct vhost_poll ~192 bytes)
    - handle_kick: offset ~368 (8 bytes)
    - last_avail_idx: offset ~376 (2 bytes)
    - avail_idx: offset ~378 (2 bytes)
    - last_used_idx: offset ~380 (2 bytes)
    - used_flags: offset ~382 (2 bytes)
    - signalled_used: offset ~384 (2 bytes)
    - signalled_used_valid: offset ~386 (1 byte)
    - log_used: offset ~387 (1 byte)
    - log_addr: offset ~392 (8 bytes, aligned)
    ... more fields ...
    - private_data: (need to calculate based on iovec arrays)
    - acked_features: offset after private_data (8 bytes)
    """

    # These offsets need to be verified on actual kernel 5.10 system
    # The tool provides a mechanism to override via environment variables

    # Check for environment variable overrides first
    offsets = {}
    env_mappings = {
        'VHOST_VQ_PRIVATE_DATA_OFFSET': 'private_data',
        'VHOST_VQ_LAST_AVAIL_IDX_OFFSET': 'last_avail_idx',
        'VHOST_VQ_AVAIL_IDX_OFFSET': 'avail_idx',
        'VHOST_VQ_LAST_USED_IDX_OFFSET': 'last_used_idx',
        'VHOST_VQ_USED_FLAGS_OFFSET': 'used_flags',
        'VHOST_VQ_SIGNALLED_USED_OFFSET': 'signalled_used',
        'VHOST_VQ_SIGNALLED_USED_VALID_OFFSET': 'signalled_used_valid',
        'VHOST_VQ_LOG_USED_OFFSET': 'log_used',
        'VHOST_VQ_LOG_ADDR_OFFSET': 'log_addr',
        'VHOST_VQ_ACKED_FEATURES_OFFSET': 'acked_features',
        'VHOST_VQ_ACKED_BACKEND_FEATURES_OFFSET': 'acked_backend_features',
        'VHOST_VQ_NUM_OFFSET': 'num',
        'VHOST_VQ_AVAIL_OFFSET': 'avail',
    }

    for env_name, field_name in env_mappings.items():
        if env_name in os.environ:
            try:
                offsets[field_name] = int(os.environ[env_name])
            except:
                pass

    # Default offsets for kernel 5.10 (x86_64)
    # NOTE: These are approximations and may need adjustment
    # The actual offsets depend on kernel config and compiler
    if kernel_version >= (5, 10, 0):
        defaults = {
            'num': 40,
            'avail': 56,
            'last_avail_idx': 376,
            'avail_idx': 378,
            'last_used_idx': 380,
            'used_flags': 382,
            'signalled_used': 384,
            'signalled_used_valid': 386,
            'log_used': 387,
            'log_addr': 392,
            # These are in a large block after iov arrays
            # private_data is typically around offset 9000-10000 due to iov[1024]
            'private_data': 9216,  # Approximate - needs verification
            'acked_features': 9224,
            'acked_backend_features': 9232,
        }
    else:
        # Kernel 4.19 style offsets (call_ctx is pointer, not struct)
        defaults = {
            'num': 40,
            'avail': 56,
            'last_avail_idx': 320,
            'avail_idx': 322,
            'last_used_idx': 324,
            'used_flags': 326,
            'signalled_used': 328,
            'signalled_used_valid': 330,
            'log_used': 331,
            'log_addr': 336,
            'private_data': 9168,  # Approximate
            'acked_features': 9176,
            'acked_backend_features': 9184,
        }

    # Merge defaults with any env overrides
    for key, value in defaults.items():
        if key not in offsets:
            offsets[key] = value

    return offsets


def main():
    parser = argparse.ArgumentParser(
        description="VHOST Queue Monitor (Kernel 5.10 compatible)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all queues on all TUN devices
  sudo %(prog)s

  # Monitor specific device and queue
  sudo %(prog)s --device vnet33 --queue 0

  # Monitor with custom private_data offset
  sudo VHOST_VQ_PRIVATE_DATA_OFFSET=9216 %(prog)s --device vnet33

  # Show offset debug info
  sudo %(prog)s --show-offsets

Offset Override Environment Variables:
  VHOST_VQ_PRIVATE_DATA_OFFSET
  VHOST_VQ_LAST_AVAIL_IDX_OFFSET
  VHOST_VQ_AVAIL_IDX_OFFSET
  ... (see source for full list)
        """
    )

    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet33)")
    parser.add_argument("--queue", "-q", type=int, help="Filter by queue index")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--show-offsets", action="store_true",
                        help="Show calculated offsets and exit")

    args = parser.parse_args()

    # Get kernel version
    kernel_version = get_kernel_version()
    print("Kernel version: {}.{}.{}".format(*kernel_version))

    # Get field offsets
    offsets = get_vhost_vq_offsets_manual(kernel_version)

    if args.show_offsets:
        print("\nvhost_virtqueue field offsets:")
        for field, offset in sorted(offsets.items()):
            print("  {}: {}".format(field, offset))
        print("\nTo override, set environment variables like:")
        print("  export VHOST_VQ_PRIVATE_DATA_OFFSET=9216")
        return

    # Find vhost_notify symbol
    vhost_notify_symbol = find_vhost_notify_symbol()
    if vhost_notify_symbol:
        print("Found vhost_notify symbol: {}".format(vhost_notify_symbol))
    else:
        print("Warning: Could not find vhost_notify symbol in kallsyms")

    # Prepare BPF program with offset defines
    bpf_defines = """
#define PRIVATE_DATA_OFFSET {}
#define LAST_AVAIL_IDX_OFFSET {}
#define AVAIL_IDX_OFFSET {}
#define LAST_USED_IDX_OFFSET {}
#define USED_FLAGS_OFFSET {}
#define SIGNALLED_USED_OFFSET {}
#define SIGNALLED_USED_VALID_OFFSET {}
#define LOG_USED_OFFSET {}
#define LOG_ADDR_OFFSET {}
#define ACKED_FEATURES_OFFSET {}
#define ACKED_BACKEND_FEATURES_OFFSET {}
#define NUM_OFFSET {}
#define AVAIL_OFFSET {}
""".format(
        offsets['private_data'],
        offsets['last_avail_idx'],
        offsets['avail_idx'],
        offsets['last_used_idx'],
        offsets['used_flags'],
        offsets['signalled_used'],
        offsets['signalled_used_valid'],
        offsets['log_used'],
        offsets['log_addr'],
        offsets['acked_features'],
        offsets['acked_backend_features'],
        offsets['num'],
        offsets['avail'],
    )

    bpf_program = bpf_defines + bpf_text_k510

    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program with offsets:")
            for field, offset in sorted(offsets.items()):
                print("  {}: {}".format(field, offset))

        b = BPF(text=bpf_program)

        # Attach kprobes
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        print("Attached to tun_net_xmit")

        # Try to attach vhost_signal
        try:
            b.attach_kprobe(event="vhost_signal", fn_name="trace_vhost_signal")
            print("Attached to vhost_signal")
        except Exception as e:
            print("Warning: Could not attach to vhost_signal: {}".format(e))

        # Try to attach vhost_notify using discovered symbol or fallbacks
        vhost_notify_attached = False

        # Try discovered symbol first
        if vhost_notify_symbol:
            try:
                b.attach_kprobe(event=vhost_notify_symbol, fn_name="trace_vhost_notify_entry")
                b.attach_kretprobe(event=vhost_notify_symbol, fn_name="trace_vhost_notify_return")
                vhost_notify_attached = True
                print("Attached to {}".format(vhost_notify_symbol))
            except Exception as e:
                if args.verbose:
                    print("Failed to attach to {}: {}".format(vhost_notify_symbol, e))

        # Try without suffix
        if not vhost_notify_attached:
            try:
                b.attach_kprobe(event="vhost_notify", fn_name="trace_vhost_notify_entry")
                b.attach_kretprobe(event="vhost_notify", fn_name="trace_vhost_notify_return")
                vhost_notify_attached = True
                print("Attached to vhost_notify")
            except:
                pass

        # Try common .isra suffixes (0-50 range to cover more cases)
        if not vhost_notify_attached:
            for i in range(51):
                suffix = ".isra.{}".format(i)
                event_name = "vhost_notify" + suffix
                try:
                    b.attach_kprobe(event=event_name, fn_name="trace_vhost_notify_entry")
                    b.attach_kretprobe(event=event_name, fn_name="trace_vhost_notify_return")
                    vhost_notify_attached = True
                    print("Attached to {}".format(event_name))
                    break
                except:
                    continue

        # Also try .constprop suffix
        if not vhost_notify_attached:
            for i in range(20):
                suffix = ".constprop.{}".format(i)
                event_name = "vhost_notify" + suffix
                try:
                    b.attach_kprobe(event=event_name, fn_name="trace_vhost_notify_entry")
                    b.attach_kretprobe(event=event_name, fn_name="trace_vhost_notify_return")
                    vhost_notify_attached = True
                    print("Attached to {}".format(event_name))
                    break
                except:
                    continue

        if not vhost_notify_attached:
            print("Warning: Could not attach to vhost_notify")
            print("The function may be inlined. Continuing without vhost_notify monitoring...")

        if args.verbose:
            print("All probes attached successfully")

    except Exception as e:
        print("Failed to load BPF program: {}".format(e))
        import traceback
        traceback.print_exc()
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

    print("\nVHOST Queue Monitor Started (Kernel 5.10+ compatible)")
    print("Monitoring: vhost_signal & vhost_notify events")
    print("Clearing maps to avoid stale entries")

    # Clear maps
    target_queues_map = b["target_queues"]
    target_queues_map.clear()

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
