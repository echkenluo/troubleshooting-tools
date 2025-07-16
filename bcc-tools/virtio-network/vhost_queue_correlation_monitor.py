#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import socket
import struct
import sys
import datetime
from bcc import BPF
import ctypes as ct

# Devname structure for device filtering
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

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
    struct eventfd_ctx *call_ctx;
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
    u8 event_type;  // 1=tun_xmit, 2=handle_rx, 3=tun_recvmsg, 4=vhost_signal
    
    // Event-specific data
    u64 skb_ptr;
    u64 tfile_ptr;
    u64 vq_ptr;
    
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

// Device filter logic
static inline int name_filter(struct net_device *dev){
    union name_buf real_devname;
    bpf_probe_read_kernel_str(real_devname.name, IFNAMSIZ, dev->name);

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

// Stage 5: vhost_signal - Track using vq -> sock with member_read
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
        4: "vhost_signal"
    }
    
    print("="*80)
    print("🔍 Event: {} | Time: {}".format(
        event_names.get(event.event_type, "unknown"), timestamp_str))
    print("📍 Queue: {} | Device: {} | Process: {} (PID: {})".format(
        event.queue_index, event.dev_name.decode('utf-8', 'replace'),
        event.comm.decode('utf-8', 'replace'), event.pid))
    print("🔑 Sock: 0x{:x}".format(event.sock_ptr))
    
    # Event-specific information
    if event.event_type == 1:  # tun_net_xmit
        print("📦 SKB: 0x{:x} | TFile: 0x{:x}".format(event.skb_ptr, event.tfile_ptr))
        if event.saddr != 0:
            print("🌐 Flow: {}:{} -> {}:{} ({})".format(
                ip_to_str(event.saddr), event.sport,
                ip_to_str(event.daddr), event.dport,
                "TCP" if event.protocol == 6 else "UDP" if event.protocol == 17 else str(event.protocol)))
        if event.rx_ring_ptr:
            print("🔗 PTR Ring: 0x{:x}".format(event.rx_ring_ptr))
    elif event.event_type == 2:  # handle_rx
        print("📥 VQ: 0x{:x}".format(event.vq_ptr))
        print("🔄 VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("🎯 Signal: signalled_used={}, valid={}, log_used={}".format(
            event.signalled_used, "YES" if event.signalled_used_valid else "NO", 
            "YES" if event.log_used else "NO"))
        print("⚙️ Features: acked=0x{:x}, backend=0x{:x}".format(
            event.acked_features, event.acked_backend_features))
        if event.rx_ring_ptr:
            print("🔗 RX Ring: 0x{:x}, upend_idx={}, done_idx={}".format(
                event.rx_ring_ptr, event.upend_idx, event.done_idx))
        print("📦 Hdr Len: vhost={}, sock={}, rxq_buf={}→{}".format(
            event.vhost_hlen, event.sock_hlen, event.rxq_head, event.rxq_tail))
    elif event.event_type == 3:  # tun_recvmsg
        print("📨 TFile: 0x{:x}".format(event.tfile_ptr))
        if event.rx_ring_ptr:
            print("🔗 PTR Ring: 0x{:x}".format(event.rx_ring_ptr))
    elif event.event_type == 4:  # vhost_signal
        print("🚨 VQ: 0x{:x}".format(event.vq_ptr))
        print("🔄 VQ State: avail_idx={}, last_avail={}, last_used={}, used_flags=0x{:x}".format(
            event.avail_idx, event.last_avail_idx, event.last_used_idx, event.used_flags))
        print("🎯 Signal: signalled_used={}, valid={}, log_used={}".format(
            event.signalled_used, "YES" if event.signalled_used_valid else "NO", 
            "YES" if event.log_used else "NO"))
        print("⚙️ Features: acked=0x{:x}, backend=0x{:x}".format(
            event.acked_features, event.acked_backend_features))
        if event.log_used and event.log_addr:
            print("📋 Log: addr=0x{:x}".format(event.log_addr))
    
    # Show ptr_ring state if available
    if event.ptr_ring_size > 0:
        print("🔗 PTR Ring: size={}, producer={}, consumer_h={}, consumer_t={}, full={}".format(
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
    
    # Load BPF program
    try:
        if args.verbose:
            print("Loading BPF program...")
        
        b = BPF(text=bpf_text)
        
        # Attach kprobes
        b.attach_kprobe(event="tun_net_xmit", fn_name="trace_tun_net_xmit")
        b.attach_kprobe(event="handle_rx", fn_name="trace_handle_rx")
        b.attach_kprobe(event="tun_recvmsg", fn_name="trace_tun_recvmsg_entry")
        b.attach_kretprobe(event="tun_recvmsg", fn_name="trace_tun_recvmsg_return")
        b.attach_kprobe(event="vhost_add_used_and_signal_n", fn_name="trace_vhost_signal")
        
        if args.verbose:
            print("✅ All probes attached successfully")
        
    except Exception as e:
        print("❌ Failed to load BPF program: {}".format(e))
        return
    
    # Set device filter
    devname_map = b["name_map"]
    _name = Devname()
    if args.device:
        _name.name = args.device.encode()
        devname_map[0] = _name
        print("📡 Device filter: {}".format(args.device))
    else:
        _name.name = b""
        devname_map[0] = _name
        print("📡 Device filter: All TUN devices")
    
    # Set queue filter
    if args.queue is not None:
        b["filter_enabled"][0] = ct.c_uint32(1)
        b["filter_queue"][0] = ct.c_uint32(args.queue)
        print("🔍 Queue filter: {} (enforced at tun_net_xmit)".format(args.queue))
    else:
        b["filter_enabled"][0] = ct.c_uint32(0)
        print("🔍 Queue filter: All queues")
    
    print("🚀 VHOST-NET Queue Correlation Monitor Started")
    print("📊 Using sock pointer (0x...) to correlate events across stages")
    print("🧹 Clearing target_queues and handle_rx_vqs maps to avoid stale entries")
    
    # Clear target_queues map to avoid stale entries
    target_queues_map = b["target_queues"]
    target_queues_map.clear()
    
    # Clear handle_rx_vqs map to avoid stale entries
    handle_rx_vqs_map = b["handle_rx_vqs"]
    handle_rx_vqs_map.clear()
    
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