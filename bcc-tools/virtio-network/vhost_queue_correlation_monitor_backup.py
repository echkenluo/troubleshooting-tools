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

// Vhost offset definitions (avoid complex structure dependencies)
#define VHOST_VQ_PRIVATE_DATA_OFFSET  320  // Approximate offset to private_data in vhost_virtqueue  
#define VHOST_NET_VQS_OFFSET         256   // Approximate offset to vqs in vhost_net

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
};

// Maps
BPF_HASH(target_queues, u64, struct queue_key, 256);  // Track target queue sock pointers
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
    if (bpf_probe_read_kernel(&tun_numqueues, sizeof(tun_numqueues), &tun->numqueues) != 0) {
        return 0;
    }
    
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
    
    // Get sock pointer from tfile
    u64 sock_ptr = (u64)&tfile->sk;
    
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
    
    // Get ptr_ring state
    get_ptr_ring_state_from_tfile(tfile, &event);
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 2: handle_rx - Track using sock pointer with offset access
int trace_handle_rx(struct pt_regs *ctx) {
    void *net = (void *)PT_REGS_PARM1(ctx);
    if (!net) return 0;
    
    // Get RX virtqueue pointer using offset (vqs[0].vq)
    void *vq = (char*)net + VHOST_NET_VQS_OFFSET;
    
    // Get sock pointer from private_data using offset
    void *private_data = NULL;
    if (bpf_probe_read_kernel(&private_data, sizeof(private_data), 
                              (char*)vq + VHOST_VQ_PRIVATE_DATA_OFFSET) != 0) {
        return 0;
    }
    
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
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 3: tun_recvmsg - Track using socket -> sock (NO device filtering here)
int trace_tun_recvmsg_entry(struct pt_regs *ctx, struct socket *sock, struct msghdr *m, size_t total_len, int flags) {
    if (!sock) return 0;
    
    // Get tun_file from socket using proper calculation
    struct tun_file *tfile = (struct tun_file *)((char *)sock - offsetof(struct tun_file, socket));
    if (!tfile) return 0;
    
    // Get sock pointer
    u64 sock_ptr = (u64)&tfile->sk;
    
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
    
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Stage 4: tun_recvmsg return
int trace_tun_recvmsg_return(struct pt_regs *ctx) {
    // We need to match this with the entry - for now skip
    return 0;
}

// Stage 5: vhost_signal - Track using vq -> sock with offset access
int trace_vhost_signal(struct pt_regs *ctx) {
    void *dev = (void *)PT_REGS_PARM1(ctx);
    void *vq = (void *)PT_REGS_PARM2(ctx);
    
    if (!vq) return 0;
    
    // Get sock pointer from private_data using offset
    void *private_data = NULL;
    if (bpf_probe_read_kernel(&private_data, sizeof(private_data), 
                              (char*)vq + VHOST_VQ_PRIVATE_DATA_OFFSET) != 0) {
        return 0;
    }
    
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
    event.event_type = 4;  // vhost_signal
    
    event.sock_ptr = sock_ptr;
    event.queue_index = qkey->queue_index;
    __builtin_memcpy(event.dev_name, qkey->dev_name, sizeof(event.dev_name));
    event.vq_ptr = (u64)vq;
    
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
    elif event.event_type == 2:  # handle_rx
        print("📥 VQ: 0x{:x}".format(event.vq_ptr))
    elif event.event_type == 3:  # tun_recvmsg
        print("📨 TFile: 0x{:x}".format(event.tfile_ptr))
    elif event.event_type == 4:  # vhost_signal
        print("🚨 VQ: 0x{:x}".format(event.vq_ptr))
    
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