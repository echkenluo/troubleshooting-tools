#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import socket
import struct
import sys
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

# Devname structure for device filtering (same as iface_netstat.py)
class Devname(ct.Structure):
    _fields_=[("name", ct.c_char*16)]

# BPF program with verified device filtering and ptr_ring monitoring
bpf_text = """
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <linux/ptr_ring.h>

#define NETDEV_ALIGN 32

// Device name union for efficient comparison (from iface_netstat.c)
union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

// User-provided macros for member access
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
	/* only used for fasnyc */
	unsigned int flags;
	union {
		u16 queue_index;
		unsigned int ifindex;
	};
	struct napi_struct napi;
	bool napi_enabled;
	bool napi_frags_enabled;
	struct mutex napi_mutex;	/* Protects access to the above napi */
	struct list_head next;
	struct tun_struct *detached;
	struct ptr_ring tx_ring;
	struct xdp_rxq_info xdp_rxq;
};


struct event_data {
    u32 pid;
    u32 tid;
    char comm[16];
    char dev_name[16];
    u32 queue_mapping;
    u32 ptr_ring_size;
    u32 producer;
    u32 consumer_head;
    u32 consumer_tail;
    u32 ring_full;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u64 skb_addr;
    u64 timestamp;
    u64 queue_producer_ptr;
    // Debug fields
    u64 tun_ptr;         // tun_struct pointer
    u64 tfile_ptr;       // tfile pointer
    u16 tun_numqueues;   // tun->numqueues for validation
    u16 tfile_queue_index; // tfile->queue_index for validation
    u32 tfile_ifindex;   // tfile->ifindex (union with queue_index)
    // New field for offsetof information
    u32 tfiles_size;     // sizeof(tfiles) array
    u32 numqueues_offset; // offsetof(struct tun_struct, numqueues)
    u32 tfile_index;     // actual index used to access tfiles array
};

BPF_PERF_OUTPUT(events);
BPF_ARRAY(filter_enabled, u32, 1);
BPF_ARRAY(filter_saddr, u32, 1);
BPF_ARRAY(filter_daddr, u32, 1);
BPF_ARRAY(filter_sport, u16, 1);
BPF_ARRAY(filter_dport, u16, 1);
BPF_ARRAY(filter_protocol, u8, 1);
BPF_ARRAY(name_map, union name_buf, 1);  // Device filter (from iface_netstat.c)
BPF_ARRAY(show_all_events, u32, 1);

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

// 5-tuple filter logic (using OR logic with BPF Maps)
static inline int check_filter(u32 saddr, u32 daddr, u16 sport, u16 dport, u8 protocol) {
    int key = 0;
    u32 *enabled = filter_enabled.lookup(&key);
    if (!enabled || *enabled == 0) {
        return 1;  // No filtering enabled
    }

    u32 *f_saddr = filter_saddr.lookup(&key);
    u32 *f_daddr = filter_daddr.lookup(&key);
    u16 *f_sport = filter_sport.lookup(&key);
    u16 *f_dport = filter_dport.lookup(&key);
    u8 *f_protocol = filter_protocol.lookup(&key);

    // OR logic: if any configured filter matches, accept the packet
    if (f_saddr && *f_saddr != 0 && *f_saddr == saddr) {
        return 1;
    }
    if (f_daddr && *f_daddr != 0 && *f_daddr == daddr) {
        return 1;
    }
    if (f_sport && *f_sport != 0 && *f_sport == sport) {
        return 1;
    }
    if (f_dport && *f_dport != 0 && *f_dport == dport) {
        return 1;
    }
    if (f_protocol && *f_protocol != 0 && *f_protocol == protocol) {
        return 1;
    }

    return 0;  // No filters matched
}

// Header parsing (based on icmp_rtt_latency.py)
static inline int parse_packet_headers(struct sk_buff *skb, u32 *saddr, u32 *daddr, 
                                     u16 *sport, u16 *dport, u8 *protocol) {
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

    *saddr = ip.saddr;
    *daddr = ip.daddr;
    *protocol = ip.protocol;

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
        *sport = bpf_ntohs(tcph.source);
        *dport = bpf_ntohs(tcph.dest);
    } else if (ip.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header_offset) < 0) {
            return 0;
        }
        *sport = bpf_ntohs(udph.source);
        *dport = bpf_ntohs(udph.dest);
    } else {
        *sport = 0;
        *dport = 0;
    }

    return 1;
}


int probe_tun_net_xmit(struct pt_regs *ctx, struct sk_buff *skb, struct net_device *dev) {
    struct event_data event = {};
    int key = 0;
    
    event.timestamp = bpf_ktime_get_ns();
    
    // Apply verified device filter first
    if (!name_filter(dev)) {
        return 0;  // Device doesn't match filter, skip
    }
    
    // Get device name for output
    bpf_probe_read_kernel_str(event.dev_name, sizeof(event.dev_name), dev->name);
    
    // Basic event info
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.skb_addr = (u64)skb;
    event.queue_mapping = skb->queue_mapping;
    
    // Parse packet headers
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    u8 protocol = 0;
    
    // Always try to parse headers, but don't filter on failure
    int header_parsed = parse_packet_headers(skb, &saddr, &daddr, &sport, &dport, &protocol);
    if (header_parsed) {
        event.saddr = saddr;
        event.daddr = daddr;
        event.sport = sport;
        event.dport = dport;
        event.protocol = protocol;
        
        // Apply 5-tuple filter if enabled and headers were successfully parsed
        if (!check_filter(saddr, daddr, sport, dport, protocol)) {
            return 0;
        }
    } else {
        // Headers failed to parse - set to 0
        event.saddr = 0;
        event.daddr = 0;
        event.sport = 0;
        event.dport = 0;
        event.protocol = 0;
        
        // If 5-tuple filter is enabled, reject packets with unparseable headers
        u32 *enabled = filter_enabled.lookup(&key);
        if (enabled && *enabled != 0) {
            return 0;  // 5-tuple filter enabled but headers failed to parse
        }
    }
    
    // Calculate TUN structure pointer from net_device
    u32 aligned_size = (sizeof(struct net_device) + NETDEV_ALIGN - 1) & ~(NETDEV_ALIGN - 1);
    struct tun_struct *tun = (struct tun_struct *)((char *)dev + aligned_size);
    event.tun_ptr = (u64)tun;
    
    // Add offsetof calculations for struct layout analysis
    event.tfiles_size = sizeof(tun->tfiles);  // Should be 256 * 8 = 2048 bytes on 64-bit
    event.numqueues_offset = offsetof(struct tun_struct, numqueues);  // Offset of second field
    
    // Verify tun structure and read numqueues
    if (bpf_probe_read_kernel(&event.tun_numqueues, sizeof(event.tun_numqueues), &tun->numqueues) != 0) {
        event.tun_numqueues = 0;
    }
    
    struct tun_file *tfile = NULL;
    event.tfile_index = event.queue_mapping;  // Record the actual index used
    
    if (event.tfile_index < event.tun_numqueues && 
        event.tun_numqueues > 0 && 
        event.tfile_index < 256) {
        // Use pointer arithmetic to calculate the exact offset of tfiles[index]
        // tfiles is at the beginning of tun_struct, so:
        // tun_struct + index * sizeof(void*) gives us &tfiles[index]
        void **tfile_ptr_addr = (void**)((char*)tun + event.tfile_index * sizeof(void*));
        if (bpf_probe_read_kernel(&tfile, sizeof(tfile), tfile_ptr_addr) != 0) {
            tfile = NULL; // Read failed
        }
    }
    event.tfile_ptr = (u64)tfile;
    
    // Read tfile fields if available
    if (tfile) {
        member_read(&event.tfile_queue_index, tfile, queue_index);
        member_read(&event.tfile_ifindex, tfile, ifindex);
        
        // Analyze ptr_ring from tfile
        struct ptr_ring *tx_ring = &tfile->tx_ring;
        u32 producer = 0, consumer_head = 0, consumer_tail = 0, size = 0;
        void **queue = NULL;
        
        member_read(&producer, tx_ring, producer);
        member_read(&consumer_head, tx_ring, consumer_head);
        member_read(&consumer_tail, tx_ring, consumer_tail);
        member_read(&size, tx_ring, size);
        member_read(&queue, tx_ring, queue);
        
        event.producer = producer;
        event.consumer_head = consumer_head;
        event.consumer_tail = consumer_tail;
        event.ptr_ring_size = size;
        
        // Check if ring is full by examining queue[producer]
        if (queue && size > 0) {
            void *queue_entry = NULL;
            if (producer < size && 
                bpf_probe_read_kernel(&queue_entry, sizeof(queue_entry), &queue[producer]) == 0) {
                event.queue_producer_ptr = (u64)queue_entry;
                event.ring_full = (queue_entry != NULL) ? 1 : 0;
            } else {
                event.ring_full = 0;
            }
        }
    }
    
    // Send event based on filter settings
    u32 *show_all = show_all_events.lookup(&key);
    if ((show_all && *show_all) || event.ring_full) {
        events.perf_submit(ctx, &event, sizeof(event));
    }
    
    return 0;
}
"""

class EventData(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("dev_name", ct.c_char * 16),
        ("queue_mapping", ct.c_uint32),
        ("ptr_ring_size", ct.c_uint32),
        ("producer", ct.c_uint32),
        ("consumer_head", ct.c_uint32),
        ("consumer_tail", ct.c_uint32),
        ("ring_full", ct.c_uint32),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("protocol", ct.c_uint8),
        ("skb_addr", ct.c_uint64),
        ("timestamp", ct.c_uint64),
        ("queue_producer_ptr", ct.c_uint64),
        # Debug fields
        ("tun_ptr", ct.c_uint64),
        ("tfile_ptr", ct.c_uint64),
        ("tun_numqueues", ct.c_uint16),
        ("tfile_queue_index", ct.c_uint16),
        ("tfile_ifindex", ct.c_uint32),
        # New offsetof fields
        ("tfiles_size", ct.c_uint32),
        ("numqueues_offset", ct.c_uint32),
        ("tfile_index", ct.c_uint32),
    ]

def ip_to_str(addr):
    if addr == 0:
        return "N/A"
    return socket.inet_ntoa(struct.pack("I", addr))

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    
    saddr_str = ip_to_str(event.saddr)
    daddr_str = ip_to_str(event.daddr)
    protocol_str = "TCP" if event.protocol == 6 else "UDP" if event.protocol == 17 else str(event.protocol)
    
    # Calculate ring utilization
    if event.ptr_ring_size > 0:
        if event.producer >= event.consumer_tail:
            used = event.producer - event.consumer_tail
        else:
            used = event.ptr_ring_size - event.consumer_tail + event.producer
        utilization = (used * 100) // event.ptr_ring_size
    else:
        utilization = 0
    
    # Format timestamp
    import datetime
    timestamp = datetime.datetime.fromtimestamp(event.timestamp / 1000000000.0)
    timestamp_str = timestamp.strftime('%H:%M:%S.%f')[:-3]
    
    print("="*80)
    if event.ring_full:
        print("TUN RING FULL DETECTED!")
    else:
        print("TUN Ring Status")
    
    print("Time: {}".format(timestamp_str))
    print("Process: {} (PID: {})".format(event.comm.decode('utf-8', 'replace'), event.pid))
    print("Device: {}".format(event.dev_name.decode('utf-8', 'replace')))
    print("Queue: {}".format(event.queue_mapping))
    print("SKB Address: 0x{:x}".format(event.skb_addr))
    print()
    
    # Show struct layout information
    print("Struct Layout Analysis:")
    print("  tfiles array size: {} bytes".format(event.tfiles_size))
    print("  numqueues offset: {} bytes".format(event.numqueues_offset))
    print("  Expected tfiles size: {} bytes (256 pointers * 8)".format(256 * 8))
    if event.tfiles_size == event.numqueues_offset:
        print("  Layout correct: tfiles takes exactly {} bytes".format(event.tfiles_size))
    else:
        print("  Layout mismatch: tfiles size {} != numqueues offset {}".format(
            event.tfiles_size, event.numqueues_offset))
    print("  Array access: queue_mapping={} -> tfiles[{}]".format(
        event.queue_mapping, event.tfile_index))
    print()
    
    # Show validation info
    print("Validation Info:")
    print("  TUN struct: 0x{:x}".format(event.tun_ptr))
    print("  TUN numqueues: {}".format(event.tun_numqueues))
    print("  TFile ptr: 0x{:x}".format(event.tfile_ptr))
    print("  TFile queue_index: {}".format(event.tfile_queue_index))
    print()
    
    # Always show 5-tuple info section - helps debug filtering issues
    print("5-Tuple Info:")
    if event.saddr != 0 or event.daddr != 0 or event.sport != 0 or event.dport != 0:
        print("  Source: {}:{}".format(saddr_str, event.sport))
        print("  Destination: {}:{}".format(daddr_str, event.dport))
        print("  Protocol: {}".format(protocol_str))
    else:
        print("  Packet headers not parsed (may be non-IP or parsing failed)")
        print("  Source: N/A:N/A")
        print("  Destination: N/A:N/A")
        print("  Protocol: N/A")
    print()
    
    print("PTR Ring Details:")
    if event.ptr_ring_size > 0:
        print("  Size: {}".format(event.ptr_ring_size))
        print("  Producer: {}".format(event.producer))
        print("  Consumer Head: {}".format(event.consumer_head))
        print("  Consumer Tail: {}".format(event.consumer_tail))
        print("  Queue[Producer] Ptr: 0x{:x}".format(event.queue_producer_ptr))
        
        if event.ring_full:
            print("  Status: FULL (queue[producer] != NULL)")
        else:
            print("  Status: Available (queue[producer] == NULL), {}% used".format(utilization))
    else:
        print("  Status: Not found (using default search offsets)")
    
    print("="*80)
    print()

def str_to_ip(ip_str):
    """Convert IP string to network-ordered hex value (same as icmp_rtt_latency.py)"""
    if not ip_str or ip_str == "0.0.0.0":
        return 0
    try:
        packed_ip = socket.inet_aton(ip_str)
        host_int = struct.unpack("!I", packed_ip)[0]
        return socket.htonl(host_int)  # BPF expects network byte order for filters
    except socket.error:
        print("Error: Invalid IP address format '{}'".format(ip_str))
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="TUN device ptr_ring monitor with struct layout analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor all TUN devices for ring full events only
  sudo %(prog)s
  
  # Monitor specific device showing all events and struct layout
  sudo %(prog)s --device vnet12 --all
  
  # Filter by 5-tuple with source IP (shows 5-tuple info)
  sudo %(prog)s --device vnet12 --src-ip 192.168.1.100 --all
        """
    )
    
    parser.add_argument("--device", "-d", help="Target device name (e.g., vnet12)")
    parser.add_argument("--src-ip", help="Filter by source IP")
    parser.add_argument("--dst-ip", help="Filter by destination IP")
    parser.add_argument("--src-port", type=int, help="Filter by source port")
    parser.add_argument("--dst-port", type=int, help="Filter by destination port")
    parser.add_argument("--protocol", choices=['tcp', 'udp'], help="Filter by protocol")
    parser.add_argument("--all", action="store_true", help="Show all events (not just ring full)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Prepare filter parameters for BPF Maps
    filter_enabled = 1 if any([args.src_ip, args.dst_ip, args.src_port, args.dst_port, args.protocol]) else 0
    filter_saddr = str_to_ip(args.src_ip) if args.src_ip else 0
    filter_daddr = str_to_ip(args.dst_ip) if args.dst_ip else 0
    filter_sport = args.src_port if args.src_port else 0
    filter_dport = args.dst_port if args.dst_port else 0
    filter_protocol = (6 if args.protocol == 'tcp' else 17) if args.protocol else 0
    
    # Load BPF program (no string replacement needed)
    try:
        if args.verbose:
            print("Loading BPF program with BPF Maps filters...")
            print("  FILTER_ENABLED: {}".format(filter_enabled))
            print("  FILTER_SADDR: 0x{:x}".format(filter_saddr))
            print("  FILTER_DADDR: 0x{:x}".format(filter_daddr))
            print("  FILTER_SPORT: {}".format(filter_sport))
            print("  FILTER_DPORT: {}".format(filter_dport))
            print("  FILTER_PROTOCOL: {}".format(filter_protocol))
        
        b = BPF(text=bpf_text)
        b.attach_kprobe(event="tun_net_xmit", fn_name="probe_tun_net_xmit")
    except Exception as e:
        print("Failed to load BPF program: {}".format(e))
        print("Make sure you have proper permissions and BCC is installed.")
        return
    
    b["filter_enabled"][0] = ct.c_uint32(filter_enabled)
    b["filter_saddr"][0] = ct.c_uint32(filter_saddr)
    b["filter_daddr"][0] = ct.c_uint32(filter_daddr)
    b["filter_sport"][0] = ct.c_uint16(filter_sport)
    b["filter_dport"][0] = ct.c_uint16(filter_dport)
    b["filter_protocol"][0] = ct.c_uint8(filter_protocol)
    
    devname_map = b["name_map"]
    _name = Devname()
    if args.device:
        _name.name = args.device.encode()
        devname_map[0] = _name
        print("Device filter: {} (using verified logic)".format(args.device))
    else:
        _name.name = b""
        devname_map[0] = _name
        print("Device filter: All TUN devices")
    
    if args.all:
        b["show_all_events"][0] = ct.c_uint32(1)
    
    # Print startup info
    print("TUN Ring Monitor Started with BPF Maps Filters...")
    if args.all:
        print("Mode: Monitoring ALL TUN transmit events")
    else:
        print("Mode: Monitoring ptr_ring FULL conditions only")
    
    filters = []
    if args.src_ip: filters.append("src-ip={}".format(args.src_ip))
    if args.dst_ip: filters.append("dst-ip={}".format(args.dst_ip))
    if args.src_port: filters.append("src-port={}".format(args.src_port))
    if args.dst_port: filters.append("dst-port={}".format(args.dst_port))
    if args.protocol: filters.append("protocol={}".format(args.protocol.upper()))
    
    if filters:
        print("5-tuple filters: {}".format(', '.join(filters)))
    
    print(" New feature: Analyzing tun_struct memory layout")
    print("   - tfiles array size calculation")
    print("   - numqueues field offset calculation")
    print("   - Memory layout validation")
    print()
    print("Waiting for TUN device events... Press Ctrl+C to stop")
    
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