#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Note: Added encoding declaration for Python 2

from __future__ import print_function
# BCC module import with fallback
try:
    from bcc import BPF
    from bcc.utils import printb
except ImportError:
    try:
        from bpfcc import BPF
        from bpfcc.utils import printb
    except ImportError:
        import sys
        print("Error: Neither bcc nor bpfcc module found!")
        if sys.version_info[0] == 3:
            print("Please install: python3-bcc or python3-bpfcc")
        else:
            print("Please install: python-bcc or python2-bcc")
        sys.exit(1)
import ctypes as ct
from socket import inet_ntop, AF_INET, inet_aton, htonl, ntohs, ntohl
from struct import pack, unpack
from time import strftime
import os
import socket
import struct
import argparse
import signal
import traceback

parser = argparse.ArgumentParser(description='Trace IP defragmentation events, focusing on duplicates.')
parser.add_argument('--src-ip', type=str, help='Source IP address to monitor (e.g., 192.168.1.1)')
parser.add_argument('--dst-ip', type=str, help='Destination IP address to monitor (e.g., 10.0.0.2)')
parser.add_argument('--protocol', type=str, help='Protocol to monitor (e.g., tcp, udp, icmp or number)')
parser.add_argument('--log-file', type=str, help='Path to log file (if specified, output will be written to this file)')
args = parser.parse_args()

# --- Helper Functions ---
def ip_to_hex(ip_str):
    """Converts dotted decimal IP string to network byte order integer, then host byte order for BPF."""
    if not ip_str:
        return 0
    try:
        # Convert to network byte order binary
        packed_ip = inet_aton(ip_str)
        # Unpack as network byte order integer
        network_order_int = unpack("!I", packed_ip)[0]
        # BPF usually expects host byte order for direct comparison in C
        # However, kernel IP addresses are often network byte order. Let's keep it network byte order.
        # return ntohl(network_order_int) # Convert to host byte order if needed by BPF code logic
        return network_order_int # Keep as network byte order - consistent with skb fields
    except socket.error:
        print("Error: Invalid IP address format: {}".format(ip_str))
        exit(1)

def proto_to_int(proto_str):
    """Converts protocol name or number string to integer."""
    if not proto_str:
        return 0
    proto_str = proto_str.lower()
    if proto_str == "tcp":
        return socket.IPPROTO_TCP
    elif proto_str == "udp":
        return socket.IPPROTO_UDP
    elif proto_str == "icmp":
        return socket.IPPROTO_ICMP
    try:
        num = int(proto_str)
        if 0 <= num <= 255:
            return num
        else:
            raise ValueError
    except ValueError:
        print("Error: Invalid protocol: {}. Use tcp, udp, icmp or a number 0-255.".format(proto_str))
        exit(1)

# Resolve IPs and Protocol
src_ip_int = ip_to_hex(args.src_ip)
dst_ip_int = ip_to_hex(args.dst_ip)
protocol_num = proto_to_int(args.protocol)

# Pre-format values for BPF text substitution
src_ip_hex_str = "0x{:x}".format(src_ip_int)
dst_ip_hex_str = "0x{:x}".format(dst_ip_int)
protocol_str = "{:d}".format(protocol_num)

log_f = None
if args.log_file:
    try:
        log_f = open(args.log_file, 'w')
    except IOError as e:
        print("Error opening log file {}: {}".format(args.log_file, e))
        log_f = None # Disable logging if file cannot be opened

def log_print(message):
    """Prints to console and optionally logs to file."""
    print(message)
    if log_f:
        log_f.write(message + '\n')
        log_f.flush() # Ensure it's written immediately

# --- BPF C Code ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <net/inet_frag.h> // Required for inet_frag_queue, IPFRAG_DUP etc.

#define IFNAMSIZ 16 // Defined in linux/if.h
#define TASK_COMM_LEN 16 // Defined in linux/sched.h

// Filter definitions - Use unique placeholders for Python's .replace()
#define FILTER_SRC_IP @@SRC_IP@@
#define FILTER_DST_IP @@DST_IP@@
#define FILTER_PROTOCOL @@PROTOCOL@@

// Use the kernel's definition for IPFRAG_DUP (usually 1)
// #define IPFRAG_DUP (-2) // Remove our incorrect definition

// Structure to hold basic SKB info
struct skb_info_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char ifname[IFNAMSIZ];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 l4_hdr_set; // Flag to indicate if L4 header was successfully read
    // MAC addresses (optional, might require more checks for header presence)
    // u8 src_mac[ETH_ALEN];
    // u8 dst_mac[ETH_ALEN];
};

// Structure for ip_defrag event data
struct ip_defrag_data_t {
    struct skb_info_t skb_info;
    u32 user;
};
BPF_PERF_OUTPUT(ip_defrag_events);

// Structure to store arguments between entry and return probes for insert
struct frag_insert_args_t {
    struct inet_frag_queue *q;
    struct sk_buff *skb;
    int offset;
    int end;
};
BPF_HASH(insert_args_map, u64, struct frag_insert_args_t);

// Structure for inet_frag_queue_insert event data (when returning IPFRAG_DUP)
struct frag_insert_data_t {
    struct skb_info_t skb_info;
    // Queue identification (from q->key.v4)
    u32 q_saddr;
    u32 q_daddr;
    u16 q_id;
    u8 q_protocol;
    // Insert parameters
    int offset;
    int end;
};
BPF_PERF_OUTPUT(frag_insert_dup_events);

// Structure for kfree_skb event data
struct kfree_skb_data_t {
    struct skb_info_t skb_info;
    int stack_id; // Change to int to hold potential negative error codes
};
BPF_PERF_OUTPUT(kfree_events);
BPF_STACK_TRACE(stack_traces, 8192); // Increase size if needed

// Helper function to extract SKB details
static inline int get_skb_details(struct sk_buff *skb, struct skb_info_t *info) {
    bpf_trace_printk("get_skb_details entered\\n");
    if (!skb) return -1;

    info->ts = bpf_ktime_get_ns();
    info->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info->comm, sizeof(info->comm));

    // --- Device Name Reading + Debug ---
    struct net_device *dev = NULL;
    int name_read_ret = -1; // Store result of reading name
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (dev) {
        // Attempt to read the name
        name_read_ret = bpf_probe_read_kernel_str(&info->ifname, IFNAMSIZ, dev->name);
        if (name_read_ret < 0) {
            // If reading failed, clear the buffer just in case
             __builtin_memset(info->ifname, 0, IFNAMSIZ);
        }
    } else {
        // dev pointer is NULL, clear the buffer
        __builtin_memset(info->ifname, 0, IFNAMSIZ);
    }
    bpf_trace_printk("get_skb_details: dev_ptr=%llx, name_read_ret=%d\\n", dev, name_read_ret);
    // --- End Device Name Reading + Debug ---

    // Check if it's an IP packet (needed before accessing network_header)
    u16 network_proto;
    bpf_probe_read_kernel(&network_proto, sizeof(network_proto), &skb->protocol);
     if (network_proto != htons(ETH_P_IP)) {
         return -2; // Not an IPv4 packet
     }

    // Read IP header using offsets
    unsigned char *head = NULL;
    u16 network_header = 0;
    u16 transport_header = 0;

    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) < 0) {
        return -3; // Failed to read IP header
    }

    info->saddr = iph.saddr; // Already in Network Byte Order
    info->daddr = iph.daddr; // Already in Network Byte Order
    info->protocol = iph.protocol;

    // Basic filtering based on IP/Proto
    if ((FILTER_SRC_IP != 0 && info->saddr != FILTER_SRC_IP) ||
        (FILTER_DST_IP != 0 && info->daddr != FILTER_DST_IP) ||
        (FILTER_PROTOCOL != 0 && info->protocol != FILTER_PROTOCOL)) {
        return -10; // Packet doesn't match filter criteria
    }

    // Read L4 header (TCP/UDP/ICMP)
    info->l4_hdr_set = 0;
    info->sport = 0;
    info->dport = 0;
    if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + transport_header) == 0) {
            info->sport = tcph.source; // Keep Network Byte Order
            info->dport = tcph.dest;   // Keep Network Byte Order
            info->l4_hdr_set = 1;
        }
    } else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), head + transport_header) == 0) {
            info->sport = udph.source; // Keep Network Byte Order
            info->dport = udph.dest;   // Keep Network Byte Order
            info->l4_hdr_set = 1;
        }
    } else if (iph.protocol == IPPROTO_ICMP) {
         // ICMP doesn't have ports in the same way, maybe read type/code later if needed
         info->l4_hdr_set = 1; // Indicate we identified ICMP
    }
    // Add more protocols if needed

    // MAC Address reading (Example - requires skb->mac_header to be valid)
    /*
    u16 mac_header_offset;
    bpf_probe_read_kernel(&mac_header_offset, sizeof(mac_header_offset), &skb->mac_header);
    struct ethhdr *eth = (struct ethhdr *)(head + mac_header_offset);
    bpf_probe_read_kernel(&info->src_mac, ETH_ALEN, eth->h_source);
    bpf_probe_read_kernel(&info->dst_mac, ETH_ALEN, eth->h_dest);
    */

    return 0; // Success
}


// --- Kprobes ---

// 1. ip_defrag entry
int trace_ip_defrag(struct pt_regs *ctx, struct net *net, struct sk_buff *skb, u32 user) {
    struct ip_defrag_data_t data = {};
    int ret = get_skb_details(skb, &data.skb_info);
    if (ret < 0) {
        return 0;
    }
    data.user = user;
    ip_defrag_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 2a. inet_frag_queue_insert entry - Store arguments
int trace_inet_frag_queue_insert_entry(struct pt_regs *ctx, struct inet_frag_queue *q, struct sk_buff *skb, int offset, int end) {
    struct skb_info_t skb_info = {};
    int ret = get_skb_details(skb, &skb_info);
    if (ret < 0) { // Catches -1, -2, -3 (parsing failed) and -10 (filtered)
        return 0;
    }
    // Note: If ret was 0 or -10, parsing was initially ok.
    // The filter check `if (ret < 0)` below will catch -10 specifically.
     if (ret < 0) { // This catches ret == -10 (parsed OK but filtered out)
         return 0; // Skb itself doesn't match filter, don't store args
     }
    u64 id = bpf_get_current_pid_tgid();
    struct frag_insert_args_t args = {};
    args.q = q;
    args.skb = skb;
    args.offset = offset;
    args.end = end;
    insert_args_map.update(&id, &args);
    return 0;
}

// 2b. inet_frag_queue_insert return - Check return value and report DUP
int trace_inet_frag_queue_insert_return(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct frag_insert_args_t *args = insert_args_map.lookup(&id);
    if (!args) {
        return 0;
    }
    int ret = PT_REGS_RC(ctx);
    if (ret == IPFRAG_DUP) {
        struct frag_insert_data_t data = {};
        int skb_ret = get_skb_details(args->skb, &data.skb_info);
        if (skb_ret < 0) {
             goto cleanup;
        }
        if (args->q) {
            struct frag_v4_compare_key key_v4;
            if (bpf_probe_read_kernel(&key_v4, sizeof(key_v4), &args->q->key.v4) == 0) {
                data.q_saddr = key_v4.saddr;
                data.q_daddr = key_v4.daddr;
                data.q_id = key_v4.id;
                data.q_protocol = key_v4.protocol;
            }
        }
        data.offset = args->offset;
        data.end = args->end;
        frag_insert_dup_events.perf_submit(ctx, &data, sizeof(data));
    }
cleanup:
    insert_args_map.delete(&id);
    return 0;
}


// 3. kfree_skb entry - Check stack trace
int trace_kfree_skb(struct pt_regs *ctx, struct sk_buff *skb) {
    struct kfree_skb_data_t data = {};
    int ret = get_skb_details(skb, &data.skb_info);
    if (ret < 0) {
        return 0;
    }
    data.stack_id = stack_traces.get_stackid(ctx, 0);
    kfree_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# --- Python Processing ---

# Load BPF program
try:
    # Replace the unique placeholders using simple string replacement
    replaced_bpf_text = bpf_text.replace("@@SRC_IP@@", src_ip_hex_str) \
                                .replace("@@DST_IP@@", dst_ip_hex_str) \
                                .replace("@@PROTOCOL@@", protocol_str)

    # Pass the replaced string to BPF
    b = BPF(text=replaced_bpf_text)
except Exception as e:
    # Print detailed exception information
    print("Error loading BPF program:")
    print("-" * 20)
    traceback.print_exc() # Print the full traceback
    print("-" * 20)
    # Also print the specific error message
    print("Error Message: {}".format(e))
    # Optionally print the BPF text *after* replacement
    # print("\n--- Replaced BPF Text ---")
    # print(replaced_bpf_text)
    # print("--- End BPF Text ---")

    if "inet_frag.h" in str(e):
        print("\nHint: Ensure kernel headers are installed and accessible (e.g., linux-headers-`uname -r`)")
    exit(1)


# Attach probes
# 1. ip_defrag
b.attach_kprobe(event="ip_defrag", fn_name="trace_ip_defrag")

# 2. inet_frag_queue_insert (entry and return)
b.attach_kprobe(event="inet_frag_queue_insert", fn_name="trace_inet_frag_queue_insert_entry")
b.attach_kretprobe(event="inet_frag_queue_insert", fn_name="trace_inet_frag_queue_insert_return")

# 3. kfree_skb (or a more central variant like __kfree_skb)
# Try __kfree_skb first, fallback to kfree_skb if it doesn't exist
kfree_func_name = "__kfree_skb"
if BPF.get_kprobe_functions(b"__kfree_skb"):
     b.attach_kprobe(event="__kfree_skb", fn_name="trace_kfree_skb")
elif BPF.get_kprobe_functions(b"kfree_skb"):
     kfree_func_name = "kfree_skb"
     b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")
else:
    print("Warning: Could not find kprobe for '__kfree_skb' or 'kfree_skb'. Free events will not be traced.")
    kfree_func_name = None


# --- Data Structures (Matching C structs) ---
class SkbInfo(ct.Structure):
    _fields_ = [
        ("ts", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("comm", ct.c_char * 16), # TASK_COMM_LEN
        ("ifname", ct.c_char * 16), # IFNAMSIZ
        ("saddr", ct.c_uint), # Network byte order
        ("daddr", ct.c_uint), # Network byte order
        ("sport", ct.c_ushort), # Network byte order
        ("dport", ct.c_ushort), # Network byte order
        ("protocol", ct.c_ubyte),
        ("l4_hdr_set", ct.c_ubyte),
    ]

class IpDefragData(ct.Structure):
    _fields_ = [
        ("skb_info", SkbInfo),
        ("user", ct.c_uint),
    ]

class FragInsertData(ct.Structure):
     _fields_ = [
        ("skb_info", SkbInfo),
        ("q_saddr", ct.c_uint), # Network byte order
        ("q_daddr", ct.c_uint), # Network byte order
        ("q_id", ct.c_ushort),  # Network byte order? Check kernel source - likely host order in struct key, convert if needed
        ("q_protocol", ct.c_ubyte),
        ("offset", ct.c_int),
        ("end", ct.c_int),
    ]

class KfreeSkbData(ct.Structure):
     _fields_ = [
        ("skb_info", SkbInfo),
        ("stack_id", ct.c_int), # Changed to c_int to match BPF struct
    ]

# --- Event Handling Functions ---

def get_ip_str(nbo_ip_int):
    """Convert Network Byte Order integer to IP string."""
    try:
        # Use native byte order "I" since ctypes already interprets the bytes
        # in host order, and we need to preserve the original network byte layout
        return inet_ntop(AF_INET, pack("I", nbo_ip_int))
    except ValueError:
        return str(nbo_ip_int) # Fallback if invalid

def get_port_str(nbo_port_short):
    """Convert Network Byte Order short to Port string."""
    return str(ntohs(nbo_port_short))

def format_skb_info(skb_info):
    """Formats the SkbInfo structure into a readable string."""
    time_str = strftime("%H:%M:%S.%f")[:-3] # Time with milliseconds
    pid_comm = "{}/{}".format(skb_info.pid, skb_info.comm.decode('utf-8', 'replace'))
    dev = skb_info.ifname.decode('utf-8', 'replace') or "?"

    src_ip = get_ip_str(skb_info.saddr)
    dst_ip = get_ip_str(skb_info.daddr)
    proto = skb_info.protocol

    l4_info = "Proto={}".format(proto)
    if skb_info.l4_hdr_set:
        if proto == socket.IPPROTO_TCP or proto == socket.IPPROTO_UDP:
            sport = get_port_str(skb_info.sport)
            dport = get_port_str(skb_info.dport)
            l4_info = "{}:{} -> {}:{} Proto={}".format(src_ip, sport, dst_ip, dport, proto)
        elif proto == socket.IPPROTO_ICMP:
             l4_info = "{} -> {} Proto=ICMP".format(src_ip, dst_ip)
    else:
        l4_info = "{} -> {} Proto={} (L4 hdr?)".format(src_ip, dst_ip, proto)

    return "{} {:<20} DEV={:<6} {}".format(time_str, pid_comm, dev, l4_info)

def print_ip_defrag_event(cpu, data, size):
    """Callback for ip_defrag_events perf buffer."""
    event = ct.cast(data, ct.POINTER(IpDefragData)).contents
    skb_summary = format_skb_info(event.skb_info)
    log_print("[ip_defrag] {} User={}".format(skb_summary, event.user))

def print_frag_insert_dup_event(cpu, data, size):
    """Callback for frag_insert_dup_events perf buffer."""
    event = ct.cast(data, ct.POINTER(FragInsertData)).contents
    skb_summary = format_skb_info(event.skb_info)
    q_src = get_ip_str(event.q_saddr)
    q_dst = get_ip_str(event.q_daddr)
    # q_id is likely host order in the key struct, but read as network order if needed
    q_id_val = ntohs(event.q_id) # Assuming kernel stores it host order in frag_v4_compare_key

    log_print("[DUP_INSERT] {} Queue=({}->{} ID={} Proto={}) Offset={} End={}".format(
        skb_summary, q_src, q_dst, q_id_val, event.q_protocol, event.offset, event.end))

def print_kfree_event(cpu, data, size):
    """Callback for kfree_events perf buffer."""
    event = ct.cast(data, ct.POINTER(KfreeSkbData)).contents
    stack_id = event.stack_id

    found_relevant_frame = True
    relevant_frames = []
    stack_trace_str = "[Stack Trace Unavailable (ID: {})]".format(stack_id)

    # Try to get stack trace only if stack_id looks valid (non-negative)
    if stack_id >= 0:
        try:
            stack_trace = list(b.get_table("stack_traces").walk(stack_id))
            stack_trace_str = "" # Clear the unavailable message
            for addr in stack_trace:
                sym = b.ksym(addr, show_offset=True)
                sym_decoded = sym.decode('utf-8', 'replace')
                # Store the full trace line for potential printing later
                stack_trace_str += "    - {}\n".format(sym_decoded)
                # if not found_relevant_frame and \
                #    ("inet_frag_queue_insert" in sym_decoded or \
                #     "ip_frag_queue" in sym_decoded or \
                #     "ip_defrag" in sym_decoded):
                #     found_relevant_frame = True
                    # Store only the relevant frames if needed for summary
                    # relevant_frames.append(sym_decoded) # Or just use found_relevant_frame flag

        except KeyError:
            # Stack ID was valid but not found in the table (e.g., evicted)
             stack_trace_str = "[Stack Trace Missing (ID: {})]".format(stack_id)
        except Exception as e:
            # Handle other potential errors during stack walk
            stack_trace_str = "[Error getting stack trace (ID: {}): {}]".format(stack_id, e)


    if found_relevant_frame:
        skb_summary = format_skb_info(event.skb_info)
        log_print("[kfree_skb] {} StackID={} (Fragment Related)".format(skb_summary, stack_id))
        # Print the full stack trace string we built (or the error message)
        log_print("  Stack Trace:\n{}".format(stack_trace_str.rstrip())) # rstrip removes trailing newline
    # Else: If no relevant frame was found, we don't print the kfree event

# --- Main Loop ---

print("Attaching probes... Press Ctrl-C to exit.")
if args.log_file:
    print("Logging output to: {}".format(args.log_file))

# Define desired page count (e.g., 128, 256, or higher if needed)
buffer_page_cnt = 128

# Open Perf Buffers with increased size
b["ip_defrag_events"].open_perf_buffer(print_ip_defrag_event, page_cnt=buffer_page_cnt)
b["frag_insert_dup_events"].open_perf_buffer(print_frag_insert_dup_event, page_cnt=buffer_page_cnt)
if kfree_func_name: # Only open if kfree probe was attached
    b["kfree_events"].open_perf_buffer(print_kfree_event, page_cnt=buffer_page_cnt)

# Signal handler for clean exit
running = True
def signal_handler(sig, frame):
    global running
    print("\nDetaching probes and exiting...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# Start polling
while running:
    try:
        b.perf_buffer_poll(timeout=100) # Poll with a timeout
    except KeyboardInterrupt:
        # Redundant due to signal handler, but good practice
        signal_handler(signal.SIGINT, None)

# Cleanup
if log_f:
    log_f.close()
