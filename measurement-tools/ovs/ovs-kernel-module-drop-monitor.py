#!/usr/bin/env python

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
from socket import inet_ntop, AF_INET, inet_aton, htonl
from struct import pack, unpack
from time import strftime
import os
import socket
import struct
import argparse
import signal

# OVS Connection Tracking state flags
OVS_CS_F_NEW = 0x01
OVS_CS_F_ESTABLISHED = 0x02
OVS_CS_F_RELATED = 0x04
OVS_CS_F_REPLY_DIR = 0x08
OVS_CS_F_INVALID = 0x10
OVS_CS_F_TRACKED = 0x20
OVS_CS_F_SRC_NAT = 0x40
OVS_CS_F_DST_NAT = 0x80

parser = argparse.ArgumentParser(description='Monitor OpenVSwitch deferred action drops')
parser.add_argument('--src-ip', '--src', type=str, help='Source IP address to monitor (in dotted decimal notation)')
parser.add_argument('--dst-ip', '--dst', type=str, help='Destination IP address to monitor (in dotted decimal notation)')
parser.add_argument('--protocol', type=str, choices=['all', 'icmp', 'tcp', 'udp'], default='all', help='Protocol to monitor')
parser.add_argument('--src-port', type=int, help='Source port to monitor (for TCP/UDP)')
parser.add_argument('--dst-port', type=int, help='Destination port to monitor (for TCP/UDP)')
args = parser.parse_args()

# Default values for filters
src_ip = args.src_ip if args.src_ip else "0.0.0.0"
dst_ip = args.dst_ip if args.dst_ip else "0.0.0.0"
src_port = args.src_port if args.src_port else 0
dst_port = args.dst_port if args.dst_port else 0

# Convert IP to hex for BPF program
def ip_to_hex(ip):
    return htonl(unpack("!I", inet_aton(ip))[0])

src_ip_hex = ip_to_hex(src_ip)
dst_ip_hex = ip_to_hex(dst_ip)

# Map protocol string to number
protocol_map = {'all': 0, 'icmp': socket.IPPROTO_ICMP, 'tcp': socket.IPPROTO_TCP, 'udp': socket.IPPROTO_UDP}
protocol_num = protocol_map[args.protocol]

# Print monitoring setup information
print("Monitoring OpenVSwitch deferred action drops")
print("Source IP: {}".format(src_ip))
print("Destination IP: {}".format(dst_ip))
print("Protocol: {}".format(args.protocol))
if args.protocol in ['tcp', 'udp']:
    print("Source port: {}".format(src_port))
    print("Destination port: {}".format(dst_port))

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>

// Remove the problematic include and provide our own definition
// Instead of: #include <linux/openvswitch/flow.h>

// OVS Connection Tracking state flags definitions
#define OVS_CS_F_NEW         0x01
#define OVS_CS_F_ESTABLISHED 0x02
#define OVS_CS_F_RELATED     0x04
#define OVS_CS_F_REPLY_DIR   0x08
#define OVS_CS_F_INVALID     0x10
#define OVS_CS_F_TRACKED     0x20
#define OVS_CS_F_SRC_NAT     0x40
#define OVS_CS_F_DST_NAT     0x80

// Define ETH_ALEN if not defined
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

// Define IP_TUNNEL_OPTS_MAX if not defined
#ifndef IP_TUNNEL_OPTS_MAX
#define IP_TUNNEL_OPTS_MAX 255
#endif

// Simplified version of relevant OVS structures with correct field offsets
struct ip_tunnel_key {
    u64 tun_id;         // 8 bytes
    union {
        struct {
            __be32 src;
            __be32 dst;
        } ipv4;
        struct {
            struct in6_addr src;
            struct in6_addr dst;
        } ipv6;
    } u;
    __be16 tun_flags;   // 2 bytes
    u8 tos;             // 1 byte
    u8 ttl;             // 1 byte
    __be16 tp_src;      // 2 bytes
    __be16 tp_dst;      // 2 bytes
    // Some other fields may be present, but we don't need them
};

struct vlan_head {
    __be16 tpid;
    __be16 tci;
};

// Minimal sw_flow_key structure with exact field offsets to match kernel definition
struct sw_flow_key {
    u8 tun_opts[IP_TUNNEL_OPTS_MAX];  // Tunnel options
    u8 tun_opts_len;                  // Length of tunnel options
    struct ip_tunnel_key tun_key;     // Tunnel key
    struct {
        u32 priority;                 // QoS priority
        u32 skb_mark;                 // SKB mark
        u16 in_port;                  // Input port
    } __attribute__((packed)) phy;    // Physical info
    u8 mac_proto;                     // MAC layer protocol
    u8 tun_proto;                     // Tunnel protocol
    u32 ovs_flow_hash;                // Flow hash
    u32 recirc_id;                    // Recirculation ID
    struct {
        u8 src[ETH_ALEN];             // MAC source
        u8 dst[ETH_ALEN];             // MAC destination
        struct vlan_head vlan;        // VLAN header
        struct vlan_head cvlan;       // CVLAN header
        __be16 type;                  // Ethernet type
    } eth;
    u8 ct_state;                      // CT state - this is the field we need!
    u8 ct_orig_proto;                 // Original protocol
    // Rest of the structure is not needed for our purpose
};

#define SRC_IP 0x%x
#define DST_IP 0x%x
#define SRC_PORT %d
#define DST_PORT %d
#define PROTOCOL %d

// Store clone_execute parameters for each skb
struct clone_exec_data_t {
    u32 recirc_id;
    u8 last;
    u8 clone_flow_key;
    u8 ct_state;     // Add ct_state field
};
BPF_HASH(active_skbs, u64, struct clone_exec_data_t);

// Output data structure
struct ovs_drop_data_t {
    u32 pid;
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u8 icmp_type;
    u8 icmp_code;
    u32 stack_id;
    char ifname[IFNAMSIZ];
    char comm[TASK_COMM_LEN];
    // Clone execute specific fields
    u32 recirc_id;
    u8 last;
    u8 clone_flow_key;
    u8 ct_state;     // Add ct_state field
    char dp_name[16];  // For ovs_dp_name
    int kernel_stack_id;
    int user_stack_id;
};

BPF_PERF_OUTPUT(ovs_drops);
BPF_STACK_TRACE(stack_traces, 32768);

// Probe for clone_execute function to capture parameters
int trace_clone_execute(struct pt_regs *ctx)
{
    // struct datapath *dp, struct sk_buff *skb, struct sw_flow_key *key, 
    // u32 recirc_id, const struct nlattr *actions, int len, bool last, bool clone_flow_key
    
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    struct sw_flow_key *key = (struct sw_flow_key *)PT_REGS_PARM3(ctx);
    u32 recirc_id = (u32)PT_REGS_PARM4(ctx);
    u8 last;
    u8 clone_flow_key;

    // Read last and clone_flow_key from the stack
    bpf_probe_read(&last, sizeof(last), (void *)(ctx->sp + 8 * 6));  // 7th param
    bpf_probe_read(&clone_flow_key, sizeof(clone_flow_key), (void *)(ctx->sp + 8 * 7));  // 8th param
    
    if (skb == NULL || key == NULL)
        return 0;
    
    // Store parameters with skb pointer as key
    u64 skb_ptr = (u64)skb;
    struct clone_exec_data_t data = {};
    data.recirc_id = recirc_id;
    data.last = last;
    data.clone_flow_key = clone_flow_key;
    
    // Extract ct_state from the key
    u8 ct_state;
    //const size_t ct_state_offset = offsetof(struct sw_flow_key, ct_state);
    //bpf_probe_read_kernel(&ct_state, sizeof(ct_state), (void *)key + ct_state_offset);
    bpf_probe_read_kernel(&ct_state, sizeof(ct_state), &key->ct_state);
    //if (ct_state == 0 ) {
    //    return 0;
    //}
    
    data.ct_state = ct_state;
    
    active_skbs.update(&skb_ptr, &data);
    
    return 0;
}

// Probe for kfree_skb to detect dropped packets
int trace_kfree_skb(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    
    if (skb == NULL)
        return 0;
    
    // Check if this skb was seen in clone_execute
    u64 skb_ptr = (u64)skb;
    struct clone_exec_data_t *clone_data = active_skbs.lookup(&skb_ptr);
    if (clone_data == NULL)
        return 0;  // Not from clone_execute we're interested in
    
    // Check if it's an IPv4 packet
    u16 protocol;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    if (protocol != htons(ETH_P_IP))
        goto cleanup;
    
    // Extract IP header
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    u32 saddr = iph.saddr;
    u32 daddr = iph.daddr;
    
    // Filter by IP if specified
    if ((SRC_IP != 0 && saddr != SRC_IP) || (DST_IP != 0 && daddr != DST_IP))
        goto cleanup;
    
    // Filter by protocol if specified
    if (PROTOCOL != 0 && iph.protocol != PROTOCOL)
        goto cleanup;
    
    // Setup output data
    struct ovs_drop_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.saddr = saddr;
    data.daddr = daddr;
    data.protocol = iph.protocol;
    
    // Use only BPF_F_FAST_STACK_CMP to minimize stack depth issues
    // The stack will be compared by hash only, which avoids the BPF_MAX_STACK_DEPTH exceeded error
    data.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP);
    
    // If that still fails, try with both FAST_STACK_CMP and REUSE_STACKID
    if (data.kernel_stack_id < 0) {
        data.kernel_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);
    }
    
    // Get user stack with the same optimizations
    data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK);
    if (data.user_stack_id < 0) {
        data.user_stack_id = stack_traces.get_stackid(ctx, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    }
    
    // Copy clone_execute data
    data.recirc_id = clone_data->recirc_id;
    data.last = clone_data->last;
    data.clone_flow_key = clone_data->clone_flow_key;
    data.ct_state = clone_data->ct_state;
    
    // Device info
    struct net_device *dev;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(data.ifname, sizeof(data.ifname), dev->name);
    
    // Process name
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Protocol specific info
    if (iph.protocol == IPPROTO_ICMP) {
        struct icmphdr icmph;
        bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->transport_header);
        data.icmp_type = icmph.type;
        data.icmp_code = icmph.code;
        ovs_drops.perf_submit(ctx, &data, sizeof(data));
    } else if (iph.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        bpf_probe_read_kernel(&tcph, sizeof(tcph), skb->head + skb->transport_header);
        data.sport = ntohs(tcph.source);
        data.dport = ntohs(tcph.dest);
        
        // Filter by port if specified
        if ((SRC_PORT == 0 || data.sport == SRC_PORT) && 
            (DST_PORT == 0 || data.dport == DST_PORT)) {
            ovs_drops.perf_submit(ctx, &data, sizeof(data));
        }
    } else if (iph.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);
        data.sport = ntohs(udph.source);
        data.dport = ntohs(udph.dest);
        
        // Filter by port if specified
        if ((SRC_PORT == 0 || data.sport == SRC_PORT) && 
            (DST_PORT == 0 || data.dport == DST_PORT)) {
            ovs_drops.perf_submit(ctx, &data, sizeof(data));
        }
    } else {
        // Other protocols
        ovs_drops.perf_submit(ctx, &data, sizeof(data));
    }
    
cleanup:
    // Clean up our entry
    active_skbs.delete(&skb_ptr);
    return 0;
}
"""

# Compile and load BPF program
b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_num))
#b = BPF(text=bpf_text % (src_ip_hex, dst_ip_hex, src_port, dst_port, protocol_num), cflags=["-I/usr/src/$(uname -r)/net/openvswitch/flow.h"])

# Attach kprobes
b.attach_kprobe(event="clone_execute", fn_name="trace_clone_execute")
b.attach_kprobe(event="kfree_skb", fn_name="trace_kfree_skb")

# Process events from perf buffer
def print_ovs_drop_event(cpu, data, size):
    event = b["ovs_drops"].event(data)
    protocol_str = {socket.IPPROTO_ICMP: "ICMP", socket.IPPROTO_TCP: "TCP", socket.IPPROTO_UDP: "UDP"}.get(event.protocol, str(event.protocol))
    
    # Stack trace with better filtering
    stack_id = event.kernel_stack_id
    
    if stack_id >= 0:
        stack_trace = []
        try:
            stack_trace = list(b.get_table("stack_traces").walk(stack_id))
        except KeyError:
            print("  Failed to retrieve stack trace (ID: %d)" % stack_id)

        if stack_trace:
            # where kfree_skb is called directly from clone_execute
            found_target_path = False
            clone_execute_index = None
            
            # First find clone_execute in the stack
            for i, addr in enumerate(stack_trace):
                func_name = b.ksym(addr)
                if b"clone_execute" in func_name:
                    clone_execute_index = i
                    break

            # If found, check if kfree_skb is the function immediately before it in the stack
            # (In stack traces, the caller appears after the callee)
            if clone_execute_index is not None and clone_execute_index > 0:
                prev_func = b.ksym(stack_trace[clone_execute_index - 1])
                if b"kfree_skb" in prev_func:
                    found_target_path = True
            
            if not found_target_path:
                return  # Skip this event, it's not the direct clone_execute -> kfree_skb call
                
            # Now print the actual stack trace
            print("\n=== OpenVSwitch Deferred Action Drop Event ===")
            print("Time: %s  PID: %-6d  Comm: %s" % (
                strftime("%H:%M:%S"), event.pid, event.comm.decode('utf-8')))
            
            print("Source IP: %-15s  Destination IP: %-15s  Protocol: %s" % (
                inet_ntop(AF_INET, pack("I", event.saddr)),
                inet_ntop(AF_INET, pack("I", event.daddr)),
                protocol_str))
            
            # Clone execute parameters
            print("OVS Parameters:")
            print("  recirc_id: 0x%-8x last: %-5s  clone_flow_key: %s" % (
                event.recirc_id, 
                "True" if event.last else "False",
                "True" if event.clone_flow_key else "False"))
                
            ct_state = event.ct_state
            ct_state_flags = []
            
            # Interpret CT state flags based on OVS definitions (rough mapping)
            if ct_state & 0x01: ct_state_flags.append("NEW")         # OVS_CS_F_NEW
            if ct_state & 0x02: ct_state_flags.append("ESTABLISHED") # OVS_CS_F_ESTABLISHED  
            if ct_state & 0x04: ct_state_flags.append("RELATED")     # OVS_CS_F_RELATED
            if ct_state & 0x08: ct_state_flags.append("REPLY_DIR")   # OVS_CS_F_REPLY_DIR
            if ct_state & 0x10: ct_state_flags.append("INVALID")     # OVS_CS_F_INVALID
            if ct_state & 0x20: ct_state_flags.append("TRACKED")     # OVS_CS_F_TRACKED
            if ct_state & 0x40: ct_state_flags.append("SRC_NAT")     # OVS_CS_F_SRC_NAT
            if ct_state & 0x80: ct_state_flags.append("DST_NAT")     # OVS_CS_F_DST_NAT
            
            ct_state_str = ", ".join(ct_state_flags) if ct_state_flags else "NONE"
            print("  ct_state: 0x%02x (%s)" % (ct_state, ct_state_str))
            
            # Protocol specific info
            if event.protocol == socket.IPPROTO_ICMP:
                print("ICMP Type: %-2d  Code: %-2d" % (event.icmp_type, event.icmp_code))
            elif event.protocol in [socket.IPPROTO_TCP, socket.IPPROTO_UDP]:
                print("Source Port: %-5d  Destination Port: %-5d" % (event.sport, event.dport))
            
            print("Device: %s" % event.ifname.decode('utf-8'))
    
            print("Stack Trace:")
            for addr in stack_trace:
                sym = b.ksym(addr, show_offset=True)
                print("  %s" % sym)

            # After displaying the kernel stack trace, add user stack trace display
            print("User Stack Trace:")
            user_stack_id = event.user_stack_id
            
            if user_stack_id >= 0:
                user_stack = []
                try:
                    user_stack = list(b.get_table("stack_traces").walk(user_stack_id))
                except KeyError:
                    print("  Failed to retrieve user stack trace (ID: %d)" % user_stack_id)
                
                if user_stack:
                    for addr in user_stack:
                        # For user-space, we use sym() instead of ksym()
                        symbol = b.sym(addr, event.pid, show_offset=True)
                        if symbol:
                            print("  %s" % symbol)
                        else:
                            print("  0x%x" % addr)
                else:
                    print("  No user stack frames found")
            else:
                error_code = abs(user_stack_id)
                error_msg = "Unknown error"
                if error_code == 1:
                    error_msg = "EFAULT: Bad address"
                elif error_code == 2:
                    error_msg = "ENOENT: No such entry"
                elif error_code == 12:
                    error_msg = "ENOMEM: Out of memory"
                elif error_code == 22:
                    error_msg = "EINVAL: Invalid argument"
                elif error_code == 14:
                    error_msg = "BPF_MAX_STACK_DEPTH exceeded"
                elif error_code == 16:
                    error_msg = "Resource temporarily unavailable"
                elif error_code == 524:
                    error_msg = "Uprobe not found"
                
                print("  Failed to capture user stack trace (Error: %s, code: %d)" % 
                    (error_msg, error_code))
            
            #print("===============================================")
    else:
        error_code = abs(event.kernel_stack_id)
        error_msg = "Unknown error"
        if error_code == 1:
            error_msg = "EFAULT: Bad address"
        elif error_code == 2:
            error_msg = "ENOENT: No such entry"
        elif error_code == 12:
            error_msg = "ENOMEM: Out of memory"
        elif error_code == 22:
            error_msg = "EINVAL: Invalid argument"
        elif error_code == 14:
            error_msg = "BPF_MAX_STACK_DEPTH exceeded"
        elif error_code == 16:
            error_msg = "Resource temporarily unavailable"
        elif error_code == 524:
            error_msg = "Uprobe not found"
        
        print("  Failed to capture stack trace (Error: %s, code: %d)" % 
              (error_msg, error_code))
    
    #print("===============================================")

b["ovs_drops"].open_perf_buffer(print_ovs_drop_event)

# Handle Ctrl-C gracefully
def signal_handler(sig, frame):
    print("\nExiting...")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop
print("Tracing OpenVSwitch deferred action drops... Hit Ctrl-C to end.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit() 
