#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
SKB VXLAN Source Detector

Comprehensive tool to identify where and how VXLAN gso_type flags appear on SKBs.
Combines static system inspection with dynamic eBPF tracing to answer:
"Why does my VM have VXLAN traffic when it's configured with IPIP?"

This tool addresses the mystery where:
- VM is configured with Calico IPIP (no VXLAN devices)
- RX packets look normal
- TX packets have VXLAN encapsulation
- Crash occurs with SKB_GSO_UDP_TUNNEL flag

Key investigations:
1. Static checks: Network devices, tunnel configuration, virtio features
2. gso_type propagation: Where is SKB_GSO_UDP_TUNNEL set?
3. Virtio RX inspection: What's in virtio_net_hdr?
4. Tunnel metadata: Does SKB carry tunnel metadata?
5. GRO/GSO state: How do GRO completion functions affect gso_type?

Usage:
    # Full analysis with static checks + tracing
    sudo python skb_vxlan_source_detector.py

    # Skip static checks (faster)
    sudo python skb_vxlan_source_detector.py --no-static-check

    # Focus on specific interface
    sudo python skb_vxlan_source_detector.py --interface eth0

    # Filter by IP
    sudo python skb_vxlan_source_detector.py --src-ip 10.132.114.11

    # Only show events that set/modify gso_type
    sudo python skb_vxlan_source_detector.py --gso-changes-only

Author: Automated kernel crash analysis
"""

from __future__ import print_function
import sys
import argparse
import ctypes
import socket
import struct
import subprocess
import re
import os
from datetime import datetime
import signal

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

# Global flag for graceful exit
exiting = False

def signal_handler(sig, frame):
    global exiting
    exiting = True

# Color codes for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print("\n" + Colors.BOLD + Colors.HEADER + "=" * 80 + Colors.ENDC)
    print(Colors.BOLD + Colors.HEADER + text + Colors.ENDC)
    print(Colors.BOLD + Colors.HEADER + "=" * 80 + Colors.ENDC)

def print_section(text):
    print("\n" + Colors.BOLD + Colors.OKCYAN + "--- " + text + " ---" + Colors.ENDC)

def print_warning(text):
    print(Colors.WARNING + "[!] " + text + Colors.ENDC)

def print_error(text):
    print(Colors.FAIL + "[ERROR] " + text + Colors.ENDC)

def print_ok(text):
    print(Colors.OKGREEN + "[+] " + text + Colors.ENDC)

def run_cmd(cmd):
    """Run shell command and return output"""
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        if sys.version_info[0] >= 3:
            output = output.decode('utf-8', 'replace')
        return output.strip()
    except subprocess.CalledProcessError:
        return None

def static_system_checks():
    """Perform static system inspection"""
    print_header("STATIC SYSTEM INSPECTION")

    # 1. Check tunnel devices
    print_section("1. Tunnel Devices")

    # VXLAN devices
    vxlan_devs = run_cmd("ip link show type vxlan 2>/dev/null")
    if vxlan_devs:
        print_warning("Found VXLAN devices:")
        print(vxlan_devs)
    else:
        print_ok("No VXLAN devices found")

    # IPIP devices
    ipip_devs = run_cmd("ip link show type ipip 2>/dev/null")
    if ipip_devs:
        print_ok("Found IPIP devices:")
        print(ipip_devs)
    else:
        print("  No IPIP devices found")

    # All tunnel devices
    tunnel_info = run_cmd("ip tunnel show 2>/dev/null")
    if tunnel_info:
        print("\n  All tunnel interfaces:")
        print("  " + tunnel_info.replace("\n", "\n  "))

    # 2. Check VXLAN ports
    print_section("2. VXLAN Port Listeners")
    vxlan_ports = run_cmd("ss -nlup | grep -E ':4789|:8472' 2>/dev/null")
    if vxlan_ports:
        print_warning("Found VXLAN port listeners (4789/8472):")
        print("  " + vxlan_ports.replace("\n", "\n  "))
    else:
        print_ok("No VXLAN ports listening")

    # 3. Check Calico configuration
    print_section("3. Calico Configuration")

    calico_config = run_cmd("calicoctl get ippool -o yaml 2>/dev/null")
    if calico_config:
        print("  Calico IP Pools:")
        for line in calico_config.split('\n'):
            if 'ipipMode' in line or 'vxlanMode' in line or 'name:' in line:
                print("  " + line)
    else:
        print("  Calico CLI not available, checking CNI config...")
        cni_config = run_cmd("cat /etc/cni/net.d/* 2>/dev/null | grep -E 'ipam|type|ipip|vxlan'")
        if cni_config:
            print("  " + cni_config.replace("\n", "\n  "))

    # 4. Check Virtio features
    print_section("4. Virtio Network Features")

    # Find virtio interfaces
    virtio_ifs = run_cmd("ls -l /sys/class/net/*/device/driver 2>/dev/null | grep virtio | awk -F'/' '{print $5}'")
    if virtio_ifs:
        for iface in virtio_ifs.split('\n'):
            if iface:
                print("\n  Interface: " + iface)

                # Check offload features
                offloads = run_cmd("ethtool -k " + iface + " 2>/dev/null | grep -E 'tx-udp|tx-gso|tx-checksum|rx-gro'")
                if offloads:
                    print("  Offload features:")
                    for line in offloads.split('\n'):
                        if 'on' in line:
                            print("    " + line)

                # Check driver info
                driver_info = run_cmd("ethtool -i " + iface + " 2>/dev/null")
                if driver_info:
                    for line in driver_info.split('\n'):
                        if 'driver' in line or 'version' in line:
                            print("  " + line)
    else:
        print("  No virtio network interfaces found")

    # 5. Check for OVS
    print_section("5. OVS Configuration (if accessible)")
    ovs_info = run_cmd("ovs-vsctl show 2>/dev/null")
    if ovs_info:
        print("  OVS found:")
        # Look for tunnel ports
        for line in ovs_info.split('\n'):
            if 'vxlan' in line.lower() or 'Port' in line or 'Bridge' in line:
                print("  " + line)
    else:
        print("  OVS not accessible (normal for VM guest)")

    # 6. Check network namespaces
    print_section("6. Network Namespaces")
    netns = run_cmd("ip netns list 2>/dev/null")
    if netns:
        print("  Found namespaces:")
        for ns in netns.split('\n'):
            print("    " + ns)
            # Check for VXLAN in each namespace
            vxlan_in_ns = run_cmd("ip netns exec " + ns.split()[0] + " ip link show type vxlan 2>/dev/null")
            if vxlan_in_ns:
                print_warning("      VXLAN in namespace: " + ns)
                print("      " + vxlan_in_ns.replace("\n", "\n      "))
    else:
        print("  No network namespaces (or permission denied)")

    # 7. Check routing
    print_section("7. Routing Configuration")
    print("  IP forwarding: " + run_cmd("sysctl net.ipv4.ip_forward 2>/dev/null"))
    print("  Default route: ")
    routes = run_cmd("ip route show default 2>/dev/null")
    if routes:
        print("    " + routes)

    # 8. Summary and recommendations
    print_section("8. Analysis Summary")

    has_vxlan_dev = bool(vxlan_devs)
    has_vxlan_port = bool(vxlan_ports)
    has_ipip = bool(ipip_devs)

    if has_vxlan_dev or has_vxlan_port:
        print_warning("VXLAN infrastructure detected in this environment")
        if not has_vxlan_dev and has_vxlan_port:
            print_warning("  VXLAN ports listening but no local devices")
            print_warning("  → Possible host-level VXLAN (Scenario 1)")
    else:
        print_ok("No VXLAN infrastructure in VM")
        print_warning("But crash shows VXLAN gso_type...")
        print("  → Likely host-level VXLAN or GRO state leakage")

    if has_ipip:
        print_ok("IPIP tunnels configured (expected for Calico IPIP mode)")

    print("\nProceed to dynamic tracing to identify gso_type source...")

# BPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/virtio_net.h>

// Configuration
#define SRC_IP_FILTER 0x%x
#define DST_IP_FILTER 0x%x
#define TARGET_IFINDEX %d
#define GSO_CHANGES_ONLY %d

// virtio_net_hdr structure (simplified)
struct virtio_net_hdr_simple {
    __u8 flags;
    __u8 gso_type;
    __le16 hdr_len;
    __le16 gso_size;
    __le16 csum_start;
    __le16 csum_offset;
};

// skb_shared_info minimal
struct skb_shared_info_min {
    __u8 __unused;
    __u8 meta_len;
    __u8 nr_frags;
    __u8 tx_flags;
    unsigned short gso_size;
    unsigned short gso_segs;
    struct sk_buff *frag_list;
    // ... rest omitted
    unsigned int gso_type;
};

// Event types
#define EVENT_GSO_TYPE_SET       1
#define EVENT_GSO_TYPE_CHANGE    2
#define EVENT_VIRTIO_RX          3
#define EVENT_GRO_COMPLETE       4
#define EVENT_TUNNEL_DECAP       5

// Event structure
struct gso_event_t {
    u64 timestamp_ns;
    u64 skb_addr;

    u32 gso_type_before;
    u32 gso_type_after;
    u16 gso_size;
    u16 gso_segs;

    u8 event_type;
    u8 virtio_gso_type;     // From virtio_net_hdr
    u8 virtio_flags;
    u8 encapsulation;

    u32 src_ip;
    u32 dst_ip;
    u16 inner_protocol;
    u16 pad;

    u32 pid;
    u32 cpu;
    char func_name[32];
    char comm[16];
    char dev_name[16];
};

BPF_HASH(skb_gso_state, u64, u32, 10240);
BPF_PERF_OUTPUT(events);
BPF_ARRAY(stats, u64, 10);
// 0: total_events, 1: gso_set, 2: gso_change, 3: virtio_rx, 4: gro_complete

// Helper: Get skb_shared_info
static __always_inline struct skb_shared_info_min* get_shinfo(struct sk_buff *skb) {
    unsigned char *head;
    u32 end_offset;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0) {
        return NULL;
    }

    if (bpf_probe_read_kernel(&end_offset, sizeof(end_offset), &skb->end) != 0) {
        return NULL;
    }

    return (struct skb_shared_info_min *)(head + end_offset);
}

// Helper: Check filters
static __always_inline int should_trace(struct sk_buff *skb) {
    // Interface filter
    if (TARGET_IFINDEX != 0) {
        struct net_device *dev;
        int ifindex;

        if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) != 0 || !dev) {
            return 0;
        }

        if (bpf_probe_read_kernel(&ifindex, sizeof(ifindex), &dev->ifindex) != 0) {
            return 0;
        }

        if (ifindex != TARGET_IFINDEX) {
            return 0;
        }
    }

    // IP filters
    if (SRC_IP_FILTER != 0 || DST_IP_FILTER != 0) {
        unsigned char *head;
        u16 network_header;
        struct iphdr ip;

        if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0) {
            return 1;
        }

        if (bpf_probe_read_kernel(&network_header, sizeof(network_header),
                                  &skb->network_header) != 0) {
            return 1;
        }

        if (network_header == (u16)~0U) {
            return 1;
        }

        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) != 0) {
            return 1;
        }

        if (SRC_IP_FILTER != 0 && ip.saddr != SRC_IP_FILTER) {
            return 0;
        }

        if (DST_IP_FILTER != 0 && ip.daddr != DST_IP_FILTER) {
            return 0;
        }
    }

    return 1;
}

// Helper: Fill common event fields
static __always_inline void fill_event_common(struct gso_event_t *event,
                                               struct sk_buff *skb,
                                               const char *func) {
    event->timestamp_ns = bpf_ktime_get_ns();
    event->skb_addr = (u64)skb;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_strncpy(event->func_name, func, sizeof(event->func_name));

    // Get device name
    struct net_device *dev;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0 && dev) {
        bpf_probe_read_kernel_str(&event->dev_name, sizeof(event->dev_name), &dev->name);
    }

    // Get IP addresses
    unsigned char *head;
    u16 network_header;
    struct iphdr ip;

    event->src_ip = 0;
    event->dst_ip = 0;

    if (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) == 0 &&
        bpf_probe_read_kernel(&network_header, sizeof(network_header),
                              &skb->network_header) == 0 &&
        network_header != (u16)~0U) {

        if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
            event->src_ip = ip.saddr;
            event->dst_ip = ip.daddr;
        }
    }

    // Get encapsulation info - bitfield workaround
    // Note: skb->encapsulation is a bitfield, cannot take address directly
    // We'll leave it as 0 for now as it's not critical for debugging
    event->encapsulation = 0;

    __be16 inner_proto;
    if (bpf_probe_read_kernel(&inner_proto, sizeof(inner_proto),
                              &skb->inner_protocol) == 0) {
        event->inner_protocol = bpf_ntohs(inner_proto);
    }
}

// Trace: receive_buf (virtio_net RX - key point!)
int trace_receive_buf(struct pt_regs *ctx, struct sk_buff *skb) {
    if (!should_trace(skb)) {
        return 0;
    }

    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (!shinfo) {
        return 0;
    }

    // Try to read virtio_net_hdr from skb head
    // virtio_net_hdr is at the beginning of the packet data
    unsigned char *data;
    if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) != 0) {
        return 0;
    }

    struct virtio_net_hdr_simple vhdr = {};
    bpf_probe_read_kernel(&vhdr, sizeof(vhdr), data);

    // Read GSO info from shinfo
    u32 gso_type;
    u16 gso_size;
    bpf_probe_read_kernel(&gso_type, sizeof(gso_type), &shinfo->gso_type);
    bpf_probe_read_kernel(&gso_size, sizeof(gso_size), &shinfo->gso_size);

    // If gso_type has UDP_TUNNEL, this is interesting!
    if (gso_type & (1 << 1)) {  // SKB_GSO_UDP_TUNNEL
        struct gso_event_t event = {};
        event.event_type = EVENT_VIRTIO_RX;
        event.gso_type_after = gso_type;
        event.gso_size = gso_size;
        event.virtio_gso_type = vhdr.gso_type;
        event.virtio_flags = vhdr.flags;

        fill_event_common(&event, skb, "receive_buf");
        events.perf_submit(ctx, &event, sizeof(event));

        int key = 3;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }

    return 0;
}

// Generic entry/return tracking for gso_type changes
static __always_inline int trace_gso_entry_common(struct sk_buff *skb) {
    if (!should_trace(skb)) {
        return 0;
    }

    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (!shinfo) {
        return 0;
    }

    u32 gso_type;
    bpf_probe_read_kernel(&gso_type, sizeof(gso_type), &shinfo->gso_type);

    u64 skb_addr = (u64)skb;
    skb_gso_state.update(&skb_addr, &gso_type);

    return 0;
}

// Specific function wrappers
int trace_udp4_gro_complete_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_gso_entry_common(skb);
}

int trace_udp4_gro_complete_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u64 skb_addr = (u64)skb;
    u32 *saved_gso = skb_gso_state.lookup(&skb_addr);
    if (!saved_gso) return 0;

    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (!shinfo) {
        skb_gso_state.delete(&skb_addr);
        return 0;
    }

    u32 current_gso;
    u16 gso_size, gso_segs;
    bpf_probe_read_kernel(&current_gso, sizeof(current_gso), &shinfo->gso_type);
    bpf_probe_read_kernel(&gso_size, sizeof(gso_size), &shinfo->gso_size);
    bpf_probe_read_kernel(&gso_segs, sizeof(gso_segs), &shinfo->gso_segs);

    int changed = (current_gso != *saved_gso);
    if (changed || (current_gso & (1 << 1))) {
        if (GSO_CHANGES_ONLY && !changed) {
            skb_gso_state.delete(&skb_addr);
            return 0;
        }

        struct gso_event_t event = {};
        event.event_type = changed ? EVENT_GSO_TYPE_CHANGE : EVENT_GRO_COMPLETE;
        event.gso_type_before = *saved_gso;
        event.gso_type_after = current_gso;
        event.gso_size = gso_size;
        event.gso_segs = gso_segs;
        fill_event_common(&event, skb, "udp4_gro_complete");
        events.perf_submit(ctx, &event, sizeof(event));

        int key = changed ? 2 : 4;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }
    skb_gso_state.delete(&skb_addr);
    return 0;
}

int trace_tcp_gro_complete_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_gso_entry_common(skb);
}

int trace_tcp_gro_complete_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u64 skb_addr = (u64)skb;
    u32 *saved_gso = skb_gso_state.lookup(&skb_addr);
    if (!saved_gso) return 0;

    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (!shinfo) {
        skb_gso_state.delete(&skb_addr);
        return 0;
    }

    u32 current_gso;
    u16 gso_size, gso_segs;
    bpf_probe_read_kernel(&current_gso, sizeof(current_gso), &shinfo->gso_type);
    bpf_probe_read_kernel(&gso_size, sizeof(gso_size), &shinfo->gso_size);
    bpf_probe_read_kernel(&gso_segs, sizeof(gso_segs), &shinfo->gso_segs);

    int changed = (current_gso != *saved_gso);
    if (changed || (current_gso & (1 << 1))) {
        if (GSO_CHANGES_ONLY && !changed) {
            skb_gso_state.delete(&skb_addr);
            return 0;
        }

        struct gso_event_t event = {};
        event.event_type = changed ? EVENT_GSO_TYPE_CHANGE : EVENT_GRO_COMPLETE;
        event.gso_type_before = *saved_gso;
        event.gso_type_after = current_gso;
        event.gso_size = gso_size;
        event.gso_segs = gso_segs;
        fill_event_common(&event, skb, "tcp_gro_complete");
        events.perf_submit(ctx, &event, sizeof(event));

        int key = changed ? 2 : 4;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }
    skb_gso_state.delete(&skb_addr);
    return 0;
}

int trace_vxlan_rcv_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_gso_entry_common(skb);
}

int trace_vxlan_rcv_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u64 skb_addr = (u64)skb;
    u32 *saved_gso = skb_gso_state.lookup(&skb_addr);
    if (!saved_gso) return 0;

    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (!shinfo) {
        skb_gso_state.delete(&skb_addr);
        return 0;
    }

    u32 current_gso;
    u16 gso_size, gso_segs;
    bpf_probe_read_kernel(&current_gso, sizeof(current_gso), &shinfo->gso_type);
    bpf_probe_read_kernel(&gso_size, sizeof(gso_size), &shinfo->gso_size);
    bpf_probe_read_kernel(&gso_segs, sizeof(gso_segs), &shinfo->gso_segs);

    int changed = (current_gso != *saved_gso);
    if (changed || (current_gso & (1 << 1))) {
        if (GSO_CHANGES_ONLY && !changed) {
            skb_gso_state.delete(&skb_addr);
            return 0;
        }

        struct gso_event_t event = {};
        event.event_type = changed ? EVENT_GSO_TYPE_CHANGE : EVENT_TUNNEL_DECAP;
        event.gso_type_before = *saved_gso;
        event.gso_type_after = current_gso;
        event.gso_size = gso_size;
        event.gso_segs = gso_segs;
        fill_event_common(&event, skb, "vxlan_rcv");
        events.perf_submit(ctx, &event, sizeof(event));

        int key = changed ? 2 : 4;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }
    skb_gso_state.delete(&skb_addr);
    return 0;
}

int trace_skb_segment_entry(struct pt_regs *ctx, struct sk_buff *skb) {
    return trace_gso_entry_common(skb);
}

int trace_skb_segment_return(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u64 skb_addr = (u64)skb;
    u32 *saved_gso = skb_gso_state.lookup(&skb_addr);
    if (!saved_gso) return 0;

    struct skb_shared_info_min *shinfo = get_shinfo(skb);
    if (!shinfo) {
        skb_gso_state.delete(&skb_addr);
        return 0;
    }

    u32 current_gso;
    u16 gso_size, gso_segs;
    bpf_probe_read_kernel(&current_gso, sizeof(current_gso), &shinfo->gso_type);
    bpf_probe_read_kernel(&gso_size, sizeof(gso_size), &shinfo->gso_size);
    bpf_probe_read_kernel(&gso_segs, sizeof(gso_segs), &shinfo->gso_segs);

    int changed = (current_gso != *saved_gso);
    if (changed || (current_gso & (1 << 1))) {
        if (GSO_CHANGES_ONLY && !changed) {
            skb_gso_state.delete(&skb_addr);
            return 0;
        }

        struct gso_event_t event = {};
        event.event_type = changed ? EVENT_GSO_TYPE_CHANGE : EVENT_GSO_TYPE_SET;
        event.gso_type_before = *saved_gso;
        event.gso_type_after = current_gso;
        event.gso_size = gso_size;
        event.gso_segs = gso_segs;
        fill_event_common(&event, skb, "skb_segment");
        events.perf_submit(ctx, &event, sizeof(event));

        int key = changed ? 2 : 4;
        u64 *val = stats.lookup(&key);
        if (val) (*val)++;
    }
    skb_gso_state.delete(&skb_addr);
    return 0;
}
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect VXLAN gso_type source in SKBs",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument("--no-static-check", action="store_true",
                        help="Skip static system checks")
    parser.add_argument("--src-ip", type=str, help="Filter by source IP")
    parser.add_argument("--dst-ip", type=str, help="Filter by destination IP")
    parser.add_argument("--interface", type=str, help="Filter by interface name")
    parser.add_argument("--gso-changes-only", action="store_true",
                        help="Only show events where gso_type changes")

    return parser.parse_args()

def ip_to_int(ip_str):
    if not ip_str:
        return 0
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except:
        print_error("Invalid IP address: %s" % ip_str)
        sys.exit(1)

def int_to_ip(ip_int):
    if ip_int == 0:
        return "0.0.0.0"
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def get_ifindex(ifname):
    if not ifname:
        return 0

    import fcntl
    SIOCGIFINDEX = 0x8933

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifr = struct.pack('16sH', ifname.encode(), 0)
        result = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifr)
        ifindex = struct.unpack('16sH', result)[1]
        s.close()
        return ifindex
    except:
        print_error("Cannot find interface: %s" % ifname)
        sys.exit(1)

def decode_gso_type(gso_type):
    flags = []
    if gso_type & (1 << 0): flags.append("DODGY")
    if gso_type & (1 << 1): flags.append("UDP_TUNNEL")  # The key flag!
    if gso_type & (1 << 2): flags.append("UDP_TUNNEL_CSUM")
    if gso_type & (1 << 3): flags.append("PARTIAL")
    if gso_type & (1 << 10): flags.append("PARTIAL")
    if gso_type & (1 << 16): flags.append("TCPV4")
    if gso_type & (1 << 17): flags.append("TCPV6")
    if gso_type & (1 << 23): flags.append("UDP_L4")
    if gso_type & (1 << 24): flags.append("FRAGLIST")

    return "|".join(flags) if flags else "NONE"

def decode_virtio_gso(vgso):
    types = {
        0: "NONE",
        1: "TCPV4",
        3: "UDP",
        4: "TCPV6",
        0x80: "ECN"
    }
    return types.get(vgso, "UNKNOWN(%d)" % vgso)

def main():
    args = parse_args()

    # Run static checks first
    if not args.no_static_check:
        static_system_checks()
        print("\n" + "=" * 80)
        print("Press Enter to continue to dynamic tracing...")
        print("=" * 80)
        try:
            raw_input() if sys.version_info[0] < 3 else input()
        except KeyboardInterrupt:
            sys.exit(0)

    print_header("DYNAMIC TRACING - GSO TYPE PROPAGATION")

    # Prepare filters
    src_ip = ip_to_int(args.src_ip)
    dst_ip = ip_to_int(args.dst_ip)
    ifindex = get_ifindex(args.interface)
    gso_changes_only = 1 if args.gso_changes_only else 0

    # Load BPF
    bpf_code = bpf_text % (src_ip, dst_ip, ifindex, gso_changes_only)

    try:
        b = BPF(text=bpf_code)
    except Exception as e:
        print_error("Failed to load BPF program:")
        print(str(e))
        sys.exit(1)

    # Attach probes
    print("Attaching probes...")
    probes = [
        ("receive_buf", "trace_receive_buf"),
        ("udp4_gro_complete", "trace_udp4_gro_complete_entry", "trace_udp4_gro_complete_return"),
        ("tcp_gro_complete", "trace_tcp_gro_complete_entry", "trace_tcp_gro_complete_return"),
        ("skb_segment", "trace_skb_segment_entry", "trace_skb_segment_return"),
    ]

    # Optional: vxlan_rcv (may not exist if no VXLAN module)
    try:
        b.attach_kprobe(event="vxlan_rcv", fn_name="trace_vxlan_rcv_entry")
        b.attach_kretprobe(event="vxlan_rcv", fn_name="trace_vxlan_rcv_return")
        print_ok("Attached to vxlan_rcv")
    except:
        print("  Note: vxlan_rcv not available (no VXLAN module)")

    for probe_info in probes:
        func = probe_info[0]
        try:
            if len(probe_info) == 2:
                # Kprobe only
                b.attach_kprobe(event=func, fn_name=probe_info[1])
            else:
                # Kprobe + kretprobe
                b.attach_kprobe(event=func, fn_name=probe_info[1])
                b.attach_kretprobe(event=func, fn_name=probe_info[2])
            print_ok("Attached to " + func)
        except Exception as e:
            print_warning("Could not attach to %s: %s" % (func, str(e)))

    # Event structure
    class GsoEvent(ctypes.Structure):
        _fields_ = [
            ("timestamp_ns", ctypes.c_uint64),
            ("skb_addr", ctypes.c_uint64),
            ("gso_type_before", ctypes.c_uint32),
            ("gso_type_after", ctypes.c_uint32),
            ("gso_size", ctypes.c_uint16),
            ("gso_segs", ctypes.c_uint16),
            ("event_type", ctypes.c_uint8),
            ("virtio_gso_type", ctypes.c_uint8),
            ("virtio_flags", ctypes.c_uint8),
            ("encapsulation", ctypes.c_uint8),
            ("src_ip", ctypes.c_uint32),
            ("dst_ip", ctypes.c_uint32),
            ("inner_protocol", ctypes.c_uint16),
            ("pad", ctypes.c_uint16),
            ("pid", ctypes.c_uint32),
            ("cpu", ctypes.c_uint32),
            ("func_name", ctypes.c_char * 32),
            ("comm", ctypes.c_char * 16),
            ("dev_name", ctypes.c_char * 16),
        ]

    event_types = {
        1: "GSO_SET",
        2: "GSO_CHANGE",
        3: "VIRTIO_RX",
        4: "GRO_COMPLETE",
        5: "TUNNEL_DECAP",
    }

    # Print header
    print("\nTracing SKB gso_type changes... Hit Ctrl-C to end.\n")
    print("%-18s %-3s %-12s %-20s | %-18s | %s" %
          ("TIME", "CPU", "EVENT", "FUNCTION", "SKB", "GSO_TYPE_INFO"))
    print("-" * 120)

    # Event handler
    def print_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(GsoEvent)).contents

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        event_type = event_types.get(event.event_type, "UNKNOWN")
        func_name = event.func_name.decode('utf-8', 'replace')
        dev_name = event.dev_name.decode('utf-8', 'replace')

        # Format gso_type info
        if event.event_type == 3:  # VIRTIO_RX
            gso_info = "virtio_gso=%s kernel_gso=%s" % (
                decode_virtio_gso(event.virtio_gso_type),
                decode_gso_type(event.gso_type_after)
            )
            if event.gso_type_after & (1 << 1):  # UDP_TUNNEL
                gso_info = Colors.FAIL + gso_info + " [VXLAN FLAG!]" + Colors.ENDC
        elif event.gso_type_before != event.gso_type_after:
            gso_info = "%s -> %s" % (
                decode_gso_type(event.gso_type_before),
                decode_gso_type(event.gso_type_after)
            )
            if event.gso_type_after & (1 << 1):  # UDP_TUNNEL added
                gso_info = Colors.WARNING + gso_info + " [VXLAN ADDED!]" + Colors.ENDC
        else:
            gso_info = decode_gso_type(event.gso_type_after)
            if event.gso_type_after & (1 << 1):
                gso_info = Colors.WARNING + gso_info + Colors.ENDC

        print("%-18s %-3d %-12s %-20s | 0x%-16x | %s" % (
            timestamp, event.cpu, event_type, func_name, event.skb_addr, gso_info
        ))

        # Additional details
        details = []
        if event.src_ip != 0:
            details.append("flow=%s->%s" % (int_to_ip(event.src_ip), int_to_ip(event.dst_ip)))
        if dev_name:
            details.append("dev=%s" % dev_name)
        if event.gso_size > 0:
            details.append("gso_size=%d segs=%d" % (event.gso_size, event.gso_segs))
        if event.encapsulation:
            details.append("encap=1 inner_proto=0x%x" % event.inner_protocol)

        if details:
            print("  " + " ".join(details))

    b["events"].open_perf_buffer(print_event, page_cnt=256)

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Main loop
    while not exiting:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break

    # Print statistics
    print("\n" + "=" * 80)
    print("Statistics:")
    stats = b.get_table("stats")
    print("  Total events:        %d" % stats[ctypes.c_int(0)].value)
    print("  GSO set events:      %d" % stats[ctypes.c_int(1)].value)
    print("  GSO change events:   %d" % stats[ctypes.c_int(2)].value)
    print("  Virtio RX events:    %d" % stats[ctypes.c_int(3)].value)
    print("  GRO complete events: %d" % stats[ctypes.c_int(4)].value)

if __name__ == "__main__":
    main()
