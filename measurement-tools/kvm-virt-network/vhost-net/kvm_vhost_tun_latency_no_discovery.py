#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
kvm_vhost_tun_latency.py

Single-phase measurement for host-side TX latency:
  KVM ioeventfd kick -> vhost handle_tx_kick -> tun_sendmsg -> netif_receive_skb

This tool uses QEMU PID-based filtering to track all vhost threads associated
with a VM, eliminating the need for a separate discovery phase.

Filtering strategy:
  - S0 (ioeventfd_write): Track all events (no packet info available here)
  - S1 (handle_tx_kick): Filter by target vhost TIDs
  - S2 (tun_sendmsg): Filter by TID + device name
  - S3 (netif_receive_skb): Filter by device + flow (IP/port)

Examples:
  # Basic usage with device name (auto-detect QEMU PID)
  sudo %(prog)s --device vnet94

  # Specify QEMU PID explicitly
  sudo %(prog)s --device vnet94 --qemu-pid 12345

  # With flow filter
  sudo %(prog)s --device vnet94 --qemu-pid 12345 \\
    --flow "proto=udp,src=10.0.0.1,dst=10.0.0.2,sport=1234,dport=4321"

  # Suppress per-packet output
  sudo %(prog)s --device vnet94 --qemu-pid 12345 --no-detail

Notes:
  - Requires root, BCC, and kernel headers.
  - QEMU PID can be auto-detected from device name via OVS/libvirt.
  - All vhost-$PID threads are automatically tracked.
"""

from __future__ import print_function

import argparse
import datetime
import ipaddress
import os
import re
import subprocess
import sys
import time

try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Error: Neither bcc nor bpfcc module found!")
        sys.exit(1)

import ctypes as ct


class Devname(ct.Structure):
    _fields_ = [("name", ct.c_char * 16)]


class LatencyEvent(ct.Structure):
    _fields_ = [
        ("s0_us", ct.c_ulonglong),
        ("s1_us", ct.c_ulonglong),
        ("s2_us", ct.c_ulonglong),
        ("tid", ct.c_uint),
        ("s0_ok", ct.c_ubyte),
        ("s1_ok", ct.c_ubyte),
        ("queue", ct.c_ushort),
        ("pad", ct.c_ubyte * 2),
    ]


def find_kernel_function(base_name, verbose=False):
    """Find actual kernel function name, handling GCC clone suffixes."""
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
    except Exception as exc:
        if verbose:
            print("Warning: Failed to read /proc/kallsyms: {}".format(exc))
        return None
    if not candidates:
        if verbose:
            print("Warning: No symbol matching '{}' found".format(base_name))
        return None
    if base_name in candidates:
        return base_name
    return min(candidates, key=len)


def get_qemu_pid_from_device(device, verbose=False):
    """Get QEMU PID from vnet device name via OVS or /proc."""
    # Method 1: Try OVS external_ids
    try:
        result = subprocess.check_output(
            ["ovs-vsctl", "get", "interface", device, "external_ids:vm-id"],
            stderr=subprocess.DEVNULL
        ).decode().strip().strip('"')
        if result and result != "":
            # Got VM UUID, now find QEMU process
            try:
                ps_out = subprocess.check_output(
                    ["pgrep", "-f", result],
                    stderr=subprocess.DEVNULL
                ).decode().strip()
                if ps_out:
                    return int(ps_out.split('\n')[0])
            except subprocess.CalledProcessError:
                pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Method 2: Try to find via /proc - look for process with tun fd
    try:
        # Find iface index
        iface_path = "/sys/class/net/{}/ifindex".format(device)
        if os.path.exists(iface_path):
            with open(iface_path) as f:
                ifindex = f.read().strip()
            # Search for qemu processes
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                try:
                    comm_path = "/proc/{}/comm".format(pid_dir)
                    with open(comm_path) as f:
                        comm = f.read().strip()
                    if "qemu" in comm.lower():
                        # Check if this qemu has the device
                        fd_dir = "/proc/{}/fd".format(pid_dir)
                        for fd in os.listdir(fd_dir):
                            try:
                                link = os.readlink(os.path.join(fd_dir, fd))
                                if "/dev/net/tun" in link or "/dev/tap" in link:
                                    return int(pid_dir)
                            except (OSError, IOError):
                                continue
                except (OSError, IOError):
                    continue
    except Exception as e:
        if verbose:
            print("Warning: /proc scan failed: {}".format(e))

    return None


def get_vhost_tids(qemu_pid, verbose=False):
    """Get all vhost kernel thread TIDs for a QEMU process.

    vhost threads are kernel threads named [vhost-<qemu_pid>], not user threads
    within the QEMU process. They run as separate kernel threads.
    """
    tids = []
    vhost_comm = "vhost-{}".format(qemu_pid)

    # Method 1: Scan /proc for kernel threads matching [vhost-<qemu_pid>]
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            try:
                comm_path = "/proc/{}/comm".format(pid_dir)
                with open(comm_path) as f:
                    comm = f.read().strip()
                if comm == vhost_comm:
                    tids.append(int(pid_dir))
            except (OSError, IOError):
                continue
    except Exception as e:
        if verbose:
            print("Warning: Failed to scan /proc: {}".format(e))

    # Method 2: Use ps if /proc method failed
    if not tids:
        try:
            ps_out = subprocess.check_output(
                ["ps", "-eo", "pid,comm"],
                stderr=subprocess.DEVNULL
            ).decode()
            for line in ps_out.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == vhost_comm:
                    tids.append(int(parts[0]))
        except subprocess.CalledProcessError:
            pass

    return sorted(tids)


def parse_flow(flow_str):
    """Parse flow string into dict of fields."""
    if not flow_str:
        return {}
    fields = {}
    parts = [p.strip() for p in flow_str.split(",") if p.strip()]
    for part in parts:
        if "=" not in part:
            raise ValueError("Invalid flow field: {}".format(part))
        k, v = [x.strip().lower() for x in part.split("=", 1)]
        fields[k] = v
    return fields


def flow_constants(flow):
    """Build constants for BPF based on flow filter."""
    const = {
        "FLOW_HAS_SRC": 0,
        "FLOW_HAS_DST": 0,
        "FLOW_HAS_SPORT": 0,
        "FLOW_HAS_DPORT": 0,
        "FLOW_HAS_PROTO": 0,
        "FLOW_IS_IPV6": 0,
        "FLOW_PROTO": 0,
        "FLOW_SPORT": 0,
        "FLOW_DPORT": 0,
        "FLOW_SRC_V4": 0,
        "FLOW_DST_V4": 0,
        "FLOW_SRC_V6_0": 0,
        "FLOW_SRC_V6_1": 0,
        "FLOW_SRC_V6_2": 0,
        "FLOW_SRC_V6_3": 0,
        "FLOW_DST_V6_0": 0,
        "FLOW_DST_V6_1": 0,
        "FLOW_DST_V6_2": 0,
        "FLOW_DST_V6_3": 0,
    }
    if not flow:
        return const

    proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}

    if "proto" in flow:
        if flow["proto"] not in proto_map:
            raise ValueError("Unsupported proto: {}".format(flow["proto"]))
        const["FLOW_HAS_PROTO"] = 1
        const["FLOW_PROTO"] = proto_map[flow["proto"]]

    if "sport" in flow:
        const["FLOW_HAS_SPORT"] = 1
        const["FLOW_SPORT"] = int(flow["sport"])
    if "dport" in flow:
        const["FLOW_HAS_DPORT"] = 1
        const["FLOW_DPORT"] = int(flow["dport"])

    if "src" in flow:
        ip = ipaddress.ip_address(flow["src"])
        const["FLOW_HAS_SRC"] = 1
        if isinstance(ip, ipaddress.IPv6Address):
            const["FLOW_IS_IPV6"] = 1
            words = ip.packed
            const["FLOW_SRC_V6_0"] = int.from_bytes(words[0:4], "big")
            const["FLOW_SRC_V6_1"] = int.from_bytes(words[4:8], "big")
            const["FLOW_SRC_V6_2"] = int.from_bytes(words[8:12], "big")
            const["FLOW_SRC_V6_3"] = int.from_bytes(words[12:16], "big")
        else:
            const["FLOW_SRC_V4"] = int(ip)

    if "dst" in flow:
        ip = ipaddress.ip_address(flow["dst"])
        const["FLOW_HAS_DST"] = 1
        if isinstance(ip, ipaddress.IPv6Address):
            const["FLOW_IS_IPV6"] = 1
            words = ip.packed
            const["FLOW_DST_V6_0"] = int.from_bytes(words[0:4], "big")
            const["FLOW_DST_V6_1"] = int.from_bytes(words[4:8], "big")
            const["FLOW_DST_V6_2"] = int.from_bytes(words[8:12], "big")
            const["FLOW_DST_V6_3"] = int.from_bytes(words[12:16], "big")
        else:
            const["FLOW_DST_V4"] = int(ip)

    return const


def build_bpf_program(flow_const, debug=False):
    """Build the BPF program text."""
    text = r"""
#include <linux/bpf.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/if_ether.h>
#include <linux/uidgid.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/llist.h>
#include <linux/stddef.h>
#include <linux/list.h>
#include <kvm/iodev.h>

#define IFNAMSIZ 16

#define FLOW_HAS_SRC __FLOW_HAS_SRC__
#define FLOW_HAS_DST __FLOW_HAS_DST__
#define FLOW_HAS_SPORT __FLOW_HAS_SPORT__
#define FLOW_HAS_DPORT __FLOW_HAS_DPORT__
#define FLOW_HAS_PROTO __FLOW_HAS_PROTO__
#define FLOW_IS_IPV6 __FLOW_IS_IPV6__
#define FLOW_PROTO __FLOW_PROTO__
#define FLOW_SPORT __FLOW_SPORT__
#define FLOW_DPORT __FLOW_DPORT__
#define FLOW_SRC_V4 __FLOW_SRC_V4__
#define FLOW_DST_V4 __FLOW_DST_V4__
#define FLOW_SRC_V6_0 __FLOW_SRC_V6_0__
#define FLOW_SRC_V6_1 __FLOW_SRC_V6_1__
#define FLOW_SRC_V6_2 __FLOW_SRC_V6_2__
#define FLOW_SRC_V6_3 __FLOW_SRC_V6_3__
#define FLOW_DST_V6_0 __FLOW_DST_V6_0__
#define FLOW_DST_V6_1 __FLOW_DST_V6_1__
#define FLOW_DST_V6_2 __FLOW_DST_V6_2__
#define FLOW_DST_V6_3 __FLOW_DST_V6_3__

#define S0_RING_SZ 1024
#define S2_RING_SZ 2048
#define DEBUG_ENABLED __DEBUG_ENABLED__

union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

struct eventfd_ctx;

struct _ioeventfd {
    struct list_head list;
    u64 addr;
    int length;
    struct eventfd_ctx *eventfd;
    u64 datamatch;
    struct kvm_io_device dev;
    u8 bus_idx;
    bool wildcard;
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
    void *dev;
};

struct s0_state {
    u32 head;
    u32 tail;
};

struct s2_state {
    u32 head;
    u32 tail;
};

struct s0_slot_key {
    u64 eventfd;
    u32 slot;
    u32 pad;
};

struct s12_slot_key {
    u32 tid;
    u32 slot;
};

struct s2_slot_key {
    u32 tid;
    u32 slot;
};

struct latency_evt {
    u64 s0_us;
    u64 s1_us;
    u64 s2_us;
    u32 tid;
    u8 s0_ok;
    u8 s1_ok;
    u16 queue;
    u8 pad[2];
};

// Device name filter
BPF_ARRAY(name_map, union name_buf, 1);

// Target vhost TIDs (populated from userspace)
BPF_HASH(target_tid, u32, u8, 256);

// Per-CPU current eventfd context
BPF_PERCPU_ARRAY(current_eventfd, u64, 1);

// Work -> eventfd_ctx mapping
BPF_HASH(work_eventfd, u64, u64, 4096);

// Known eventfds (associated with target TIDs) - for filtering in ioeventfd_write
BPF_HASH(known_eventfd, u64, u8, 256);

// S0 FIFO per eventfd (ioeventfd_write timestamps)
BPF_HASH(s0_state, u64, struct s0_state, 4096);  // key: eventfd_ctx
BPF_HASH(s0_ts, struct s0_slot_key, u64, 65536);  // key: {eventfd, slot}

// Last S0 delta per TID (calculated in handle_tx_kick)
BPF_HASH(s0_last, u32, u64, 4096);
BPF_HASH(s0_last_ok, u32, u8, 4096);

// S1 start timestamp per TID
BPF_HASH(s1_start, u32, u64, 4096);

// S2 FIFO per TID
BPF_HASH(s2_state, u32, struct s2_state, 4096);
BPF_HASH(s2_ts, struct s2_slot_key, u64, 65536);

// S0/S1 delta FIFO aligned with S2
BPF_HASH(s0_val, struct s12_slot_key, u64, 65536);
BPF_HASH(s1_val, struct s12_slot_key, u64, 65536);
BPF_HASH(s0_ok, struct s12_slot_key, u8, 65536);
BPF_HASH(s1_ok, struct s12_slot_key, u8, 65536);

// Per-packet latency events
BPF_PERF_OUTPUT(events);

// Stats counters (debug only, completely removed when disabled)
#if DEBUG_ENABLED
BPF_ARRAY(stats, u64, 32);
static __always_inline void stats_inc(int idx) {
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}
#else
#define stats_inc(idx)
#endif

static __always_inline int name_filter(struct net_device *dev) {
    union name_buf real = {};
    bpf_probe_read_kernel(&real, IFNAMSIZ, dev->name);
    int key = 0;
    union name_buf *filter = name_map.lookup(&key);
    if (!filter) return 1;
    if (filter->name_int.hi == 0 && filter->name_int.lo == 0) return 1;
    return (filter->name_int.hi == real.name_int.hi &&
            filter->name_int.lo == real.name_int.lo);
}

static __always_inline int is_target_tid(u32 tid) {
    u8 *ok = target_tid.lookup(&tid);
    return ok != NULL;
}

// S0 FIFO operations (per eventfd)
static __always_inline void s0_fifo_push(u64 evt, u64 ts) {
    struct s0_state st = {};
    struct s0_state *p = s0_state.lookup(&evt);
    if (p) st = *p;

    u32 depth = st.tail - st.head;
    if (depth >= S0_RING_SZ) {
        stats_inc(7);
        st.head++;
    }

    struct s0_slot_key key = {.eventfd = evt, .slot = st.tail % S0_RING_SZ};
    s0_ts.update(&key, &ts);
    st.tail++;
    s0_state.update(&evt, &st);
}

static __always_inline int s0_fifo_pop(u64 evt, u64 *ts) {
    struct s0_state *p = s0_state.lookup(&evt);
    if (!p) {
        stats_inc(17);  // s0_state not found
        stats_inc(6);
        return 0;
    }
    if (p->head == p->tail) {
        stats_inc(18);  // s0 fifo empty (head == tail)
        stats_inc(6);
        return 0;
    }
    // Check for wrap-around corruption: head > tail means state corrupted
    if (p->head > p->tail) {
        stats_inc(19);  // s0 fifo corrupted (head > tail)
        stats_inc(6);
        return 0;
    }
    struct s0_slot_key key = {.eventfd = evt, .slot = p->head % S0_RING_SZ};
    u64 *val = s0_ts.lookup(&key);
    if (!val) {
        stats_inc(20);  // s0_ts lookup failed (slot data missing)
        stats_inc(6);
        p->head++;
        return 0;
    }
    *ts = *val;
    p->head++;
    stats_inc(24);  // s0_fifo_pop success
    return 1;
}

// S2 FIFO operations
static __always_inline void s2_fifo_push(u32 tid, u64 ts, u64 s0_us, u64 s1_us, u8 s0_ok_val, u8 s1_ok_val) {
    struct s2_state st = {};
    struct s2_state *p = s2_state.lookup(&tid);
    if (p) st = *p;

    u32 depth = st.tail - st.head;
    if (depth >= S2_RING_SZ) {
        stats_inc(7);
        st.head++;
    }

    u32 slot = st.tail % S2_RING_SZ;
    struct s2_slot_key key = {.tid = tid, .slot = slot};
    s2_ts.update(&key, &ts);

    struct s12_slot_key k12 = {.tid = tid, .slot = slot};
    s0_val.update(&k12, &s0_us);
    s1_val.update(&k12, &s1_us);
    s0_ok.update(&k12, &s0_ok_val);
    s1_ok.update(&k12, &s1_ok_val);

    st.tail++;
    s2_state.update(&tid, &st);
}

static __always_inline int s2_fifo_pop(u32 tid, u64 *ts, u32 *slot) {
    struct s2_state *p = s2_state.lookup(&tid);
    if (!p || p->head == p->tail) {
        stats_inc(6);
        return 0;
    }
    *slot = p->head % S2_RING_SZ;
    struct s2_slot_key key = {.tid = tid, .slot = *slot};
    u64 *val = s2_ts.lookup(&key);
    if (!val) {
        stats_inc(6);
        p->head++;
        return 0;
    }
    *ts = *val;
    p->head++;
    return 1;
}

// Flow matching
static __always_inline int flow_match_ipv4(struct sk_buff *skb, void *nh) {
    struct iphdr iph = {};
    if (bpf_probe_read_kernel(&iph, sizeof(iph), nh) < 0)
        return 0;
    if (FLOW_HAS_PROTO && iph.protocol != FLOW_PROTO)
        return 0;
    if (FLOW_HAS_SRC && ntohl(iph.saddr) != FLOW_SRC_V4)
        return 0;
    if (FLOW_HAS_DST && ntohl(iph.daddr) != FLOW_DST_V4)
        return 0;

    if (FLOW_HAS_SPORT || FLOW_HAS_DPORT) {
        u64 off = (u64)(iph.ihl * 4);
        if (iph.protocol == IPPROTO_TCP) {
            struct tcphdr th = {};
            if (bpf_probe_read_kernel(&th, sizeof(th), nh + off) < 0)
                return 0;
            if (FLOW_HAS_SPORT && ntohs(th.source) != FLOW_SPORT)
                return 0;
            if (FLOW_HAS_DPORT && ntohs(th.dest) != FLOW_DPORT)
                return 0;
        } else if (iph.protocol == IPPROTO_UDP) {
            struct udphdr uh = {};
            if (bpf_probe_read_kernel(&uh, sizeof(uh), nh + off) < 0)
                return 0;
            if (FLOW_HAS_SPORT && ntohs(uh.source) != FLOW_SPORT)
                return 0;
            if (FLOW_HAS_DPORT && ntohs(uh.dest) != FLOW_DPORT)
                return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

static __always_inline int flow_match_ipv6(struct sk_buff *skb, void *nh) {
    struct ipv6hdr iph6 = {};
    if (bpf_probe_read_kernel(&iph6, sizeof(iph6), nh) < 0)
        return 0;
    if (FLOW_HAS_PROTO && iph6.nexthdr != FLOW_PROTO)
        return 0;
    if (FLOW_HAS_SRC) {
        if (ntohl(iph6.saddr.in6_u.u6_addr32[0]) != FLOW_SRC_V6_0) return 0;
        if (ntohl(iph6.saddr.in6_u.u6_addr32[1]) != FLOW_SRC_V6_1) return 0;
        if (ntohl(iph6.saddr.in6_u.u6_addr32[2]) != FLOW_SRC_V6_2) return 0;
        if (ntohl(iph6.saddr.in6_u.u6_addr32[3]) != FLOW_SRC_V6_3) return 0;
    }
    if (FLOW_HAS_DST) {
        if (ntohl(iph6.daddr.in6_u.u6_addr32[0]) != FLOW_DST_V6_0) return 0;
        if (ntohl(iph6.daddr.in6_u.u6_addr32[1]) != FLOW_DST_V6_1) return 0;
        if (ntohl(iph6.daddr.in6_u.u6_addr32[2]) != FLOW_DST_V6_2) return 0;
        if (ntohl(iph6.daddr.in6_u.u6_addr32[3]) != FLOW_DST_V6_3) return 0;
    }

    if (FLOW_HAS_SPORT || FLOW_HAS_DPORT) {
        if (iph6.nexthdr == IPPROTO_TCP) {
            struct tcphdr th = {};
            if (bpf_probe_read_kernel(&th, sizeof(th), nh + sizeof(iph6)) < 0)
                return 0;
            if (FLOW_HAS_SPORT && ntohs(th.source) != FLOW_SPORT)
                return 0;
            if (FLOW_HAS_DPORT && ntohs(th.dest) != FLOW_DPORT)
                return 0;
        } else if (iph6.nexthdr == IPPROTO_UDP) {
            struct udphdr uh = {};
            if (bpf_probe_read_kernel(&uh, sizeof(uh), nh + sizeof(iph6)) < 0)
                return 0;
            if (FLOW_HAS_SPORT && ntohs(uh.source) != FLOW_SPORT)
                return 0;
            if (FLOW_HAS_DPORT && ntohs(uh.dest) != FLOW_DPORT)
                return 0;
        } else {
            return 0;
        }
    }
    return 1;
}

static __always_inline int flow_match(struct sk_buff *skb) {
    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (!dev) return 0;
    if (!name_filter(dev)) return 0;

    void *head = NULL;
    u16 network_header = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    if (!head) return 0;
    void *nh = head + network_header;

    __be16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto == bpf_htons(ETH_P_IP)) {
        if (FLOW_IS_IPV6) return 0;
        return flow_match_ipv4(skb, nh);
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        return flow_match_ipv6(skb, nh);
    }
    return 0;
}

// S0: ioeventfd_write - track all, store timestamp by work
int trace_eventfd_signal(struct pt_regs *ctx) {
    struct eventfd_ctx *eventfd = (struct eventfd_ctx *)PT_REGS_PARM1(ctx);
    if (!eventfd) return 0;
    stats_inc(21);
    int key = 0;
    u64 val = (u64)eventfd;
    current_eventfd.update(&key, &val);
    return 0;
}

int trace_eventfd_signal_ret(struct pt_regs *ctx) {
    int key = 0;
    u64 val = 0;
    current_eventfd.update(&key, &val);
    return 0;
}

int trace_vhost_poll_wakeup(struct pt_regs *ctx) {
    wait_queue_entry_t *wait = (wait_queue_entry_t *)PT_REGS_PARM1(ctx);
    if (!wait) return 0;
    int key = 0;
    u64 *eventfd = current_eventfd.lookup(&key);
    if (!eventfd || *eventfd == 0) return 0;

    struct vhost_poll *poll = (struct vhost_poll *)((char *)wait - offsetof(struct vhost_poll, wait));
    u64 work_ptr = (u64)&poll->work;
    work_eventfd.update(&work_ptr, eventfd);
    return 0;
}

int trace_ioeventfd_write(struct pt_regs *ctx) {
    struct kvm_io_device *dev = (struct kvm_io_device *)PT_REGS_PARM2(ctx);
    if (!dev) return 0;
    stats_inc(0);

    // Get eventfd from ioeventfd structure
    struct _ioeventfd *p = (struct _ioeventfd *)((char *)dev - offsetof(struct _ioeventfd, dev));
    struct eventfd_ctx *eventfd = NULL;
    bpf_probe_read_kernel(&eventfd, sizeof(eventfd), &p->eventfd);
    if (!eventfd) return 0;
    u64 evt_ptr = (u64)eventfd;

    // Only track eventfds that are known to be associated with target TIDs
    u8 *is_known = known_eventfd.lookup(&evt_ptr);
    if (!is_known) {
        stats_inc(21);  // eventfd not known (filtered out)
        return 0;
    }

    // Record timestamp in S0 FIFO (keyed by eventfd)
    u64 ts = bpf_ktime_get_ns();
    s0_fifo_push(evt_ptr, ts);
    stats_inc(23);  // s0_fifo_push count (for known eventfd)

    return 0;
}

// S1: handle_tx_kick - filter by target TID, calculate S0 latency
int trace_handle_tx_kick(struct pt_regs *ctx) {
    void *work = (void *)PT_REGS_PARM1(ctx);
    if (!work) return 0;
    stats_inc(8);

    u32 tid = (u32)bpf_get_current_pid_tgid();

    // Filter by target TID
    if (!is_target_tid(tid)) return 0;
    stats_inc(22);

    u64 ts = bpf_ktime_get_ns();

    // Get eventfd from work->eventfd mapping
    u64 work_ptr = (u64)work;
    u64 *eventfd = work_eventfd.lookup(&work_ptr);

    // Calculate S0 latency (ioeventfd_write -> handle_tx_kick)
    if (eventfd) {
        stats_inc(14);  // work_eventfd lookup success
        // Mark this eventfd as known (associated with target TID)
        u8 one = 1;
        known_eventfd.update(eventfd, &one);

        u64 s0_start = 0;
        if (s0_fifo_pop(*eventfd, &s0_start)) {
            u64 s0_delta = (ts - s0_start) / 1000;  // us
            s0_last.update(&tid, &s0_delta);
            u8 one = 1;
            s0_last_ok.update(&tid, &one);
        } else {
            stats_inc(15);  // eventfd found but fifo pop failed
            u8 zero = 0;
            s0_last_ok.update(&tid, &zero);
        }
    } else {
        stats_inc(16);  // work_eventfd lookup failed
        u8 zero = 0;
        s0_last_ok.update(&tid, &zero);
    }

    // Record S1 start time
    s1_start.update(&tid, &ts);

    return 0;
}

// S2: tun_sendmsg - filter by TID, record S1->S2 latency
int trace_tun_sendmsg(struct pt_regs *ctx) {
    stats_inc(9);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    if (!is_target_tid(tid)) return 0;
    stats_inc(10);

    u64 ts = bpf_ktime_get_ns();

    // Get S0 delta (already calculated in handle_tx_kick)
    u64 s0_us = 0;
    u8 s0_ok_val = 0;
    u64 *s0_ptr = s0_last.lookup(&tid);
    u8 *s0_ok_ptr = s0_last_ok.lookup(&tid);
    if (s0_ptr && s0_ok_ptr && *s0_ok_ptr) {
        s0_ok_val = 1;
        s0_us = *s0_ptr;
    }

    // Get S1 timestamp and calculate S1 delta
    u64 s1_us = 0;
    u8 s1_ok_val = 0;
    u64 *s1_ts = s1_start.lookup(&tid);
    if (s1_ts) {
        s1_ok_val = 1;
        s1_us = (ts - *s1_ts) / 1000;
    }

    // Push to S2 FIFO for netif_receive_skb
    s2_fifo_push(tid, ts, s0_us, s1_us, s0_ok_val, s1_ok_val);

    return 0;
}

// S3: netif_receive_skb - filter by device + flow, emit event
RAW_TRACEPOINT_PROBE(netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;
    stats_inc(12);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    if (!is_target_tid(tid)) return 0;
    stats_inc(13);

    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (!dev) return 0;
    if (!name_filter(dev)) return 0;

    u64 ts_start = 0;
    u32 slot = 0;
    if (!s2_fifo_pop(tid, &ts_start, &slot)) {
        stats_inc(5);
        return 0;
    }
    stats_inc(11);

    struct s12_slot_key k12 = {.tid = tid, .slot = slot};

    if (!flow_match(skb)) {
        // Drop non-target flow but keep FIFO aligned
        s0_val.delete(&k12);
        s1_val.delete(&k12);
        s0_ok.delete(&k12);
        s1_ok.delete(&k12);
        return 0;
    }
    stats_inc(10);

    u64 ts = bpf_ktime_get_ns();
    u64 delta = ts - ts_start;
    u64 s2_us = delta / 1000;
    stats_inc(2);

    // Get S0/S1 values
    u8 s0_ok_val = 0;
    u8 s1_ok_val = 0;
    u64 s0_us = 0;
    u64 s1_us = 0;
    u8 *s0ok = s0_ok.lookup(&k12);
    u8 *s1ok = s1_ok.lookup(&k12);
    u64 *s0us = s0_val.lookup(&k12);
    u64 *s1us = s1_val.lookup(&k12);
    if (s0ok && *s0ok && s0us) {
        s0_ok_val = 1;
        s0_us = *s0us;
    }
    if (s1ok && *s1ok && s1us) {
        s1_ok_val = 1;
        s1_us = *s1us;
    }

    // Queue mapping
    u16 qmap = 0;
    bpf_probe_read_kernel(&qmap, sizeof(qmap), &skb->queue_mapping);
    u16 queue = qmap > 0 ? qmap - 1 : 0;

    struct latency_evt evt = {};
    evt.s0_us = s0_us;
    evt.s1_us = s1_us;
    evt.s2_us = s2_us;
    evt.tid = tid;
    evt.s0_ok = s0_ok_val;
    evt.s1_ok = s1_ok_val;
    evt.queue = queue;
    events.perf_submit(ctx, &evt, sizeof(evt));

    // Cleanup
    s0_val.delete(&k12);
    s1_val.delete(&k12);
    s0_ok.delete(&k12);
    s1_ok.delete(&k12);

    return 0;
}
"""
    for k, v in flow_const.items():
        text = text.replace("__{}__".format(k), str(v))
    text = text.replace("__DEBUG_ENABLED__", "1" if debug else "0")
    return text


def set_device_filter(bpf, device):
    """Set device name filter in BPF map."""
    devname_map = bpf["name_map"]
    _name = Devname()
    if device:
        _name.name = device.encode()
        devname_map[0] = _name
        print("Device filter: {}".format(device))
    else:
        _name.name = b""
        devname_map[0] = _name
        print("Device filter: All TUN/TAP devices")


def set_target_tids(bpf, tids):
    """Set target vhost TIDs in BPF map."""
    target_tid = bpf["target_tid"]
    for tid in tids:
        target_tid[ct.c_uint(tid)] = ct.c_ubyte(1)
    print("Target vhost TIDs: {}".format(tids))


def main():
    parser = argparse.ArgumentParser(
        description="Single-phase KVM/vhost/TUN TX latency measurement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--device", "-d", required=True,
                        help="Target device name (e.g., vnet94)")
    parser.add_argument("--qemu-pid", type=int,
                        help="QEMU process PID (auto-detect if not specified)")
    parser.add_argument("--flow",
                        help="Flow filter: proto=udp,src=...,dst=...,sport=...,dport=...")
    parser.add_argument("--duration", type=int,
                        help="Run duration in seconds (default: until Ctrl+C)")
    parser.add_argument("--warmup", type=int, default=2,
                        help="Warmup seconds to learn eventfds before output (default: 2)")
    parser.add_argument("--no-detail", action="store_true",
                        help="Disable per-packet detail output")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug counters in BPF (impacts performance)")

    args = parser.parse_args()

    # Get QEMU PID
    qemu_pid = args.qemu_pid
    if not qemu_pid:
        print("Auto-detecting QEMU PID for device {}...".format(args.device))
        qemu_pid = get_qemu_pid_from_device(args.device)
        if not qemu_pid:
            print("Error: Could not auto-detect QEMU PID. Please specify --qemu-pid")
            sys.exit(1)
    print("QEMU PID: {}".format(qemu_pid))

    # Get vhost TIDs
    vhost_tids = get_vhost_tids(qemu_pid)
    if not vhost_tids:
        print("Error: No vhost threads found for QEMU PID {}".format(qemu_pid))
        sys.exit(1)
    print("Found {} vhost threads: {}".format(len(vhost_tids), vhost_tids))

    # Parse flow filter
    flow = parse_flow(args.flow)
    flow_const = flow_constants(flow)

    # Build and load BPF program
    bpf_text = build_bpf_program(flow_const, debug=args.debug)
    b = BPF(text=bpf_text)

    # Find kernel functions
    eventfd_signal = find_kernel_function("eventfd_signal")
    vhost_poll_wakeup = find_kernel_function("vhost_poll_wakeup")
    handle_tx_kick = find_kernel_function("handle_tx_kick")
    tun_sendmsg = find_kernel_function("tun_sendmsg")
    ioeventfd_write = find_kernel_function("ioeventfd_write")

    missing = [n for n, v in [
        ("eventfd_signal", eventfd_signal),
        ("vhost_poll_wakeup", vhost_poll_wakeup),
        ("handle_tx_kick", handle_tx_kick),
        ("tun_sendmsg", tun_sendmsg),
        ("ioeventfd_write", ioeventfd_write),
    ] if not v]
    if missing:
        print("Error: missing kernel symbols: {}".format(", ".join(missing)))
        sys.exit(1)

    # Attach probes
    b.attach_kprobe(event=eventfd_signal, fn_name="trace_eventfd_signal")
    b.attach_kretprobe(event=eventfd_signal, fn_name="trace_eventfd_signal_ret")
    b.attach_kprobe(event=vhost_poll_wakeup, fn_name="trace_vhost_poll_wakeup")
    b.attach_kprobe(event=ioeventfd_write, fn_name="trace_ioeventfd_write")
    b.attach_kprobe(event=handle_tx_kick, fn_name="trace_handle_tx_kick")
    b.attach_kprobe(event=tun_sendmsg, fn_name="trace_tun_sendmsg")

    # Set filters
    set_device_filter(b, args.device)
    set_target_tids(b, vhost_tids)

    if args.flow:
        print("Flow filter: {}".format(args.flow))
    else:
        print("Flow filter: All packets")

    # Statistics
    total_s0_sum = 0
    total_s1_sum = 0
    total_s2_sum = 0
    total_s0_cnt = 0
    total_s1_cnt = 0
    total_s2_cnt = 0
    total_chain_sum = 0
    total_chain_cnt = 0
    in_warmup = [True] if args.warmup > 0 else [False]  # Use list for nonlocal mutation

    def handle_event(_cpu, data, _size):
        nonlocal total_s0_sum, total_s1_sum, total_s2_sum
        nonlocal total_s0_cnt, total_s1_cnt, total_s2_cnt
        nonlocal total_chain_sum, total_chain_cnt
        if in_warmup[0]:
            return  # Skip during warmup (eventfd learning happens in BPF)
        evt = ct.cast(data, ct.POINTER(LatencyEvent)).contents
        total_s2_sum += evt.s2_us
        total_s2_cnt += 1
        if evt.s0_ok:
            total_s0_sum += evt.s0_us
            total_s0_cnt += 1
        if evt.s1_ok:
            total_s1_sum += evt.s1_us
            total_s1_cnt += 1
        if evt.s0_ok and evt.s1_ok:
            total_chain_sum += (evt.s0_us + evt.s1_us + evt.s2_us)
            total_chain_cnt += 1
        if not args.no_detail:
            total = evt.s0_us + evt.s1_us + evt.s2_us if (evt.s0_ok and evt.s1_ok) else 0
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print("[{}] tid={} queue={} s0={}us s1={}us s2={}us total={}us".format(
                ts, evt.tid, evt.queue, evt.s0_us, evt.s1_us, evt.s2_us, total))

    b["events"].open_perf_buffer(handle_event)

    # Warmup phase to learn eventfds
    if args.warmup > 0:
        print("\nWarmup: {}s (learning eventfds)...".format(args.warmup))
        warmup_start = time.time()
        try:
            while (time.time() - warmup_start) < args.warmup:
                b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            pass
        in_warmup[0] = False
        print("Warmup complete.")

    print("\nTracing... Hit Ctrl+C to end.")
    if args.duration:
        print("Duration: {}s".format(args.duration))

    start_time = time.time()
    try:
        while True:
            b.perf_buffer_poll(timeout=100)
            if args.duration and (time.time() - start_time) >= args.duration:
                break
    except KeyboardInterrupt:
        pass

    # Print summary
    print("\n" + "=" * 60)
    print("Summary Statistics")
    print("=" * 60)

    def fmt_avg(total, count):
        return "{:.1f}".format(total / count) if count else "N/A"

    print("S0 (ioeventfd->kick):   cnt={:>8}  avg={:>10}us".format(
        total_s0_cnt, fmt_avg(total_s0_sum, total_s0_cnt)))
    print("S1 (kick->sendmsg):     cnt={:>8}  avg={:>10}us".format(
        total_s1_cnt, fmt_avg(total_s1_sum, total_s1_cnt)))
    print("S2 (sendmsg->receive):  cnt={:>8}  avg={:>10}us".format(
        total_s2_cnt, fmt_avg(total_s2_sum, total_s2_cnt)))
    print("Total chain:            cnt={:>8}  avg={:>10}us".format(
        total_chain_cnt, fmt_avg(total_chain_sum, total_chain_cnt)))

    # Print debug stats if debug mode enabled
    if args.debug:
        print("\nDebug counters:")
        stats = b["stats"]
        labels = [
            "ioeventfd_write", "s1_samples", "s2_samples",
            "s0_miss", "s1_miss", "s2_miss",
            "fifo_underflow", "fifo_overflow",
            "handle_tx_kick", "tun_sendmsg", "flow_match",
            "has_s2_start", "netif_receive", "tid_active",
            "eventfd_lookup_ok", "eventfd_ok_fifo_fail", "eventfd_lookup_fail",
            "s0_state_notfound", "s0_fifo_empty", "s0_fifo_corrupted",
            "s0_ts_lookup_fail", "eventfd_filtered", "target_tid_kick",
            "s0_push", "s0_pop_ok"
        ]
        for i, label in enumerate(labels):
            if i < len(labels):
                print("  [{}] {}: {}".format(i, label, stats[i].value))


if __name__ == "__main__":
    main()
