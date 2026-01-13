#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
kvm_vhost_tun_latency.py

Two-phase measurement for host-side latency:
  KVM ioeventfd kick -> vhost handle_tx_kick -> tun_sendmsg -> netif_receive_skb

Phase 1 (discover):
  - Identify vhost worker tids that carry the specified flow.
  - Build tid -> eventfd_ctx mapping via vhost handle_tx_kick.

Phase 2 (measure):
  - Use a Phase 1 profile to filter and measure per-packet latency.

Examples:
  # Phase 1: discover using a flow filter on vnet94
  sudo %(prog)s --mode discover --device vnet94 \
    --flow "proto=udp,src=10.0.0.1,dst=10.0.0.2,sport=1234,dport=4321" \
    --out profile.json

  # Phase 2: measure using profile
  sudo %(prog)s --mode measure --profile profile.json --interval 1 --duration 30

Notes:
  - Requires root, BCC, and kernel headers.
  - Assumes tfile->napi_enabled is off and RPS is disabled.
"""

from __future__ import print_function

import argparse
import datetime
import ipaddress
import json
import re
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

    proto_map = {
        "tcp": 6,
        "udp": 17,
        "icmp": 1,
        "icmpv6": 58,
    }

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


def build_common_bpf(flow_const):
    """Build BPF flow matcher helpers and device filter."""
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

union name_buf {
    char name[IFNAMSIZ];
    struct {
        u64 hi;
        u64 lo;
    } name_int;
};

struct queue_key {
    u16 queue_index;
    u16 pad;
};

#define MAX_TAP_QUEUES 256

struct tun_struct;
struct tun_file {
    struct sock sk;
    struct socket socket;
    struct socket_wq wq;
    struct tun_struct *tun;
    struct fasync_struct *fasync;
    unsigned int flags;
    u16 queue_index;
};

struct tun_struct {
    struct tun_file *tfiles[MAX_TAP_QUEUES];
    unsigned int numqueues;
    unsigned int flags;
    kuid_t owner;
    kgid_t group;
    struct net_device *dev;
};

BPF_ARRAY(name_map, union name_buf, 1);

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
"""
    for k, v in flow_const.items():
        text = text.replace("__{}__".format(k), str(v))
    return text


def build_discover_bpf(flow_const):
    return build_common_bpf(flow_const) + r"""

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

// current eventfd ctx (per-cpu)
BPF_PERCPU_ARRAY(current_eventfd, u64, 1);
// work_ptr -> eventfd_ctx
BPF_HASH(work_eventfd, u64, u64, 4096);
// tid -> eventfd_ctx (set in handle_tx_kick)
BPF_HASH(tid_eventfd, u32, u64, 4096);

// tid -> flow info (count + queue)
struct tid_info {
    u64 count;
    u32 queue;
    u32 pad;
};
BPF_HASH(flow_tid_info, u32, struct tid_info, 4096);

// Debug counters
// 0: eventfd_signal, 1: vhost_poll_wakeup, 2: work_eventfd_update
// 3: handle_tx_kick, 4: work_eventfd_miss, 5: tid_eventfd_update
// 6: netif_receive, 7: devname_match, 8: ipv4_packet, 9: flow_match
// 10: tid_info_update
BPF_ARRAY(stats, u64, 16);

static __always_inline void stats_inc(int idx) {
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

int trace_eventfd_signal(struct pt_regs *ctx) {
    struct eventfd_ctx *eventfd = (struct eventfd_ctx *)PT_REGS_PARM1(ctx);
    if (!eventfd) return 0;
    stats_inc(0);
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
    stats_inc(1);
    int key = 0;
    u64 *eventfd = current_eventfd.lookup(&key);
    if (!eventfd || *eventfd == 0) return 0;

    struct vhost_poll *poll = (struct vhost_poll *)((char *)wait - offsetof(struct vhost_poll, wait));
    u64 work_ptr = (u64)&poll->work;
    work_eventfd.update(&work_ptr, eventfd);
    stats_inc(2);
    return 0;
}

int trace_handle_tx_kick(struct pt_regs *ctx) {
    void *work = (void *)PT_REGS_PARM1(ctx);
    if (!work) return 0;
    stats_inc(3);

    u64 work_ptr = (u64)work;
    u64 *eventfd = work_eventfd.lookup(&work_ptr);
    if (!eventfd) {
        stats_inc(4);
        return 0;
    }
    stats_inc(5);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    tid_eventfd.update(&tid, eventfd);
    return 0;
}

int trace_netif_receive_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) return 0;
    stats_inc(6);

    struct net_device *dev = NULL;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    if (!dev) return 0;
    if (!name_filter(dev)) return 0;
    stats_inc(7);

    __be16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto == bpf_htons(ETH_P_IP))
        stats_inc(8);

    if (!flow_match(skb)) return 0;
    stats_inc(9);

    // Get queue mapping from skb
    u16 qmap = 0;
    bpf_probe_read_kernel(&qmap, sizeof(qmap), &skb->queue_mapping);
    u32 queue = qmap > 0 ? qmap - 1 : 0;

    // Record TID -> (count, queue) mapping
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_info *info = flow_tid_info.lookup(&tid);
    if (info) {
        __sync_fetch_and_add(&info->count, 1);
        info->queue = queue;
    } else {
        struct tid_info new_info = {.count = 1, .queue = queue, .pad = 0};
        flow_tid_info.update(&tid, &new_info);
    }
    stats_inc(10);
    return 0;
}
"""


def build_measure_bpf(flow_const):
    return build_common_bpf(flow_const) + r"""

#include <kvm/iodev.h>

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

struct s2_state {
    u32 head;
    u32 tail;
};

struct s0_state {
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

#define S0_RING_SZ 1024
#define S2_RING_SZ 2048

// Filters
BPF_HASH(target_eventfd, u64, u8, 4096);
// Dynamic TID marking - set when handle_tx_kick sees target eventfd
BPF_HASH(active_tid, u32, u8, 4096);

// current eventfd ctx (per-cpu)
BPF_PERCPU_ARRAY(current_eventfd, u64, 1);
// Work -> eventfd_ctx mapping
BPF_HASH(work_eventfd, u64, u64, 4096);

// Timestamps
BPF_HASH(s1_start, u32, u64, 4096); // key: tid

// S0 FIFO per eventfd
BPF_HASH(s0_state, u64, struct s0_state, 4096); // key: eventfd_ctx
BPF_HASH(s0_ts, struct s0_slot_key, u64, 65536);

// Last S0 delta per tid (use to stamp each packet in batch)
BPF_HASH(s0_last, u32, u64, 4096);
BPF_HASH(s0_last_ok, u32, u8, 4096);

// S2 FIFO per thread
BPF_HASH(s2_state, u32, struct s2_state, 4096); // key: tid
BPF_HASH(s2_ts, struct s2_slot_key, u64, 65536);
// S0/S1 delta FIFO aligned with S2
BPF_HASH(s0_val, struct s12_slot_key, u64, 65536);
BPF_HASH(s1_val, struct s12_slot_key, u64, 65536);
BPF_HASH(s0_ok, struct s12_slot_key, u8, 65536);
BPF_HASH(s1_ok, struct s12_slot_key, u8, 65536);

// Histograms
BPF_HISTOGRAM(s0_hist, u64, 64);
BPF_HISTOGRAM(s1_hist, u64, 64);
BPF_HISTOGRAM(s2_hist, u64, 64);

// Stats: 24 detailed counters
// 0: s0_samples, 1: s1_samples, 2: s2_samples
// 3: s0_miss, 4: s1_miss, 5: s2_miss
// 6: fifo_underflow, 7: fifo_overflow
// 8: handle_tx_kick, 9: tun_sendmsg, 10: flow_hits
// 11: has_s2_start, 12: netif_receive, 13: tid_active
// 14: not_ipv4, 15: is_ipv4, 16: proto_mismatch, 17: proto_ok
// 18: src_mismatch, 19: src_ok, 20: dst_mismatch
// 21: ioeventfd_write, 22: eventfd_filter_pass, 23: has_head
BPF_ARRAY(stats, u64, 24);

static __always_inline void stats_inc(int idx) {
    u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

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
    if (!p || p->head == p->tail) {
        stats_inc(6);
        return 0;
    }
    struct s0_slot_key key = {.eventfd = evt, .slot = p->head % S0_RING_SZ};
    u64 *val = s0_ts.lookup(&key);
    if (!val) {
        stats_inc(6);
        p->head++;
        return 0;
    }
    *ts = *val;
    p->head++;
    return 1;
}

static __always_inline void s2_fifo_push(u32 tid, u64 ts) {
    struct s2_state st = {};
    struct s2_state *p = s2_state.lookup(&tid);
    if (p) st = *p;

    u32 depth = st.tail - st.head;
    if (depth >= S2_RING_SZ) {
        stats_inc(7);
        st.head++;
    }

    struct s2_slot_key key = {.tid = tid, .slot = st.tail % S2_RING_SZ};
    s2_ts.update(&key, &ts);
    st.tail++;
    s2_state.update(&tid, &st);
}

static __always_inline int s2_fifo_pop(u32 tid, u64 *ts, u32 *slot) {
    struct s2_state *p = s2_state.lookup(&tid);
    if (!p || p->head == p->tail) {
        stats_inc(6);
        return 0;
    }
    u32 idx = p->head % S2_RING_SZ;
    if (slot)
        *slot = idx;
    struct s2_slot_key key = {.tid = tid, .slot = idx};
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

int trace_eventfd_signal(struct pt_regs *ctx) {
    struct eventfd_ctx *eventfd = (struct eventfd_ctx *)PT_REGS_PARM1(ctx);
    if (!eventfd) return 0;
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
    stats_inc(21);
    struct _ioeventfd *p = (struct _ioeventfd *)((char *)dev - offsetof(struct _ioeventfd, dev));
    struct eventfd_ctx *eventfd = NULL;
    bpf_probe_read_kernel(&eventfd, sizeof(eventfd), &p->eventfd);
    if (!eventfd) return 0;
    u64 evt_ptr = (u64)eventfd;

    // Filter by target eventfd
    u8 *ok = target_eventfd.lookup(&evt_ptr);
    if (!ok) return 0;
    stats_inc(22);

    u64 ts = bpf_ktime_get_ns();
    s0_fifo_push(evt_ptr, ts);
    return 0;
}

int trace_handle_tx_kick(struct pt_regs *ctx) {
    stats_inc(8);
    void *work = (void *)PT_REGS_PARM1(ctx);
    if (!work) return 0;

    u64 work_ptr = (u64)work;
    u64 *eventfd = work_eventfd.lookup(&work_ptr);
    if (!eventfd) return 0;

    // Filter by target eventfd
    u8 *ok = target_eventfd.lookup(eventfd);
    if (!ok) return 0;

    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    // S0: Calculate latency from ioeventfd_write
    u64 start = 0;
    if (s0_fifo_pop(*eventfd, &start)) {
        u64 delta = ts - start;
        u64 us = delta / 1000;
        s0_last.update(&tid, &us);
        u8 one = 1;
        s0_last_ok.update(&tid, &one);
    } else {
        u8 zero = 0;
        s0_last_ok.update(&tid, &zero);
    }

    // Mark this TID as active and start S1 timing
    u8 one = 1;
    active_tid.update(&tid, &one);
    s1_start.update(&tid, &ts);
    return 0;
}

int trace_tun_sendmsg(struct pt_regs *ctx) {
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    if (!sock) return 0;
    stats_inc(9);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    // Check if TID is active (from handle_tx_kick)
    u8 *ok = active_tid.lookup(&tid);
    if (!ok) return 0;

    u64 ts = bpf_ktime_get_ns();
    u64 s1_us = 0;
    u8 s1_ok_val = 0;
    u64 *start = s1_start.lookup(&tid);
    if (start) {
        u64 delta = ts - *start;
        s1_us = delta / 1000;
        s1_ok_val = 1;
    }
    s1_start.delete(&tid);

    // Prepare FIFO slot
    struct s2_state st = {};
    struct s2_state *p = s2_state.lookup(&tid);
    if (p) st = *p;
    u32 idx = st.tail % S2_RING_SZ;

    // S2 start
    struct s2_slot_key key = {.tid = tid, .slot = idx};
    s2_ts.update(&key, &ts);

    // S0/S1 delta storage aligned with S2
    struct s12_slot_key k12 = {.tid = tid, .slot = idx};
    u64 s0_us = 0;
    u8 s0_ok_val = 0;
    u64 *s0p = s0_last.lookup(&tid);
    u8 *s0ok = s0_last_ok.lookup(&tid);
    if (s0p)
        s0_us = *s0p;
    if (s0ok && *s0ok)
        s0_ok_val = 1;
    s0_val.update(&k12, &s0_us);
    s1_val.update(&k12, &s1_us);
    s0_ok.update(&k12, &s0_ok_val);
    s1_ok.update(&k12, &s1_ok_val);

    // Advance FIFO
    st.tail++;
    s2_state.update(&tid, &st);
    return 0;
}

int trace_netif_receive_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    if (!skb) return 0;
    stats_inc(12);

    u32 tid = (u32)bpf_get_current_pid_tgid();
    // Check if TID is active (from handle_tx_kick)
    u8 *ok = active_tid.lookup(&tid);
    if (!ok) return 0;
    stats_inc(13);

    // Ensure packet belongs to target device before consuming FIFO
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
        struct s2_state *st = s2_state.lookup(&tid);
        if (st && st->head == st->tail)
            active_tid.delete(&tid);
        return 0;
    }
    stats_inc(10);

    u64 ts = bpf_ktime_get_ns();
    u64 delta = ts - ts_start;
    u64 us = delta / 1000;
    s2_hist.increment(us > 0 ? bpf_log2l(us) : 0);
    stats_inc(2);

    // Emit S0/S1 only for flow-matched chain
    u8 *s0ok = s0_ok.lookup(&k12);
    u8 *s1ok = s1_ok.lookup(&k12);
    u64 *s0us = s0_val.lookup(&k12);
    u64 *s1us = s1_val.lookup(&k12);
    if (s0ok && *s0ok && s0us) {
        s0_hist.increment(*s0us > 0 ? bpf_log2l(*s0us) : 0);
        stats_inc(0);
    } else {
        stats_inc(3);
    }
    if (s1ok && *s1ok && s1us) {
        s1_hist.increment(*s1us > 0 ? bpf_log2l(*s1us) : 0);
        stats_inc(1);
    } else {
        stats_inc(4);
    }

    // Cleanup aligned slots
    s0_val.delete(&k12);
    s1_val.delete(&k12);
    s0_ok.delete(&k12);
    s1_ok.delete(&k12);

    struct s2_state *st = s2_state.lookup(&tid);
    if (st && st->head == st->tail) {
        active_tid.delete(&tid);
    }
    return 0;
}
"""


def calc_histogram_stats(hist):
    """Calculate avg, p50, p95, p99 from log2 histogram buckets."""
    items = []
    for k, v in hist.items():
        if v.value > 0:
            items.append((k.value, v.value))
    if not items:
        return None

    items.sort(key=lambda x: x[0])
    total = sum(count for _, count in items)
    if total == 0:
        return None

    # Calculate average using bucket midpoints
    weighted_sum = 0
    for bucket, count in items:
        if bucket == 0:
            midpoint = 0.5  # 0->1 range, midpoint ~0.5
        else:
            low = 1 << bucket
            high = (1 << (bucket + 1)) - 1
            midpoint = (low + high) / 2.0
        weighted_sum += midpoint * count
    avg = weighted_sum / total

    # Calculate percentiles
    def get_percentile(pct):
        target = total * pct / 100.0
        cumulative = 0
        for bucket, count in items:
            cumulative += count
            if cumulative >= target:
                if bucket == 0:
                    return 1
                else:
                    low = 1 << bucket
                    high = (1 << (bucket + 1)) - 1
                    # Linear interpolation within bucket
                    prev_cumulative = cumulative - count
                    fraction = (target - prev_cumulative) / count if count > 0 else 0
                    return low + fraction * (high - low)
        # Return max bucket value
        last_bucket = items[-1][0]
        return (1 << (last_bucket + 1)) - 1 if last_bucket > 0 else 1

    return {
        "avg": avg,
        "p50": get_percentile(50),
        "p90": get_percentile(90),
        "p99": get_percentile(99),
        "total": total,
    }


def print_histogram(hist, title, unit="us"):
    """Print histogram and return stats."""
    print("\n{}".format(title))
    print("{:>16} : {:>8}   {}".format(unit, "count", "distribution"))
    items = []
    max_count = 0
    for k, v in hist.items():
        if v.value > 0:
            items.append((k.value, v.value))
            max_count = max(max_count, v.value)
    if not items:
        print("   (no samples)")
        return None
    items.sort(key=lambda x: x[0])
    for bucket, count in items:
        if bucket == 0:
            range_str = "0 -> 1"
        else:
            low = 1 << bucket
            high = (1 << (bucket + 1)) - 1
            range_str = "{} -> {}".format(low, high)
        bar_len = int(40 * count / max_count) if max_count > 0 else 0
        bar = '*' * bar_len
        print("{:>16} : {:>8}   |{:<40}|".format(range_str, count, bar))

    # Calculate and print stats
    stats = calc_histogram_stats(hist)
    if stats:
        print("  avg={:.1f}us  p50={:.1f}us  p90={:.1f}us  p99={:.1f}us  (n={})".format(
            stats["avg"], stats["p50"], stats["p90"], stats["p99"], stats["total"]))
    return stats


def histogram_to_dict(hist):
    """Convert BPF histogram to dict bucket->count."""
    data = {}
    for k, v in hist.items():
        if v.value > 0:
            data[k.value] = v.value
    return data


def print_histogram_delta(cur, prev, title, unit="us"):
    """Print per-interval histogram (delta)."""
    print("\n{}".format(title))
    print("{:>16} : {:>8}   {}".format(unit, "count", "distribution"))
    items = []
    max_count = 0
    for bucket, count in cur.items():
        delta = count - prev.get(bucket, 0)
        if delta > 0:
            items.append((bucket, delta))
            max_count = max(max_count, delta)
    if not items:
        print("   (no samples)")
        return None
    items.sort(key=lambda x: x[0])
    for bucket, count in items:
        if bucket == 0:
            range_str = "0 -> 1"
        else:
            low = 1 << bucket
            high = (1 << (bucket + 1)) - 1
            range_str = "{} -> {}".format(low, high)
        bar_len = int(40 * count / max_count) if max_count > 0 else 0
        bar = '*' * bar_len
        print("{:>16} : {:>8}   |{:<40}|".format(range_str, count, bar))
    stats = calc_histogram_stats_dict(items)
    if stats:
        print("  avg={:.1f}us  p50={:.1f}us  p90={:.1f}us  p99={:.1f}us  (n={})".format(
            stats["avg"], stats["p50"], stats["p90"], stats["p99"], stats["total"]))
    return stats


def calc_histogram_stats_dict(items):
    """Calculate avg/p50/p95/p99 from (bucket, count) list."""
    if not items:
        return None
    total = sum(count for _, count in items)
    if total == 0:
        return None
    items = sorted(items, key=lambda x: x[0])

    weighted_sum = 0
    for bucket, count in items:
        if bucket == 0:
            midpoint = 0.5
        else:
            low = 1 << bucket
            high = (1 << (bucket + 1)) - 1
            midpoint = (low + high) / 2.0
        weighted_sum += midpoint * count
    avg = weighted_sum / total

    def get_percentile(pct):
        target = total * pct / 100.0
        cumulative = 0
        for bucket, count in items:
            cumulative += count
            if cumulative >= target:
                if bucket == 0:
                    return 1
                low = 1 << bucket
                high = (1 << (bucket + 1)) - 1
                prev_cumulative = cumulative - count
                fraction = (target - prev_cumulative) / count if count > 0 else 0
                return low + fraction * (high - low)
        last_bucket = items[-1][0]
        return (1 << (last_bucket + 1)) - 1 if last_bucket > 0 else 1

    return {
        "avg": avg,
        "p50": get_percentile(50),
        "p90": get_percentile(90),
        "p99": get_percentile(99),
        "total": total,
    }


def set_device_filter(bpf, device):
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


def run_discover(args):
    flow = parse_flow(args.flow)
    flow_const = flow_constants(flow)
    bpf_text = build_discover_bpf(flow_const)
    b = BPF(text=bpf_text)

    eventfd_signal = find_kernel_function("eventfd_signal", args.verbose)
    vhost_poll_wakeup = find_kernel_function("vhost_poll_wakeup", args.verbose)
    handle_tx_kick = find_kernel_function("handle_tx_kick", args.verbose)
    netif_recv = find_kernel_function("__netif_receive_skb", args.verbose)
    if not netif_recv:
        netif_recv = find_kernel_function("netif_receive_skb", args.verbose)

    missing = [n for n, v in [
        ("eventfd_signal", eventfd_signal),
        ("vhost_poll_wakeup", vhost_poll_wakeup),
        ("handle_tx_kick", handle_tx_kick),
    ] if not v]
    if not netif_recv:
        missing.append("__netif_receive_skb/netif_receive_skb")
    if missing:
        print("Error: missing kernel symbols: {}".format(", ".join(missing)))
        sys.exit(1)

    b.attach_kprobe(event=eventfd_signal, fn_name="trace_eventfd_signal")
    b.attach_kretprobe(event=eventfd_signal, fn_name="trace_eventfd_signal_ret")
    b.attach_kprobe(event=vhost_poll_wakeup, fn_name="trace_vhost_poll_wakeup")
    b.attach_kprobe(event=handle_tx_kick, fn_name="trace_handle_tx_kick")
    b.attach_kprobe(event=netif_recv, fn_name="trace_netif_receive_skb")

    set_device_filter(b, args.device)
    print("Discover mode: running for {}s".format(args.duration))
    time.sleep(args.duration)

    stats = b["stats"]
    print("\nDebug counters:")
    labels = [
        "eventfd_signal", "vhost_poll_wakeup", "work_eventfd_update",
        "handle_tx_kick", "work_eventfd_miss", "tid_eventfd_update",
        "netif_receive", "devname_match", "ipv4_packet", "flow_match",
        "tid_info_update"
    ]
    for i, label in enumerate(labels):
        print("  [{}] {}: {}".format(i, label, stats[i].value))

    flow_tid_info = b["flow_tid_info"]
    tid_eventfd = b["tid_eventfd"]

    # Build TID -> eventfd mapping
    tid_eventfd_map = {}
    for k, v in tid_eventfd.items():
        tid = int(k.value if hasattr(k, "value") else k)
        eventfd = int(v.value)
        tid_eventfd_map[tid] = eventfd

    # Collect flow TID info and correlate with eventfd
    associations = []
    tids = []
    eventfds = set()
    for k, v in flow_tid_info.items():
        tid = int(k.value if hasattr(k, "value") else k)
        if tid == 0:
            continue
        count = int(v.count)
        queue = int(v.queue)
        eventfd = tid_eventfd_map.get(tid, 0)
        if eventfd:
            eventfds.add(eventfd)
        associations.append({
            "tid": tid,
            "queue": queue,
            "count": count,
            "eventfd": "0x{:x}".format(eventfd) if eventfd else None
        })
        tids.append({"tid": tid, "count": count})

    # Fallback: if no eventfd found, collect all observed eventfds
    if not eventfds:
        print("Warning: no eventfd_ctx matched flow tids; falling back to all eventfd_ctx seen.")
        for k, v in tid_eventfd.items():
            eventfds.add(int(v.value))

    # Sort associations by count descending
    associations.sort(key=lambda x: x["count"], reverse=True)
    tids.sort(key=lambda x: x["tid"])

    # Print discovered associations
    print("\nDiscovered TID -> Queue -> Eventfd associations:")
    print("{:>8} {:>6} {:>8} {:>20}".format("TID", "Queue", "Count", "Eventfd"))
    print("-" * 50)
    for a in associations:
        print("{:>8} {:>6} {:>8} {:>20}".format(
            a["tid"], a["queue"], a["count"],
            a["eventfd"] if a["eventfd"] else "N/A"))

    profile = {
        "device": args.device,
        "flow": args.flow,
        "tids": tids,
        "associations": associations,
        "eventfd_ctx": ["0x{:x}".format(e) for e in sorted(eventfds)],
        "timestamp": datetime.datetime.now().isoformat(),
    }

    if args.out:
        with open(args.out, "w") as f:
            json.dump(profile, f, indent=2, sort_keys=True)
        print("\nWrote profile: {}".format(args.out))
    else:
        print(json.dumps(profile, indent=2, sort_keys=True))


def load_profile(path):
    with open(path, "r") as f:
        return json.load(f)


def run_measure(args):
    profile = load_profile(args.profile)
    if not profile.get("eventfd_ctx"):
        print("Error: profile missing eventfd_ctx; re-run discovery.")
        sys.exit(1)
    flow = parse_flow(profile.get("flow", ""))
    flow_const = flow_constants(flow)
    bpf_text = build_measure_bpf(flow_const)
    b = BPF(text=bpf_text)

    eventfd_signal = find_kernel_function("eventfd_signal", args.verbose)
    vhost_poll_wakeup = find_kernel_function("vhost_poll_wakeup", args.verbose)
    handle_tx_kick = find_kernel_function("handle_tx_kick", args.verbose)
    tun_sendmsg = find_kernel_function("tun_sendmsg", args.verbose)
    netif_recv = find_kernel_function("__netif_receive_skb", args.verbose)
    if not netif_recv:
        netif_recv = find_kernel_function("netif_receive_skb", args.verbose)
    ioeventfd_write = find_kernel_function("ioeventfd_write", args.verbose)

    missing = [n for n, v in [
        ("eventfd_signal", eventfd_signal),
        ("vhost_poll_wakeup", vhost_poll_wakeup),
        ("handle_tx_kick", handle_tx_kick),
        ("tun_sendmsg", tun_sendmsg),
        ("__netif_receive_skb/netif_receive_skb", netif_recv),
        ("ioeventfd_write", ioeventfd_write),
    ] if not v]
    if missing:
        print("Error: missing kernel symbols: {}".format(", ".join(missing)))
        sys.exit(1)

    b.attach_kprobe(event=eventfd_signal, fn_name="trace_eventfd_signal")
    b.attach_kretprobe(event=eventfd_signal, fn_name="trace_eventfd_signal_ret")
    b.attach_kprobe(event=vhost_poll_wakeup, fn_name="trace_vhost_poll_wakeup")
    b.attach_kprobe(event=ioeventfd_write, fn_name="trace_ioeventfd_write")
    b.attach_kprobe(event=handle_tx_kick, fn_name="trace_handle_tx_kick")
    b.attach_kprobe(event=tun_sendmsg, fn_name="trace_tun_sendmsg")
    b.attach_kprobe(event=netif_recv, fn_name="trace_netif_receive_skb")

    set_device_filter(b, profile.get("device"))

    # Load target eventfd filter (TID correlation via active_tid is dynamic)
    target_eventfd = b["target_eventfd"]
    for e in profile.get("eventfd_ctx", []):
        if isinstance(e, str):
            e = int(e, 16)
        target_eventfd[ct.c_ulonglong(e)] = ct.c_ubyte(1)

    print("Target eventfds: {}".format(profile.get("eventfd_ctx", [])))
    if profile.get("associations"):
        print("\nTID -> Queue -> Eventfd associations from discovery:")
        for a in profile["associations"]:
            print("  TID {} -> Queue {} -> {} (count={})".format(
                a["tid"], a["queue"], a["eventfd"], a["count"]))

    print("\nMeasure mode: interval={}s duration={}s".format(
        args.interval, args.duration))
    start = time.time()
    prev_stats = {}
    prev_hists = {
        "s0": {},
        "s1": {},
        "s2": {},
    }
    total_stats = None
    try:
        while True:
            time.sleep(args.interval)
            elapsed = time.time() - start
            stats = b["stats"]
            cur_stats = {
                "s0": stats[0].value,
                "s1": stats[1].value,
                "s2": stats[2].value,
                "s0_miss": stats[3].value,
                "s1_miss": stats[4].value,
                "s2_miss": stats[5].value,
                "fifo_under": stats[6].value,
                "fifo_over": stats[7].value,
                "kick_calls": stats[8].value,
                "sendmsg_calls": stats[9].value,
                "flow_hits": stats[10].value,
                "has_s2_start": stats[11].value,
                "netif_recv": stats[12].value,
                "tid_active": stats[13].value,
                "ioeventfd_calls": stats[21].value,
                "eventfd_filter": stats[22].value,
            }
            total_stats = cur_stats
            delta_stats = {}
            for k, v in cur_stats.items():
                delta_stats[k] = v - prev_stats.get(k, 0)
            prev_stats = cur_stats

            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print("=" * 72)
            print("[{}] KVM -> vhost -> TUN latency".format(ts))
            print("Interval samples: S0={} S1={} S2={}".format(
                delta_stats["s0"], delta_stats["s1"], delta_stats["s2"]))
            print("Interval misses:  S0={} S1={} S2={}".format(
                delta_stats["s0_miss"], delta_stats["s1_miss"], delta_stats["s2_miss"]))
            print("Interval FIFO: underflow={} overflow={}".format(
                delta_stats["fifo_under"], delta_stats["fifo_over"]))
            print("Interval S0 path: ioeventfd={} filtered={}".format(
                delta_stats["ioeventfd_calls"], delta_stats["eventfd_filter"]))
            print("Interval S1 path: handle_tx_kick={} tun_sendmsg={}".format(
                delta_stats["kick_calls"], delta_stats["sendmsg_calls"]))
            print("Interval S2 path: netif={} tid_active={} has_s2={} flow={}".format(
                delta_stats["netif_recv"], delta_stats["tid_active"],
                delta_stats["has_s2_start"], delta_stats["flow_hits"]))

            cur_s0 = histogram_to_dict(b["s0_hist"])
            cur_s1 = histogram_to_dict(b["s1_hist"])
            cur_s2 = histogram_to_dict(b["s2_hist"])
            print_histogram_delta(cur_s0, prev_hists["s0"], "S0: ioeventfd_write -> handle_tx_kick")
            print_histogram_delta(cur_s1, prev_hists["s1"], "S1: handle_tx_kick -> tun_sendmsg")
            print_histogram_delta(cur_s2, prev_hists["s2"], "S2: tun_sendmsg -> netif_receive_skb")
            prev_hists["s0"] = cur_s0
            prev_hists["s1"] = cur_s1
            prev_hists["s2"] = cur_s2
            print()

            if args.clear:
                b["s0_hist"].clear()
                b["s1_hist"].clear()
                b["s2_hist"].clear()
                prev_hists["s0"] = {}
                prev_hists["s1"] = {}
                prev_hists["s2"] = {}

            if args.duration and elapsed >= args.duration:
                break
    except KeyboardInterrupt:
        pass

    if total_stats:
        stats = b["stats"]
        total_stats = {
            "s0": stats[0].value,
            "s1": stats[1].value,
            "s2": stats[2].value,
            "s0_miss": stats[3].value,
            "s1_miss": stats[4].value,
            "s2_miss": stats[5].value,
            "fifo_under": stats[6].value,
            "fifo_over": stats[7].value,
            "kick_calls": stats[8].value,
            "sendmsg_calls": stats[9].value,
            "flow_hits": stats[10].value,
            "has_s2_start": stats[11].value,
            "netif_recv": stats[12].value,
            "tid_active": stats[13].value,
            "ioeventfd_calls": stats[21].value,
            "eventfd_filter": stats[22].value,
        }
        print("=" * 72)
        print("[final] KVM -> vhost -> TUN latency totals")
        print("Total samples: S0={} S1={} S2={}".format(
            total_stats["s0"], total_stats["s1"], total_stats["s2"]))
        print("Total misses:  S0={} S1={} S2={}".format(
            total_stats["s0_miss"], total_stats["s1_miss"], total_stats["s2_miss"]))
        print("Total FIFO: underflow={} overflow={}".format(
            total_stats["fifo_under"], total_stats["fifo_over"]))
        print("Total S0 path: ioeventfd={} filtered={}".format(
            total_stats["ioeventfd_calls"], total_stats["eventfd_filter"]))
        print("Total S1 path: handle_tx_kick={} tun_sendmsg={}".format(
            total_stats["kick_calls"], total_stats["sendmsg_calls"]))
        print("Total S2 path: netif={} tid_active={} has_s2={} flow={}".format(
            total_stats["netif_recv"], total_stats["tid_active"],
            total_stats["has_s2_start"], total_stats["flow_hits"]))

        print_histogram(b["s0_hist"], "S0: ioeventfd_write -> handle_tx_kick")
        print_histogram(b["s1_hist"], "S1: handle_tx_kick -> tun_sendmsg")
        print_histogram(b["s2_hist"], "S2: tun_sendmsg -> netif_receive_skb")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="KVM -> vhost -> tun latency tool (two-phase)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--mode", choices=["discover", "measure"], required=True)
    parser.add_argument("--device", help="Target device name (e.g., vnet94)")
    parser.add_argument("--flow", help="Flow filter, e.g. proto=udp,src=...,dst=...,sport=...,dport=...")
    parser.add_argument("--out", help="Discovery output profile path")
    parser.add_argument("--profile", help="Measurement profile path")
    parser.add_argument("--interval", type=int, default=1, help="Output interval in seconds")
    parser.add_argument("--duration", type=int, default=10, help="Run duration in seconds")
    parser.add_argument("--clear", action="store_true", help="Clear histograms after each interval")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.mode == "discover":
        run_discover(args)
    elif args.mode == "measure":
        if not args.profile:
            parser.error("--profile is required in measure mode")
        run_measure(args)


if __name__ == "__main__":
    main()
