#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <bcc/proto.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_HASH(last_ts_snd, struct flow_key_t, u64);
BPF_HASH(last_ts_rcv, struct flow_key_t, u64);

static __always_inline int is_target_port(u16 port)
{
    return ntohs(port) == 62109;
}


static __always_inline bool devname_is_vnet45(const char *ifname)
{
    if (ifname[0] == 'v' && ifname[1] == 'n' &&
        ifname[2] == 'e' && ifname[3] == 't' &&
        ifname[4] == '4' && ifname[5] == '5' &&
        ifname[6] == 0 )
    {
        return true;
    }
    return false;
}

static __always_inline bool devname_is_vnet48(const char *ifname)
{
    if (ifname[0] == 'v' && ifname[1] == 'n' &&
        ifname[2] == 'e' && ifname[3] == 't' &&
        ifname[4] == '4' && ifname[5] == '8' &&
        ifname[6] == 0 )
    {
        return true;
    }
    return false;
}


RAW_TRACEPOINT_PROBE(net_dev_xmit)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    struct net_device *dev = 0;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);

    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);

    if (!devname_is_vnet45(ifname)) {
        return 0;
    }

    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    if (iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
    }

    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_snd.lookup(&key);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        bpf_trace_printk("SND GAP: %llu us, flow = %x -> %x\\n", delta_us, iph.saddr, iph.daddr);
    }
    last_ts_snd.update(&key, &now);

    return 0;
}


TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct net_device *dev = 0;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);

    char ifname[IFNAMSIZ] = {};
    bpf_probe_read_kernel_str(ifname, sizeof(ifname), dev->name);

    if (!devname_is_vnet48(ifname)) {
        return 0;
    }

    u16 proto = 0;
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    if (iph.protocol != IPPROTO_UDP) {
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
        return 0;
    }

    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    u64 now = bpf_ktime_get_ns();
    u64 *p_last = last_ts_rcv.lookup(&key);
    if (p_last) {
        u64 delta_ns = now - *p_last;
        u64 delta_us = delta_ns / 1000;
        bpf_trace_printk("RCV GAP: %llu us, flow = %x -> %x\\n", delta_us, iph.saddr, iph.daddr);
    }
    last_ts_rcv.update(&key, &now);

    return 0;
}
"""

def main():
    b = BPF(text=bpf_text)
    print("Tracing UDP port 62109 from vnet48->vnet45 (in host perspective)...")
    print("Hit Ctrl+C to exit.\n")

    try:
        while True:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
            if "SND GAP:" in msg or "RCV GAP:" in msg:
                print("%-18.9f %s" % (ts, msg.decode()))
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

