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

BPF_HASH(send_ts, struct flow_key_t, u64);

static inline int is_target_port(u16 port)
{
    return ntohs(port) == 62109;
}

static __always_inline int my_strncmp(const char *s1, const char *s2, int n)
{
    #pragma unroll
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i]) {
            return (s1[i] - s2[i]);
        }
        if (s1[i] == '\0')
            break;
    }
    return 0;
}

static __always_inline bool devname_is(const char *ifname, const char *prefix, int prefix_len) {
    #pragma unroll
    for (int i = 0; i < prefix_len; i++) {
        if (ifname[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}


RAW_TRACEPOINT_PROBE(net_dev_xmit)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (!skb) return 0;

    // Get device info from skb
    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    // Judge if it's vnet45
    //if (my_strncmp(ifname, "vnet45", 6) != 0) {
    //    return 0;  
    //}
    if (!devname_is(ifname, "vnet100", 7)) return 0;

    u16 proto = 0;
    bpf_probe_read(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("LATENCY_DBG xmit: non-IP protocol %x\\n", proto);
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    if (iph.protocol != IPPROTO_UDP) {
        bpf_trace_printk("LATENCY_DBG xmit: non-UDP protocol %x\\n", iph.protocol);
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    // Debug: Print IP and ports
    //bpf_trace_printk("LATENCY_DBG xmit: %x -> %x\\n", iph.saddr, iph.daddr);

    //bpf_trace_printk("LATENCY_DBG xmit: ports %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));
    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
        return 0;
    }
    //bpf_trace_printk("LATENCY_DBG xmit: ports %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));

    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    u64 *ts = send_ts.lookup(&key);
    if (ts) {
        u64 delta = bpf_ktime_get_ns() - *ts;
        bpf_trace_printk("LATENCY_DBG latency=%d us\\n", delta / 1000);
        send_ts.delete(&key);
    }

    return 0;
}

TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb) return 0;

    struct net_device *dev;
    char ifname[IFNAMSIZ] = {0};
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);
    bpf_probe_read_kernel_str(ifname, IFNAMSIZ, dev->name);

    //if (my_strncmp(ifname, "vnet48", 6) != 0) {
    //    return 0;
    //}
    if (!devname_is(ifname, "vnet103", 7)) return 0;

    u16 proto = 0;
    bpf_probe_read(&proto, sizeof(proto), &skb->protocol);
    if (proto != __constant_htons(ETH_P_IP)) {
        bpf_trace_printk("LATENCY_DBG recv: non-IP protocol %x\\n", proto);
        return 0;
    }

    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header);
    if (iph.protocol != IPPROTO_UDP) {
        bpf_trace_printk("LATENCY_DBG recv: non-UDP protocol %x\\n", iph.protocol);
        return 0;
    }

    struct udphdr udph;
    bpf_probe_read_kernel(&udph, sizeof(udph), skb->head + skb->transport_header);

    // Debug: Print IP and ports
    //bpf_trace_printk("LATENCY_DBG recv: %x -> %x\\n", iph.saddr, iph.daddr);

    //bpf_trace_printk("LATENCY_DBG recv: ports %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));
    if (!is_target_port(udph.source) && !is_target_port(udph.dest)) {
        return 0;
    }
    //bpf_trace_printk("LATENCY_DBG recv: ports %d -> %d\\n", ntohs(udph.source), ntohs(udph.dest));

    struct flow_key_t key = {};
    key.saddr = iph.saddr;
    key.daddr = iph.daddr;
    key.sport = udph.source;
    key.dport = udph.dest;

    u64 ts = bpf_ktime_get_ns();
    send_ts.update(&key, &ts);

    return 0;
}
"""

def main():
    b = BPF(text=bpf_text)
    print("Tracing UDP port 62109 from vnet48 -> vnet45; hit Ctrl+C to exit.\n")

    # Print debug messages
    print("Printing debug output...")
    try:
        while True:
            try:
                (task, pid, cpu, flags, ts, msg) = b.trace_fields()
                if "LATENCY_DBG" in msg.decode():
                    print("%-18.9f %s" % (ts, msg))
            except ValueError:
                continue
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

