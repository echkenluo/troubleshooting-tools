// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// skb_frag_list_watcher - SKB frag_list change monitor BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "skb_frag_list_watcher.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration */
const volatile __u32 targ_ifindex = 0;
const volatile __be32 targ_src_ip = 0;
const volatile __be32 targ_dst_ip = 0;
const volatile __u8 gso_only = 0;
const volatile __u8 enable_stack_trace = 0;

/* Ring buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Stack traces */
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 1024);
} stack_traces SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Helper to get skb_shared_info */
static __always_inline void *get_shinfo(struct sk_buff *skb)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    unsigned int end = BPF_CORE_READ(skb, end);
    return head + end;
}

/* Submit event */
static __always_inline void submit_event(struct sk_buff *skb, __u8 event_type,
                                         __u64 frag_before, __u64 frag_after,
                                         const char *func)
{
    struct frag_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->skb_addr = (__u64)skb;
    e->frag_list_before = frag_before;
    e->frag_list_after = frag_after;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cpu = bpf_get_smp_processor_id();
    e->event_type = event_type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Get GSO info from skb_shared_info */
    void *shinfo = get_shinfo(skb);
    if (shinfo) {
        bpf_probe_read_kernel(&e->gso_size, sizeof(e->gso_size), shinfo + 4);
        bpf_probe_read_kernel(&e->gso_segs, sizeof(e->gso_segs), shinfo + 6);
        bpf_probe_read_kernel(&e->gso_type, sizeof(e->gso_type), shinfo + 24);
        bpf_probe_read_kernel(&e->nr_frags, sizeof(e->nr_frags), shinfo + 2);
    }

    e->len = BPF_CORE_READ(skb, len);
    e->data_len = BPF_CORE_READ(skb, data_len);
    e->cloned = BPF_CORE_READ(skb, cloned);

    /* Copy function name */
    __builtin_memset(e->func_name, 0, sizeof(e->func_name));
    bpf_probe_read_kernel_str(e->func_name, sizeof(e->func_name), func);

    /* Stack trace */
    if (enable_stack_trace)
        e->stack_id = bpf_get_stackid((void *)bpf_get_current_task(), &stack_traces, 0);
    else
        e->stack_id = -1;

    bpf_ringbuf_submit(e, 0);

    /* Update stats */
    __u32 idx = event_type;
    __u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

/* Monitor skb_gro_receive_list - frag_list creation */
SEC("kprobe/skb_gro_receive_list")
int BPF_KPROBE(kprobe_skb_gro_receive_list, struct sk_buff *p, struct sk_buff *skb)
{
    if (!p)
        return 0;

    void *shinfo = get_shinfo(p);
    struct sk_buff *frag_list = NULL;
    if (shinfo)
        bpf_probe_read_kernel(&frag_list, sizeof(frag_list), shinfo + 8);

    submit_event(p, EVENT_FRAG_LIST_CREATE, (__u64)frag_list, (__u64)skb, "skb_gro_receive_list");
    return 0;
}

/* Monitor skb_segment_list - frag_list clearing */
SEC("kprobe/skb_segment_list")
int BPF_KPROBE(kprobe_skb_segment_list, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    void *shinfo = get_shinfo(skb);
    struct sk_buff *frag_list = NULL;
    if (shinfo)
        bpf_probe_read_kernel(&frag_list, sizeof(frag_list), shinfo + 8);

    submit_event(skb, EVENT_FRAG_LIST_CLEAR, (__u64)frag_list, 0, "skb_segment_list");
    return 0;
}

/* Monitor skb_segment - GSO segmentation */
SEC("kprobe/skb_segment")
int BPF_KPROBE(kprobe_skb_segment, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    void *shinfo = get_shinfo(skb);
    if (!shinfo)
        return 0;

    struct sk_buff *frag_list = NULL;
    __u16 gso_size = 0;

    bpf_probe_read_kernel(&frag_list, sizeof(frag_list), shinfo + 8);
    bpf_probe_read_kernel(&gso_size, sizeof(gso_size), shinfo + 4);

    /* Detect inconsistent state */
    if (!frag_list && gso_size > 0) {
        submit_event(skb, EVENT_GSO_INCONSISTENT, 0, 0, "skb_segment");
    } else {
        submit_event(skb, EVENT_FRAG_LIST_ACCESS, (__u64)frag_list, (__u64)frag_list, "skb_segment");
    }

    return 0;
}

/* Monitor __skb_linearize - linearization */
SEC("kprobe/__skb_linearize")
int BPF_KPROBE(kprobe_skb_linearize, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    void *shinfo = get_shinfo(skb);
    struct sk_buff *frag_list = NULL;
    if (shinfo)
        bpf_probe_read_kernel(&frag_list, sizeof(frag_list), shinfo + 8);

    if (frag_list)
        submit_event(skb, EVENT_FRAG_LIST_CLEAR, (__u64)frag_list, 0, "__skb_linearize");

    return 0;
}
