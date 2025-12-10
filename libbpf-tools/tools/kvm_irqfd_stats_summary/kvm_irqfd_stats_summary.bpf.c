// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Network Troubleshooting Tools Authors
// kvm_irqfd_stats_summary - VM interrupt statistics histogram BPF program

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kvm_irqfd_stats_summary.h"

char LICENSE[] SEC("license") = "GPL";

/* Configuration - set from userspace before load */
const volatile __u32 targ_qemu_pid = 0;
const volatile __u32 targ_vhost_pid = 0;
const volatile __u8 targ_filter_category = FILTER_ALL;
const volatile __u8 targ_filter_subcategory = SUBCAT_ALL;

/* IRQ count histogram - keyed by hist_key */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct hist_key);
    __type(value, __u64);
} irq_count_hist SEC(".maps");

/* IRQFD info map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);  /* irqfd_ptr */
    __type(value, struct irqfd_info);
} irqfd_info_map SEC(".maps");

/* Active KVM+GSI tracking from irqfd_wakeup */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct kvm_gsi_key);
    __type(value, __u8);
} active_kvm_gsi SEC(".maps");

/* Active KVM pointers for vgic_queue_irq_unlock filtering */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);  /* kvm_ptr */
    __type(value, __u8);
} active_kvm_ptrs SEC(".maps");

/* Arch set IRQ histogram */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct arch_set_irq_hist_key);
    __type(value, __u64);
} arch_set_irq_hist SEC(".maps");

/* KVM set MSI histogram */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct kvm_set_msi_hist_key);
    __type(value, __u64);
} kvm_set_msi_hist SEC(".maps");

/* KVM VCPU kick histogram */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct kvm_vcpu_kick_hist_key);
    __type(value, __u64);
} kvm_vcpu_kick_hist SEC(".maps");

/* Arch set IRQ return stats */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct arch_set_irq_ret_key);
    __type(value, struct arch_set_irq_ret_val);
} arch_set_irq_ret_stats SEC(".maps");

/* Thread-local storage for return probe */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  /* tid */
    __type(value, struct arch_set_irq_ret_key);
} arch_set_irq_args SEC(".maps");

/* Helper: check if process matches vhost-<qemu_pid> pattern */
static __always_inline bool is_vhost_thread(char *comm, __u32 qemu_pid)
{
    __u32 extracted_pid = 0;
    int i;

    /* Check prefix "vhost-" */
    if (comm[0] != 'v' || comm[1] != 'h' || comm[2] != 'o' ||
        comm[3] != 's' || comm[4] != 't' || comm[5] != '-')
        return false;

    /* Parse digits after "vhost-" */
    #pragma unroll
    for (i = 0; i < 8; i++) {
        char c = comm[6 + i];
        if (c >= '0' && c <= '9')
            extracted_pid = extracted_pid * 10 + (c - '0');
        else
            break;
    }

    return extracted_pid == qemu_pid;
}

/* Helper: increment histogram counter */
static __always_inline void hist_increment(void *map, void *key)
{
    __u64 *count = bpf_map_lookup_elem(map, key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(map, key, &one, BPF_ANY);
    }
}

/* Trace: irqfd_wakeup */
SEC("kprobe/irqfd_wakeup")
int BPF_KPROBE(kprobe_irqfd_wakeup, wait_queue_entry_t *wait, unsigned mode,
               int sync, void *key)
{
    struct kvm *kvm = NULL;
    struct eventfd_ctx *eventfd = NULL;
    int gsi = 0;
    __u64 flags;
    __u32 pid;
    char comm[TASK_COMM_LEN] = {};
    bool is_vhost;

    if (!wait)
        return 0;

    flags = (__u64)key;
    if (!(flags & 0x1))
        return 0;

    /* Get irqfd from wait queue entry using container_of logic */
    /* struct kvm_kernel_irqfd has wait at known offset */
    void *irqfd = (void *)((char *)wait - 16);  /* Approximate offset */

    /* Read fields using CO-RE */
    if (bpf_probe_read_kernel(&kvm, sizeof(kvm), irqfd) < 0)
        return 0;
    if (bpf_probe_read_kernel(&eventfd, sizeof(eventfd), irqfd + 64) < 0)
        return 0;
    if (bpf_probe_read_kernel(&gsi, sizeof(gsi), irqfd + 56) < 0)
        return 0;

    if (!kvm || !eventfd || (__u64)kvm < 0xffff000000000000ULL ||
        (__u64)eventfd < 0xffff000000000000ULL)
        return 0;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Apply filtering */
    is_vhost = is_vhost_thread(comm, targ_qemu_pid);

    if (targ_filter_category == FILTER_ALL) {
        if (pid != targ_qemu_pid && !is_vhost)
            return 0;
    } else if (targ_filter_category == FILTER_DATA) {
        if (!is_vhost)
            return 0;
        if (targ_vhost_pid != 0 && pid != targ_vhost_pid)
            return 0;
    } else if (targ_filter_category == FILTER_CONTROL) {
        if (pid != targ_qemu_pid)
            return 0;
    }

    /* Record to histogram */
    struct hist_key hist_key = {};
    hist_key.kvm_ptr = (__u64)kvm;
    hist_key.irqfd_ptr = (__u64)irqfd;
    hist_key.gsi = (__u32)gsi;
    hist_key.cpu_id = bpf_get_smp_processor_id();
    hist_key.pid = pid;
    __builtin_memcpy(hist_key.comm, comm, TASK_COMM_LEN);
    hist_key.wait_ptr = (__u64)wait;
    hist_key.mode = mode;
    hist_key.sync = sync;
    hist_key.key_flags = flags;
    hist_key.slot = 0;

    hist_increment(&irq_count_hist, &hist_key);

    /* Update IRQFD info */
    __u64 irqfd_key = (__u64)irqfd;
    struct irqfd_info *info = bpf_map_lookup_elem(&irqfd_info_map, &irqfd_key);
    if (!info) {
        struct irqfd_info new_info = {};
        new_info.gsi = (__u32)gsi;
        new_info.eventfd_ctx = (__u64)eventfd;
        new_info.first_timestamp = bpf_ktime_get_ns();
        new_info.last_timestamp = new_info.first_timestamp;
        bpf_map_update_elem(&irqfd_info_map, &irqfd_key, &new_info, BPF_ANY);
    } else {
        info->last_timestamp = bpf_ktime_get_ns();
    }

    /* Track this KVM+GSI combination */
    struct kvm_gsi_key kvm_gsi_key = {};
    kvm_gsi_key.kvm_ptr = (__u64)kvm;
    kvm_gsi_key.gsi = (__u32)gsi;
    __u8 active = 1;
    bpf_map_update_elem(&active_kvm_gsi, &kvm_gsi_key, &active, BPF_ANY);

    /* Track KVM pointer */
    __u64 kvm_ptr_key = (__u64)kvm;
    bpf_map_update_elem(&active_kvm_ptrs, &kvm_ptr_key, &active, BPF_ANY);

    return 0;
}

/* Trace: kvm_arch_set_irq_inatomic */
SEC("kprobe/kvm_arch_set_irq_inatomic")
int BPF_KPROBE(kprobe_kvm_arch_set_irq_inatomic, void *e, struct kvm *kvm)
{
    __u32 gsi = 0;
    __u8 *is_active;
    struct kvm_gsi_key filter_key = {};
    struct arch_set_irq_hist_key hist_key = {};
    struct arch_set_irq_ret_key ret_key = {};
    __u64 tid;

    if (!e || !kvm || (__u64)kvm < 0xffff000000000000ULL)
        return 0;

    bpf_probe_read_kernel(&gsi, sizeof(gsi), e);

    /* Apply filtering based on active_kvm_gsi from irqfd_wakeup */
    filter_key.kvm_ptr = (__u64)kvm;
    filter_key.gsi = gsi;

    is_active = bpf_map_lookup_elem(&active_kvm_gsi, &filter_key);
    if (!is_active)
        return 0;

    /* Record to histogram */
    hist_key.kvm_ptr = (__u64)kvm;
    hist_key.gsi = gsi;
    hist_key.slot = 0;
    hist_increment(&arch_set_irq_hist, &hist_key);

    /* Store for return probe */
    ret_key.kvm_ptr = (__u64)kvm;
    ret_key.gsi = gsi;
    tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&arch_set_irq_args, &tid, &ret_key, BPF_ANY);

    return 0;
}

/* Trace: kvm_arch_set_irq_inatomic return */
SEC("kretprobe/kvm_arch_set_irq_inatomic")
int BPF_KRETPROBE(kretprobe_kvm_arch_set_irq_inatomic, int ret)
{
    __u64 tid = bpf_get_current_pid_tgid();
    struct arch_set_irq_ret_key *key_ptr;
    struct arch_set_irq_ret_key key;
    struct arch_set_irq_ret_val *val;

    key_ptr = bpf_map_lookup_elem(&arch_set_irq_args, &tid);
    if (!key_ptr)
        return 0;

    key = *key_ptr;
    bpf_map_delete_elem(&arch_set_irq_args, &tid);

    val = bpf_map_lookup_elem(&arch_set_irq_ret_stats, &key);
    if (!val) {
        struct arch_set_irq_ret_val new_val = {};
        new_val.total_calls = 1;
        if (ret > 0) {
            new_val.success_count = 1;
            new_val.total_delivered = ret;
        } else {
            new_val.fail_count = 1;
        }
        bpf_map_update_elem(&arch_set_irq_ret_stats, &key, &new_val, BPF_ANY);
    } else {
        __sync_fetch_and_add(&val->total_calls, 1);
        if (ret > 0) {
            __sync_fetch_and_add(&val->success_count, 1);
            __sync_fetch_and_add(&val->total_delivered, ret);
        } else {
            __sync_fetch_and_add(&val->fail_count, 1);
        }
    }

    return 0;
}

/* Trace: kvm_set_msi */
SEC("kprobe/kvm_set_msi")
int BPF_KPROBE(kprobe_kvm_set_msi, void *e, struct kvm *kvm)
{
    __u32 gsi = 0;
    __u8 *is_active;
    struct kvm_gsi_key filter_key = {};
    struct kvm_set_msi_hist_key hist_key = {};

    if (!e || !kvm || (__u64)kvm < 0xffff000000000000ULL)
        return 0;

    bpf_probe_read_kernel(&gsi, sizeof(gsi), e);

    /* Apply filtering */
    filter_key.kvm_ptr = (__u64)kvm;
    filter_key.gsi = gsi;

    is_active = bpf_map_lookup_elem(&active_kvm_gsi, &filter_key);
    if (!is_active)
        return 0;

    /* Record to histogram */
    hist_key.kvm_ptr = (__u64)kvm;
    hist_key.gsi = gsi;
    hist_key.slot = 0;
    hist_increment(&kvm_set_msi_hist, &hist_key);

    return 0;
}

/* Trace: kvm_vcpu_kick */
SEC("kprobe/kvm_vcpu_kick")
int BPF_KPROBE(kprobe_kvm_vcpu_kick, struct kvm_vcpu *vcpu)
{
    struct kvm *kvm = NULL;
    __u32 vcpu_id = 0;
    __u8 *is_active;
    __u64 kvm_ptr_key;
    struct kvm_vcpu_kick_hist_key hist_key = {};

    if (!vcpu || (__u64)vcpu < 0xffff000000000000ULL)
        return 0;

    kvm = BPF_CORE_READ(vcpu, kvm);
    if (!kvm || (__u64)kvm < 0xffff000000000000ULL)
        return 0;

    vcpu_id = BPF_CORE_READ(vcpu, vcpu_id);

    /* Apply filtering based on active KVM pointers */
    kvm_ptr_key = (__u64)kvm;
    is_active = bpf_map_lookup_elem(&active_kvm_ptrs, &kvm_ptr_key);
    if (!is_active)
        return 0;

    /* Record to histogram */
    hist_key.kvm_ptr = (__u64)kvm;
    hist_key.vcpu_id = vcpu_id;
    hist_key.slot = 0;
    hist_increment(&kvm_vcpu_kick_hist, &hist_key);

    return 0;
}
