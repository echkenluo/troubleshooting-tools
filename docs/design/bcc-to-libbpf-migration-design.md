# BCC to libbpf Migration Design Document

## Software Design Description (SDD) - IEEE 1016 Compliant

**Document Version**: 1.0
**Date**: 2025-12-10
**Status**: Draft

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Overview](#2-system-overview)
3. [Architecture Design (HLD)](#3-architecture-design-hld)
4. [Detailed Design (LLD)](#4-detailed-design-lld)
5. [Data Design](#5-data-design)
6. [Performance Analysis](#6-performance-analysis)
7. [Migration Strategy](#7-migration-strategy)
8. [Build System Design](#8-build-system-design)
9. [Testing Strategy](#9-testing-strategy)
10. [References](#10-references)

---

## 1. Introduction

### 1.1 Purpose

This document provides a comprehensive design specification for migrating the existing BCC-based eBPF measurement tools to libbpf-based implementations. The migration aims to leverage BPF CO-RE (Compile Once - Run Everywhere) capabilities for improved deployment efficiency and reduced runtime overhead.

### 1.2 Scope

**In Scope:**
- Migration of 50 BCC Python tools to libbpf C implementations
- Design of common library components for histogram, tracing, and output formatting
- Userspace application architecture using C
- Build system and toolchain design

**Out of Scope:**
- Migration of 19 bpftrace scripts (independent runtime, no migration needed)
- Migration of 5 shell wrapper scripts (will be updated to invoke new binaries)

### 1.3 Definitions and Acronyms

| Term | Definition |
|------|------------|
| BCC | BPF Compiler Collection - Python-based eBPF development framework |
| libbpf | Kernel-maintained library for loading and interacting with BPF programs |
| CO-RE | Compile Once - Run Everywhere - BTF-based portability mechanism |
| BTF | BPF Type Format - Debug information for BPF programs |
| Skeleton | Auto-generated C code for loading and interacting with BPF programs |

### 1.4 Target Environment

| Kernel | Version | BTF Support | Status |
|--------|---------|-------------|--------|
| openEuler | 5.10.0-247.0.0 | CONFIG_DEBUG_INFO_BTF=y | Verified |
| TencentOS | 5.4.119-19.0009.54 | /sys/kernel/btf/vmlinux exists | Verified |

### 1.5 References

- [BCC to libbpf conversion guide (Andrii Nakryiko)](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/)
- [libbpf-tools reference implementations](https://github.com/iovisor/bcc/tree/master/libbpf-tools)
- [PingCAP: Why We Switched from BCC to libbpf](https://www.pingcap.com/blog/why-we-switched-from-bcc-to-libbpf-for-linux-bpf-performance-analysis/)
- [Brendan Gregg: BPF CO-RE, BTF](https://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html)

---

## 2. System Overview

### 2.1 Current System (BCC-based)

```
┌─────────────────────────────────────────────────────────────────┐
│                    BCC Tool Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  Python CLI  │    │  BPF C Code  │    │   Runtime    │       │
│  │  (argparse)  │ -> │ (embedded in │ -> │  Compilation │       │
│  │              │    │   Python)    │    │ (LLVM/Clang) │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                 │                │
│                                                 v                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Output     │ <- │  BPF Maps    │ <- │   Kernel     │       │
│  │  Formatting  │    │  (via BCC)   │    │  BPF Program │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
└─────────────────────────────────────────────────────────────────┘

Dependencies:
- python-bcc / python3-bpfcc
- kernel-headers
- LLVM/Clang (embedded)
- ~80 MB memory per tool
```

### 2.2 Target System (libbpf-based)

```
┌─────────────────────────────────────────────────────────────────┐
│                   libbpf Tool Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   C CLI      │    │  BPF Object  │    │   libbpf     │       │
│  │  (getopt)    │ -> │   (.bpf.o)   │ -> │   Loader     │       │
│  │              │    │ (precompiled)│    │              │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                             │                   │                │
│                             v                   v                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Output     │ <- │  Skeleton    │ <- │   Kernel     │       │
│  │  Formatting  │    │  Generated   │    │  BPF Program │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
└─────────────────────────────────────────────────────────────────┘

Dependencies:
- libbpf.so (runtime)
- BTF in kernel (/sys/kernel/btf/vmlinux)
- ~9 MB memory per tool
```

### 2.3 Tool Inventory Summary

| Category | Tool Count | Histogram Usage | Complexity |
|----------|------------|-----------------|------------|
| Linux Network Stack | 6 | 4 | Medium-Complex |
| OVS Monitoring | 3 | 2 | Medium-Complex |
| System Network Perf | 15 | 12 | Medium-Very Complex |
| VM Network Perf | 11 | 8 | Medium-Complex |
| KVM Virtualization | 8 | 6 | Complex-Very Complex |
| CPU Scheduling | 1 | 1 | Complex |
| **Total** | **50** | **33** | - |

### 2.4 Design Constraints

1. **Kernel BPF Logic Preservation**: BPF program logic must remain functionally identical to BCC versions
2. **Interface Compatibility**: Command-line interface and output format should be consistent
3. **Performance**: Must not exceed BCC overhead; target 9x memory reduction
4. **BTF Dependency**: Target kernels must have BTF support enabled

### 2.5 Assumptions and Dependencies

- Target kernels are openEuler 5.10+ or TencentOS 5.4+ with BTF enabled
- Build environment has Clang 10+ and pahole 1.16+
- libbpf library (>=0.8) available on target systems

---

## 3. Architecture Design (HLD)

### 3.1 Architectural Style

The migrated toolset follows a **layered architecture** with clear separation between:
- BPF kernel programs (data plane)
- Userspace application logic (control plane)
- Common utilities library (shared infrastructure)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Tool Binary Layer                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │ eth_drop    │ │ icmp_rtt    │ │vm_latency   │ │ kvm_irqfd   │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                      Common Library Layer                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │trace_helpers│ │  histogram  │ │   network   │ │   output    │   │
│  │    .c/.h    │ │    .c/.h    │ │  helpers.h  │ │  format.c   │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                    BPF Common Headers Layer                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │  bits.bpf.h │ │ maps.bpf.h  │ │ core_fixes  │ │vmlinux_local│   │
│  │  (log2)     │ │ (map macros)│ │   .bpf.h    │ │    .h       │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                      External Dependencies                           │
│  ┌─────────────────────────────┐ ┌─────────────────────────────┐   │
│  │         libbpf              │ │      vmlinux.h (BTF)        │   │
│  └─────────────────────────────┘ └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Per-Tool Components                        │
│                                                                      │
│   ┌────────────────────┐        ┌────────────────────┐              │
│   │   <tool>.bpf.c     │        │   <tool>.c         │              │
│   │ ─────────────────  │        │ ─────────────────  │              │
│   │ - BPF programs     │        │ - main()           │              │
│   │ - Map definitions  │        │ - Argument parsing │              │
│   │ - Helper functions │        │ - Skeleton loading │              │
│   │ - CO-RE macros     │ ──────>│ - Map reading      │              │
│   └────────────────────┘        │ - Output formatting│              │
│            │                    └────────────────────┘              │
│            │ bpftool gen skeleton                                   │
│            v                                                        │
│   ┌────────────────────┐                                            │
│   │  <tool>.skel.h     │                                            │
│   │ ─────────────────  │                                            │
│   │ - Auto-generated   │                                            │
│   │ - Type definitions │                                            │
│   │ - Load/Attach APIs │                                            │
│   └────────────────────┘                                            │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                         Shared Header Files                          │
│                                                                      │
│   ┌────────────────────┐        ┌────────────────────┐              │
│   │   <tool>.h         │        │   common headers   │              │
│   │ ─────────────────  │        │ ─────────────────  │              │
│   │ - Shared structs   │        │ - bits.bpf.h       │              │
│   │   (BPF <-> User)   │        │ - maps.bpf.h       │              │
│   │ - Constants        │        │ - trace_helpers.h  │              │
│   │ - Enums            │        │ - histogram.h      │              │
│   └────────────────────┘        └────────────────────┘              │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.3 Component Descriptions

#### 3.3.1 BPF Program Component (`<tool>.bpf.c`)

**Responsibility**: Kernel-side data collection and aggregation

**Key Elements**:
- SEC() macro for program attachment
- BPF_KPROBE/BPF_KRETPROBE macros for kprobe programs
- BPF_CORE_READ() for CO-RE compatible field access
- Map definitions using BTF-style declarations

**Design Decision DD-ARCH-001**: BPF Program Structure
- **Background**: BCC allows inline BPF code in Python; libbpf requires separate .bpf.c files
- **Decision**: Each tool has a dedicated `.bpf.c` file with self-contained BPF logic
- **Rationale**: Clean separation, easier debugging, standard libbpf pattern

#### 3.3.2 Skeleton Component (`<tool>.skel.h`)

**Responsibility**: Auto-generated interface between userspace and BPF

**Generation**: `bpftool gen skeleton <tool>.bpf.o > <tool>.skel.h`

**Provides**:
- `<tool>_bpf__open()` - Open BPF object
- `<tool>_bpf__load()` - Load BPF programs
- `<tool>_bpf__attach()` - Attach to hooks
- `<tool>_bpf__destroy()` - Cleanup
- Type-safe map access via `skel->maps.<mapname>`
- Read-only data access via `skel->rodata`

#### 3.3.3 Userspace Application Component (`<tool>.c`)

**Responsibility**: CLI interface, BPF lifecycle management, output formatting

**Structure**:
```c
int main(int argc, char **argv) {
    // 1. Parse arguments
    // 2. Bump memlock rlimit
    // 3. Open BPF object
    // 4. Set global variables (filters)
    // 5. Load and attach BPF programs
    // 6. Main loop: read maps, format output
    // 7. Cleanup
}
```

#### 3.3.4 Common Library Components

| Component | File | Purpose |
|-----------|------|---------|
| Trace Helpers | trace_helpers.c/h | Probe attachment, symbol resolution |
| Histogram | histogram.c/h | Log2 histogram printing, linear histogram |
| Network Helpers | network_helpers.h | IP formatting, interface lookup |
| Output Format | output_format.c/h | Consistent output formatting |
| Bits BPF | bits.bpf.h | log2/log2l functions for BPF |
| Maps BPF | maps.bpf.h | Common map definition macros |

### 3.4 Interface Design

#### 3.4.1 BPF-Userspace Interface (Shared Header Pattern)

```
┌────────────────────────────────────────────────────┐
│                  <tool>.h                           │
├────────────────────────────────────────────────────┤
│  // Shared between BPF and userspace               │
│                                                    │
│  #define MAX_SLOTS 26                              │
│  #define TASK_COMM_LEN 16                          │
│                                                    │
│  struct hist {                                     │
│      __u32 slots[MAX_SLOTS];                       │
│      char comm[TASK_COMM_LEN];                     │
│  };                                                │
│                                                    │
│  struct packet_key {                               │
│      __be32 src_ip;                                │
│      __be32 dst_ip;                                │
│      __u8 protocol;                                │
│      // ...                                        │
│  };                                                │
└────────────────────────────────────────────────────┘
```

#### 3.4.2 Command-Line Interface Compatibility

Maintain BCC CLI compatibility:
```bash
# BCC version
sudo python system_network_latency_summary.py --phy-interface eth0 --src-ip 10.0.0.1 --direction tx

# libbpf version (same interface)
sudo ./system_network_latency_summary --phy-interface eth0 --src-ip 10.0.0.1 --direction tx
```

---

## 4. Detailed Design (LLD)

### 4.1 BPF_HISTOGRAM Migration Design

**Design Decision DD-DATA-001**: Histogram Implementation Strategy

- **Background**: BCC provides `BPF_HISTOGRAM` macro with automatic log2 bucketing; libbpf has no equivalent
- **Considered Options**:
  - Option A: BPF_MAP_TYPE_ARRAY with fixed slots
  - Option B: BPF_MAP_TYPE_HASH with bucket keys
  - Option C: BPF_MAP_TYPE_PERCPU_ARRAY for lock-free updates
- **Decision**: Option C (PERCPU_ARRAY) for simple histograms, Option A for keyed histograms
- **Rationale**: PERCPU avoids atomic operations, better performance; ARRAY for keyed histograms allows complex keys

#### 4.1.1 Simple Histogram (Single Distribution)

**BCC Original**:
```c
BPF_HISTOGRAM(latency_hist, u8, 256);
// Usage:
latency_hist.increment(bpf_log2l(delta_us));
```

**libbpf Migration**:

```c
// <tool>.h - Shared header
#define MAX_SLOTS 26

struct hist {
    __u32 slots[MAX_SLOTS];
};

// <tool>.bpf.c - BPF program
#include "bits.bpf.h"  // for log2l()

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct hist);
} latency_hist SEC(".maps");

static __always_inline void update_hist(struct hist *hist, __u64 value) {
    __u64 slot = log2l(value);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&hist->slots[slot], 1);
}

// In BPF program:
__u32 key = 0;
struct hist *hist = bpf_map_lookup_elem(&latency_hist, &key);
if (hist)
    update_hist(hist, delta_us);
```

**Userspace Reading (PERCPU)**:
```c
// <tool>.c - Userspace
void print_hist(struct <tool>_bpf *skel) {
    __u32 key = 0;
    int ncpus = libbpf_num_possible_cpus();
    struct hist values[ncpus];
    struct hist total = {};

    // Read per-CPU values
    int err = bpf_map_lookup_elem(
        bpf_map__fd(skel->maps.latency_hist), &key, values);
    if (err < 0)
        return;

    // Aggregate across CPUs
    for (int cpu = 0; cpu < ncpus; cpu++) {
        for (int slot = 0; slot < MAX_SLOTS; slot++) {
            total.slots[slot] += values[cpu].slots[slot];
        }
    }

    // Print histogram
    print_log2_hist(total.slots, MAX_SLOTS, "usecs");
}
```

#### 4.1.2 Keyed Histogram (Multi-dimensional)

**BCC Original**:
```c
struct stage_pair_key_t {
    u8 prev_stage;
    u8 curr_stage;
    u8 direction;
    u8 latency_bucket;
};
BPF_HISTOGRAM(adjacent_latency_hist, struct stage_pair_key_t, 1024);
// Usage:
adjacent_latency_hist.increment(pair_key, 1);
```

**libbpf Migration**:
```c
// <tool>.h
struct stage_pair_key {
    __u8 prev_stage;
    __u8 curr_stage;
    __u8 direction;
    __u8 pad;
};

#define MAX_STAGE_PAIRS 64
#define MAX_BUCKETS 26

struct keyed_hist {
    __u64 slots[MAX_BUCKETS];
};

// <tool>.bpf.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_STAGE_PAIRS);
    __type(key, struct stage_pair_key);
    __type(value, struct keyed_hist);
} adjacent_latency_hist SEC(".maps");

static __always_inline void update_keyed_hist(
    struct stage_pair_key *key, __u64 latency_us)
{
    struct keyed_hist *hist = bpf_map_lookup_elem(&adjacent_latency_hist, key);
    if (!hist) {
        struct keyed_hist zero = {};
        bpf_map_update_elem(&adjacent_latency_hist, key, &zero, BPF_NOEXIST);
        hist = bpf_map_lookup_elem(&adjacent_latency_hist, key);
        if (!hist)
            return;
    }

    __u64 slot = log2l(latency_us + 1);
    if (slot >= MAX_BUCKETS)
        slot = MAX_BUCKETS - 1;
    __sync_fetch_and_add(&hist->slots[slot], 1);
}
```

#### 4.1.3 Log2 Implementation (`bits.bpf.h`)

```c
// bits.bpf.h - From libbpf-tools

#ifndef __BITS_BPF_H
#define __BITS_BPF_H

static __always_inline __u64 log2(__u32 v)
{
    __u32 shift, r;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);

    return r;
}

static __always_inline __u64 log2l(__u64 v)
{
    __u32 hi = v >> 32;

    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

#endif /* __BITS_BPF_H */
```

### 4.2 Kprobe Migration Design

#### 4.2.1 Simple Kprobe

**BCC Original**:
```c
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t size) {
    // ...
}
```

**libbpf Migration**:
```c
// <tool>.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk,
               struct msghdr *msg, size_t size)
{
    // Direct argument access via BPF_KPROBE macro
    __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    // ...
    return 0;
}
```

#### 4.2.2 Kretprobe with Return Value

**BCC Original**:
```c
int kretprobe__kvm_arch_set_irq_inatomic(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    // ...
}
```

**libbpf Migration**:
```c
SEC("kretprobe/kvm_arch_set_irq_inatomic")
int BPF_KRETPROBE(kretprobe_kvm_irq, int ret)
{
    // ret is automatically extracted
    if (ret < 0) {
        // handle error
    }
    return 0;
}
```

#### 4.2.3 Entry/Return Correlation Pattern

**BCC Original**:
```c
BPF_HASH(entry_args, u32, struct entry_t);

int kprobe__func(struct pt_regs *ctx, struct foo *arg) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t entry = { .arg = arg, .ts = bpf_ktime_get_ns() };
    entry_args.update(&tid, &entry);
    return 0;
}

int kretprobe__func(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct entry_t *entry = entry_args.lookup(&tid);
    if (!entry) return 0;

    u64 delta = bpf_ktime_get_ns() - entry->ts;
    entry_args.delete(&tid);
    // process delta
    return 0;
}
```

**libbpf Migration**:
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct entry_t);
} entry_args SEC(".maps");

SEC("kprobe/func")
int BPF_KPROBE(kprobe_func, struct foo *arg)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct entry_t entry = {
        .arg = arg,
        .ts = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(&entry_args, &tid, &entry, BPF_ANY);
    return 0;
}

SEC("kretprobe/func")
int BPF_KRETPROBE(kretprobe_func, int ret)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct entry_t *entry = bpf_map_lookup_elem(&entry_args, &tid);
    if (!entry)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - entry->ts;
    bpf_map_delete_elem(&entry_args, &tid);
    // process delta
    return 0;
}
```

### 4.3 Tracepoint Migration Design

**BCC Original**:
```c
TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    // ...
}
```

**libbpf Migration**:
```c
// Use raw tracepoint for 5.4+ kernels
SEC("tp/net/netif_receive_skb")
int handle_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    void *skbaddr = ctx->skbaddr;
    struct sk_buff *skb = (struct sk_buff *)skbaddr;
    // ...
    return 0;
}
```

### 4.4 Memory Read Migration Design

**Design Decision DD-TECH-001**: CO-RE Memory Access

- **Background**: BCC rewrites field accesses to bpf_probe_read(); libbpf requires explicit CO-RE macros
- **Decision**: Use BPF_CORE_READ() for all kernel structure access
- **Rationale**: CO-RE provides kernel version independence and compiler verification

**BCC Original**:
```c
// BCC magically rewrites this:
u32 pid = tsk->parent->pid;
struct iphdr *ip = &skb->network_header;
```

**libbpf Migration**:
```c
// Explicit CO-RE reads:
__u32 pid = BPF_CORE_READ(tsk, parent, pid);

// For complex reads:
struct iphdr ip;
unsigned char *head = BPF_CORE_READ(skb, head);
__u16 network_header = BPF_CORE_READ(skb, network_header);
bpf_core_read(&ip, sizeof(ip), head + network_header);
```

### 4.5 Global Variables / Configuration Design

**BCC Original**:
```c
// In BPF code with Python substitution:
#define SRC_IP_FILTER 0x%x
#define DIRECTION_FILTER %d

// Python:
bpf_text = bpf_text % (src_ip_hex, direction_filter)
```

**libbpf Migration**:
```c
// <tool>.bpf.c
const volatile __u32 targ_src_ip = 0;
const volatile __u32 targ_dst_ip = 0;
const volatile __u8 targ_direction = 0;
const volatile __u8 targ_protocol = 0;

SEC("kprobe/...")
int BPF_KPROBE(...)
{
    // Use globals directly
    if (targ_src_ip && saddr != targ_src_ip)
        return 0;
    // ...
}
```

```c
// <tool>.c - Userspace
int main(int argc, char **argv)
{
    struct <tool>_bpf *skel;

    skel = <tool>_bpf__open();
    if (!skel)
        return 1;

    // Set before load
    skel->rodata->targ_src_ip = args.src_ip;
    skel->rodata->targ_dst_ip = args.dst_ip;
    skel->rodata->targ_direction = args.direction;

    err = <tool>_bpf__load(skel);
    // ...
}
```

### 4.6 Userspace Application Design

#### 4.6.1 Standard Main Function Template

```c
// <tool>.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "<tool>.h"
#include "<tool>.skel.h"
#include "trace_helpers.h"
#include "histogram.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    struct <tool>_bpf *skel = NULL;
    int err;

    // Parse arguments
    struct args args = {};
    err = parse_args(argc, argv, &args);
    if (err)
        return err;

    // Setup libbpf
    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    // Open BPF application
    skel = <tool>_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Set global variables (filters)
    skel->rodata->targ_src_ip = args.src_ip;
    skel->rodata->targ_dst_ip = args.dst_ip;
    skel->rodata->targ_direction = args.direction;

    // Load & verify BPF programs
    err = <tool>_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach BPF programs
    err = <tool>_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Tracing... Hit Ctrl-C to end.\n");

    // Main loop
    while (!exiting) {
        sleep(args.interval);
        print_stats(skel);
    }

    // Final output
    print_stats(skel);

cleanup:
    <tool>_bpf__destroy(skel);
    return err != 0;
}
```

#### 4.6.2 Histogram Printing Functions

```c
// histogram.h
#ifndef __HISTOGRAM_H
#define __HISTOGRAM_H

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type);
void print_linear_hist(unsigned int *vals, int vals_size,
                       unsigned int base, unsigned int step,
                       const char *val_type);

#endif

// histogram.c
#include <stdio.h>
#include "histogram.h"

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
    int num_stars = val_max > 0 ? (val * width / val_max) : 0;
    for (int i = 0; i < num_stars; i++)
        printf("*");
}

void print_log2_hist(unsigned int *vals, int vals_size, const char *val_type)
{
    int stars_max = 40;
    int idx_max = -1;
    unsigned int val_max = 0;

    // Find max index and value
    for (int i = 0; i < vals_size; i++) {
        if (vals[i] > 0)
            idx_max = i;
        if (vals[i] > val_max)
            val_max = vals[i];
    }

    if (idx_max < 0)
        return;

    printf("%*s%-*s : count    distribution\n",
           idx_max <= 32 ? 5 : 15, "",
           idx_max <= 32 ? 19 : 29, val_type);

    // Print histogram
    for (int i = 0; i <= idx_max; i++) {
        unsigned long long low = (1ULL << (i + 1)) >> 1;
        unsigned long long high = (1ULL << (i + 1)) - 1;
        if (low == high)
            low -= 1;

        int width = idx_max <= 32 ? 10 : 20;
        printf("%*lld -> %-*lld : %-8d |", width, low, width, high, vals[i]);
        print_stars(vals[i], val_max, stars_max);
        printf("|\n");
    }
}
```

---

## 5. Data Design

### 5.1 Map Type Mapping

| BCC Map Type | libbpf Map Type | Notes |
|--------------|-----------------|-------|
| `BPF_HASH` | `BPF_MAP_TYPE_HASH` | Direct mapping |
| `BPF_TABLE("lru_hash")` | `BPF_MAP_TYPE_LRU_HASH` | Direct mapping |
| `BPF_ARRAY` | `BPF_MAP_TYPE_ARRAY` | Direct mapping |
| `BPF_PERCPU_ARRAY` | `BPF_MAP_TYPE_PERCPU_ARRAY` | Direct mapping |
| `BPF_HISTOGRAM` | Custom (see 4.1) | Requires redesign |
| `BPF_PERF_OUTPUT` | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` or Ring Buffer | Ring buffer preferred for 5.8+ |
| `BPF_STACK_TRACE` | `BPF_MAP_TYPE_STACK_TRACE` | Direct mapping |

### 5.2 Common Data Structures

```c
// common_types.h - Shared across tools

#ifndef __COMMON_TYPES_H
#define __COMMON_TYPES_H

// Network packet identification
struct packet_key {
    __be32 src_ip;
    __be32 dst_ip;
    __u8 protocol;
    __u8 pad[3];
    union {
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be32 seq;
        } tcp;
        struct {
            __be16 src_port;
            __be16 dst_port;
            __be16 ip_id;
            __be16 udp_len;
        } udp;
    };
};

// Flow tracking data
struct flow_data {
    __u64 first_ts;
    __u64 last_ts;
    __u8 direction;
    __u8 last_stage;
    __u8 pad[6];
};

// Histogram bucket sizes
#define HIST_SLOTS_SMALL  16   // For small value ranges
#define HIST_SLOTS_NORMAL 26   // For general latency (ns to seconds)
#define HIST_SLOTS_LARGE  64   // For wide value ranges

// Per-CPU histogram
struct hist {
    __u64 slots[HIST_SLOTS_NORMAL];
};

// Keyed histogram entry
struct keyed_hist_entry {
    __u64 count;
};

#endif /* __COMMON_TYPES_H */
```

### 5.3 Ring Buffer vs Perf Buffer

**Design Decision DD-PERF-001**: Event Output Mechanism

- **Background**: BCC uses `BPF_PERF_OUTPUT`; libbpf offers both perf buffer and ring buffer
- **Decision**: Use Ring Buffer for kernel 5.8+, fall back to perf buffer for 5.4
- **Rationale**: Ring buffer is more efficient (shared memory, no per-CPU overhead)

```c
// For kernel 5.8+ (Ring Buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Usage in BPF:
struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e)
    return 0;
// fill event
bpf_ringbuf_submit(e, 0);

// For kernel 5.4 (Perf Buffer)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Usage in BPF:
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
```

---

## 6. Performance Analysis

### 6.1 BCC vs libbpf Overhead Comparison

| Metric | BCC | libbpf | Improvement |
|--------|-----|--------|-------------|
| Memory footprint | ~80 MB | ~9 MB | **8.9x** |
| Startup time | 2-5 seconds | <100 ms | **20-50x** |
| Binary size | N/A (Python) | 150-500 KB | Standalone |
| Runtime dependencies | LLVM, Clang, headers | libbpf.so only | Simplified |
| First event latency | High (compile) | Low (preloaded) | Significant |

### 6.2 Histogram Performance

#### 6.2.1 PERCPU_ARRAY vs Regular ARRAY

| Operation | PERCPU_ARRAY | Regular ARRAY |
|-----------|--------------|---------------|
| Update (kernel) | No locking | Atomic ops required |
| Read (userspace) | Aggregate N CPUs | Direct read |
| Memory usage | N * size | 1 * size |
| Contention | None | Potential |

**Recommendation**: Use `PERCPU_ARRAY` for high-frequency updates (>10K/sec)

#### 6.2.2 Hash Map vs Array for Keyed Histograms

| Aspect | HASH Map | ARRAY |
|--------|----------|-------|
| Key flexibility | Any struct | Integer index |
| Lookup cost | O(1) average | O(1) |
| Memory | Dynamic | Pre-allocated |
| Max entries | Configurable | Fixed |

**Recommendation**: Use `HASH` for sparse/dynamic keys (stage pairs), `ARRAY` for dense/known keys

### 6.3 Expected Performance Profile

```
Tool Startup:
┌─────────────────────────────────────────────────┐
│ BCC:    [==========] 2-5 seconds                │
│ libbpf: [=] <100ms                              │
└─────────────────────────────────────────────────┘

Memory Usage (typical tool):
┌─────────────────────────────────────────────────┐
│ BCC:    [====================================] 80MB │
│ libbpf: [====] 9MB                                  │
└─────────────────────────────────────────────────┘

Event Processing Overhead:
┌─────────────────────────────────────────────────┐
│ BCC:    Python dict/list operations             │
│ libbpf: Direct C struct access                  │
└─────────────────────────────────────────────────┘
```

---

## 7. Migration Strategy

### 7.1 Migration Phases

```
Phase 1: Infrastructure Setup (Week 1-2)
├── Setup build system (Makefile, CMake)
├── Generate vmlinux.h for target kernels
├── Port common helper libraries
│   ├── bits.bpf.h
│   ├── maps.bpf.h
│   ├── trace_helpers.c/h
│   └── histogram.c/h
└── Create template tool as reference

Phase 2: Simple Tools Migration (Week 3-4)
├── iface_netstat
├── vhost_eventfd_count
├── vhost_queue_correlation_simple
└── Tools with < 100 lines BPF code

Phase 3: Medium Complexity Tools (Week 5-8)
├── system_network_latency_summary
├── vm_network_latency_summary
├── ovs_upcall_latency_summary
├── tcp_perf_observer
└── Tools with histograms and multi-probe

Phase 4: Complex Tools (Week 9-12)
├── eth_drop
├── kernel_icmp_rtt
├── vm_network_latency_details
└── Tools with 4+ probes, stack traces

Phase 5: Very Complex Tools (Week 13-16)
├── kvm_irqfd_stats_summary
├── kvm_irqfd_stats_summary_arm
├── offcputime-ts
└── Tools with kretprobes, complex correlation

Phase 6: Integration & Testing (Week 17-20)
├── Integration testing
├── Performance validation
├── Documentation
└── Deployment packaging
```

### 7.2 Tool Migration Priority

| Priority | Tools | Rationale |
|----------|-------|-----------|
| P0 | system_network_latency_summary, vm_network_latency_summary | Most frequently used |
| P1 | eth_drop, kernel_icmp_rtt | Critical diagnostics |
| P2 | ovs_*, kvm_irqfd_stats_summary | OVS/KVM monitoring |
| P3 | tcp_perf_*, vm_pair_latency* | Performance analysis |
| P4 | Remaining tools | Complete coverage |

### 7.3 Migration Checklist Per Tool

```
[ ] 1. Create <tool>.h with shared structures
[ ] 2. Create <tool>.bpf.c with BPF programs
    [ ] 2.1 Convert map definitions
    [ ] 2.2 Convert probe functions
    [ ] 2.3 Convert memory reads to BPF_CORE_READ
    [ ] 2.4 Replace BPF_HISTOGRAM with custom impl
    [ ] 2.5 Add global volatile variables for filters
[ ] 3. Generate skeleton: bpftool gen skeleton
[ ] 4. Create <tool>.c userspace application
    [ ] 4.1 Argument parsing (compatible with BCC version)
    [ ] 4.2 BPF lifecycle management
    [ ] 4.3 Map reading and aggregation
    [ ] 4.4 Output formatting (match BCC output)
[ ] 5. Add to build system
[ ] 6. Test functional equivalence
[ ] 7. Validate performance
```

---

## 8. Build System Design

### 8.1 Directory Structure

```
libbpf-tools/
├── Makefile                    # Main build file
├── vmlinux/
│   ├── vmlinux_510.h          # BTF for openEuler 5.10
│   └── vmlinux_54.h           # BTF for TencentOS 5.4
├── include/
│   ├── bits.bpf.h
│   ├── maps.bpf.h
│   ├── core_fixes.bpf.h
│   └── compat.bpf.h
├── lib/
│   ├── trace_helpers.c
│   ├── trace_helpers.h
│   ├── histogram.c
│   ├── histogram.h
│   ├── network_helpers.c
│   └── network_helpers.h
├── tools/
│   ├── eth_drop/
│   │   ├── eth_drop.h
│   │   ├── eth_drop.bpf.c
│   │   └── eth_drop.c
│   ├── system_network_latency/
│   │   ├── system_network_latency_summary.h
│   │   ├── system_network_latency_summary.bpf.c
│   │   └── system_network_latency_summary.c
│   └── ...
└── output/                     # Build output
    ├── *.bpf.o
    ├── *.skel.h
    └── * (binaries)
```

### 8.2 Makefile Template

```makefile
# Makefile for libbpf-tools

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

OUTPUT := output
LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(OUTPUT)/libbpf.a

INCLUDES := -I$(OUTPUT) -Iinclude -Ivmlinux
CFLAGS := -g -O2 -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

TOOLS := eth_drop system_network_latency_summary vm_network_latency_summary

.PHONY: all clean $(TOOLS)

all: $(TOOLS)

$(OUTPUT):
	mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(abspath $(OUTPUT))/libbpf \
		DESTDIR=$(abspath $(OUTPUT)) install

# Generate vmlinux.h
vmlinux/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Pattern rule for BPF objects
$(OUTPUT)/%.bpf.o: tools/%/%.bpf.c vmlinux/vmlinux.h | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Pattern rule for skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

# Pattern rule for userspace
$(OUTPUT)/%: tools/%/%.c $(OUTPUT)/%.skel.h $(LIBBPF_OBJ) lib/*.c | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -I$(OUTPUT) $< lib/*.c \
		$(LIBBPF_OBJ) -lelf -lz -o $@

# Tool targets
eth_drop: $(OUTPUT)/eth_drop
system_network_latency_summary: $(OUTPUT)/system_network_latency_summary
vm_network_latency_summary: $(OUTPUT)/vm_network_latency_summary

clean:
	rm -rf $(OUTPUT)
```

### 8.3 Build Dependencies

```bash
# Development machine requirements
clang >= 10.0
llvm >= 10.0
bpftool
libelf-dev
zlib-dev
libbpf-dev (or build from source)

# Target machine requirements
libbpf.so >= 0.8
Kernel with BTF (/sys/kernel/btf/vmlinux)
```

---

## 9. Testing Strategy

### 9.1 Functional Testing

```
Test Category 1: Output Equivalence
├── Run BCC tool with specific parameters
├── Run libbpf tool with same parameters
├── Compare output format and values
└── Verify histogram bucket distributions match

Test Category 2: Filter Validation
├── Test IP filters (src, dst)
├── Test port filters
├── Test protocol filters
├── Test direction filters
└── Test interface filters

Test Category 3: Edge Cases
├── No matching traffic
├── High traffic volume
├── Map overflow conditions
├── Process exit handling
└── Signal handling (SIGINT, SIGTERM)
```

### 9.2 Performance Testing

```
Metric 1: Startup Time
├── Measure time from exec to first event
├── Target: < 100ms (vs 2-5s BCC)

Metric 2: Memory Usage
├── Measure RSS after stabilization
├── Target: < 15MB (vs 80MB BCC)

Metric 3: CPU Overhead
├── Measure CPU usage under load
├── Target: <= BCC overhead

Metric 4: Event Latency
├── Measure time from kernel event to userspace output
├── Target: < 1ms average
```

### 9.3 Test Environment

```yaml
# test_config.yaml
environments:
  openeuler_510:
    host: test-server-1
    kernel: 5.10.0-247.0.0.oe1.v57.x86_64
    btf: /sys/kernel/btf/vmlinux

  tencentos_54:
    host: test-server-2
    kernel: 5.4.119-19.0009.54.tl3.v63.x86_64
    btf: /sys/kernel/btf/vmlinux

test_cases:
  - name: system_network_latency_summary
    params:
      phy_interface: eth0
      src_ip: 10.0.0.1
      direction: tx
      interval: 5
    duration: 60
    validation:
      - histogram_buckets_exist
      - packet_counters_positive
      - output_format_match
```

---

## 10. References

### 10.1 Primary Sources

1. **libbpf-tools Repository**
   - URL: https://github.com/iovisor/bcc/tree/master/libbpf-tools
   - Reference implementations for histogram, trace_helpers

2. **BCC to libbpf Conversion Guide**
   - URL: https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/
   - Author: Andrii Nakryiko (libbpf maintainer)

3. **libbpf Documentation**
   - URL: https://libbpf.readthedocs.io/
   - API reference and examples

### 10.2 Technical References

4. **BPF CO-RE Reference Guide**
   - URL: https://nakryiko.com/posts/bpf-core-reference-guide/
   - CO-RE macros and patterns

5. **Kernel BTF Documentation**
   - URL: https://docs.kernel.org/bpf/btf.html
   - BTF format specification

6. **BPF Map Types**
   - URL: https://docs.kernel.org/bpf/maps.html
   - Map type reference

### 10.3 Performance References

7. **PingCAP Migration Experience**
   - URL: https://www.pingcap.com/blog/why-we-switched-from-bcc-to-libbpf-for-linux-bpf-performance-analysis/
   - Real-world migration case study

8. **Brendan Gregg: BPF CO-RE**
   - URL: https://www.brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html
   - Performance analysis and comparison

---

## Appendix A: Code Templates

### A.1 BPF Program Template

```c
// <tool>.bpf.c template

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Your Organization

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bits.bpf.h"
#include "<tool>.h"

char LICENSE[] SEC("license") = "GPL";

// Global configuration (set from userspace before load)
const volatile __u32 targ_filter1 = 0;
const volatile __u32 targ_filter2 = 0;

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, struct value_t);
} my_map SEC(".maps");

// Helper functions
static __always_inline int process_event(void *ctx, struct some_struct *s)
{
    // Implementation
    return 0;
}

// Probe definitions
SEC("kprobe/target_function")
int BPF_KPROBE(kprobe_target, struct arg1 *a1, int a2)
{
    // Filter check
    if (targ_filter1 && some_condition)
        return 0;

    // Process
    return process_event(ctx, a1);
}
```

### A.2 Userspace Template

```c
// <tool>.c template

// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Your Organization

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "<tool>.h"
#include "<tool>.skel.h"
#include "trace_helpers.h"
#include "histogram.h"

#define PROGRAM_NAME "<tool>"

static struct env {
    __u32 filter1;
    __u32 filter2;
    int interval;
    bool verbose;
} env = {
    .interval = 5,
};

static volatile bool exiting = false;

static const char *argp_program_doc =
    "Tool description.\n"
    "\n"
    "USAGE: " PROGRAM_NAME " [OPTIONS]\n"
    "\n"
    "EXAMPLES:\n"
    "    " PROGRAM_NAME " --filter1 value\n";

static const struct option long_options[] = {
    {"filter1", required_argument, NULL, 'f'},
    {"filter2", required_argument, NULL, 'F'},
    {"interval", required_argument, NULL, 'i'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_usage(void)
{
    printf("%s", argp_program_doc);
}

static int parse_args(int argc, char **argv)
{
    int opt;
    while ((opt = getopt_long(argc, argv, "f:F:i:vh",
                              long_options, NULL)) != -1) {
        switch (opt) {
        case 'f':
            env.filter1 = atoi(optarg);
            break;
        case 'F':
            env.filter2 = atoi(optarg);
            break;
        case 'i':
            env.interval = atoi(optarg);
            break;
        case 'v':
            env.verbose = true;
            break;
        case 'h':
            print_usage();
            exit(0);
        default:
            print_usage();
            return -1;
        }
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static void print_stats(struct <tool>_bpf *skel)
{
    // Read maps and print statistics
    // Implementation specific to each tool
}

int main(int argc, char **argv)
{
    struct <tool>_bpf *skel = NULL;
    int err;

    err = parse_args(argc, argv);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    skel = <tool>_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Set global variables
    skel->rodata->targ_filter1 = env.filter1;
    skel->rodata->targ_filter2 = env.filter2;

    err = <tool>_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = <tool>_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Tracing... Hit Ctrl-C to end.\n");

    while (!exiting) {
        sleep(env.interval);
        print_stats(skel);
    }

    print_stats(skel);

cleanup:
    <tool>_bpf__destroy(skel);
    return err != 0;
}
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-10 | Claude | Initial version |

---

*End of Document*
