# KVM -> vhost -> TUN Latency Measurement Tool Design

## 1. Overview

### 1.1 Goal

Measure per-packet latency distribution for the host-side virtualization path:
```
KVM ioeventfd kick -> vhost handle_tx_kick -> tun_sendmsg -> netif_receive_skb
```

The measurement filters on a known target flow (5-tuple) and produces three latency segments (S0/S1/S2).

### 1.2 Scope

- **Host side only**: Measures from KVM ioeventfd to network stack entry
- **Assumptions**:
  - `tfile->napi_enabled` is off (no NAPI thread)
  - RPS disabled (no cross-CPU RX)
  - TUN multi-queue may be enabled; per-thread correlation is preserved

### 1.3 Implementation

Two tool variants sharing the same two-phase approach:

| Tool | Output Style | Use Case |
|------|--------------|----------|
| `kvm_vhost_tun_latency_details.py` | Per-packet exact values via perf_buffer | Precise single-packet analysis |
| `kvm_vhost_tun_latency_summary.py` | Histogram distributions via BPF_HISTOGRAM | Long-term monitoring, comparison |

---

## 2. Key Observations (Kernel Data Structures)

### 2.1 KVM ioeventfd

```c
struct _ioeventfd {
    struct list_head list;
    u64 addr;
    int length;
    struct eventfd_ctx *eventfd;  // Key field for correlation
    u64 datamatch;
    struct kvm_io_device dev;     // Parameter to ioeventfd_write
    u8 bus_idx;
    bool wildcard;
};
```

- `ioeventfd_write()` receives `kvm_io_device *` as parameter
- `eventfd_ctx *` can be obtained via `container_of(dev, struct _ioeventfd, dev)`

### 2.2 vhost -> eventfd Correlation

```c
struct vhost_poll {
    poll_table table;
    wait_queue_head_t *wqh;
    wait_queue_entry_t wait;   // Registered on eventfd's wait queue
    struct vhost_work work;    // Work item for vhost worker
    __poll_t mask;
    void *dev;
};
```

- `vhost_poll_wakeup()` is called from `eventfd_signal()` via wait queue callback
- The `work` pointer uniquely identifies the vhost operation
- Mapping: `work_ptr -> eventfd_ctx` can be built during `vhost_poll_wakeup()`

### 2.3 Thread Context Stability

When `napi_enabled` is off and RPS is disabled:
- `handle_tx_kick()`, `tun_sendmsg()`, and `netif_receive_skb()` run in the **same vhost worker thread**
- Thread ID (`tid`) is therefore a stable correlation key for S1/S2 segments

### 2.4 Correlation Chain

```
KVM:        ioeventfd_write(kvm_io_device *)
              └─► eventfd_signal(eventfd_ctx *)
                    └─► current_eventfd = eventfd_ctx

vhost:      vhost_poll_wakeup(wait_queue_entry_t *)
              └─► work_ptr -> eventfd_ctx mapping established

            handle_tx_kick(vhost_work *)
              └─► tid -> eventfd_ctx mapping established
              └─► mark tid as active

TUN:        tun_sendmsg(socket *)  [same tid]
              └─► S2 FIFO push

netif:      netif_receive_skb(skb *) [same tid]
              └─► S2 FIFO pop, flow filter, emit
```

---

## 3. Two-Phase Workflow

### 3.1 Why Two Phases?

Flow filtering (5-tuple matching) is only reliable when `skb` is available at `netif_receive_skb()`. Earlier trace points (ioeventfd, handle_tx_kick, tun_sendmsg) have no access to packet headers.

The solution:
1. **Phase 1 (discover)**: Identify which vhost workers carry the target flow
2. **Phase 2 (measure)**: Use discovered filter set to minimize noise and measure latency

### 3.2 Phase 1: Discovery

**Purpose**: Build the filter set for Phase 2

**Probes**:
```
kprobe:eventfd_signal          - Record current eventfd_ctx (per-CPU)
kretprobe:eventfd_signal       - Clear current eventfd_ctx
kprobe:vhost_poll_wakeup       - Build work_ptr -> eventfd_ctx mapping
kprobe:handle_tx_kick          - Build tid -> eventfd_ctx mapping
kprobe:netif_receive_skb       - Match target flow, record tid + queue
```

**Maps**:
```c
BPF_PERCPU_ARRAY(current_eventfd, u64, 1);   // Per-CPU eventfd tracking
BPF_HASH(work_eventfd, u64, u64, 4096);      // work_ptr -> eventfd_ctx
BPF_HASH(tid_eventfd, u32, u64, 4096);       // tid -> eventfd_ctx
BPF_HASH(flow_tid_info, u32, struct tid_info, 4096);  // tid -> (count, queue)
```

**Output (profile.json)**:
```json
{
  "device": "vnet94",
  "flow": "proto=udp,src=10.0.0.1,dst=10.0.0.2,sport=1234,dport=4321",
  "eventfd_ctx": ["0xffff9c8e8b1c8000"],
  "associations": [
    {"tid": 12345, "queue": 0, "count": 1523, "eventfd": "0xffff9c8e8b1c8000"}
  ],
  "timestamp": "2026-01-13T14:32:01"
}
```

### 3.3 Phase 2: Measurement

**Purpose**: Produce per-packet or histogram latency for target flow

**Probes**:
```
kprobe:eventfd_signal          - (same as Phase 1)
kretprobe:eventfd_signal       - (same as Phase 1)
kprobe:vhost_poll_wakeup       - (same as Phase 1)
kprobe:ioeventfd_write         - S0 start, push to S0 FIFO
kprobe:handle_tx_kick          - S0 end / S1 start
kprobe:tun_sendmsg             - S1 end / S2 start, push to S2 FIFO
kprobe:netif_receive_skb       - S2 end, flow filter, emit
```

---

## 4. Latency Segment Definitions

### 4.1 S0: KVM kick -> vhost start

| Property | Value |
|----------|-------|
| Start | `ioeventfd_write()` for matching eventfd_ctx |
| End | `handle_tx_kick()` for same eventfd_ctx |
| Key | `eventfd_ctx *` |
| Meaning | vhost worker scheduling delay |
| Expected | 5-50 us (typical), 100+ us (under load) |

### 4.2 S1: vhost start -> tun_sendmsg

| Property | Value |
|----------|-------|
| Start | `handle_tx_kick()` for matching tid |
| End | `tun_sendmsg()` in same thread |
| Key | `tid` |
| Meaning | vhost batch processing to first packet |
| Expected | 1-5 us |

### 4.3 S2: tun_sendmsg -> netif_receive_skb (per packet)

| Property | Value |
|----------|-------|
| Start | `tun_sendmsg()` per packet |
| End | `netif_receive_skb()` per packet |
| Key | `tid` + FIFO slot |
| Meaning | TUN device processing |
| Expected | 1-3 us |

---

## 5. FIFO Design for Per-Packet Correlation

### 5.1 S0 FIFO (per eventfd_ctx)

```c
struct s0_state { u32 head; u32 tail; };
struct s0_slot_key { u64 eventfd; u32 slot; u32 pad; };

BPF_HASH(s0_state, u64, struct s0_state, 4096);
BPF_HASH(s0_ts, struct s0_slot_key, u64, 65536);

#define S0_RING_SZ 1024

// Push: ioeventfd_write
slot = state.tail % S0_RING_SZ;
s0_ts[eventfd, slot] = now;
state.tail++;

// Pop: handle_tx_kick
slot = state.head % S0_RING_SZ;
ts = s0_ts[eventfd, slot];
state.head++;
s0_delta = now - ts;
```

### 5.2 S2 FIFO (per tid, aligned with S0/S1)

```c
struct s2_state { u32 head; u32 tail; };
struct s2_slot_key { u32 tid; u32 slot; };
struct s12_slot_key { u32 tid; u32 slot; };

BPF_HASH(s2_state, u32, struct s2_state, 4096);
BPF_HASH(s2_ts, struct s2_slot_key, u64, 65536);
BPF_HASH(s0_val, struct s12_slot_key, u64, 65536);  // S0 delta stored with S2
BPF_HASH(s1_val, struct s12_slot_key, u64, 65536);  // S1 delta stored with S2
BPF_HASH(s0_ok, struct s12_slot_key, u8, 65536);    // S0 valid flag
BPF_HASH(s1_ok, struct s12_slot_key, u8, 65536);    // S1 valid flag

#define S2_RING_SZ 2048

// Push: tun_sendmsg
slot = state.tail % S2_RING_SZ;
s2_ts[tid, slot] = now;
s0_val[tid, slot] = s0_delta;
s1_val[tid, slot] = s1_delta;
state.tail++;

// Pop: netif_receive_skb (ALWAYS pop to keep alignment)
slot = state.head % S2_RING_SZ;
ts = s2_ts[tid, slot];
s0 = s0_val[tid, slot];
s1 = s1_val[tid, slot];
state.head++;
s2_delta = now - ts;

if (flow_match(skb)) {
    emit(s0, s1, s2_delta);
}
```

### 5.3 FIFO Sizing

| FIFO | Ring Size | Rationale |
|------|-----------|-----------|
| S0 | 1024 | One eventfd may have multiple outstanding kicks |
| S2 | 2048 | Must cover max in-flight packets per thread |

Overflow handling: Drop oldest entry and increment `fifo_overflow` counter.

---

## 6. Filtering Strategy

### 6.1 Early Filtering (S0)

- Load `target_eventfd` set from Phase 1 profile
- `ioeventfd_write`: Only push if eventfd_ctx in target set
- `handle_tx_kick`: Only process if work -> eventfd_ctx in target set

### 6.2 Dynamic TID Marking (S1/S2)

```c
BPF_HASH(active_tid, u32, u8, 4096);

// handle_tx_kick: Mark tid as active when eventfd matches
active_tid[tid] = 1;

// tun_sendmsg: Only process if tid is active
if (!active_tid[tid]) return;

// netif_receive_skb: Only process if tid is active
if (!active_tid[tid]) return;

// Clear tid when FIFO is empty (batch complete)
if (s2_state[tid].head == s2_state[tid].tail) {
    active_tid.delete(tid);
}
```

### 6.3 Final Filtering (flow_match)

Only `netif_receive_skb` can confirm target flow via skb header parsing.

```c
static __always_inline int flow_match(struct sk_buff *skb) {
    // 1. Device name filter
    if (!name_filter(dev)) return 0;

    // 2. Protocol filter (IPv4/IPv6)
    if (proto == ETH_P_IP && FLOW_IS_IPV6) return 0;

    // 3. L3/L4 header matching
    // - IP src/dst
    // - Protocol (TCP/UDP/ICMP)
    // - Port src/dst (for TCP/UDP)
    return flow_match_ipv4(skb, nh) || flow_match_ipv6(skb, nh);
}
```

---

## 7. Output Variants

### 7.1 Details Version (perf_buffer)

```c
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

BPF_PERF_OUTPUT(events);

// In netif_receive_skb after flow match:
events.perf_submit(ctx, &evt, sizeof(evt));
```

User-space output:
```
[14:32:01.123] tid=12345 queue=0 s0=15us s1=3us s2=2us total=20us
```

### 7.2 Summary Version (histogram)

```c
BPF_HISTOGRAM(s0_hist, u64, 64);  // log2 buckets
BPF_HISTOGRAM(s1_hist, u64, 64);
BPF_HISTOGRAM(s2_hist, u64, 64);

// In netif_receive_skb after flow match:
s0_hist.increment(bpf_log2l(s0_us));
s1_hist.increment(bpf_log2l(s1_us));
s2_hist.increment(bpf_log2l(s2_us));
```

User-space output:
```
S0: ioeventfd_write -> handle_tx_kick
     usec        : count     distribution
         8 -> 15 : 78       |****************************************|
        16 -> 31 : 10       |***                                     |
  avg=8.2us  p50=9.5us  p90=18.2us  p99=42.1us  (n=152)
```

---

## 8. CLI Interface

### 8.1 Phase 1: Discover

```bash
python3 kvm_vhost_tun_latency_details.py \
    --mode discover \
    --device vnet94 \
    --flow "proto=udp,src=10.0.0.1,dst=10.0.0.2,sport=1234,dport=4321" \
    --duration 10 \
    --out profile.json
```

### 8.2 Phase 2: Measure (Details)

```bash
python3 kvm_vhost_tun_latency_details.py \
    --mode measure \
    --profile profile.json \
    --duration 30
    [--no-detail]  # Suppress per-packet output
```

### 8.3 Phase 2: Measure (Summary)

```bash
python3 kvm_vhost_tun_latency_summary.py \
    --mode measure \
    --profile profile.json \
    --interval 1 \
    --duration 30 \
    [--clear]  # Clear histograms each interval
```

---

## 9. Validation Checklist

### 9.1 Phase 1 Validation

- [ ] At least one tid -> eventfd_ctx association discovered
- [ ] `flow_match` count matches expected packet count
- [ ] `work_eventfd_miss` count is 0 or minimal

### 9.2 Phase 2 Validation

- [ ] `s0_samples <= s1_samples <= s2_samples` (accounting for flow filtering)
- [ ] FIFO underflow/overflow counts are 0 or minimal
- [ ] S2 sample count approximately equals target flow packet count
- [ ] Total chain (S0+S1+S2) latency is reasonable

### 9.3 Debug Counters

| Counter | Expected | Meaning if high |
|---------|----------|-----------------|
| `fifo_underflow` | 0 | Timing/ordering issue |
| `fifo_overflow` | 0 | RING_SZ too small |
| `s0_miss` | Low | eventfd correlation issue |
| `s1_miss` | Low | tid correlation issue |
| `work_eventfd_miss` | 0 | vhost_poll_wakeup not called |

---

## 10. Limitations

### 10.1 Pointer Validity

- `eventfd_ctx *` and `socket *` pointers become invalid after:
  - Device reset
  - vhost reinitialization
  - VM migration
- **Mitigation**: Re-run Phase 1 after any reconfiguration

### 10.2 NAPI/RPS

If enabled, thread context and ordering assumptions break:
- `netif_receive_skb` may run in different thread than `tun_sendmsg`
- FIFO correlation will fail
- **Mitigation**: Tool detects and warns about this condition

### 10.3 Multiple Flows

Multiple flows on the same vhost worker thread will all be measured.
- **Mitigation**: Use strict 5-tuple filter; Phase 2 only emits matching packets

---

## 11. File Locations

```
measurement-tools/kvm-virt-network/vhost-net/
├── kvm_vhost_tun_latency_details.py  # Per-packet exact values
└── kvm_vhost_tun_latency_summary.py  # Histogram distributions
```

---

*Document Version: 2.0*
*Last Updated: 2026-01-13*
*Based on: Final implementation of kvm_vhost_tun_latency_details.py / kvm_vhost_tun_latency_summary.py*
