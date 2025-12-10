# BCC to libbpf Migration Checklist

This document tracks the migration progress of BCC Python tools to libbpf C implementations.

## Summary

| Category | Total | Migrated | Remaining |
|----------|-------|----------|-----------|
| CPU Scheduling | 1 | 1 | 0 |
| KVM Virtualization | 2 | 2 | 0 |
| TUN | 4 | 3 | 1 |
| Vhost-net | 4 | 4 | 0 |
| Virtio-net | 2 | 2 | 0 |
| Linux Network Stack | 6 | 6 | 0 |
| OVS Monitoring | 3 | 3 | 0 |
| Interface Stats | 1 | 0 | 1 |
| Internal Latency | 3 | 0 | 3 |
| Scheduler Latency | 1 | 0 | 1 |
| SKB Fragmentation | 2 | 0 | 2 |
| VXLAN | 2 | 0 | 2 |
| Syscall Latency | 1 | 0 | 1 |
| TCP Performance | 3 | 0 | 3 |
| Performance Misc | 1 | 1 | 0 |
| **Total** | **36** | **22** | **14** |

**Note:** VM Pair Latency tools (5 tools) are excluded from migration per user request.

---

## Migrated Tools (22)

### 1. CPU Scheduling
- [x] `offcputime-ts.py` → `offcputime_ts` ✓

### 2. KVM Virtualization
- [x] `kvm_irqfd_stats_summary.py` → `kvm_irqfd_stats_summary` ✓
- [x] `kvm_irqfd_stats_summary_arm.py` → `kvm_irqfd_stats_summary_arm` ✓

### 3. TUN
- [x] `tun_ring_monitor.py` → `tun_ring_monitor` ✓
- [x] `tun_to_vhost_queue_stats_details.py` → `tun_vhost_queue_stats_full` ✓
- [x] `tun_to_vhost_queue_status_simple.py` → `tun_vhost_queue_stats_simple` ✓

### 4. Vhost-net
- [x] `vhost_buf_peek_stats.py` → `vhost_buf_peek_stats` ✓
- [x] `vhost_eventfd_count.py` → `vhost_eventfd_count` ✓
- [x] `vhost_queue_correlation_details.py` → `vhost_queue_correlation_details` ✓
- [x] `vhost_queue_correlation_simple.py` → `vhost_queue_correlation` ✓

### 5. Virtio-net
- [x] `virtnet_irq_monitor.py` → `virtnet_irq_monitor` ✓
- [x] `virtnet_poll_monitor.py` → `virtnet_poll_monitor` ✓

### 6. Linux Network Stack
- [x] `eth_drop.py` → `eth_drop` ✓
- [x] `kernel_drop_stack_stats_summary.py` → `kernel_drop_stack_stats_summary` ✓
- [x] `kernel_drop_stack_stats_summary_all.py` → `kernel_drop_stack_stats_summary` ✓ (merged)
- [x] `qdisc_drop_trace.py` → `qdisc_drop_trace` ✓
- [x] `trace_conntrack.py` → `trace_conntrack` ✓
- [x] `trace_ip_defrag.py` → `trace_ip_defrag` ✓

### 7. OVS Monitoring
- [x] `ovs-kernel-module-drop-monitor.py` → `ovs_kernel_drop_monitor` ✓
- [x] `ovs_upcall_latency_summary.py` → `ovs_upcall_latency_summary` ✓
- [x] `ovs_userspace_megaflow.py` → `ovs_userspace_megaflow` ✓

### 8. Performance Misc
- [x] `qdisc_lateny_details.py` → `qdisc_latency_details` ✓

### 9. System Network Performance (5 of 16)
- [x] `kernel_icmp_rtt.py` → `kernel_icmp_rtt` ✓
- [x] `system_network_icmp_rtt.py` → `system_network_icmp_rtt` ✓
- [x] `system_network_latency_details.py` → `system_network_latency_details` ✓
- [x] `system_network_latency_summary.py` → `system_network_latency_summary` ✓
- [x] `system_network_perfomance_metrics.py` → `system_network_performance_metrics` ✓

### 10. VM Network Performance (4 of 9)
- [x] `vm_network_latency_details.py` → `vm_network_latency_details` ✓
- [x] `vm_network_latency_summary.py` → `vm_network_latency_summary` ✓
- [x] `vm_network_performance_metrics.py` → `vm_network_performance_metrics` ✓
- [x] `vm_pair_latency.py` → `vm_pair_latency` ✓

---

## Remaining Tools to Migrate (14)

### 1. TUN/KVM (1 tool)
- [ ] `tun_tx_to_kvm_irq.py` → `tun_tx_to_kvm_irq`
  - Function: Traces TUN TX queue interrupt chain (tun_net_xmit → vhost_signal → irqfd_wakeup)
  - Priority: Medium

### 2. Interface Stats (1 tool)
- [ ] `iface_netstat.py` → `iface_netstat`
  - Function: Per-queue packet size distribution and throughput monitoring
  - Priority: Medium

### 3. Internal Latency (3 tools)
- [ ] `enqueue_to_iprec_latency_summary.py` → `enqueue_to_iprec_latency_summary`
  - Function: RX latency measurement (enqueue_to_backlog → ip_rcv)
  - Priority: High

- [ ] `enqueue_to_iprec_latency_threshold.py` → `enqueue_to_iprec_latency_threshold`
  - Function: Threshold-based RX latency with stack traces
  - Priority: High

- [ ] `system_network_rx_internal_port_latency_details.py` → `system_network_rx_internal_latency`
  - Function: Internal port RX latency details
  - Priority: Medium

### 4. Scheduler Latency (1 tool)
- [ ] `ksoftirqd_sched_latency_summary.py` → `ksoftirqd_sched_latency`
  - Function: ksoftirqd scheduling latency measurement
  - Priority: High

### 5. SKB Fragmentation (2 tools)
- [ ] `skb_frag_list_watcher.py` → `skb_frag_list_watcher`
  - Function: Traces sk_buff frag_list modifications for GSO debugging
  - Priority: Low

- [ ] `skb_frag_list_watcher_kprobe_only.py` → `skb_frag_list_watcher_kprobe`
  - Function: Kprobe-only version of frag_list watcher
  - Priority: Low

### 6. VXLAN (2 tools)
- [ ] `skb_vxlan_source_detector.py` → `skb_vxlan_source_detector`
  - Function: VXLAN source detection
  - Priority: Low

- [ ] `vxlan_tracer.py` → `vxlan_tracer`
  - Function: VXLAN packet tracing
  - Priority: Low

### 7. Syscall Latency (1 tool)
- [ ] `syscall_recv_latency_summary.py` → `syscall_recv_latency`
  - Function: read/recv/recvfrom syscall latency measurement
  - Priority: Medium

### 8. TCP Performance (3 tools)
- [ ] `tcp_perf_observer.py` → `tcp_perf_observer`
  - Function: TCP performance observer (RTT, handshake latency, retrans, drops)
  - Priority: High

- [ ] `tcp_rtt_inflight_hist.py` → `tcp_rtt_inflight_hist`
  - Function: TCP RTT and in-flight histogram
  - Priority: Medium

- [ ] `tcp_send_rtt_inflight_hist.py` → `tcp_send_rtt_inflight_hist`
  - Function: TCP send RTT and in-flight histogram
  - Priority: Medium

---

## Excluded from Migration

### VM Pair Latency Tools (5 tools) - Per User Request
- `multi_vm_pair_latency.py`
- `multi_vm_pair_latency_pairid.py`
- `multi_port_gap.py`
- `multi_vm_pair_multi_port_gap.py`
- `vm_pair_gap.py`

### Non-BPF Utility Scripts
- `sort_vhost_queue_correlation_monitor_signals.py` - Log parsing utility
- `drop_monitor_controller.py` - Controller script

---

## Migration Progress Log

| Date | Tools Migrated | Notes |
|------|----------------|-------|
| 2025-12-10 | eth_drop, system_network_latency_summary, vm_network_latency_summary, kernel_icmp_rtt | Initial P0/P1 tools |
| 2025-12-10 | ovs_upcall_latency_summary, kvm_irqfd_stats_summary, vhost_queue_correlation, virtnet_poll_monitor, vhost_buf_peek_stats | P2 tools |
| 2025-12-10 | kernel_drop_stack_stats_summary, qdisc_drop_trace, trace_conntrack, trace_ip_defrag, ovs_kernel_drop_monitor, ovs_userspace_megaflow | Network stack & OVS tools |
| 2025-12-10 | system_network_latency_details, system_network_icmp_rtt, system_network_performance_metrics | System network perf tools |
| 2025-12-10 | vm_network_latency_details, vm_network_performance_metrics, vm_pair_latency | VM network perf tools |
| 2025-12-10 | kvm_irqfd_stats_summary_arm | KVM ARM tools |
| 2025-12-10 | tun_ring_monitor, tun_vhost_queue_stats_full, tun_vhost_queue_stats_simple | TUN tools |
| 2025-12-10 | vhost_queue_correlation_details, vhost_eventfd_count | Vhost-net tools |
| 2025-12-10 | virtnet_irq_monitor | Virtio-net tools |
| 2025-12-10 | offcputime_ts, qdisc_latency_details | CPU & misc tools |

---

## Files per Tool

Each migrated tool consists of 3 files:
1. `<tool>.h` - Shared types between BPF and userspace
2. `<tool>.bpf.c` - BPF program (kernel space)
3. `<tool>.c` - Userspace program
