# BCC to libbpf Migration Checklist

This document tracks the migration progress of BCC Python tools to libbpf C implementations.

## Summary

| Category | Total | Migrated | Remaining |
|----------|-------|----------|-----------|
| Linux Network Stack | 5 | 5 | 0 |
| OVS Monitoring | 3 | 3 | 0 |
| System Network Perf | 5 | 5 | 0 |
| VM Network Perf | 4 | 4 | 0 |
| KVM Virtualization | 2 | 2 | 0 |
| TUN | 3 | 3 | 0 |
| Vhost-net | 4 | 4 | 0 |
| Virtio-net | 2 | 2 | 0 |
| CPU Scheduling | 1 | 1 | 0 |
| Performance Misc | 1 | 1 | 0 |
| **Total** | **30** | **30** | **0** |

**Status: ✅ MIGRATION COMPLETE**

---

## 1. Linux Network Stack (5 tools)

### Packet Drop
- [x] `eth_drop.py` → `eth_drop` ✓
- [x] `kernel_drop_stack_stats_summary_all.py` → `kernel_drop_stack_stats_summary` ✓
- [x] `qdisc_drop_trace.py` → `qdisc_drop_trace` ✓

### Network Tracing
- [x] `trace_conntrack.py` → `trace_conntrack` ✓
- [x] `trace_ip_defrag.py` → `trace_ip_defrag` ✓

---

## 2. OVS Monitoring (3 tools)

- [x] `ovs_upcall_latency_summary.py` → `ovs_upcall_latency_summary` ✓
- [x] `ovs-kernel-module-drop-monitor.py` → `ovs_kernel_drop_monitor` ✓
- [x] `ovs_userspace_megaflow.py` → `ovs_userspace_megaflow` ✓

---

## 3. System Network Performance (5 tools)

- [x] `system_network_latency_summary.py` → `system_network_latency_summary` ✓
- [x] `kernel_icmp_rtt.py` → `kernel_icmp_rtt` ✓
- [x] `system_network_latency_details.py` → `system_network_latency_details` ✓
- [x] `system_network_icmp_rtt.py` → `system_network_icmp_rtt` ✓
- [x] `system_network_perfomance_metrics.py` → `system_network_performance_metrics` ✓

---

## 4. VM Network Performance (4 tools)

- [x] `vm_network_latency_summary.py` → `vm_network_latency_summary` ✓
- [x] `vm_network_latency_details.py` → `vm_network_latency_details` ✓
- [x] `vm_network_performance_metrics.py` → `vm_network_performance_metrics` ✓
- [x] `vm_pair_latency.py` → `vm_pair_latency` ✓

---

## 5. KVM Virtualization (2 tools)

- [x] `kvm_irqfd_stats_summary.py` → `kvm_irqfd_stats_summary` ✓
- [x] `kvm_irqfd_stats_summary_arm.py` → `kvm_irqfd_stats_summary_arm` ✓

---

## 6. TUN (3 tools)

- [x] `tun_ring_monitor.py` → `tun_ring_monitor` ✓
- [x] `tun_to_vhost_queue_stats_full_summary.py` → `tun_vhost_queue_stats_full` ✓
- [x] `tun_to_vhost_queue_status_simple_summary.py` → `tun_vhost_queue_stats_simple` ✓

---

## 7. Vhost-net (4 tools)

- [x] `vhost_queue_correlation_simple.py` → `vhost_queue_correlation` ✓
- [x] `vhost_buf_peek_stats.py` → `vhost_buf_peek_stats` ✓
- [x] `vhost_queue_correlation_details.py` → `vhost_queue_correlation_details` ✓
- [x] `vhost_eventfd_count.py` → `vhost_eventfd_count` ✓

**Note:** `sort_vhost_queue_correlation_monitor_signals.py` is a log parsing utility (not a BPF tool), so it is excluded from migration.

---

## 8. Virtio-net (2 tools)

- [x] `virtnet_poll_monitor.py` → `virtnet_poll_monitor` ✓
- [x] `virtnet_irq_monitor.py` → `virtnet_irq_monitor` ✓

---

## 9. CPU Scheduling (1 tool)

- [x] `offcputime-ts.py` → `offcputime_ts` ✓

---

## 10. Performance Misc (1 tool)

- [x] `qdisc_lateny_details.py` → `qdisc_latency_details` ✓

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

---

## Excluded Files (Not BPF Tools)

The following files are utility scripts and not BPF tracing tools:

- `sort_vhost_queue_correlation_monitor_signals.py` - Log parsing/sorting utility for analyzing vhost_signal events from correlation monitor logs
