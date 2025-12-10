# BCC to libbpf Migration Checklist

This document tracks the migration progress of BCC Python tools to libbpf C implementations.

## Summary

| Category | Total | Migrated | Remaining |
|----------|-------|----------|-----------|
| Linux Network Stack | 5 | 1 | 4 |
| OVS Monitoring | 3 | 1 | 2 |
| System Network Perf | 5 | 3 | 2 |
| VM Network Perf | 4 | 1 | 3 |
| KVM Virtualization | 2 | 1 | 1 |
| TUN | 3 | 0 | 3 |
| Vhost-net | 5 | 3 | 2 |
| Virtio-net | 2 | 1 | 1 |
| CPU Scheduling | 1 | 0 | 1 |
| **Total** | **31** | **11** | **20** |

---

## 1. Linux Network Stack (5 tools)

### Packet Drop
- [x] `eth_drop.py` → `eth_drop` ✓
- [ ] `kernel_drop_stack_stats_summary_all.py` → `kernel_drop_stack_stats_summary`
- [ ] `qdisc_drop_trace.py` → `qdisc_drop_trace`

### Network Tracing
- [ ] `trace_conntrack.py` → `trace_conntrack`
- [ ] `trace_ip_defrag.py` → `trace_ip_defrag`

---

## 2. OVS Monitoring (3 tools)

- [x] `ovs_upcall_latency_summary.py` → `ovs_upcall_latency_summary` ✓
- [ ] `ovs-kernel-module-drop-monitor.py` → `ovs_kernel_drop_monitor`
- [ ] `ovs_userspace_megaflow.py` → `ovs_userspace_megaflow`

---

## 3. System Network Performance (5 tools)

- [x] `system_network_latency_summary.py` → `system_network_latency_summary` ✓
- [x] `kernel_icmp_rtt.py` → `kernel_icmp_rtt` ✓
- [ ] `system_network_latency_details.py` → `system_network_latency_details`
- [ ] `system_network_icmp_rtt.py` → `system_network_icmp_rtt`
- [ ] `system_network_perfomance_metrics.py` → `system_network_performance_metrics`

---

## 4. VM Network Performance (4 tools)

- [x] `vm_network_latency_summary.py` → `vm_network_latency_summary` ✓
- [ ] `vm_network_latency_details.py` → `vm_network_latency_details`
- [ ] `vm_network_performance_metrics.py` → `vm_network_performance_metrics`
- [ ] `vm_pair_latency.py` → `vm_pair_latency`

---

## 5. KVM Virtualization (2 tools)

- [x] `kvm_irqfd_stats_summary.py` → `kvm_irqfd_stats_summary` ✓
- [ ] `kvm_irqfd_stats_summary_arm.py` → `kvm_irqfd_stats_summary_arm`

---

## 6. TUN (3 tools)

- [ ] `tun_ring_monitor.py` → `tun_ring_monitor`
- [ ] `tun_to_vhost_queue_stats_full_summary.py` → `tun_vhost_queue_stats_full`
- [ ] `tun_to_vhost_queue_status_simple_summary.py` → `tun_vhost_queue_stats_simple`

---

## 7. Vhost-net (5 tools)

- [x] `vhost_queue_correlation_simple.py` → `vhost_queue_correlation` ✓
- [x] `vhost_buf_peek_stats.py` → `vhost_buf_peek_stats` ✓
- [ ] `vhost_queue_correlation_details.py` → `vhost_queue_correlation_details`
- [ ] `vhost_eventfd_count.py` → `vhost_eventfd_count`
- [ ] `sort_vhost_queue_correlation_monitor_signals.py` → `vhost_queue_monitor_signals`

---

## 8. Virtio-net (2 tools)

- [x] `virtnet_poll_monitor.py` → `virtnet_poll_monitor` ✓
- [ ] `virtnet_irq_monitor.py` → `virtnet_irq_monitor`

---

## 9. CPU Scheduling (1 tool)

- [ ] `offcputime-ts.py` → `offcputime_ts`

---

## 10. Performance Misc (1 tool)

- [ ] `qdisc_lateny_details.py` → `qdisc_latency_details`

---

## Migration Progress Log

| Date | Tools Migrated | Notes |
|------|----------------|-------|
| 2025-12-10 | eth_drop, system_network_latency_summary, vm_network_latency_summary, kernel_icmp_rtt | Initial P0/P1 tools |
| 2025-12-10 | ovs_upcall_latency_summary, kvm_irqfd_stats_summary, vhost_queue_correlation, virtnet_poll_monitor, vhost_buf_peek_stats | P2 tools |

---

## Files per Tool

Each migrated tool consists of 3 files:
1. `<tool>.h` - Shared types between BPF and userspace
2. `<tool>.bpf.c` - BPF program (kernel space)
3. `<tool>.c` - Userspace program
