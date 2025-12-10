# BCC to libbpf Tool Mapping

This document provides a complete mapping between original BCC Python tools and their migrated libbpf C implementations.

## Quick Reference

| # | BCC Source Path | Original Name | libbpf Tool Name | Status |
|---|-----------------|---------------|------------------|--------|
| 1 | `cpu/` | `offcputime-ts.py` | `offcputime_ts` | ✅ |
| 2 | `kvm-virt-network/kvm/` | `kvm_irqfd_stats_summary.py` | `kvm_irqfd_stats_summary` | ✅ |
| 3 | `kvm-virt-network/kvm/` | `kvm_irqfd_stats_summary_arm.py` | `kvm_irqfd_stats_summary_arm` | ✅ |
| 4 | `kvm-virt-network/tun/` | `tun_ring_monitor.py` | `tun_ring_monitor` | ✅ |
| 5 | `kvm-virt-network/tun/` | `tun_to_vhost_queue_stats_full_summary.py` | `tun_vhost_queue_stats_full` | ✅ |
| 6 | `kvm-virt-network/tun/` | `tun_to_vhost_queue_status_simple_summary.py` | `tun_vhost_queue_stats_simple` | ✅ |
| 7 | `kvm-virt-network/vhost-net/` | `vhost_buf_peek_stats.py` | `vhost_buf_peek_stats` | ✅ |
| 8 | `kvm-virt-network/vhost-net/` | `vhost_eventfd_count.py` | `vhost_eventfd_count` | ✅ |
| 9 | `kvm-virt-network/vhost-net/` | `vhost_queue_correlation_details.py` | `vhost_queue_correlation_details` | ✅ |
| 10 | `kvm-virt-network/vhost-net/` | `vhost_queue_correlation_simple.py` | `vhost_queue_correlation` | ✅ |
| 11 | `kvm-virt-network/virtio-net/` | `virtnet_irq_monitor.py` | `virtnet_irq_monitor` | ✅ |
| 12 | `kvm-virt-network/virtio-net/` | `virtnet_poll_monitor.py` | `virtnet_poll_monitor` | ✅ |
| 13 | `linux-network-stack/packet-drop/` | `eth_drop.py` | `eth_drop` | ✅ |
| 14 | `linux-network-stack/packet-drop/` | `kernel_drop_stack_stats_summary_all.py` | `kernel_drop_stack_stats_summary` | ✅ |
| 15 | `linux-network-stack/packet-drop/` | `qdisc_drop_trace.py` | `qdisc_drop_trace` | ✅ |
| 16 | `linux-network-stack/` | `trace_conntrack.py` | `trace_conntrack` | ✅ |
| 17 | `linux-network-stack/` | `trace_ip_defrag.py` | `trace_ip_defrag` | ✅ |
| 18 | `ovs/` | `ovs-kernel-module-drop-monitor.py` | `ovs_kernel_drop_monitor` | ✅ |
| 19 | `ovs/` | `ovs_upcall_latency_summary.py` | `ovs_upcall_latency_summary` | ✅ |
| 20 | `ovs/` | `ovs_userspace_megaflow.py` | `ovs_userspace_megaflow` | ✅ |
| 21 | `performance/system-network/` | `kernel_icmp_rtt.py` | `kernel_icmp_rtt` | ✅ |
| 22 | `performance/system-network/` | `system_network_icmp_rtt.py` | `system_network_icmp_rtt` | ✅ |
| 23 | `performance/system-network/` | `system_network_latency_details.py` | `system_network_latency_details` | ✅ |
| 24 | `performance/system-network/` | `system_network_latency_summary.py` | `system_network_latency_summary` | ✅ |
| 25 | `performance/system-network/` | `system_network_perfomance_metrics.py` | `system_network_performance_metrics` | ✅ |
| 26 | `performance/vm-network/vm_pair_latency/` | `vm_pair_latency.py` | `vm_pair_latency` | ✅ |
| 27 | `performance/vm-network/` | `vm_network_latency_details.py` | `vm_network_latency_details` | ✅ |
| 28 | `performance/vm-network/` | `vm_network_latency_summary.py` | `vm_network_latency_summary` | ✅ |
| 29 | `performance/vm-network/` | `vm_network_performance_metrics.py` | `vm_network_performance_metrics` | ✅ |
| 30 | `performance/` | `qdisc_lateny_details.py` | `qdisc_latency_details` | ✅ |

---

## Detailed Mapping by Category

### 1. CPU Scheduling (1 tool)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `cpu/offcputime-ts.py` | `offcputime_ts/` | ✅ Migrated |

### 2. KVM Virtualization (2 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `kvm-virt-network/kvm/kvm_irqfd_stats_summary.py` | `kvm_irqfd_stats_summary/` | ✅ Migrated |
| `kvm-virt-network/kvm/kvm_irqfd_stats_summary_arm.py` | `kvm_irqfd_stats_summary_arm/` | ✅ Migrated |

### 3. TUN (3 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `kvm-virt-network/tun/tun_ring_monitor.py` | `tun_ring_monitor/` | ✅ Migrated |
| `kvm-virt-network/tun/tun_to_vhost_queue_stats_full_summary.py` | `tun_vhost_queue_stats_full/` | ✅ Migrated |
| `kvm-virt-network/tun/tun_to_vhost_queue_status_simple_summary.py` | `tun_vhost_queue_stats_simple/` | ✅ Migrated |

### 4. Vhost-net (4 BPF tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `kvm-virt-network/vhost-net/vhost_buf_peek_stats.py` | `vhost_buf_peek_stats/` | ✅ Migrated |
| `kvm-virt-network/vhost-net/vhost_eventfd_count.py` | `vhost_eventfd_count/` | ✅ Migrated |
| `kvm-virt-network/vhost-net/vhost_queue_correlation_details.py` | `vhost_queue_correlation_details/` | ✅ Migrated |
| `kvm-virt-network/vhost-net/vhost_queue_correlation_simple.py` | `vhost_queue_correlation/` | ✅ Migrated |

### 5. Virtio-net (2 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `kvm-virt-network/virtio-net/virtnet_irq_monitor.py` | `virtnet_irq_monitor/` | ✅ Migrated |
| `kvm-virt-network/virtio-net/virtnet_poll_monitor.py` | `virtnet_poll_monitor/` | ✅ Migrated |

### 6. Linux Network Stack - Packet Drop (3 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `linux-network-stack/packet-drop/eth_drop.py` | `eth_drop/` | ✅ Migrated |
| `linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py` | `kernel_drop_stack_stats_summary/` | ✅ Migrated |
| `linux-network-stack/packet-drop/qdisc_drop_trace.py` | `qdisc_drop_trace/` | ✅ Migrated |

### 7. Linux Network Stack - Tracing (2 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `linux-network-stack/trace_conntrack.py` | `trace_conntrack/` | ✅ Migrated |
| `linux-network-stack/trace_ip_defrag.py` | `trace_ip_defrag/` | ✅ Migrated |

### 8. OVS Monitoring (3 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `ovs/ovs-kernel-module-drop-monitor.py` | `ovs_kernel_drop_monitor/` | ✅ Migrated |
| `ovs/ovs_upcall_latency_summary.py` | `ovs_upcall_latency_summary/` | ✅ Migrated |
| `ovs/ovs_userspace_megaflow.py` | `ovs_userspace_megaflow/` | ✅ Migrated |

### 9. System Network Performance (5 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `performance/system-network/kernel_icmp_rtt.py` | `kernel_icmp_rtt/` | ✅ Migrated |
| `performance/system-network/system_network_icmp_rtt.py` | `system_network_icmp_rtt/` | ✅ Migrated |
| `performance/system-network/system_network_latency_details.py` | `system_network_latency_details/` | ✅ Migrated |
| `performance/system-network/system_network_latency_summary.py` | `system_network_latency_summary/` | ✅ Migrated |
| `performance/system-network/system_network_perfomance_metrics.py` | `system_network_performance_metrics/` | ✅ Migrated |

### 10. VM Network Performance (4 tools)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `performance/vm-network/vm_pair_latency/vm_pair_latency.py` | `vm_pair_latency/` | ✅ Migrated |
| `performance/vm-network/vm_network_latency_details.py` | `vm_network_latency_details/` | ✅ Migrated |
| `performance/vm-network/vm_network_latency_summary.py` | `vm_network_latency_summary/` | ✅ Migrated |
| `performance/vm-network/vm_network_performance_metrics.py` | `vm_network_performance_metrics/` | ✅ Migrated |

### 11. Performance Misc (1 tool)

| BCC Tool | libbpf Tool | Location |
|----------|-------------|----------|
| `performance/qdisc_lateny_details.py` | `qdisc_latency_details/` | ✅ Migrated |

---

## Excluded Files (Not BPF Tools)

The following files are utility scripts, not BPF tracing tools:

| File | Description | Reason for Exclusion |
|------|-------------|---------------------|
| `kvm-virt-network/vhost-net/sort_vhost_queue_correlation_monitor_signals.py` | Log parsing utility | Pure Python script that parses log output, does not use BPF |

---

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total BCC BPF Tools | 30 |
| Migrated to libbpf | 30 |
| Excluded (non-BPF) | 1 |
| **Migration Completion** | **100%** |

---

## Directory Structure

```
measurement-tools/                    # Original BCC tools
├── cpu/
│   └── offcputime-ts.py
├── kvm-virt-network/
│   ├── kvm/
│   │   ├── kvm_irqfd_stats_summary.py
│   │   └── kvm_irqfd_stats_summary_arm.py
│   ├── tun/
│   │   ├── tun_ring_monitor.py
│   │   ├── tun_to_vhost_queue_stats_full_summary.py
│   │   └── tun_to_vhost_queue_status_simple_summary.py
│   ├── vhost-net/
│   │   ├── sort_vhost_queue_correlation_monitor_signals.py  # Not BPF
│   │   ├── vhost_buf_peek_stats.py
│   │   ├── vhost_eventfd_count.py
│   │   ├── vhost_queue_correlation_details.py
│   │   └── vhost_queue_correlation_simple.py
│   └── virtio-net/
│       ├── virtnet_irq_monitor.py
│       └── virtnet_poll_monitor.py
├── linux-network-stack/
│   ├── packet-drop/
│   │   ├── eth_drop.py
│   │   ├── kernel_drop_stack_stats_summary_all.py
│   │   └── qdisc_drop_trace.py
│   ├── trace_conntrack.py
│   └── trace_ip_defrag.py
├── ovs/
│   ├── ovs-kernel-module-drop-monitor.py
│   ├── ovs_upcall_latency_summary.py
│   └── ovs_userspace_megaflow.py
└── performance/
    ├── qdisc_lateny_details.py
    ├── system-network/
    │   ├── kernel_icmp_rtt.py
    │   ├── system_network_icmp_rtt.py
    │   ├── system_network_latency_details.py
    │   ├── system_network_latency_summary.py
    │   └── system_network_perfomance_metrics.py
    └── vm-network/
        ├── vm_network_latency_details.py
        ├── vm_network_latency_summary.py
        ├── vm_network_performance_metrics.py
        └── vm_pair_latency/
            └── vm_pair_latency.py

libbpf-tools/tools/                   # Migrated libbpf tools
├── eth_drop/
├── kernel_drop_stack_stats_summary/
├── kernel_icmp_rtt/
├── kvm_irqfd_stats_summary/
├── kvm_irqfd_stats_summary_arm/
├── offcputime_ts/
├── ovs_kernel_drop_monitor/
├── ovs_upcall_latency_summary/
├── ovs_userspace_megaflow/
├── qdisc_drop_trace/
├── qdisc_latency_details/
├── system_network_icmp_rtt/
├── system_network_latency_details/
├── system_network_latency_summary/
├── system_network_performance_metrics/
├── trace_conntrack/
├── trace_ip_defrag/
├── tun_ring_monitor/
├── tun_vhost_queue_stats_full/
├── tun_vhost_queue_stats_simple/
├── vhost_buf_peek_stats/
├── vhost_eventfd_count/
├── vhost_queue_correlation/
├── vhost_queue_correlation_details/
├── virtnet_irq_monitor/
├── virtnet_poll_monitor/
├── vm_network_latency_details/
├── vm_network_latency_summary/
├── vm_network_performance_metrics/
└── vm_pair_latency/
```
