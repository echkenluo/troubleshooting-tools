# BCC to libbpf Tool Mapping

This document provides a complete mapping between original BCC Python tools and their migrated libbpf C implementations.

## Summary

| Metric | Count |
|--------|-------|
| Total BPF Tools | 50 |
| Migrated | 42 |
| Not Migrated (Excluded) | 8 |
| **Migration Progress** | **84%** |

> **Note**: VM pair latency gap tools (5 tools) and related multi-vm tools (3 tools) are intentionally excluded from migration scope.

---

## Complete Tool Mapping

### ✅ Migrated Tools (42)

| # | BCC Source Path | BCC Tool | libbpf Tool |
|---|-----------------|----------|-------------|
| 1 | `cpu/` | `offcputime-ts.py` | `offcputime_ts` |
| 2 | `kvm-virt-network/kvm/` | `kvm_irqfd_stats_summary.py` | `kvm_irqfd_stats_summary` |
| 3 | `kvm-virt-network/kvm/` | `kvm_irqfd_stats_summary_arm.py` | `kvm_irqfd_stats_summary_arm` |
| 4 | `kvm-virt-network/tun/` | `tun_ring_monitor.py` | `tun_ring_monitor` |
| 5 | `kvm-virt-network/tun/` | `tun_to_vhost_queue_stats_details.py` | `tun_vhost_queue_stats_full` |
| 6 | `kvm-virt-network/tun/` | `tun_to_vhost_queue_status_simple.py` | `tun_vhost_queue_stats_simple` |
| 7 | `kvm-virt-network/tun/` | `tun_tx_to_kvm_irq.py` | `tun_tx_to_kvm_irq` |
| 8 | `kvm-virt-network/vhost-net/` | `vhost_buf_peek_stats.py` | `vhost_buf_peek_stats` |
| 9 | `kvm-virt-network/vhost-net/` | `vhost_eventfd_count.py` | `vhost_eventfd_count` |
| 10 | `kvm-virt-network/vhost-net/` | `vhost_queue_correlation_details.py` | `vhost_queue_correlation_details` |
| 11 | `kvm-virt-network/vhost-net/` | `vhost_queue_correlation_simple.py` | `vhost_queue_correlation` |
| 12 | `kvm-virt-network/virtio-net/` | `virtnet_irq_monitor.py` | `virtnet_irq_monitor` |
| 13 | `kvm-virt-network/virtio-net/` | `virtnet_poll_monitor.py` | `virtnet_poll_monitor` |
| 14 | `linux-network-stack/packet-drop/` | `eth_drop.py` | `eth_drop` |
| 15 | `linux-network-stack/packet-drop/` | `kernel_drop_stack_stats_summary.py` | `kernel_drop_stack_stats_summary` |
| 16 | `linux-network-stack/packet-drop/` | `kernel_drop_stack_stats_summary_all.py` | `kernel_drop_stack_stats_summary` (merged) |
| 17 | `linux-network-stack/packet-drop/` | `qdisc_drop_trace.py` | `qdisc_drop_trace` |
| 18 | `linux-network-stack/` | `trace_conntrack.py` | `trace_conntrack` |
| 19 | `linux-network-stack/` | `trace_ip_defrag.py` | `trace_ip_defrag` |
| 20 | `ovs/` | `ovs-kernel-module-drop-monitor.py` | `ovs_kernel_drop_monitor` |
| 21 | `ovs/` | `ovs_upcall_latency_summary.py` | `ovs_upcall_latency_summary` |
| 22 | `ovs/` | `ovs_userspace_megaflow.py` | `ovs_userspace_megaflow` |
| 23 | `performance/` | `iface_netstat.py` | `iface_netstat` |
| 24 | `performance/` | `qdisc_lateny_details.py` | `qdisc_latency_details` |
| 25 | `performance/system-network/` | `enqueue_to_iprec_latency_summary.py` | `enqueue_to_iprec_latency` |
| 26 | `performance/system-network/` | `enqueue_to_iprec_latency_threshold.py` | `enqueue_to_iprec_latency` (merged) |
| 27 | `performance/system-network/` | `kernel_icmp_rtt.py` | `kernel_icmp_rtt` |
| 28 | `performance/system-network/` | `ksoftirqd_sched_latency_summary.py` | `ksoftirqd_sched_latency` |
| 29 | `performance/system-network/` | `skb_frag_list_watcher.py` | `skb_frag_list_watcher` |
| 30 | `performance/system-network/` | `skb_frag_list_watcher_kprobe_only.py` | `skb_frag_list_watcher` (merged) |
| 31 | `performance/system-network/` | `skb_vxlan_source_detector.py` | `skb_vxlan_source_detector` |
| 32 | `performance/system-network/` | `syscall_recv_latency_summary.py` | `syscall_recv_latency` |
| 33 | `performance/system-network/` | `system_network_icmp_rtt.py` | `system_network_icmp_rtt` |
| 34 | `performance/system-network/` | `system_network_latency_details.py` | `system_network_latency_details` |
| 35 | `performance/system-network/` | `system_network_latency_summary.py` | `system_network_latency_summary` |
| 36 | `performance/system-network/` | `system_network_perfomance_metrics.py` | `system_network_performance_metrics` |
| 37 | `performance/system-network/` | `system_network_rx_internal_port_latency_details.py` | `system_network_rx_internal_latency` |
| 38 | `performance/system-network/` | `tcp_perf_observer.py` | `tcp_perf_observer` |
| 39 | `performance/system-network/` | `tcp_rtt_inflight_hist.py` | `tcp_rtt_inflight_hist` |
| 40 | `performance/system-network/` | `tcp_send_rtt_inflight_hist.py` | `tcp_send_rtt_inflight_hist` |
| 41 | `performance/system-network/` | `vxlan_tracer.py` | `vxlan_tracer` |
| 42 | `performance/vm-network/` | `vm_network_latency_details.py` | `vm_network_latency_details` |
| 43 | `performance/vm-network/` | `vm_network_latency_summary.py` | `vm_network_latency_summary` |
| 44 | `performance/vm-network/` | `vm_network_performance_metrics.py` | `vm_network_performance_metrics` |
| 45 | `performance/vm-network/vm_pair_latency/` | `vm_pair_latency.py` | `vm_pair_latency` |

---

### ❌ Not Migrated Tools (8) - Excluded from Scope

These tools are intentionally excluded from migration scope:

| # | BCC Source Path | BCC Tool | Reason |
|---|-----------------|----------|--------|
| 1 | `performance/system-network/` | `tcp_connection_analyzer.py` | Complex variant, use tcp_perf_observer instead |
| 2 | `performance/vm-network/vm_pair_latency/` | `multi_vm_pair_latency.py` | VM pair latency variant - excluded |
| 3 | `performance/vm-network/vm_pair_latency/` | `multi_vm_pair_latency_pairid.py` | VM pair latency variant - excluded |
| 4 | `performance/vm-network/vm_pair_latency/vm_pair_latency_gap/` | `multi_port_gap.py` | VM Gap Analysis - excluded |
| 5 | `performance/vm-network/vm_pair_latency/vm_pair_latency_gap/` | `multi_vm_pair_multi_port_gap.py` | VM Gap Analysis - excluded |
| 6 | `performance/vm-network/vm_pair_latency/vm_pair_latency_gap/` | `vm_pair_gap.py` | VM Gap Analysis - excluded |

---

### 🚫 Excluded Files (Not BPF Tools)

| File | Description |
|------|-------------|
| `kvm-virt-network/vhost-net/sort_vhost_queue_correlation_monitor_signals.py` | Log parsing utility (pure Python) |
| `linux-network-stack/packet-drop/drop_monitor_controller.py` | Controller script (no BPF) |
| Various `skb-frag_list/` subdirectory files | Duplicate/variant scripts |
| Various `system-network-internal/` subdirectory files | Duplicate/variant scripts |
| Various `tcp-perf/` subdirectory files | Duplicate/variant scripts |

---

## Directory Structure

```
measurement-tools/                           # Original BCC tools
├── cpu/
│   └── offcputime-ts.py                    ✅
├── kvm-virt-network/
│   ├── kvm/
│   │   ├── kvm_irqfd_stats_summary.py      ✅
│   │   └── kvm_irqfd_stats_summary_arm.py  ✅
│   ├── tun/
│   │   ├── tun_ring_monitor.py             ✅
│   │   ├── tun_to_vhost_queue_stats_details.py  ✅
│   │   ├── tun_to_vhost_queue_status_simple.py  ✅
│   │   └── tun_tx_to_kvm_irq.py            ✅
│   ├── vhost-net/
│   │   ├── vhost_buf_peek_stats.py         ✅
│   │   ├── vhost_eventfd_count.py          ✅
│   │   ├── vhost_queue_correlation_details.py  ✅
│   │   └── vhost_queue_correlation_simple.py   ✅
│   └── virtio-net/
│       ├── virtnet_irq_monitor.py          ✅
│       └── virtnet_poll_monitor.py         ✅
├── linux-network-stack/
│   ├── packet-drop/
│   │   ├── eth_drop.py                     ✅
│   │   ├── kernel_drop_stack_stats_summary.py      ✅
│   │   ├── kernel_drop_stack_stats_summary_all.py  ✅
│   │   └── qdisc_drop_trace.py             ✅
│   ├── trace_conntrack.py                  ✅
│   └── trace_ip_defrag.py                  ✅
├── ovs/
│   ├── ovs-kernel-module-drop-monitor.py   ✅
│   ├── ovs_upcall_latency_summary.py       ✅
│   └── ovs_userspace_megaflow.py           ✅
└── performance/
    ├── iface_netstat.py                    ✅
    ├── qdisc_lateny_details.py             ✅
    └── system-network/
        ├── enqueue_to_iprec_latency_summary.py   ✅
        ├── enqueue_to_iprec_latency_threshold.py ✅
        ├── kernel_icmp_rtt.py              ✅
        ├── ksoftirqd_sched_latency_summary.py    ✅
        ├── skb_frag_list_watcher.py              ✅
        ├── skb_frag_list_watcher_kprobe_only.py  ✅
        ├── skb_vxlan_source_detector.py          ✅
        ├── syscall_recv_latency_summary.py       ✅
        ├── system_network_icmp_rtt.py      ✅
        ├── system_network_latency_details.py   ✅
        ├── system_network_latency_summary.py   ✅
        ├── system_network_perfomance_metrics.py  ✅
        ├── system_network_rx_internal_port_latency_details.py  ✅
        ├── tcp_perf_observer.py                  ✅
        ├── tcp_rtt_inflight_hist.py              ✅
        ├── tcp_send_rtt_inflight_hist.py         ✅
        └── vxlan_tracer.py                       ✅
    └── vm-network/
        ├── vm_network_latency_details.py         ✅
        ├── vm_network_latency_summary.py         ✅
        ├── vm_network_performance_metrics.py     ✅
        └── vm_pair_latency/
            ├── vm_pair_latency.py                ✅
            ├── multi_vm_pair_latency.py          🚫 (excluded)
            ├── multi_vm_pair_latency_pairid.py   🚫 (excluded)
            └── vm_pair_latency_gap/              🚫 (excluded)

libbpf-tools/tools/                         # Migrated libbpf tools (42 directories)
├── enqueue_to_iprec_latency/
├── eth_drop/
├── iface_netstat/
├── kernel_drop_stack_stats_summary/
├── kernel_icmp_rtt/
├── ksoftirqd_sched_latency/
├── kvm_irqfd_stats_summary/
├── kvm_irqfd_stats_summary_arm/
├── offcputime_ts/
├── ovs_kernel_drop_monitor/
├── ovs_upcall_latency_summary/
├── ovs_userspace_megaflow/
├── qdisc_drop_trace/
├── qdisc_latency_details/
├── skb_frag_list_watcher/
├── skb_vxlan_source_detector/
├── syscall_recv_latency/
├── system_network_icmp_rtt/
├── system_network_latency_details/
├── system_network_latency_summary/
├── system_network_performance_metrics/
├── system_network_rx_internal_latency/
├── tcp_perf_observer/
├── tcp_rtt_inflight_hist/
├── tcp_send_rtt_inflight_hist/
├── trace_conntrack/
├── trace_ip_defrag/
├── tun_ring_monitor/
├── tun_tx_to_kvm_irq/
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
├── vm_pair_latency/
└── vxlan_tracer/
```

---

## Migration Categories Summary

| Category | Total | Migrated | Notes |
|----------|-------|----------|-------|
| CPU Scheduling | 1 | 1 | Complete |
| KVM Virtualization | 2 | 2 | Complete |
| TUN | 4 | 4 | Complete |
| Vhost-net | 4 | 4 | Complete |
| Virtio-net | 2 | 2 | Complete |
| Linux Network Stack | 6 | 6 | Complete |
| OVS Monitoring | 3 | 3 | Complete |
| Performance Misc | 2 | 2 | Complete |
| System Network Performance | 16 | 16 | Complete |
| VM Network Performance | 9 | 4 | 5 tools excluded (vm_pair_latency_gap) |
| **Total** | **50** | **42** | **84% migrated** |

---

## New Tools Added (This Migration)

The following tools were migrated in this batch:

| libbpf Tool | Description |
|-------------|-------------|
| `tun_tx_to_kvm_irq` | TUN TX to KVM IRQ interrupt chain tracer |
| `iface_netstat` | Per-queue packet size distribution monitoring |
| `enqueue_to_iprec_latency` | RX latency from enqueue_to_backlog to ip_rcv |
| `ksoftirqd_sched_latency` | ksoftirqd scheduling latency measurement |
| `skb_frag_list_watcher` | SKB frag_list change monitor for GSO debugging |
| `skb_vxlan_source_detector` | VXLAN encapsulated packet source detector |
| `syscall_recv_latency` | recv/recvfrom/recvmsg syscall latency |
| `tcp_perf_observer` | TCP performance (RTT, handshake, retransmissions) |
| `tcp_rtt_inflight_hist` | TCP RTT vs inflight 2D histogram |
| `tcp_send_rtt_inflight_hist` | TCP RTT/inflight/cwnd from SEND perspective |
| `vxlan_tracer` | VXLAN packet tracer (ports 4789, 8472) |
| `system_network_rx_internal_latency` | Detailed RX path latency (10 stages) |

---

## License

GPL-2.0
