# libbpf-tools

Native libbpf-based network troubleshooting tools, migrated from BCC Python implementations.

## Overview

This directory contains CO-RE (Compile Once - Run Everywhere) BPF programs using libbpf for better portability and performance compared to BCC-based tools.

## Directory Structure

```
libbpf-tools/
├── include/            # Common BPF headers
│   ├── bits.bpf.h      # Bit manipulation helpers
│   ├── maps.bpf.h      # BPF map definition macros
│   ├── core_fixes.bpf.h # CO-RE compatibility helpers
│   └── common_types.h  # Shared type definitions
├── lib/                # Userspace helper libraries
│   ├── trace_helpers.c/h   # Symbol resolution, stack traces
│   ├── histogram.c/h       # Histogram printing
│   └── network_helpers.c/h # Network formatting utilities
├── vmlinux/            # vmlinux.h (auto-generated)
├── tools/              # Individual tools
│   ├── eth_drop/
│   ├── system_network_latency_summary/
│   ├── vm_network_latency_summary/
│   ├── kernel_icmp_rtt/
│   ├── ovs_upcall_latency_summary/
│   ├── kvm_irqfd_stats_summary/
│   ├── vhost_queue_correlation/
│   ├── virtnet_poll_monitor/
│   └── vhost_buf_peek_stats/
└── output/             # Build output directory
```

## Building

### Prerequisites

- Linux kernel >= 5.4 with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- clang >= 10
- libbpf-dev
- bpftool
- libelf-dev
- zlib1g-dev

### Build Commands

```bash
# Generate vmlinux.h and build all tools
make

# Build specific tool
make eth_drop
make system_network_latency_summary

# Clean build artifacts
make clean

# Show help
make help
```

## Available Tools

### eth_drop
Network packet drop tracer with protocol filtering and VLAN support.

```bash
./output/eth_drop --type ipv4 --src-ip 10.0.0.1
./output/eth_drop --l4-protocol tcp --dst-port 80
./output/eth_drop --interface eth0 --verbose
```

### system_network_latency_summary
System network stack latency histogram tool for measuring adjacent stage latencies.

```bash
./output/system_network_latency_summary --phy-interface eth0 --direction tx --src-ip 192.168.1.10
./output/system_network_latency_summary --phy-interface eth0 --direction rx --protocol tcp
```

### vm_network_latency_summary
VM network stack latency histogram tool for measuring latencies in virtualized environments.

```bash
./output/vm_network_latency_summary --vm-interface vnet0 --phy-interface eth0 --direction rx
./output/vm_network_latency_summary --vm-interface vnet37 --phy-interface enp0s31f6 --direction tx
```

### kernel_icmp_rtt
ICMP RTT tracer for kernel network stack (no OVS dependency).

```bash
./output/kernel_icmp_rtt --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --direction tx
./output/kernel_icmp_rtt --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --interface eth0 --latency-ms 10
```

### ovs_upcall_latency_summary
OVS upcall latency histogram tool for measuring delay between upcall and userspace processing.

```bash
./output/ovs_upcall_latency_summary --interval 5
./output/ovs_upcall_latency_summary --src-ip 192.168.1.10 --protocol tcp
./output/ovs_upcall_latency_summary --protocol tcp --dst-port 22 --interval 10
```

### kvm_irqfd_stats_summary
VM interrupt statistics tool with histogram aggregation for tracking QEMU/KVM interrupts.

```bash
./output/kvm_irqfd_stats_summary 12345                           # Monitor VM with QEMU PID 12345
./output/kvm_irqfd_stats_summary 12345 --category data           # Only vhost threads
./output/kvm_irqfd_stats_summary 12345 --category data --vhost-pid 12350
./output/kvm_irqfd_stats_summary 12345 --interval 10
```

### vhost_queue_correlation
Simple VHOST queue monitor for vhost_signal and vhost_notify events.

```bash
./output/vhost_queue_correlation
./output/vhost_queue_correlation --device vnet33 --queue 0
./output/vhost_queue_correlation --device vnet33 --verbose
```

### virtnet_poll_monitor
Virtio-net RX function monitor (virtnet_poll and skb_recv_done).

```bash
./output/virtnet_poll_monitor
./output/virtnet_poll_monitor --device eth0
./output/virtnet_poll_monitor --device eth0 --queue 0
```

### vhost_buf_peek_stats
Track vhost_net_buf_peek return values by nvq pointer.

```bash
./output/vhost_buf_peek_stats
./output/vhost_buf_peek_stats -i 5
./output/vhost_buf_peek_stats -i 1 -c
```

## Architecture

### BPF Program Structure

Each tool consists of:
1. `<tool>.h` - Shared types between BPF and userspace
2. `<tool>.bpf.c` - BPF program (kernel space)
3. `<tool>.c` - Userspace program

### CO-RE Benefits

- **Portable**: Works across different kernel versions without recompilation
- **Efficient**: No runtime BPF compilation, reduced startup time
- **Safe**: BTF-based type verification ensures compatibility

## Migration from BCC

This is a migration from the BCC Python tools in `measurement-tools/`. Key differences:

| Feature | BCC | libbpf |
|---------|-----|--------|
| Language | Python + embedded C | Pure C |
| Compilation | Runtime | Build time |
| Portability | Limited | CO-RE |
| Dependencies | python-bcc, clang | libbpf, libelf |
| Performance | Good | Better |

## License

GPL-2.0
