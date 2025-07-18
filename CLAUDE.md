# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a troubleshooting and performance analysis toolset for virtualized network systems. It contains eBPF-based tools for monitoring, tracing, and analyzing network packet drops, latency, and data path issues in virtualization environments. The primary focus is on providing comprehensive network performance analysis capabilities for virtualized infrastructures.

## Architecture

The codebase follows a modular architecture with tools organized by functionality and technology:

### Core Directories
- **bcc-tools/**: Python-based BPF tools using the BCC framework (main functionality)
  - **packet-drop/**: Multi-protocol packet drop analysis (`multi-protocol-drop-monitor.py`, `drop.py`, `eth_drop.py`)
  - **performance/**: Performance analysis tools with subdirectories for different scopes
  - **ovs-measurement/**: Open vSwitch specific monitoring tools
  - **linux-network-stack/**: Linux kernel network stack tracing
  - **cpu-measurement/**: CPU-specific monitoring and latency analysis
  - **virtio-network/**: Virtio network device monitoring (TUN/TAP devices)

- **bpftrace-tools/**: High-level tracing scripts using bpftrace syntax
  - Network event tracers (ARP, OVS conntrack, GSO, UDP datapath)
  - Queue and transmission monitors
  - Protocol-specific datapath tracers

- **kernel-source/**: Linux kernel source code (openEuler 4.19.90) for reference
- **md/**: Documentation and design documents for analysis methodologies

## Development Commands

### Running BPF Tools

All BPF tools require root privileges. Python tools use Python 2 (marked with `#!/usr/bin/python2`):

```bash
# Basic packet drop monitoring
sudo python2 bcc-tools/packet-drop/multi-protocol-drop-monitor.py

# Monitor specific protocol with filters  
sudo python2 bcc-tools/packet-drop/multi-protocol-drop-monitor.py --src 192.168.1.10 --dst 192.168.1.20 --protocol tcp --dst-port 80

# VM network latency measurement
sudo python2 bcc-tools/performance/system-network/icmp_rtt_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 --phy-iface1 eth0 --phy-iface2 eth1

# TUN device ring buffer monitoring
sudo python2 bcc-tools/virtio-network/tun_ring_monitor.py --device vnet12 --all

# VHOST-NET datapath tracing
sudo python2 bcc-tools/virtio-network/vhost_datapath_monitor.py --device vnet12 --queue 0

# Run with log output
sudo python2 [tool-name] [options] > output.log 2>&1
```

### Running bpftrace Scripts

```bash
# Run bpftrace scripts
sudo bpftrace bpftrace-tools/trace-abnormal-arp.bt
sudo bpftrace bpftrace-tools/trace-ovs-ct-invalid.bt
sudo bpftrace bpftrace-tools/vpc-vm-udp-datapath.bt
```

### Testing and Deployment

BCC tools that require testing should be deployed to the test environment:

```bash
# Deploy to test environment
scp [tool-name] smartx@192.168.70.33:/home/smartx/lcc/[test-directory]/
# or use: ssh mcpserver

# Run tests remotely
ssh smartx@192.168.70.33
# or use: ssh mcpserver
```

Create test subdirectories under `/home/smartx/lcc/` named after the tool's purpose for each testing session.

## Key Components and Data Flow Architecture

### Packet Drop Analysis Pipeline
- **Multi-Protocol Drop Monitor**: `bcc-tools/packet-drop/multi-protocol-drop-monitor.py`
  - Traces `kfree_skb` kernel function to detect packet drops
  - Supports filtering by IP, port, protocol (TCP/UDP/ICMP)
  - Provides kernel and user stack traces for drop location analysis
  - C code separated in `multi-protocol-drop-monitor.c`

### Performance Analysis Layers
- **System Network**: Physical host network interfaces and kernel stack
  - ICMP latency tools: `icmp_rtt_latency.py`, `icmp_rx_latency.py`, `icmp_tx_latency.py`
  - TCP latency measurement: `tcp_latency.py`
- **VM Network**: Virtual machine network interfaces (TUN/TAP devices, vnet interfaces)
  - VM pair latency analysis: `vm_pair_latency/` directory tools
  - VM pair latency gap analysis: `vm_pair_latency_gap/` directory tools
- **Virtio Network**: Virtio network device performance
  - TUN ring buffer monitoring: `tun_ring_monitor.py`
  - VHOST-NET datapath tracing: `vhost_datapath_monitor.py`

### OVS (Open vSwitch) Integration
- **Kernel Module Analysis**: `ovs-kernel-module-drop-monitor.py`
- **Userspace Flow Analysis**: `ovs_userspace_megaflow.py`, `ovs_userspace_megaflow_kernel_parse.py`
- **Execution Path Tracing**: `ovs-clone-execute-summary.py`, `ovs-upcall-execute.py`
- **Connection Tracking**: `trace-ovs-ct-invalid.bt`

### CPU Performance and Binding
- **CPU Monitoring**: `cpu_monitor.sh`, `offcputime-ts.py`
- **Scheduler Analysis**: `sched_latency_monitor.sh`
- **VM Binding Tools**: `binding.py`, `set-vm-pair-cpu-affinity.sh`
- **Resource Optimization**: `set-process-cpu-mem-affinitity.sh`

## Virtualized Network Architecture

The toolset is designed for complex virtualized network environments with multiple layers:

### Network Stack Hierarchy
1. **Physical Network Layer**: Host physical interfaces (eth0, eth1, etc.)
2. **Virtualization Layer**: TUN/TAP devices, vnet interfaces, OVS bridges
3. **Guest Network Layer**: VM internal network interfaces
4. **Application Layer**: Network applications and services

### Data Path Analysis Methodology
- **Root Cause Analysis**: Tools trace execution paths to identify where data structures/metadata values change unexpectedly, affecting control logic
- **Drop Analysis**: Beyond simple drop detection, tools analyze data structure changes at multiple points along the data path
- **Performance Bottleneck Identification**: Multi-layer latency measurement from physical to virtual interfaces

## Common Analysis Scenarios

### Execution Path Anomalies
When packet processing in virtualized data paths doesn't behave as expected, tools help identify:
- Control logic execution path changes
- Data structure/metadata value changes at critical points
- Correlation between multiple processing stages

### Packet Drop Root Cause Analysis
Tools provide detailed drop analysis by:
- Identifying drop locations through call stack analysis
- Analyzing data structure changes before/after drop points
- Correlating drops with system state changes

### Performance Optimization
Tools support systematic performance analysis:
- VM network latency measurement and optimization
- CPU binding and affinity optimization
- System-level network performance analysis

## Dependencies

- **bcc** (BPF Compiler Collection) - Required for Python BPF tools
- **bpftrace** - Required for .bt scripts
- **Python 2** - Most tools use Python 2 (shebang: `#!/usr/bin/python2`)
- **Kernel Debug Symbols** - Required for proper stack trace resolution
- **Root/sudo access** - Required for all BPF operations

## Important Implementation Notes

1. **Output Handling**: All tools output to stdout by default. Use redirection for logging: `tool > output.log 2>&1`
2. **Interface Configuration**: Tools are designed for virtualization environments. Many have hardcoded interface names (vnet, tap, tun) - modify as needed
3. **Performance Impact**: Consider performance overhead when running in production environments
4. **Symbol Resolution**: Stack traces require proper kernel debug symbols for meaningful analysis
5. **Kernel Version Compatibility**: Tools are tested with openEuler 4.19.90 kernel (available in kernel-source/ directory)

## Target Users

### Development Team
- Configure specific tracing parameters based on problem analysis
- Provide complete command lines for field support or self-execution
- Analyze complex execution path and data structure changes

### Field Support Team
- Follow documented procedures to collect logs
- Deploy tools according to provided instructions
- Forward collected data to development team for analysis

## Test Environment

BCC tools requiring testing should be deployed to: `smartx@192.168.70.33:/home/smartx/lcc/`
- Create test subdirectories named after the tool's purpose for each testing session
- Use `ssh mcpserver` or direct `scp` for deployment
- Execute tests using `ssh mcpserver` or direct `ssh` connections

## Test 
- 测试环境如果是 python3-bcc 包，测试前修改使用的 python版本为 python3。
- 测试环境操作系统（uname -a) 如果是 oe ，则 import bcc 需要改为 import bpfcc