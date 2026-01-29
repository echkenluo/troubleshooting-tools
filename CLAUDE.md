# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Memory File Structure

This is the main Claude configuration file. Additional context-specific memory files:

- `claude_local_coding.md` - BPF/BCC coding guidelines and conventions
- `claude_local_test.md` - Testing procedures and environment setup

### Agents and Workflows

Custom agents are defined in `.claude/agents/`:

| Agent                 | Trigger  | Purpose                                                                   |
| --------------------- | -------- | ------------------------------------------------------------------------- |
| `research-agent`    | Auto     | Research: source code analysis, web search, documentation, best practices |
| `prd-agent`         | Explicit | Create IEEE 830 requirements documents                                    |
| `design-agent`      | Explicit | Create IEEE 1016 design documents (HLD/LLD)                               |
| `development-agent` | Explicit | Implement code following project conventions                              |
| `testing-agent`     | Explicit | Execute tests on remote environments                                      |
| `debug-agent`       | Explicit | Add debug instrumentation, diagnose issues                                |

**Orchestration Workflow**: `.claude/workflows/debug-fix-workflow.md`

When user requests debugging or fixing a tool, follow the debug-fix workflow:

1. **debug-agent**: Add debug_inc() instrumentation or analyze existing debug output
2. **testing-agent**: Run tests, collect debug statistics
3. **Iterate**: debug-agent analyzes stats, adds more debug or returns diagnosis
4. **Review**: Main agent reviews diagnosis, may use research-agent if needed
5. **development-agent**: Apply fix based on diagnosis
6. **testing-agent**: Verify fix
7. **Iterate if needed**: Back to debug-agent if verification fails

## Project Overview

This is an **eBPF-based network troubleshooting and performance analysis toolset** for virtualized environments. The repository contains two major components:

1. **Measurement Tools** (`measurement-tools/`): Production-ready eBPF monitoring tools using BCC and bpftrace
2. **Traffic Analyzer** (`traffic-analyzer/`): Python-based PCAP and TCP socket analysis tools (under development)

**Target Environment**: openEuler 4.19.90 kernel, virtualized network infrastructure with OVS

## Quick Reference

### Common Commands

```bash
# Execute BCC Python tools (requires root/sudo)
sudo python measurement-tools/linux-network-stack/packet-drop/eth_drop.py
sudo python measurement-tools/performance/system-network/kernel_icmp_rtt.py --src-ip IP1 --dst-ip IP2
sudo python measurement-tools/performance/vm-network/vm_network_latency_summary.py

# Execute bpftrace scripts
sudo bpftrace measurement-tools/other/trace-abnormal-arp.bt
sudo bpftrace measurement-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt

# Run test suite (automated testing framework)
python3 test/workflow/tools/test_case_generator.py --spec test/workflow/spec/performance-test-spec.yaml --output test/workflow/case/performance-test-cases.json
python3 test/workflow/tools/test_runner.py --config test/workflow/config/performance-test-config.yaml --topic performance

# Traffic Analyzer (under development)
# Design docs: docs/design/traffic-analyzer/claude/
# Requirements: docs/prd/traffic-analyzer/claude/traffic-analysis-requirements-v3.0.md
```

## Architecture

### Measurement Tools Directory Structure

```
measurement-tools/
├── linux-network-stack/     # Packet drop monitoring, connection tracking
│   └── packet-drop/         # kfree_skb tracing with stack analysis
├── performance/
│   ├── system-network/      # Host-level network performance (ICMP RTT, TCP latency, metrics)
│   └── vm-network/          # VM network latency decomposition and VM pair analysis
│       └── vm_pair_latency/ # Inter-VM latency monitoring and gap analysis
├── ovs/                     # Open vSwitch monitoring (megaflow, upcall, kernel module drops)
├── kvm-virt-network/        # Virtio/TUN/TAP/vhost monitoring
│   ├── kvm/                 # KVM IRQ injection statistics (x86/ARM)
│   ├── tun/                 # TUN/TAP device ring buffer, GSO, TX to vhost correlation
│   ├── vhost-net/           # vhost eventfd, queue correlation, buffer peek stats
│   └── virtio-net/          # virtio-net polling, IRQ monitoring, RX path tracing
├── cpu/                     # CPU and scheduler analysis (off-CPU time, futex, pthread locks)
└── other/                   # Additional tracers (ARP, OVS conntrack, qdisc, VPC datapath)
```

### Traffic Analyzer Project (Under Development)

**Location**: `traffic-analyzer/` contains three subdirectories:

- **traffic-analyzer-claude/**: Target implementation location (currently empty - awaiting implementation)
- **traffic-analyzer-kimi/**: Kimi AI-assisted research and prototypes
- **traffic-analyzer-original/**: Original analysis scripts and test data from real network issues

**Documentation**:

- **Design**: `docs/design/traffic-analyzer/claude/` (IEEE 1016 format)
- **Requirements**: `docs/prd/traffic-analyzer/claude/traffic-analysis-requirements-v3.0.md` (IEEE 830 format)

**Two Independent Tools** (planned):

1. **PCAP Analyzer**: Packet-level analysis using tshark (Summary/Details/Analysis modes)
2. **TCP Socket Analyzer**: Kernel socket state analysis from eBPF data (Summary/Detailed/Pipeline modes)

**Development Status**: Design and requirements complete, implementation pending

### Test Framework

**Location**: `test/` directory contains three subdirectories:

- **workflow/**: Specification-driven test framework (YAML specs, test cases, results)
- **automate-performance-test/**: Performance test automation scripts and analysis
- **debug/**: Debug utilities and tools
- **tools/**: Shared test utilities

**Test Framework Pattern**:

- **Specification-driven**: Test specs (YAML) define parameter matrices
- **Remote execution**: Tools run via SSH on test servers
- **Results collection**: Stored in `test/workflow/result/`

## Key Design Patterns

### eBPF Tool Patterns

1. **Tool Arguments**: Consistent argparse pattern across tools

   - `--src-ip`, `--dst-ip`: Source and destination IP addresses
   - `--protocol`: Protocol type (tcp, udp, icmp)
   - `--direction`: Traffic direction (rx, tx)
   - `--phy-interface`: Physical interface name
   - `--vm-interface`: Virtual machine interface name
   - `--debug`: Enable debug output
2. **BCC Import Compatibility**: All tools use fallback pattern for `bcc`/`bpfcc` modules

   ```python
   #!/usr/bin/env python
   try:
       from bcc import BPF
   except ImportError:
       from bpfcc import BPF
   ```
3. **Data Flow**: eBPF kernel program → BPF maps → Python userspace processing → stdout

## Virtualized Network Stack

The tools trace data flow through multiple layers:

```
Application Layer
       ↓
Socket Layer (tcp_sendmsg/tcp_recvmsg)
       ↓
TCP/IP Stack (kernel network stack)
       ↓
OVS Datapath (megaflow, upcall)
       ↓
TUN/TAP Device (vnet interfaces)
       ↓
vhost-net (kernel accelerator)
       ↓
virtio-net (guest driver)
       ↓
VM Network Interface
```

**Root Cause Analysis Methodology**: Tools trace execution paths to identify unexpected data structure/metadata changes affecting control logic at each layer.

## Critical Development Guidelines

### Code Style (BPF/BCC Tools)

**IMPORTANT**: See `claude_local_coding.md` for complete guidelines

Key rules:

- Use `#!/usr/bin/env python` for Python 2/3 compatibility
- **Forbidden**: Emojis in print/log statements
- **Forbidden**: Chinese characters in comments/print/log
- Use concise English comments (max 3 per function)
- BPF stack limit: 512 bytes (use maps for large data structures)
- No BTF support on target systems (use direct memory read/write)

### Documentation Standards

**NEVER create documentation files unless explicitly requested**. This includes:

- No proactive creation of README.md files
- No markdown documentation files
- No design documents without explicit user request

**Exception**: When working on Traffic Analyzer, follow IEEE 1016 (design) and IEEE 830 (requirements) standards as defined in `docs/design/README.md` and `docs/prd/README.md`.

### Testing Requirements

See `claude_local_test.md` for environment details:

- **Virtualization Host**: Physical server testing
- **Virtualization Guest**: VM testing
- Python 2 (el7 with `python-bcc`) or Python 3 (oe1 with `python3-bpfcc`)

## Important Instructions

**Do what has been asked; nothing more, nothing less.**

- ALWAYS prefer editing an existing file to creating a new one
- NEVER proactively create documentation files (*.md) or README files
- All eBPF tools require root access and can impact system performance
- Test in dev environment first - never run untested BPF on production
- Output to stdout by default (use redirection for logging)

## Safety Notes

- **All tools require root access** - can impact system performance
- **BPF stack limit**: 512 bytes - use maps for large data structures
- **Test in dev first** - never run untested BPF programs on production systems
- **Symbol resolution**: Stack traces require kernel debug symbols
- **Performance impact**: Consider overhead when running in production

## Documentation Structure

```
docs/
├── design/                        # Software Design Descriptions (SDD)
│   ├── README.md                 # IEEE 1016 standard guidelines
│   ├── traffic-analyzer/claude/  # Traffic analyzer HLD/LLD
│   └── *.md                      # Individual tool designs (eth_drop, vm-latency, etc.)
├── prd/                          # Product Requirements Documents
│   ├── README.md                 # IEEE 830 standard guidelines
│   └── traffic-analyzer/claude/  # Traffic analyzer SRS (v3.0)
├── analysis/                     # Kernel code analysis and research
│   ├── virtlization-datapath-analysis/  # Virtio/vhost/TUN TX analysis
│   ├── tcp-perf-doc/            # TCP performance analysis
│   └── *.md                     # BCC/eBPF compatibility, performance analysis
├── publish/                      # User manuals and deployment guides
│   └── tools/                   # Tool-specific documentation
└── workflow/                     # Test workflow documentation
```

## Target Users

1. **Development Team**: Configure tracing parameters, analyze complex execution paths
2. **Field Support Team**: Collect logs following documented procedures, forward to dev team


## planning-with-files Directory Convention

When using the planning-with-files skill for complex tasks:

1. **Create task directory**: `docs/planning-with-files/{task-name}/`
2. **All planning files go in this directory**:
   - `task_plan.md` - Phase tracking and decisions
   - `findings.md` - Research and discoveries
   - `progress.md` - Session log and test results
3. **Task name should be kebab-case** (e.g., `tcp-udp-drop-detector`)

Example structure:
```
docs/planning-with-files/
├── tcp-udp-drop-detector/
│   ├── task_plan.md
│   ├── findings.md
│   └── progress.md
└── traffic-analyzer-impl/
    ├── task_plan.md
    ├── findings.md
    └── progress.md
```

**Important**: Always create files in the task subdirectory, never in the project root. 

## Reference Materials

- **Kernel probe functions**: `kprobe_functions.txt` (available kprobe points for target kernel)
- **User manual**: `docs/publish/user-manual.md`
- **Design standards**: `docs/design/README.md` (IEEE 1016)
- **Requirements standards**: `docs/prd/README.md` (IEEE 830)
- **Additional kernel sources**: Available in `/Users/admin/workspace/kernel/` and `/Users/admin/workspace/linux-4.18.0-553.47.1.el8_10/`
