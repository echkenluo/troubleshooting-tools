---
name: latency-analysis
description: |
  Analyze cross-node VM ICMP ping latency by parsing measurement logs,
  calculating derived segments, and building attribution tables.

  Trigger keywords: analyzing latency logs, latency breakdown, compare latency,
  延迟分析, 延迟分解, 延迟归因, ICMP RTT analysis

allowed-tools: Read, Grep, Glob, Write, Edit, Bash
---

# Latency Analysis Skill

## Overview

This skill provides a systematic methodology for analyzing end-to-end network latency in virtualized environments. It focuses on cross-node VM ICMP ping latency, decomposing the total RTT into measurable and derived segments.

## Applicable Scenarios

- Cross-node VM ICMP ping latency analysis
- Latency comparison between two environments
- Root cause analysis for latency issues
- Latency attribution by layer (VM/Host/Network/Virtualization)

## Data Path Model

The ICMP request-reply path is divided into 13 segments (A-M). See [data-path-model.md](data-path-model.md) for the complete diagram and definitions.

**Quick Reference**:
- **Request Path**: A → B → C → D → E → F → G
- **Reply Path**: H → I → J → K → L → M

## Measurement Tools

Three tools provide latency measurements at different layers:

| Tool | Location | Measures |
|------|----------|----------|
| `kernel_icmp_rtt.py` | VM kernel | Path 1, Path 2, Inter-Path, Total RTT |
| `icmp_drop_detector.py` | Host | ReqInternal, External, RepInternal, Total |
| `tun_tx_to_kvm_irq.py` | Host vhost | Stage 1-5, Total Delay |

See [tool-mapping.md](tool-mapping.md) for detailed output field mappings.

## Analysis Methodology

### Step 1: Identify Data Sources

Confirm the following log files are available:

**Sender Side**:
- Sender VM: `kernel_icmp_rtt` output (Path 1, Path 2, Inter-Path, Total RTT)
- Sender Host: `icmp_drop_detector` output (ReqInternal, External, RepInternal)
- Sender Host vhost: `tun_tx_to_kvm_irq` output (S1-S5 for receiving reply)

**Receiver Side**:
- Receiver VM: `kernel_icmp_rtt` output (Path 1, Path 2, Inter-Path)
- Receiver Host: `icmp_drop_detector` output (ReqInternal, External, RepInternal)
- Receiver Host vhost: `tun_tx_to_kvm_irq` output (S1-S5 for receiving request)

### Step 2: Parse Log Data

Extract key metrics from each log file and calculate averages:

```
# Example: Parse Total RTT from VM log
grep "Total RTT" sfsvm-send.log | awk '{sum+=$NF; count++} END {print sum/count}'

# Example: Parse External latency from Host log
grep "External" oshost-send.log | awk -F'[=|]' '{sum+=$2; count++} END {print sum/count}'
```

### Step 3: Map Measurements to Segments

Using the tool output mappings, populate the directly measured segments:

| Segment | Source | Field |
|---------|--------|-------|
| A | Sender VM | Path 1 |
| B | Sender Host | ReqInternal |
| C+J | Derived | (see Step 4) |
| D | Receiver Host | ReqInternal |
| E | Receiver Host vhost | Total (S1→S5) |
| F | Receiver VM | Path 1 |
| G | Receiver VM | Inter-Path |
| H | Receiver VM | Path 2 |
| I | Receiver Host | RepInternal |
| K | Sender Host | RepInternal |
| L | Sender Host vhost | Total (S1→S5) |
| M | Sender VM | Path 2 |

### Step 4: Calculate Derived Segments

Apply calculation formulas for segments that cannot be directly measured.
See [formulas.md](formulas.md) for complete derivation.

**Key Formula - Physical Network Latency**:
```
Physical_Network (C + J) = Sender_External - Receiver_Host_Total
```

Where:
- `Sender_External` = Sender Host icmp_drop_detector External field
- `Receiver_Host_Total` = Receiver Host icmp_drop_detector Total field

### Step 5: Validate Calculations

Cross-check with validation equations:

```
# End-to-end validation
VM_Total_RTT ≈ A + B + C + D + E + F + G + H + I + J + K + L + M

# Three-segment model validation
VM_Total_RTT ≈ Sender_Host_Total + Physical_Network + Receiver_Host_Total
```

### Step 6: Attribution Analysis

Group segments by layer and calculate percentages:

| Layer | Segments | Description |
|-------|----------|-------------|
| VM Internal | A + F + G + H + M | Kernel stack processing |
| Host Internal | B + D + I + K | OVS/bridge forwarding |
| Physical Network | C + J | Wire/switch latency |
| Virt Measured | E + L | vhost→KVM IRQ injection |
| Virt Unmeasured | Derived | Host_Total - measured segments |

### Step 7: Generate Report

Use the report template to produce structured output.
See [report-template.md](report-template.md) for the standard format.

## Output

The analysis produces:
1. **Data Path Diagram**: Visual representation of latency segments
2. **Raw Data Summary**: Parsed values from all log files
3. **Segment Breakdown Table**: Each segment with source and value
4. **Attribution Table**: Latency grouped by layer with percentages
5. **Key Findings**: Notable observations and potential issues

## Related Files

- [data-path-model.md](data-path-model.md) - Segment definitions and diagram
- [tool-mapping.md](tool-mapping.md) - Tool output to segment mappings
- [formulas.md](formulas.md) - Calculation formulas and derivations
- [report-template.md](report-template.md) - Output report template

## Workflow Integration

For running measurements remotely (not just analyzing existing logs), use the
[latency-measurement-workflow](../../workflows/latency-measurement-workflow.md).
