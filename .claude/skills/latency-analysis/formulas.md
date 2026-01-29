# Calculation Formulas

## Overview

This document defines the formulas for calculating derived segments and validating measurements.

## Key Variables

From measurement tools:

| Variable | Source | Description |
|----------|--------|-------------|
| `VM_Sender_Total` | Sender VM kernel_icmp_rtt | Total RTT |
| `VM_Sender_Path1` | Sender VM kernel_icmp_rtt | Path 1 (segment A) |
| `VM_Sender_Path2` | Sender VM kernel_icmp_rtt | Path 2 (segment M) |
| `VM_Sender_InterPath` | Sender VM kernel_icmp_rtt | Inter-Path Latency |
| `VM_Recv_Path1` | Receiver VM kernel_icmp_rtt | Path 1 (segment F) |
| `VM_Recv_Path2` | Receiver VM kernel_icmp_rtt | Path 2 (segment H) |
| `VM_Recv_InterPath` | Receiver VM kernel_icmp_rtt | Inter-Path (segment G) |
| `VM_Recv_Total` | Receiver VM kernel_icmp_rtt | Total RTT (F+G+H) |
| `Sender_ReqInternal` | Sender Host icmp_drop_detector | ReqInternal (segment B) |
| `Sender_External` | Sender Host icmp_drop_detector | External |
| `Sender_RepInternal` | Sender Host icmp_drop_detector | RepInternal (segment K) |
| `Sender_Host_Total` | Sender Host icmp_drop_detector | Total |
| `Recv_ReqInternal` | Receiver Host icmp_drop_detector | ReqInternal (segment D) |
| `Recv_External` | Receiver Host icmp_drop_detector | External |
| `Recv_RepInternal` | Receiver Host icmp_drop_detector | RepInternal (segment I) |
| `Recv_Host_Total` | Receiver Host icmp_drop_detector | Total |
| `Recv_vhost_Total` | Receiver Host tun_tx_to_kvm_irq | Total Delay (segment E) |
| `Send_vhost_Total` | Sender Host tun_tx_to_kvm_irq | Total Delay (segment L) |

## Derived Segment Calculations

### Physical Network Latency (C + J)

The physical network transit time (both directions combined) is derived from:

```
Physical_Network = Sender_External - Recv_Host_Total
```

**Derivation**:
- `Sender_External` covers: C + D + E + F + G + H + I + J
- `Recv_Host_Total` covers: D + (E + F + G + H + I) + I = D + Recv_External + I
- Wait, this needs refinement...

**Correct Derivation**:
```
Sender_External = C + [D + E + F + G + H + I] + J
                = C + Recv_Host_Total + J

Therefore:
C + J = Sender_External - Recv_Host_Total
```

Where `Recv_Host_Total` = D + E + F + G + H + I (time packet is "inside" receiver host's view)

**Note**: The receiver host's `Total` includes the vhost→KVM path (E) and the VM processing (F+G+H) because these happen between physical NIC RX and TX.

### Individual Network Segments

If C and J are assumed symmetric:
```
C ≈ J ≈ (Physical_Network) / 2
```

However, network asymmetry may exist. Without bidirectional measurement, we can only calculate the sum C+J.

### Unmeasured Virtualization Overhead

The gap between host-level measurements and individually measured segments:

**On Receiver Host (Request Direction)**:
```
Recv_Virt_Unmeasured = Recv_ReqInternal - (measured_host_forwarding_time)
```

Actually, a cleaner model:
```
Recv_Virt_Unmeasured = Recv_Host_Total - (D + E + F + G + H + I)
```

Where:
- D = Recv_ReqInternal
- E = Recv_vhost_Total
- F + G + H = VM_Recv_Total
- I = Recv_RepInternal

## Validation Equations

### End-to-End Validation

```
VM_Sender_Total ≈ A + B + C + D + E + F + G + H + I + J + K + L + M
```

Expanded:
```
VM_Sender_Total ≈ VM_Sender_Path1 +      # A
                  Sender_ReqInternal +    # B
                  Physical_Network +      # C + J
                  Recv_ReqInternal +      # D
                  Recv_vhost_Total +      # E
                  VM_Recv_Total +         # F + G + H
                  Recv_RepInternal +      # I
                  Sender_RepInternal +    # K
                  Send_vhost_Total +      # L
                  VM_Sender_Path2         # M
```

### Three-Segment Model Validation

Simplified view:
```
VM_Sender_Total ≈ Sender_Host_Total_Effective + Physical_Network + Recv_Host_Total
```

Where:
```
Sender_Host_Total_Effective = VM_Sender_Total - Sender_External
                            = A + B + K + L + M  (sender-side processing)
```

### Host-Level Cross-Check

```
Sender_Host_Total = Sender_ReqInternal + Sender_External + Sender_RepInternal
                  = B + (C + Recv_Host_Total + J) + K
```

## Practical Calculation Steps

### Step 1: Extract Raw Averages

From each log file, calculate the average of each metric.

### Step 2: Calculate Physical Network

```python
physical_network = sender_external - recv_host_total
```

### Step 3: Build Segment Table

Map each segment to its source value:

| Segment | Value | Source |
|---------|-------|--------|
| A | VM_Sender_Path1 | Sender VM Path 1 |
| B | Sender_ReqInternal | Sender Host ReqInternal |
| C+J | physical_network | Derived |
| D | Recv_ReqInternal | Receiver Host ReqInternal |
| E | Recv_vhost_Total | Receiver vhost Total |
| F | VM_Recv_Path1 | Receiver VM Path 1 |
| G | VM_Recv_InterPath | Receiver VM Inter-Path |
| H | VM_Recv_Path2 | Receiver VM Path 2 |
| I | Recv_RepInternal | Receiver Host RepInternal |
| K | Sender_RepInternal | Sender Host RepInternal |
| L | Send_vhost_Total | Sender vhost Total |
| M | VM_Sender_Path2 | Sender VM Path 2 |

### Step 4: Calculate Layer Totals

```python
vm_internal = A + F + G + H + M
host_internal = B + D + I + K
physical_network = C + J  # already calculated
virt_measured = E + L
virt_unmeasured = VM_Sender_Total - (vm_internal + host_internal + physical_network + virt_measured)
```

### Step 5: Validate

Check that layer totals approximately equal VM_Sender_Total:
```python
calculated_total = vm_internal + host_internal + physical_network + virt_measured + virt_unmeasured
assert abs(calculated_total - VM_Sender_Total) < tolerance
```

## Common Issues

1. **Clock Skew**: Cross-machine measurements may have clock synchronization issues. Use relative measurements within each machine.

2. **Measurement Overhead**: eBPF tracing adds some overhead. For precise measurements, account for this.

3. **Sample Variance**: Take multiple samples and use averages. Consider reporting min/max/stddev.

4. **Unit Conversion**: Ensure consistent units (microseconds preferred). Convert milliseconds (ms) to microseconds (us) by multiplying by 1000.
