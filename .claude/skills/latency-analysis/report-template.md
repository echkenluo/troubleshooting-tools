# Report Template

## Overview

This template defines the standard output format for latency analysis reports.

---

# Cross-Node VM ICMP Ping Latency Analysis Report

## 1. Executive Summary

**Environment**: [Environment Name]
**Date**: [Analysis Date]
**Total RTT (Sender VM)**: [X.XX] us
**Primary Finding**: [One-sentence summary of key finding]

## 2. Test Configuration

| Parameter | Value |
|-----------|-------|
| Sender VM IP | [IP Address] |
| Receiver VM IP | [IP Address] |
| Sender Host | [Hostname] |
| Receiver Host | [Hostname] |
| Kernel Version | [Version] |
| Measurement Duration | [Duration] |
| Sample Count | [N] |

## 3. Data Path Overview

```
Request:  Sender VM [A] → Sender Host [B] → Network [C] → Receiver Host [D,E] → Receiver VM [F,G,H]
Reply:    Receiver VM [H] → Receiver Host [I] → Network [J] → Sender Host [K,L] → Sender VM [M]
```

## 4. Raw Measurement Data

### 4.1 Sender VM (kernel_icmp_rtt)

| Metric | Average | Min | Max | Samples |
|--------|---------|-----|-----|---------|
| Path 1 (A) | X.XX us | | | |
| Path 2 (M) | X.XX us | | | |
| Inter-Path | X.XX us | | | |
| Total RTT | X.XX us | | | |

### 4.2 Receiver VM (kernel_icmp_rtt)

| Metric | Average | Min | Max | Samples |
|--------|---------|-----|-----|---------|
| Path 1 (F) | X.XX us | | | |
| Path 2 (H) | X.XX us | | | |
| Inter-Path (G) | X.XX us | | | |
| Total RTT | X.XX us | | | |

### 4.3 Sender Host (icmp_drop_detector)

| Metric | Average | Min | Max | Samples |
|--------|---------|-----|-----|---------|
| ReqInternal (B) | X.XX us | | | |
| External | X.XX us | | | |
| RepInternal (K) | X.XX us | | | |
| Total | X.XX us | | | |

### 4.4 Receiver Host (icmp_drop_detector)

| Metric | Average | Min | Max | Samples |
|--------|---------|-----|-----|---------|
| ReqInternal (D) | X.XX us | | | |
| External | X.XX us | | | |
| RepInternal (I) | X.XX us | | | |
| Total | X.XX us | | | |

### 4.5 Receiver Host vhost (tun_tx_to_kvm_irq)

| Metric | Average | Min | Max | Samples |
|--------|---------|-----|-----|---------|
| Total Delay (E) | X.XX us | | | |
| Stage 1→2 | X.XX us | | | |
| Stage 2→3 | X.XX us | | | |
| Stage 3→4 | X.XX us | | | |
| Stage 4→5 | X.XX us | | | |

### 4.6 Sender Host vhost (tun_tx_to_kvm_irq)

| Metric | Average | Min | Max | Samples |
|--------|---------|-----|-----|---------|
| Total Delay (L) | X.XX us | | | |

## 5. Segment Breakdown

### 5.1 Direct Measurements

| Segment | Description | Value (us) | Source |
|---------|-------------|------------|--------|
| A | Sender VM TX | X.XX | Sender VM Path 1 |
| B | Sender Host forwarding | X.XX | Sender Host ReqInternal |
| D | Receiver Host forwarding | X.XX | Receiver Host ReqInternal |
| E | Receiver vhost→KVM | X.XX | Receiver vhost Total |
| F | Receiver VM RX | X.XX | Receiver VM Path 1 |
| G | Receiver VM ICMP processing | X.XX | Receiver VM Inter-Path |
| H | Receiver VM TX | X.XX | Receiver VM Path 2 |
| I | Receiver Host forwarding | X.XX | Receiver Host RepInternal |
| K | Sender Host forwarding | X.XX | Sender Host RepInternal |
| L | Sender vhost→KVM | X.XX | Sender vhost Total |
| M | Sender VM RX | X.XX | Sender VM Path 2 |

### 5.2 Derived Measurements

| Segment | Description | Value (us) | Calculation |
|---------|-------------|------------|-------------|
| C+J | Physical Network | X.XX | Sender_External - Receiver_Host_Total |

## 6. Layer Attribution

| Layer | Segments | Latency (us) | Percentage |
|-------|----------|--------------|------------|
| VM Internal | A+F+G+H+M | X.XX | XX% |
| Host Internal | B+D+I+K | X.XX | XX% |
| Physical Network | C+J | X.XX | XX% |
| Virt Measured | E+L | X.XX | XX% |
| Virt Unmeasured | (derived) | X.XX | XX% |
| **Total** | | **X.XX** | **100%** |

## 7. Validation

### 7.1 Cross-Check Calculation

```
Calculated Total = VM_Internal + Host_Internal + Physical_Network + Virt_Measured + Virt_Unmeasured
                 = X.XX + X.XX + X.XX + X.XX + X.XX
                 = X.XX us

Measured Total (Sender VM RTT) = X.XX us

Difference = X.XX us (X.X%)
```

### 7.2 Three-Segment Model

```
Sender_Host_Effective = VM_Total - Sender_External = X.XX us
Physical_Network = X.XX us
Receiver_Host_Total = X.XX us

Sum = X.XX us
```

## 8. Key Findings

1. **[Finding 1]**: Description of first key observation
2. **[Finding 2]**: Description of second key observation
3. **[Finding 3]**: Description of third key observation

## 9. Comparison (if applicable)

### Environment Comparison

| Metric | Env A | Env B | Difference | % Change |
|--------|-------|-------|------------|----------|
| Total RTT | X.XX us | X.XX us | +X.XX us | +XX% |
| VM Internal | X.XX us | X.XX us | +X.XX us | +XX% |
| Host Internal | X.XX us | X.XX us | +X.XX us | +XX% |
| Physical Network | X.XX us | X.XX us | +X.XX us | +XX% |
| Virt Measured | X.XX us | X.XX us | +X.XX us | +XX% |
| Virt Unmeasured | X.XX us | X.XX us | +X.XX us | +XX% |

### Attribution of Difference

| Layer | Latency Diff (us) | % of Total Diff |
|-------|-------------------|-----------------|
| VM Internal | +X.XX | XX% |
| Host Internal | +X.XX | XX% |
| Physical Network | +X.XX | XX% |
| Virt Measured | +X.XX | XX% |
| Virt Unmeasured | +X.XX | XX% |
| **Total** | **+X.XX** | **100%** |

## 10. Recommendations

1. **[Recommendation 1]**: Action item based on findings
2. **[Recommendation 2]**: Action item based on findings

---

## Appendix A: Log File References

| Log File | Location | Description |
|----------|----------|-------------|
| sfsvm-send.log | [path] | Sender VM kernel_icmp_rtt output |
| sfsvm-recv.log | [path] | Receiver VM kernel_icmp_rtt output |
| host-send.log | [path] | Sender Host icmp_drop_detector output |
| host-recv.log | [path] | Receiver Host icmp_drop_detector output |
| vhost-recv-request.log | [path] | Receiver vhost tun_tx_to_kvm_irq output |
| vhost-send-reply.log | [path] | Sender vhost tun_tx_to_kvm_irq output |

## Appendix B: Command Reference

```bash
# Sender VM
sudo python kernel_icmp_rtt.py --src-ip <sender-ip> --dst-ip <receiver-ip> > sfsvm-send.log

# Receiver VM
sudo python kernel_icmp_rtt.py --src-ip <sender-ip> --dst-ip <receiver-ip> > sfsvm-recv.log

# Sender Host
sudo python icmp_drop_detector.py --src-ip <sender-ip> --dst-ip <receiver-ip> \
    --phy-interface <phy-if> --vm-interface <vnet-if> > host-send.log

# Receiver Host
sudo python icmp_drop_detector.py --src-ip <sender-ip> --dst-ip <receiver-ip> \
    --phy-interface <phy-if> --vm-interface <vnet-if> > host-recv.log

# Receiver Host vhost (for request)
sudo python tun_tx_to_kvm_irq.py --vm-interface <vnet-if> --direction rx > vhost-recv-request.log

# Sender Host vhost (for reply)
sudo python tun_tx_to_kvm_irq.py --vm-interface <vnet-if> --direction rx > vhost-send-reply.log
```
