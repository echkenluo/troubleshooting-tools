# Data Path Model

## Overview

This document defines the 13 segments (A-M) of the cross-node VM ICMP ping data path.

## Complete Data Path Diagram

```
                          ICMP Request Path
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                     │
  │  Sender VM (VM-A)                                                                   │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [A] icmp_send → tcp/ip stack → virtio-net TX                               │   │
  │  │      (kernel_icmp_rtt Path 1)                                                │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                              │                                                      │
  │                              ▼                                                      │
  │  Sender Host (Host-A)                                                               │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [B] vnet RX → OVS/bridge → physical NIC TX                                 │   │
  │  │      (icmp_drop_detector ReqInternal: vnet→phy)                             │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                              │                                                      │
  │                              ▼                                                      │
  │  Network                                                                            │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [C] Physical wire / switch latency                                         │   │
  │  │      (Derived from External measurements)                                   │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                              │                                                      │
  │                              ▼                                                      │
  │  Receiver Host (Host-B)                                                             │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [D] physical NIC RX → OVS/bridge → vnet TX                                 │   │
  │  │      (icmp_drop_detector ReqInternal: phy→vnet)                             │   │
  │  │                                                                              │   │
  │  │  [E] tun_net_xmit → vhost_signal → eventfd → irqfd → KVM IRQ injection      │   │
  │  │      (tun_tx_to_kvm_irq: Stage1→Stage5)                                     │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                              │                                                      │
  │                              ▼                                                      │
  │  Receiver VM (VM-B)                                                                 │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [F] virtio-net RX → tcp/ip stack → icmp_rcv                                │   │
  │  │      (kernel_icmp_rtt Path 1)                                                │   │
  │  │                                                                              │   │
  │  │  [G] ICMP echo request processing → echo reply generation                   │   │
  │  │      (kernel_icmp_rtt Inter-Path)                                            │   │
  │  │                                                                              │   │
  │  │  [H] icmp_reply → tcp/ip stack → virtio-net TX                              │   │
  │  │      (kernel_icmp_rtt Path 2)                                                │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                                                                                     │
  └─────────────────────────────────────────────────────────────────────────────────────┘

                          ICMP Reply Path (reverse)
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                     │
  │  Receiver Host (Host-B)                                                             │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [I] vnet RX → OVS/bridge → physical NIC TX                                 │   │
  │  │      (icmp_drop_detector RepInternal: vnet→phy on recv-host)                │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                              │                                                      │
  │                              ▼                                                      │
  │  Network                                                                            │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [J] Physical wire / switch latency (reply direction)                       │   │
  │  │      (Derived from External measurements)                                   │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                              │                                                      │
  │                              ▼                                                      │
  │  Sender Host (Host-A)                                                               │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [K] physical NIC RX → OVS/bridge → vnet TX                                 │   │
  │  │      (icmp_drop_detector RepInternal: phy→vnet on send-host)                │   │
  │  │                                                                              │   │
  │  │  [L] tun_net_xmit → vhost_signal → eventfd → irqfd → KVM IRQ injection      │   │
  │  │      (tun_tx_to_kvm_irq on sender host, receiving reply)                    │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                              │                                                      │
  │                              ▼                                                      │
  │  Sender VM (VM-A)                                                                   │
  │  ┌──────────────────────────────────────────────────────────────────────────────┐   │
  │  │  [M] virtio-net RX → tcp/ip stack → icmp_rcv (reply)                        │   │
  │  │      (kernel_icmp_rtt Path 2)                                                │   │
  │  └──────────────────────────────────────────────────────────────────────────────┘   │
  │                                                                                     │
  └─────────────────────────────────────────────────────────────────────────────────────┘
```

## Segment Definitions

| Segment | Description | Direction | Location | Measurable |
|---------|-------------|-----------|----------|------------|
| A | Sender VM kernel TX stack (icmp_send → virtio TX) | Request | Sender VM | Yes |
| B | Sender host internal forwarding (vnet RX → phy TX) | Request | Sender Host | Yes |
| C | Network transit - request direction | Request | Wire | Derived |
| D | Receiver host internal forwarding (phy RX → vnet TX) | Request | Receiver Host | Yes |
| E | Receiver host vhost→KVM IRQ injection | Request | Receiver Host | Yes |
| F | Receiver VM kernel RX stack (virtio RX → icmp_rcv) | Request | Receiver VM | Yes |
| G | Receiver VM ICMP echo processing | - | Receiver VM | Yes |
| H | Receiver VM kernel TX stack (icmp_reply → virtio TX) | Reply | Receiver VM | Yes |
| I | Receiver host internal forwarding (vnet RX → phy TX) | Reply | Receiver Host | Yes |
| J | Network transit - reply direction | Reply | Wire | Derived |
| K | Sender host internal forwarding (phy RX → vnet TX) | Reply | Sender Host | Yes |
| L | Sender host vhost→KVM IRQ injection | Reply | Sender Host | Yes |
| M | Sender VM kernel RX stack (virtio RX → icmp_rcv) | Reply | Sender VM | Yes |

## Layer Grouping

| Layer | Segments | Description |
|-------|----------|-------------|
| VM Internal | A, F, G, H, M | Guest kernel network stack |
| Host Internal | B, D, I, K | Host OVS/bridge forwarding |
| Physical Network | C, J | Wire and switch latency |
| Virtualization (Measured) | E, L | vhost→KVM IRQ path |
| Virtualization (Unmeasured) | Derived | Gap between Host Total and measured segments |

## Notes

1. **Segments C and J** (physical network) cannot be directly measured and must be derived from other measurements.

2. **Segments E and L** (vhost→KVM) are measured by `tun_tx_to_kvm_irq.py` which traces 5 stages:
   - Stage 1: tun_net_xmit
   - Stage 2: vhost_signal_used_irq
   - Stage 3: eventfd_signal
   - Stage 4: irqfd_wakeup
   - Stage 5: kvm_set_irq (KVM IRQ injection)

3. **Unmeasured virtualization overhead** includes the time between when the host sees the packet and when it enters the tun_tx_to_kvm_irq tracing, as well as any other virtualization overhead not captured by the tools.
