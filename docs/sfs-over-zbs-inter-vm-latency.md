# 			sfs over zbs 集群性能问题调查报告

## 

| 修订时间 | 修订者 | 描述 |
| :---- | :---- | :---- |
| Jan 9, 2026 | [Chengcheng Luo](mailto:chengcheng.luo@smartx.com) |  |
|  |  |  |

# **背景**

Sfs over zbs 集群上 sfs bench 测试性能显著低于其他环境，初步确定两环境 计算节点（vm）到 sfs vm 的延迟存储明显的稳定差异，sfs workload 对延迟敏感，推测主要影响因素来自延迟较高，对该问题进行进一步详细调查。

# **跨节点虚拟机 ICMP Ping 延迟分析**

## **文档概述**

本文档包含两个环境之间 跨节点的 vm  ICMP ping 延迟比较的完整方法和分析结果 （两集群均为 x86 cpu）：

- **SMTX OS**: 内核 4.19，基准环境  
- **ZBS**: 内核 5.10，目标环境（sfs over zbs 性能测试集群）

测试场景：跨节点 VM ping（Host-A 上的 VM-A 向 Host-B 上的 VM-B 发送 ICMP echo request，接收 reply）

测量：**host 上 与 vm 内部测量均基于 ebpf 工具进行**

---

# **第一部分：分析方法论**

## **1.1 完整数据路径延迟段定义**

| 段 | 描述 | 方向 | 位置 |
| :---- | :---- | :---- | :---- |
| A | 发送方 VM 内核 TX 协议栈 | Request | 发送方 VM |
| B | 发送方宿主机内部转发 | Request | 发送方宿主机 |
| B\_1  | 发送方 kvm \-\> tun | Request | 发送方宿主机 |
| C | 物理网络传输（request） | Request | 物理线缆 |
| D | 接收方宿主机内部转发 | Request | 接收方宿主机 |
| E | 接收方宿主机 vhost-\>KVM 中断 | Request | 接收方宿主机 |
| F | 接收方 VM 内核 RX 协议栈 | Request | 接收方 VM |
| G | 接收方 VM ICMP 处理 | \- | 接收方 VM |
| H | 接收方 VM 内核 TX 协议栈 | Reply | 接收方 VM |
| I | 接收方宿主机内部转发 | Reply | 接收方宿主机 |
| I\_1 | 接收方 host  kvm \-\> tun | Reply | 接收方宿主机 |
| J | 物理网络传输（reply） | Reply | 物理线缆 |
| K | 发送方宿主机内部转发 | Reply | 发送方宿主机 |
| L | 发送方宿主机 vhost-\>KVM 中断 | Reply | 发送方宿主机 |
| M | 发送方 VM 内核 RX 协议栈 | Reply | 发送方 VM |

## **1.2 测量工具** 

### **1.2.1 kernel icmp latency measurement（VM 内部）**

在 VM 内部运行，测量内核网络协议栈延迟。

**发送方 VM (sfsvm-send.log)**:

- `Path 1` \= 段落 A（request 的 VM TX 协议栈）  
- `Path 2` \= 段落 M（reply 的 VM RX 协议栈）  
- `Inter-Path Latency` \= 段落 B \+ C \+ D \+ E \+ F \+ G \+ H \+ I \+ J \+ K \+ L  
- `Total RTT` \= A \+ Inter-Path \+ M \= 完整端到端 RTT

**接收方 VM (sfsvm-recv.log)**:

- `Path 1` \= 段落 F（request 的 VM RX 协议栈）  
- `Path 2` \= 段落 H（reply 的 VM TX 协议栈）  
- `Inter-Path Latency` \= 段落 G（仅 ICMP 处理）  
- `Total RTT` \= F \+ G \+ H（接收方视角的 request-\>reply）

### **1.2.2  host latency measurement （宿主机层面）**

在宿主机上运行，测量 ICMP 流经宿主机接口的过程。

**发送方宿主机 (oshost-send.log / zbshost-send.log)**:

- `ReqInternal` \= 段落 B（request 的 vnet-\>phy）  
- `External` \= 段落 C \+ D \+ E \+ F \+ G \+ H \+ I \+ J（request 发出 \-\> reply 返回）  
- `RepInternal` \= 段落 K（reply 的 phy-\>vnet）  
- `Total` \= B \+ External \+ K

**接收方宿主机 (oshost-recv.log / zbshost-recv.log)**:

- `ReqInternal` \= 段落 D（request 的 phy-\>vnet）  
- `External` \= 段落 E \+ F \+ G \+ H \+ I（接收方的 vhost-\>VM-\>vhost 往返）  
- `RepInternal` \= 段落 I（reply 的 vnet-\>phy）  
- `Total` \= D \+ External \+ I

### **1.2.3 tun tx to kvm measurement（tun-\>KVM 路径）**

### **`虚拟化 vm rx 路径通常占总延迟占比更高。`** 

在宿主机上运行，测量 vhost-net 到 KVM 中断注入的 5 阶段路径。

**阶段**:

- Stage 1 (S1): `tun_net_xmit` \- 数据包进入 TUN 设备  
- Stage 2 (S2): `vhost_signal` \- vhost-net worker 发送信号  
- Stage 3 (S3): `eventfd_signal` \- eventfd 被触发  
- Stage 4 (S4): `irqfd_wakeup` \- irqfd 唤醒  
- Stage 5 (S5): `posted_int` \- KVM 中断注入

**接收方宿主机处理 Request (oshost-vhost-recv-request.log / zbshost-vhost-recv-request.log)**:

- `Total Delay (S1->S5)` \= 段落 E（接收 request 的 vhost-\>KVM）

**发送方宿主机处理 Reply (oshost-vhost-rerecv-reply.log / zbshost-vhost-recv-reply.log)**:

- `Total Delay (S1->S5)` \= 段落 L（接收 reply 的 vhost-\>KVM）

### **1.2.4 kvm to tun measurement (KVM -> TUN)**

在宿主机上运行，测量 KVM ioeventfd 到 TUN 设备发包的 3 阶段路径。

**阶段**:

- Stage 0 (S0): `ioeventfd_write` -> `handle_tx_kick` - KVM 通知 vhost worker
- Stage 1 (S1): `handle_tx_kick` -> `tun_sendmsg` - vhost worker 处理 TX
- Stage 2 (S2): `tun_sendmsg` -> `netif_receive_skb` - TUN 设备发包

**发送方宿主机处理 Request**:

- `Total Delay (S0+S1+S2)` = 段落 B_1（发送 request 的 KVM->TUN）

**接收方宿主机处理 Reply**:

- `Total Delay (S0+S1+S2)` = 段落 I_1（发送 reply 的 KVM->TUN）

## **1.3 段落测量映射**

### **直接测量的分段**

| 段 | 来源 | 字段 |
| :---- | :---- | :---- |
| A | 发送方 VM kernel\_icmp\_rtt | Path 1 |
| M | 发送方 VM kernel\_icmp\_rtt | Path 2 |
| F | 接收方 VM kernel\_icmp\_rtt | Path 1 |
| H | 接收方 VM kernel\_icmp\_rtt | Path 2 |
| G | 接收方 VM kernel\_icmp\_rtt | Inter-Path |
| B | 发送方宿主机 icmp\_drop\_detector | ReqInternal |
| K | 发送方宿主机 icmp\_drop\_detector | RepInternal |
| D | 接收方宿主机 icmp\_drop\_detector | ReqInternal |
| I | 接收方宿主机 icmp\_drop\_detector | RepInternal |
| E | 接收方宿主机 tun\_tx\_to\_kvm\_irq | Total (S1-\>S5) |
| L | 发送方宿主机 tun\_tx\_to\_kvm\_irq | Total (S1-\>S5) |
| B\_1  | 发送方宿主机 kvm\_vhost\_latency |  Kvm \-\> tun |
| I\_1  | 接收方宿主机 kvm\_vhost\_latency |  Kvm \-\> tun |

### **派生分段和高层计算**

完整的 ICMP RTT 可以分解为三个高层分段：

VM\_Sender\_Total \= Sender\_Host\_Total \+ Physical\_Network \+ Receiver\_Host\_Total

**段落定义**：

| 高层段落 | 描述 | 详细段落 | 计算方法 |
| :---- | :---- | :---- | :---- |
| **Sender\_Host\_Total** | 发送方宿主机上的所有延迟（包含 VM） | A \+ B \+ K \+ L \+ M | VM\_Sender\_Total \- Sender\_External |
| **Physical\_Network** | 纯物理线缆延迟（request C \+ reply J） | C \+ J | Sender\_External \- Receiver\_Host\_Total |
| **Receiver\_Host\_Total** | 接收方宿主机上的所有延迟（包含 VM） | D \+ E \+ F \+ G \+ H \+ I | icmp\_drop\_detector 直接测量 |

**公式原理**：

1. **Sender\_External**（发送方宿主机 icmp\_drop\_detector 测量）：  
   - 从 phy TX（B 之后）到 phy RX（K 之前）  
   - \= C \+ Receiver\_Host\_Total \+ J

2. **Receiver\_Host\_Total**（接收方宿主机 icmp\_drop\_detector 测量）：  
   - 从 phy RX 到 phy TX  
   - \= D \+ E \+ F \+ G \+ H \+ I（接收方宿主机完整往返，VM 是宿主机的一部分）

3. 因此：  
   - Physical\_Network (C \+ J) \= Sender\_External \- Receiver\_Host\_Total  
   - Sender\_Host\_Total \= VM\_Sender\_Total \- Sender\_External

**验证公式**：

VM\_Sender\_Total \= Sender\_Host\_Total \+ Physical\_Network \+ Receiver\_Host\_Total

                \= (VM\_Sender\_Total \- Sender\_External) \+ (Sender\_External \- Receiver\_Host\_Total) \+ Receiver\_Host\_Total

                \= VM\_Sender\_Total  

---

# **第二部分：分析结果**

## **2.1 原始数据汇总**

### **2.1.1 SMTX OS 环境**

**发送方 VM (sfsvm-send.log)**:

| 指标 | 数值 (us) | 平均值 |
| :---- | :---- | :---- |
| Path 1 (A) | 20.8, 19.6, 22.0, 17.2, 32.9, 12.8, 11.7, 17.5, 16.3, 14.6, 19.9, 13.1, 17.1, 21.9, 11.5, 23.0 | 18.2 us |
| Path 2 (M) | 14.2, 15.2, 14.0, 17.9, 15.1, 14.8, 15.2, 15.8, 16.0, 15.1, 14.5, 15.5, 24.6, 14.3, 15.3, 14.3 | 15.7 us |
| Inter-Path | 183.7, 216.3, 183.7, 181.1, 192.3, 190.1, 212.8, 225.7, 192.5, 189.6, 193.1, 196.8, 163.8, 167.2, 200.1, 196.2 | 192.9 us |
| Total RTT | 218.7, 251.1, 219.8, 216.2, 240.3, 217.7, 239.7, 259.1, 224.8, 219.3, 227.5, 225.4, 205.4, 203.3, 226.9, 233.5 | 227 us |

**接收方 VM (sfsvm-recv.log)**:

| 指标 | 数值 (us) | 平均值 |
| :---- | :---- | :---- |
| Path 1 (F) | 27.2, 24.0, 23.4, 22.1, 23.1, 23.7, 24.1, 24.8, 23.3, 24.1, 22.5, 25.4, 26.9, 24.1, 22.0, 28.1 | 24.3 us |
| Path 2 (H) | 6.2, 8.9, 6.1, 6.3, 7.3, 7.2, 7.5, 8.3, 7.1, 8.3, 7.0, 8.4, 5.9, 6.4, 7.1, 8.3 | 7.3 us |
| Inter-Path (G) | 7.9, 8.2, 7.3, 7.7, 9.3, 8.9, 8.9, 9.9, 8.3, 8.6, 8.5, 10.4, 5.7, 7.6, 7.9, 9.8 | 8.4 us |
| Total RTT | 41.2, 41.0, 36.8, 36.1, 39.7, 39.8, 40.5, 43.1, 38.8, 41.0, 37.9, 44.2, 38.5, 38.1, 37.1, 46.2 | 40.0 us |

**发送方宿主机 (oshost-send.log)**:

| 指标 | 平均值 |
| :---- | :---- |
| ReqInternal (B) | 13.5 us |
| External | 144.1 us |
| RepInternal (K) | 8.3 us |
| Total | 165.3 us |

**接收方宿主机 (oshost-recv.log)**:

| 指标 | 平均值 |
| :---- | :---- |
| ReqInternal (D) | 12.7 us |
| External | 91.3 us |
| RepInternal (I) | 9.4 us |
| Total | 113.4 us |

**接收方宿主机 vhost-\>KVM (oshost-vhost-recv-request.log)**:

| 阶段 | 延迟 (ms) | 延迟 (us) |
| :---- | :---- | :---- |
| S1-\>S2 (tun\_net\_xmit \-\> vhost\_signal) | 0.022 | 22 |
| S2-\>S3 (vhost\_signal \-\> eventfd) | 0.007 | 7 |
| S3-\>S4 (eventfd \-\> irqfd) | 0.010 | 10 |
| S4-\>S5 (irqfd \-\> posted\_int) | 0.003 | 3 |
| **Total S1-\>S5 (E)** | **0.042** | **42** |

**发送方宿主机 vhost-\>KVM (oshost-vhost-rerecv-reply.log)**:

| 阶段 | 延迟 (ms) | 延迟 (us) |
| :---- | :---- | :---- |
| S1-\>S2 | 0.020 | 20 |
| S2-\>S3 | 0.006 | 6 |
| S3-\>S4 | 0.009 | 9 |
| S4-\>S5 | 0.002 | 2 |
| **Total S1-\>S5 (L)** | **0.038** | **38** |

**发送方宿主机 KVM-\>TUN (oshost-kvm-tx.log)**:

| 阶段 | 延迟 (us) |
| :---- | :---- |
| S0 (ioeventfd \-\> handle\_tx\_kick) | 11.3 |
| S1 (handle\_tx\_kick \-\> tun\_sendmsg) | 7.0 |
| S2 (tun\_sendmsg \-\> netif\_receive\_skb) | 6.5 |
| **Total S0+S1+S2 (B\_1)** | **24.8** |

### **2.1.2 ZBS 环境**

**发送方 VM (sfsvm-send.log)**:

| 指标 | 数值 (us) | 平均值 |
| :---- | :---- | :---- |
| Path 1 (A) | 23.8, 12.3, 14.6, 11.9, 24.4, 14.0, 12.9, 24.2, 24.4, 16.6, 11.4, 24.6, 14.5, 15.1, 14.8, 12.4 | 16.8 us |
| Path 2 (M) | 17.4, 16.5, 16.7, 20.5, 15.5, 18.2, 17.5, 15.9, 21.1, 19.8, 14.6, 15.5, 14.9, 15.5, 16.6, 19.2 | 17.2 us |
| Inter-Path | 520.2, 522.5, 495.3, 724.2, 564.6, 565.8, 503.1, 519.0, 418.0, 592.6, 584.6, 592.4, 634.9, 591.9, 723.3, 511.6 | 567.5 us |
| Total RTT | 561.5, 551.3, 526.6, 756.6, 604.5, 598.0, 533.4, 559.1, 463.5, 629.1, 610.7, 632.5, 664.3, 622.5, 754.7, 543.3 | 601 us |

**接收方 VM (sfsvm-recv.log)**:

| 指标 | 数值 (us) | 平均值 |
| :---- | :---- | :---- |
| Path 1 (F) | 23.6, 19.1, 23.5, 33.0, 22.6, 30.5, 31.5, 25.0, 19.0, 36.9, 25.9, 21.5, 38.7, 40.7, 38.8, 21.9 | 28.3 us |
| Path 2 (H) | 5.5, 5.1, 6.1, 6.4, 5.6, 6.2, 5.2, 6.8, 5.6, 6.1, 6.8, 5.2, 7.0, 6.8, 6.4, 5.8 | 5.9 us |
| Inter-Path (G) | 5.5, 4.8, 5.4, 6.7, 5.8, 6.0, 5.3, 7.1, 5.3, 6.4, 7.0, 6.0, 7.2, 7.1, 7.0, 6.4 | 6.2 us |
| Total RTT | 34.6, 29.0, 34.9, 46.0, 34.0, 42.7, 42.0, 38.9, 29.9, 49.4, 39.6, 32.7, 53.0, 54.6, 52.3, 34.2 | 39.9 us |

**发送方宿主机 (zbshost-sender.log)**:

| 指标 | 平均值 |
| :---- | :---- |
| ReqInternal (B) | 17.1 us |
| External | 429.7 us |
| RepInternal (K) | 13.6 us |
| Total | 461.0 us |

**接收方宿主机 (zbshost-receiver.log)**:

| 指标 | 平均值 |
| :---- | :---- |
| ReqInternal (D) | 12.8 us |
| External | 254.8 us |
| RepInternal (I) | 17.5 us |
| Total | 285.7 us |

**接收方宿主机 vhost-\>KVM (zbshost-vhost-recv-request.log)**:

| 阶段 | 延迟 (ms) | 延迟 (us) |
| :---- | :---- | :---- |
| S1-\>S2 (tun\_net\_xmit \-\> vhost\_signal) | 0.098 | 98 |
| S2-\>S3 (vhost\_signal \-\> eventfd) | 0.008 | 8 |
| S3-\>S4 (eventfd \-\> irqfd) | 0.010 | 10 |
| S4-\>S5 (irqfd \-\> posted\_int) | 0.002 | 2 |
| **Total S1-\>S5 (E)** | **0.120** | **120** |

**发送方宿主机 vhost-\>KVM (zbshost-vhost-recv-reply.log)**:

| 阶段 | 延迟 (ms) | 延迟 (us) |
| :---- | :---- | :---- |
| S1-\>S2 | 0.085 | 85 |
| S2-\>S3 | 0.006 | 6 |
| S3-\>S4 | 0.008 | 8 |
| S4-\>S5 | 0.002 | 2 |
| **Total S1-\>S5 (L)** | **0.105** | **105** |

**发送方宿主机 KVM-\>TUN (zbshost-kvm-tx.log)**:

| 阶段 | 延迟 (us) |
| :---- | :---- |
| S0 (ioeventfd \-\> handle\_tx\_kick) | 86.5 |
| S1 (handle\_tx\_kick \-\> tun\_sendmsg) | 6.5 |
| S2 (tun\_sendmsg \-\> netif\_receive\_skb) | 5.2 |
| **Total S0+S1+S2 (B\_1)** | **98.1** |

## **2.6 KVM-\>TUN 逐阶段对比**

| 阶段 | 描述 | SMTX OS (us) | ZBS (us) | 倍数 |
| :---- | :---- | :---- | :---- | :---- |
| S0 | ioeventfd \-\> handle\_tx\_kick | **11.3** | **86.5** | **7.7x** |
| S1 | handle\_tx\_kick \-\> tun\_sendmsg | 7.0 | 6.5 | 0.9x |
| S2 | tun\_sendmsg \-\> netif\_receive\_skb | 6.5 | 5.2 | 0.8x |
| **Total** | S0+S1+S2 | **24.8** | **98.1** | **4.0x** |

## **2.2 逐段落对比**

| 段落 | 描述 | SMTX OS (us) | ZBS (us) | 差异 (us) | 倍数 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **A** | 发送方 VM TX 协议栈 | 18.2 | 16.8 | \-1.4 | 0.9x |
| **B** | 发送方宿主机内部 TX | 13.5 | 17.1 | \+3.6 | 1.3x |
| **D** | 接收方宿主机内部 RX | 12.7 | 12.8 | \+0.1 | 1.0x |
| **E** | 接收方 vhost-\>KVM | **42** | **120** | **\+78** | **2.9x** |
| **F** | 接收方 VM RX 协议栈 | 24.3 | 28.3 | \+4.0 | 1.2x |
| **G** | 接收方 VM ICMP 处理 | 8.4 | 6.2 | \-2.2 | 0.7x |
| **H** | 接收方 VM TX 协议栈 | 7.3 | 5.9 | \-1.4 | 0.8x |
| **I** | 接收方宿主机内部 TX | 9.4 | 17.5 | \+8.1 | 1.9x |
| **K** | 发送方宿主机内部 RX | 8.3 | 13.6 | \+5.3 | 1.6x |
| **L** | 发送方 vhost-\>KVM | **38** | **105** | **\+67** | **2.8x** |
| **M** | 发送方 VM RX 协议栈 | 15.7 | 17.2 | \+1.5 | 1.1x |

## **2.3 三段式高层延迟分解**

使用第 1.4 节的计算方法：

**原始测量值**：

| 指标 | SMTX OS | ZBS |
| :---- | :---- | :---- |
| VM\_Sender\_Total（来自 kernel\_icmp\_rtt） | 226.8 us | 601.0 us |
| Sender\_External（来自 icmp\_drop\_detector） | 144.1 us | 429.7 us |
| Receiver\_Host\_Total（来自 icmp\_drop\_detector） | 113.4 us | 285.7 us |

**计算得到的段落**：

| 段落 | SMTX OS | ZBS | 差异 | 倍数 |
| :---- | :---- | :---- | :---- | :---- |
| **Sender\_Host\_Total** | 82.7 us | 171.3 us | \+88.6 us | **2.1x** |
| **Physical\_Network (C+J)** | 30.7 us | 144.0 us | \+113.3 us | **4.7x** |
| **Receiver\_Host\_Total** | 113.4 us | 285.7 us | \+172.3 us | **2.5x** |
| **VM\_Sender\_Total** | **226.8 us** | **601.0 us** | **\+374.2 us** | **2.7x** |

**验证**：

- SMTX OS: 82.7 \+ 30.7 \+ 113.4 \= 226.8 us   
- ZBS: 171.3 \+ 144.0 \+ 285.7 \= 601.0 us 

**总延迟增加的贡献（+374.2 us）**：

| 来源 | 增加量 | 占比 |
| :---- | :---- | :---- |
| 发送方宿主机 | \+88.6 us | 24% |
| 物理网络 | \+113.3 us | 30% |
| 接收方宿主机 | \+172.3 us | 46% |

## **2.4 详细指标对比**

| 指标 | SMTX OS | ZBS | 差异 | 倍数 |
| :---- | :---- | :---- | :---- | :---- |
| **发送方 VM 总 RTT** | **227 us** | **601 us** | **\+374 us** | **2.6x** |
| 发送方 VM Path 1 (A) | 18.2 us | 16.8 us | \-1.4 us | 0.9x |
| 发送方 VM Path 2 (M) | 15.7 us | 17.2 us | \+1.5 us | 1.1x |
| 发送方 VM Inter-Path | 192.9 us | 567.5 us | \+374.6 us | 2.9x |
| 接收方 VM 总 RTT | 40.0 us | 39.9 us | \-0.1 us | 1.0x |
| 发送方宿主机 External | 144.1 us | 429.7 us | \+285.6 us | 3.0x |
| 接收方宿主机 External | 91.3 us | 254.8 us | \+163.5 us | 2.8x |

## **2.5 vhost-\>KVM 逐阶段对比**

| 阶段 | 描述 | SMTX OS (us) | ZBS (us) | 倍数 |
| :---- | :---- | :---- | :---- | :---- |
| S1-\>S2 | tun\_net\_xmit \-\> vhost\_signal | **22** | **98** | **4.5x** |
| S2-\>S3 | vhost\_signal \-\> eventfd | 7 | 8 | 1.1x |
| S3-\>S4 | eventfd \-\> irqfd\_wakeup | 10 | 10 | 1.0x |
| S4-\>S5 | irqfd \-\> posted\_interrupt | 3 | 2 | 0.7x |
| **Total** | S1-\>S5 | **42** | **120** | **2.9x** |

---

# **第二部分：分析与结论**

## **3.1 关键发现与根因分析**

ZBS 环境的端到端 ping 延迟比 SMTX OS **高 2.6 倍**（601us vs 227us）。

## **3.2 根因定位**

延迟差异**主要集中在 vhost-\>KVM 中断注入路径**，特别是 **S1-\>S2 阶段**（tun\_net\_xmit 到 vhost\_signal）：

| 环境 | S1-\>S2 延迟 | vhost-\>KVM 总延迟 |
| :---- | :---- | :---- |
| SMTX OS | 22 us | 42 us |
| ZBS | 98 us | 120 us |
| **差异** | **\+76 us (4.5x)** | **\+78 us (2.9x)** |

## **3.3 各层延迟汇总**

### **3.3.1 VM 内部延迟汇总**

| 段落 | 描述 | SMTX OS | ZBS | 差异 |
| :---- | :---- | :---- | :---- | :---- |
| A | 发送方 VM TX 协议栈 | 18.2 us | 16.8 us | \-1.4 us |
| F | 接收方 VM RX 协议栈 | 24.3 us | 28.3 us | \+4.0 us |
| G | 接收方 VM ICMP 处理 | 8.4 us | 6.2 us | \-2.2 us |
| H | 接收方 VM TX 协议栈 | 7.3 us | 5.9 us | \-1.4 us |
| M | 发送方 VM RX 协议栈 | 15.7 us | 17.2 us | \+1.5 us |
| **VM Internal 总计** | A \+ F \+ G \+ H \+ M | **73.9 us** | **74.4 us** | **\+0.5 us** |

**结论**：VM 内部处理延迟在两个环境中**基本相同**（差异 \< 1 us）。

### **3.3.2 宿主机内部转发延迟汇总**

| 段落 | 描述 | SMTX OS | ZBS | 差异 |
| :---- | :---- | :---- | :---- | :---- |
| B | 发送方宿主机 TX (vnet→phy) | 13.5 us | 17.1 us | \+3.6 us |
| D | 接收方宿主机 RX (phy→vnet) | 12.7 us | 12.8 us | \+0.1 us |
| I | 接收方宿主机 TX (vnet→phy) | 9.4 us | 17.5 us | \+8.1 us |
| K | 发送方宿主机 RX (phy→vnet) | 8.3 us | 13.6 us | \+5.3 us |
| **Host Internal 总计** | B \+ D \+ I \+ K | **43.9 us** | **61.0 us** | **\+17.1 us** |

**结论**：宿主机内部转发延迟差异中等（+17.1 us, 5%），不是主要原因但值得注意。

### **3.3.3 虚拟化层延迟分析**

虚拟化层延迟分为 **VM RX 路径 (tun→KVM)** 和 **VM TX 路径 (KVM→tun)** 两部分：

**VM RX 路径 (tun\_net\_xmit → KVM IRQ)**：

| 段落 | 描述 | SMTX OS | ZBS | 差异 | 倍数 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| E | 接收方 tun→KVM (收 request) | 42 us | 120 us | \+78 us | 2.9x |
| L | 发送方 tun→KVM (收 reply) | 38 us | 105 us | \+67 us | 2.8x |
| **RX 路径总计** | E \+ L | **80 us** | **225 us** | **\+145 us** | **2.8x** |

**VM TX 路径 (KVM ioeventfd → tun\_net\_xmit)**：

| 段落 | 描述 | SMTX OS | ZBS | 差异 | 倍数 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| B\_1 | 发送方 KVM→TUN (发 request) | 24.8 us | 98.1 us | \+73.3 us | 4.0x |
| I\_1 | 接收方 KVM→TUN (发 reply) | \~25 us | \~98 us | \+73 us | \~4.0x |
| **TX 路径总计** | B\_1 \+ I\_1 | **\~50 us** | **\~196 us** | **\+146 us** | **\~4.0x** |

**虚拟化层延迟汇总**：

| 路径 | SMTX OS | ZBS | 差异 | 占总延迟增量比 |
| :---- | :---- | :---- | :---- | :---- |
| RX 路径 (tun→KVM) | 80 us | 225 us | \+145 us | 39% |
| TX 路径 (KVM→tun) | \~50 us | \~196 us | \+146 us | 39% |
| **虚拟化层总计** | **\~130 us** | **\~421 us** | **\+291 us** | **78%** |

**关键发现**：通过 KVM→TUN 测量数据，原先 "未测量的虚拟化部分" 现已基本明确：

1. **VM TX 路径延迟来源已确认**：KVM→TUN 测量显示 ZBS 的 S0 阶段（ioeventfd→handle\_tx\_kick）延迟为 86.5us，是 SMTX OS 11.3us 的 **7.7 倍**

2. **VM 内部 virtio 收发延迟可忽略**：
   - TX 路径：KVM→TUN 测量覆盖了从 ioeventfd 到 netif\_receive\_skb 的完整路径
   - S1 (handle\_tx\_kick→tun\_sendmsg) 和 S2 (tun\_sendmsg→netif) 在两环境基本相同
   - 说明 VM 内部 virtio TX 驱动处理无显著差异

3. **剩余未测量部分**：
   - KVM IRQ 注入后 → VM 唤醒 → virtio RX 驱动处理（E 结束到 F 开始、L 结束到 M 开始）
   - 推算：Receiver 侧 285.7 - (12.8 + 120 + 28.3 + 6.2 + 5.9 + 17.5 + 98) = \~0 us
   - 说明此部分延迟在两环境差异不大，主要延迟来源已被测量覆盖

**注**：由于各工具测量时间非同一时间采集，各部分相加可能与总和有差异，但总体分布比例可作为分析依据。

### **3.3.4 完整延迟差异归因**

将 374.2 us 的总延迟差异精确归因到各个层次：

| 层次 | 组成部分 | SMTX OS | ZBS | 差异 | 占比 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **VM Internal** | A \+ F \+ G \+ H \+ M | 73.9 us | 74.4 us | \+0.5 us | 0% |
| **Host Internal** | B \+ D \+ I \+ K | 43.9 us | 61.0 us | \+17.1 us | 5% |
| **Physical Network** | C \+ J | 30.7 us | 144.0 us | \+113.3 us | 30% |
| **Virt RX (tun→KVM)** | E \+ L | 80 us | 225 us | \+145 us | 39% |
| **Virt TX (KVM→tun)** | B\_1 \+ I\_1 | \~50 us | \~196 us | \+146 us | 39% |
| **总计** |  | **\~278 us** | **\~701 us** | **\~421 us** | **\>100%\*** |

**\*** 各部分测量非同一时间，总和超过实际 RTT 属正常。实际 RTT 约 227 us (SMTX OS) / 601 us (ZBS)，各部分占比可作为分析参考。

### **3.3.5 结论**

**1\. VM 内部处理**：两个环境几乎**完全相同**（差异 \< 1 us），可排除

**2\. 宿主机内部转发**：差异中等（+17.1 us, 5%），不是主要原因

**3\. 物理网络**：ZBS **高 4.7 倍**（+113.3 us, **30%**）- **显著贡献者**

- 这是重要发现 \- ZBS 物理网络延迟接近 SMTX OS 的 5 倍
- 可能原因：网络拓扑不同、bonding 配置、物理距离、交换机跳数等

**4\. 虚拟化层**：贡献了 **78%** 的延迟增量（\~291 us）

- RX 路径 (tun→KVM): \+145 us (39%)
- TX 路径 (KVM→tun): \+146 us (39%)

**5\. 虚拟化层延迟的核心问题**：

两条虚拟化路径的延迟问题定位到**同一根因** \-\- **vhost worker 线程唤醒延迟**：

| 路径 | 阶段 | SMTX OS | ZBS | 倍数 |
| :---- | :---- | :---- | :---- | :---- |
| tun→KVM | S1→S2 (tun\_net\_xmit → vhost\_signal) | 22 us | 98 us | **4.5x** |
| KVM→tun | S0 (ioeventfd → handle\_tx\_kick) | 11.3 us | 86.5 us | **7.7x** |

**两阶段的共同特征**：从数据包进入 vhost 子系统（RX 路径的 TUN ring buffer / TX 路径的 ioeventfd 信号）到 vhost worker 开始处理的时间显著增加。

### **3.4 vhost worker 唤醒路径分析**

#### **3.4.1 内核代码路径**

**RX 路径 (tun→vhost)**：
```
tun_net_xmit()
  → TUN ring buffer 写入
  → socket poll 机制触发
  → vhost_poll_wakeup()
    → vhost_poll_queue()
      → vhost_work_queue()
        → llist_add(&work->node, &dev->work_list)
        → wake_up_process(dev->worker)  // 唤醒 vhost worker
  → vhost_worker() 被调度执行
    → vhost_net_rx_handle_vq()
      → vhost_signal()  // S2 阶段开始
```

**TX 路径 (KVM→vhost)**：
```
VM virtio TX kick
  → KVM MMIO 处理
  → ioeventfd_write()
    → eventfd_signal(p->eventfd, 1)
      → 触发 vhost poll 回调
      → vhost_poll_wakeup()
        → vhost_poll_queue()
          → vhost_work_queue()
            → wake_up_process(dev->worker)  // 唤醒 vhost worker
  → vhost_worker() 被调度执行
    → handle_tx_kick()  // S0 阶段结束
```

#### **3.4.2 延迟来源定位**

两条路径共享相同的唤醒机制：`wake_up_process(dev->worker)` 到 vhost\_worker 实际开始执行。

延迟发生在 **vhost worker 进程调度阶段**，即从 `wake_up_process()` 调用到进程实际运行的时间差。

---

# **第四部分：根因验证与结论**

## **4.1 配置检查**

### **C-state 配置对比**

| 配置项 | SMTX OS (172.21.128.40) | ZBS (172.21.128.244) |
| :---- | :---- | :---- |
| **内核参数** | `intel_idle.max_cstate=0 processor.max_cstate=1` | 无 |
| **启用的 C-states** | POLL, C1 | POLL, C1, C1E, **C6** |
| **最大唤醒延迟** | 1us | **290us** |

### **C-state 使用统计（CPU 0）**

| 环境 | POLL | C1 | C1E | C6 |
| :---- | :---- | :---- | :---- | :---- |
| SMTX OS | 5100万次 | 144亿次 | - | - |
| ZBS | 115万次 | 346万次 | 32亿次 | **17.5亿次** |

ZBS 环境大量使用 C6 深度睡眠状态。

## **4.2 禁用 C6 验证**

### **禁用命令**
```bash
for cpu in /sys/devices/system/cpu/cpu*/cpuidle/state3; do
    echo 1 | sudo tee $cpu/disable > /dev/null
done
```

### **禁用后测量结果**

**KVM→TUN 延迟**：

| 阶段 | 禁用前 | 禁用后 | 改善 |
| :---- | :---- | :---- | :---- |
| S0 (ioeventfd → handle\_tx\_kick) | 86.5 us | **14.8 us** | **5.8x** |
| S1 (handle\_tx\_kick → tun\_sendmsg) | 6.5 us | 3.5 us | 1.9x |
| S2 (tun\_sendmsg → netif) | 5.2 us | 3.3 us | 1.6x |
| **Total** | **98.1 us** | **21.5 us** | **4.6x** |

**原始数据**：
```
[14:23:16.827] tid=73868 queue=2 s0=14us s1=5us s2=4us total=23us
[14:23:21.841] tid=73868 queue=2 s0=11us s1=3us s2=3us total=17us
[14:23:26.855] tid=73868 queue=2 s0=22us s1=3us s2=3us total=28us
[14:23:31.871] tid=73868 queue=2 s0=12us s1=3us s2=3us total=18us

Exact averages (us): S0=14.750, S1=3.500, S2=3.250, Total=21.500
```

**TUN→KVM 延迟**：
```
TUN TX [vnet2:q2] Stage 1: Time=05:28:58.266 Queue=2 CPU=36 ICMP 10.0.129.145->10.0.129.143 type=8
TUN TX [vnet2:q2] Stage 2: Time=05:28:58.266 Delay=0.016ms CPU=12 PID=73868
TUN TX [vnet2:q2] Stage 3: Time=05:28:58.266 Delay=0.008ms CPU=12 PID=73868
TUN TX [vnet2:q2] Stage 4: Time=05:28:58.266 Delay=0.010ms CPU=12 PID=73868
TUN TX [vnet2:q2] Stage 5: Time=05:28:58.266 Delay=0.001ms CPU=12 PID=73868
```

S1→S2 延迟从 98us 降至 16us，与 SMTX OS 基准环境（22us）相当。

## **4.3 结论**

### **根因确认**

**CPU C6 深度睡眠状态是 vhost worker 调度延迟的根本原因**

| 证据 | 说明 |
| :---- | :---- |
| 配置差异 | ZBS 启用 C6（290us），SMTX OS 禁用 |
| C6 使用率 | ZBS CPU 进入 C6 状态 17.5 亿次 |
| 禁用效果 | S0 延迟 86.5us → 14.8us（改善 5.8x） |
| 基准对比 | 禁用后延迟与 SMTX OS 相当 |

### **修复方案**

**临时修复**（立即生效，重启失效）：
```bash
for cpu in /sys/devices/system/cpu/cpu*/cpuidle/state3; do
    echo 1 | sudo tee $cpu/disable > /dev/null
done
```

**永久修复**：编辑 `/etc/default/grub`，添加：
```
intel_idle.max_cstate=1 processor.max_cstate=1
```
然后 `grub2-mkconfig -o /boot/grub2/grub.cfg && reboot`

### **其他说明**

- 部分 ZBS 环境可能在 BIOS 层面已禁用 C6，内核中不可见 state2/state3
- 物理网络延迟（144us vs 31us）需单独调查

---

*文档更新：2026-01-15*
*通过配置对比和禁用测试确认根因：ZBS 环境 C6 深度睡眠导致 vhost 调度延迟，禁用后 S0 从 86.5us 降至 14.8us*