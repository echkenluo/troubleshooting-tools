# Network Troubleshooting Tools - User Guide

---

## 目录

1. [背景与设计考量](#1-背景与设计考量)
2. [项目 Overview](#2-项目-overview)
3. [分析方法论](#3-分析方法论)
4. [实战应用](#4-实战应用)
5. [性能测试](#5-性能测试数据)
6. [总结](#6-总结)

---

## 1. 背景与设计考量

### 1.1 问题背景

虚拟化环境的网络架构复杂度给故障定位带来了巨大挑战。数据包从 VM 到物理网卡需要经过多个层次：

- VM 应用层 → VM 内核协议栈 → Virtio-net 驱动 -> vCPU(kvm)
- Vhost  → TUN 设备 → OVS Bridge
- 物理网卡队列 → 物理网卡 NIC Driver → 物理网络

**核心痛点**:

1. **组件众多**: 从 VM 到物理网卡涉及 10+ 层软件组件
2. **路径复杂**: TX/RX 双向路径、快速路径(fastpath)/慢速路径(slowpath)
3. **故障多样**: 丢包、延迟、抖动、吞吐量下降,原因难以定位
4. **量化困难**: 传统监控工具只能看非常宏观的指标,无法精确量化测量各种指标

**典型故障场景实例**:

- **场景 1**: VM 网络偶发丢包 (0.01%), 是网卡丢包还是 OVS 丢包？丢在哪个阶段？
- **场景 2**: ICMP 延迟突增至 200ms+，什么部分引入的高延迟？
- **场景 3**: OVS CPU 平均利用率 15%, 但业务报告周期性网络重传/高延迟抖动, 为什么？

### 1.2 设计目标与原则

针对上述痛点, 本工具集的设计遵循以下核心目标:

#### 目标 1: 轻量可控

严格的开销控制,确保工具在提供精确测量能力的同时,将对业务系统的影响降至最低。

##### eBPF 程序性能开销模型

相关性能开销概览

内核态：

- 内核 CPU 消耗 ：挂载 eBPF 后的数据路径要与 baseline 对比，不同 attach 类型
  （kprobe、tracepoint、fentry 等）和 JIT 状态决定进入/退出开销；程序内的 map 访问、helper 调用、尾调用等占主要变量成本。
- mem：BPF 程序镜像、JIT 产物、普通 map（ARRAY/HASH/LRU 等）、全局数据段都常驻内核。 占用大小与程序实现以及使用的 map 类型以及架构有关，per-cpu array 最占内存，但是最大占用在程序确定后可以确定。

 eBPF 程序对数据路径的性能影响主要由四部分组成:

**总延迟 = 进入开销 + 执行开销 + 提交开销 + 退出开销**

| 开销类型       | 时间范围                 | 主要因素              | 可优化性 |
| -------------- | ------------------------ | --------------------- | -------- |
| **进入** | 15-50 ns                 | Probe 类型选择        | 设计时   |
| **执行** | （10-2000 ns）* 指令数量 | 逻辑复杂度、Map 操作  | 设计时   |
| **提交** | 500-1000 ns              | 事件频率、Buffer 类型 | 运行时   |

* 事件提交开销占总开销的比例较高,是性能优化的核心目标。
* 程序本身逻辑复杂，即使用的指令越复杂，叠加总开销越大，且与总 probe 点数成正比。
* 最大内存在程序&&架构确认后可以确定，可调节部分 page_cnt (8 ~256)。 >5.4 支持 bpf ringbuf 内存更少。

用户态程序开销

- 内存：脚本本身 + 运行时库（libbcc/LLVM/Python VM 等）+ 与内核共享的 map/ringbuf/perf buffer 影子结构；
- CPU：事件消费线程需持续 poll + 解析 + 聚合/输出；高频事件时用户态缓存与解析
- logsize：总体约为 事件数 ×（事件数据结构 + 通道元数据）。事件数量取决于 eBPF 触发频率及过滤策略；若写文件或远端日志，还要考虑 I/O 对应用的影响。

结论：

* 开销与提交到 userspace 部分的事件数量以及速率高度相关；
* 用户态缓存以及 log 实现需要合理设计

#### 目标 2: 简单易用

- **单工具单职责**: 每个工具聚焦特定问题域(丢包/延迟/OVS/虚拟化)
- **开箱即用**: 参数设计直观,支持 IP/端口/协议过滤
- **输出清晰**: Histogram 统计 + 详细事件,满足不同诊断阶段需求

**示例对比**:

```bash
# 传统方式: 需要组合多个工具 + 手动关联
tcpdump -i vnet0 | tee log1.txt  # 抓包
perf record -e skb:kfree_skb     # 丢包事件
bpftrace -e 'kprobe:ovs_dp_process_packet {...}' # OVS 跟踪
# 然后手动分析日志,时间戳关联...

# 本工具集: 一键获取结构化数据
sudo python3 kernel_drop_stack_stats_summary_all.py \
    --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --l4-protocol tcp --interval 60
```

#### 目标 3: 模块化与可组合性

基于虚拟化网络的分层架构,工具按功能域和网络层次组织,支持灵活组合使用:

提供 **30+ eBPF 工具**,覆盖虚拟化网络的 **全链路监控/测量**:

**工具覆盖范围 (按网络层次)**:

- **VM 层**: virtio-net/ (4 工具) - NAPI 轮询、RX 路径跟踪
- **vhost 层**: vhost-net/ (5 工具) - 事件通知、队列关联、线程唤醒
- **TUN/TAP 层**: tun/ (4 工具) - 环形缓冲区监控、GSO 类型检测
- **OVS 层**: ovs/ (6 工具) - Upcall 延迟、Megaflow 跟踪、丢包分析
- **Linux 网络栈**: linux-network-stack/ (8 工具) - 丢包栈统计、队列跟踪
- **性能测量**:
  - system-network/ (4 工具) - 系统网络延迟与性能指标测量
  - vm-network/ (4 工具) - VM 网络延迟分析与性能指标测量
- **CPU/调度分析**: cpu/ (5 工具) - Off-CPU 分析、锁监控、进程 cpu 测量，cpu 热点

## 2. 项目 Overview

### 2.1 工具全景图

**分层清晰的工具分类**:

```
measurement-tools/
├── performance/                    # 性能测量
│   ├── system-network/             # 系统网络路径
│   │   ├── *_summary.py            # Summary 版本
│   │   └── *_details.py            # Details 版本
│   └── vm-network/                 # VM 网络路径
│       ├── *_summary.py
│       └── *_details.py
├── linux-network-stack/            # Linux 协议栈
│   └── packet-drop/                # 丢包分析
│       ├── kernel_drop_stats_summary_all.py  # Summary
│       └── eth_drop.py             # Details
├── ovs/                            # Open vSwitch
│   ├── ovs_upcall_latency_summary.py
│   └── ovs_userspace_megaflow.py
├── kvm-virt-network/               # KVM 虚拟化
│   ├── vhost-net/                  # vhost 内核加速
│   ├── virtio-net/                 # virtio 驱动
│   ├── tun/                        # TUN/TAP 设备
│   └── kvm/                        # KVM 相关逻辑
└── cpu/                            # CPU 分析
    ├── offcputime-ts.py            # Off-CPU 时间
    └── pthread_rwlock_wrlock.bt    # 锁分析
```

---

## 3. 分析方法论

### 3.1 三层诊断模型

**第一层: 问题定位 (Summary 工具)**

目标: 快速识别异常范围

- 方法: Histogram 统计、宏观指标
- 输出: 延迟分布 (P50/P95/P99/P999)、丢包统计、流表命中率
- 性能: 极低开销,可持续运行
- 时长: 小时 - 天

示例问题:

- "网络偶有卡顿" → 使用 latency_summary 发现 P99.9 = 150ms
- "丢包率 0.01%" → 使用 drop_summary 发现丢在 tun_net_xmit

**第二层: 精确追踪 (Details 工具)**

目标: 定位具体瓶颈、捕获上下文

- 方法: Per-packet 跟踪 + 过滤器
- 输出: 单包完整路径时间戳、各阶段处理延迟、五元组信息、cpu/队列等等中间状态 metadata
- 性能: 开销可调节,取决于过滤粒度
- 时长: 取决于环境 workload && 过滤条件设定

过滤器策略:

- 针对特定 IP/端口 → 降低需经过全部快速路径逻辑事件量
- 延迟阈值过滤 (>100ms) → 仅捕获异常事件

示例问题:

- 知道 P99.9 慢,但不知道慢在哪个阶段，或者某个阶段内部的何种处理逻辑
  → latency_details + 阈值过滤 100ms
  → 捕获 3 个事件,发现都慢在 OVS FLOW_EXTRACT 阶段

**第三层: 根因分析 (专项工具 + 系统工具)**

目标: 深挖底层原因 (CPU/锁/队列/内存)，针对特定进程/模块的特定类型问题

- 方法: Off-CPU 分析、锁监控、调度跟踪
- 输出: Off-CPU 火焰图、锁竞争热点、调度延迟分布
- 性能: 开销取决于具体工具和使用场景
- 时长: 秒 - 分钟 (精确定位阶段)

工具组合:

- offcputime-ts.py → 发现 handler 线程 187ms off-CPU
- pthread_rwlock_wrlock.bt → 定位到 fat_rwlock 锁等待
- t → 确认进入 mutex 慢速路径

示例问题:

- OVS 阶段慢 221ms,但 CPU 使用率正常
  → offcputime 发现大量 off-CPU 时间
  → pthread_rwlock 发现 revalidator 持有写锁 200ms

### 3.2 诊断决策流程

```
                    [网络问题症状]
                          |
          ┌───────────────┼───────────────┐
          |               |               |
        丢包            延迟高           吞吐量低
          |               |               |
          v               v               v
    ┌─────────┐     ┌─────────┐     ┌─────────┐
    │ Layer 1 │     │ Layer 1 │     │ Layer 1 │
    │ Summary │     │ Summary │     │ Summary │
    └────┬────┘     └────┬────┘     └────┬────┘
         |               |               |
         v               v               v
    丢在哪里?       慢在哪个阶段?      瓶颈在哪层?
         |               |               |
         v               v               v
    ┌─────────┐     ┌─────────┐     ┌─────────┐
    │ Layer 2 │     │ Layer 2 │     │ Layer 2 │
    │ Details │     │ Details │     │ Details │
    └────┬────┘     └────┬────┘     └────┬────┘
         |               |               |
         v               v               v
    具体哪个包?     具体多慢?        具体什么问题?
         |               |               |
         └───────────────┼───────────────┘
                         v
                    ┌─────────┐
                    │ Layer 3 │
                    │  专项   │
                    └────┬────┘
                         v
                    CPU/锁/调度
                    根因确认
```

---

## 4. 实战应用

### 4.1 单工具使用示例

#### 示例 1: kernel_drop_stack_stats_summary_all.py

**场景**: 系统报告 ICMP 丢包,需要确认真实丢包量和丢包位置

**命令**:

```bash
sudo python3 measurement-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --l4-protocol icmp \
  --interval 60 \
  --duration 1800 \
  --top 10
```

**输出解读**:

```
[2025-10-20 10:45:00] === Drop Stack Statistics (Interval: 60.0s) ===

Found 2 unique stack+flow combinations:

#1 Count: 23 calls [device: br-int] [stack_id: 127]
   Flow: 10.132.114.11 -> 10.132.114.12 (ICMP)
Stack trace:
  kfree_skb+0x1 [kernel]
  ip_rcv_core+0x1a2 [kernel]        ← 丢包位置: IP 层
  ip_rcv+0x2d [kernel]
  __netif_receive_skb_core+0x677

分析: IP 层丢包,可能原因是 TTL 超时或路由失败

#2 Count: 8 calls [device: ens11] [stack_id: 234]
   Flow: 10.132.114.11 -> 10.132.114.12 (ICMP)
Stack trace:
  kfree_skb+0x1 [kernel]
  __dev_queue_xmit+0x7a2 [kernel]   ← 丢包位置: TX 队列
  dev_queue_xmit+0x10

分析: TX 队列溢出,可能是 qdisc 满或网卡忙

Total drops in 30 min: 31 packets (0.17% of 18,000 sent)
```

**关键发现**: 真实内核丢包模块/位置

#### 示例 2: vm_network_latency_summary.py

**场景**: 需要建立 VM 网络延迟 baseline,分析各阶段延迟分布

**命令**:

```bash
sudo python3 measurement-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 \
  --phy-interface ens11 \
  --src-ip 172.21.153.114 \
  --dst-ip 172.21.153.113 \
  --direction tx \
  --protocol tcp \
  --interval 1
```

**输出解读**:

```
================================================================================
[2025-10-24 10:31:57] Adjacent Stage Latency Report (Interval: 1.0s)
================================================================================
Found 6 unique stage pairs

VM TX (VM->External):
------------------------------------------------------------

  VNET_RX -> OVS_RX:
    Total samples: 9
    Latency distribution:
      1-1us       :      2 |**************************              |
      2-3us       :      2 |**************************              |
      4-7us       :      3 |****************************************|
      8-15us      :      2 |**************************              |

  OVS_RX -> FLOW_EXTRACT_END_RX:
    Total samples: 9
    Latency distribution:
      1-1us       :      2 |*************                           |
      2-3us       :      6 |****************************************|
      4-7us       :      1 |******                                  |

  FLOW_EXTRACT_END_RX -> QDISC_ENQ:
    Total samples: 9
    Latency distribution:
      2-3us       :      4 |********************************        |
      4-7us       :      5 |****************************************|

  QDISC_ENQ -> QDISC_DEQ:
    Total samples: 8
    Latency distribution:
      2-3us       :      3 |************************                |
      4-7us       :      5 |****************************************|

  QDISC_DEQ -> TX_QUEUE:
    Total samples: 8
    Latency distribution:
      2-3us       :      5 |****************************************|
      4-7us       :      3 |************************                |

  TX_QUEUE -> TX_XMIT:
    Total samples: 8
    Latency distribution:
      2-3us       :      8 |****************************************|

Packet Counters:
  VM TX packets: 17
  VM RX packets: 0

Flow Session Analysis (Counter-based):
  VM TX started: 8, completed: 8, incomplete: 0
  VM RX started: 0, completed: 0, incomplete: 0
  Currently active flow sessions: 0

Total End-to-End Latency Distribution (First Stage -> Last Stage):
------------------------------------------------------------
  4-7us       :      3 |************************                |
  16-31us     :      5 |****************************************|

分析:
• 多阶段延迟分解: 从 VNET_RX 到 TX_XMIT,完整展示 VM 发送路径各阶段延迟
• VNET_RX -> OVS_RX: 主要在 4-7us,反映 vhost-net 到 OVS 的传输延迟
• OVS_RX -> FLOW_EXTRACT_END_RX: 多数在 2-3us,OVS 流提取效率高
• QDISC 队列处理: 延迟稳定在 2-7us 范围
• 端到端延迟: 主要集中在 16-31us,性能良好
• 会话跟踪: 8 个 TX 会话全部完成,无丢包
```

**关键发现**:

- 提供了完整的 VM 网络数据路径各阶段延迟分布
- 可精确识别各段延迟贡献,快速定位性能瓶颈
- 会话级跟踪确保数据包完整性分析

#### 示例 3: tun_ring_monitor.py

**场景**: VM 网络间歇性不通,怀疑 TUN/TAP 设备队列问题

**命令 1: 监控 ring full 事件** (默认模式,仅在队列满时输出):

```bash
sudo python2 measurement-tools/kvm-virt-network/tun/tun_ring_monitor.py --device vnet246
```

**输出解读 (ring full 检测)**:

```
================================================================================
TUN RING FULL DETECTED!
Time: 07:23:34.419
Process: handler15 (PID: 5562)
Device: vnet246
Queue: 6
SKB Address: 0xffff919b51986800

Struct Layout Analysis:
  tfiles array size: 2048 bytes
  numqueues offset: 2048 bytes
  Expected tfiles size: 2048 bytes (256 pointers * 8)
  Layout correct: tfiles takes exactly 2048 bytes
  Array access: queue_mapping=6 -> tfiles[6]

Validation Info:
  TUN struct: 0xffff91b6e8b2cac0
  TUN numqueues: 8
  TFile ptr: 0xffff919a709f7000
  TFile queue_index: 6

5-Tuple Info:
  Packet headers not parsed (may be non-IP or parsing failed)
  Source: N/A:N/A
  Destination: N/A:N/A
  Protocol: N/A

PTR Ring Details:
  Size: 1000
  Producer: 999
  Consumer Head: 12
  Consumer Tail: 999
  Queue[Producer] Ptr: 0xffff919b51986800 (非 NULL!)
  Status: FULL (queue[producer] != NULL)
================================================================================

分析:
• Ring Full 检测: queue[producer] != NULL,表明队列已满
• Queue 6 满载: Producer(999) 追上 Consumer Tail(999),queue[producer] 仍有数据
• Consumer 滞后: Consumer Head(12) 远落后于 Tail(999),消费速度慢
• 队列利用率: 100% 满载,vhost-net 无法继续写入
• 根因方向: VM 内部 Queue 6 未及时消费数据
```

**命令 2: 监控所有事件** (使用 --all 查看正常状态):

```bash
sudo python2 measurement-tools/kvm-virt-network/tun/tun_ring_monitor.py --device vnet246 --all
```

**输出解读 (正常状态)**:

```
================================================================================
TUN Ring Status
Time: 07:23:34.419
Process: handler15 (PID: 5562)
Device: vnet246
Queue: 6
SKB Address: 0xffff919b51986800

Struct Layout Analysis:
  tfiles array size: 2048 bytes
  numqueues offset: 2048 bytes
  Expected tfiles size: 2048 bytes (256 pointers * 8)
  Layout correct: tfiles takes exactly 2048 bytes
  Array access: queue_mapping=6 -> tfiles[6]

Validation Info:
  TUN struct: 0xffff91b6e8b2cac0
  TUN numqueues: 8
  TFile ptr: 0xffff919a709f7000
  TFile queue_index: 6

5-Tuple Info:
  Packet headers not parsed (may be non-IP or parsing failed)
  Source: N/A:N/A
  Destination: N/A:N/A
  Protocol: N/A

PTR Ring Details:
  Size: 1000
  Producer: 540
  Consumer Head: 540
  Consumer Tail: 528
  Queue[Producer] Ptr: 0x0
  Status: Available (queue[producer] == NULL), 1% used
================================================================================

分析:
• 正常状态: queue[producer] == NULL,队列有空闲空间
• 低利用率: 仅 1% 使用,Producer/Consumer 正常工作
• 数据流动: Consumer Tail(528) 略落后于 Head(540),正在处理中
```

**关键发现**:

- **默认模式**: 仅在检测到 ring full 时输出,适合长期监控异常情况
- **--all 模式**: 显示所有 TUN 传输事件,用于观察队列正常运行状态
- **精确队列级隔离**: 可定位到具体哪个队列 (Queue 6) 出现问题
- **内核数据结构验证**: 自动验证 tun_struct 布局,确保测量准确性
- **根因定位**: ring full 表明 VM 内部消费不足,需进一步检查 VM NAPI 处理

### 4.2 复杂问题实战: 案例研究

#### 案例 1: 系统网络 ICMP "丢包" 根因分析 - 延迟误判问题

**完整诊断流程** (详见 troubleshooting-practice.md 案例 1):

**问题描述**:

- 监控报告: ICMP 丢包率 1/10000 (200ms 超时阈值)
- 业务影响: 持续存在，无明显规律
- 环境: ELF 平台
- 流量: 10.132.114.11 ↔ 10.132.114.12, ICMP ping

**1. 真实丢包 vs 高延迟区分**

工具: eth_drop.py icmp 丢包测量（可用 drop summary 工具）
运行时长: 长期监控
结果:

- 真实内核丢包:  < 20 packets
- 监控"丢包": 234 packets,
- 差异: 214 packets → 高延迟超时!
  结论: 问题不是丢包,是持续存在少量高延迟包

**2. 延迟阶段来源定位：系统网络数据路径延迟分布**

工具: system_network_latency_summary.py
结果:

- P99: 89 us (正常)
- 超过 200ms 的包:  延迟 > 200ms  200 pkt +
- 延迟集中阶段: OVS_UPCALL → FLOW_EXTRACT_END_RX
  结论: OVS 处理阶段偶发极端延迟

**3. ovs upcall 延迟分析**

工具: ovs_upcall_latency_summary.py
结果:

- P50: 65 us (正常)
- P95: 289 us (可接受)
- p99.99: 234,542 us = 254ms (异常!)
- Max: > 2s (远超过阈值)
  结论: Upcall 处理有极端长尾延迟

**4. 精确事件捕获**

工具: system_network_icmp_rtt.py --threshold 200ms
结果: 捕获若干个高延迟事件

- Event #1: 10:28:42.567 → 10:28:42.789 (221ms)
- Event #2: 10:29:15.234 → 10:29:15.521 (287ms)
- Event #3: 10:31:08.123 → 10:31:08.412 (289ms)
- ......

共同特征:

- 都在 OVS_UPCALL -> 下发 flow 阶段
- 处理进程: handler23 (ovs-vswitchd)
- CPU: 始终在 CPU 12
  结论: 获得精确时间戳,可关联其他监控数据

**5. ovs 进程 CPU/调度分析**

工具 1:  cpu_monitor，长时间部署测量 1s 级别 ovs cpu 利用率以及相应时间段进程现场 （perf）
发现:

* 高延迟时间点与 ovs cpu 高 cpu 利用率时间点完全一致

工具 2: offcputime-ts.py -p $(pgrep ovs-vswitchd)
发现:

- handler23 线程 off-CPU: 187ms, 203ms
- 原因: 多线程绑定到单个 cpu，多线程对某些临界区较大，多线程活跃时可能导致调度混乱，handler && 主线程反复获取写锁 → 反复来回调度，且在 spin + sched_yeild 阶段，大量自旋开销加极少量业务逻辑 。
- 结论: 大量时间在等锁,非计算密集，锁慢速路径开销占据主导。需要改变 cpu 绑定模式，不同线程可调度到不同 cpu ，同环境可极大缓解该问题

**解决方案与验证**:

需要改变 cpu 绑定模式，不同线程可调度到不同 cpu ，同环境可极大缓解该问题

**关键经验**:

1. 区分真实丢包 vs 高延迟超时 (Summary 工具验证)
2. Histogram 长尾识别 (P99.9 vs P50)
3. 精确事件捕获 + 时间戳关联
4. 多层深入: 网络 → CPU → ovs多线程同步 -> 锁实现慢速路径 && 调度
5. Off-CPU 分析: CPU 使用率高 ≠ 计算密集
6. 已有监控盲区: 15s 粒度遗漏 ～s burst

---

#### 案例 2: VM 网络间歇性不通 - virtio-net 中断风暴根因分析

**问题背景**:

环境:

- 虚拟化平台: OpenStack + KVM/QEMU (ARM64)
- 网络层: OVS → TAP/TUN → vhost-net → virtio-net
- VM 网卡: eth0 (8 个 RX 队列)

症状:

- VM 内部网络间歇性不通
- SSH 连接非连续性断连
- 持续数分钟后自动恢复
- 不定期随机出现

初步线索:

- 宿主机 vnet37 设备存在丢包
- VM 内核日志偶尔出现中断相关告警

**诊断流程** (8 层递进式分析):

**1.  宿主机丢包定位**

- 工具: kernel_drop_stack_stats_summary.py
- 发现: 100% 丢包集中在 tun_net_xmit 路径,调用栈完全一致
- 结论: vhost-net 写 tfile->tx_ring 失败 → ring full

**2. TUN ring 详细监控**

- 工具: tun_ring_monitor.py
- 发现: Queue 2 的 tfile->tx_ring 持续满载,其他 7 个队列完全正常
- 结论: VM 内部 RX Queue 2 不消费数据

**3. vhost-net 线程行为分析**

- 工具: vhost_queue_correlation_details.py
- 发现: vhost 正常写入 vring,但 Guest 设置 avail_flags = NO_INTERRUPT
- 结论: "死锁"状态 - ring满 → 无中断 → Guest不消费

**4. VM NAPI poll 监控**

- 工具: virtnet_poll_monitor.py (VM 内部)
- 发现: Queue 2 完全无 NAPI 处理,其他队列正常
- 结论: Queue 2 中断处理被禁用或中断未到达

**5. VM 内核日志分析** ← 关键发现!

- 操作: dmesg | grep -i "irq"
- 发现: 内核保护机制触发
  ```
  [kernel] irq 69: nobody cared
  [kernel] handlers: vring_interrupt [virtio_ring]
  [kernel] Disabling IRQ #69 ← IRQ 被禁用!
  [kernel] virtio_net: IRQ 69 disabled for input.2-rx
  ```
- /proc/interrupts 确认: 69: 987654 ... 0 GIC-0 input.2-rx (DISABLED)
- 结论: Linux IRQ storm 保护机制触发,vring_interrupt 返回 IRQ_NONE 过多 → 禁用 IRQ

****外部数据: Kylin 工具报告持续存在： vring_interrupt 次数 > idx 增量， 并且排除 ring buf 回环问题，二次确认测量代码无误**
*

**6. 交叉验证 - 排除宿主机侧"空中断"**

- 验证 1 (vhost_queue_correlation_details.py): vhost_signal 8,234 次 = vring idx 更新 8,234 次,  1:1 对应
- 验证 2 (kvm_irqfd_stats_summary_arm.py): irqfd_wakeup 8,234 = vgic_v3_populate_lr 8,234,KVM 无重复注入
- 自研工具验证: 实际中断 8,567 vs Kylin 报告 10,123 (偏差 18%),IRQ_NONE 比例 10.3%
- 结论: 宿主机侧无问题

**7. IRQ_NONE 详细分析 （vm 内部数据重新测量分析）**

- 工具: trace_int_final.bt && virtionet-rx-path-summary.bt (VM 内部)
- 发现: IRQ_NONE 持续存在,平时 5-8% (正常),问题期 10-20% (超阈值)；中断触发 polling 次数显著多于 napi polling 总调用次数；
- 原因: used_idx == last_used_idx (vring 无新数据)
- 触发问题: 短时间达到 99,900/100,000 阈值则触发保护
- IRQ_NONE 产生原因: Host 更新 idx → 发送中断 → 但 Guest 已提前读取 idx （提前 polling）→ 中断到达时发现已处理 → 返回 IRQ_NONE
- 结论: Kylin 工具有偏差, 测量数据失真导致误判为 host 多发无效中断；并且存在非中断触发 virtnet_poll, 需要找出谁在"抢先消费"数据,

**8. 调用栈分析 - 定位根因!**

- 工具: virtnet_poll_stack_stats.py (VM 内部)
- 发现: 84% virtnet_poll 来自 napi_busy_loop!
- 调用栈统计 (45,678 次 virtnet_poll):
  - 正常中断路径 (net_rx_action): 7,234 (5.8%)
  - napi_busy_loop 路径: 38,444 (94.2%)
- busy_loop 调用链: 用户态 → tcp_recvmsg → sk_busy_loop → napi_busy_loop → virtnet_poll (绕过中断!)
- 时序冲突: busy_loop 主动调用 virtnet_poll 处理包后,中断到达时发现数据已处理,返回 IRQ_NONE
- 参数验证: sysctl net.core.busy_poll = 50 ← 启用了 busy poll!
- 根因确认: SO_BUSY_POLL + 中断竞争 → IRQ storm

**完整因果链**:

```
VM 应用启用 SO_BUSY_POLL (net.core.busy_poll=50)
→ 用户态频繁主动调用 napi_busy_loop (94% 的 poll 调用)
→ busy_loop 抢先处理 vring 数据 (比中断更快)
→ 中断到达时发现数据已处理 (used_idx == last_used_idx)
→ vring_interrupt 返回 IRQ_NONE
→ spurious interrupt 比例达到 10-20%
→ 短时间内累积到 99,900/100,000 阈值
→ 内核触发保护: "irq 69: nobody cared"
→ 内核禁用该 IRQ
→ Queue 2 彻底失效,无法接收数据
→ tfile->tx_ring 持续 full (宿主机侧)
→ 宿主机丢包,VM 网络不通
```

**解决方案与验证**:

```bash
# 修复方案 1: 禁用 busy_poll (推荐)
sysctl -w net.core.busy_poll=0
sysctl -w net.core.busy_read=0

# 修复方案 2: 增大 busy_poll 延迟 (减少轮询频率)
sysctl -w net.core.busy_poll=500  # 50us → 500us

# 持久化配置
cat >> /etc/sysctl.conf <<EOF
net.core.busy_poll = 0
net.core.busy_read = 0
EOF
```

**关键经验**:

1. 调用栈 100% 一致性: 立即排除随机因素,聚焦系统性原因
2. 队列级别隔离: 单队列问题快速缩小排查范围
3. 内核日志优先级: dmesg 的 "nobody cared" 是关键线索
4. 交叉验证外部数据: 发现第三方工具偏差,避免误判
5. 理解内核保护机制: IRQ storm protection 的阈值和触发条件
6. 时序分析: busy_poll 与中断的竞争关系
7. 用户态参数影响: sysctl 参数会显著影响内核行为
8. 工具组合模式: Summary → Details → 系统日志 → 参数验证
9. 双向交叉验证: 宿主机测量 ↔ VM 内部测量
10. 工具互补: BCC Python (灵活过滤) + bpftrace (快速原型)

---

## 5. 性能测试

延迟：直接体现，datapath 中新增测量逻辑所占用 cpu 时间，直接体现在每 packet 延迟

吞吐/pps：非直接体现，新增测量逻辑不直接影响数据路径端到端 pipeline 吞吐，增加单包处理所需 cpu 资源，该压力反压到上游，间接影响端到端性能

### 5.1 关键性能数据点

本节展示标志性的性能测试数据,说明不同类型工具的性能特征:  1) throughput / pps: 1 && 4 stream（4 进程）；2）latency： udp_rr && tcp_rr

#### 1. Summary 工具: 性能开销极小,对 workload 影响极小

**工具**: vm_network_latency_summary.py

测试结果:

| 指标              | 无工具基线 | 运行工具       | 变化  | 分析                   |
| ----------------- | ---------- | -------------- | ----- | ---------------------- |
| CPU 使用率 (avg)  | -          | 0% ~ 0.06%     | + <1% | 极低开销               |
| CPU 使用率 (峰值) | -          | 4.0%           | +4.0% | 峰值仍然很低           |
| 延迟影响          | 基线       | -0.29% ～ 3.7% |       | 性能轻微提升(误差范围) |
| 吞吐量影响        | 基线       | -              |       | 几乎无影响             |

**结论**:

Summary 工具采用内核侧聚合策略,仅定期提交统计数据而非每包提交,因此性能开销极小,可持续运行。

#### 2. Details 工具最坏情况: 大流量且所有包走完整路径并提交用户态

**工具**: trace_conntrack.py (无过滤器)

测试条件:

- 流量类型: TCP RX
- 所有包都执行完整 eBPF 测量逻辑
- 所有包都提交到用户态

测试结果:

| 指标       | 无工具基线 | 运行工具  | 变化    | 分析           |
| ---------- | ---------- | --------- | ------- | -------------- |
| 延迟影响   | 82.31 us   | 139.46 us | +69.46% | 显著延迟增加   |
| 吞吐量影响 | 基线       | 基线      | -35.19% | 吞吐量大幅下降 |

**结论**: 在最坏情况下(所有包都走完整逻辑并提交用户态),Details 工具对 workload 的性能影响最大。这种场景应避免在生产环境长期运行。

#### 3. 过滤器灵活控制 eBPF 程序开销及对 workload 的影响

**工具**: eth_drop.py / system_network_latency_details.py (带过滤器)

**过滤策略对比**:

| 过滤条件                   | 事件提交率 | CPU 开销估算 | 对业务影响 | 适用场景     |
| -------------------------- | ---------- | ------------ | ---------- | ------------ |
| 无过滤 (1M PPS)            | 1M evt/s   | ~50% CPU     | 高 (30%+)  | 禁止使用     |
| IP 过滤 (特定源/目标)      | ~10K evt/s | ~5% CPU      | 中 (5-10%) | 短期诊断     |
| 五元组过滤                 | ~1K evt/s  | ~0.5% CPU    | 低 (<2%)   | 针对性追踪   |
| 五元组 + 延迟阈值 (>100ms) | ~100 evt/s | <0.1% CPU    | 极低       | 异常事件捕获 |

**示例**: system_network_latency_details.py --threshold 200 (200us)

```bash
# 只捕获延迟超过 100ms 的异常事件
sudo python3 system_network_latency_details.py \
  --phy-interface ens11 \
  --src-ip 10.132.114.11 \
  --dst-ip 10.132.114.12 \
  --direction rx \
  --protocol icmp \
  --latency-threshold 200  
```

**过滤机制原理**:

- 在内核态尽早过滤,避免无效数据提交
- 协议过滤 → IP 过滤 → 端口过滤 → 阈值过滤
- 只有通过所有过滤器的包才会提交到用户态
- 绝大多数包在测量逻辑中提前返回

**结论**: 通过合理配置过滤条件,Details 工具的资源占用和对业务的影响可灵活调节,从而在精度和开销之间取得平衡。

#### 4. 多阶段整合提交配合过滤条件/阈值,进一步调节开销

**工具**: system_network_performance_metrics.py / vm_network_performance_metrics.py etc

**多阶段整合策略**:

1. 在多个 probe 点收集数据 (6-8 个关键点)
2. 通过唯一标识 key 关联不同阶段
3. 在最后阶段整合所有信息
4. 仅提交一次完整事件 (而非每个阶段都提交)

**结论**: 多阶段整合提交是 Details 工具在保持精确测量能力的同时控制性能开销的关键技术。配合过滤条件和阈值,可以将工具开销降至极低水平。

---

## 6. 总结

项目构建了一套 **轻量、精确、易用** 的 eBPF 网络故障排查工具集:

1. **三层诊断模型**

   - Summary (长期监控) + Details (精确追踪) + 专项工具 (根因分析)
   - 平衡性能开销与监控精度
2. **性能开销可控**

   - 基于 eBPF 性能模型的工程化实践
   - Summary: 极低开销,对业务性能影响极小
   - Details: 通过多级过滤和多阶段整合,资源占用灵活可调
3. **全链路覆盖**

   - VM → vhost → TUN/TAP → OVS → Linux 栈 → 物理网卡
   - 30+ 工具,按层次、按模块/组件分类
4. **精确测量**

   - 分阶段性能元数据测量
   - skb 关联,跨层追踪
   - 时间戳 + 调用栈：完整上下文
5. **实战验证**

   - 实战应用案例
   - 性能测试: Summary 工具可持续运行,Details 工具开销可调节

**从"无法观测"到"精确测量"**
**从"经验猜测"到"数据驱动"**
**从"事后救火"到"主动监控"**

---

## 附录

### A. 参考资料

#### 1. eBPF 权威书籍

**BPF Performance Tools**

- 作者: Brendan Gregg
- 出版: Addison-Wesley, 2019
- ISBN: 978-0136554820
- 评价: 最权威的 BPF 性能分析书籍
- 相关章节:
  - Chapter 2: Technology Background (探针类型开销)
  - Chapter 4: BPF Tools (性能测量方法)
  - Chapter 14: Networking (网络 BPF 性能)

**Linux Observability with BPF**

- 作者: David Calavera, Lorenzo Fontana
- 出版: O'Reilly, 2019
- ISBN: 978-1492050209
- 内容: BPF 内部实现和性能特性

#### 2. Linux 内核官方文档

**BPF 文档**

- 链接: https://www.kernel.org/doc/html/latest/bpf/
- 包含:
  - `bpf_design_QA.rst` - 设计和性能问答
  - `maps.rst` - Map 类型详解
  - `prog_sk_lookup.rst` - 程序类型

**Tracing 文档**

- 链接: https://www.kernel.org/doc/html/latest/trace/
- 包含:
  - `kprobes.rst` - kprobe 实现和开销
  - `tracepoints.rst` - tracepoint 设计
  - `ftrace.rst` - tracing 基础设施
  - `events.rst` - 事件跟踪和 buffer 配置

#### 3. 学术论文

**"The Performance Cost of Software-Based Packet Processing"**

- 会议: ACM SIGCOMM 2017
- 作者: Sebastiano Miano et al.
- DOI: 10.1145/3131365.3131367
- 关键结论: eBPF JIT 性能达到原生代码的 95-98%

**"Unleashing the Power of BPF for Network Function Virtualization"**

- 会议: SOSR 2020
- 内容: BPF 在网络场景的性能分析

#### 4. 内核开发资源

**Linux Kernel Mailing List (BPF)**

- 链接: https://lore.kernel.org/bpf/
- 内容: BPF 开发者讨论、性能改进 patch

**BPF Trampoline (fentry/fexit)**

- 主题: "[PATCH bpf-next 0/9] Introduce BPF trampoline"
- 作者: Alexei Starovoitov (BPF 维护者)
- 链接: https://lore.kernel.org/bpf/20191114185720.1641606-1-ast@kernel.org/
- 性能提升: 相比 kprobe 提升 2-4x

**BPF Ring Buffer**

- Commit: "bpf: Implement BPF ring buffer and verifier support"
- 作者: Andrii Nakryiko (Facebook)
- 链接: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=457f44363a88
- 性能提升: 相比 perf_buffer 快 1.8-2.1x

#### 5. 在线技术资源

**BCC GitHub Repository**

- 链接: https://github.com/iovisor/bcc
- 包含: 工具实现代码、性能测试、Reference Guide
- GitHub Issue #1751: "Performance comparison of probe types"

**Cilium Blog**

- 链接: https://cilium.io/blog/
- 推荐文章: "BPF extensions: fentry/fexit and trampoline"
  - https://cilium.io/blog/2020/02/18/bpf-intro-fentry-fexit/
  - fentry 性能: 相比 kprobe 提升 4x

**Brendan Gregg's Blog**

- 链接: https://www.brendangregg.com/blog/
- 推荐文章: "Linux uprobe: User-Level Dynamic Tracing"
  - https://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html
- 内容: eBPF 性能分析实战案例

**libbpf**

- 链接: https://github.com/libbpf/libbpf
- 说明: 现代 BPF 开发库,包含性能优化实现
