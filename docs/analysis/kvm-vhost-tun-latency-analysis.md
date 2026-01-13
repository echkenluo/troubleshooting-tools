# KVM-vhost-TUN 虚拟化延迟路径深度分析

## 文档概述

本文档是对跨节点 VM ping 延迟分析中 Host 侧未覆盖路径的深度调研分析：

**Host 侧**: KVM ioeventfd kick -> vhost handle_tx_kick -> tun_sendmsg -> netif_receive_skb

基于 `docs/cross-node-vm-ping-latency-analysis-cn.md` 中的测量方法论和结果。

**实现工具**:
- `kvm_vhost_tun_latency_details.py` - 输出每包精确延迟值
- `kvm_vhost_tun_latency_summary.py` - 输出延迟直方图统计

---

## 第一部分：延迟风险评估

### 1.1 结论

**Host 侧 KVM -> vhost -> tun 路径**更可能造成高延迟

### 1.2 对比分析

| 对比项 | VM 内部 virtio 驱动 | Host KVM->vhost->tun |
|--------|---------------------|---------------------|
| 主要开销 | CPU 密集型内存操作 | **调度+跨上下文切换** |
| 是否涉及调度 | 否 (softirq/进程连续执行) | **是** (vhost worker 线程调度) |
| 预期延迟范围 | 5-20 us | **20-100+ us** |
| NUMA 影响 | 低 | **高** |
| 批处理影响 | NAPI budget (64) | VHOST_NET_BATCH (64) |

### 1.3 实测数据支持

从 ZBS vs SMTX OS 对比数据：

| 指标 | SMTX OS | ZBS | 差异 |
|------|---------|-----|------|
| VM 内部 RTT (F+G+H) | 40.0 us | 39.9 us | -0.1 us (相同) |
| 接收方未测量部分 (U2+U3) | ~9 us | **95 us** | +86 us |
| vhost->KVM (E) | 42 us | 120 us | +78 us |

**结论**: VM 内部处理基本相同，差异主要在 Host 侧虚拟化路径。

---

## 第二部分：完整事件链

### 2.1 数据流概览

```
Guest 发包:
1. virtqueue_kick() -> 写入 ioeventfd (Guest 内部, MMIO/PIO)
   └─► 可能触发 VM Exit 或 Posted Write

Host 响应:
2. ioeventfd_write() [KVM 模块]           ◄── S0 起点
   └─► eventfd_signal(kick_ctx)
       └─► wake_up_locked_poll()
           └─► vhost_poll_wakeup()

3. vhost worker 唤醒 [调度延迟点!]
   └─► schedule() -> vhost_worker() 运行
       └─► node = llist_del_all(&dev->work_list)
       └─► work->fn(work) -> handle_tx_kick()  ◄── S0 终点 / S1 起点

4. handle_tx_kick() 处理
   ├─► vhost_net_tx_get_vq_desc() [批处理开始]
   │   └─► vhost_get_vq_desc() - 获取 desc 索引
   │       └─► 读取 vq->avail->ring[last_avail_idx]
   │       └─► 地址翻译: GPA -> HVA
   │
   ├─► copy_from_iter() - 从 Guest 复制数据 [主要开销]
   │
   └─► sock->ops->sendmsg()
       └─► tun_sendmsg()                       ◄── S1 终点 / S2 起点
           └─► tun_get_user() [skb 构建点]
               └─► netif_receive_skb()         ◄── S2 终点
```

### 2.2 延迟分段定义

| 段 | 起点 | 终点 | 含义 |
|----|------|------|------|
| S0 | ioeventfd_write | handle_tx_kick | **KVM kick -> vhost 调度延迟** |
| S1 | handle_tx_kick | tun_sendmsg | **vhost 处理到每包 sendmsg** |
| S2 | tun_sendmsg | netif_receive_skb | **TUN -> 网络栈** |

### 2.3 关键延迟因素

| 因素 | 描述 | 影响范围 |
|------|------|----------|
| vhost worker 调度 | 内核线程被唤醒到实际运行 | 10-100+ us |
| NUMA 访问 | worker 与 vCPU 不在同一 NUMA 节点 | 2-5x 增加 |
| Guest 内存访问 | GPA->HVA 翻译 + 可能的页错误 | 变化大 |
| 批处理积累 | 等待多个包后一起处理 | 取决于流量 |

---

## 第三部分：工具实现方案

### 3.1 两阶段测量设计

由于在 `tun_get_user` 构建 skb 之前无法按 5 元组过滤特定流量，采用**两阶段测量**方案：

**Phase 1 (discover)**: 识别目标流量
- 在 `netif_receive_skb` 处解析 skb 匹配目标 5 元组
- 记录携带目标流量的 vhost worker tid
- 建立 tid -> eventfd_ctx 映射关系
- 输出 profile 文件供 Phase 2 使用

**Phase 2 (measure)**: 精确测量
- 加载 Phase 1 的 profile 作为过滤条件
- 使用 eventfd_ctx 过滤 S0 起点
- 使用 tid 动态标记过滤 S1/S2
- 输出每包或汇总的延迟统计

### 3.2 关联链设计

```
eventfd_ctx 关联链:
  ioeventfd_write()
    └─► eventfd_signal(eventfd_ctx)     记录 current_eventfd
        └─► vhost_poll_wakeup(wait)     使用 current_eventfd
            └─► work_ptr -> eventfd_ctx 映射建立

  handle_tx_kick(work)
    └─► 通过 work_eventfd 查找 eventfd_ctx
    └─► 标记当前 tid 为 active

tid 关联链:
  handle_tx_kick -> tun_sendmsg -> netif_receive_skb
  (同一 vhost worker 线程，无调度切换)
```

### 3.3 FIFO 队列设计 (S2 单包关联)

即使无 NAPI，`tun_rx_batched` 仍可能批量提交 skb。使用 **per-tid FIFO** 维护时间戳：

```
S0 FIFO (per eventfd_ctx):
  - ioeventfd_write: push timestamp
  - handle_tx_kick: pop timestamp, calculate S0

S2 FIFO (per tid, aligned with S0/S1):
  - tun_sendmsg: push S2 start ts + S0/S1 values
  - netif_receive_skb: pop and emit latency
```

**FIFO 对齐原则**:
- `netif_receive_skb` **无论是否匹配目标流量都必须 pop**
- 若流量过滤失败（非目标流量），直接丢弃该样本
- 确保 FIFO 顺序不错位

### 3.4 两种输出变体

**Details 版本** (`kvm_vhost_tun_latency_details.py`):
- 通过 perf_buffer 输出每包精确延迟值
- 支持 `--no-detail` 参数仅输出汇总统计
- 适合精确分析单包延迟分布

**Summary 版本** (`kvm_vhost_tun_latency_summary.py`):
- 使用 BPF_HISTOGRAM 收集延迟分布
- 按 interval 输出直方图和统计值
- 适合长时间监控和对比测试

---

## 第四部分：Trace 点与 BPF 实现

### 4.1 使用的 Trace 点

**Phase 1 (discover)**:
```
kprobe:eventfd_signal          - 记录当前 eventfd_ctx
kretprobe:eventfd_signal       - 清除当前 eventfd_ctx
kprobe:vhost_poll_wakeup       - 建立 work -> eventfd 映射
kprobe:handle_tx_kick          - 建立 tid -> eventfd 映射
kprobe:netif_receive_skb       - 匹配流量，记录 tid
```

**Phase 2 (measure)**:
```
kprobe:eventfd_signal          - (同上)
kretprobe:eventfd_signal       - (同上)
kprobe:vhost_poll_wakeup       - 建立 work -> eventfd 映射
kprobe:ioeventfd_write         - S0 起点，push FIFO
kprobe:handle_tx_kick          - S0 终点 / S1 起点
kprobe:tun_sendmsg             - S1 终点 / S2 起点
kprobe:netif_receive_skb       - S2 终点，流量过滤
```

### 4.2 关键数据结构

```c
// eventfd_ctx 过滤 (从 Phase 1 profile 加载)
BPF_HASH(target_eventfd, u64, u8, 4096);

// 动态 TID 标记 (handle_tx_kick 时设置)
BPF_HASH(active_tid, u32, u8, 4096);

// eventfd_ctx 关联链
BPF_PERCPU_ARRAY(current_eventfd, u64, 1);
BPF_HASH(work_eventfd, u64, u64, 4096);

// S0 FIFO (per eventfd_ctx)
BPF_HASH(s0_state, u64, struct s0_state, 4096);
BPF_HASH(s0_ts, struct s0_slot_key, u64, 65536);

// S2 FIFO + S0/S1 值对齐 (per tid)
BPF_HASH(s2_state, u32, struct s2_state, 4096);
BPF_HASH(s2_ts, struct s2_slot_key, u64, 65536);
BPF_HASH(s0_val, struct s12_slot_key, u64, 65536);
BPF_HASH(s1_val, struct s12_slot_key, u64, 65536);
```

### 4.3 ioeventfd 结构体偏移

```c
struct _ioeventfd {
    struct list_head list;
    u64 addr;
    int length;
    struct eventfd_ctx *eventfd;  // 需要读取此字段
    u64 datamatch;
    struct kvm_io_device dev;     // ioeventfd_write 参数
    u8 bus_idx;
    bool wildcard;
};
```

通过 `container_of(dev, struct _ioeventfd, dev)` 获取 eventfd_ctx。

### 4.4 vhost_poll 结构体关联

```c
// 在 vhost_poll_wakeup 中
struct vhost_poll *poll = container_of(wait, struct vhost_poll, wait);
u64 work_ptr = (u64)&poll->work;
// 建立 work_ptr -> eventfd_ctx 映射
```

---

## 第五部分：工具使用

### 5.1 Phase 1: 流量发现

```bash
# 发现携带目标流量的 vhost worker
sudo python3 kvm_vhost_tun_latency_details.py \
    --mode discover \
    --device vnet94 \
    --flow "proto=udp,src=10.0.0.1,dst=10.0.0.2,sport=1234,dport=4321" \
    --duration 10 \
    --out profile.json
```

**输出示例**:
```
Device filter: vnet94
Discover mode: running for 10s

Debug counters:
  [0] eventfd_signal: 1523
  [1] vhost_poll_wakeup: 1523
  [2] work_eventfd_update: 1523
  [3] handle_tx_kick: 1523
  [4] work_eventfd_miss: 0
  [5] tid_eventfd_update: 1523
  [6] netif_receive: 15234
  [7] devname_match: 1523
  [8] ipv4_packet: 1523
  [9] flow_match: 1523
  [10] tid_info_update: 1523

Discovered TID -> Queue -> Eventfd associations:
     TID  Queue    Count             Eventfd
--------------------------------------------------
   12345      0     1523   0xffff9c8e8b1c8000
```

### 5.2 Phase 2: 延迟测量

**Details 版本 (每包输出)**:
```bash
sudo python3 kvm_vhost_tun_latency_details.py \
    --mode measure \
    --profile profile.json \
    --duration 30
```

**输出示例**:
```
[14:32:01.123] tid=12345 queue=0 s0=15us s1=3us s2=2us total=20us
[14:32:01.124] tid=12345 queue=0 s0=12us s1=2us s2=1us total=15us
...
========================================================================
[final] KVM -> vhost -> TUN latency totals
Total samples: S0=1523 S1=1523 S2=1523 chain(all)=1523
Total misses:  S0=0 S1=0 S2=0

Exact averages (us):
  S0 avg: 14.235
  S1 avg: 2.456
  S2 avg: 1.823
  S0+S1+S2 avg (per-packet): 18.514
```

**Summary 版本 (直方图输出)**:
```bash
sudo python3 kvm_vhost_tun_latency_summary.py \
    --mode measure \
    --profile profile.json \
    --interval 1 \
    --duration 30
```

**输出示例**:
```
========================================================================
[14:32:01] KVM -> vhost -> TUN latency
Interval samples: S0=152 S1=152 S2=152

S0: ioeventfd_write -> handle_tx_kick
     usec        : count     distribution
         0 -> 1  : 5        |*                                       |
         2 -> 3  : 12       |****                                    |
         4 -> 7  : 45       |***************                         |
         8 -> 15 : 78       |****************************************|
        16 -> 31 : 10       |***                                     |
        32 -> 63 : 2        |                                        |
  avg=8.2us  p50=9.5us  p90=18.2us  p99=42.1us  (n=152)
```

### 5.3 命令行参数

**通用参数**:
- `--mode {discover,measure}`: 工作模式
- `--device NAME`: 目标设备名 (如 vnet94)
- `--verbose`: 详细输出

**Discover 模式**:
- `--flow FILTER`: 流量过滤器 (proto=...,src=...,dst=...,sport=...,dport=...)
- `--out PATH`: profile 输出路径
- `--duration N`: 运行时长 (秒)

**Measure 模式**:
- `--profile PATH`: Phase 1 profile 路径
- `--duration N`: 运行时长 (秒)
- `--no-detail`: (details 版本) 禁用每包输出
- `--interval N`: (summary 版本) 输出间隔
- `--clear`: (summary 版本) 每间隔清空直方图

---

## 第六部分：关键指标解读

### 6.1 延迟分段含义

- **S0 (KVM kick -> vhost start)**: 最可能出现高延迟的段
  - 包含 vhost worker 调度延迟
  - 受 CPU 调度策略、NUMA 布局影响
  - 典型值: 5-50 us，异常可达 100+ us

- **S1 (vhost start -> tun_sendmsg)**: 批处理内处理开销
  - 包含 vhost 描述符处理、GPA->HVA 翻译、数据拷贝
  - 通常相对稳定: 1-5 us

- **S2 (tun_sendmsg -> netif_receive_skb)**: TUN 设备处理
  - 同步执行，无调度
  - skb 构建和网络栈入口
  - 通常很短: 1-3 us

### 6.2 异常诊断

| 现象 | 可能原因 | 排查方向 |
|------|----------|----------|
| S0 高且波动大 | vhost worker 调度延迟 | 检查 CPU 绑定、NUMA 布局 |
| S0 持续高 | worker 与 vCPU 跨 NUMA | 调整 vhost worker affinity |
| S1 异常高 | Guest 内存访问慢 | 检查内存大页、NUMA 分布 |
| S2 异常高 | TUN 设备问题 | 检查 GSO/GRO 配置 |
| FIFO underflow | 事件丢失或时序错位 | 检查过滤条件、RING_SZ |

---

## 第七部分：验证检查点

### 7.1 Phase 1 验证

- 发现至少一个有效的 tid -> eventfd 关联
- flow_match 计数与预期包数量一致
- work_eventfd_miss 计数应为 0 或很小

### 7.2 Phase 2 验证

- S0 <= S1 <= S2 样本数 (考虑过滤损失)
- FIFO underflow/overflow 计数为 0 或很小
- S2 样本数约等于目标流量包数

### 7.3 环境前提

- `tfile->napi_enabled` 未开启 (无 NAPI 线程)
- 未启用 RPS (不跨 CPU)
- 无设备重置或 vhost 重初始化

---

## 附录: 与其他工具的配合

### A.1 完整 RTT 分解

```
完整发送路径:
  [已有] icmp_send -> dev_queue_xmit           (kernel_icmp_rtt)
  [NEW]  ioeventfd_write -> netif_receive_skb  (kvm_vhost_tun_latency)
  [已有] tun_net_xmit -> phy TX                (icmp_drop_detector)

完整接收路径:
  [已有] phy RX -> vnet TX                     (icmp_drop_detector)
  [已有] tun_net_xmit -> KVM IRQ               (tun_tx_to_kvm_irq)
  [未测] KVM IRQ -> virtnet_poll               (需 vCPU 调度分析)
  [已有] napi_gro_receive -> icmp_rcv          (kernel_icmp_rtt)
```

### A.2 工具位置

```
measurement-tools/kvm-virt-network/vhost-net/
├── kvm_vhost_tun_latency_details.py  # 每包精确值
└── kvm_vhost_tun_latency_summary.py  # 直方图统计
```

---

*文档版本: 2.0*
*更新日期: 2026-01-13*
*基于: kvm_vhost_tun_latency_details.py / kvm_vhost_tun_latency_summary.py 最终实现*
