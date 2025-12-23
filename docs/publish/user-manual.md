# eBPF 网络故障排查工具 - 用户手册

## 1. 项目结构

项目按照系统组件和问题域进行模块化目录组织。主要结构由使用 Python（BCC）编写的 eBPF 工具和 bpftrace 脚本组成。

### 目录分类

```
ebpf-tools/
├── cpu/                              # CPU 和调度器监控工具
├── kvm-virtualization-network/      # KVM/QEMU 虚拟化网络栈工具
│   ├── kvm/                         # KVM 中断和 IRQ 监控
│   ├── tun/                         # TUN/TAP 设备监控
│   ├── vhost-net/                   # vhost-net 后端监控
│   └── virtio-net/                  # virtio-net 客户机驱动监控
├── linux-network-stack/             # Linux 内核网络栈工具
│   └── packet-drop/                 # 丢包检测和分析
├── other/                           # 其他跟踪工具
├── ovs/                             # Open vSwitch 监控工具
└── performance/                     # 网络性能监控
    ├── system-network/              # 系统级网络性能
    └── vm-network/                  # 虚拟机专用网络性能
        └── vm_pair_latency/         # 同节点虚拟机间延迟监控
```

## 2. 工具测量类型分类

除了按模块/子系统分类外,工具还可以按照测量方式和数据采集粒度分为以下几类:

### 2.1 Details 版本 - 详细信息测量工具

**特点:**

- 采集特定网络路径上每个数据包的完整元数据
- 实时输出,per-packet 级别跟踪
- 记录详细的时间戳、SKB 信息、设备信息、栈跟踪等
- 支持多种过滤器(五元组、接口、协议等)以缩小采集范围

**适用场景:**

- 精确问题定位和根因分析
- 详细数据包路径分析
- 异常流量的细粒度追踪
- 特定时段的深度性能分析

**性能开销:**

- 较高(per-packet 处理和输出)
- 建议使用过滤器限制采集范围
- 不适合长时间大范围监控

**典型工具:**

- `system_network_latency_details.py` - 系统网络延迟详细分析
- `vm_network_latency_details.py` - VM 网络延迟详细分析
- `vhost_queue_correlation_details.py` - vhost 队列关联详细统计
- `tun_to_vhost_queue_stats_details.py` - TUN 到 vhost 队列详细统计
- `qdisc_lateny_details.py` - Qdisc 数据包排序详细跟踪

### 2.2 Summary 版本 - 汇总统计测量工具

**特点:**

- 基于 BPF_HISTOGRAM 的高效内核态聚合
- 按时间间隔输出统计结果(直方图分布)
- 统计延迟分布、计数分布、频率分布等
- 使用对数刻度的 bucket 划分: [0-1), [1-2), [2-4), [4-8), [8-16), [16-32), ...
- Bucket 计算公式: `bpf_log2l(value + 1)`

**适用场景:**

- 长时间性能监控和趋势分析
- 建立性能基线和识别异常时段
- 大范围流量特征分析
- 初步问题筛查和范围确定
- 生产环境持续监控

**性能开销:**

- 低(内核态聚合,定期输出)
- 适合长时间运行
- 可覆盖大量流量

**典型工具:**

- `system_network_latency_summary.py` - 系统网络相邻阶段延迟直方图
- `vm_network_latency_summary.py` - VM 网络相邻阶段延迟直方图
- `ovs_upcall_latency_summary.py` - OVS upcall 延迟分布统计
- `kvm_irqfd_stats_summary.py` - KVM 中断注入统计(直方图)
- `kernel_drop_stack_stats_summary.py` - 内核丢包栈统计(直方图)

### 2.3 Simple 版本 - 简化版工具

**特点:**

- 介于 details 和 summary 之间的轻量级跟踪
- 简化的 per-event 跟踪(非 histogram 聚合)
- 减少数据采集维度和输出信息量
- 通常基于关键事件或简化的数据结构

**适用场景:**

- 需要事件级跟踪但不需要完整元数据
- 快速验证某些行为模式
- 资源受限环境下的监控

**典型工具:**

- `vhost_queue_correlation_simple.py` - vhost 队列关联简化监控
- `tun_to_vhost_queue_status_simple.py` - TUN 到 vhost 队列状态简化跟踪
- `eth_drop.py` - 以太网层简化丢包监控

### 2.4 Standalone 工具 - 独立功能工具

**特点:**

- 无版本变体的专用工具
- 针对特定监控场景或功能
- 通常是 bpftrace 脚本或特殊用途工具

**典型工具:**

- `system_network_icmp_rtt.py` - ICMP RTT 专用测量
- `trace_conntrack.py` - 连接跟踪监控
- `ovs_userspace_megaflow.py` - OVS megaflow 跟踪
- 各类 bpftrace 脚本 (*.bt)

### 2.5 分层测量策略建议

**推荐的问题诊断流程:**

1. **第一阶段 - 问题筛查** (使用 Summary 工具)

   - 部署相关模块的 summary 版本工具
   - 设置合理的统计间隔(5-10 秒)
   - 建立性能基线,识别异常时段
   - 分析延迟分布、丢包分布等直方图
   - 确定需要深入分析的时间窗口和流量特征
2. **第二阶段 - 精确定位** (使用 Details 工具)

   - 根据 summary 结果提取异常五元组、时间段等
   - 使用这些信息作为 details 工具的过滤器
   - 部署对应的 details 版本工具
   - 采集精确的 per-packet 元数据
   - 分析具体数据包的处理路径和延迟
3. **第三阶段 - 持续监控** (使用 Summary 工具)

   - 问题修复后,部署 summary 工具持续监控
   - 低性能开销,可长时间运行
   - 验证问题是否复现
   - 支持自动化告警集成

**示例:**

```bash
# 阶段1: 使用 summary 工具建立基线
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --protocol tcp --direction rx --interval 5

# 发现 P99 延迟异常,且主要来自 172.21.153.113 → 172.21.153.114

# 阶段2: 使用 details 工具精确分析
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --protocol tcp --direction rx

# 分析 per-packet 数据,定位到 OVS_RX 阶段延迟异常

# 阶段3: 修复后持续监控
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --protocol tcp --direction rx --interval 10
```

## 3. 模块特定工具详情

### 3.1 CPU 模块 (`cpu/`)

**用途**：监控 CPU 调度、锁竞争和 off-CPU 时间分析

#### 工具：

- **offcputime-ts.py**：跟踪线程阻塞（off-CPU）时间

  - **使用场景**：识别由阻塞操作引起的性能瓶颈
  - **收集数据**：栈跟踪、阻塞时长、时间戳
- **futex.bt**：跟踪 futex 系统调用

  - **使用场景**：调试互斥锁/信号量竞争问题
  - **收集数据**：Futex 操作、等待时间
- **pthread_rwlock_wrlock.bt**：监控 pthread 读写锁写操作

  - **使用场景**：分析读写锁竞争
  - **收集数据**：锁获取尝试、等待时间、栈跟踪
- **cpu_monitor.sh**：综合 CPU 监控脚本

  - **使用场景**：系统范围 CPU 性能分析
  - **收集数据**：CPU 利用率、调度指标
- **sched_latency_monitor.sh**：调度器延迟监控

  - **使用场景**：检测调度延迟
  - **收集数据**：调度延迟直方图

### 3.2 KVM 虚拟化网络模块 (`kvm-virtualization-network/`)

#### 3.2.1 KVM 子系统 (`kvm/`)

- **kvm_irqfd_stats_summary.py**：KVM 中断注入统计

  - **使用场景**：监控虚拟中断传递性能
  - **收集数据**：IRQ 注入次数、延迟、每虚拟机统计
- **kvm_irqfd_stats_summary_arm.py**：ARM 特定 KVM 中断监控

  - **使用场景**：ARM 虚拟化中断分析
  - **收集数据**：ARM 特定 IRQ 统计

#### 3.2.2 TUN/TAP 子系统 (`tun/`)

- **tun_ring_monitor.py**：TUN 设备环形缓冲区监控

  - **使用场景**：检测 TUN 设备缓冲区问题
  - **收集数据**：环形缓冲区利用率、溢出事件
- **tun-abnormal-gso-type.bt**：异常 GSO 类型检测

  - **使用场景**：识别 GSO 卸载问题
  - **收集数据**：无效 GSO 类型、数据包详情
- **tun-tx-ring-stas.bt**：TUN 发送环统计

  - **使用场景**：TX 环性能分析
  - **收集数据**：TX 环占用率、吞吐量

#### 3.2.3 vhost-net 后端 (`vhost-net/`)

- **vhost_eventfd_count.py/bt**：vhost eventfd 信号监控

  - **使用场景**：分析客户机-主机通知效率
  - **收集数据**：Eventfd 信号次数、频率
- **vhost_queue_correlation_simple.py**：简单队列关联分析

  - **使用场景**：理解队列利用模式
  - **收集数据**：队列对映射、利用率指标
- **vhost_queue_correlation_details.py**：详细队列关联

  - **使用场景**：深度队列性能分析
  - **收集数据**：每队列统计、关联指标
- **vhost_buf_peek_stats.py**：vhost 缓冲区 peek 操作

  - **使用场景**：缓冲区管理效率
  - **收集数据**：缓冲区 peek 次数、延迟

#### 3.2.4 virtio-net 客户机驱动 (`virtio-net/`)

- **virtnet_poll_monitor.py**：virtio-net NAPI 轮询监控

  - **使用场景**：NAPI 轮询效率分析
  - **收集数据**：轮询次数、数据包批量大小
- **virtnet_irq_monitor.py**：virtio-net 中断监控

  - **使用场景**：中断合并有效性
  - **收集数据**：IRQ 速率、CPU 亲和性
- **virtionet-rx-path-monitor.bt**：RX 路径详细监控

  - **使用场景**：RX 处理瓶颈识别
  - **收集数据**：函数延迟、数据包流
- **virtionet-rx-path-summary.bt**：RX 路径汇总统计

  - **使用场景**：整体 RX 性能评估
  - **收集数据**：聚合 RX 指标
- **trace_virtio_net_rcvbuf.bt**：接收缓冲区跟踪

  - **使用场景**：缓冲区分配问题
  - **收集数据**：缓冲区大小、分配失败

#### 3.2.5 跨层工具

- **tun_to_vhost_queue_status_simple.py**：TUN 到 vhost 队列映射

  - **使用场景**：理解层间数据流
  - **收集数据**：队列映射、流统计
- **tun_to_vhost_queue_stats_details.py**：详细队列统计

  - **使用场景**：性能关联分析
  - **收集数据**：详细每队列指标
- **tun_tx_to_kvm_irq.py**：TX 到 IRQ 注入关联

  - **使用场景**：端到端延迟分析
  - **收集数据**：TX 到 IRQ 延迟、注入速率

### 3.3 Linux 网络栈模块 (`linux-network-stack/`)

#### 核心网络栈工具

- **trace_conntrack.py**：连接跟踪监控

  - **使用场景**：NAT/防火墙连接问题
  - **收集数据**：连接状态、超时
- **trace_ip_defrag.py**：IP 分片/重组

  - **使用场景**：分片相关丢包
  - **收集数据**：分片计数、重组失败

#### 丢包子系统 (`packet-drop/`)

- **drop_monitor_controller.py**：集中式丢包监控

  - **使用场景**：系统范围丢包检测
  - **收集数据**：丢包位置、原因、计数
- **eth_drop.py**：以太网层丢包监控

  - **使用场景**：网卡驱动丢包检测
  - **收集数据**：驱动丢包统计
- **kernel_drop_stack_stats_summary.py**：内核丢包栈分析

  - **使用场景**：识别内核中的丢包位置
  - **收集数据**：栈跟踪、丢包频率
- **kernel_drop_stack_stats.bt**：实时丢包栈跟踪

  - **使用场景**：实时丢包调试
  - **收集数据**：实时栈跟踪
- **qdisc_drop_trace.py**：队列规则丢包监控

  - **使用场景**：流量控制丢包分析
  - **收集数据**：Qdisc 丢包原因、队列深度

### 3.4 Open vSwitch 模块 (`ovs/`)

- **ovs-kernel-module-drop-monitor.py**：OVS 数据路径丢包监控

  - **使用场景**：OVS 内核模块丢包
  - **收集数据**：丢包原因、流信息
- **ovs_userspace_megaflow.py**：Megaflow 缓存监控

  - **使用场景**：流缓存效率分析
  - **收集数据**：缓存命中/未命中率、流计数

### 3.5 性能模块 (`performance/`)

#### 系统网络性能 (`system-network/`)

- **system_network_latency_summary.py** [Summary 版本] 新增

  - **使用场景**：长时间系统网络延迟监控,建立性能基线
  - **测量方式**：基于 BPF_HISTOGRAM 的相邻阶段延迟统计
  - **收集数据**：延迟分布直方图(对数刻度 buckets),按时间间隔聚合
  - **性能开销**：低(内核态聚合)
  - **输出特点**：每个相邻阶段对的延迟直方图分布
- **system_network_latency_details.py** [Details 版本]

  - **使用场景**：精确问题定位,详细数据包路径分析
  - **测量方式**：Per-packet 实时跟踪
  - **收集数据**：每个数据包的完整元数据、时间戳、阶段延迟
  - **性能开销**：较高(需使用过滤器控制)
  - **输出特点**：每包详细信息,五元组、SKB 指针、设备信息
- **system_network_icmp_rtt.py** [Standalone 工具]

  - **使用场景**：ICMP 网络延迟基准测试
  - **收集数据**：ICMP 往返时间统计、丢包率
  - **特殊参数**：支持 `--direction` (tx/rx) 指定跟踪方向
- **system_network_perfomance_metrics.py** [Standalone 工具]

  - **使用场景**：整体系统网络性能评估
  - **收集数据**：完整数据流跟踪、吞吐量、延迟、CPU 使用率
  - **特点**：支持连接跟踪 (`--enable-ct`)

#### 虚拟机网络性能 (`vm-network/`)

- **vm_network_latency_summary.py** [Summary 版本]  

  - **使用场景**：长时间 VM 网络延迟监控,性能基线建立
  - **测量方式**：基于 BPF_HISTOGRAM 的相邻阶段延迟统计
  - **收集数据**：VM 网络栈各阶段延迟分布直方图
  - **性能开销**：低(内核态聚合)
  - **监控阶段**：VNET_RX → OVS_RX → FLOW_EXTRACT → QDISC_ENQ → TX_QUEUE → TX_XMIT
- **vm_network_latency_details.py** [Details 版本]

  - **使用场景**：虚拟机网络精确延迟分析
  - **测量方式**：Per-packet 级别跟踪
  - **收集数据**：主机-虚拟机-主机完整路径的详细延迟组件
  - **性能开销**：较高(建议使用过滤器)
- **vm_network_performance_metrics.py** [Standalone 工具]

  - **使用场景**：虚拟机网络性能全面监控
  - **收集数据**：虚拟机特定吞吐量、PPS、完整流跟踪

##### 虚拟机对延迟分析 (`vm_pair_latency/`)

- **vm_pair_latency.py** [Standalone 工具]

  - **使用场景**：同节点虚拟机间通信延迟测量
  - **收集数据**：点对点延迟、基本统计
  - **参数**：`--send-dev`, `--recv-dev`
- **multi_vm_pair_latency.py** [Standalone 工具]  新增

  - **使用场景**：多虚拟机对延迟监控
  - **收集数据**：多个 VM 对的延迟统计
  - **参数**：`--send-dev`, `--recv-dev`, `--ports`
- **multi_vm_pair_latency_pairid.py** [Standalone 工具]  新增

  - **使用场景**：带 Pair ID 标识的多 VM 对延迟监控
  - **收集数据**：多个 VM 对的延迟,带 pair 标识符
  - **特点**：支持从配置文件读取 VM 对配置

##### 虚拟机对延迟间隙分析 (`vm_pair_latency/vm_pair_latency_gap/`)

- **vm_pair_gap.py** [Standalone 工具] 新增

  - **使用场景**：检测超过阈值的延迟间隙
  - **收集数据**：延迟异常事件、间隙统计
  - **参数**：`--threshold` (延迟阈值,微秒), `--ports`
- **multi_port_gap.py** [Standalone 工具] 新增

  - **使用场景**：多端口延迟间隙分析
  - **收集数据**：多个端口的延迟异常统计
  - **参数**：`--threshold`, `--ports` (多个端口列表)
- **multi_vm_pair_multi_port_gap.py** [Standalone 工具]  新增

  - **使用场景**：多 VM 对、多端口延迟间隙综合分析
  - **收集数据**：复杂场景下的延迟异常检测
  - **特点**：支持复杂的 VM 对和端口组合

#### 通用性能工具

- **qdisc_lateny_details.py** [Details 版本] 新增

  - **使用场景**：Qdisc 数据包排序详细跟踪
  - **收集数据**：队列规则处理时间、数据包排序信息
  - **性能开销**：较高(per-packet 跟踪)
- **iface_netstat.py** [Standalone 工具]

  - **使用场景**：网络接口统计实时监控
  - **收集数据**：RX/TX 计数器、错误、丢包统计

### 3.6 其他工具模块 (`other/`)

- **trace-abnormal-arp.bt**：异常 ARP 检测

  - **使用场景**：ARP 欺骗/问题检测
  - **收集数据**：可疑 ARP 数据包
- **trace-ovs-ct-invalid.bt**：OVS 连接跟踪无效状态

  - **使用场景**：连接跟踪问题
  - **收集数据**：无效 CT 条目
- **trace_offloading_segment.bt**：分段卸载跟踪

  - **使用场景**：TSO/GSO 问题调试
  - **收集数据**：卸载参数
- **trace_vlanvm_udp_workload.bt**：VLAN 虚拟机 UDP 跟踪

  - **使用场景**：VLAN 特定 UDP 问题
  - **收集数据**：VLAN 标签、UDP 流
- **vpc-vm-udp-datapath.bt**：VPC 虚拟机 UDP 数据路径

  - **使用场景**：云网络 UDP 分析
  - **收集数据**：VPC 流路径
- **trace-qdisc-dequeue.bt**：Qdisc 出队操作

  - **使用场景**：队列调度分析
  - **收集数据**：出队模式
- **trace_dev_queue_xmit.bt**：设备队列传输

  - **使用场景**：TX 队列行为
  - **收集数据**：队列深度、丢包
- **trace_tc_qdisc.bt**：流量控制 qdisc 跟踪

  - **使用场景**：TC 配置调试
  - **收集数据**：TC 动作、分类

## 4. 工具使用指南

### 4.1 基本使用模式

**Python BCC 工具通用使用模式：**

```bash
sudo python3 <工具路径> [选项]
```

**Bpftrace 脚本通用使用模式：**

```bash
sudo bpftrace <脚本路径> [参数]
```

**注意事项：**

- 所有工具需要 root 权限执行
- 建议先在开发环境测试
- 推荐使用 Python 3（部分工具兼容 Python 2）
- 工具运行时会对系统性能产生一定影响

### 4.2 性能监控模块 (Performance)

#### 4.2.1 通用参数说明

**网络层过滤参数：**

- `--src-ip IP_ADDRESS`：源 IP 地址过滤器
- `--dst-ip IP_ADDRESS`：目标 IP 地址过滤器
- `--src-port PORT`：源端口过滤器（TCP/UDP）
- `--dst-port PORT`：目标端口过滤器（TCP/UDP）
- `--protocol PROTOCOL`：协议过滤器（tcp、udp、icmp、all）

**接口参数：**

- `--vm-interface INTERFACE`：虚拟机接口（如 tap0、vnet0）
- `--phy-interface INTERFACE`：物理接口，支持逗号分隔列表用于 bond 场景（如 eth0 或 eth0,eth1）
- `--internal-interface INTERFACE`：内部接口（用于系统级工具）

**方向和行为控制：**

- `--direction DIRECTION`：数据方向（rx、tx、both）
- `--enable-ct`：启用连接跟踪
- `--verbose`：详细输出模式

#### 4.2.2 系统网络性能工具

**system_network_latency_summary.py** - 系统网络延迟直方图 [Summary 版本] 新增

```bash
# 系统网络相邻阶段延迟直方图统计
sudo python3 ebpf-tools/performance/system-network/system_network_latency_summary.py \
  --phy-interface ens11 --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction rx --protocol tcp --interval 5

# 监控所有协议的延迟分布
sudo python3 ebpf-tools/performance/system-network/system_network_latency_summary.py \
  --phy-interface eth0 --protocol all --direction tx --interval 10
```

**system_network_latency_details.py** - 系统网络延迟详细分析 [Details 版本]

```bash
# 详细 per-packet 延迟分析
sudo python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
  --phy-interface ens11 --src-ip 10.132.114.12 --dst-ip 10.132.114.11 \
  --direction rx --protocol tcp

# 双向延迟监控
sudo python3 ebpf-tools/performance/system-network/system_network_latency_details.py \
  --phy-interface eth0 --src-ip 192.168.1.100 --dst-ip 192.168.1.200 \
  --direction both --protocol udp
```

**system_network_perfomance_metrics.py** - 系统网络性能指标

```bash
# 监控系统网络性能指标
sudo python3 ebpf-tools/performance/system-network/system_network_perfomance_metrics.py \
  --internal-interface port-storage --phy-interface ens11 \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction rx --protocol tcp

# 启用连接跟踪的性能监控
sudo python3 ebpf-tools/performance/system-network/system_network_perfomance_metrics.py \
  --internal-interface br0 --phy-interface eth0 \
  --enable-ct --verbose
```

**system_network_icmp_rtt.py** - ICMP RTT 测量

```bash
# ICMP 往返时间测量
sudo python3 ebpf-tools/performance/system-network/system_network_icmp_rtt.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 \
  --direction tx --phy-interface ens11
```

#### 4.2.3 虚拟机网络性能工具

**vm_network_latency_summary.py** - VM 网络延迟直方图 [Summary 版本] ⭐ 新增

```bash
# VM 网络相邻阶段延迟直方图统计
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --direction rx --protocol tcp --interval 5

# 监控所有协议的 VM 网络延迟分布
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_summary.py \
  --vm-interface tap0 --phy-interface eth0 \
  --protocol all --direction tx --interval 10
```

**vm_network_latency_details.py** - VM 网络延迟详细分析 [Details 版本]

```bash
# 虚拟机延迟 per-packet 详细分解
sudo python3 ebpf-tools/performance/vm-network/vm_network_latency_details.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 \
  --direction tx --protocol udp
```

**vm_network_performance_metrics.py** - 虚拟机网络性能指标

```bash
# 虚拟机网络性能监控
sudo python3 ebpf-tools/performance/vm-network/vm_network_performance_metrics.py \
  --vm-interface vnet0 --phy-interface ens4 \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 \
  --direction rx --protocol tcp
```

#### 4.2.4 虚拟机对延迟分析工具

**vm_pair_latency.py** - 基本虚拟机间延迟分析

```bash
# 基本虚拟机对延迟监控
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/vm_pair_latency.py \
  --send-dev tap0 --recv-dev tap1
```

**multi_vm_pair_latency.py** - 多虚拟机对延迟监控  新增

```bash
# 多虚拟机对、多端口延迟监控
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/multi_vm_pair_latency.py \
  --send-dev tap0 --recv-dev tap1 --ports 22 80 443
```

**multi_vm_pair_latency_pairid.py** - 带 Pair ID 的多 VM 对延迟 新增

```bash
# 使用 Pair ID 标识的多 VM 对延迟监控
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/multi_vm_pair_latency_pairid.py \
  --config vm_pairs.txt
```

**vm_pair_gap.py** - 延迟间隙分析  新增

```bash
# 延迟间隙分析（设定阈值,微秒）
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/vm_pair_latency_gap/vm_pair_gap.py \
  --threshold 100 --ports 22 80
```

**multi_port_gap.py** - 多端口延迟间隙分析  新增

```bash
# 多端口延迟间隙分析
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/vm_pair_latency_gap/multi_port_gap.py \
  --threshold 50 --ports 22 80 443 8080
```

**multi_vm_pair_multi_port_gap.py** - 多 VM 对多端口延迟间隙 新增

```bash
# 复杂场景：多 VM 对、多端口延迟间隙综合分析
sudo python3 ebpf-tools/performance/vm-network/vm_pair_latency/vm_pair_latency_gap/multi_vm_pair_multi_port_gap.py \
  --config vm_pairs.txt --threshold 100 --ports 22 80 443
```

### 4.3 Linux 网络栈模块 (Linux Network Stack)

#### 4.3.1 通用参数说明

**五元组过滤参数：**

- `--src-ip IP_ADDRESS`：源 IP 过滤器
- `--dst-ip IP_ADDRESS`：目标 IP 过滤器
- `--src-port PORT`：源端口过滤器
- `--dst-port PORT`：目标端口过滤器
- `--protocol PROTOCOL`：协议过滤器（tcp、udp、icmp、all）

**丢包监控特定参数：**

- `--type PROTOCOL_TYPE`：协议类型（arp、rarp、ipv4、ipv6、lldp、flow_control、other、all）
- `--l4-protocol PROTOCOL`：L4 协议过滤器
- `--vlan-id VLAN_ID`：VLAN ID 过滤器
- `--interface DEVICE`：网络接口过滤器

**输出控制参数：**

- `--verbose`：详细输出
- `--no-stack-trace`：禁用栈跟踪
- `--disable-normal-filter`：显示正常的 kfree 模式
- `--interval SECONDS`：报告间隔（默认：10）
- `--duration SECONDS`：总监控时长
- `--top NUMBER`：显示前 N 个栈（默认：5）

#### 4.3.2 丢包监控工具

**eth_drop.py** - 以太网层丢包监控

```bash
# 基本以太网丢包监控
sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --l4-protocol tcp

# 指定接口和协议类型的丢包监控
sudo python3 ebpf-tools/linux-network-stack/packet-drop/eth_drop.py \
  --type ipv4 --src-ip 192.168.1.100 --dst-port 80 \
  --interface eth0 --verbose
```

**kernel_drop_stack_stats_summary_all.py** - 内核丢包栈统计

```bash
# 内核丢包栈统计分析
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --src-ip 10.132.114.12 --dst-ip 10.132.114.11 --l4-protocol tcp

# 详细栈统计（指定设备和时间间隔）
sudo python3 ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats_summary_all.py \
  --interval 5 --duration 60 --top 10 \
  --device br-int --src-ip 10.0.0.100 --l4-protocol tcp
```

**qdisc_drop_trace.py** - 队列规则丢包跟踪 (仅 kernel 4.19)

```bash
# 队列规则丢包监控
sudo python3 ebpf-tools/linux-network-stack/packet-drop/qdisc_drop_trace.py
```

#### 4.3.3 连接跟踪和分片工具

**trace_conntrack.py** - 连接跟踪监控

```bash
# 基本连接跟踪
sudo python3 ebpf-tools/linux-network-stack/trace_conntrack.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --protocol tcp

# 相对时间显示的连接跟踪
sudo python3 ebpf-tools/linux-network-stack/trace_conntrack.py \
  --src-ip 192.168.1.100 --protocol tcp --rel-time

# 使用过滤器文件的多过滤器连接跟踪
sudo python3 ebpf-tools/linux-network-stack/trace_conntrack.py \
  --filters-file /path/to/filters.json --stack true
```

**trace_ip_defrag.py** - IP 分片重组跟踪

```bash
# IP 分片重组监控
sudo python3 ebpf-tools/linux-network-stack/trace_ip_defrag.py \
  --src-ip 10.132.114.11 --dst-ip 10.132.114.12 --protocol udp

# 带日志记录的 IP 分片监控
sudo python3 ebpf-tools/linux-network-stack/trace_ip_defrag.py \
  --src-ip 192.168.1.100 --protocol udp --log-file /tmp/defrag.log
```

### 4.4 Open vSwitch 模块 (OVS)

#### 4.4.1 通用参数说明

**网络过滤参数：**

- `--src-ip IP_ADDRESS`：源 IP 过滤器
- `--dst-ip IP_ADDRESS`：目标 IP 过滤器
- `--src-port PORT`：源端口过滤器
- `--dst-port PORT`：目标端口过滤器
- `--protocol PROTOCOL`：协议过滤器

**OVS 特定参数：**

- `--interval SECONDS`：直方图报告间隔

**Megaflow 特定参数：**

- `--eth-src MAC_ADDRESS`：源 MAC 地址过滤器
- `--eth-dst MAC_ADDRESS`：目标 MAC 地址过滤器
- `--eth-type ETHERTYPE`：以太网类型过滤器
- `--ip-proto PROTOCOL`：IP 协议号
- `--l4-src-port PORT`：L4 源端口
- `--l4-dst-port PORT`：L4 目标端口

#### 4.4.2 OVS 工具使用

**ovs_upcall_latency_summary.py** - OVS Upcall 延迟分析 [Summary 版本]

```bash
# OVS upcall 延迟直方图统计 (注意: 使用 --proto 而非 --protocol)
sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 --proto tcp

# 指定报告间隔的 upcall 延迟监控
sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
  --src-ip 192.168.76.198 --proto tcp --interval 5

# 监控所有协议的 upcall 延迟
sudo python3 ebpf-tools/ovs/ovs_upcall_latency_summary.py \
  --proto all --interval 10
```

**参数说明:**

- `--src-ip IP`: 源 IP 过滤器
- `--dst-ip IP`: 目标 IP 过滤器
- `--proto PROTOCOL`: 协议过滤器 (tcp/udp/all) **注意:是 --proto 不是 --protocol**
- `--interval SECONDS`: 统计间隔 (默认 5)

**ovs_userspace_megaflow.py** - OVS 用户空间 Megaflow 跟踪

```bash
# 基本 megaflow 跟踪
sudo python3 ebpf-tools/ovs/ovs_userspace_megaflow.py \
  --src-ip 172.21.153.114 --dst-ip 172.21.153.113 --protocol tcp

# 综合过滤的 megaflow 跟踪
sudo python3 ebpf-tools/ovs/ovs_userspace_megaflow.py \
  --eth-src 00:11:22:33:44:55 --src-ip 10.0.0.100 \
  --l4-src-port 80 --ip-proto 6
```

**ovs-kernel-module-drop-monitor.py** - OVS 内核模块丢包监控

```bash
# OVS 内核丢包监控
sudo python3 ebpf-tools/ovs/ovs-kernel-module-drop-monitor.py \
  --src-ip 172.21.153.113 --dst-ip 172.21.153.114 --protocol udp
```

### 4.5 KVM 虚拟化网络模块 (KVM Virt Network)

#### 4.5.1 通用参数说明

**基本监控参数：**

- `--interval SECONDS`：输出间隔（默认：1）
- `--clear`：输出后清空计数器
- `--device DEVICE_NAME`：设备名称过滤器
- `--queue-id ID`：特定队列 ID
- `--threshold VALUE`：各种阈值参数

**TUN/TAP 特定参数：**

- `--tun-device DEVICE`：TUN 设备名称
- `--ring-size SIZE`：环形缓冲区大小

#### 4.5.2 vhost-net 工具

**vhost_eventfd_count.py** - vhost eventfd 监控

```bash
# 监控 vhost eventfd 信号
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_eventfd_count.py \
  --interval 5 --clear
```

**vhost_queue_correlation_details.py** - vhost 队列关联分析

```bash
# 详细 vhost 队列关联分析
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_queue_correlation_details.py \
  --device vhost-1 --interval 2
```

**vhost_buf_peek_stats.py** - vhost 缓冲区 peek 统计

```bash
# vhost 缓冲区 peek 操作监控
sudo python3 ebpf-tools/kvm-virt-network/vhost-net/vhost_buf_peek_stats.py \
  --interval 1
```

#### 4.5.3 TUN/TAP 工具

**tun_ring_monitor.py** - TUN 环形缓冲区监控

```bash
# TUN 设备环形缓冲区监控
sudo python3 ebpf-tools/kvm-virt-network/tun/tun_ring_monitor.py \
  --device tun0 --interval 1
```

**tun_to_vhost_queue_stats_details.py** - TUN 到 vhost 队列统计

```bash
# TUN 到 vhost 队列详细统计
sudo python3 ebpf-tools/kvm-virt-network/tun/tun_to_vhost_queue_stats_details.py \
  --tun-device tap0 --interval 3
```

#### 4.5.4 virtio-net 工具

**virtnet_poll_monitor.py** - virtio-net NAPI 轮询监控

```bash
# virtio-net NAPI 轮询效率监控
sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_poll_monitor.py \
  --interval 2
```

**virtnet_irq_monitor.py** - virtio-net 中断监控

```bash
# virtio-net 中断合并监控
sudo python3 ebpf-tools/kvm-virt-network/virtio-net/virtnet_irq_monitor.py \
  --interval 1 --device virtio0
```

#### 4.5.5 KVM IRQ 工具

**kvm_irqfd_stats_summary.py** - KVM 中断注入统计 [Summary 版本]

```bash
# KVM 中断注入性能监控 (必需参数: --qemu-pid)
sudo python3 ebpf-tools/kvm-virt-network/kvm/kvm_irqfd_stats_summary.py \
  --qemu-pid 12345 --interval 5

# 监控特定 QEMU 进程的中断统计
sudo python3 ebpf-tools/kvm-virt-network/kvm/kvm_irqfd_stats_summary.py \
  --qemu-pid $(pgrep -f "qemu.*vm-name")
```

**重要参数说明:**

- `--qemu-pid PID`: QEMU 进程 PID (必需参数!)
- `--interval SECONDS`: 报告间隔 (默认 1)
- 支持分类过滤和线程过滤等高级参数

### 4.6 Bpftrace 脚本工具

#### 4.6.1 网络异常检测脚本

```bash
# 跟踪异常 ARP 数据包
sudo bpftrace ebpf-tools/other/trace-abnormal-arp.bt

# 监控 OVS 连接跟踪无效状态
sudo bpftrace ebpf-tools/other/trace-ovs-ct-invalid.bt

# 跟踪卸载分段问题
sudo bpftrace ebpf-tools/other/trace_offloading_segment.bt
```

#### 4.6.2 virtio-net 路径监控脚本

```bash
# virtio-net RX 路径详细监控
sudo bpftrace ebpf-tools/kvm-virt-network/virtio-net/virtionet-rx-path-monitor.bt

# virtio-net RX 路径汇总统计
sudo bpftrace ebpf-tools/kvm-virt-network/virtio-net/virtionet-rx-path-summary.bt

# 跟踪 virtio-net 接收缓冲区
sudo bpftrace ebpf-tools/kvm-virt-network/virtio-net/trace_virtio_net_rcvbuf.bt
```

#### 4.6.3 TUN/TAP 监控脚本

```bash
# TUN 异常 GSO 类型检测
sudo bpftrace ebpf-tools/kvm-virt-network/tun/tun-abnormal-gso-type.bt

# TUN TX 环形缓冲区统计
sudo bpftrace ebpf-tools/kvm-virt-network/tun/tun-tx-ring-stas.bt
```

#### 4.6.4 内核丢包分析脚本

```bash
# 实时内核丢包栈跟踪
sudo bpftrace ebpf-tools/linux-network-stack/packet-drop/kernel_drop_stack_stats.bt

# 队列规则出队操作跟踪
sudo bpftrace ebpf-tools/other/trace-qdisc-dequeue.bt

# 设备队列传输跟踪
sudo bpftrace ebpf-tools/other/trace_dev_queue_xmit.bt
```

### 4.7 CPU 和调度器监控脚本

```bash
# 综合 CPU 监控
sudo ./ebpf-tools/cpu/cpu_monitor.sh

# 调度器延迟分析
sudo ./ebpf-tools/cpu/sched_latency_monitor.sh --interval 1 --duration 60

# off-CPU 时间分析
sudo python3 ebpf-tools/cpu/offcputime-ts.py
```

### 4.8 参数模式总结

#### 4.8.1 通用参数（大多数工具支持）

```bash
--src-ip IP_ADDRESS        # 源 IP 过滤器
--dst-ip IP_ADDRESS        # 目标 IP 过滤器
--src-port PORT           # 源端口过滤器
--dst-port PORT           # 目标端口过滤器
--protocol PROTOCOL       # 协议过滤器（tcp/udp/icmp/all）
--verbose                 # 详细输出模式
--interval SECONDS        # 报告间隔
--duration SECONDS        # 总监控时长
```

#### 4.8.2 主题特定参数

| 主题                  | 特有参数                                                                                                                                          |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Performance** | `--vm-interface`, `--phy-interface`, `--internal-interface`, `--direction`, `--enable-ct`, `--vm-ip`, `--threshold`, `--interval` |
| **Linux Stack** | `--type`, `--l4-protocol`, `--vlan-id`, `--rel-time`, `--filters-file`, `--stack`, `--log-file`, `--device`, `--top`            |
| **OVS**         | `--eth-src`, `--eth-dst`, `--eth-type`, `--ip-proto`, `--proto` (注意不是 --protocol), `--interval`                                   |
| **KVM Virt**    | `--device`, `--queue-id`, `--clear`, `--tun-device`, `--ring-size`, `--qemu-pid` (KVM IRQ 必需)                                       |

#### 4.8.3 输出控制参数

```bash
--verbose                 # 详细输出模式
--interval SECONDS        # 报告间隔
--duration SECONDS        # 总监控时长
--log-file FILE          # 输出到日志文件
--no-stack-trace         # 禁用栈跟踪
--clear                  # 清空计数器（部分工具）
--top NUMBER             # 显示前 N 项（统计工具）
```

## 5. 输出数据格式详解

### 5.1 性能监控工具输出格式

#### 5.1.1 Summary 工具输出格式 (直方图统计)  新增

Summary 版本工具使用 BPF_HISTOGRAM 进行内核态聚合统计,输出延迟分布直方图。

**system_network_latency_summary.py 输出格式:**

```
=== System Network Latency Summary Tool ===
Protocol filter: TCP
Direction filter: RX
Source IP filter: 10.132.114.11
Destination IP filter: 10.132.114.12
Physical interface: ens11 (ifindex 2)
Statistics interval: 5 seconds

Tracing system network latency... Hit Ctrl-C to end.

[2025-10-20 14:30:15] === Latency Report (Interval: 5.0s) ===

相邻阶段延迟分布 (Adjacent Stage Latency Distribution):

Stage: INTERNAL_RX → FLOW_EXTRACT_END_RX
     latency (us)    : count    distribution
        0 -> 1       :   156   |**************************        |
        2 -> 3       :   234   |************************************|
        4 -> 7       :   89    |*************                      |
        8 -> 15      :   23    |***                                |
       16 -> 31      :   5     |                                   |
       32 -> 63      :   1     |                                   |

Stage: FLOW_EXTRACT_END_RX → QDISC_ENQ
     latency (us)    : count    distribution
        0 -> 1       :   45    |**************                     |
        2 -> 3       :   123   |**************************************|
        4 -> 7       :   256   |************************************|
        8 -> 15      :   67    |********************               |
       16 -> 31      :   12    |***                                |

Stage: QDISC_ENQ → TX_QUEUE
     latency (us)    : count    distribution
        0 -> 1       :   234   |************************************|
        2 -> 3       :   198   |******************************     |
        4 -> 7       :   45    |******                             |
        8 -> 15      :   8     |*                                  |

Stage: TX_QUEUE → TX_XMIT
     latency (us)    : count    distribution
        0 -> 1       :   412   |************************************|
        2 -> 3       :   76    |******                             |
        4 -> 7       :   12    |*                                  |

Total packets analyzed: 508
```

**vm_network_latency_summary.py 输出格式:**

```
=== VM Network Latency Summary Tool ===
Protocol filter: TCP
Direction filter: RX
Source IP filter: 172.21.153.113
Destination IP filter: 172.21.153.114
VM interface: vnet0 (ifindex 22)
Physical interface: ens4 (ifindex 2)
Statistics interval: 5 seconds

Tracing VM network latency... Hit Ctrl-C to end.

[2025-10-20 14:35:20] === Latency Report (Interval: 5.0s) ===

相邻阶段延迟分布 (Adjacent Stage Latency Distribution):

Stage: VNET_RX → OVS_RX
     latency (us)    : count    distribution
        0 -> 1       :   12    |***                                |
        2 -> 3       :   45    |*************                      |
        4 -> 7       :   123   |************************************|
        8 -> 15      :   89    |**************************         |
       16 -> 31      :   34    |**********                         |
       32 -> 63      :   8     |**                                 |

Stage: OVS_RX → FLOW_EXTRACT_END_RX
     latency (us)    : count    distribution
        0 -> 1       :   23    |*******                            |
        2 -> 3       :   78    |*************************          |
        4 -> 7       :   145   |************************************|
        8 -> 15      :   45    |***********                        |
       16 -> 31      :   12    |***                                |

Stage: FLOW_EXTRACT_END_RX → QDISC_ENQ
     latency (us)    : count    distribution
        0 -> 1       :   56    |******************                 |
        2 -> 3       :   112   |************************************|
        4 -> 7       :   98    |*******************************    |
        8 -> 15      :   34    |***********                        |
       16 -> 31      :   5     |*                                  |

[继续输出后续阶段的直方图...]

Total packets analyzed: 311
```

**Histogram Bucket 说明:**

- Bucket 使用对数刻度: [0-1), [1-2), [2-4), [4-8), [8-16), [16-32), [32-64), ...
- 计算公式: `bucket_id = bpf_log2l(latency_us + 1)`
- 延迟单位: 微秒 (us)
- Distribution 列: ASCII 字符绘制的分布图,最长条对应最大计数

**ovs_upcall_latency_summary.py 输出格式:**

```
=== OVS Upcall Latency Histogram Tool ===
Protocol filter: TCP
Source IP filter: 172.21.153.113
Destination IP filter: 172.21.153.114
Statistics interval: 5 seconds

Collecting OVS upcall latency data... Hit Ctrl-C to end.

[2025-10-20 14:40:30] === Upcall Latency Report (Interval: 5.0s) ===

Upcall Latency Distribution:
     latency (us)    : count    distribution
        0 -> 1       :   5     |**                                 |
        2 -> 3       :   12    |*****                              |
        4 -> 7       :   34    |***************                    |
        8 -> 15      :   67    |******************************     |
       16 -> 31      :   89    |************************************|
       32 -> 63      :   45    |********************               |
       64 -> 127     :   23    |**********                         |
      128 -> 255     :   8     |***                                |
      256 -> 511     :   2     |                                   |

Total upcalls: 285
Average latency: 34.5 us
P50 latency: 28 us
P95 latency: 98 us
P99 latency: 234 us
```

#### 5.1.2 系统网络性能指标输出 (Details 工具)

**system_network_perfomance_metrics.py 输出格式：**

```
=== System Network Performance Tracer ===
Protocol filter: TCP
Direction filter: RX (1=VNET_RX/VM_TX, 2=VNET_TX/VM_RX)
Source IP filter: 10.132.114.12
Destination IP filter: 10.132.114.11
Internal interface: port-storage (ifindex 15)
Physical interface: ens11 (ifindex 2)
Conntrack measurement: DISABLED

BPF program loaded successfully

Tracing system network performance... Hit Ctrl-C to end.
Format: [YYYY-MM-DD HH:MM:SS.mmm] PKT_ID DIR STAGE DEV KTIME=ns
        FLOW: src -> dst (protocol_identifier)
        QUEUE/CT/QDISC metrics
        Complete flow summary at last stage

[2025-09-22 18:08:45.123] === FLOW COMPLETE: 5 stages captured ===
FLOW: 10.132.114.12 -> 10.132.114.11 (TCP 45678->80 seq=1234567890)
5-TUPLE: 10.132.114.12:45678 -> 10.132.114.11:80 TCP (seq=1234567890) DIR=INTERNAL_RX
  Stage INTERNAL_RX: KTIME=1579019845123456789ns
    SKB: ptr=0xffff888123456789 len=1500 data_len=1448 queue_mapping=2 hash=0x12345678
    DEV: port-storage (ifindex=15) CPU=3
  Stage FLOW_EXTRACT_END_RX: KTIME=1579019845125456789ns (+2.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=2 hash=0x12345678
    DEV: port-storage (ifindex=15) CPU=3
  Stage QDISC_ENQ: KTIME=1579019845128456789ns (+3.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=5 hash=0x87654321
    DEV: ens11 (ifindex=2) CPU=3
  Stage TX_QUEUE: KTIME=1579019845131456789ns (+3.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=5 hash=0x87654321
    DEV: ens11 (ifindex=2) CPU=3
  Stage TX_XMIT: KTIME=1579019845134456789ns (+3.000us)
    SKB: ptr=0xffff888123456789 len=1514 data_len=1448 queue_mapping=5 hash=0x87654321
    DEV: ens11 (ifindex=2) CPU=3
  TOTAL DURATION: 11.000us
  PACKET: len=1500 data_len=1448 queue_mapping=2 skb_hash=0x12345678
  PROCESS: pid=12345 comm=ksoftirqd/3 first_dev=port-storage
  FINAL_STAGE: dev=ens11(ifindex=2) cpu=3
```

**输出字段说明：**

- **FLOW COMPLETE**: 完整数据流跟踪的阶段数
- **5-TUPLE**: 五元组信息（源IP:Port -> 目标IP:Port 协议）
- **Stage**: 数据包在网络栈中的处理阶段
- **KTIME**: 内核时间戳（纳秒）
- **SKB**: socket buffer 信息（指针、长度、数据长度、队列映射、哈希值）
- **DEV**: 网络设备信息（设备名、接口索引、CPU）
- **TOTAL DURATION**: 整个数据流的处理时间

#### 5.1.3 虚拟机网络性能输出

**vm_network_performance_metrics.py 输出格式：**

```
=== VM Network Performance Tracer ===
Protocol filter: TCP
Direction filter: RX (1=VNET_RX/VM_TX, 2=VNET_TX/VM_RX)
Source IP filter: 172.21.153.114
Destination IP filter: 172.21.153.113
VM interface: vnet0 (ifindex 22)
Physical interface: ens4 (ifindex 2)
Conntrack measurement: DISABLED

[2025-09-22 18:25:29.132] === FLOW COMPLETE: 6 stages captured ===
FLOW: 172.21.153.114 -> 172.21.153.113 (TCP 40040->5001 seq=3649330686)
5-TUPLE: 172.21.153.114:40040 -> 172.21.153.113:5001 TCP (seq=3649330686) DIR=VNET_RX
  Stage VNET_RX: KTIME=1579020094156218ns
    SKB: ptr=0xffff888569f5ec00 len=7292 data_len=5784 queue_mapping=1 hash=0x0
    DEV: vnet0 (ifindex=22) CPU=19
  Stage OVS_RX: KTIME=1579020094183298ns (+27.080us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=1 hash=0x0
    DEV: vnet0 (ifindex=22) CPU=19
  Stage FLOW_EXTRACT_END_RX: KTIME=1579020094189943ns (+6.645us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=1 hash=0x0
    DEV: vnet0 (ifindex=22) CPU=19
  Stage QDISC_ENQ: KTIME=1579020094201422ns (+11.479us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=15 hash=0xf3621051
    DEV: ens4 (ifindex=2) CPU=19
  Stage TX_QUEUE: KTIME=1579020094208923ns (+7.501us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=15 hash=0xf3621051
    DEV: ens4 (ifindex=2) CPU=19
  Stage TX_XMIT: KTIME=1579020094214416ns (+5.493us)
    SKB: ptr=0xffff888569f5ec00 len=7306 data_len=5784 queue_mapping=15 hash=0xf3621051
    DEV: ens4 (ifindex=2) CPU=19
  TOTAL DURATION: 58.198us
  PACKET: len=7292 data_len=5784 queue_mapping=1 skb_hash=0x0
  PROCESS: pid=688598 comm=vhost-688571 first_dev=vnet0
  FINAL_STAGE: dev=ens4(ifindex=2) cpu=19

=== Performance Statistics ===
Event counts by probe point:
  Probe 1: 18 events
  Probe 2: 18 events
  Probe 3: 18 events
  Probe 8: 18 events
  Probe 10: 18 events
  Probe 11: 18 events
```

**虚拟机网络栈阶段说明：**

- **VNET_RX**: 虚拟机网络接口接收阶段
- **OVS_RX**: Open vSwitch 接收处理阶段
- **FLOW_EXTRACT_END_RX**: OVS 流提取结束阶段
- **QDISC_ENQ**: 队列规则入队阶段
- **TX_QUEUE**: 发送队列阶段
- **TX_XMIT**: 物理设备发送阶段

#### 5.1.4 延迟汇总统计输出 (旧版 - 已弃用)

**vm_network_latency_summary.py 输出格式：**

```
=== VM Network Latency Summary Tool ===
Protocol filter: TCP
Direction filter: RX
Source IP filter: 172.21.153.114
Destination IP filter: 172.21.153.113
VM interface: vnet0 (ifindex 22)
Physical interface: ens4 (ifindex 2)

Tracing VM network latency... Hit Ctrl-C to end.
Interval: 5 seconds

[2025-09-22 18:15:30] === Latency Report (Interval: 5.2s) ===
Packets analyzed: 234
Latency distribution:
  - Min: 12.3 us
  - Average: 45.7 us
  - Median (P50): 42.1 us
  - P95: 78.9 us
  - P99: 125.6 us
  - Max: 234.5 us

Stage-wise latency breakdown:
  - VNET_RX to OVS_RX: 15.2 us (33.2%)
  - OVS_RX to FLOW_EXTRACT: 8.3 us (18.2%)
  - FLOW_EXTRACT to QDISC_ENQ: 12.1 us (26.5%)
  - QDISC_ENQ to TX_QUEUE: 5.8 us (12.7%)
  - TX_QUEUE to TX_XMIT: 4.3 us (9.4%)

Flow summary:
  - Total flows: 45
  - Complete flows: 43
  - Incomplete flows: 2

CPU distribution:
  - CPU 13: 156 packets (66.7%)
  - CPU 15: 45 packets (19.2%)
  - CPU 16: 18 packets (7.7%)
  - CPU 19: 15 packets (6.4%)
```

### 5.2 Linux 网络栈监控输出格式

#### 5.2.1 丢包监控输出

**eth_drop.py 输出格式：**

```
--------------------------------------------------------------------------------
Starting packet drop monitoring... Press Ctrl+C to stop
[17:46:56] PID: 0 TGID: 0 COMM: swapper/0 CPU: 0
Ethernet Header:
  Source MAC: 9a:b9:0a:b6:d2:7a
  Dest MAC:   ff:ff:ff:ff:ff:ff
  EtherType:  0x0806
ARP PACKET
ARP Header:
  Hardware Type: 0x0001
  Protocol Type: 0x0800
  Operation:     Request
  Sender MAC:    9a:b9:0a:b6:d2:7a
  Sender IP:     10.42.213.89
  Target MAC:    00:00:00:00:00:00
  Target IP:     10.42.213.91
Interface: ovsbr-bbfi49amm
Stack trace:
  kfree_skb+0x1
  ovs_vport_send+0x9d
  do_output+0x57
  do_execute_actions+0x362
  ovs_execute_actions+0x4f
  ovs_dp_process_packet+0x9d
  ovs_vport_receive+0x76
  netdev_frame_hook+0xc2
  __netif_receive_skb_core+0x225
  __netif_receive_skb_list_core+0x129
  netif_receive_skb_list_internal+0x1f8
  gro_normal_list.part.141+0x1e
  napi_complete_done+0x8a
  virtnet_poll+0x376
  net_rx_action+0x12d
  __softirqentry_text_start+0x91
  irq_exit+0xa3
  do_IRQ+0x59
  ret_from_intr+0x0
  default_idle+0x35
  arch_cpu_idle+0x15
  default_idle_call+0x26
  do_idle+0x1b4
  cpu_startup_entry+0x1d
  rest_init+0xae
  arch_call_rest_init+0xe
  start_kernel+0x4ce
  x86_64_start_reservations+0x24
  x86_64_start_kernel+0xa4
  secondary_startup_64+0xb6
```

**kernel_drop_stack_stats_summary_all.py 输出格式：**

```
 Stack trace failures by device:
    port-storage: 1 failed
  Found 5 unique stack+flow combinations, showing top 5:

  #1 Count: 76 calls [device: port-storage] [stack_id: 2]
     Flow: 10.132.114.12 -> 10.132.114.11 (ICMP)
  Stack trace:
    Stack depth: 21 frames
    kfree_skb+0x1 [kernel]
    ip_protocol_deliver_rcu+0x1a9 [kernel]
    ip_local_deliver_finish+0x48 [kernel]
    ip_local_deliver+0xcd [kernel]
    ip_rcv_finish+0x84 [kernel]
    ... (16 more frames)

  #2 Count: 3 calls [device: port-storage] [stack_id: 344]
     Flow: 10.132.114.12 -> 10.132.114.11 (ICMP)
  Stack trace:
    Stack depth: 21 frames
    kfree_skb+0x1 [kernel]
  ...
```

#### 5.2.2 连接跟踪输出

**trace_conntrack.py 输出格式：**

```
DATETIME: 2025-09-22 17:57:33.760 COMM: swapper/19       FUNC: __nf_ct_refresh_acct      DEV: port-storage[18]
PKTINFO: 10.132.114.12:37323 -> 10.132.114.11:5201 (UDP) IP_ID:0x5013
OVS_CT_INFO: OvsConInfoNFCT:N/A(Init) OvsCommit:N/A(Init) OvsZoneID:N/A(Init) OvsZoneDir:N/A(Init)
SKB_CT_INFO: CT_STATUS:0x18e(NOT_TEMPLATE) CTINFO:0(IP_CT_ESTABLISHED) NFCT_PTR:0xffff88816bac30c0 SKBZoneID:0(KernelDefaultZone) SKBZoneDir:N/A(NoCfg) CT_LABEL:0x00000000000000000000000000000000
  b'__nf_ct_refresh_acct+0x1'
  b'nf_conntrack_in+0x3cd'
  b'ipv4_conntrack_in+0x14'
  b'nf_hook_slow+0x49'
  ...
```

### 5.3 OVS 监控输出格式

#### 5.3.1 OVS Upcall 延迟输出

**ovs_upcall_latency_summary.py 输出格式：**

```
=== OVS Upcall Latency Histogram Tool ===
Protocol filter: TCP
Source IP filter: 172.21.153.113
Destination IP filter: 172.21.153.114
Statistics interval: 5 seconds
BPF program loaded successfully

Collecting OVS upcall latency data... Hit Ctrl-C to end.
Statistics will be displayed every 5 seconds

[2025-09-22 18:10:30] OVS Upcall Latency Report (Interval: 5.0s)
================================================================================
Upcall Statistics:
  Total upcalls: 234
  Completed upcalls: 230
  Pending upcalls: 4

Latency Distribution (microseconds):
     [0, 10)     ████████████████████  56 (24.3%)
    [10, 20)     ██████████████████████████████  78 (33.9%)
    [20, 50)     ████████████████████  67 (29.1%)
    [50, 100)    ██████████  23 (10.0%)
   [100, 200)    ███  5 (2.2%)
   [200, +)      █  1 (0.4%)

Statistics:
  - Min latency: 2.3 us
  - Average latency: 23.4 us
  - Median (P50): 18.7 us
  - P95 latency: 67.8 us
  - P99 latency: 123.4 us
  - Max latency: 234.5 us

Upcall types:
  - MISS: 156 (67.8%)
  - ACTION: 45 (19.6%)
  - SLOW_PATH: 29 (12.6%)

Active upcall sessions: 4

[2025-09-22 18:10:35] OVS Upcall Latency Report (Interval: 5.0s)
...
```

#### 5.3.2 OVS Megaflow 输出

**ovs_userspace_megaflow.py 输出格式：**

```
OVS Megaflow Tracker V8
Filter Configuration:
  IP Source: 172.21.153.113
  IP Destination: 172.21.153.114
  IP Protocol: TCP (6)
Filter mode: only showing matching events

Attached to ovs_dp_upcall
Starting monitoring...

[18:25:30.123] UPCALL_EVENT:
  Netlink PID: 12345
  Upcall type: MISS
  Packet info:
    - Ethernet: 52:54:00:12:34:56 -> 52:54:00:ab:cd:ef
    - IP: 172.21.153.113 -> 172.21.153.114
    - TCP: 45678 -> 80
    - Packet length: 1500 bytes
  Kernel timestamp: 1579021145610018ns

[18:25:30.156] FLOW_INSTALL:
  Netlink PID: 12345
  Flow key:
    - in_port: 1
    - eth_src: 52:54:00:12:34:56
    - eth_dst: 52:54:00:ab:cd:ef
    - eth_type: 0x0800
    - ip_src: 172.21.153.113/32
    - ip_dst: 172.21.153.114/32
    - ip_proto: 6
    - tcp_src: 45678
    - tcp_dst: 80
  Actions: output:2

[18:25:30.234] UPCALL_EVENT:
  Netlink PID: 12345
  Upcall type: ACTION
  Packet info:
    - Ethernet: 52:54:00:ab:cd:ef -> 52:54:00:12:34:56
    - IP: 172.21.153.114 -> 172.21.153.113
    - TCP: 80 -> 45678
    - Packet length: 64 bytes
  Kernel timestamp: 1579021145692345ns

```

### 5.4 KVM 虚拟化网络输出格式

#### 5.4.1 vhost-net 监控输出

**vhost_eventfd_count.py 输出格式：**

```
=== vhost eventfd Monitor ===
Interval: 5 seconds
Clear counters: enabled

Starting vhost eventfd monitoring...

[2025-09-22 16:30:15] === vhost eventfd Statistics ===
Eventfd combinations (last 5 seconds):
  kick_fd=25, call_fd=26: 1234 events
  kick_fd=27, call_fd=28: 567 events
  kick_fd=29, call_fd=30: 89 events

Total eventfd events: 1890
Unique fd combinations: 3
Average events per combination: 630

Top combinations by frequency:
1. kick_fd=25, call_fd=26: 1234 events (65.3%)
2. kick_fd=27, call_fd=28: 567 events (30.0%)
3. kick_fd=29, call_fd=30: 89 events (4.7%)

[2025-09-22 16:30:20] === vhost eventfd Statistics ===
Eventfd combinations (last 5 seconds):
  kick_fd=25, call_fd=26: 1456 events
  kick_fd=27, call_fd=28: 623 events
  kick_fd=29, call_fd=30: 112 events

Total eventfd events: 2191
Unique fd combinations: 3
Average events per combination: 730
```

**vhost_queue_correlation_details.py 输出格式：**

```
=== vhost Queue Correlation Monitor ===
Device filter: vhost-1
Interval: 2 seconds

Attaching to vhost functions...
BPF program loaded successfully

[2025-09-22 17:15:30] === Queue Correlation Report ===
Monitored device: vhost-1
Active queues: 4

Queue pair correlations:
  RX Queue 0 <-> TX Queue 1:
    - Packets processed: 1234 (RX), 1189 (TX)
    - Correlation rate: 96.4%
    - Average processing gap: 12.3 us

  RX Queue 2 <-> TX Queue 3:
    - Packets processed: 567 (RX), 545 (TX)
    - Correlation rate: 96.1%
    - Average processing gap: 15.7 us

Queue utilization:
  - Queue 0 (RX): 67.8% busy
  - Queue 1 (TX): 65.4% busy
  - Queue 2 (RX): 31.2% busy
  - Queue 3 (TX): 29.8% busy

Load balancing efficiency: 78.5%
Overall queue correlation rate: 96.3%
```

### 5.5 Bpftrace 脚本输出格式

#### 5.5.1 事件跟踪输出

**virtionet-rx-path-monitor.bt 输出格式：**

```
Attaching 6 probes...
Tracing virtio-net RX path. Hit Ctrl-C to end.

TIME     PID    COMM           FUNC                    DETAILS
18:45:23 1234   vhost-1234     virtqueue_get_buf      vq=0 len=1500
18:45:23 1234   vhost-1234     virtqueue_kick         vq=0
18:45:23 0      swapper/5      virtnet_poll           napi=0xffff888123456789 budget=64
18:45:23 0      swapper/5      receive_buf            skb=0xffff888abcdef012 len=1500
18:45:23 0      swapper/5      virtnet_receive        packets=1 bytes=1500
18:45:23 1234   vhost-1234     vhost_add_used_and_signal vq=0 head=15 len=1500

TIME     PID    COMM           FUNC                    DETAILS
18:45:23 1234   vhost-1234     virtqueue_get_buf      vq=2 len=64
18:45:23 1234   vhost-1234     virtqueue_kick         vq=2
18:45:23 0      swapper/3      virtnet_poll           napi=0xffff888123456789 budget=64
18:45:23 0      swapper/3      receive_buf            skb=0xffff888abcdef345 len=64
18:45:23 0      swapper/3      virtnet_receive        packets=1 bytes=64
18:45:23 1234   vhost-1234     vhost_add_used_and_signal vq=2 head=23 len=64
```

**kernel_drop_stack_stats.bt 输出格式：**

```
Attaching 1 probe...
Tracing kernel packet drops. Hit Ctrl-C to end.

@drop_stacks[
    kfree_skb+0
    tcp_v4_rcv+564
    ip_local_deliver_finish+291
    ip_local_deliver+69
    ip_rcv_finish+103
    ip_rcv+137
    __netif_receive_skb_one_core+134
    __netif_receive_skb+21
    process_backlog+137
    __napi_poll+298
    net_rx_action+564
    __do_softirq+342
]: 15

@drop_stacks[
    kfree_skb+0
    netif_receive_skb_core+325
    __netif_receive_skb_one_core+134
    __netif_receive_skb+21
    netif_rx+298
    loopback_xmit+105
    dev_hard_start_xmit+232
    __dev_queue_xmit+1456
    dev_queue_xmit+15
    ip_finish_output2+567
    ip_finish_output+234
    ip_output+123
]: 8

@drop_locations[
    tcp_v4_rcv+564
]: 15

@drop_locations[
    netif_receive_skb_core+325
]: 8
```

### 5.6 输出格式特点总结

#### 5.6.1 时间戳格式

- **绝对时间**: `[YYYY-MM-DD HH:MM:SS.mmm]` 格式
- **相对时间**: `[    0.000]` 格式（从启动开始的秒数）
- **内核时间戳**: `KTIME=1579020094156218ns` 格式

#### 5.6.2 网络信息格式

- **五元组**: `src_ip:src_port -> dst_ip:dst_port protocol`
- **MAC 地址**: `52:54:00:12:34:56` 格式
- **接口信息**: `device_name (ifindex=N) CPU=N`

#### 5.6.3 性能指标格式

- **延迟**: 以微秒 (us) 为单位
- **吞吐量**: 以 pps、Mbps、GB 等单位
- **百分比**: P50、P95、P99 等百分位数
- **直方图**: 使用 ASCII 字符绘制的分布图

#### 5.6.4 错误和异常信息

- **返回值**: 特定函数返回值常量
- **栈跟踪**: 函数名+偏移量 格式
- **错误码**: BPF 程序加载错误信息

这些输出格式提供了丰富的网络性能和问题诊断信息，帮助用户全面理解系统网络状态和性能特征。

## 6. 部署和环境

### 6.1 系统要求

#### 6.1.1 基本要求

- **内核版本**: Linux 内核 4.19.90+ （推荐 openEuler 20.03 LTS 或更高版本）
- **BPF 支持**: 内核必须编译启用 CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y
- **权限要求**: 所有 eBPF 工具需要 root 权限执行
- **安装包要求**: 所有 eBPF 工具运行需要安装 kernel-devel && kernel-header , 此外推荐安装内核调试符号包 (kernel-debuginfo)

#### 6.1.2 依赖组件

- **BCC 工具链**: BPF Compiler Collection 0.18.0+
- **bpftrace**: bpftrace 0.10.0+
- **Python 环境**: Python 3.6+ （支持 Python 2.7 兼容）

#### 6.1.3 内核配置验证

```bash
# 检查 BPF 支持
zgrep CONFIG_BPF /proc/config.gz
zgrep CONFIG_BPF_SYSCALL /proc/config.gz
zgrep CONFIG_BPF_JIT /proc/config.gz

# 检查 BPF 文件系统
ls /sys/fs/bpf

# 检查 BCC 安装
python3 -c "import bcc; print('BCC version:', bcc.__version__)"

# 检查 bpftrace 安装
bpftrace --version
```

### 6.2 目标环境

#### 6.2.1 虚拟化环境

- **Hypervisor**: KVM/QEMU 4.0+
- **虚拟网卡**: virtio-net 驱动
- **网络后端**: vhost-net
- **多队列支持**: 启用 virtio-net 多队列 && vhost-net 多线程

#### 6.2.2 网络环境

- **虚拟网络**: Open vSwitch 2.13+ 或 Linux Bridge
- **网络协议**: 支持 TCP/UDP/ICMP IPv4/IPv6
- **VLAN 支持**: 802.1Q VLAN 标签
- **Conntrace 支持**: 协议栈 conntrack 模块
- **流量控制**: TC (Traffic Control) qdisc 支持

#### 6.2.3 操作系统支持

- **主要支持**: openEuler 20.03 LTS+
- **测试支持**: CentOS 7+, Ubuntu 18.04+, RHEL 8+
- **内核版本**: 4.19.90 && tecentos tls 5.4 && 5.10 为主要适配目标

### 6.3 安装部署步骤

#### 6.3.1 openEuler 系统安装

```bash
# 安装 BCC 工具
sudo yum install -y bcc-tools python3-bcc

# 安装 bpftrace
sudo yum install -y bpftrace

# 安装其他依赖
sudo yum install -y kernel-devel-$(uname -r) kernel-header-$(uname -r) 

# 克隆项目
git clone https://github.com/your-org/troubleshooting-tools.git
cd troubleshooting-tools
```

#### 6.3.2 Ubuntu 系统安装

```bash
# 更新包管理器
sudo apt update

# 安装 BCC
sudo apt install -y bcc-tools python3-bcc

# 安装 bpftrace
sudo apt install -y bpftrace

# 安装其他依赖
sudo apt install -y kernel-devel-$(uname -r) kernel-header-$(uname -r) 

# 克隆项目
git clone https://github.com/echkenluo/troubleshooting-tools.git
cd troubleshooting-tools
```

#### 6.3.3 环境验证

```bash
# 测试基本 BPF 功能
sudo python3 -c "from bcc import BPF; print('BCC import successful')"
# oe 系统上
sudo python3 -c "from bpfcc import BPF; print('BCC import successful')"

# 测试简单 eBPF 程序
sudo bpftrace -e 'BEGIN { printf("bpftrace is working\\n"); exit(); }'

# 测试项目工具
cd troubleshooting-tools
sudo python3 ebpf-tools/performance/system-network/system_network_icmp_rtt.py --help
```

### 6.4 故障排查和支持

#### 6.4.1 常见错误和解决方案

**BPF 程序加载失败**

- **错误信息**: `bpf: Failed to load program: Permission denied`
- **解决方案**:
  1. 检查是否使用 root 权限
  2. 检查内核版本是否支持 BPF
  3. 检查 BCC 安装是否完整

**程序挂起**

- **错误信息**: `Cannot attach to function: No such file or directory`
- **解决方案**:
  1. 检查内核符号表是否可用
  2. 检查函数名是否正确
  3. 检查内核模块是否加载

**数据采集异常**

- **现象**: 无数据或数据不完整
- **解决方案**:
  1. 检查网络流量是否匹配过滤器
  2. 调整采样间隔和时长
  3. 检查系统资源使用情况

#### 6.4.2 BCC 和环境问题解决

**BCC 导入错误**:

```bash
# 检查 Python 路径
sudo python3 -c "import sys; print(sys.path)"
sudo find /usr -name "*bcc*" -type d

# 重新安装 BCC
sudo yum reinstall python3-bcc bcc-tools  # CentOS
sudo apt reinstall python3-bpfcc bpfcc-tools  # openEuler 
```

**内核符号问题**:

```bash
# 检查内核符号表
sudo ls -la /proc/kallsyms
sudo cat /proc/kallsyms | grep "netif_receive_skb"

# 安装内核调试信息
sudo yum install kernel-debuginfo-$(uname -r) kernel-devel-$(uname -r) kernel-headers-$(uname -r) # openEuler/CentOS
```

### 6.5 版本兼容性

#### 6.5.1 内核版本支持

| 内核版本            | 支持状态                          | 说明                                 |
| ------------------- | --------------------------------- | ------------------------------------ |
| 4.19.90 (openEuler) | 全面支持                          | 主要适配目标                         |
| 5.4.x               | 支持                              | 所有功能可用                         |
| 5.10.x LTS          | 支持                              | 推荐使用                             |
| 4.18.x              | 部分支持                          | 部分新特性不可用                     |
| < 4.18              | 不支持(redhat 系系统部分工具支持) | BPF 功能不完整，仅 redhat 系部分支持 |

#### 6.5.2 工具版本支持

| 组件     | 最低版本 | 推荐版本 | 说明                                                                            |
| -------- | -------- | -------- | ------------------------------------------------------------------------------- |
| BCC      | 0.15.0   | 0.25.0+  | 较新版本更好                                                                    |
| bpftrace | 0.10.0   | 0.16.0+  | 支持更多语言特性,部分实现优化                                                   |
| Python   | 2.7      | 3.8+     | 推荐使用 Python 3, 依赖 package: python-bcc 或 python3-bcc，oe 系统 python3-bcc |
| LLVM     | 6.0      | 12.0+    | 更好的 BPF 编译支持                                                             |

## 7. 使用最佳实践

### 7.1 监控最佳实践

#### 7.1.1 生产环境监控

**分层测量**:

1. **基线性能采集** : 使用若干问题域/模块的 summary 版本测量工具，获取问题初筛结果，确定需要做精细 detail 信息测量的范围，即如何进一步过滤
2. **问题时段详细分析** : 部署特定问题域的 details 版测量工具，使用 summary 筛查结果作为过滤器，进一步减小对 workload 影响
3. **持续监控和报警** : 合理设计的 summary metric ， histogram 形式统计， 部署关键模块，核心指标测量。

#### 7.1.2 权限管理

- **Root 权限**: 所有 eBPF 工具需要 root 权限
- **Capability 管理**: 可考虑使用 CAP_BPF 和 CAP_SYS_ADMIN
- **用户隔离**: 建议使用专用的监控用户账号

#### 7.1.3 性能影响控制

- **资源限制**: 监控 CPU 和内存使用情况
- **并发数量**: 同时运行的工具数量不超过 3-5 个

该项目为虚拟化环境的网络性能监控和故障排查提供了全面的 eBPF 工具集，通过合理的部署和使用，可以有效提升网络问题诊断的效率和准确性。
