# VM 内 virtio-net RX 队列监测工具使用指南

## 概述

本指南介绍如何在 VM 内使用新开发的 virtio-net RX 队列监测工具来诊断 vhost-net queue 0 问题。这些工具与 host 侧工具配合，提供完整的端到端诊断能力。

## 工具列表

### 1. `virtio_net_rx_monitor.py` - 核心监控工具
- **功能**：全面监控 virtio-net RX 处理流程
- **适用场景**：详细分析特定队列的行为
- **输出**：NAPI 调度、包处理、队列状态的详细事件流

### 2. `virtio_queue_balance.py` - 队列负载均衡分析
- **功能**：专门分析队列间负载分布和 CPU 亲和性
- **适用场景**：识别队列不平衡和 queue 0 异常
- **输出**：队列活动对比、负载分布、异常检测

### 3. `virtio-rx-debug.bt` - 快速诊断脚本
- **功能**：轻量级实时监控和自动异常检测
- **适用场景**：快速确认问题存在
- **输出**：定期统计摘要和异常警告

## 使用流程

### 快速诊断流程

1. **快速确认问题**（在 VM 内运行）：
   ```bash
   sudo bpftrace virtio-rx-debug.bt
   ```
   观察是否出现 "Queue 0 inactive" 警告

2. **详细队列分析**（在 VM 内运行）：
   ```bash
   sudo python2 virtio_queue_balance.py --device eth0 --interval 5
   ```
   检查队列活动分布和 queue 0 状态

3. **深度事件监控**（在 VM 内运行）：
   ```bash
   sudo python2 virtio_net_rx_monitor.py --device eth0 --show-packets
   ```
   查看详细的包处理事件

### 与 Host 侧工具配合诊断

**完整诊断流程**：

1. **Host 侧检测**：
   ```bash
   # 在 host 上运行
   sudo python2 vhost_net_monitor.py --device vnet0 --queue 0
   ```

2. **VM 侧验证**：
   ```bash
   # 在 VM 内运行
   sudo python2 virtio_queue_balance.py --device eth0
   ```

3. **数据关联分析**：
   - Host 侧显示 ptr_ring 全 0
   - VM 侧显示 queue 0 无包接收
   - → 确认 vhost-net queue 0 问题

## 详细使用说明

### virtio_net_rx_monitor.py

**基本用法**：
```bash
# 监控所有 virtio-net RX 活动
sudo python2 virtio_net_rx_monitor.py

# 监控特定设备
sudo python2 virtio_net_rx_monitor.py --device eth0

# 监控特定设备和队列，显示包详情
sudo python2 virtio_net_rx_monitor.py --device eth0 --queue 0 --show-packets

# 详细事件输出
sudo python2 virtio_net_rx_monitor.py --verbose
```

**输出示例**：
```
[14:30:15.123] eth0     Q0  NAPI_POLL_ENTER   budget=64 CPU0
[14:30:15.124] eth0     Q0  RECEIVE_BUF       len=1500 CPU0 skb=0xffff888123456789
[14:30:15.125] eth0     Q0  NETIF_RECEIVE     len=1500 CPU0 skb=0xffff888123456789
[14:30:15.126] eth0     Q0  NAPI_POLL_EXIT    received=5 CPU0
```

**关键指标**：
- `NAPI_POLL_ENTER/EXIT`: NAPI 调度频率和处理包数
- `RECEIVE_BUF`: 单包处理事件
- `NETIF_RECEIVE`: 向协议栈递交事件
- 5 秒间隔的队列统计摘要

### virtio_queue_balance.py

**基本用法**：
```bash
# 队列负载均衡分析，10s 间隔
sudo python2 virtio_queue_balance.py

# 特定设备，5s 间隔
sudo python2 virtio_queue_balance.py --device eth0 --interval 5

# 显示详细事件
sudo python2 virtio_queue_balance.py --detailed
```

**输出示例**：
```
================================================================================
VIRTIO-NET QUEUE BALANCE ANALYSIS
================================================================================
Queue  Status     Packets  PPS      Bytes      BPS        NAPI   CPU Dist        Last Seen 
--------------------------------------------------------------------------------
Q0     🚨 STALE   0        0.0      0          0.0        0      N/A             Never     
Q1     ✅ ACTIVE  1250     125.0    1875000    187500.0   45     CPU1(+2)        2.1s      
Q2     ✅ ACTIVE  980      98.0     1470000    147000.0   38     CPU2            1.8s      

📊 Summary:
  Total packets this interval: 2230
  Active queues: [1, 2]
  Stale queues: [0]
  🚨 CRITICAL: Queue 0 is stale while other queues are active!
     This matches the reported vhost-net queue 0 issue pattern.
```

**关键指标**：
- **Status**: ✅ ACTIVE, 🚨 STALE, 💤 IDLE
- **PPS/BPS**: 每秒包数和字节数
- **CPU Dist**: CPU 亲和性分布
- **Last Seen**: 最后活动时间

### virtio-rx-debug.bt

**基本用法**：
```bash
# 快速诊断监控
sudo bpftrace virtio-rx-debug.bt
```

**输出示例**：
```
TIME         DEV      QUEUE    CPU    TYPE     DETAILS
14:30:15     eth0     Q1       1      PKT_RX   len=1500
14:30:15     N/A      NAPI     1      POLL_IN  budget=64
14:30:15     N/A      NAPI     1      POLL_OUT received=5

📊 Activity Summary (last 10s):
RX Packets by Queue:
@queue_packets[1]: 1250
@queue_packets[2]: 980
🚨 WARNING: Queue 0 inactive while other queues are active!
   This indicates the queue 0 issue is present.

NAPI: polls=83 received=2230 softirq_total=150 drops=0
```

**异常检测**：
- 自动检测 queue 0 无活动的情况
- 监控 CPU 亲和性问题
- 跟踪包丢弃和中断分布
- 定期输出统计摘要

## 诊断场景和解读

### 场景 1: 确认 Queue 0 问题

**症状**：
- Host 侧：`vhost_net_monitor.py` 显示 queue 0 ptr_ring 全 0
- VM 侧：`virtio_queue_balance.py` 显示 queue 0 无活动

**诊断步骤**：
1. 在 VM 内运行：`sudo bpftrace virtio-rx-debug.bt`
2. 观察 10s 摘要是否显示 "Queue 0 inactive" 警告
3. 运行：`sudo python2 virtio_queue_balance.py --interval 5`
4. 确认 Queue 0 状态为 "STALE" 而其他队列为 "ACTIVE"

**结论**：确认 vhost-net queue 0 问题存在

### 场景 2: 排除 VM 侧问题

**症状**：
- Host 侧：ptr_ring 异常
- VM 侧：所有队列正常活动

**诊断步骤**：
1. 运行：`sudo python2 virtio_net_rx_monitor.py --queue 0 --verbose`
2. 观察 queue 0 是否有 NAPI 和包处理事件
3. 如果 VM 侧 queue 0 正常，问题在 host 侧

### 场景 3: 负载不均衡分析

**症状**：
- 某些队列负载过高，其他队列空闲

**诊断步骤**：
1. 运行：`sudo python2 virtio_queue_balance.py --detailed`
2. 检查 "Load imbalance detected" 警告
3. 分析 CPU 分布和队列亲和性

## 与 Host 侧工具的数据关联

### 数据对比表

| 指标 | Host 侧工具 | VM 侧工具 | 正常状态 | Queue 0 问题状态 |
|------|-------------|-----------|----------|------------------|
| ptr_ring producer | vhost_net_monitor | N/A | >0 | 0 |
| ptr_ring consumer | vhost_net_monitor | N/A | >0 | 0 |
| NAPI 调度 | N/A | virtio_net_rx_monitor | 定期调度 | queue 0 无调度 |
| 包接收计数 | N/A | virtio_queue_balance | 各队列均有 | queue 0 为 0 |
| vhost worker | vhost_net_monitor | N/A | 正常工作 | queue 0 无活动 |

### 联合诊断脚本示例

```bash
#!/bin/bash
# 联合诊断脚本（需在 host 和 VM 中分别运行）

echo "=== Host 侧检测 ==="
sudo python2 vhost_net_monitor.py --device vnet0 --queue 0 > host_monitor.log 2>&1 &
HOST_PID=$!

echo "=== VM 侧检测 ==="
sudo python2 virtio_queue_balance.py --device eth0 --interval 5 > vm_monitor.log 2>&1 &
VM_PID=$!

echo "监控 30 秒..."
sleep 30

kill $HOST_PID $VM_PID

echo "=== 结果分析 ==="
grep "ptr_ring" host_monitor.log
grep "Queue 0" vm_monitor.log
```

## 故障排除

### 常见问题

1. **BPF 程序加载失败**：
   ```bash
   # 检查内核版本和 BPF 支持
   uname -r
   ls /sys/kernel/debug/tracing/
   
   # 确保有 root 权限
   sudo -i
   ```

2. **找不到 virtio-net 函数**：
   ```bash
   # 检查 virtio_net 模块是否加载
   lsmod | grep virtio_net
   
   # 检查可用的内核函数
   sudo bpftrace -l 'kprobe:*virtnet*'
   ```

3. **设备名识别错误**：
   ```bash
   # 确认网络设备名称
   ip link show
   
   # 确认设备类型
   ethtool -i eth0 | grep driver
   ```

### 性能影响

- **virtio-rx-debug.bt**: 最轻量级，生产环境可用
- **virtio_queue_balance.py**: 中等开销，适合短期监控
- **virtio_net_rx_monitor.py**: 详细监控，开销较大，用于深度分析

### 日志保存和分析

```bash
# 保存监控数据
sudo python2 virtio_queue_balance.py --device eth0 > vm_queue_analysis.log 2>&1

# 提取关键信息
grep "CRITICAL\|WARNING" vm_queue_analysis.log
grep "Queue 0" vm_queue_analysis.log

# 与 host 侧数据关联
paste host_monitor.log vm_monitor.log | grep -E "queue.*0|ptr_ring"
```

## 总结

这套 VM 内监控工具为 vhost-net queue 0 问题提供了关键的诊断能力：

1. **确认问题范围**：区分 host 侧、VM 侧问题
2. **验证修复效果**：量化修复前后的改善
3. **性能调优**：识别负载不均衡问题
4. **端到端诊断**：与 host 侧工具配合提供完整视图

通过这些工具，可以快速定位 vhost-net queue 0 问题的根本原因，并验证修复方案的有效性。