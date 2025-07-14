# vhost-net 测量程序设计文档

## 问题描述

当前使用 `tun_ring_monitor.py` 监控发现：
- 丢包都发生在 queue 0
- queue 0 监测到丢包时 ptr_ring 的 producer、consumer_head、consumer_tail 都为 0
- VM 内 rx queue 0 的 ethtool -S 计数不再增加
- 问题出现在 vnet 的 queue 0 上

## 处理流程分析

### TUN TX 到 vhost-net 的完整流程

1. **tun_net_xmit** (drivers/net/tun.c)
   ```
   skb → tun_ptr_hash_alloc → ptr_ring_produce(tfile->tx_ring) → 通知 vhost
   ```

2. **vhost-net worker** (drivers/vhost/net.c)
   ```
   worker 线程 → handle_tx → tun_recvmsg → ptr_ring_consume → 发送到 guest
   ```

3. **关键同步点**
   - ptr_ring 生产者/消费者操作
   - vhost worker 工作队列调度
   - guest 通知机制

## 测量目标

### 1. ptr_ring 状态监控
- **生产者操作**：监控 ptr_ring_produce 的成功/失败
- **消费者操作**：监控 ptr_ring_consume 的活动
- **队列状态**：实时监控 producer/consumer 指针变化
- **容量管理**：监控队列满、空状态

### 2. vhost-net worker 状态
- **worker 线程活动**：监控是否正常调度
- **handle_tx 执行**：监控处理频率和耗时
- **工作队列状态**：监控是否有待处理工作

### 3. 队列级别分析
- **per-queue 统计**：每个队列的独立状态
- **queue 0 特殊性**：为什么只有 queue 0 出问题
- **队列间比较**：对比正常队列和异常队列

### 4. 错误条件检测
- **死锁检测**：是否存在锁竞争
- **内存分配失败**：ptr_ring 扩容失败
- **worker 停止**：vhost worker 是否异常退出

## 程序设计

### 工具1：vhost-net-monitor.py (BCC)

**功能**：全面监控 vhost-net 处理流程

**监控点**：
1. `handle_tx` 函数入口/出口
2. `tun_recvmsg` 执行
3. `ptr_ring_consume` 操作
4. vhost worker 调度

**数据收集**：
```c
struct vhost_event {
    u64 timestamp;
    u32 pid;                    // vhost worker PID
    u32 queue_id;              // vhost queue ID
    char dev_name[16];         // vnet device name
    u32 ptr_ring_producer;     // 当前 producer 指针
    u32 ptr_ring_consumer_head; // 当前 consumer_head
    u32 ptr_ring_consumer_tail; // 当前 consumer_tail
    u32 ptr_ring_size;         // 队列大小
    u32 available_work;        // 待处理工作数量
    u32 consumed_packets;      // 本次消费的包数
    u64 worker_last_activity;  // worker 最后活动时间
    u32 event_type;           // 事件类型
    s32 error_code;           // 错误码
};
```

**事件类型**：
- HANDLE_TX_ENTER/EXIT
- PTR_RING_CONSUME_SUCCESS/FAIL
- WORKER_SCHEDULE/IDLE
- QUEUE_STATE_CHANGE

### 工具2：ptr-ring-tracer.bt (bpftrace)

**功能**：轻量级 ptr_ring 操作跟踪

```
kprobe:ptr_ring_produce,
kprobe:ptr_ring_consume
{
    if (comm == "vhost-" || comm == "qemu-system-x86") {
        printf("%s: %s ring=%p producer=%d consumer_head=%d\n",
               comm, probe, arg0, 
               *(uint32*)(arg0 + 0),  // producer offset
               *(uint32*)(arg0 + 4)); // consumer_head offset
    }
}
```

### 工具3：queue-state-monitor.py (BCC)

**功能**：专门监控各个队列的状态变化

**特性**：
- 对比 queue 0 和其他队列的行为差异
- 检测队列状态异常变化
- 统计每个队列的处理性能

### 工具4：vhost-worker-monitor.py (BCC)

**功能**：监控 vhost worker 线程状态

**监控点**：
- worker 线程创建/销毁
- 工作队列调度
- 处理延迟统计

## 关键测量点

### 1. ptr_ring 操作监控
```c
// 在 tun_net_xmit 中
if (ptr_ring_produce(&tfile->tx_ring, skb) < 0) {
    // 记录生产失败事件
}

// 在 tun_ring_recv 中  
skb = ptr_ring_consume(&tfile->tx_ring);
if (!skb) {
    // 记录消费失败/空队列事件
}
```

### 2. vhost worker 活动监控
```c
// 在 vhost_worker 函数中
// 记录 worker 调度事件

// 在 handle_tx 中
// 记录处理开始/结束时间
// 统计处理的包数量
```

### 3. 队列状态快照
定期捕获所有队列的状态：
- ptr_ring 各个指针位置
- 队列中待处理包数量  
- worker 线程状态
- 最近的错误事件

## 预期发现

### 可能的根本原因

1. **ptr_ring 未正确初始化**
   - queue 0 的 ptr_ring 结构损坏
   - 指针重置为 0

2. **vhost worker 停止处理 queue 0**
   - worker 线程选择性忽略 queue 0
   - 工作队列调度异常

3. **通知机制失效**
   - tun 到 vhost 的通知丢失
   - eventfd 或 irqfd 异常

4. **内存管理问题**
   - ptr_ring 内存被覆盖
   - queue 0 的 tfile 结构异常

### 诊断流程

1. **运行基础监控**
   ```bash
   sudo python vhost-net-monitor.py --device vnet0 --queue 0
   ```

2. **对比队列行为**
   ```bash
   sudo python queue-state-monitor.py --device vnet0 --compare-queues
   ```

3. **检查 worker 活动**
   ```bash
   sudo python vhost-worker-monitor.py --track-all-workers
   ```

4. **轻量级实时跟踪**
   ```bash
   sudo bpftrace ptr-ring-tracer.bt
   ```

## 实现优先级

### Phase 1：基础监控 (高优先级)
- vhost-net-monitor.py 核心功能
- queue 状态对比工具

### Phase 2：深度分析 (中优先级)  
- worker 线程监控
- 错误事件统计

### Phase 3：自动化诊断 (低优先级)
- 自动故障检测
- 修复建议生成

## 输出格式

所有工具统一输出格式：
```
[时间戳] [设备] [队列] [事件类型] [详细信息]
```

支持 JSON 格式导出，便于后续分析和可视化。

---

这个设计文档提供了全面的测量框架，可以帮助定位 queue 0 的 ptr_ring 异常问题。