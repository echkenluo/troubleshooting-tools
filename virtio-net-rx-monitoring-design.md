# VM 内 virtio-net 驱动层面 RX 队列监测设计文档

## 1. 问题背景

在 vhost-net queue 0 出现 ptr_ring 全为 0 的问题时，需要从 VM 内部验证：
- virtio-net 驱动是否正常接收各个队列的数据包
- RX 队列的处理能力和负载分布
- NAPI 调度是否均衡
- 与 host 侧 vhost-net 问题的对应关系

## 2. virtio-net RX 处理流程分析

### 2.1 整体架构
```
Host vhost-net → VM virtio-net driver → Network Stack
     ↓                    ↓                    ↓
  ptr_ring            virtqueue              netif_receive_skb
  produce/consume     get_buf/add_buf        protocol processing
```

### 2.2 关键处理路径

**中断到 NAPI 流程**：
1. **vq interrupt** → `skb_recv_done()` (line 1269)
2. **schedule NAPI** → `virtqueue_napi_schedule()`  
3. **NAPI poll** → `virtnet_poll()` (line 1444)
4. **receive packets** → `virtnet_receive()` (line 1336)
5. **process buffer** → `receive_buf()` (line 1038)
6. **deliver to stack** → `netif_receive_skb()`

**关键数据结构**：
```c
struct receive_queue {
    struct virtqueue *vq;           // virtqueue 操作接口
    struct napi_struct napi;        // NAPI 调度结构
    struct virtnet_rq_stats stats; // RX 队列统计
    // ...
};

struct virtnet_rq_stats {
    u64 packets;     // 接收包数
    u64 bytes;       // 接收字节数
    u64 drops;       // 丢包数
    u64 xdp_packets; // XDP 处理包数
    // ...
};
```

## 3. 监测方案设计

### 3.1 监测目标

**核心指标**：
- 每个 RX 队列的包处理速率
- NAPI 调度频率和执行时间
- virtqueue 操作成功/失败率
- 队列间负载均衡情况
- 异常和错误统计

**关联分析**：
- 识别 queue 0 是否真的无活动
- 队列活动与 host 侧 vhost-net 状态的对应关系
- 中断分布和 CPU affinity 影响

### 3.2 可用的 Probe 点

**主要函数** (通过内核符号表确认存在)：
- `virtnet_poll` - NAPI 主处理函数
- `virtnet_receive` - 接收处理函数  
- `receive_buf` - 单包处理函数
- `virtqueue_get_buf` / `virtqueue_get_buf_ctx` - virtqueue 操作
- `virtqueue_kick` / `virtqueue_notify` - virtqueue 通知
- `skb_recv_done` - RX 中断处理函数

**网络层函数**：
- `netif_receive_skb` - 向上层协议栈递交
- `netif_rx` - 网络接收入口
- `__netif_receive_skb_core` - 核心接收处理

### 3.3 监测工具架构

#### 工具 1: `virtio_net_rx_monitor.py` (BCC)

**功能**：全面监控 virtio-net RX 处理流程

**监控事件**：
```c
struct virtio_rx_event {
    u64 timestamp;
    u32 queue_id;           // RX 队列 ID
    char dev_name[16];      // 网络设备名
    u32 event_type;         // 事件类型
    u32 budget;             // NAPI budget
    u32 received;           // 实际处理包数
    u64 duration_ns;        // 处理时长
    u32 vq_num_free;        // virtqueue 空闲缓冲区数
    u32 packet_len;         // 包长度
    s32 error_code;         // 错误码
};
```

**事件类型**：
- `RX_NAPI_POLL_ENTER/EXIT` - NAPI 调度
- `RX_VIRTQUEUE_GET_BUF` - virtqueue 缓冲区获取  
- `RX_RECEIVE_BUF` - 单包处理
- `RX_NETIF_RECEIVE` - 向协议栈递交
- `RX_INTERRUPT` - 中断处理
- `RX_QUEUE_REFILL` - 缓冲区补充

#### 工具 2: `virtio_queue_balance.py` (BCC)

**功能**：专门监控队列间负载均衡

**特性**：
- 实时统计各 RX 队列的活动
- 检测队列负载不均衡
- 对比 queue 0 与其他队列的差异
- 监控 CPU affinity 和中断分布

#### 工具 3: `virtio-rx-debug.bt` (bpftrace)

**功能**：轻量级快速诊断

**监控重点**：
- 每队列包接收计数
- NAPI 调度统计
- 异常和错误事件
- 5 秒间隔摘要报告

### 3.4 实现细节

#### BPF Program 设计

```c
// 监控 NAPI poll
int probe_virtnet_poll_enter(struct pt_regs *ctx, struct napi_struct *napi, int budget) {
    struct receive_queue *rq = container_of(napi, struct receive_queue, napi);
    u32 queue_id = rq - rq->vq->vdev->priv->rq; // 计算队列索引
    
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.queue_id = queue_id;
    event.event_type = RX_NAPI_POLL_ENTER;
    event.budget = budget;
    
    // 保存开始时间用于计算持续时间
    u64 ts = bpf_ktime_get_ns();
    napi_start_times.update(&napi, &ts);
    
    events.perf_submit(ctx, &event, sizeof(event));
}

// 监控 virtqueue 缓冲区获取
int probe_virtqueue_get_buf(struct pt_regs *ctx, struct virtqueue *vq, u32 *len) {
    // 检查是否是 RX virtqueue (通过 callback 函数判断)
    if (vq->callback != skb_recv_done) return 0;
    
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.event_type = RX_VIRTQUEUE_GET_BUF;
    
    // 获取返回值(缓冲区指针)来判断是否成功
    events.perf_submit(ctx, &event, sizeof(event));
}

// 监控包处理
int probe_receive_buf(struct pt_regs *ctx, struct virtnet_info *vi, 
                      struct receive_queue *rq, void *buf, u32 len) {
    u32 queue_id = rq - vi->rq; // 计算队列索引
    
    struct virtio_rx_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.queue_id = queue_id;
    event.event_type = RX_RECEIVE_BUF;
    event.packet_len = len;
    
    events.perf_submit(ctx, &event, sizeof(event));
}
```

#### 队列索引计算

由于需要确定具体的队列 ID，有几种方法：

1. **通过结构体偏移计算**：
   ```c
   // rq 在 vi->rq 数组中的索引
   u32 queue_id = rq - vi->rq;
   ```

2. **通过 virtqueue 索引**：
   ```c
   // virtqueue 编号 (RX队列是偶数: 0,2,4...)
   u32 vq_index = vq->index;
   u32 queue_id = vq_index / 2;  // RX队列索引
   ```

3. **通过 NAPI 结构**：
   ```c
   // 从 napi 结构获取队列信息
   struct receive_queue *rq = container_of(napi, struct receive_queue, napi);
   ```

#### 数据采集策略

**实时监控**：
- 监控每个 NAPI poll 周期的处理结果
- 统计 virtqueue 操作的成功/失败率
- 记录包处理的详细时间线

**周期性统计**：
- 每秒输出各队列的包处理速率
- 计算队列间负载分布
- 检测异常模式（如某队列长时间无活动）

**事件关联**：
- 将中断、NAPI、包处理事件关联
- 跟踪单个包从接收到递交的完整路径
- 分析处理延迟的分布

### 3.5 诊断逻辑

#### 正常状态识别

**健康队列特征**：
- NAPI 定期被调度
- virtqueue_get_buf 有规律返回数据
- 包处理速率与负载相匹配
- 错误率低

#### 异常检测

**Queue 0 异常模式**：
- NAPI 长时间未被调度 (>5s)
- virtqueue_get_buf 持续返回 NULL
- 中断到达但 NAPI 未响应
- 与其他队列活动形成明显对比

**关联分析**：
- VM 内 queue 0 无活动 + Host 侧 ptr_ring 全 0 → 确认问题
- VM 内 queue 0 有活动 + Host 侧 ptr_ring 全 0 → Host 侧问题
- VM 内外都无活动 → 上游问题

## 4. 工具实现优先级

### Phase 1: 基础监控工具 (高优先级)
- `virtio_net_rx_monitor.py` - 核心监控功能
- 重点监控 NAPI 调度和 virtqueue 操作

### Phase 2: 队列分析工具 (中优先级)  
- `virtio_queue_balance.py` - 队列负载均衡分析
- 与 host 侧工具的数据对比

### Phase 3: 自动化诊断 (低优先级)
- `virtio-rx-debug.bt` - 快速诊断脚本
- 异常模式自动识别

## 5. 与 Host 侧工具的配合

### 5.1 联合诊断流程

1. **Host 侧检测**：运行 `vhost_net_monitor.py` 发现 queue 0 异常
2. **VM 侧确认**：运行 `virtio_net_rx_monitor.py` 验证 RX 活动
3. **对比分析**：检查 VM 侧队列活动与 host 侧 ptr_ring 状态的对应关系
4. **定位问题**：确定是 host 侧、VM 侧还是通信机制的问题

### 5.2 数据格式统一

**输出格式**：
```
[时间戳] [设备] [队列] [事件类型] [关键指标]
```

**日志关联**：
- 使用统一的时间戳格式
- 设备名和队列 ID 保持一致
- 支持 JSON 格式导出便于分析

## 6. 预期效果

通过 VM 内监控，能够：

1. **确认问题范围**：区分是 host 侧、VM 侧还是通信机制问题
2. **验证修复效果**：对比修复前后的队列活动变化  
3. **性能优化**：识别队列负载不均衡和调度问题
4. **联合诊断**：与 host 侧工具配合提供完整的数据路径视图

这套工具将为 vhost-net queue 0 问题提供 VM 侧的关键诊断数据，与已有的 host 侧工具形成完整的监控体系。