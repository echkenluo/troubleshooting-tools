# 未测量虚拟化延迟路径深度分析

## 文档概述

本文档是对跨节点 VM ping 延迟分析中未覆盖的两部分虚拟化路径的深度调研分析：

1. **VM 内部**: virtio 网卡驱动 ↔ 有 skb 表示的收发包调用 (netif_receive_skb / dev_queue_xmit)
2. **Host 侧**: vCPU → vhost → tun (在 tun_get_user 之前，没有 skb 概念)

基于 `docs/cross-node-vm-ping-latency-analysis-cn.md` 中的测量方法论和结果。

---

## 第一部分：延迟风险评估

### 1.1 结论

**Host 侧 vCPU → vhost → tun 路径**更可能造成高延迟

### 1.2 对比分析

| 对比项 | VM 内部 virtio 驱动 | Host vCPU→vhost→tun |
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
| vhost→KVM (E) | 42 us | 120 us | +78 us |

**结论**: VM 内部处理基本相同，差异主要在 Host 侧虚拟化路径。

---

## 第二部分：Host 侧路径分析 (vCPU → vhost → tun)

### 2.1 完整事件链

```
Guest 发包:
1. virtqueue_kick() → 写入 ioeventfd (Guest 内部, MMIO/PIO)
   └─► 可能触发 VM Exit 或 Posted Write

Host 响应:
2. ioeventfd_signal() [KVM 模块]
   └─► eventfd_signal(kick_ctx)
       └─► wake_up_locked_poll()
           └─► vhost_poll_wakeup()

3. vhost worker 唤醒 [调度延迟点!]
   └─► schedule() → vhost_worker() 运行
       └─► node = llist_del_all(&dev->work_list)
       └─► work->fn(work) → handle_tx_net()

4. handle_tx_net() 处理
   ├─► vhost_net_tx_get_vq_desc() [批处理开始]
   │   └─► vhost_get_vq_desc() - 获取 desc 索引
   │       └─► 读取 vq->avail->ring[last_avail_idx]
   │       └─► 地址翻译: GPA → HVA
   │
   ├─► copy_from_iter() - 从 Guest 复制数据 [主要开销]
   │
   └─► sock->ops->sendmsg()
       └─► tun_sendmsg()
           └─► tun_get_user() [skb 构建点]
```

### 2.2 关键延迟因素

| 因素 | 描述 | 影响范围 |
|------|------|----------|
| vhost worker 调度 | 内核线程被唤醒到实际运行 | 10-100+ us |
| NUMA 访问 | worker 与 vCPU 不在同一 NUMA 节点 | 2-5x 增加 |
| Guest 内存访问 | GPA→HVA 翻译 + 可能的页错误 | 变化大 |
| 批处理积累 | 等待多个包后一起处理 | 取决于流量 |

### 2.3 可用关联元数据

| 阶段 | 函数 | 可用参数 | 关联信息 |
|------|------|----------|----------|
| 1 | `ioeventfd_signal` | eventfd_ctx | 可通过预建映射关联到 vq |
| 2 | `vhost_poll_wakeup` | vhost_poll | 包含 vq 信息 |
| 3 | **`handle_tx_kick`** | **vhost_work** | **最早可识别 vq 的点** |
| 4 | `handle_tx_net` | vhost_net | 包含所有 vq |
| 5 | `vhost_get_vq_desc` | vq, &head | 返回 desc 索引 |
| 6 | `tun_sendmsg` | sock, msg | sock 关联到 vq->private_data |
| 7 | `tun_get_user` | tun, tfile | 完整上下文 |

### 2.4 最早可识别 vhost/queue 的点

**调用链分析** (来自 kernel/drivers/vhost/vhost.c):

```
Guest: virtqueue_kick() → MMIO write to ioeventfd
    │
    ▼
KVM: ioeventfd_write()
    ├─► eventfd_signal(eventfd_ctx)         [KVM context, only has eventfd_ctx]
    │       │
    │       ▼
    │   wake_up_locked_poll(&ctx->wqh)      [Calls registered callback]
    │
    ▼
vhost_poll_wakeup(wait, mode, sync, key)    ← EARLIEST vhost/vq identification!
    │   poll = container_of(wait, struct vhost_poll, wait)
    │
    ├─► vhost_poll_queue(poll)
    │       ├─► llist_add(&work->node, &dev->work_list)
    │       └─► wake_up_process(dev->worker)  ← vhost worker WOKEN here
    │
    ▼
[Scheduling delay - waiting for vhost worker to run]
    │
    ▼
vhost_worker() runs
    └─► work->fn(work) → handle_tx_kick(work)
```

**关键发现**:

1. **`vhost_poll_wakeup` 是最早可识别 vhost/vq 的点** (仍在 KVM/ioeventfd 上下文)
   ```c
   static int vhost_poll_wakeup(wait_queue_entry_t *wait, unsigned mode,
                                int sync, void *key)
   {
       struct vhost_poll *poll = container_of(wait, struct vhost_poll, wait);
       vhost_poll_queue(poll);  // 队列化工作，唤醒 vhost worker
       return 0;
   }
   ```

2. **`ioeventfd_signal` 无法直接识别 vhost** - 仅有 `eventfd_ctx*`，需要预建映射

3. **调度延迟测量**: `vhost_poll_wakeup` → `handle_tx_kick` = vhost worker 调度延迟 (最关键!)

**结论**:
- `vhost_poll_wakeup` 是最早的识别点 (KVM 上下文)
- `handle_tx_kick` 是 vhost worker 上下文的入口点
- 两者之间的延迟 = vhost worker 调度延迟

**识别链**:
```
handle_tx_kick(work)
    │
    ├─► container_of(work, vhost_virtqueue, poll.work) → vq
    │
    ├─► vq->dev → vhost_dev
    │   └─► container_of(vq->dev, vhost_net, dev) → vhost_net
    │
    └─► vq->private_data → socket
        └─► container_of(socket, tun_file, socket) → tfile
            └─► tfile->tun → tun_struct
                └─► tun->dev → net_device
                    └─► dev->name → 设备名 (如 "vnet0")
```

**队列索引获取方式**:
1. 通过 `tfile->queue_index` 直接获取
2. 通过 `vq - vhost_dev->vqs[0]` 计算偏移

**BPF 实现要点**:
```c
// 在 handle_tx_kick 入口
kprobe:handle_tx_kick {
    struct vhost_work *work = (struct vhost_work *)PT_REGS_PARM1(ctx);

    // container_of 在 BPF 中的实现:
    // vq = (char*)work - offsetof(struct vhost_virtqueue, poll.work)
    // 需要正确计算 offsetof(vhost_virtqueue, poll.work)
    // 该偏移量依赖于内核版本 (call_ctx 是 8 或 72 字节)

    struct vhost_virtqueue *vq = ...;  // container_of result
    void *private_data;
    bpf_probe_read_kernel(&private_data, sizeof(private_data), &vq->private_data);

    // 从 socket 获取 tun_file, 再获取设备名和队列索引
}
```

### 2.5 数据包关联方案

**方案 A: eventfd → tun_sendmsg 批次级别**

```c
// Probe 1: 记录 kick 信号
kprobe:ioeventfd_signal {
    eventfd_ctx = PT_REGS_PARM1(ctx);
    timestamp1[eventfd_ctx] = bpf_ktime_get_ns();
}

// Probe 2: handle_tx_net 入口
kprobe:handle_tx_net {
    vq = ...;  // 从参数获取
    sock = vq->private_data;
    // 通过预建映射: sock → eventfd_ctx
    // 计算调度延迟
}

// Probe 3: tun_sendmsg
kprobe:tun_sendmsg {
    sock = PT_REGS_PARM1(ctx);
    // 关联并计算总延迟
}
```

**方案 B: vhost_get_vq_desc 单包级别**

```c
// 使用 desc 索引作为包标识
kretprobe:vhost_get_vq_desc {
    desc_id = PT_REGS_RC(ctx);
    vq = saved_vq;
    key = make_key(vq, desc_id);
    timestamp[key] = bpf_ktime_get_ns();
}
```

### 2.6 批处理问题

```c
#define VHOST_NET_BATCH 64

// handle_tx_net 处理循环
do {
    head = vhost_net_tx_get_vq_desc(net, vq, ...);
    if (head < 0)
        break;
    // 处理单个 descriptor
    msg.msg_control = NULL;
    sock->ops->sendmsg(sock, &msg, len);
    ++n_packets;
} while (likely(!vhost_exceeds_weight(vq, ++sent_pkts, total_len)));
```

**影响**:
- 单次 handle_tx 可能处理 1-64 个包
- 无法直接测量每个包的调度延迟
- 建议测量批次级别延迟或使用 desc 索引区分

### 2.7 统计直方图方案 (推荐)

由于在 `tun_get_user` 构建 skb 之前无法识别特定数据包 (无法按 IP/Port/ICMP 过滤)，
放弃精确的单包关联，改用**队列级别的统计直方图**方案。

**方案优势**:
- 无需关联具体数据包
- 可按设备名/队列号过滤
- 支持不同环境对比 (ZBS vs SMTX OS)
- 输出延迟分布直方图和时序数据

**测量段设计**:

| 段 | 起点 | 终点 | 统计粒度 |
|----|------|------|----------|
| S1 | `handle_tx_kick` | `handle_tx_kick` 返回 | 批次级别 |
| S2 | `handle_tx_kick` | `tun_sendmsg` (首次调用) | 批次级别 |
| S3 | `tun_sendmsg` 入口 | `tun_sendmsg` 返回 | 单包级别 |

**工具输出示例**:

```
vhost TX Latency Histogram (device=vnet0, queue=0)

S1: handle_tx_kick duration
     usec        : count     distribution
         0 -> 1  : 0        |                                    |
         2 -> 3  : 12       |****                                |
         4 -> 7  : 156      |***************************         |
         8 -> 15 : 234      |****************************************|
        16 -> 31 : 89       |***************                     |
        32 -> 63 : 23       |***                                 |
        64 -> 127: 5        |                                    |

S2: handle_tx_kick -> first tun_sendmsg
     usec        : count     distribution
         0 -> 1  : 45       |*******                             |
         2 -> 3  : 189      |****************************************|
         4 -> 7  : 134      |****************************        |
         8 -> 15 : 56       |***********                         |
        16 -> 31 : 12       |**                                  |

Time series (1s intervals):
Time       S1_avg  S1_p99  S2_avg  S2_p99  Pkts/s
14:32:01   8.2us   45us    3.1us   12us    15234
14:32:02   7.9us   38us    2.9us   11us    16012
14:32:03   12.1us  89us    4.2us   18us    14567
```

**过滤参数**:
- `--dev NAME`: 按设备名过滤 (如 vnet0)
- `--queue N`: 按队列号过滤 (如 0, 1)
- 不指定则聚合所有队列

---

## 第三部分：VM 内部路径分析 (virtio 驱动 ↔ 网络栈)

### 3.1 TX 方向 (dev_queue_xmit → virtio TX)

```
dev_queue_xmit(skb)
    └─► dev_hard_start_xmit(skb, dev)    [skb 可用]
        └─► virtnet_start_xmit(skb, dev) [skb 可用]
            └─► xmit_skb(sq, skb, mergeable)
                ├─► sg_init_table(sq->sg, ...)
                ├─► skb_to_sgvec(skb, sq->sg, ...)
                └─► virtqueue_add_outbuf(vq, sq->sg, num, skb, GFP_ATOMIC)
                    │                              ↑
                    │                         skb 作为 cookie!
                    └─► virtqueue_kick_prepare(vq)
                        └─► virtqueue_notify(vq)
```

**关键发现**: `virtqueue_add_outbuf` 的第 4 个参数 `void *data` 对于 virtio-net TX 就是 **skb 指针**！

### 3.2 RX 方向 (virtio RX → netif_receive_skb)

```
vring_interrupt(irq, _vq)
    └─► vq->callback(&vq->vq)
        └─► skb_recv_done(rvq)
            └─► virtqueue_napi_schedule(&rq->napi, rvq)
                └─► napi_schedule(&rq->napi)

virtnet_poll(napi, budget)
    └─► virtnet_receive(rq, budget, &xdp_xmit)
        │
        │   // 循环获取完成的 buffer
        │   while (stats.packets < budget) {
        │       buf = virtqueue_get_buf_ctx(rq->vq, &len, &ctx);
        │       if (!buf) break;
        │       receive_buf(vi, rq, buf, len, ctx, ...);
        │       stats.packets++;
        │   }
        │
        └─► receive_buf(vi, rq, buf, len, ctx, xdp_xmit, stats)
            ├─► receive_small(dev, vi, rq, buf, ctx, len, ...)
            │   └─► build_skb(buf, buflen)  [skb 创建]
            │       └─► napi_gro_receive(&rq->napi, skb)
            │
            ├─► receive_mergeable(dev, vi, rq, buf, ctx, len, ...)
            │   └─► page_to_skb(vi, rq, page, ...)  [skb 创建]
            │       └─► napi_gro_receive(&rq->napi, skb)
            │
            └─► receive_big(dev, vi, rq, buf, len, stats)
                └─► ... [skb 创建]
```

### 3.3 可用关联元数据

**TX 方向**:

| 函数 | skb 可用 | 说明 |
|------|----------|------|
| `dev_hard_start_xmit` | Yes | 通用 TX 入口 |
| `virtnet_start_xmit` | Yes | virtio-net TX 入口 (可能 inline) |
| `virtqueue_add_outbuf` | Yes (data 参数) | vring 操作 |
| `virtqueue_kick` | No | 通知 host |

**RX 方向**:

| 函数 | 标识符 | 说明 |
|------|--------|------|
| `virtqueue_get_buf_ctx` | buf (返回值) | 获取完成 buffer |
| `receive_buf` | buf (参数) | 单包处理 |
| `napi_gro_receive` | skb | 交付网络栈 |

### 3.4 测量方案

**TX 延迟测量**:

```c
// 方案 1: dev_hard_start_xmit → virtqueue_add_outbuf
BPF_HASH(tx_timestamps, u64, u64);  // key: skb, value: timestamp

kprobe:dev_hard_start_xmit {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    u64 ts = bpf_ktime_get_ns();
    tx_timestamps.update(&skb, &ts);
}

kprobe:virtqueue_add_outbuf {
    void *data = (void *)PT_REGS_PARM4(ctx);  // skb
    u64 *start_ts = tx_timestamps.lookup(&data);
    if (start_ts) {
        u64 latency = bpf_ktime_get_ns() - *start_ts;
        // 输出延迟
        tx_timestamps.delete(&data);
    }
}
```

**RX 延迟测量**:

```c
// 方案: receive_buf 入口到出口
BPF_HASH(rx_timestamps, u64, u64);  // key: buf, value: timestamp

kprobe:receive_buf {
    void *buf = (void *)PT_REGS_PARM3(ctx);  // buf 参数位置取决于实际签名
    u64 ts = bpf_ktime_get_ns();
    rx_timestamps.update(&buf, &ts);
}

kretprobe:receive_buf {
    void *buf = ...; // 需要从入口保存
    u64 *start_ts = rx_timestamps.lookup(&buf);
    if (start_ts) {
        u64 latency = bpf_ktime_get_ns() - *start_ts;
        // 输出延迟
        rx_timestamps.delete(&buf);
    }
}
```

---

## 第四部分：可用 kprobe 函数

### 4.1 内核 4.19 可用函数 (来自 kprobe_functions.txt)

**virtio 相关**:
```
virtqueue_add_outbuf      - TX, data 参数是 skb
virtqueue_get_buf         - RX 简化版
virtqueue_get_buf_ctx     - RX 完整版
virtqueue_kick            - 通知 host (检查是否需要)
virtqueue_kick_prepare    - 准备 kick
virtqueue_notify          - 实际通知
```

**Host 侧 vhost/tun**:
```
# ioeventfd 相关
ioeventfd_signal          - kick 信号 (如果不 inline)

# vhost 相关
vhost_poll_wakeup         - poll 唤醒
handle_tx_kick            - TX kick 处理 (最早可识别 vq 的点!)
handle_rx_kick            - RX kick 处理
handle_tx_net             - TX 处理 (如果不 inline)
handle_rx_net             - RX 处理 (如果不 inline)
vhost_get_vq_desc         - 获取 descriptor

# tun 相关
tun_sendmsg               - tun 发送入口
tun_get_user              - skb 构建点
tun_net_xmit              - tun TX (已有工具)
```

**网络栈通用**:
```
dev_hard_start_xmit       - TX 通用入口
napi_gro_receive          - RX GRO 交付
netif_receive_skb         - RX 交付
```

### 4.2 不可用/可能 inline 的函数

```
virtnet_start_xmit        - 不在 kprobe_functions.txt
xmit_skb                  - 静态内联函数
receive_small/mergeable/big - 静态函数
```

---

## 第五部分：推荐实现方案

### 5.1 新工具: vhost_tx_batch_latency.py (统计直方图方案)

**目标**: 测量 Guest TX → Host 处理的延迟分布

**设计原则**:
- 放弃单包精确关联 (在 tun_get_user 之前无法识别特定包)
- 采用队列级别统计直方图
- 支持按设备/队列过滤
- 输出延迟分布和时序数据

**Trace 点**:
1. `kprobe:vhost_poll_wakeup` - Guest kick 到达 (KVM 上下文，最早识别点)
2. `kprobe:handle_tx_kick` - vhost worker 开始处理 (调度延迟结束点)
3. `kprobe:tun_sendmsg` - 单包发送开始
4. `kprobe:__netif_receive_skb` - 包进入网络栈 (有 skb，可获取 queue_mapping)

**延迟分段**:
| 段 | 起点 | 终点 | 含义 |
|----|------|------|------|
| S0 | vhost_poll_wakeup | handle_tx_kick | **vhost worker 调度延迟** (最关键!) |
| S1 | handle_tx_kick | tun_sendmsg | handle_tx 到首次 tun_sendmsg |
| S2 | tun_sendmsg | __netif_receive_skb | TUN 发送到网络栈 (同步，无调度) |

**完整关联链**:
```
                          关联 Key
                        ═══════════
vhost_poll_wakeup  ─┬─► vq pointer
                    │
handle_tx_kick     ─┴─► vq pointer
                    │
                   ─┬─► socket pointer (vq->private_data)
                    │
tun_sendmsg        ─┴─► socket → tun_file → (dev, queue_index)
                    │
                   ─┬─► (dev, queue_index)
                    │
__netif_receive_skb ┴─► (skb->dev, skb->queue_mapping - 1)
```

**关联可靠性分析**:

| 关联点 | 关联 Key | 可靠性 | 说明 |
|--------|----------|--------|------|
| vhost_poll_wakeup → handle_tx_kick | vq pointer | ✅ 可靠 | 同一 vq，BPF hash map |
| handle_tx_kick → tun_sendmsg | socket pointer | ✅ 可靠 | vq->private_data = sock |
| tun_sendmsg → __netif_receive_skb | (dev, queue) | ✅ 可靠 | skb->queue_mapping 可靠 |

**skb->queue_mapping 可靠性**:
- TUN 驱动在 `tun_rx_batched()` 中调用 `skb_record_rx_queue(skb, tfile->queue_index)`
- 该字段存储在 skb 中，不会被 RPS/backlog 修改
- 在 `__netif_receive_skb` 中通过 `skb->queue_mapping - 1` 获取原始 queue_index

**注意**: Per-CPU 关联有 RPS 风险 (包可能被转发到其他 CPU)，推荐使用 hash map。

**BPF 实现** (使用 (dev, queue) hash map):
```c
// 关联 Key: (设备指针, 队列号)
struct queue_key {
    u64 dev_ptr;
    u16 queue_index;
    u16 pad[3];
};

// 各阶段时间戳 maps
BPF_HASH(wakeup_ts, u64, u64, 256);           // key: vq pointer
BPF_HASH(kick_ts, struct queue_key, u64, 256); // key: (dev, queue)
BPF_HASH(send_ts, struct queue_key, u64, 256); // key: (dev, queue)

// 延迟直方图 (per queue)
BPF_HISTOGRAM(s0_hist, u64, 64);  // vhost_poll_wakeup → handle_tx_kick
BPF_HISTOGRAM(s1_hist, u64, 64);  // handle_tx_kick → tun_sendmsg
BPF_HISTOGRAM(s2_hist, u64, 64);  // tun_sendmsg → __netif_receive_skb

// S0: vhost_poll_wakeup (KVM 上下文，最早识别点)
kprobe:vhost_poll_wakeup {
    wait_queue_entry_t *wait = (wait_queue_entry_t *)PT_REGS_PARM1(ctx);
    struct vhost_poll *poll = CONTAINER_OF_POLL_WAIT(wait);
    struct vhost_virtqueue *vq = CONTAINER_OF_VQ_POLL(poll);

    u64 vq_key = (u64)vq;
    u64 ts = bpf_ktime_get_ns();
    wakeup_ts.update(&vq_key, &ts);
}

// S0 end, S1 start: handle_tx_kick (vhost worker 上下文)
kprobe:handle_tx_kick {
    struct vhost_work *work = (struct vhost_work *)PT_REGS_PARM1(ctx);
    struct vhost_virtqueue *vq = CONTAINER_OF_POLL_WORK(work);

    // S0: 计算调度延迟
    u64 vq_key = (u64)vq;
    u64 *wakeup = wakeup_ts.lookup(&vq_key);
    if (wakeup) {
        u64 s0_lat = bpf_ktime_get_ns() - *wakeup;
        s0_hist.increment(bpf_log2l(s0_lat / 1000));  // us
        wakeup_ts.delete(&vq_key);
    }

    // 获取 (dev, queue) 用于后续关联
    void *sock;
    bpf_probe_read_kernel(&sock, sizeof(sock), &vq->private_data);
    // sock → tun_file → (dev, queue_index)
    struct queue_key key = get_queue_key_from_socket(sock);

    u64 ts = bpf_ktime_get_ns();
    kick_ts.update(&key, &ts);
}

// S1 end, S2 start: tun_sendmsg
kprobe:tun_sendmsg {
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    struct queue_key key = get_queue_key_from_socket(sock);

    // S1: handle_tx_kick → tun_sendmsg
    u64 *kick = kick_ts.lookup(&key);
    if (kick) {
        u64 s1_lat = bpf_ktime_get_ns() - *kick;
        s1_hist.increment(bpf_log2l(s1_lat / 1000));
        // 不删除 kick_ts，因为一个批次有多个 tun_sendmsg
    }

    // S2 start
    u64 ts = bpf_ktime_get_ns();
    send_ts.update(&key, &ts);
}

// S2 end: __netif_receive_skb (同步执行，同 CPU)
kprobe:__netif_receive_skb {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

    // 从 skb 获取 (dev, queue)
    struct net_device *dev;
    bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev);

    u16 queue_mapping;
    bpf_probe_read_kernel(&queue_mapping, sizeof(queue_mapping), &skb->queue_mapping);
    u16 queue_index = queue_mapping - 1;  // skb_get_rx_queue

    struct queue_key key = {.dev_ptr = (u64)dev, .queue_index = queue_index};

    // S2: tun_sendmsg → __netif_receive_skb
    u64 *send = send_ts.lookup(&key);
    if (send) {
        u64 s2_lat = bpf_ktime_get_ns() - *send;
        s2_hist.increment(bpf_log2l(s2_lat / 1000));
        send_ts.delete(&key);
    }
}

// 辅助函数: 从 socket 获取 (dev, queue_index)
static inline struct queue_key get_queue_key_from_socket(void *sock) {
    // socket 是 tun_file->socket
    // tun_file = container_of(sock, struct tun_file, socket)
    struct tun_file *tfile = CONTAINER_OF_TUN_FILE_SOCKET(sock);

    u16 queue_index;
    bpf_probe_read_kernel(&queue_index, sizeof(queue_index), &tfile->queue_index);

    struct tun_struct *tun;
    bpf_probe_read_kernel(&tun, sizeof(tun), &tfile->tun);

    struct net_device *dev;
    bpf_probe_read_kernel(&dev, sizeof(dev), &tun->dev);

    struct queue_key key = {.dev_ptr = (u64)dev, .queue_index = queue_index};
    return key;
}
```

**命令行参数**:
```
--dev NAME      Filter by device name (e.g., vnet0)
--queue N       Filter by queue number (0, 1, ...)
--interval N    Output interval in seconds (default: 1)
--histogram     Show latency histogram (default: on)
--timeseries    Show time series data
```

**预期输出**:
```
vhost TX Path Latency (device=vnet0, queue=0)

S0: vhost_poll_wakeup → handle_tx_kick (vhost worker scheduling delay)
     usec        : count     distribution
         0 -> 1  : 5        |*                                       |
         2 -> 3  : 45       |*********                               |
         4 -> 7  : 189      |****************************************|
         8 -> 15 : 156      |*********************************       |
        16 -> 31 : 78       |****************                        |
        32 -> 63 : 23       |****                                    |
        64 -> 127: 8        |*                                       |

S1: handle_tx_kick → tun_sendmsg (vhost batch processing start)
     usec        : count     distribution
         0 -> 1  : 234      |****************************************|
         2 -> 3  : 156      |**************************              |
         4 -> 7  : 45       |*******                                 |

S2: tun_sendmsg → __netif_receive_skb (TUN to network stack, sync)
     usec        : count     distribution
         0 -> 1  : 312      |****************************************|
         2 -> 3  : 89       |***********                             |
         4 -> 7  : 12       |*                                       |

Time series (1s intervals):
Time       S0_avg  S0_p99  S1_avg  S2_avg  Pkts/s
14:32:01   12.3us  78us    1.2us   0.8us   15234
14:32:02   11.8us  65us    1.1us   0.9us   16012
14:32:03   45.2us  234us   1.5us   1.1us   14567  ← scheduling spike
```

**关键指标解读**:
- **S0 (调度延迟)**: 最可能出现高延迟的段，与 CPU 调度/NUMA 相关
- **S1 (批处理启动)**: 通常很短 (< 5us)
- **S2 (TUN→网络栈)**: 同步执行，无调度，通常 < 3us

### 5.2 新工具: virtio_net_stack_latency.py (VM 内部)

**目标**:
- TX: dev_hard_start_xmit → virtqueue_add_outbuf
- RX: receive_buf 处理延迟

**Trace 点 (TX)**:
1. `kprobe:dev_hard_start_xmit` - skb 入口
2. `kprobe:virtqueue_add_outbuf` - vring 操作

**Trace 点 (RX)**:
1. `kprobe:receive_buf` - buf 入口
2. `kretprobe:receive_buf` - 处理完成

### 5.3 完整测量覆盖

结合现有和新工具:

```
完整 RTT 分解:

Sender VM:
├─ [A] icmp_send → dev_queue_xmit             (kernel_icmp_rtt Path1)
├─ [NEW] dev_hard_start_xmit → virtqueue_add  (virtio_net_stack_latency TX)
├─ [U1] virtqueue_kick → ioeventfd            (未测量, < 5us)

Sender Host:
├─ [NEW] ioeventfd → handle_tx → tun_sendmsg  (vhost_tx_latency)
├─ [B] tun_net_xmit → phy TX                  (icmp_drop_detector)

Physical Network:
├─ [C] 物理线缆                               (派生计算)

Receiver Host:
├─ [D] phy RX → vnet TX                       (icmp_drop_detector)
├─ [E] tun_net_xmit → KVM IRQ                 (tun_tx_to_kvm_irq)

Receiver VM:
├─ [U2] KVM IRQ → virtnet_poll                (未测量, 需 vCPU 调度分析)
├─ [NEW] receive_buf 处理                     (virtio_net_stack_latency RX)
├─ [F] napi_gro_receive → icmp_rcv            (kernel_icmp_rtt Path1)
...
```

---

## 第六部分：实现优先级

### 优先级 1: Host 侧 vhost_tx_latency

**原因**:
- ZBS 数据显示主要差异在 Host 侧
- vhost worker 调度是已知的延迟热点
- 与现有 tun_tx_to_kvm_irq 形成互补

### 优先级 2: VM 内部 RX 路径

**原因**:
- receive_buf 可能因 buffer 策略不同有差异
- GRO 处理开销可测量

### 优先级 3: VM 内部 TX 路径

**原因**:
- 通常相对稳定
- 作为完整性补充

---

## 附录: 关键数据结构

### A.1 vhost_virtqueue 结构 (Host 侧)

```c
struct vhost_virtqueue {
    struct vhost_dev *dev;
    struct mutex mutex;
    unsigned int num;
    struct vring_desc __user *desc;
    struct vring_avail __user *avail;
    struct vring_used __user *used;

    u16 last_avail_idx;          // 用于跟踪进度
    u16 last_used_idx;

    struct vhost_vring_call call_ctx;  // eventfd 上下文
    void *private_data;                 // 指向 &tfile->socket
    // ...
};
```

### A.2 receive_queue 结构 (VM 侧)

```c
struct receive_queue {
    struct virtqueue *vq;        // 偏移 0
    struct napi_struct napi;     // 偏移 8 (用于 container_of)
    struct bpf_prog __rcu *xdp_prog;
    struct virtnet_rq_stats stats;
    struct page *pages;
    // ...
};
```

### A.3 send_queue 结构 (VM 侧)

```c
struct send_queue {
    struct virtqueue *vq;
    struct scatterlist sg[MAX_SKB_FRAGS + 2];
    char name[40];
    struct virtnet_sq_stats stats;
    struct napi_struct napi;
};
```

---

*文档版本: 1.0*
*创建日期: 2026-01-09*
*基于: troubleshooting-tools 代码库和内核源码分析*
