# TUN TX to KVM IRQ Interrupt Chain Analysis

## Overview

This document provides a comprehensive analysis of the kernel interrupt chain from TUN device TX to KVM guest interrupt injection. The analysis covers the complete data flow, correlation mechanisms, and probe point selection for the `tun_tx_to_kvm_irq.py` tracing tool.

## Complete Kernel Call Chain

```
tun_net_xmit
    ↓
vhost_add_used_and_signal_n
    ↓
vhost_signal
    ↓
eventfd_signal
    ↓
eventfd_signal_mask
    ↓
wake_up_locked_poll
    ↓
irqfd_wakeup
    ↓
kvm_arch_set_irq_inatomic
    ↓
kvm_apic_set_irq / __apic_accept_irq
    ↓
vmx_deliver_posted_interrupt (if APICv enabled)
```

## Stage-by-Stage Analysis

### Stage 1: tun_net_xmit

**Source**: `drivers/net/tun.c`

```c
static netdev_tx_t tun_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct tun_struct *tun = netdev_priv(dev);
    struct tun_file *tfile;
    int txq = skb->queue_mapping;

    // Get tfile for this queue
    tfile = rcu_dereference(tun->tfiles[txq]);

    // Queue packet to ptr_ring
    if (ptr_ring_produce(&tfile->tx_ring, skb)) {
        // Ring full - drop packet
    }

    // Wake up vhost via socket callback
    tfile->socket.sk->sk_data_ready(tfile->socket.sk);

    return NETDEV_TX_OK;
}
```

**Key Data Structures**:

- `struct tun_file`: Contains `socket` member that vhost uses for correlation
- `tfile->socket`: This is the socket pointer passed to vhost via `tun_get_socket()`

**Correlation Output**: `sock_ptr = &tfile->socket`

### Stage 2: vhost_signal (via vhost_add_used_and_signal_n)

**Source**: `drivers/vhost/vhost.c`

```c
void vhost_add_used_and_signal_n(struct vhost_dev *dev,
                                  struct vhost_virtqueue *vq,
                                  struct vring_used_elem *heads,
                                  unsigned count)
{
    vhost_add_used_n(vq, heads, count);
    vhost_signal(dev, vq);
}

void vhost_signal(struct vhost_dev *dev, struct vhost_virtqueue *vq)
{
    if (vq->call_ctx.ctx && vhost_notify(dev, vq))
        eventfd_signal(vq->call_ctx.ctx, 1);
}
```

**Key Data Structures**:

- `struct vhost_virtqueue`: Contains `private_data` (socket pointer) and `call_ctx` (eventfd)
- `vq->private_data`: Points to `&tfile->socket` (set by vhost_net_open via tun_get_socket)
- `vq->call_ctx.ctx`: eventfd_ctx pointer used for KVM notification

**Correlation Mechanism**:

- Input: `sock_ptr` from Stage 1
- Match: `vq->private_data == sock_ptr`
- Output: `eventfd_ctx = vq->call_ctx.ctx`

### Stage 3: irqfd_wakeup

**Source**: `virt/kvm/eventfd.c`

```c
static int irqfd_wakeup(wait_queue_entry_t *wait, unsigned mode,
                        int sync, void *key)
{
    struct kvm_kernel_irqfd *irqfd =
        container_of(wait, struct kvm_kernel_irqfd, wait);
    __poll_t flags = key_to_poll(key);

    if (flags & EPOLLIN) {
        // Inject interrupt to guest
        if (kvm_arch_set_irq_inatomic(&irq, kvm,
                      KVM_USERSPACE_IRQ_SOURCE_ID, 1,
                      false) == -EWOULDBLOCK)
            schedule_work(&irqfd->inject);
    }

    return 0;
}
```

**Key Data Structures**:

- `struct kvm_kernel_irqfd`: Contains `eventfd` (eventfd_ctx pointer) and `gsi`
- `irqfd->eventfd`: Same eventfd_ctx as `vq->call_ctx.ctx`
- `irqfd->gsi`: Guest System Interrupt number

**Correlation Mechanism**:

- Input: `eventfd_ctx` from Stage 2
- Match: `irqfd->eventfd == eventfd_ctx`
- Output: `gsi` (interrupt number)

**Setup (kvm_irqfd_assign)**:

```c
static int kvm_irqfd_assign(struct kvm *kvm, struct kvm_irqfd *args)
{
    irqfd->eventfd = eventfd;                    // Line 328
    irqfd->gsi = args->gsi;                      // Line 310
    init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);  // Line 383

    // Register on eventfd's waitqueue
    events = vfs_poll(f.file, &irqfd->pt);       // Line 409
}
```

### Stage 4: eventfd_signal (Entry Point)

**Source**: `fs/eventfd.c`

```c
__u64 eventfd_signal(struct eventfd_ctx *ctx, __u64 n)
{
    return eventfd_signal_mask(ctx, n, 0);
}

__u64 eventfd_signal_mask(struct eventfd_ctx *ctx, __u64 n, unsigned mask)
{
    spin_lock_irqsave(&ctx->wqh.lock, flags);
    ctx->count += n;
    if (waitqueue_active(&ctx->wqh))
        wake_up_locked_poll(&ctx->wqh, EPOLLIN | mask);  // Triggers irqfd_wakeup
    spin_unlock_irqrestore(&ctx->wqh.lock, flags);
    return n;
}
```

**Important**: `eventfd_signal` kprobe fires at function entry, BEFORE `wake_up_locked_poll` is called. This means:

1. `trace_eventfd_signal` fires first
2. `irqfd_wakeup` is called from within `eventfd_signal`
3. `trace_irqfd_wakeup` fires second

### Stage 5: vmx_deliver_posted_interrupt (Optional)

**Source**: `arch/x86/kvm/vmx/vmx.c`

```c
static int vmx_deliver_posted_interrupt(struct kvm_vcpu *vcpu, int vector)
{
    // Hardware posted interrupt delivery
    // Only receives vcpu and vector - NO eventfd_ctx!
}
```

**Critical Finding**: This function does NOT have access to eventfd_ctx, so correlation with specific vnet queue is NOT possible at this stage.

## Correlation Chain Summary

```
Stage 1 (tun_net_xmit)
    │
    │ sock_ptr = &tfile->socket
    ↓
Stage 2 (vhost_signal)
    │ Match: vq->private_data == sock_ptr
    │
    │ eventfd_ctx = vq->call_ctx.ctx
    ↓
Stage 3 (irqfd_wakeup)
    │ Match: irqfd->eventfd == eventfd_ctx
    │
    │ gsi = irqfd->gsi
    ↓
Stage 4+ (kvm_arch_set_irq_inatomic, vmx_deliver_posted_interrupt)
    │
    │ eventfd_ctx is LOST - cannot correlate!
    ↓
Guest receives interrupt
```

## Kernel Structure Layouts

### vhost_virtqueue (Kernel 4.x vs 5.x)

**Kernel 4.x** (without irqbypass):

```c
struct vhost_virtqueue {
    struct vhost_dev *dev;
    struct mutex mutex;
    unsigned int num;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
    void *meta_iotlb[3];
    struct file *kick;
    struct eventfd_ctx *call_ctx;      // Direct pointer (8 bytes)
    struct eventfd_ctx *error_ctx;
    struct eventfd_ctx *log_ctx;
    // ... rest of structure
};
```

**Kernel 5.x** (with irqbypass):

```c
struct vhost_vring_call {
    struct eventfd_ctx *ctx;           // 8 bytes
    struct irq_bypass_producer producer;  // 64 bytes
};  // Total: 72 bytes

struct vhost_virtqueue {
    struct vhost_dev *dev;
    struct mutex mutex;
    unsigned int num;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
    void *meta_iotlb[3];
    struct file *kick;
    struct vhost_vring_call call_ctx;  // 72 bytes (not 8!)
    struct eventfd_ctx *error_ctx;
    struct eventfd_ctx *log_ctx;
    // ... rest of structure
};
```

### kvm_kernel_irqfd

**Field Offsets** (measured on actual kernels):

| Field     | Kernel 4.19 | Kernel 5.10 |
| --------- | ----------- | ----------- |
| kvm       | 0           | 0           |
| wait      | 8           | 8           |
| irq_entry | varies      | varies      |
| gsi       | 72          | 72          |
| eventfd   | 104         | 232         |

The offset difference for `eventfd` is due to different sizes of `kvm_kernel_irq_routing_entry` between kernel versions.

## IRQ Bypass vs Software Path

### Software Path (vhost-net default)

```
vhost_signal
    ↓
eventfd_signal(vq->call_ctx.ctx)
    ↓
wake_up_locked_poll
    ↓
irqfd_wakeup
    ↓
kvm_arch_set_irq_inatomic
    ↓
kvm_apic_set_irq / __apic_accept_irq
    ↓
vmx_deliver_posted_interrupt (APICv enabled)
    or
kvm_vcpu_kick (APICv disabled)
```

### Hardware IRQ Bypass Path (vDPA)

The IRQ bypass path is ONLY used for vDPA (virtio Data Path Acceleration) devices with real hardware interrupts:

```c
// From virt/lib/irqbypass.c
int irq_bypass_register_producer(struct irq_bypass_producer *producer)
{
    // Matches producer (hardware IRQ) with consumer (KVM irqfd)
    // Uses token (eventfd_ctx) for matching
}
```

**vhost-net does NOT use IRQ bypass** because:

1. It doesn't have real hardware interrupts
2. The `producer` in `vhost_vring_call` is never registered
3. Interrupt delivery goes through the software path

However, APICv/Posted Interrupts can still be used at the final delivery stage (`vmx_deliver_posted_interrupt`) even with the software path.

## Probe Point Selection

### Recommended Probe Points

| Stage | Function                     | Purpose                                  |
| ----- | ---------------------------- | ---------------------------------------- |
| 1     | tun_net_xmit                 | Capture packet entry, get socket pointer |
| 2     | vhost_add_used_and_signal_n  | Get eventfd_ctx from vq->call_ctx        |
| 3     | irqfd_wakeup                 | Key correlation point, get GSI           |
| 4     | eventfd_signal               | Debug/monitoring (fires before Stage 3)  |
| 5     | vmx_deliver_posted_interrupt | Optional (no correlation possible)       |

### Why NOT to Use Certain Probe Points

1. **vhost_signal**: Inlined in some kernels
2. **kvm_set_irq**: No eventfd_ctx available
3. **kvm_arch_set_irq_inatomic**: No eventfd_ctx available
4. **__apic_accept_irq**: Only has vector, no queue correlation

## Sequence Validation Issue and Fix

### Original Problem

The original code had strict sequence validation:

```c
// In trace_irqfd_wakeup (Stage 3)
u64 *last_stage = sequence_check.lookup(&eventfd_ctx);
if (!last_stage || *last_stage != 2) {
    return 0;  // Expected Stage 2
}

// In trace_eventfd_signal (Stage 4)
if (*last_stage != 2 && *last_stage != 3) {
    return 0;
}
// Update to Stage 4
u64 current_stage = 4;
sequence_check.update(&eventfd_ctx, &current_stage);
```

**Problem**: Since `eventfd_signal` kprobe fires at function entry:

1. `trace_eventfd_signal` updates sequence to 4
2. `irqfd_wakeup` is called from within `eventfd_signal`
3. `trace_irqfd_wakeup` sees stage 4, not 2, and returns early!

### Fix

1. Remove sequence validation from `trace_irqfd_wakeup` - map lookup is sufficient
2. Don't update sequence in `trace_eventfd_signal` - let Stage 3 update it

```c
// Fixed trace_irqfd_wakeup (Stage 3)
struct interrupt_connection *ic_info = interrupt_chains.lookup(&eventfd_ctx);
if (!ic_info) {
    return 0;  // Only check map lookup - no sequence validation
}

// Fixed trace_eventfd_signal (Stage 4)
u64 *last_stage = sequence_check.lookup(&eventfd_ctx);
if (!last_stage || *last_stage != 2) {
    return 0;
}
// Don't update sequence - let Stage 3 update it
```

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HOST KERNEL                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │  TUN Device  │     │  vhost-net   │     │     KVM      │        │
│  │              │     │              │     │              │        │
│  │ tun_net_xmit │────▶│ handle_rx    │     │  irqfd_wakeup│        │
│  │              │     │      │       │     │      │       │        │
│  │ sock_ptr ────┼─────┼──────┘       │     │      ▼       │        │
│  │              │     │              │     │ kvm_set_irq  │        │
│  └──────────────┘     │ vhost_signal │     │      │       │        │
│                       │      │       │     │      ▼       │        │
│                       │ eventfd_ctx ─┼─────┼──▶ inject    │        │
│                       │      │       │     │              │        │
│                       │      ▼       │     └──────────────┘        │
│                       │ eventfd_signal                              │
│                       │      │       │                              │
│                       │      ▼       │                              │
│                       │ wake_up_poll │                              │
│                       │              │                              │
│                       └──────────────┘                              │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                          GUEST VM                                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐                                                   │
│  │ virtio-net   │◀─── Posted Interrupt / VMCS interrupt injection   │
│  │ driver       │                                                   │
│  └──────────────┘                                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Correlation Map Usage

### BPF Maps

```c
// Stage 1 output: sock_ptr -> queue info
BPF_HASH(target_queues, u64, struct queue_key, 256);

// Stage 2 output: eventfd_ctx -> connection info (including sock_ptr, dev_name, queue)
BPF_HASH(interrupt_chains, u64, struct interrupt_connection, 256);

// Sequence tracking: eventfd_ctx -> last stage number
BPF_HASH(sequence_check, u64, u64, 256);
```

### Correlation Flow

1. **Stage 1**: Store queue info keyed by sock_ptr

   ```c
   target_queues.update(&sock_ptr, &qkey);
   ```
2. **Stage 2**: Lookup by sock_ptr, store by eventfd_ctx

   ```c
   struct queue_key *qkey = target_queues.lookup(&sock_ptr);
   interrupt_chains.update(&eventfd_ctx, &ic_info);
   ```
3. **Stage 3**: Lookup by eventfd_ctx

   ```c
   struct interrupt_connection *ic_info = interrupt_chains.lookup(&eventfd_ctx);
   // Now have dev_name, queue_index, sock_ptr from original Stage 1
   ```

## Limitations

1. **Correlation ends at irqfd_wakeup**: After this point, eventfd_ctx is not passed to subsequent functions
2. **vmx_deliver_posted_interrupt cannot be correlated**: Only receives (vcpu, vector)
3. **Multiple VMs sharing same GSI**: Cannot distinguish without additional context
4. **High frequency events**: May cause map overflow or missed events

## References

- `drivers/net/tun.c`: TUN device driver
- `drivers/vhost/vhost.c`: vhost core implementation
- `drivers/vhost/net.c`: vhost-net implementation
- `fs/eventfd.c`: eventfd implementation
- `virt/kvm/eventfd.c`: KVM irqfd implementation
- `virt/lib/irqbypass.c`: IRQ bypass manager
- `arch/x86/kvm/vmx/vmx.c`: VMX posted interrupt implementation
- `include/linux/kvm_irqfd.h`: kvm_kernel_irqfd structure definition




# attach



完整流程分析

  根据内核代码分析，整个数据流程如下：

  Stage 1-2: TUN -> vhost (已确认正确)

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 1: tun_net_xmit                                                          │
  │  drivers/net/tun.c:1090                                                         │
  │                                                                                 │
  │  tun_net_xmit(skb, dev) {                                                       │
  │      tfile = tun->tfiles[skb->queue_mapping];  // 根据 queue_mapping 获取 tfile │
  │      ptr_ring_produce(&tfile->tx_ring, skb);   // 放入 ptr_ring                 │
  │      tfile->socket.sk->sk_data_ready();        // 唤醒 vhost worker             │
  │  }                                                                              │
  │                                                                                 │
  │  关键数据:                                                                       │
  │  - tfile->socket (struct socket *) - 唯一标识此 TUN 队列                         │
  │  - skb->queue_mapping - 队列索引                                                │
  └─────────────────────────────────────────────────────────────────────────────────┘
    │
    │ sk_data_ready() 唤醒
    ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  vhost worker 处理 (RX path - 从 TUN 读取发送给 Guest)                           │
  │  drivers/vhost/net.c:1108                                                       │
  │                                                                                 │
  │  handle_rx() {                                                                  │
  │      sock = vhost_vq_get_backend(vq);          // 获取 socket (=tfile->socket)  │
  │      ptr_ring_consume(nvq->rx_ring);           // 从 ptr_ring 消费数据包        │
  │      vhost_net_signal_used(nvq);               // 处理完成，通知 Guest          │
  │  }                                                                              │
  └─────────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 2: vhost_signal                                                          │
  │  drivers/vhost/vhost.c:2496                                                     │
  │                                                                                 │
  │  vhost_signal(dev, vq) {                                                        │
  │      eventfd_signal(vq->call_ctx.ctx, 1);      // 通过 eventfd 通知 KVM         │
  │  }                                                                              │
  │                                                                                 │
  │  关键数据:                                                                       │
  │  - vq->private_data = socket 指针 (与 Stage 1 的 tfile->socket 相同)             │
  │  - vq->call_ctx.ctx = eventfd_ctx 指针 (用于通知 KVM)                            │
  └─────────────────────────────────────────────────────────────────────────────────┘


 Stage 1-2 关联机制: vq->private_data == &tfile->socket

  Stage 3+: eventfd -> KVM 中断注入

  这里有 两条不同的路径：

    eventfd_signal(ctx, 1)
                                      │
                                      ▼
                      ┌───────────────────────────────────┐
                      │  eventfd_signal_mask()            │
                      │  fs/eventfd.c:48                  │
                      │                                   │
                      │  ctx->count += 1;                 │
                      │  wake_up_locked_poll(&ctx->wqh);  │
                      └───────────────────────────────────┘
                                      │
                                      │ 唤醒 waitqueue 上的所有 waiter
                                      ▼
             ┌────────────────────────┴────────────────────────┐
             │                                                 │
      路径 A: 普通 irqfd                               路径 B: IRQ bypass (Posted Interrupt)
      (irqbypass 未启用或未匹配)                       (vDPA 硬件 + VT-d Posted Interrupt)
             │                                                 │
             ▼                                                 ▼
  ┌──────────────────────────────┐              ┌──────────────────────────────────┐
  │  irqfd_wakeup()              │              │  硬件直接投递中断                  │
  │  virt/kvm/eventfd.c:190      │              │  (不经过 irqfd_wakeup)            │
  │                              │              │                                  │
  │  kvm_arch_set_irq_inatomic() │              │  IOMMU IRTE 配置为 Posted Mode    │
  │      ├─ 成功: 直接注入       │              │  中断直接写入 Guest PIR            │
  │      └─ 失败: schedule_work  │              │  发送 Posted Interrupt IPI        │
  │           └─> irqfd_inject() │              │                                  │
  │               └─> kvm_set_irq│              │  Guest 无需 VM Exit 即可处理中断  │
  └──────────────────────────────┘              └──────────────────────────────────┘


 关键问题分析

  问题 1: vhost-net 不是 vDPA，为什么有 Posted Interrupt?

  查看代码发现，vhost-net 的 call_ctx.producer 没有注册到 irqbypass！

  // drivers/vhost/vhost.h:64-67
  struct vhost_vring_call {
      struct eventfd_ctx *ctx;                // eventfd 指针
      struct irq_bypass_producer producer;    // 只有 vDPA 会注册这个！
  };

  只有 vDPA (硬件 vhost) 才会调用 irq_bypass_register_producer()：

- drivers/vhost/vdpa.c:200 - vhost_vdpa_setup_vq_irq()

  vhost-net (软件) 不会注册 IRQ bypass producer，所以：

- vhost-net → eventfd_signal → irqfd_wakeup → kvm_set_irq → vmx_deliver_posted_interrupt

  问题 2: 为什么 irqfd_wakeup 没有触发？

  让我检查 irqfd_wakeup 的触发条件：







完整流程分析总结

  根据内核代码分析，完整的数据流程如下：

  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 1: tun_net_xmit (drivers/net/tun.c:1090)                                 │
  │                                                                                 │
  │  关键数据:                                                                       │
  │  - tfile->socket (struct socket *) → 唯一标识 TUN 队列                           │
  │  - skb->queue_mapping → 队列索引                                                │
  │  - dev->name → 设备名                                                           │
  └───────────────────────────────────────────────────────────────────────────────┬─┘
                                                                                  │
                                sk_data_ready() 唤醒 vhost worker                  │
                                                                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 2: vhost_signal (drivers/vhost/vhost.c:2496)                             │
  │  通过 vhost_add_used_and_signal_n() 调用                                        │
  │                                                                                 │
  │  关联方式: vq->private_data == &tfile->socket                                   │
  │                                                                                 │
  │  关键数据:                                                                       │
  │  - vq->private_data → 指向 tfile->socket                                        │
  │  - vq->call_ctx.ctx → eventfd_ctx 指针 (用于通知 KVM)                            │
  └───────────────────────────────────────────────────────────────────────────────┬─┘
                                                                                  │
                                eventfd_signal(vq->call_ctx.ctx, 1)               │
                                                                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 3: eventfd_signal (fs/eventfd.c:48)                                      │
  │                                                                                 │
  │  eventfd_signal_mask(ctx, n, 0) {                                               │
  │      ctx->count += n;                                                           │
  │      wake_up_locked_poll(&ctx->wqh, EPOLLIN);  → 唤醒 irqfd_wakeup              │
  │  }                                                                              │
  │                                                                                 │
  │  关联方式: eventfd_ctx 指针在 Stage 2 和 Stage 3 相同                            │
  └───────────────────────────────────────────────────────────────────────────────┬─┘
                                                                                  │
                                wake_up_locked_poll() 唤醒 waitqueue               │
                                                                                  ▼

▼                                                                                                                        17:41:47 [565/1889]
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 4: irqfd_wakeup (virt/kvm/eventfd.c:190)                                 │
  │                                                                                 │
  │  irqfd_wakeup(wait, mode, sync, key) {                                          │
  │      irqfd = container_of(wait, struct kvm_kernel_irqfd, wait);                 │
  │      if (flags & EPOLLIN) {                                                     │
  │          irq = irqfd->irq_entry;      // 获取 IRQ routing entry                 │
  │          if (kvm_arch_set_irq_inatomic(...) == -EWOULDBLOCK)                    │
  │              schedule_work(&irqfd->inject);                                     │
  │      }                                                                          │
  │  }                                                                              │
  │                                                                                 │
  │  关联方式: irqfd->eventfd == eventfd_ctx (通过 waitqueue 注册时建立)             │
  │                                                                                 │
  │  关键数据:                                                                       │
  │  - irqfd->eventfd → eventfd_ctx 指针 (与 Stage 2/3 相同)                         │
  │  - irqfd->gsi → Guest GSI 号                                                    │
  │  - irqfd->irq_entry → IRQ routing 信息 (MSI address/data)                       │
  └───────────────────────────────────────────────────────────────────────────────┬─┘
                                                                                  │
                                kvm_arch_set_irq_inatomic() 或 irqfd_inject()      │
                                                                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 5: kvm_arch_set_irq_inatomic (arch/x86/kvm/irq_comm.c:161)                │
  │                                                                                 │
  │  kvm_arch_set_irq_inatomic() {                                                  │
  │      case KVM_IRQ_ROUTING_MSI:                                                  │
  │          kvm_set_msi_irq(kvm, e, &irq);                                         │
  │          if (kvm_irq_delivery_to_apic_fast(...))                                │
  │              return r;                                                          │
  │      return -EWOULDBLOCK;  // fallback to irqfd_inject                          │
  │  }                                                                              │
  │                                                                                 │
  │  关联: 通过 irqfd->irq_entry 中的 MSI routing 信息                               │
  └───────────────────────────────────────────────────────────────────────────────┬─┘
                                                                                  │
                                kvm_irq_delivery_to_apic_fast() → kvm_apic_set_irq()
                                                                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 6: __apic_accept_irq (arch/x86/kvm/lapic.c:1065)                         │
  │                                                                                 │
  │  __apic_accept_irq(apic, delivery_mode, vector, ...) {                          │
  │      case APIC_DM_FIXED:                                                        │
  │          result = 1;                                                            │
  │          if (kvm_x86_ops.deliver_posted_interrupt(vcpu, vector)) {              │
  │              // Posted Interrupt 失败，使用软件路径                               │
  │              kvm_lapic_set_irr(vector, apic);                                   │
  │              kvm_vcpu_kick(vcpu);                                               │
  │          }                                                                      │
  │  }                                                                              │
  │                                                                                 │
  │  关键: vector 是从 MSI routing 解析出来的中断向量                                 │
  └───────────────────────────────────────────────────────────────────────────────┬─┘

│
                                kvm_x86_ops.deliver_posted_interrupt()            │
                                                                                  ▼
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │  Stage 7: vmx_deliver_posted_interrupt (arch/x86/kvm/vmx/vmx.c:4279)            │
  │                                                                                 │
  │  vmx_deliver_posted_interrupt(vcpu, vector) {                                   │
  │      if (!vcpu->arch.apicv_active) return -1;   // APICv 未启用，返回失败         │
  │      pi_test_and_set_pir(vector, &vmx->pi_desc); // 设置 PIR                     │
  │      pi_test_and_set_on(&vmx->pi_desc);          // 设置 ON bit                  │
  │      kvm_vcpu_trigger_posted_interrupt(vcpu);    // 发送 Posted Interrupt IPI   │
  │      return 0;  // 成功                                                         │
  │  }                                                                              │
  │                                                                                 │
  │  注意: 此函数只接收 (vcpu, vector) 参数，无法直接关联到 eventfd_ctx               │
  └─────────────────────────────────────────────────────────────────────────────────┘


  关键问题：如何关联 vmx_deliver_posted_interrupt 到特定 vnet 队列？

  问题: vmx_deliver_posted_interrupt(vcpu, vector) 只接收 vcpu 和 vector，没有 eventfd_ctx 信息。

  分析调用链:
  vhost_signal(eventfd_ctx)
      → eventfd_signal(eventfd_ctx)
          → irqfd_wakeup(irqfd->eventfd == eventfd_ctx)
              → kvm_arch_set_irq_inatomic(irqfd->irq_entry)
                  → kvm_irq_delivery_to_apic_fast(irq from irq_entry)
                      → kvm_apic_set_irq(vcpu, irq)
                          → __apic_accept_irq(apic, vector)
                              → vmx_deliver_posted_interrupt(vcpu, vector)

  eventfd_ctx 在 irqfd_wakeup 之后就丢失了！

- irqfd_wakeup 有 irqfd->eventfd (即 eventfd_ctx)
- 但它调用的 kvm_arch_set_irq_inatomic 只传递 irqfd->irq_entry (MSI routing info)
- 后续所有函数都只有 (kvm, irq_entry, vcpu, vector) 信息

  正确的 Probe 策略

  基于上述分析，有效的关联点是：

| Stage | Probe Point                  | 可获取的关联信息                           | 能否关联到 vnet 队列 |
| ----- | ---------------------------- | ------------------------------------------ | -------------------- |
| 1     | tun_net_xmit                 | socket ptr, dev_name, queue_index          | ✓ 起点              |
| 2     | vhost_signal                 | socket ptr (via private_data), eventfd_ctx | ✓ 与 Stage 1 关联   |
| 3     | eventfd_signal               | eventfd_ctx                                | ✓ 与 Stage 2 关联   |
| 4     | irqfd_wakeup                 | eventfd_ctx (via container_of), gsi        | ✓ 与 Stage 3 关联   |
| 5     | kvm_arch_set_irq_inatomic    | irq_entry (无 eventfd_ctx)                 | ✗ 关联断裂          |
| 6     | __apic_accept_irq            | vcpu, vector (无 eventfd_ctx)              | ✗ 关联断裂          |
| 7     | vmx_deliver_posted_interrupt | vcpu, vector (无 eventfd_ctx)              | ✗ 关联断裂          |

  结论:

- 最远可关联到 Stage 4 (irqfd_wakeup)
- Stage 5+ 无法直接关联，除非通过 gsi/vector 间接匹配


  修正设计方案

  正确的 Trace 链:

  Stage 1: tun_net_xmit
      ├─ 输出: dev_name, queue_index, socket_ptr
      └─ 存储: socket_ptr → {dev_name, queue_index, timestamp}

  Stage 2: vhost_signal (或 vhost_add_used_and_signal_n)
      ├─ 输入: vq->private_data (= socket_ptr)
      ├─ 查找: socket_ptr → {dev_name, queue_index}
      ├─ 输出: dev_name, queue_index, eventfd_ctx
      └─ 存储: eventfd_ctx → {dev_name, queue_index, timestamp}

  Stage 3: irqfd_wakeup  (而不是 eventfd_signal)
      ├─ 输入: wait_queue_entry → container_of → irqfd
      ├─ 获取: irqfd->eventfd (= eventfd_ctx), irqfd->gsi
      ├─ 查找: eventfd_ctx → {dev_name, queue_index}
      └─ 输出: dev_name, queue_index, gsi, delay

  Stage 4: (可选) vmx_deliver_posted_interrupt
      ├─ 输入: vcpu, vector
      ├─ 无法直接关联，只能输出 vector
      └─ 用户空间通过 gsi/vector 映射间接关联

  现在我需要验证当前工具的实现，看看为什么 Stage 3 (irqfd_wakeup) 没有触发。让我检查当前工具在 5.10 服务器上的实际运行情况：

⏺ Bash(ssh smartx@172.21.128.243 "timeout 6 sudo python3 /tmp/tun_tx_to_kvm_irq.py --debug 2>&1 | grep -E 'Stage|attached|irqfd' | head -50" || true) timeout: 30s
  ⎿  Successfully attached to tun_net_xmit
    Successfully attached to vhost_add_used_and_signal_n
     Successfully attached to irqfd_wakeup (traditional irqfd path)
     … +47 lines (ctrl+o to expand)

⏺ 非常好！现在我可以看到完整的图像：

  当前状态：

- ✅ Stage 1 (tun_net_xmit): 工作正常，输出 vnet4:q9, vnet3:q0 等
- ✅ Stage 2 (vhost_signal): 工作正常，与 Stage 1 关联
- ✅ Stage 4 (eventfd_signal): 工作正常，与 Stage 2 关联
- ❌ Stage 3 (irqfd_wakeup): 没有触发！
- ❓ Stage 5 (posted_int): 触发但无法关联
