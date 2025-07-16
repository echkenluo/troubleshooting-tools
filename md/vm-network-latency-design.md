# 虚拟机网络端到端延迟测量工具设计文档

## 概述

本文档描述了一个专门针对KVM虚拟机网络的端到端延迟分段测量工具的设计。该工具支持TCP和UDP协议，使用五元组进行流识别，实现单向延迟测量和分段分析。

## 1. 系统架构设计

### 1.1 数据路径分析

虚拟机网络数据路径与系统网络的主要区别在于虚拟机端口使用TUN设备（vnet口）：

```
VM内部 <-> TUN设备(vnet) <-> OVS内核模块 <-> OVS用户态(可选) <-> 物理网卡
```

**TX方向（从虚拟机发出）：**
```
VM Guest → TUN设备(tun_get_user) → OVS处理 → 物理网卡发送
```

**RX方向（发送到虚拟机）：**
```
物理网卡接收 → OVS处理 → TUN设备(tun_net_xmit) → VM Guest
```

### 1.2 关键探测点设计

#### TX方向探测点序列：
1. **STAGE_0**: `tun_get_user` - TUN设备接收来自虚拟机的数据包
2. **STAGE_1**: `internal_dev_xmit` - OVS内部设备处理
3. **STAGE_2**: `ovs_dp_process_packet` - OVS数据路径处理
4. **STAGE_3**: `ovs_dp_upcall` - OVS upcall处理（可选）
5. **STAGE_4**: `ovs_flow_key_extract_userspace` - 用户态流表键提取（可选）
6. **STAGE_5**: `ovs_vport_send` - OVS虚拟端口发送
7. **STAGE_6**: `__dev_queue_xmit` - 物理设备队列发送

#### RX方向探测点序列：
1. **STAGE_0**: `__netif_receive_skb` - 物理网卡接收数据包
2. **STAGE_1**: `netdev_frame_hook` - 网络设备帧处理钩子
3. **STAGE_2**: `ovs_dp_process_packet` - OVS数据路径处理
4. **STAGE_3**: `ovs_dp_upcall` - OVS upcall处理（可选）
5. **STAGE_4**: `ovs_flow_key_extract_userspace` - 用户态流表键提取（可选）
6. **STAGE_5**: `ovs_vport_send` - OVS虚拟端口发送
7. **STAGE_6**: `tun_net_xmit` - TUN设备发送到虚拟机

## 2. 五元组流识别机制

### 2.1 五元组定义

```c
struct flow_key_t {
    __be32 src_ip;      // 源IP地址
    __be32 dst_ip;      // 目标IP地址
    __be16 src_port;    // 源端口
    __be16 dst_port;    // 目标端口
    u8     protocol;    // 协议类型 (TCP=6, UDP=17)
};
```

### 2.2 流识别策略

- **TCP流**: 使用完整五元组进行识别
- **UDP流**: 使用完整五元组进行识别
- **方向性**: 单向测量，不区分请求/响应方向
- **唯一性**: 五元组确保流的唯一标识

### 2.3 数据包解析

支持以下场景的数据包解析：
- 标准以太网帧
- VLAN标签帧（单层和双层）
- IPv4协议
- TCP/UDP传输层协议

## 3. 技术实现细节

### 3.1 BPF程序结构

```c
// 主要数据结构
struct packet_key_t {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    u8 protocol;
};

struct flow_data_t {
    u64 ts[MAX_STAGES];           // 各阶段时间戳
    u64 skb_ptr[MAX_STAGES];      // SKB指针
    int kstack_id[MAX_STAGES];    // 内核栈ID
    u32 pid;                      // 进程ID
    char comm[16];                // 进程名
    char ifname[16];              // 接口名
    u8 protocol;                  // 协议类型
    u8 saw_start:1;               // 标记开始
    u8 saw_end:1;                 // 标记结束
};
```

### 3.2 数据包解析函数

提供两种解析模式：
1. **内核模式解析**: 使用skb的header偏移
2. **用户态模式解析**: 直接解析skb->data（用于stage 4）

```c
static __always_inline int parse_packet_key(
    struct sk_buff *skb, 
    struct packet_key_t *key, 
    u8 stage_id
);

static __always_inline int parse_packet_key_userspace(
    struct sk_buff *skb, 
    struct packet_key_t *key
);
```

### 3.3 过滤机制

支持以下过滤条件：
- 源IP地址过滤
- 目标IP地址过滤
- 源端口过滤
- 目标端口过滤
- 协议类型过滤（TCP/UDP）
- 延迟阈值过滤
- 物理接口过滤

### 3.4 TUN设备特殊处理

#### tun_get_user探测（TX方向起点）
```c
int kprobe__tun_get_user(struct pt_regs *ctx, 
    struct tun_struct *tun, struct tun_file *tfile, 
    void *msg_control, struct iov_iter *from, 
    int noblock, bool more) {
    // 需要特殊处理：从iov_iter中解析数据包
    // 构造临时skb进行五元组解析
}
```

#### tun_net_xmit探测（RX方向终点）
```c
int kprobe__tun_net_xmit(struct pt_regs *ctx, 
    struct sk_buff *skb, struct net_device *dev) {
    // 标准skb解析
    // 直接从skb中提取五元组
}
```

## 4. 性能优化策略

### 4.1 高效流查找
- 使用BPF_LRU_HASH_MAP进行流状态存储
- 基于五元组的哈希索引
- 自动老化机制防止内存泄漏

### 4.2 条件过滤
- 在BPF层面进行早期过滤
- 减少用户态事件传输
- 支持多维度组合过滤

### 4.3 内存管理
- 使用percpu数组避免锁竞争
- 合理设置map大小限制
- 及时清理完成的流状态

## 5. 错误处理机制

### 5.1 数据包解析错误
- 畸形数据包检测
- Header偏移验证
- 协议类型验证

### 5.2 探测点错误
- 函数不存在的处理
- 参数变化的兼容性
- 内核版本适配

### 5.3 资源限制
- Map容量限制处理
- 栈空间溢出保护
- 事件丢失处理

## 6. 输出格式设计

### 6.1 延迟报告格式
```
=== VM Network Latency Trace: 2025-01-15 10:30:45.123 (TX) ===
Flow: 192.168.1.10:8080 -> 192.168.1.20:80 (TCP)
VM Device: vnet0 → Physical: eth0
Process: PID=1234 COMM=qemu-kvm

Latencies (us):
  [0->1] STAGE_0 (tun_get_user) -> STAGE_1 (internal_dev_xmit): 12.345 us
  [1->2] STAGE_1 (internal_dev_xmit) -> STAGE_2 (ovs_dp_process_packet): 8.234 us
  [2->5] STAGE_2 (ovs_dp_process_packet) -> STAGE_5 (ovs_vport_send): 15.678 us (OVS No Upcall)
  [5->6] STAGE_5 (ovs_vport_send) -> STAGE_6 (__dev_queue_xmit): 5.123 us

Total Latency: 41.380 us
```

### 6.2 统计信息
- 分段延迟统计
- 总延迟分布
- 流量统计
- 错误计数

## 7. 使用示例

### 7.1 基本用法
```bash
# 监控特定虚拟机的出站TCP流量
sudo ./vm_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                     --protocol tcp --direction tx \
                     --vm-interface vnet0 --phy-interface eth0

# 监控特定端口的UDP流量
sudo ./vm_latency.py --src-ip 192.168.1.10 --dst-port 53 \
                     --protocol udp --direction rx \
                     --vm-interface vnet0 --phy-interface eth0
```

### 7.2 高级过滤
```bash
# 仅监控高延迟流量
sudo ./vm_latency.py --src-ip 192.168.1.10 --dst-ip 192.168.1.20 \
                     --latency-threshold 100 \
                     --protocol tcp --direction tx \
                     --vm-interface vnet0 --phy-interface eth0
```

## 8. 与现有工具的关系

### 8.1 与系统网络延迟工具的区别
- **起点不同**: 使用TUN设备作为起点/终点
- **探测点不同**: 增加TUN设备相关探测点
- **场景不同**: 专门针对虚拟化环境

### 8.2 与ICMP工具的区别
- **协议支持**: 支持TCP/UDP而非ICMP
- **流识别**: 使用五元组而非ICMP ID/SEQ
- **方向性**: 单向测量而非往返测量

## 9. 实现优先级

### 9.1 第一阶段（核心功能）
- [ ] 基础BPF程序框架
- [ ] 五元组解析和过滤
- [ ] TX方向完整链路追踪
- [ ] 基本输出格式

### 9.2 第二阶段（完善功能）
- [ ] RX方向链路追踪
- [ ] 高级过滤机制
- [ ] 性能优化
- [ ] 错误处理完善

### 9.3 第三阶段（增强功能）
- [ ] 统计分析功能
- [ ] 多虚拟机同时监控
- [ ] 图形化输出
- [ ] 与其他工具集成

## 10. 测试验证计划

### 10.1 功能测试
- TCP/UDP协议支持验证
- 五元组过滤准确性测试
- 延迟测量精度验证
- 边界条件测试

### 10.2 性能测试
- 高流量场景下的性能影响
- 内存使用情况监控
- CPU开销测量
- 丢包率分析

### 10.3 兼容性测试
- 不同内核版本测试
- 不同虚拟化平台测试
- 各种网络配置验证

---

## 附录A：探测函数详细说明

### A.1 TUN设备函数
- `tun_get_user`: 从用户态接收数据到内核
- `tun_net_xmit`: 从内核发送数据到用户态
- `tun_build_skb`: SKB构建过程

### A.2 OVS相关函数
- `ovs_dp_process_packet`: 数据路径处理
- `ovs_dp_upcall`: 用户态调用
- `ovs_flow_key_extract_userspace`: 流键提取
- `ovs_vport_send`: 虚拟端口发送

### A.3 网络栈函数
- `__netif_receive_skb`: 网络接收入口
- `__dev_queue_xmit`: 设备发送队列
- `internal_dev_xmit`: 内部设备发送
- `netdev_frame_hook`: 网络帧处理钩子

---

*本设计文档将根据实现过程中的发现和需求变化进行持续更新。*