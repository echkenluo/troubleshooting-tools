# VHOST-NET Datapath Monitor

## 概述

`vhost_datapath_monitor.py` 是一个增强版的网络性能监控工具，专门用于追踪 vhost-net 到 TUN 设备的数据路径。该工具基于原有的 `tun_ring_monitor.py` 扩展，增加了对关键内核函数调用链的追踪功能。

## 主要功能

### 1. 完整数据路径追踪
- **handle_rx**: vhost-net 接收处理入口点
- **tun_recvmsg**: TUN 设备消息接收函数
- **vhost_net_signal_used**: vhost-net 信号完成函数
- **tun_net_xmit**: TUN 设备发送函数（用于关联）

### 2. ptr_ring 状态监控
在每个关键点捕获 ptr_ring 状态：
- Producer 位置
- Consumer head/tail 位置
- 队列满状态检测
- 队列利用率计算

### 3. 事件关联
- 进程/线程 ID 追踪
- 时间戳记录
- 设备和队列信息
- 包头信息解析

## 使用方法

### 基本使用
```bash
# 监控所有 TUN 设备
sudo python2 vhost_datapath_monitor.py

# 监控特定设备
sudo python2 vhost_datapath_monitor.py --device vnet12

# 监控特定设备和队列
sudo python2 vhost_datapath_monitor.py --device vnet12 --queue 0

# 详细输出
sudo python2 vhost_datapath_monitor.py --device vnet12 --verbose
```

### 参数说明
- `--device, -d`: 指定监控的设备名称（如 vnet12）
- `--queue, -q`: 指定监控的队列索引
- `--verbose, -v`: 启用详细输出

## 输出解析

### 事件类型
1. **handle_rx**: vhost-net 开始处理接收
2. **tun_recvmsg_entry**: TUN 设备开始接收消息
3. **tun_recvmsg_return**: TUN 设备完成接收消息
4. **vhost_net_signal_used**: vhost-net 信号处理完成
5. **tun_net_xmit**: TUN 设备发送（用于关联分析）

### 关键信息
- **时间戳**: 精确到微秒的事件时间
- **进程信息**: PID/TID 和进程名
- **设备信息**: 设备名和队列索引
- **ptr_ring 状态**: 生产者/消费者位置、队列满状态
- **网络信息**: 源/目的 IP 和端口、协议类型

### 示例输出
```
================================================================================
🔍 VHOST Datapath Event: handle_rx
Time: 14:23:45.123
Process: vhost-1234 (PID: 1234)
Device: vnet12
Queue: 0
📥 handle_rx called
  NVQ ptr: 0xffff888123456000
================================================================================

================================================================================
🔍 VHOST Datapath Event: tun_recvmsg_entry  
Time: 14:23:45.124
Process: vhost-1234 (PID: 1234)
Device: vnet12
Queue: 0
📨 tun_recvmsg called
  Socket ptr: 0xffff888123457000
  TFile ptr: 0xffff888123458000
  Flags: 0x40
  Total len: 1500
  PTR Ring State:
    Size: 256
    Producer: 10
    Consumer Head: 8
    Consumer Tail: 8
    Status: ✅ Available (7% used)
================================================================================
```

## 部署和测试

### 1. 部署到测试环境
```bash
# 运行部署脚本
./deploy_vhost_tools.sh
```

### 2. 在测试环境中运行
```bash
# SSH 到测试主机
ssh smartx@192.168.70.33

# 进入工具目录
cd /home/smartx/lcc/vhost-datapath-test

# 运行测试
sudo python2 test_vhost_datapath.py

# 运行监控工具
sudo python2 vhost_datapath_monitor.py --device vnet12
```

## 故障排查

### 1. 检查内核函数可用性
```bash
# 检查关键函数是否在内核符号表中
grep -E "(handle_rx|tun_recvmsg|vhost_net_signal_used)" /proc/kallsyms
```

### 2. 检查 BCC 环境
```bash
# 检查 BCC 安装
python2 -c "import bcc; print('BCC available')"

# 检查内核头文件
ls /lib/modules/$(uname -r)/build/include/
```

### 3. 权限问题
- 确保使用 root 权限运行
- 检查 /sys/kernel/debug/tracing 目录权限

## 与原工具的区别

### 原工具 (tun_ring_monitor.py)
- 只监控 `tun_net_xmit` 函数
- 主要关注 ptr_ring 队列满状态
- 单点监控，缺乏数据路径全貌

### 增强工具 (vhost_datapath_monitor.py)
- 追踪完整的 vhost-net 数据路径
- 在多个关键点捕获 ptr_ring 状态
- 提供事件关联和时序分析
- 支持更细粒度的过滤和分析

## 性能考虑

- 该工具使用 kprobe/kretprobe，对性能有一定影响
- 建议在测试环境中使用，生产环境需谨慎
- 可以通过设备和队列过滤减少事件数量
- 长时间运行可能产生大量日志数据

## 扩展功能

### 未来可能的增强
1. 支持更多过滤条件（IP、端口、协议）
2. 增加统计和分析功能
3. 支持事件录制和回放
4. 集成性能基准测试
5. 支持 JSON 格式输出

## 注意事项

1. 该工具基于特定内核版本开发，可能需要根据实际内核版本调整
2. 内核函数签名可能因版本而异，需要相应修改探测点
3. 在高负载环境中使用时需要注意性能影响
4. 建议结合其他网络分析工具使用以获得更全面的视图