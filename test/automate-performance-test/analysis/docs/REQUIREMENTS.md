# 性能测试数据分析工具需求文档

## 📌 当前实现状态（2025-10-22）

### ✅ 已实现功能
- ✅ 完整的数据定位和解析系统
- ✅ Multi-stream 数据累加（Throughput + PPS）
- ✅ PPS packet_size 容错处理
- ✅ Baseline 对比和差异计算
- ✅ 双报告系统：合并报告 + 分离报告
- ✅ 时间范围匹配的资源监控分析
- ✅ 详细的错误日志和容错机制

### 📊 数据完整性
- Client 端数据：80%（Latency, Throughput, PPS 全部可用）
- Server 端数据：待排查（当前缺失）
- 资源监控数据：70%（部分 case 可用）

### 🎯 主要特性
1. **智能数据定位**：自动识别 Host/VM 测试类型
2. **容错解析**：Multi-stream timing 格式自适应
3. **分离报告**：5个专项报告（延迟/吞吐量/PPS/资源/概览）
4. **灵活输出**：支持 CSV 和 Markdown 格式

---

## 1. 背景与目标

### 1.1 背景
- 已有 scheduled_automation 测试生成的性能测试数据
- 数据位于 `results/1021/` 目录，包含 3 个 iteration
- 需要对测试结果进行系统化的统计分析

### 1.2 目标
开发一个自动化分析工具，用于：
1. 提取和整理性能测试指标（延迟、吞吐量、PPS）
2. 分析 eBPF 工具的资源开销（CPU、内存、日志大小）
3. 与 baseline 进行对比
4. 生成汇总表格和报告（支持合并和分离两种模式）

---

## 2. 数据结构分析

### 2.1 目录结构

```
results/1021/
├── iteration_001/
│   ├── host-server/
│   │   └── performance-test-results/
│   │       ├── baseline/
│   │       │   └── host/
│   │       │       ├── server_results/
│   │       │       │   ├── latency/
│   │       │       │   ├── pps/
│   │       │       │   └── throughput/
│   │       │       └── ebpf_monitoring/
│   │       └── ebpf/
│   │           ├── system_network_performance/         # topic目录（可选）
│   │           ├── system_network_performance_case_*   # tool case 目录
│   │           └── linux_network_stack_case_*
│   ├── host-client/
│   │   └── performance-test-results/
│   │       ├── baseline/
│   │       │   └── host/
│   │       │       └── client_results/
│   │       │           ├── latency/
│   │       │           ├── pps/
│   │       │           └── throughput/
│   │       └── ebpf/
│   │           └── {tool_case_name}/
│   │               └── host/
│   │                   └── client_results/
│   │                       ├── latency/
│   │                       ├── pps/
│   │                       └── throughput/
│   ├── vm-server/
│   │   └── performance-test-results/
│   │       ├── baseline/
│   │       │   └── vm/
│   │       │       └── server_results/
│   │       └── ebpf/
│   │           ├── kvm_virt_network/
│   │           ├── ovs_monitoring/
│   │           ├── vm_network_performance/
│   │           └── {tool_case_name}/
│   │               └── vm/
│   │                   └── server_results/
│   ├── vm-client/
│   │   └── performance-test-results/
│   │       ├── baseline/
│   │       │   └── vm/
│   │       │       └── client_results/
│   │       └── ebpf/
│   │           └── {tool_case_name}/
│   │               └── vm/
│   │                   └── client_results/
│   └── collection_summary.txt
├── iteration_002/
└── iteration_003/
```

### 2.2 测试机器类型

**Host 测试（system_network_performance, linux_network_stack）：**
- host-server: 性能测试数据在 `host/server_results/`，eBPF 监控数据在 `host/ebpf_monitoring/`
- host-client: 性能测试数据在 `host/client_results/`

**VM 测试（kvm_virt_network, ovs_monitoring, vm_network_performance）：**
- vm-server: 性能测试数据在 `vm/server_results/`
- vm-client: 性能测试数据在 `vm/client_results/`
- host-server: eBPF 监控数据在 `vm/ebpf_monitoring/`（注意：监控数据在 host 上）

### 2.3 Tool Case 命名规则

格式：`{topic}_case_{number}_{protocol}_{direction}_{hash}`

示例：
- `system_network_performance_case_6_tcp_tx_0388a9`
- `kvm_virt_network_case_1_tcp_rx_9d5e19`
- `linux_network_stack_case_3_udp_rx_b58f1e`

### 2.4 性能测试数据文件

#### 2.4.1 延迟测试（Latency）
```
client_results/latency/
├── tcp_rr_YYYYMMDD_HHMMSS/
│   └── latency_tcp_rr.txt          # CSV 格式，包含 Min, Mean, Max 延迟
└── udp_rr_YYYYMMDD_HHMMSS/
    └── latency_udp_rr.txt
```

**文件格式：**
```
MIGRATED TCP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 192.168.70.31 () port 0 AF_INET : first burst 0
Minimum Latency Microseconds,Mean Latency Microseconds,Maximum Latency Microseconds
55,112.59,19236
```

#### 2.4.2 吞吐量测试（Throughput）
```
client_results/throughput/
├── single_YYYYMMDD_HHMMSS/
│   ├── throughput_single_tcp.json     # iperf3 JSON 输出
│   └── throughput_single_timing.log   # 时间戳记录
└── multi_N_YYYYMMDD_HHMMSS/
    ├── throughput_multi_stream_1_port_5001.json  # 每个 stream 一个文件
    ├── throughput_multi_stream_2_port_5002.json
    ├── throughput_multi_stream_3_port_5003.json
    ├── throughput_multi_stream_4_port_5004.json
    ├── throughput_multi_stream_1_port_5001_timing.log  # 每个 stream 的 timing
    ├── throughput_multi_stream_2_port_5002_timing.log
    ├── throughput_multi_stream_3_port_5003_timing.log
    └── throughput_multi_stream_4_port_5004_timing.log
```

**Single stream timing.log 格式：**
```
Test: throughput_single_tcp
Start: 2025-10-21 14:12:43.774
End: 2025-10-21 14:12:53.890
```

**Multi stream timing.log 格式：**（注意：格式与 PPS 相同！）
```
Test: throughput_multi_stream_process_1_port_5001
Process_Start: 2025-10-21 14:04:49.933
Actual_Launch: 2025-10-21 14:04:50.169
Test_End: 2025-10-21 14:05:02.638
```

**JSON 文件：** iperf3 标准输出格式，包含：
- `intervals[]`: 每秒的吞吐量数据
- `end.sum_sent.bytes`: 总发送字节数
- `end.sum_sent.bits_per_second`: 平均比特率

**Multi-stream 累加逻辑：**
```python
# 需要累加所有 stream 的吞吐量
total_bps = sum([json["end"]["sum_sent"]["bits_per_second"] for json in all_stream_jsons])
total_throughput_gbps = total_bps / 1e9
```

#### 2.4.3 PPS 测试（Packets Per Second）
```
client_results/pps/
├── single_YYYYMMDD_HHMMSS/
│   ├── pps_single_tcp.json
│   └── pps_single_timing.log
└── multi_N_YYYYMMDD_HHMMSS/
    ├── pps_multi_stream_1_port_5001.json  # 每个 stream 一个文件
    ├── pps_multi_stream_2_port_5002.json
    ├── pps_multi_stream_3_port_5003.json
    ├── pps_multi_stream_4_port_5004.json
    └── pps_multi_timing.log  # 注意：PPS multi 只有一个 timing 文件！
```

**timing.log 格式：**
```
Test: pps_single_stream_process_1_port_5001
Process_Start: 2025-10-21 14:13:41.897
Actual_Launch: 2025-10-21 14:13:41.966
Test_End: 2025-10-21 14:13:54.085
```

**JSON 文件：** iperf3 输出，使用小包（64 bytes）+ 目标带宽限制（5Gbps）

**重要注意事项：**
- PPS JSON 文件中可能缺少 `test_start` 字段
- 需要从 `start` 部分获取 `blksize` 字段作为包大小
- 如果 `test_start` 缺失，尝试从其他位置获取 packet_size

**Multi-stream PPS 累加逻辑：**
```python
# 需要累加所有 stream 的 PPS
total_bps = sum([json["end"]["sum_sent"]["bits_per_second"] for json in all_stream_jsons])
packet_size = json["start"]["test_start"]["blksize"]  # 或 json["test_start"]["blksize"]
total_pps = total_bps / (packet_size * 8)
```

### 2.5 eBPF 监控数据文件

位置：`{tool_case_name}/{host|vm}/ebpf_monitoring/`

#### 2.5.1 资源监控日志
文件：`ebpf_resource_monitor_YYYYMMDD_HHMMSS.log`

**格式：**
```
# eBPF Resource Monitoring - CPU and Memory statistics using pidstat
# DEBUG: Starting resource monitoring for PID 47899 with interval 2s
# START_DATETIME: 2025-10-21 22:12:39.672278096  START_EPOCH: 1761055959  INTERVAL: 2s  PID: 47899
Linux 4.19.90-2307.3.0.el7.v97.x86_64 (node31) 	10/21/2025 	_x86_64_	(80 CPU)

#      Time   UID       PID    %usr %system  %guest    %CPU   CPU  minflt/s  majflt/s     VSZ    RSS   %MEM  Command
 1761055961     0     47899   84.00    7.00    0.00   91.00     5   8292.00      0.00  356276 146004   0.03  python2

#      Time   UID       PID    %usr %system  %guest    %CPU   CPU  minflt/s  majflt/s     VSZ    RSS   %MEM  Command
 1761055963     0     47899    4.50   15.50    0.00   20.00     7     75.00      0.00  359164 146992   0.03  python2
```

**关键字段：**
- `Time`: Unix 时间戳（绝对时间）
- `%CPU`: CPU 使用率
- `VSZ`: 虚拟内存大小（KB）
- `RSS`: 物理内存大小（KB）
- `%MEM`: 内存使用百分比

#### 2.5.2 日志大小监控
文件：`ebpf_logsize_monitor_YYYYMMDD_HHMMSS.log`

**格式：**
```
# eBPF Log Size Monitoring - Log file size (instantaneous)
# Timestamp                     Size_Bytes  Size_Human
# DEBUG: Starting logsize monitoring for /home/smartx/lcc/performance-test-results/ebpf/system_network_performance_case_6_tcp_tx_0388a9/host/ebpf_output_20251021_141238.log
# DEBUG: Monitor process PID: 47972, PGID: 47972
2025-10-21 22:12:40.118987979 0 0B
2025-10-21 22:12:42.221254361 0 0B
2025-10-21 22:12:44.278388729 0 0B
```

---

## 3. 数据提取需求

### 3.1 性能测试指标提取

#### 3.1.1 延迟（Latency）
**数据源：** Client 端数据即可

**提取内容：**
- TCP RR 延迟：Min, Mean, Max (微秒)
- UDP RR 延迟：Min, Mean, Max (微秒)

**输出格式：**
```python
{
    "tcp_rr": {
        "min_us": 55,
        "mean_us": 112.59,
        "max_us": 19236
    },
    "udp_rr": {
        "min_us": ...,
        "mean_us": ...,
        "max_us": ...
    }
}
```

#### 3.1.2 吞吐量（Throughput）
**数据源：** 分别统计 Client 和 Server 端

**提取内容：**
- Single stream 吞吐量（Gbps）
- Multi stream 吞吐量（Gbps）
- 测试时间段（用于关联 eBPF 资源监控）

**计算方法：**
- 从 iperf3 JSON 的 `end.sum_sent.bits_per_second` 提取
- 转换为 Gbps：`bits_per_second / 1e9`

**输出格式：**
```python
{
    "client": {
        "single_stream": {
            "throughput_gbps": 12.05,
            "start_time": "2025-10-21 14:12:43.774",
            "end_time": "2025-10-21 14:12:53.890"
        },
        "multi_stream": {
            "throughput_gbps": 45.23,
            "start_time": "...",
            "end_time": "..."
        }
    },
    "server": {
        "single_stream": {...},
        "multi_stream": {...}
    }
}
```

#### 3.1.3 PPS（Packets Per Second）
**数据源：** 分别统计 Client 和 Server 端

**提取内容：**
- Single stream PPS
- Multi stream PPS
- 测试时间段（用于关联 eBPF 资源监控）

**计算方法：**
```python
# 从 iperf3 JSON 提取
bits_per_second = json["end"]["sum_sent"]["bits_per_second"]
packet_size_bytes = 64  # 固定值，从测试配置获取
packet_size_bits = packet_size_bytes * 8
pps = bits_per_second / packet_size_bits
```

**输出格式：**
```python
{
    "client": {
        "single_stream": {
            "pps": 4500000,
            "throughput_gbps": 2.304,  # 辅助信息
            "start_time": "2025-10-21 14:13:41.966",
            "end_time": "2025-10-21 14:13:54.085"
        },
        "multi_stream": {...}
    },
    "server": {...}
}
```

### 3.2 eBPF 资源开销提取

#### 3.2.1 PPS/Throughput 测试期间的资源开销

**需求：**
1. 根据 client 端的 PPS/Throughput timing 日志，确定测试时间段
2. 从 server 端的 resource monitor 日志中提取对应时间段的数据
3. 计算该时间段内的资源使用统计

**提取指标：**
- CPU 使用率：平均值、最大值、最小值
- 内存使用（RSS）：平均值、最大值
- 缺页中断率（minflt/s）：平均值、最大值

**时间匹配逻辑：**
```python
# 1. 从 timing.log 获取测试时间段
test_start = parse_datetime("2025-10-21 14:12:43.774")
test_end = parse_datetime("2025-10-21 14:12:53.890")

# 2. 转换为 Unix 时间戳
start_epoch = 1761055963
end_epoch = 1761055973

# 3. 从 resource monitor 日志筛选
# 匹配 Time 列在 [start_epoch, end_epoch] 范围内的所有行
```

**输出格式：**
```python
{
    "pps_workload": {
        "single_stream": {
            "time_range": {
                "start": "2025-10-21 14:13:41.966",
                "end": "2025-10-21 14:13:54.085"
            },
            "cpu": {
                "avg_percent": 15.3,
                "max_percent": 20.0,
                "min_percent": 0.0
            },
            "memory": {
                "avg_rss_kb": 146992,
                "max_rss_kb": 146992
            },
            "page_faults": {
                "avg_minflt_per_sec": 25.5,
                "max_minflt_per_sec": 75.0
            }
        },
        "multi_stream": {...}
    },
    "throughput_workload": {
        "single_stream": {...},
        "multi_stream": {...}
    }
}
```

#### 3.2.2 全周期最大内存占用

**需求：**
从整个测试周期（从 eBPF 工具启动到停止）的 resource monitor 日志中，提取最大内存占用。

**提取指标：**
- 最大 RSS（KB）
- 最大 VSZ（KB）
- 对应时间点

**输出格式：**
```python
{
    "max_memory": {
        "rss_kb": 146992,
        "vsz_kb": 359164,
        "timestamp": 1761055963,
        "datetime": "2025-10-21 22:12:43"
    }
}
```

#### 3.2.3 日志大小统计

**需求：**
统计整个测试周期的日志文件大小。

**提取指标：**
- 最终日志大小（字节）
- 日志增长率（bytes/s）

**输出格式：**
```python
{
    "log_size": {
        "final_size_bytes": 0,
        "final_size_human": "0B",
        "growth_rate_bytes_per_sec": 0
    }
}
```

### 3.3 Baseline 数据提取

**位置：**
- Host baseline: `host-server/performance-test-results/baseline/host/`
- VM baseline: `vm-server/performance-test-results/baseline/vm/`

**提取内容：**
与 eBPF tool case 相同的性能指标：
- 延迟（TCP RR, UDP RR）
- 吞吐量（Single, Multi stream）
- PPS（Single, Multi stream）

**输出格式：** 与 3.1 相同

---

## 4. 数据对比与差异计算

### 4.1 性能差异计算

**公式：**
```python
# 对于延迟（越低越好）
latency_diff_percent = ((ebpf_latency - baseline_latency) / baseline_latency) * 100

# 对于吞吐量/PPS（越高越好）
throughput_diff_percent = ((ebpf_throughput - baseline_throughput) / baseline_throughput) * 100
```

**输出格式：**
```python
{
    "ebpf_value": 112.59,
    "baseline_value": 105.00,
    "diff_percent": 7.23,
    "diff_absolute": 7.59
}
```

### 4.2 对比逻辑

**Host 测试（system_network_performance, linux_network_stack）：**
- eBPF tool case vs Host baseline

**VM 测试（kvm_virt_network, ovs_monitoring, vm_network_performance）：**
- eBPF tool case vs VM baseline

---

## 5. 汇总表格需求

### 5.1 表格结构

**按 Topic 分组，每个 Topic 一张表格：**
- system_network_performance
- linux_network_stack
- kvm_virt_network
- ovs_monitoring
- vm_network_performance

### 5.2 表格列定义

| 列名 | 说明 | 数据来源 |
|------|------|----------|
| Tool Case | Tool case 名称 | 目录名 |
| Protocol | 协议（TCP/UDP） | 从名称解析 |
| Direction | 方向（RX/TX） | 从名称解析 |
| **延迟指标** | | |
| Latency Mean (us) | 平均延迟 | Client 端 latency 数据 |
| Latency Mean Diff (%) | 与 baseline 差异 | 对比计算 |
| **吞吐量指标** | | |
| Throughput Single (Gbps) - Client | 客户端单流吞吐量 | Client 端 throughput 数据 |
| Throughput Single Diff (%) - Client | 与 baseline 差异 | 对比计算 |
| Throughput Multi (Gbps) - Client | 客户端多流吞吐量 | Client 端 throughput 数据 |
| Throughput Multi Diff (%) - Client | 与 baseline 差异 | 对比计算 |
| Throughput Single (Gbps) - Server | 服务端单流吞吐量 | Server 端 throughput 数据 |
| Throughput Single Diff (%) - Server | 与 baseline 差异 | 对比计算 |
| Throughput Multi (Gbps) - Server | 服务端多流吞吐量 | Server 端 throughput 数据 |
| Throughput Multi Diff (%) - Server | 与 baseline 差异 | 对比计算 |
| **PPS 指标** | | |
| PPS Single - Client | 客户端单流 PPS | Client 端 pps 数据 |
| PPS Single Diff (%) - Client | 与 baseline 差异 | 对比计算 |
| PPS Multi - Client | 客户端多流 PPS | Client 端 pps 数据 |
| PPS Multi Diff (%) - Client | 与 baseline 差异 | 对比计算 |
| PPS Single - Server | 服务端单流 PPS | Server 端 pps 数据 |
| PPS Single Diff (%) - Server | 与 baseline 差异 | 对比计算 |
| PPS Multi - Server | 服务端多流 PPS | Server 端 pps 数据 |
| PPS Multi Diff (%) - Server | 与 baseline 差异 | 对比计算 |
| **eBPF 资源开销（PPS 负载）** | | |
| CPU Avg (%) - PPS Single | PPS 单流测试时平均 CPU | Resource monitor + timing 匹配 |
| CPU Max (%) - PPS Single | PPS 单流测试时最大 CPU | Resource monitor + timing 匹配 |
| Memory Max (KB) - PPS Single | PPS 单流测试时最大内存 | Resource monitor + timing 匹配 |
| CPU Avg (%) - PPS Multi | PPS 多流测试时平均 CPU | Resource monitor + timing 匹配 |
| CPU Max (%) - PPS Multi | PPS 多流测试时最大 CPU | Resource monitor + timing 匹配 |
| Memory Max (KB) - PPS Multi | PPS 多流测试时最大内存 | Resource monitor + timing 匹配 |
| **eBPF 资源开销（Throughput 负载）** | | |
| CPU Avg (%) - TP Single | Throughput 单流测试时平均 CPU | Resource monitor + timing 匹配 |
| CPU Max (%) - TP Single | Throughput 单流测试时最大 CPU | Resource monitor + timing 匹配 |
| Memory Max (KB) - TP Single | Throughput 单流测试时最大内存 | Resource monitor + timing 匹配 |
| CPU Avg (%) - TP Multi | Throughput 多流测试时平均 CPU | Resource monitor + timing 匹配 |
| CPU Max (%) - TP Multi | Throughput 多流测试时最大 CPU | Resource monitor + timing 匹配 |
| Memory Max (KB) - TP Multi | Throughput 多流测试时最大内存 | Resource monitor + timing 匹配 |
| **全周期资源开销** | | |
| Max RSS (KB) | 全周期最大物理内存 | Resource monitor 全局最大值 |
| Max VSZ (KB) | 全周期最大虚拟内存 | Resource monitor 全局最大值 |
| **日志大小** | | |
| Log Size (Bytes) | 日志文件大小 | Logsize monitor 最终值 |

### 5.3 输出格式

**CSV 格式：**
- 文件名：`{topic}_summary_{iteration}.csv`
- 编码：UTF-8
- 分隔符：逗号

**Markdown 格式：**
- 文件名：`{topic}_summary_{iteration}.md`
- 用于可读性展示

**Excel 格式（可选）：**
- 文件名：`{topic}_summary_{iteration}.xlsx`
- 支持条件格式化（差异 > 5% 标红）

---

## 6. 工具设计需求

### 6.1 模块化设计

#### 6.1.1 核心模块

**Module 1: Data Locator（数据定位器）**
- 输入：iteration 路径、tool case 名称
- 输出：所有相关数据文件的路径字典
- 功能：
  - 自动识别测试类型（host/vm）
  - 定位 client/server 端数据
  - 定位 eBPF 监控数据

**Module 2: Performance Data Parser（性能数据解析器）**
- 输入：数据文件路径
- 输出：结构化性能指标数据
- 功能：
  - 解析延迟数据（latency_*.txt）
  - 解析吞吐量数据（iperf3 JSON）
  - 解析 PPS 数据（iperf3 JSON）
  - 提取 timing 信息

**Module 3: Resource Monitor Parser（资源监控解析器）**
- 输入：resource monitor 日志路径、时间范围（可选）
- 输出：资源使用统计
- 功能：
  - 解析 pidstat 输出格式
  - 时间范围过滤
  - 统计计算（平均值、最大值、最小值）

**Module 4: Log Size Parser（日志大小解析器）**
- 输入：logsize monitor 日志路径
- 输出：日志大小统计
- 功能：
  - 解析日志大小记录
  - 计算增长率

**Module 5: Baseline Comparator（基线对比器）**
- 输入：eBPF tool case 数据、baseline 数据
- 输出：差异分析结果
- 功能：
  - 计算绝对差异
  - 计算百分比差异
  - 生成对比报告

**Module 6: Report Generator（报告生成器）**
- 输入：所有 tool cases 的分析结果
- 输出：汇总表格（CSV/Markdown/Excel）
- 功能：
  - 按 topic 分组
  - 生成多格式报告
  - 应用条件格式化

#### 6.1.2 主流程

```python
# 伪代码
for iteration in iterations:
    for topic in topics:
        baseline_data = parse_baseline(iteration, topic)

        tool_cases = get_tool_cases(iteration, topic)
        results = []

        for tool_case in tool_cases:
            # 1. 定位数据
            paths = data_locator.locate(iteration, tool_case)

            # 2. 解析性能数据
            perf_data = performance_parser.parse(paths)

            # 3. 解析资源监控数据
            resource_data = resource_parser.parse(
                paths["resource_monitor"],
                time_ranges=perf_data["time_ranges"]
            )

            # 4. 解析日志大小
            log_data = logsize_parser.parse(paths["logsize_monitor"])

            # 5. 对比 baseline
            comparison = comparator.compare(perf_data, baseline_data)

            # 6. 汇总结果
            results.append({
                "tool_case": tool_case,
                "performance": perf_data,
                "resources": resource_data,
                "logs": log_data,
                "comparison": comparison
            })

        # 7. 生成报告
        report_generator.generate(topic, results)
```

### 6.2 容错处理

**数据缺失处理：**
- 如果某个 tool case 的数据不完整，在表格中标记为 "N/A"
- 在日志中记录缺失的文件路径
- 继续处理其他 tool cases

**数据格式异常处理：**
- 捕获解析异常
- 记录错误详情
- 使用默认值或跳过该条目

### 6.3 配置文件

**配置项：**
```yaml
# config.yaml
data_root: "/Users/admin/workspace/troubleshooting-tools/test/automate-performance-test/results"
iterations: ["iteration_001", "iteration_002", "iteration_003"]
selected_iteration: "iteration_001"  # 优先分析的 iteration

topics:
  host:
    - system_network_performance
    - linux_network_stack
  vm:
    - kvm_virt_network
    - ovs_monitoring
    - vm_network_performance

output_dir: "./analysis_results"
output_formats: ["csv", "markdown"]

# 性能差异阈值（用于高亮显示）
thresholds:
  latency_degradation_percent: 5.0   # 延迟增加 > 5% 标红
  throughput_degradation_percent: 5.0  # 吞吐量下降 > 5% 标红
  pps_degradation_percent: 5.0       # PPS 下降 > 5% 标红
```

### 6.4 命令行接口

```bash
# 分析特定 iteration 的所有 topics
python analyze_performance.py --iteration iteration_001

# 分析特定 topic
python analyze_performance.py --iteration iteration_001 --topic system_network_performance

# 指定输出格式
python analyze_performance.py --iteration iteration_001 --format csv,markdown,excel

# 详细模式（输出调试信息）
python analyze_performance.py --iteration iteration_001 --verbose

# 仅对比，不生成资源监控分析
python analyze_performance.py --iteration iteration_001 --skip-resource-analysis
```

---

## 7. 输出示例

### 7.1 单个 Tool Case 分析结果（JSON）

```json
{
  "tool_case": "system_network_performance_case_6_tcp_tx_0388a9",
  "protocol": "tcp",
  "direction": "tx",
  "performance": {
    "latency": {
      "tcp_rr": {
        "min_us": 55,
        "mean_us": 112.59,
        "max_us": 19236
      }
    },
    "throughput": {
      "client": {
        "single_stream": {
          "throughput_gbps": 12.05,
          "start_time": "2025-10-21 14:12:43.774",
          "end_time": "2025-10-21 14:12:53.890"
        },
        "multi_stream": {
          "throughput_gbps": 45.23,
          "start_time": "...",
          "end_time": "..."
        }
      },
      "server": {...}
    },
    "pps": {
      "client": {
        "single_stream": {
          "pps": 4500000,
          "throughput_gbps": 2.304,
          "start_time": "2025-10-21 14:13:41.966",
          "end_time": "2025-10-21 14:13:54.085"
        },
        "multi_stream": {...}
      },
      "server": {...}
    }
  },
  "resources": {
    "pps_workload": {
      "single_stream": {
        "cpu": {"avg_percent": 15.3, "max_percent": 20.0},
        "memory": {"avg_rss_kb": 146992, "max_rss_kb": 146992}
      },
      "multi_stream": {...}
    },
    "throughput_workload": {
      "single_stream": {...},
      "multi_stream": {...}
    },
    "max_memory": {
      "rss_kb": 146992,
      "vsz_kb": 359164
    }
  },
  "logs": {
    "log_size": {
      "final_size_bytes": 0,
      "final_size_human": "0B"
    }
  },
  "comparison": {
    "latency": {
      "tcp_rr_mean_us": {
        "ebpf": 112.59,
        "baseline": 105.00,
        "diff_percent": 7.23
      }
    },
    "throughput": {
      "client_single_gbps": {
        "ebpf": 12.05,
        "baseline": 12.50,
        "diff_percent": -3.60
      }
    },
    "pps": {...}
  }
}
```

### 7.2 汇总表格示例（Markdown）

```markdown
# System Network Performance - Summary Report

Iteration: iteration_001
Date: 2025-10-22

| Tool Case | Protocol | Direction | Latency Mean (us) | Latency Diff (%) | Throughput Single Client (Gbps) | Throughput Diff (%) | PPS Single Client | PPS Diff (%) | CPU Avg (%) - PPS Single | Memory Max (KB) - PPS Single | Max RSS (KB) | Log Size (Bytes) |
|-----------|----------|-----------|-------------------|------------------|----------------------------------|---------------------|-------------------|--------------|--------------------------|------------------------------|--------------|------------------|
| case_1    | tcp      | rx        | 110.5             | +5.2             | 12.05                            | -3.6                | 4500000           | -2.1         | 15.3                     | 146992                       | 146992       | 0                |
| case_2    | tcp      | tx        | 108.2             | +3.0             | 11.98                            | -4.2                | 4480000           | -2.5         | 14.8                     | 145000                       | 145000       | 0                |
| ...       | ...      | ...       | ...               | ...              | ...                              | ...                 | ...               | ...          | ...                      | ...                          | ...          | ...              |

**Note:**
- Red values indicate degradation > 5%
- N/A indicates missing data
```

---

## 8. 开发优先级

### Phase 1: 核心数据提取（必需）
1. Data Locator
2. Performance Data Parser
3. Baseline Comparator

### Phase 2: 资源监控分析（重要）
1. Resource Monitor Parser
2. 时间范围匹配逻辑
3. Log Size Parser

### Phase 3: 报告生成（重要）
1. Report Generator（CSV + Markdown）
2. 按 topic 分组逻辑

### Phase 4: 增强功能（可选）
1. Excel 输出 + 条件格式化
2. 图表生成
3. 趋势分析（跨 iteration 对比）

---

## 9. 验证计划

### 9.1 单元测试
- 每个解析器模块的独立测试
- 使用已知数据验证解析正确性

### 9.2 集成测试
- 使用 `iteration_001` 的完整数据运行工具
- 手工验证部分 tool case 的计算结果
- 对比工具输出与人工分析结果

### 9.3 边界测试
- 测试数据缺失场景
- 测试文件格式异常场景
- 测试空数据场景

---

## 10. 注意事项

### 10.1 时间戳处理
- Resource monitor 的 Time 列是 Unix 时间戳
- Timing log 的时间是可读字符串格式
- 需要统一转换为 Unix 时间戳进行匹配
- 考虑时区问题（日志中显示的是本地时间）

### 10.2 数据单位转换
- 内存：KB（pidstat 输出）
- 吞吐量：bps → Gbps（/1e9）
- PPS：从 bps 计算，packet_size = 64 bytes

### 10.3 浮点数精度
- 延迟：保留 2 位小数
- 吞吐量：保留 2 位小数
- 百分比差异：保留 2 位小数

### 10.4 数据完整性
- 当前 `system_network_performance` 和 `vm_network_performance` 数据完整
- 其他 topic 可能存在 eBPF 监控数据缺失
- 工具应优雅处理缺失数据

---

## 11. 报告输出系统（当前实现）

### 11.1 双报告模式

工具支持两种报告生成模式：

#### 模式1：合并报告（Combined）
- **文件数**：每个 topic 2 个文件
- **格式**：CSV (37列) + Markdown
- **用途**：完整数据，兼容旧版
- **适用场景**：需要在单个文件中查看所有指标

#### 模式2：分离报告（Separated，推荐）
- **文件数**：每个 topic 5 个文件
- **格式**：4个专项 CSV + 1个概览 Markdown
- **用途**：按类型分离，易读易分析
- **适用场景**：日常分析，Excel 处理

### 11.2 分离报告详细说明

每个 topic 生成 5 个报告文件：

#### 1. 概览报告（Overview Markdown）
**文件名**: `{topic}_overview_{iteration}.md`

**内容**：
- 统计摘要（总 case 数，各类数据完整性）
- 性能摘要表格（Tool Case, Protocol, Direction, 三大指标的差异%）
- 详细报告文件列表

**用途**: 快速了解整体情况

**示例**：
```markdown
# System Network Performance - Analysis Overview

**Iteration:** iteration_001
**Total Cases:** 10

## Summary Statistics
- Cases with latency data: 10
- Cases with throughput data: 10
- Cases with PPS data: 10

## Performance Summary
| Tool Case | Protocol | Dir | Latency Diff (%) | Throughput Diff (%) | PPS Diff (%) |
|-----------|----------|-----|------------------|---------------------|---------------|
| case_1    | tcp      | rx  | 28.05            | -16.41              | -3.34         |
```

#### 2. 延迟专项报告（Latency CSV）
**文件名**: `{topic}_latency_{iteration}.csv`

**列数**: 13 列

**列定义**：
| 列名 | 说明 |
|------|------|
| Tool Case | Tool case 名称 |
| Protocol | 协议（TCP/UDP） |
| Direction | 方向（RX/TX） |
| TCP RR Min (us) | TCP RR 最小延迟 |
| TCP RR Mean (us) | TCP RR 平均延迟 |
| TCP RR Max (us) | TCP RR 最大延迟 |
| TCP RR Baseline (us) | TCP RR baseline 延迟 |
| TCP RR Diff (%) | TCP RR 差异百分比 |
| UDP RR Min (us) | UDP RR 最小延迟 |
| UDP RR Mean (us) | UDP RR 平均延迟 |
| UDP RR Max (us) | UDP RR 最大延迟 |
| UDP RR Baseline (us) | UDP RR baseline 延迟 |
| UDP RR Diff (%) | UDP RR 差异百分比 |

**用途**: 专注于延迟分析和对比

#### 3. 吞吐量专项报告（Throughput CSV）
**文件名**: `{topic}_throughput_{iteration}.csv`

**列数**: 15 列

**列定义**：
| 分类 | 列名 | 说明 |
|------|------|------|
| 基本 | Tool Case, Protocol, Direction | 基本信息 |
| Client Single | Client Single (Gbps) | Client 单流吞吐量 |
| | Client Single Baseline (Gbps) | Baseline 值 |
| | Client Single Diff (%) | 差异百分比 |
| Client Multi | Client Multi (Gbps) | Client 多流吞吐量 |
| | Client Multi Baseline (Gbps) | Baseline 值 |
| | Client Multi Diff (%) | 差异百分比 |
| Server Single | Server Single (Gbps) | Server 单流吞吐量 |
| | Server Single Baseline (Gbps) | Baseline 值 |
| | Server Single Diff (%) | 差异百分比 |
| Server Multi | Server Multi (Gbps) | Server 多流吞吐量 |
| | Server Multi Baseline (Gbps) | Baseline 值 |
| | Server Multi Diff (%) | 差异百分比 |

**特点**：
- Multi-stream 数据已累加所有 stream
- 分别统计 Client 和 Server 端

#### 4. PPS 专项报告（PPS CSV）
**文件名**: `{topic}_pps_{iteration}.csv`

**列数**: 15 列

**列定义**: 与 Throughput 相同结构，但值为 PPS（packets per second）

**计算方法**：
```python
pps = bits_per_second / (packet_size_bytes * 8)
# packet_size 默认 64 bytes（小包测试）
```

**特点**：
- 自动容错处理缺失的 packet_size（使用默认值 64）
- Multi-stream 数据已累加

#### 5. 资源开销专项报告（Resources CSV）
**文件名**: `{topic}_resources_{iteration}.csv`

**列数**: 20 列

**列定义**：
| 分类 | 列名 | 说明 |
|------|------|------|
| 基本 | Tool Case, Protocol, Direction | 基本信息 |
| PPS Single | PPS Single - CPU Avg (%) | PPS 单流平均 CPU |
| | PPS Single - CPU Max (%) | PPS 单流最大 CPU |
| | PPS Single - Mem Max (KB) | PPS 单流最大内存 |
| PPS Multi | PPS Multi - CPU Avg (%) | PPS 多流平均 CPU |
| | PPS Multi - CPU Max (%) | PPS 多流最大 CPU |
| | PPS Multi - Mem Max (KB) | PPS 多流最大内存 |
| TP Single | TP Single - CPU Avg (%) | Throughput 单流平均 CPU |
| | TP Single - CPU Max (%) | Throughput 单流最大 CPU |
| | TP Single - Mem Max (KB) | Throughput 单流最大内存 |
| TP Multi | TP Multi - CPU Avg (%) | Throughput 多流平均 CPU |
| | TP Multi - CPU Max (%) | Throughput 多流最大 CPU |
| | TP Multi - Mem Max (KB) | Throughput 多流最大内存 |
| Full Cycle | Max RSS (KB) | 全周期最大物理内存 |
| | Max VSZ (KB) | 全周期最大虚拟内存 |
| | Total Samples | 监控采样总数 |
| Log | Log Size (Bytes) | 日志文件大小（字节） |
| | Log Size (Human) | 日志文件大小（可读） |

**特点**：
- 区分不同 workload 的资源开销
- 提供全周期最大内存统计

### 11.3 命令行选项

```bash
# 只生成分离报告（推荐）
python3 analyze_performance.py --report-style separated

# 只生成合并报告
python3 analyze_performance.py --report-style combined

# 同时生成两种报告（默认）
python3 analyze_performance.py --report-style both
```

### 11.4 报告使用建议

**工作流程**：
1. 打开 `*_overview_*.md` 查看总体情况
2. 根据分析需求打开对应的专项 CSV：
   - 关注延迟 → `*_latency_*.csv`
   - 关注吞吐量 → `*_throughput_*.csv`
   - 关注 PPS → `*_pps_*.csv`
   - 关注资源开销 → `*_resources_*.csv`
3. 使用 Excel 进行排序、筛选、图表分析

**优势**：
- ✅ 每个报告聚焦一类指标，易于理解
- ✅ 列数合理（13-20列），Excel 可完整显示
- ✅ 支持独立分析，无需滚动查看
- ✅ 保留合并报告作为兼容选项

---

## 12. 实现状态与已知问题

### 12.1 已实现功能（v1.0）

✅ **核心功能**
- 数据定位：自动识别 Host/VM 测试类型
- 性能解析：Latency, Throughput (Single+Multi), PPS (Single+Multi)
- 资源监控：CPU/内存/日志大小，按 workload 分类
- Baseline 对比：计算绝对差异和百分比差异
- 双报告系统：合并报告 + 分离报告

✅ **容错处理**
- Multi-stream timing 格式自适应（Throughput/PPS）
- PPS packet_size 容错（默认 64 bytes）
- 数据缺失标记为 N/A
- 详细的错误日志

✅ **易用性**
- 命令行参数：--topic, --iteration, --report-style, --verbose
- 配置文件：config.yaml
- 文档完整：需求、设计、使用、修复、优化

### 12.2 数据完整性现状

| 数据类型 | Client 端 | Server 端 | 完整性 |
|---------|----------|----------|--------|
| Latency | ✅ 100% | N/A | 完整 |
| Throughput Single | ✅ 100% | ❌ 0% | Client 完整 |
| Throughput Multi | ✅ 100% | ❌ 0% | Client 完整 |
| PPS Single | ✅ 100% | ❌ 0% | Client 完整 |
| PPS Multi | ✅ 100% | ❌ 0% | Client 完整 |
| eBPF Resources | ⚠️ 70% | - | 部分可用 |

**总体**: Client 端 80%, Server 端待排查

### 12.3 已知限制

#### 问题1: Server 端数据缺失
- **现象**: 所有 tool cases 的 Server 端数据都是 N/A
- **可能原因**: DataLocator 定位路径问题或数据源问题
- **影响**: 无法对比 Server 端的吞吐量和 PPS
- **优先级**: 中（不影响 Client 端分析）

#### 问题2: 资源监控时间戳不匹配
- **现象**: 部分测试显示 "No records in time range"
- **可能原因**: Client timing 与 Server resource monitor 时间不同步
- **影响**: 无法提取特定 workload 的资源开销
- **优先级**: 中（仍有全周期数据）

#### 问题3: 部分 case 监控数据为空
- **现象**: 个别 case 的 resource monitor 或 logsize monitor 日志为空
- **可能原因**: 测试过程中监控脚本未正常启动
- **影响**: 该 case 的资源和日志数据为 N/A
- **优先级**: 低（属于测试环境问题）

### 12.4 后续改进方向

**短期**：
- 排查 Server 端数据缺失原因
- 优化资源监控时间戳匹配逻辑

**中期**：
- 添加数据验证逻辑（检测异常值）
- 支持 Excel 输出（带条件格式化）

**长期**：
- 生成性能趋势图表
- 支持跨 iteration 对比分析
- 添加自动化测试用例

---

## 附录：关键修复记录

### A1. Multi-stream Timing 格式修复
**日期**: 2025-10-22
**文件**: `src/parsers/performance_parser.py`
**修改**: `parse_throughput_multi()` 改用 PPS 格式解析 timing
**影响**: Multi-stream 数据从 0% → 100%

### A2. PPS Packet Size 容错
**日期**: 2025-10-22
**文件**: `src/parsers/performance_parser.py`
**修改**: 添加多位置查找逻辑 + 默认值
**影响**: PPS 数据从 0% → 100%

### A3. 分离报告系统
**日期**: 2025-10-22
**文件**: `src/report_generator_v2.py`, `analyze_performance.py`
**修改**: 新增 5 个专项报告生成器
**影响**: 报告可读性大幅提升

