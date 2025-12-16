# 性能测试数据分析工具 - 设计文档

## 📌 当前版本：v1.0（2025-10-22）

### 实现状态
- ✅ 所有核心模块已实现
- ✅ Multi-stream 数据累加已修复
- ✅ PPS 容错处理已实现
- ✅ 双报告系统已部署
- ⏳ Server 端数据定位待优化
- ⏳ 资源监控时间匹配待优化

### 关键特性
1. **智能数据定位**：自动识别 Host/VM 测试类型
2. **容错解析**：Multi-stream timing 自适应，PPS packet_size 容错
3. **双报告系统**：合并报告（37列）+ 分离报告（5个专项文件）
4. **灵活配置**：支持 YAML 配置和命令行参数

---

## 1. 架构概览

### 1.1 系统架构图

```
┌─────────────────────────────────────────────────────────────┐
│                     Main Application                        │
│                  (analyze_performance.py)                   │
└──────────────┬──────────────────────────────────────────────┘
               │
               ├─── Configuration Manager (config.yaml)
               │
               ├─── Data Locator
               │    ├─── 定位所有数据文件路径
               │    └─── 自动识别 Host/VM 测试类型
               │
               ├─── Performance Data Parser
               │    ├─── Latency Parser
               │    ├─── Throughput Parser (支持 Multi-stream)
               │    └─── PPS Parser (支持容错)
               │
               ├─── Resource Monitor Parser
               │    ├─── Pidstat Log Parser
               │    └─── Time Range Filter
               │
               ├─── Log Size Parser
               │
               ├─── Baseline Comparator
               │    └─── Diff Calculator
               │
               ├─── Report Generator (合并报告)
               │    ├─── CSV Generator (37列)
               │    └─── Markdown Generator
               │
               └─── Report Generator V2 (分离报告，推荐)
                    ├─── Latency Report (13列)
                    ├─── Throughput Report (15列)
                    ├─── PPS Report (15列)
                    ├─── Resources Report (20列)
                    └─── Overview Markdown
```

### 1.2 模块依赖关系

```
analyze_performance.py (主程序)
    ↓
config.yaml (配置)
    ↓
data_locator.py (数据定位)
    ↓
parsers/
    ├── performance_parser.py (性能数据解析)
    ├── resource_parser.py (资源监控解析)
    └── logsize_parser.py (日志大小解析)
    ↓
comparator.py (基线对比)
    ↓
report_generator.py (报告生成)
```

### 1.3 目录结构

```
analysis/
├── REQUIREMENTS.md           # 需求文档
├── DESIGN.md                # 设计文档（本文档）
├── README.md                # 使用说明
├── config.yaml              # 配置文件
├── analyze_performance.py   # 主程序
├── src/                     # 源代码
│   ├── __init__.py
│   ├── data_locator.py      # 数据定位器
│   ├── comparator.py        # 基线对比器
│   ├── report_generator.py  # 报告生成器
│   ├── utils.py             # 工具函数
│   └── parsers/             # 解析器模块
│       ├── __init__.py
│       ├── performance_parser.py  # 性能数据解析器
│       ├── resource_parser.py     # 资源监控解析器
│       └── logsize_parser.py      # 日志大小解析器
├── tests/                   # 单元测试
│   ├── __init__.py
│   ├── test_data_locator.py
│   ├── test_parsers.py
│   └── test_comparator.py
└── output/                  # 输出目录
    └── .gitkeep
```

---

## 2. 核心模块设计

### 2.1 Data Locator（数据定位器）

**职责：** 根据 iteration 和 tool case 名称，定位所有相关数据文件路径

**输入：**
- `iteration_path`: iteration 目录路径
- `tool_case_name`: tool case 名称

**输出：**
```python
{
    "test_type": "host" | "vm",
    "client": {
        "latency": {
            "tcp_rr": "/path/to/latency/tcp_rr_*/latency_tcp_rr.txt",
            "udp_rr": "/path/to/latency/udp_rr_*/latency_udp_rr.txt"
        },
        "throughput": {
            "single": {
                "json": "/path/to/throughput/single_*/throughput_single_tcp.json",
                "timing": "/path/to/throughput/single_*/throughput_single_timing.log"
            },
            "multi": {
                "json_files": ["/path/to/throughput/multi_*/throughput_multi_tcp_port_*.json"],
                "timing": "/path/to/throughput/multi_*/throughput_multi_timing.log"
            }
        },
        "pps": {
            "single": {...},
            "multi": {...}
        }
    },
    "server": {
        "latency": {...},
        "throughput": {...},
        "pps": {...},
        "ebpf_monitoring": {
            "resource_monitor": "/path/to/ebpf_monitoring/ebpf_resource_monitor_*.log",
            "logsize_monitor": "/path/to/ebpf_monitoring/ebpf_logsize_monitor_*.log"
        }
    }
}
```

**关键逻辑：**
1. 自动识别测试类型（host/vm）
   - 检查 `host-server/performance-test-results/ebpf/{tool_case_name}/host/` 是否存在
   - 检查 `vm-server/performance-test-results/ebpf/{tool_case_name}/vm/` 是否存在
2. 根据测试类型构建不同的路径
3. 使用 glob 模式匹配时间戳文件名

**错误处理：**
- 如果关键文件不存在，返回 None 并记录警告
- 如果找到多个匹配文件，选择最新的（按文件名排序）

**类设计：**
```python
class DataLocator:
    def __init__(self, iteration_path: str):
        self.iteration_path = iteration_path

    def locate_tool_case(self, tool_case_name: str) -> dict:
        """定位单个 tool case 的所有数据文件"""
        pass

    def locate_baseline(self, test_type: str) -> dict:
        """定位 baseline 数据文件"""
        pass

    def _detect_test_type(self, tool_case_name: str) -> str:
        """检测测试类型（host/vm）"""
        pass

    def _find_latest_file(self, pattern: str) -> str:
        """找到最新的匹配文件"""
        pass
```

---

### 2.2 Performance Data Parser（性能数据解析器）

**职责：** 解析延迟、吞吐量、PPS 测试结果

#### 2.2.1 Latency Parser

**输入：** latency_tcp_rr.txt 文件路径

**输出：**
```python
{
    "min_us": 55,
    "mean_us": 112.59,
    "max_us": 19236
}
```

**解析逻辑：**
```python
def parse_latency(file_path: str) -> dict:
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # 跳过前两行（header）
    data_line = lines[2].strip()
    values = data_line.split(',')

    return {
        "min_us": float(values[0]),
        "mean_us": float(values[1]),
        "max_us": float(values[2])
    }
```

#### 2.2.2 Throughput Parser

**输入：**
- JSON 文件路径（单个或多个）
- timing.log 文件路径

**输出：**
```python
{
    "throughput_gbps": 12.05,
    "start_time": "2025-10-21 14:12:43.774",
    "end_time": "2025-10-21 14:12:53.890",
    "start_epoch": 1761055963,
    "end_epoch": 1761055973
}
```

**解析逻辑：**
```python
def parse_throughput(json_path: str, timing_path: str) -> dict:
    # 1. 解析 iperf3 JSON
    with open(json_path, 'r') as f:
        data = json.load(f)

    bps = data["end"]["sum_sent"]["bits_per_second"]
    throughput_gbps = bps / 1e9

    # 2. 解析 timing log
    with open(timing_path, 'r') as f:
        lines = f.readlines()

    start_time = parse_line(lines[1], "Start: ")
    end_time = parse_line(lines[2], "End: ")

    return {
        "throughput_gbps": round(throughput_gbps, 2),
        "start_time": start_time,
        "end_time": end_time,
        "start_epoch": datetime_to_epoch(start_time),
        "end_epoch": datetime_to_epoch(end_time)
    }
```

**Multi-stream 处理：**
```python
def parse_throughput_multi(json_paths: list, timing_path: str) -> dict:
    # 累加所有 stream 的吞吐量
    total_bps = 0
    for json_path in json_paths:
        with open(json_path, 'r') as f:
            data = json.load(f)
        total_bps += data["end"]["sum_sent"]["bits_per_second"]

    throughput_gbps = total_bps / 1e9

    # 注意：Multi-stream 的 timing 格式与 PPS 相同（Process_Start/Actual_Launch/Test_End）
    # 而不是 Start/End 格式！
    # 需要使用 parse_timing_log(timing_path, "pps") 而不是 "throughput"
    timing = parse_timing_log(timing_path, "pps")  # 修正：使用 PPS 格式
    # ...
```

#### 2.2.3 PPS Parser

**输入：** 同 Throughput Parser

**输出：**
```python
{
    "pps": 4500000,
    "throughput_gbps": 2.304,  # 辅助信息
    "packet_size_bytes": 64,
    "start_time": "2025-10-21 14:13:41.966",
    "end_time": "2025-10-21 14:13:54.085",
    "start_epoch": 1761056021,
    "end_epoch": 1761056034
}
```

**解析逻辑：**
```python
def parse_pps(json_path: str, timing_path: str) -> dict:
    # 1. 解析 iperf3 JSON
    with open(json_path, 'r') as f:
        data = json.load(f)

    bps = data["end"]["sum_sent"]["bits_per_second"]

    # 获取 packet_size（容错处理）
    packet_size = None
    # 尝试从 test_start 获取
    if "test_start" in data and "blksize" in data["test_start"]:
        packet_size = data["test_start"]["blksize"]
    # 尝试从 start.test_start 获取
    elif "start" in data and "test_start" in data["start"] and "blksize" in data["start"]["test_start"]:
        packet_size = data["start"]["test_start"]["blksize"]
    # 默认值
    else:
        packet_size = 64  # 默认 PPS 测试使用 64 字节包

    pps = bps / (packet_size * 8)
    throughput_gbps = bps / 1e9

    # 2. 解析 timing log（注意：PPS timing 格式不同）
    # Process_Start / Actual_Launch / Test_End
    with open(timing_path, 'r') as f:
        lines = f.readlines()

    start_time = parse_line(lines[2], "Actual_Launch: ")
    end_time = parse_line(lines[3], "Test_End: ")

    return {
        "pps": int(pps),
        "throughput_gbps": round(throughput_gbps, 2),
        "packet_size_bytes": packet_size,
        "start_time": start_time,
        "end_time": end_time,
        "start_epoch": datetime_to_epoch(start_time),
        "end_epoch": datetime_to_epoch(end_time)
    }
```

**类设计：**
```python
class PerformanceParser:
    @staticmethod
    def parse_latency(file_path: str) -> dict:
        pass

    @staticmethod
    def parse_throughput_single(json_path: str, timing_path: str) -> dict:
        pass

    @staticmethod
    def parse_throughput_multi(json_paths: list, timing_path: str) -> dict:
        pass

    @staticmethod
    def parse_pps_single(json_path: str, timing_path: str) -> dict:
        pass

    @staticmethod
    def parse_pps_multi(json_paths: list, timing_path: str) -> dict:
        pass

    @staticmethod
    def parse_all(paths: dict) -> dict:
        """解析所有性能数据"""
        pass
```

---

### 2.3 Resource Monitor Parser（资源监控解析器）

**职责：** 解析 pidstat 资源监控日志，支持时间范围过滤

**输入：**
- `log_path`: resource monitor 日志路径
- `time_ranges`: 时间范围列表（可选）

**输出：**
```python
{
    "full_cycle": {
        "max_rss_kb": 146992,
        "max_vsz_kb": 359164,
        "max_rss_timestamp": 1761055963,
        "max_vsz_timestamp": 1761055963
    },
    "time_range_stats": {
        "pps_single": {
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
            },
            "sample_count": 5
        },
        "throughput_multi": {...}
    }
}
```

**解析逻辑：**
```python
def parse_resource_monitor(log_path: str, time_ranges: dict = None) -> dict:
    records = []

    with open(log_path, 'r') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue

            # 解析 pidstat 输出格式
            parts = line.split()
            if len(parts) < 13:
                continue

            record = {
                "timestamp": int(parts[0]),
                "cpu_percent": float(parts[6]),
                "rss_kb": int(parts[11]),
                "vsz_kb": int(parts[10]),
                "minflt_per_sec": float(parts[8]),
                "mem_percent": float(parts[12])
            }
            records.append(record)

    # 全周期统计
    full_cycle = calculate_full_cycle_stats(records)

    # 时间范围统计
    time_range_stats = {}
    if time_ranges:
        for name, (start_epoch, end_epoch) in time_ranges.items():
            filtered = [r for r in records
                       if start_epoch <= r["timestamp"] <= end_epoch]
            time_range_stats[name] = calculate_stats(filtered)

    return {
        "full_cycle": full_cycle,
        "time_range_stats": time_range_stats
    }

def calculate_stats(records: list) -> dict:
    if not records:
        return None

    cpu_values = [r["cpu_percent"] for r in records]
    rss_values = [r["rss_kb"] for r in records]
    minflt_values = [r["minflt_per_sec"] for r in records]

    return {
        "cpu": {
            "avg_percent": round(sum(cpu_values) / len(cpu_values), 2),
            "max_percent": round(max(cpu_values), 2),
            "min_percent": round(min(cpu_values), 2)
        },
        "memory": {
            "avg_rss_kb": int(sum(rss_values) / len(rss_values)),
            "max_rss_kb": max(rss_values)
        },
        "page_faults": {
            "avg_minflt_per_sec": round(sum(minflt_values) / len(minflt_values), 2),
            "max_minflt_per_sec": round(max(minflt_values), 2)
        },
        "sample_count": len(records)
    }
```

**类设计：**
```python
class ResourceParser:
    @staticmethod
    def parse(log_path: str, time_ranges: dict = None) -> dict:
        pass

    @staticmethod
    def _parse_pidstat_line(line: str) -> dict:
        """解析单行 pidstat 输出"""
        pass

    @staticmethod
    def _calculate_stats(records: list) -> dict:
        """计算统计指标"""
        pass
```

---

### 2.4 Log Size Parser（日志大小解析器）

**职责：** 解析 eBPF 日志大小监控数据

**输入：** logsize monitor 日志路径

**输出：**
```python
{
    "final_size_bytes": 0,
    "final_size_human": "0B",
    "growth_rate_bytes_per_sec": 0,
    "sample_count": 48
}
```

**解析逻辑：**
```python
def parse_logsize(log_path: str) -> dict:
    records = []

    with open(log_path, 'r') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            timestamp_str = parts[0] + ' ' + parts[1]
            size_bytes = int(parts[2])

            records.append({
                "timestamp": parse_datetime(timestamp_str),
                "size_bytes": size_bytes
            })

    if not records:
        return None

    # 最终大小
    final_size = records[-1]["size_bytes"]

    # 计算增长率
    if len(records) > 1:
        duration = (records[-1]["timestamp"] - records[0]["timestamp"]).total_seconds()
        growth = final_size - records[0]["size_bytes"]
        growth_rate = growth / duration if duration > 0 else 0
    else:
        growth_rate = 0

    return {
        "final_size_bytes": final_size,
        "final_size_human": humanize_bytes(final_size),
        "growth_rate_bytes_per_sec": round(growth_rate, 2),
        "sample_count": len(records)
    }
```

**类设计：**
```python
class LogSizeParser:
    @staticmethod
    def parse(log_path: str) -> dict:
        pass
```

---

### 2.5 Baseline Comparator（基线对比器）

**职责：** 对比 eBPF tool case 和 baseline 的性能差异

**输入：**
- `ebpf_data`: eBPF tool case 的性能数据
- `baseline_data`: Baseline 性能数据

**输出：**
```python
{
    "latency": {
        "tcp_rr_mean_us": {
            "ebpf": 112.59,
            "baseline": 105.00,
            "diff_absolute": 7.59,
            "diff_percent": 7.23
        }
    },
    "throughput": {
        "client_single_gbps": {
            "ebpf": 12.05,
            "baseline": 12.50,
            "diff_absolute": -0.45,
            "diff_percent": -3.60
        },
        "server_multi_gbps": {...}
    },
    "pps": {...}
}
```

**对比逻辑：**
```python
def compare(ebpf_data: dict, baseline_data: dict) -> dict:
    result = {}

    # 延迟对比（越低越好）
    if "latency" in ebpf_data and "latency" in baseline_data:
        result["latency"] = {}
        for protocol in ["tcp_rr", "udp_rr"]:
            if protocol in ebpf_data["latency"]:
                ebpf_val = ebpf_data["latency"][protocol]["mean_us"]
                baseline_val = baseline_data["latency"][protocol]["mean_us"]
                result["latency"][f"{protocol}_mean_us"] = calculate_diff(
                    ebpf_val, baseline_val
                )

    # 吞吐量对比（越高越好）
    # PPS 对比（越高越好）
    # ...

    return result

def calculate_diff(ebpf_val: float, baseline_val: float) -> dict:
    diff_absolute = ebpf_val - baseline_val
    diff_percent = (diff_absolute / baseline_val) * 100 if baseline_val != 0 else 0

    return {
        "ebpf": round(ebpf_val, 2),
        "baseline": round(baseline_val, 2),
        "diff_absolute": round(diff_absolute, 2),
        "diff_percent": round(diff_percent, 2)
    }
```

**类设计：**
```python
class BaselineComparator:
    @staticmethod
    def compare(ebpf_data: dict, baseline_data: dict) -> dict:
        pass

    @staticmethod
    def _calculate_diff(ebpf_val: float, baseline_val: float) -> dict:
        pass

    @staticmethod
    def _compare_latency(ebpf: dict, baseline: dict) -> dict:
        pass

    @staticmethod
    def _compare_throughput(ebpf: dict, baseline: dict) -> dict:
        pass

    @staticmethod
    def _compare_pps(ebpf: dict, baseline: dict) -> dict:
        pass
```

---

### 2.6 Report Generator（报告生成器）

**职责：** 生成汇总表格（CSV、Markdown）

**输入：**
- `topic`: Topic 名称
- `results`: 所有 tool cases 的分析结果列表

**输出：** 生成文件到 output 目录

#### 2.6.1 CSV Generator

**输出格式：**
```csv
Tool Case,Protocol,Direction,Latency Mean (us),Latency Diff (%),Throughput Single Client (Gbps),Throughput Single Diff (%),PPS Single Client,PPS Single Diff (%),CPU Avg (%) - PPS Single,Memory Max (KB) - PPS Single,Max RSS (KB),Log Size (Bytes)
case_1,tcp,rx,110.5,5.2,12.05,-3.6,4500000,-2.1,15.3,146992,146992,0
```

**生成逻辑：**
```python
def generate_csv(topic: str, results: list, output_path: str):
    headers = [
        "Tool Case", "Protocol", "Direction",
        "Latency Mean (us)", "Latency Diff (%)",
        "Throughput Single Client (Gbps)", "Throughput Single Diff (%)",
        "PPS Single Client", "PPS Single Diff (%)",
        "CPU Avg (%) - PPS Single", "Memory Max (KB) - PPS Single",
        "Max RSS (KB)", "Log Size (Bytes)"
    ]

    rows = []
    for result in results:
        row = extract_row_data(result)
        rows.append(row)

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
```

#### 2.6.2 Markdown Generator

**输出格式：**
```markdown
# Topic Name - Summary Report

**Iteration:** iteration_001
**Date:** 2025-10-22

| Tool Case | Protocol | Direction | Latency Mean (us) | ... |
|-----------|----------|-----------|-------------------|-----|
| case_1    | tcp      | rx        | 110.5             | ... |
```

**类设计：**
```python
class ReportGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def generate(self, topic: str, results: list, iteration: str):
        """生成所有格式的报告"""
        self.generate_csv(topic, results, iteration)
        self.generate_markdown(topic, results, iteration)

    def generate_csv(self, topic: str, results: list, iteration: str):
        pass

    def generate_markdown(self, topic: str, results: list, iteration: str):
        pass

    def _extract_row_data(self, result: dict) -> list:
        """从结果字典提取表格行数据"""
        pass
```

---

## 3. 工具函数（utils.py）

### 3.1 时间转换函数

```python
def parse_datetime(datetime_str: str) -> datetime:
    """解析日期时间字符串

    支持格式：
    - 2025-10-21 14:12:43.774
    - Tue, 21 Oct 2025 14:13:41 GMT
    """
    pass

def datetime_to_epoch(datetime_str: str) -> int:
    """将日期时间字符串转换为 Unix 时间戳"""
    pass

def epoch_to_datetime(epoch: int) -> str:
    """将 Unix 时间戳转换为可读字符串"""
    pass
```

### 3.2 数据单位转换

```python
def humanize_bytes(bytes: int) -> str:
    """转换字节数为人类可读格式

    Examples:
        0 -> "0B"
        1024 -> "1.0KB"
        1048576 -> "1.0MB"
    """
    pass

def bps_to_gbps(bps: float) -> float:
    """将 bps 转换为 Gbps"""
    return round(bps / 1e9, 2)
```

### 3.3 文件操作

```python
def find_latest_file(pattern: str) -> str:
    """找到匹配 glob 模式的最新文件"""
    import glob
    files = glob.glob(pattern)
    if not files:
        return None
    return sorted(files)[-1]

def safe_read_json(file_path: str) -> dict:
    """安全读取 JSON 文件，处理异常"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to read JSON {file_path}: {e}")
        return None
```

### 3.4 Tool Case 名称解析

```python
def parse_tool_case_name(tool_case_name: str) -> dict:
    """解析 tool case 名称

    Input: "system_network_performance_case_6_tcp_tx_0388a9"
    Output: {
        "topic": "system_network_performance",
        "case_number": 6,
        "protocol": "tcp",
        "direction": "tx",
        "hash": "0388a9"
    }
    """
    import re
    pattern = r"(.+)_case_(\d+)_(\w+)_(\w+)_(\w+)"
    match = re.match(pattern, tool_case_name)

    if not match:
        return None

    return {
        "topic": match.group(1),
        "case_number": int(match.group(2)),
        "protocol": match.group(3),
        "direction": match.group(4),
        "hash": match.group(5)
    }
```

---

## 4. 主程序设计

### 4.1 主流程

```python
def main():
    # 1. 加载配置
    config = load_config("config.yaml")

    # 2. 初始化组件
    iteration_path = os.path.join(config["data_root"], config["selected_iteration"])
    locator = DataLocator(iteration_path)
    report_gen = ReportGenerator(config["output_dir"])

    # 3. 获取所有 topics
    topics = get_all_topics(iteration_path, config)

    # 4. 处理每个 topic
    for topic in topics:
        logger.info(f"Processing topic: {topic}")

        # 4.1 获取该 topic 的所有 tool cases
        tool_cases = get_tool_cases_for_topic(iteration_path, topic)

        # 4.2 解析 baseline
        test_type = detect_test_type_for_topic(topic)
        baseline_paths = locator.locate_baseline(test_type)
        baseline_data = PerformanceParser.parse_all(baseline_paths)

        # 4.3 处理每个 tool case
        results = []
        for tool_case in tool_cases:
            try:
                result = process_tool_case(
                    locator, tool_case, baseline_data, config
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to process {tool_case}: {e}")
                continue

        # 4.4 生成报告
        report_gen.generate(topic, results, config["selected_iteration"])

def process_tool_case(locator, tool_case_name, baseline_data, config):
    """处理单个 tool case"""
    # 1. 定位数据
    paths = locator.locate_tool_case(tool_case_name)

    # 2. 解析性能数据
    perf_data = PerformanceParser.parse_all(paths)

    # 3. 解析资源监控数据
    time_ranges = extract_time_ranges(perf_data)
    resource_data = ResourceParser.parse(
        paths["server"]["ebpf_monitoring"]["resource_monitor"],
        time_ranges
    )

    # 4. 解析日志大小
    log_data = LogSizeParser.parse(
        paths["server"]["ebpf_monitoring"]["logsize_monitor"]
    )

    # 5. 对比 baseline
    comparison = BaselineComparator.compare(perf_data, baseline_data)

    # 6. 返回汇总结果
    return {
        "tool_case": tool_case_name,
        "metadata": parse_tool_case_name(tool_case_name),
        "performance": perf_data,
        "resources": resource_data,
        "logs": log_data,
        "comparison": comparison
    }
```

### 4.2 命令行参数

```python
import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze performance test results"
    )

    parser.add_argument(
        "--iteration",
        type=str,
        default="iteration_001",
        help="Iteration to analyze (default: iteration_001)"
    )

    parser.add_argument(
        "--topic",
        type=str,
        default=None,
        help="Specific topic to analyze (default: all topics)"
    )

    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="./output",
        help="Output directory (default: ./output)"
    )

    parser.add_argument(
        "--format",
        type=str,
        default="csv,markdown",
        help="Output formats (default: csv,markdown)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    return parser.parse_args()
```

---

## 5. 配置文件设计

```yaml
# config.yaml

# 数据根目录
data_root: "../results"

# 待分析的 iterations
iterations:
  - iteration_001
  - iteration_002
  - iteration_003

# 优先分析的 iteration
selected_iteration: iteration_001

# Topics 配置
topics:
  host:
    - system_network_performance
    - linux_network_stack
  vm:
    - kvm_virt_network
    - ovs_monitoring
    - vm_network_performance

# 输出配置
output_dir: "./output"
output_formats:
  - csv
  - markdown

# 性能差异阈值（用于高亮）
thresholds:
  latency_degradation_percent: 5.0
  throughput_degradation_percent: 5.0
  pps_degradation_percent: 5.0

# 日志配置
logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "./analysis.log"
```

---

## 6. 错误处理策略

### 6.1 数据缺失处理

**策略：**
1. 关键数据缺失：记录警告，该 tool case 标记为 "N/A"，继续处理其他 cases
2. 次要数据缺失：使用默认值填充，在报告中添加注释

**实现：**
```python
def safe_parse(parser_func, *args, default=None):
    """安全解析，捕获异常并返回默认值"""
    try:
        return parser_func(*args)
    except FileNotFoundError as e:
        logger.warning(f"File not found: {e}")
        return default
    except Exception as e:
        logger.error(f"Parse error: {e}")
        return default
```

### 6.2 数据格式异常

**策略：**
1. JSON 解析失败：记录错误，返回 None
2. CSV 格式不匹配：尝试灵活解析，失败则跳过
3. 数值转换失败：使用 0 或 NaN

---

## 7. 测试策略

### 7.1 单元测试

**测试模块：**
- `test_data_locator.py`: 测试文件定位逻辑
- `test_parsers.py`: 测试各解析器的正确性
- `test_comparator.py`: 测试对比计算
- `test_utils.py`: 测试工具函数

**测试数据：**
- 使用 `tests/fixtures/` 存放测试数据样本

### 7.2 集成测试

**测试流程：**
1. 使用真实的 `iteration_001` 数据运行完整分析
2. 验证输出文件生成正确
3. 手工检查部分结果的准确性

---

## 8. 性能优化考虑

### 8.1 并行处理

对于多个 tool cases 的处理，可以考虑使用多进程：

```python
from multiprocessing import Pool

def parallel_process_tool_cases(tool_cases, locator, baseline_data, config):
    with Pool(processes=4) as pool:
        results = pool.starmap(
            process_tool_case,
            [(locator, tc, baseline_data, config) for tc in tool_cases]
        )
    return results
```

### 8.2 数据缓存

对于重复读取的 baseline 数据，可以使用缓存：

```python
from functools import lru_cache

@lru_cache(maxsize=10)
def load_baseline_cached(baseline_path):
    return PerformanceParser.parse_all(baseline_path)
```

---

## 9. 扩展性设计

### 9.1 新增输出格式

**接口设计：**
```python
class ReportGenerator:
    def generate(self, topic, results, iteration):
        for fmt in self.formats:
            generator = self._get_generator(fmt)
            generator.generate(topic, results, iteration)

    def _get_generator(self, fmt):
        if fmt == "csv":
            return CSVGenerator(self.output_dir)
        elif fmt == "markdown":
            return MarkdownGenerator(self.output_dir)
        elif fmt == "excel":
            return ExcelGenerator(self.output_dir)
        else:
            raise ValueError(f"Unknown format: {fmt}")
```

### 9.2 新增解析器

只需实现新的 Parser 类并在主流程中调用即可。

---

## 10. 安全性考虑

### 10.1 路径注入

**防护：**
```python
def safe_join_path(base, *parts):
    """安全拼接路径，防止路径遍历攻击"""
    path = os.path.join(base, *parts)
    if not os.path.abspath(path).startswith(os.path.abspath(base)):
        raise ValueError("Invalid path")
    return path
```

### 10.2 资源限制

**防护：**
- 限制单个日志文件最大读取大小（避免 OOM）
- 设置超时机制

---

## 11. 文档输出

### 11.1 使用说明（README.md）

包含：
- 快速开始
- 配置说明
- 命令行参数
- 输出格式说明
- 常见问题

### 11.2 开发文档

包含：
- 架构设计（本文档）
- API 文档（自动生成）
- 贡献指南

---

## 10. 报告生成器 V2 设计（当前实现）

### 10.1 设计目标

解决原始合并报告的问题：
- ❌ 列数过多（37列），难以阅读
- ❌ Excel 需要横向滚动
- ❌ 不同类型指标混在一起

新设计目标：
- ✅ 按指标类型分离报告
- ✅ 每个报告列数合理（13-20列）
- ✅ 提供概览 Markdown 快速查看

### 10.2 类设计

```python
class ReportGeneratorV2:
    """Enhanced report generator with separated report types"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
    
    def generate_all(self, topic: str, results: List[Dict], iteration: str):
        """Generate all types of reports"""
        self.generate_latency_report(topic, results, iteration)
        self.generate_throughput_report(topic, results, iteration)
        self.generate_pps_report(topic, results, iteration)
        self.generate_resources_report(topic, results, iteration)
        self.generate_overview_markdown(topic, results, iteration)
```

### 10.3 报告类型详细设计

#### 10.3.1 延迟报告（Latency Report）

**文件名**: `{topic}_latency_{iteration}.csv`

**数据提取逻辑**：
```python
def _extract_latency_row(self, result: Dict) -> List:
    """从 result["performance"]["client"]["latency"] 提取数据"""
    # TCP RR 数据
    tcp_rr = result["performance"]["client"]["latency"]["tcp_rr"]
    tcp_comp = result["comparison"]["latency"]["tcp_rr_mean_us"]
    
    # UDP RR 数据
    udp_rr = result["performance"]["client"]["latency"]["udp_rr"]
    udp_comp = result["comparison"]["latency"]["udp_rr_mean_us"]
    
    return [
        tool_case, protocol, direction,
        tcp_rr["min_us"], tcp_rr["mean_us"], tcp_rr["max_us"],
        tcp_comp["baseline"], tcp_comp["diff_percent"],
        udp_rr["min_us"], udp_rr["mean_us"], udp_rr["max_us"],
        udp_comp["baseline"], udp_comp["diff_percent"]
    ]
```

#### 10.3.2 吞吐量报告（Throughput Report）

**文件名**: `{topic}_throughput_{iteration}.csv`

**数据提取逻辑**：
```python
def _extract_throughput_row(self, result: Dict) -> List:
    """从 result["comparison"]["throughput_client/server"] 提取数据"""
    # Client 数据
    client_single = result["comparison"]["throughput_client"]["single_gbps"]
    client_multi = result["comparison"]["throughput_client"]["multi_gbps"]
    
    # Server 数据
    server_single = result["comparison"]["throughput_server"]["single_gbps"]
    server_multi = result["comparison"]["throughput_server"]["multi_gbps"]
    
    return [
        tool_case, protocol, direction,
        client_single["ebpf"], client_single["baseline"], client_single["diff_percent"],
        client_multi["ebpf"], client_multi["baseline"], client_multi["diff_percent"],
        server_single["ebpf"], server_single["baseline"], server_single["diff_percent"],
        server_multi["ebpf"], server_multi["baseline"], server_multi["diff_percent"]
    ]
```

#### 10.3.3 PPS 报告（PPS Report）

**设计**: 与 Throughput 报告结构相同，但值为 PPS

#### 10.3.4 资源报告（Resources Report）

**文件名**: `{topic}_resources_{iteration}.csv`

**数据提取逻辑**：
```python
def _extract_resources_row(self, result: Dict) -> List:
    """从 result["resources"] 和 result["logs"] 提取数据"""
    time_range_stats = result["resources"]["time_range_stats"]
    full_cycle = result["resources"]["full_cycle"]
    log_size = result["logs"]["log_size"]
    
    return [
        tool_case, protocol, direction,
        # PPS workload
        time_range_stats["pps_single"]["cpu"]["avg_percent"],
        time_range_stats["pps_single"]["cpu"]["max_percent"],
        time_range_stats["pps_single"]["memory"]["max_rss_kb"],
        # ... 更多字段
        # Full cycle
        full_cycle["max_rss_kb"],
        full_cycle["max_vsz_kb"],
        # Log size
        log_size["final_size_bytes"],
        log_size["final_size_human"]
    ]
```

#### 10.3.5 概览报告（Overview Markdown）

**文件名**: `{topic}_overview_{iteration}.md`

**生成逻辑**：
```python
def generate_overview_markdown(self, topic, results, iteration):
    """生成概览 Markdown"""
    # 1. 统计摘要
    stats = self._calculate_summary_stats(results)
    
    # 2. 性能摘要表格（精简版）
    # 只显示 Tool Case, Protocol, Direction, 三大指标差异%
    
    # 3. 详细报告文件列表
    # 指向其他 4 个 CSV 文件
```

### 10.4 数据流程

```
analyze_performance.py (主程序)
    ↓
process_tool_case() → 生成 result 字典
    ↓
results = [result1, result2, ...] (所有 tool cases)
    ↓
根据 --report-style 参数选择：
    ├─── combined → ReportGenerator.generate()
    │    └─── 生成 37 列的合并 CSV + Markdown
    │
    ├─── separated → ReportGeneratorV2.generate_all()
    │    └─── 生成 5 个专项文件
    │
    └─── both (默认) → 两者都生成
```

### 10.5 命令行集成

在 `analyze_performance.py` 中添加参数：

```python
parser.add_argument(
    "--report-style",
    type=str,
    choices=["combined", "separated", "both"],
    default="both",
    help="Report generation style (default: both)"
)

# 使用
if args.report_style in ["combined", "both"]:
    report_gen.generate(topic, results, iteration, formats=config["output_formats"])

if args.report_style in ["separated", "both"]:
    report_gen_v2.generate_all(topic, results, iteration)
```

### 10.6 优势对比

| 特性 | 合并报告 | 分离报告 |
|------|---------|---------|
| 文件数 | 2个 | 5个 |
| CSV 列数 | 37 | 13-20 |
| Excel 适配 | ❌ 需要滚动 | ✅ 完整显示 |
| 可读性 | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| 聚焦性 | ❌ 混合 | ✅ 按类型分离 |
| 分析效率 | 低 | 高 |
| 兼容性 | ✅ 向后兼容 | - |

**推荐**: 日常分析使用分离报告，需要完整数据时使用合并报告。

---

## 11. 已实现的关键修复

### 11.1 Multi-stream Timing 格式修复

**问题**: Multi-stream throughput 的 timing 格式与 single stream 不同

**解决方案**: `src/parsers/performance_parser.py:131`

```python
# 修改前
timing = PerformanceParser._parse_timing_log(timing_path, "throughput")

# 修改后
timing = PerformanceParser._parse_timing_log(timing_path, "pps")  # Multi-stream 使用 PPS 格式
```

### 11.2 PPS Packet Size 容错

**问题**: 部分 PPS JSON 缺少 `test_start` 字段

**解决方案**: `src/parsers/performance_parser.py:163-174`

```python
packet_size = None
# 尝试 1: data["test_start"]["blksize"]
if "test_start" in data and "blksize" in data["test_start"]:
    packet_size = data["test_start"]["blksize"]
# 尝试 2: data["start"]["test_start"]["blksize"]
elif "start" in data and "test_start" in data["start"]:
    packet_size = data["start"]["test_start"]["blksize"]
# 默认值
else:
    logger.warning("Using default packet size 64 bytes")
    packet_size = 64
```

### 11.3 Multi-stream 数据累加

**实现**: `src/parsers/performance_parser.py:113-127`

```python
def parse_throughput_multi(json_paths, timing_path):
    total_bps = 0
    for json_path in json_paths:
        data = json.load(open(json_path))
        total_bps += data["end"]["sum_sent"]["bits_per_second"]
    
    throughput_gbps = total_bps / 1e9
    # 返回累加后的总吞吐量
```

---

## 12. 文档与代码对应关系

### 12.1 核心文件清单

| 文件 | 功能 | 行数 | 状态 |
|------|------|------|------|
| `analyze_performance.py` | 主程序 | ~400 | ✅ |
| `src/data_locator.py` | 数据定位 | ~350 | ✅ |
| `src/parsers/performance_parser.py` | 性能解析 | ~400 | ✅ |
| `src/parsers/resource_parser.py` | 资源监控解析 | ~200 | ✅ |
| `src/parsers/logsize_parser.py` | 日志大小解析 | ~100 | ✅ |
| `src/comparator.py` | Baseline 对比 | ~150 | ✅ |
| `src/report_generator.py` | 合并报告 | ~300 | ✅ |
| `src/report_generator_v2.py` | 分离报告 | ~500 | ✅ |
| `src/utils.py` | 工具函数 | ~200 | ✅ |

### 12.2 配置文件

| 文件 | 功能 | 状态 |
|------|------|------|
| `config.yaml` | 主配置 | ✅ |
| `.gitignore` | Git 忽略 | ✅ |

### 12.3 文档文件

| 文件 | 内容 | 状态 |
|------|------|------|
| `REQUIREMENTS.md` | 详细需求 | ✅ 已更新 |
| `DESIGN.md` | 架构设计 | ✅ 已更新 |
| `README.md` | 使用说明 | ✅ |
| `QUICKSTART.md` | 快速开始 | ✅ 已更新 |
| `FIXES_SUMMARY.md` | 修复记录 | ✅ |
| `OPTIMIZATION_SUMMARY.md` | 优化总结 | ✅ |

---

## 13. 总结

本工具采用模块化设计，各模块职责清晰：
- **数据定位**: DataLocator 自动识别测试类型和文件路径
- **数据解析**: 3 个专项 Parser 处理不同类型数据
- **数据对比**: Comparator 计算与 baseline 的差异
- **报告生成**: 双报告系统满足不同需求

**关键创新**：
1. Multi-stream 数据累加
2. PPS packet_size 容错
3. 分离报告系统

**代码质量**：
- 详细的日志输出
- 完善的容错处理
- 清晰的代码注释
- 完整的文档覆盖

工具已达到生产可用状态，可用于实际的性能分析工作。
