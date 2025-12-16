# Performance Analysis Tool - 使用指南

## 概述

本工具用于分析 eBPF 性能测试结果，支持按主题(topic)分类分析延迟、吞吐量、PPS等性能指标。

## 目录结构

```
test/automate-performance-test/
├── iteration_001/              # 测试数据目录
│   ├── host-server/           # 主机服务端数据
│   ├── host-client/           # 主机客户端数据
│   ├── vm-server/             # 虚拟机服务端数据
│   └── vm-client/             # 虚拟机客户端数据
└── analysis/                  # 分析工具
    ├── analyze_performance.py # 主程序
    ├── config.yaml           # 默认配置
    └── src/                  # 源代码
```

## 可用的Topics

基于当前数据，支持以下5个topics：

### Host类型 (主机测试)
1. **system_network_performance** - 系统网络性能测试
   - 测试用例数: 10个
   - 测试内容: TCP/UDP的RX/TX性能

2. **linux_network_stack** - Linux网络栈测试
   - 测试内容: 内核网络栈各层性能

### VM类型 (虚拟机测试)
3. **kvm_virt_network** - KVM虚拟化网络测试
   - 测试内容: Virtio/TUN/TAP/vhost性能

4. **ovs_monitoring** - Open vSwitch监控
   - 测试内容: OVS数据平面性能

5. **vm_network_performance** - VM网络性能测试
   - 测试内容: VM端到端网络性能

## 配置数据目录

### 方法1: 修改配置文件

编辑 `config.yaml`:

```yaml
# 使用相对路径（相对于config.yaml所在目录）
data_root: ".."

# 或使用绝对路径
data_root: "/Users/echken/workspace/troubleshooting-tools/test/automate-performance-test"

# 选择要分析的iteration
selected_iteration: iteration_001
```

### 方法2: 创建自定义配置文件

```bash
# 复制默认配置
cp config.yaml config_custom.yaml

# 编辑自定义配置
vi config_custom.yaml

# 使用自定义配置运行
python3 analyze_performance.py --config config_custom.yaml
```

## 使用方法

### 基本用法

```bash
# 进入分析目录
cd /Users/echken/workspace/troubleshooting-tools/test/automate-performance-test/analysis

# 分析所有topics
python3 analyze_performance.py --iteration iteration_001

# 分析特定topic
python3 analyze_performance.py --topic system_network_performance --iteration iteration_001
```

### 常用命令示例

```bash
# 1. 分析系统网络性能（包含10个测试用例）
python3 analyze_performance.py --topic system_network_performance

# 2. 分析Linux网络栈
python3 analyze_performance.py --topic linux_network_stack

# 3. 分析KVM虚拟化网络
python3 analyze_performance.py --topic kvm_virt_network

# 4. 分析OVS监控数据
python3 analyze_performance.py --topic ovs_monitoring

# 5. 分析VM网络性能
python3 analyze_performance.py --topic vm_network_performance

# 6. 启用详细日志
python3 analyze_performance.py --topic system_network_performance --verbose

# 7. 指定输出目录
python3 analyze_performance.py --topic system_network_performance --output-dir ./my_results

# 8. 指定输出格式
python3 analyze_performance.py --topic system_network_performance --format csv,markdown

# 9. 选择报告样式
python3 analyze_performance.py --topic system_network_performance --report-style separated
```

### 命令行参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--iteration` | 指定要分析的iteration | config中的selected_iteration |
| `--topic` | 指定要分析的topic | 全部topics |
| `--config` | 配置文件路径 | config.yaml |
| `--output-dir` | 输出目录 | ./output |
| `--format` | 输出格式(csv,markdown) | csv,markdown |
| `--verbose` | 启用详细日志 | INFO级别 |
| `--report-style` | 报告样式(combined/separated/both) | both |

## 输出结果

分析完成后，结果会保存在 `output/` 目录下：

```
output/
├── system_network_performance/
│   ├── iteration_001_system_network_performance.csv
│   ├── iteration_001_system_network_performance.md
│   └── separated/                    # 分离式报告
│       ├── performance_summary.csv
│       ├── resource_summary.csv
│       └── comparison_summary.csv
└── linux_network_stack/
    └── ...
```

### 报告内容

1. **性能汇总** (Performance Summary)
   - 延迟指标: TCP/UDP RR的最小/平均/最大延迟
   - 吞吐量: 单流/多流吞吐量(Gbps)
   - PPS: 单流/多流包转发率

2. **资源使用** (Resource Usage)
   - CPU使用率
   - 内存使用情况
   - 按测试阶段关联的资源数据

3. **与基线对比** (Baseline Comparison)
   - 性能变化百分比
   - 性能退化警告(超过阈值时)

4. **日志统计** (Log Statistics)
   - eBPF工具日志大小统计

## 工作流程

```
1. 数据定位 (DataLocator)
   ↓
   根据topic查找所有测试用例
   例如: system_network_performance_case_1_tcp_rx_e5620a

2. 数据解析 (Parsers)
   ↓
   - 性能数据: latency/throughput/pps
   - 资源数据: CPU/Memory
   - 日志数据: log size

3. 基线对比 (Comparator)
   ↓
   计算与baseline的性能差异

4. 报告生成 (ReportGenerator)
   ↓
   生成CSV和Markdown格式报告
```

## 数据组织结构

每个测试用例的数据组织如下：

```
iteration_001/host-server/performance-test-results/ebpf/
└── system_network_performance_case_1_tcp_rx_e5620a/
    └── host/
        ├── server_results/
        │   ├── latency/
        │   │   ├── tcp_rr_*/latency_tcp_rr.txt
        │   │   └── udp_rr_*/latency_udp_rr.txt
        │   ├── throughput/
        │   │   ├── single_*/throughput_single_*.json
        │   │   └── multi_*/throughput_multi_*.json
        │   └── pps/
        │       ├── single_*/pps_single_*.json
        │       └── multi_*/pps_multi_*.json
        └── ebpf_monitoring/
            ├── ebpf_resource_monitor_*.log
            └── ebpf_logsize_monitor_*.log
```

## 示例: 完整分析流程

```bash
# 1. 进入分析目录
cd /Users/echken/workspace/troubleshooting-tools/test/automate-performance-test/analysis

# 2. 检查配置
cat config.yaml

# 3. 分析单个topic（快速验证）
python3 analyze_performance.py --topic system_network_performance --verbose

# 4. 查看结果
ls -la output/system_network_performance/

# 5. 查看生成的报告
cat output/system_network_performance/iteration_001_system_network_performance.md

# 6. 分析所有topics（完整分析）
python3 analyze_performance.py --iteration iteration_001

# 7. 检查日志
tail -f analysis.log
```

## 故障排查

### 问题1: 找不到数据目录

```
错误: Iteration path not found
解决: 检查config.yaml中的data_root配置是否正确
```

### 问题2: 没有找到测试用例

```
警告: No tool cases found for topic
解决: 检查topic名称是否正确，查看可用的topics列表
```

### 问题3: 解析错误

```
错误: Failed to parse performance data
解决: 使用--verbose查看详细日志，检查数据文件格式
```

## 高级用法

### 自定义阈值

编辑 `config.yaml` 中的阈值配置：

```yaml
thresholds:
  latency_degradation_percent: 5.0      # 延迟退化阈值
  throughput_degradation_percent: 5.0   # 吞吐量退化阈值
  pps_degradation_percent: 5.0          # PPS退化阈值
```

### 仅生成特定格式报告

```bash
# 仅生成CSV
python3 analyze_performance.py --format csv

# 仅生成Markdown
python3 analyze_performance.py --format markdown
```

### 批量分析多个iterations

```bash
#!/bin/bash
# 批量分析脚本
for iter in iteration_001 iteration_002 iteration_003; do
    echo "Analyzing $iter..."
    python3 analyze_performance.py --iteration $iter --output-dir "./output_$iter"
done
```

## 相关文档

- `DESIGN.md` - 架构设计文档
- `REQUIREMENTS.md` - 需求文档
- `OPTIMIZATION_SUMMARY.md` - 优化说明
