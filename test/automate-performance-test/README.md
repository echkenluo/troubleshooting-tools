# Automated Performance Test Framework

eBPF 工具自动化性能测试框架，支持配置引导、工作流生成和结果分析。

## Quick Start

只需定义一个 minimal config，即可运行完整的自动化测试：

```bash
# 一步完成: bootstrap + 执行测试
python3 scripts/run_automation.py \
  --bootstrap \
  --minimal-input config/my-env/minimal-input.yaml \
  --output-dir config/my-env
```

或者分步执行：

```bash
# Step 1: Bootstrap - 生成完整配置和测试用例
python3 scripts/run_automation.py \
  --bootstrap \
  --minimal-input config/my-env/minimal-input.yaml \
  --output-dir config/my-env

# Step 2: 执行测试（单次）
python3 scripts/run_automation.py --config-dir config/my-env

# Step 3: 获取结果
python3 scripts/fetch_remote_results.py \
  --host host-server \
  --remote-path /home/user/lcc/performance-test-results \
  --local-dir ./results

# Step 4: 分析结果
python3 analysis/analyze_performance.py \
  --iteration-path ./results \
  --output-dir ./output
```

### 多轮迭代测试

使用 `scheduled_automation.py` 执行多轮测试并自动收集结果：

```bash
# 执行 3 轮迭代测试
python3 scripts/scheduled_automation.py \
  --config-dir config/my-env \
  --iterations 3 \
  --results-dir ./results

# 分析多轮结果
python3 analysis/analyze_performance.py \
  --iteration-path ./results \
  --output-dir ./output
```

**参数说明：**
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--config-dir` | 配置目录（包含 full.yaml 和 cases.json） | 必填 |
| `--iterations` | 迭代次数 | 1 |
| `--delay` | 开始前延迟秒数 | 0 |
| `--results-dir` | 本地结果存储目录 | ./results |
| `--no-cleanup` | 跳过远程清理 | false |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Automation Platform                         │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐     │
│  │ Bootstrap   │  │ Workflow     │  │ Test Executor       │     │
│  │ (配置引导)   │→ │ (工作流生成)  │→ │ (测试执行)          │     │
│  └─────────────┘  └──────────────┘  └─────────────────────┘     │
├─────────────────────────────────────────────────────────────────┤
│  ConfigLoader │ SSHManager │ RemotePathManager                  │
├─────────────────────────────────────────────────────────────────┤
│  InitHooks │ PostHooks │ RemoteEBPFMonitor                      │
├─────────────────────────────────────────────────────────────────┤
│  DataLocator │ Parsers │ ReportGenerator                        │
└─────────────────────────────────────────────────────────────────┘
```

## Workflow Pipeline

```
minimal-input.yaml (用户唯一需要提供的输入)
         │
         ▼ Bootstrap (自动发现网络配置)
<env>-full.yaml + <env>-cases.json
         │
         ▼ Workflow Generation
workflow.json
         │
         ▼ Test Execution (SSH 远程执行)
Remote: performance-test-results/
         │
         ▼ Analysis
CSV/Markdown Reports
```

### 1. Minimal Input Config

用户只需提供最基本的节点信息：

```yaml
version: "1.0"
environment: "my-env"

nodes:
  host-server:
    ssh: "user@192.168.1.100"
    workdir: "/home/user/lcc"
    role: "host"

  host-client:
    ssh: "user@192.168.1.101"
    workdir: "/home/user/lcc"
    role: "host"

  vm-server:
    ssh: "root@192.168.2.100"
    role: "vm"
    host_ref: "host-server"
    uuid: "vm-domain-uuid"
    test_ip: "192.168.2.100"

  vm-client:
    ssh: "root@192.168.2.101"
    role: "vm"
    host_ref: "host-client"
    uuid: "vm-domain-uuid"
    test_ip: "192.168.2.101"
```

### 2. Bootstrap (Auto-Discovery)

Bootstrap 自动发现网络配置：

```
ConfigBootstrap
    ├─ discover_host()  → OVS 内部接口、物理接口、测试 IP
    ├─ discover_vm()    → MAC 链: test_ip → MAC → vnet → qemu_pid → vhost_pids
    └─ generate_full_config() + generate_test_cases()
```

**生成的文件：**
- `<env>-full.yaml` - 完整配置（SSH、环境、工具、性能测试规范）
- `<env>-cases.json` - 展开后的测试用例

### 3. Tools Template (工具选择器)

`config/tools-template.yaml` 定义哪些工具参与测试（**必需**）：

```yaml
tools:
  categories:
    performance/system-network:           # 对应 measurement-tools/performance/system-network/
      environment: "host"
      directions:
        rx: {SRC_IP: "{host_REMOTE_IP}", DST_IP: "{host_LOCAL_IP}"}
        tx: {SRC_IP: "{host_LOCAL_IP}", DST_IP: "{host_REMOTE_IP}"}
      tools:
        - script: "system_network_latency_summary.py"
          template: "sudo python3 {path} --src-ip {SRC_IP} --dst-ip {DST_IP} --direction {direction} --protocol {protocol}"
          parameters:
            protocol: ["tcp", "udp"]      # 2 protocols × 2 directions = 4 test cases
```

**关键特性：**
- **显式选择器**：只有定义的工具才会生成测试用例
- **参数矩阵展开**：`itertools.product` 自动生成所有参数组合
- **Category 映射目录**：`performance/system-network` → `measurement-tools/performance/system-network/`

**当前模板覆盖的工具：**

| Category | 工具数量 |
|----------|---------|
| `performance/system-network` | 4 |
| `performance/vm-network` | 3 |
| `linux-network-stack/packet-drop` | 3 |
| `linux-network-stack` | 2 |
| `ovs` | 3 |
| `kvm-virt-network/vhost-net` | 4 |
| `kvm-virt-network/tun` | 3 |
| `kvm-virt-network/virtio-net` | 2 |
| `kvm-virt-network/kvm` | 1 |

### 4. Test Execution

分层 Hooks 执行模型：

```
Global Init Hook
│
├─ For Each Test Cycle:
│   ├─ Case Init Hook
│   │   ├─ 启动 eBPF 程序 (后台)
│   │   ├─ 启动资源监控 (CPU/Memory/LogSize)
│   │   └─ 启动性能测试基础设施 (iperf3 -s, netserver)
│   │
│   ├─ Performance Tests
│   │   ├─ Throughput (iperf3)
│   │   ├─ Latency (netperf TCP_RR/UDP_RR)
│   │   └─ PPS
│   │
│   └─ Case Post Hook
│       ├─ 停止监控和 eBPF 程序
│       └─ 收集结果
│
└─ Global Post Hook
```

### 5. Resource Monitoring

| 监控项 | 输出文件 |
|--------|----------|
| CPU 使用率 | `tool_cpu_usage_{ts}.log` |
| 内存使用 | `tool_memory_{ts}.log` |
| 日志大小 | `tool_logsize_{ts}.log` |

### 6. Result Analysis

```bash
python3 analysis/analyze_performance.py \
  --iteration-path ./results \
  --output-dir ./output
```

**输出报告：**
- `*_latency_*.csv` - 延迟数据
- `*_throughput_*.csv` - 吞吐量数据
- `*_pps_*.csv` - PPS 数据
- `*_resources_*.csv` - 资源使用数据
- `*_overview_*.md` - Markdown 概览

## Remote Storage Structure

```
{workdir}/performance-test-results/
├── baseline/{env}/{perf_type}/
│   ├─ client_results/
│   ├─ server_results/
│   └─ metadata.json
│
└── ebpf/{tool_id}_case_{id}_{hash}/{env}/{perf_type}/
    ├─ client_results/
    ├─ server_results/
    ├─ ebpf_monitoring/
    ├─ ebpf_output_{ts}.log
    └─ metadata.json
```

## Directory Structure

```
automate-performance-test/
├── config/
│   ├── tools-template.yaml           # 工具注册表 (共享)
│   ├── performance-test-template.yaml # 性能测试规范 (共享)
│   ├── minimal-input-template.yaml    # Minimal 配置模板
│   └── <environment>/                 # 环境特定配置
│       ├── minimal-input.yaml         # 用户输入
│       ├── <env>-full.yaml            # 自动生成
│       └── <env>-cases.json           # 自动生成
├── scripts/
│   ├── run_automation.py              # 主入口
│   ├── fetch_remote_results.py        # 结果获取
│   └── ...
├── src/
│   ├── config/config_bootstrap.py     # 配置引导
│   ├── core/workflow_generator.py     # 工作流生成
│   ├── core/test_executor.py          # 测试执行
│   ├── hooks/                         # 生命周期钩子
│   └── monitoring/                    # 资源监控
└── analysis/                          # 结果分析
```

## Key Design Patterns

| 模式 | 说明 |
|------|------|
| **Config Auto-Discovery** | minimal → auto-discovery → full，最小化用户输入 |
| **Tools Template as Selector** | 显式定义测试工具，而非自动扫描目录 |
| **Parameter Matrix Expansion** | `itertools.product` 自动展开参数组合 |
| **Layered Hooks** | global → tool → case → test 四级回调 |
| **Workflow/Execution Separation** | 生成 JSON 可检查，执行可重复 |
