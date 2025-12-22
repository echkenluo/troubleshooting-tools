# Automated Performance Test Framework

eBPF tools automated performance testing framework with configuration bootstrap, workflow generation, and result analysis.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│              Automation Platform                                 │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐    │
│  │ Bootstrap   │  │ Workflow     │  │ Test Executor       │    │
│  │ (配置引导)   │  │ (工作流生成)  │  │ (测试执行)          │    │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────────┘    │
│         └────────────────┴───────────────────┘                  │
├─────────────────────────────────────────────────────────────────┤
│           Configuration Management & SSH Layer                   │
│  ConfigLoader │ SSHManager │ RemotePathManager                  │
├─────────────────────────────────────────────────────────────────┤
│              Hooks & Monitoring Layer                            │
│  InitHooks │ PostHooks │ RemoteEBPFMonitor                      │
├─────────────────────────────────────────────────────────────────┤
│              Analysis & Reporting Layer                          │
│  DataLocator │ Parsers │ ReportGenerator                        │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
automate-performance-test/
├── config/                          # Configuration templates and examples
│   ├── minimal-input-template.yaml  # Minimal input template
│   ├── performance-test-template.yaml
│   ├── tools-template.yaml          # eBPF tools registry
│   └── <environment>/               # Environment-specific configs
│       ├── minimal-input.yaml       # User input (minimal)
│       ├── <env>-full.yaml          # Auto-generated full config
│       └── <env>-cases.json         # Auto-generated test cases
├── scripts/                         # Automation scripts
│   ├── run_automation.py            # Main entry point
│   ├── generate_workflow.py         # Workflow generation
│   ├── fetch_remote_results.py      # Results retrieval
│   ├── validate_test_results.py     # Results validation
│   └── scheduled_automation.py      # Scheduled execution
├── src/                             # Core source code
│   ├── config/                      # Configuration management
│   │   ├── config_bootstrap.py      # Auto-discovery & bootstrap
│   │   ├── case_generator.py        # Test case generation
│   │   └── tool_registry.py         # Tool registration
│   ├── core/                        # Core execution engine
│   │   ├── ssh_manager.py           # SSH connection pooling
│   │   ├── remote_path_manager.py   # Remote path management
│   │   ├── workflow_generator.py    # Workflow generation
│   │   └── test_executor.py         # Test execution engine
│   ├── hooks/                       # Lifecycle hooks
│   │   ├── init_hooks.py            # Initialization hooks
│   │   ├── post_hooks.py            # Post-processing hooks
│   │   └── custom_hooks.py          # Custom hook extensions
│   ├── monitoring/                  # Resource monitoring
│   │   └── remote_ebpf_monitor.py   # eBPF process monitoring
│   └── utils/                       # Utilities
│       ├── config_loader.py         # Configuration loading
│       └── testcase_loader.py       # Test case loading
└── analysis/                        # Result analysis
    ├── analyze_performance.py       # Main analysis script
    ├── config.yaml                  # Analysis configuration
    └── src/                         # Analysis modules
        ├── data_locator.py          # Data file locator
        ├── comparator.py            # Baseline comparison
        ├── iteration_aggregator.py  # Multi-iteration aggregation
        ├── report_generator.py      # Report generation
        └── parsers/                 # Data parsers
            ├── performance_parser.py  # Latency/Throughput/PPS
            ├── resource_parser.py     # CPU/Memory
            └── logsize_parser.py      # Log size tracking
```

## Workflow Pipeline

### Complete Pipeline

```
minimal-input.yaml (User Input)
         │
         ▼ Bootstrap (auto-discovery)
<env>-full.yaml + <env>-cases.json
         │
         ▼ Workflow Generation
workflow.json
         │
         ▼ Test Execution (SSH)
Remote: performance-test-results/
├── baseline/{env}/{type}/
└── ebpf/{tool_id}_case_{id}_{hash}/{env}/{type}/
         │
         ▼ Fetch Results
Local: results/
         │
         ▼ Analysis
CSV/Markdown Reports
```

### 1. Configuration Bootstrap

Bootstrap from minimal user input to full configuration with auto-discovery.

```
minimal-input.yaml (user provides minimal info)
         │
         ▼
ConfigBootstrap (src/config/config_bootstrap.py)
    ├─ discover_host()  → OVS internal interface, physical interface, test IP
    ├─ discover_vm()    → MAC chain: test_ip → MAC → vnet → qemu_pid → vhost_pids
    └─ generate_full_config()
         │
         ▼
<env>-full.yaml (complete configuration)
         │
         ▼
ConfigBootstrap.generate_test_cases()
    └─ Parameter matrix expansion (itertools.product)
         │
         ▼
<env>-cases.json (complete test cases)
```

**Minimal Input Example:**
```yaml
version: "1.0"
environment: "my-env"
nodes:
  host-server:
    ssh: "user@192.168.1.100"
    workdir: "/home/user/lcc"
    role: "host"
  vm-server:
    ssh: "root@192.168.2.100"
    role: "vm"
    host_ref: "host-server"
    uuid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    test_ip: "192.168.2.100"
```

### 2. Test Case Generation

Parameter matrix expansion generates all test case combinations automatically.

**Input:**
```yaml
tools:
  - script: "system_network_latency_summary.py"
    parameters:
      protocol: ["tcp", "udp"]
directions: [rx, tx]
```

**Output:** 4 test cases (2 protocols × 2 directions)
```json
[
  {"id": 1, "name": "rx_protocol_tcp", "command": "... --direction rx --protocol tcp"},
  {"id": 2, "name": "rx_protocol_udp", "command": "... --direction rx --protocol udp"},
  {"id": 3, "name": "tx_protocol_tcp", "command": "... --direction tx --protocol tcp"},
  {"id": 4, "name": "tx_protocol_udp", "command": "... --direction tx --protocol udp"}
]
```

### 3. Workflow Generation

**Generator:** `src/core/workflow_generator.py`

```
ConfigLoader.load_all_configs()
         │
         ▼
EBPFCentricWorkflowGenerator.generate_workflow_auto()
    ├─ Auto-detect format (unified/legacy)
    ├─ Generate baseline test cycles
    └─ Generate eBPF tool test cycles
         │
         ▼
workflow.json (complete workflow specification)
```

**Workflow Structure:**
```json
{
  "metadata": {
    "total_test_cycles": 50,
    "environments": ["host", "vm"]
  },
  "test_sequence": [
    {
      "cycle_id": "eth_drop_case_1_rx_tcp_host",
      "cycle_type": "ebpf_test",
      "environment": "host",
      "ebpf_case": {
        "case_id": 1,
        "tool_id": "eth_drop",
        "command": "sudo python3 ... --direction rx --protocol tcp"
      },
      "test_cycle": {
        "init_hook": {"tasks": [...], "ebpf_startup_command": "..."},
        "performance_tests": [{"type": "throughput"}, {"type": "latency"}],
        "post_hook": {"tasks": [...]}
      }
    }
  ]
}
```

### 4. Test Execution

**Executor:** `src/core/test_executor.py`

**Layered Hooks Execution:**
```
Global Init Hook (global initialization)
│
├─ For Each Test Cycle:
│   ├─ Tool Init Hook (tool initialization)
│   │
│   ├─ Case Init Hook (case initialization)
│   │   ├─ Start eBPF program (background)
│   │   ├─ Start resource monitoring (CPU/Memory/LogSize)
│   │   └─ Start performance test infrastructure (iperf3 -s, netserver)
│   │
│   ├─ Test Execution (performance tests)
│   │   ├─ Throughput tests (iperf3)
│   │   ├─ Latency tests (netperf TCP_RR/UDP_RR)
│   │   └─ PPS tests
│   │
│   ├─ Case Post Hook (case post-processing)
│   │   ├─ Stop resource monitoring
│   │   ├─ Stop eBPF program
│   │   └─ Collect results
│   │
│   └─ Tool Post Hook (tool post-processing)
│
└─ Global Post Hook (global post-processing)
```

### 5. Resource Monitoring

**Monitor:** `src/monitoring/remote_ebpf_monitor.py`

| Metric | Command | Output Format |
|--------|---------|---------------|
| CPU | `top -b -n 1 -p {PID}` | `timestamp cpu%` |
| Memory | `ps -p {PID} -o vsz,rss,pmem` | `timestamp virt rss pmem` |
| LogSize | `stat -c %s {log_file}` | `timestamp bytes` |

**Storage Path:**
```
{result_path}/ebpf_monitoring/
├── tool_cpu_usage_{timestamp}.log
├── tool_memory_{timestamp}.log
└── tool_logsize_{timestamp}.log
```

### 6. Result Analysis

**Analysis Modules:** `analysis/`

```
analysis/
├── analyze_performance.py      # Main entry
└── src/
    ├── data_locator.py         # Locate data files
    ├── parsers/
    │   ├── performance_parser.py  # Latency/Throughput/PPS
    │   ├── resource_parser.py     # CPU/Memory
    │   └── logsize_parser.py      # Log size
    ├── comparator.py           # Baseline comparison
    ├── iteration_aggregator.py # Multi-iteration aggregation
    └── report_generator.py     # Report generation
```

**Output Reports:**
- `{topic}_latency_{iteration}.csv` (13 columns)
- `{topic}_throughput_{iteration}.csv` (15 columns)
- `{topic}_pps_{iteration}.csv` (15 columns)
- `{topic}_resources_{iteration}.csv` (20 columns)
- `{topic}_overview_{iteration}.md` (Markdown overview)

## Remote Storage Structure

```
{workdir}/performance-test-results/
├── baseline/{env}/{perf_type}/{conn_type}_{timestamp}/
│   ├── client_results/
│   │   ├── latency_tcp_rr.txt
│   │   ├── latency_udp_rr.txt
│   │   ├── throughput_single_tcp.json
│   │   ├── throughput_multi_tcp_port_*.json
│   │   └── pps_*.txt
│   ├── server_results/
│   ├── monitoring/
│   └── metadata_{timestamp}.json
│
└── ebpf/{tool_id}_case_{id}_{hash}/{env}/{perf_type}/
    ├── client_results/
    ├── server_results/
    ├── monitoring/
    ├── ebpf_monitoring/
    │   ├── tool_cpu_usage_{ts}.log
    │   ├── tool_memory_{ts}.log
    │   └── tool_logsize_{ts}.log
    ├── ebpf_output_{ts}.log
    └── metadata_{ts}.json
```

## Key Design Patterns

| Pattern | Description |
|---------|-------------|
| **Layered Hooks** | global → tool → case → test four-level callbacks |
| **Workflow/Execution Separation** | Generate JSON for inspection, execution is repeatable |
| **Config Auto-Discovery** | minimal → auto-discovery → full |
| **Parameter Matrix Expansion** | itertools.product for automatic combinations |
| **Remote Path Encoding** | `{tool}_case_{id}_{hash}` self-describing paths |

## Quick Start

### 1. Bootstrap Configuration

```bash
python3 scripts/run_automation.py \
  --bootstrap \
  --minimal-input config/my-env/minimal-input.yaml \
  --output-dir config/my-env
```

**Generated files:**
- `config/my-env/my-env-full.yaml`
- `config/my-env/my-env-cases.json`

### 2. Execute Tests

```bash
python3 scripts/run_automation.py \
  --config-dir config/my-env \
  --output workflow-results.json
```

### 3. Generate Workflow Only (Dry Run)

```bash
python3 scripts/generate_workflow.py \
  --config-dir config/my-env \
  --output workflow.json \
  --pretty
```

### 4. Fetch Results

```bash
python3 scripts/fetch_remote_results.py \
  --host host-server \
  --remote-path /home/user/lcc/performance-test-results \
  --local-dir ./results
```

### 5. Analyze Results

```bash
cd analysis
python3 analyze_performance.py \
  --iteration-path ../results \
  --output-dir ./output \
  --config config.yaml
```

## Configuration Formats

### Unified Format (Recommended)

```
config/<environment>/
├── <env>-minimal.yaml   # User input
├── <env>-full.yaml      # Auto-generated
└── <env>-cases.json     # Auto-generated
```

### Legacy Format (4 Files)

```
config/<environment>/
├── ssh-config.yaml           # SSH definitions
├── test-env-config.yaml      # Environment definitions
├── performance-test-spec.yaml # Performance specifications
└── ebpf-tools-config.yaml    # Tool definitions
```

**Auto-detection:** ConfigLoader automatically detects and adapts to both formats.

## Core Modules Reference

| Module | File | Description |
|--------|------|-------------|
| ConfigBootstrap | `src/config/config_bootstrap.py` | Auto-discovery & config generation |
| CaseGenerator | `src/config/case_generator.py` | Test case matrix expansion |
| SSHManager | `src/core/ssh_manager.py` | SSH connection pooling |
| RemotePathManager | `src/core/remote_path_manager.py` | Remote path management |
| WorkflowGenerator | `src/core/workflow_generator.py` | Workflow JSON generation |
| TestExecutor | `src/core/test_executor.py` | Test execution engine |
| InitHooks | `src/hooks/init_hooks.py` | Initialization hooks |
| PostHooks | `src/hooks/post_hooks.py` | Post-processing hooks |
| RemoteEBPFMonitor | `src/monitoring/remote_ebpf_monitor.py` | Resource monitoring |
| ConfigLoader | `src/utils/config_loader.py` | Configuration loading |

## Variable Substitution

Templates support variable substitution from environment config:

```
Template:
  sudo python3 {path} --src-ip {SRC_IP} --dst-ip {DST_IP} --direction {direction}

Environment Variables:
  {host_LOCAL_IP}  → 192.168.75.101
  {host_REMOTE_IP} → 192.168.76.173
  {vm_LOCAL_IP}    → 192.168.74.221
  {vm_REMOTE_IP}   → 192.168.79.232

Direction Variables (rx):
  {SRC_IP} → {host_REMOTE_IP}
  {DST_IP} → {host_LOCAL_IP}

Final Command:
  sudo python3 ... --src-ip 192.168.76.173 --dst-ip 192.168.75.101 --direction rx
```

## Error Handling & Cleanup

The framework includes automatic cleanup on interruption:

- Signal handlers (SIGINT, SIGTERM)
- Emergency cleanup commands for remote processes
- SSH connection cleanup via atexit handlers

```python
# Emergency cleanup targets:
pkill -f "python.*ebpf-tools/performance"
pkill -f "iperf3.*-s"
pkill -f "netserver"
pkill -f "pidstat.*ebpf"
```
