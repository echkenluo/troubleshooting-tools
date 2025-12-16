# Automated eBPF Performance Testing Platform

A comprehensive automated testing platform for eBPF network performance tools, designed around eBPF-centric test cycles with complete remote execution and data collection.

## Architecture Overview

The platform follows an eBPF-centric design where each test cycle revolves around an eBPF program:

```
eBPF Case + Performance Tests = Complete Test Cycle
    ↓
1. Init: Start eBPF program + monitoring
2. Execute: All performance tests (throughput/latency/pps)
3. Post: Stop monitoring + collect data
```

## Key Features

- **eBPF-Centric Design**: Each test cycle centers around an eBPF case with complete lifecycle management
- **Complete Decoupling**: eBPF tools and performance tests are completely independent
- **Remote Execution**: All tests and monitoring execute on remote hosts with timestamped data
- **Layered Hooks**: Global/tool/case/test level hooks for flexible lifecycle management
- **Structured Storage**: Organized remote storage with clear directory encoding

## Directory Structure

```
test/automate-performance-test/
├── config/                          # Configuration files
│   ├── ssh-config.yaml             # SSH connection settings
│   ├── test-env-config.yaml        # Test environment definitions
│   ├── performance-test-spec.yaml  # Performance test specifications
│   └── ebpf-tools-config.yaml      # eBPF tools configuration
├── src/
│   ├── core/                       # Core modules
│   │   ├── ssh_manager.py          # SSH connection management
│   │   ├── remote_path_manager.py  # Remote path management
│   │   ├── workflow_generator.py   # Workflow generation
│   │   └── test_executor.py        # Test execution engine
│   ├── hooks/                      # Hook implementations
│   │   ├── init_hooks.py           # Initialization hooks
│   │   ├── post_hooks.py           # Post-processing hooks
│   │   └── custom_hooks.py         # Custom monitoring hooks
│   ├── monitoring/                 # Monitoring modules
│   │   └── remote_ebpf_monitor.py  # eBPF monitoring
│   └── utils/                      # Utility modules
│       ├── config_loader.py        # Configuration loading
│       └── testcase_loader.py      # Testcase loading
└── scripts/                        # Execution scripts
    ├── run_automation.py           # Main execution script
    ├── generate_workflow.py        # Workflow generation
    └── fetch_remote_results.py     # Result fetching
```

## Remote Storage Structure

Results are stored on remote hosts with timestamped organization:

```
{workdir}/performance-test-results/
├── baseline/                       # Baseline test results
│   └── {env}/{test_type}/{conn_type}_{timestamp}/
└── ebpf/                          # eBPF test results
    └── {tool_id}_case_{case_id}_{params_hash}/{env}/{test_type}/
        ├── client_results/
        ├── server_results/
        ├── monitoring/            # System monitoring
        ├── ebpf_monitoring/       # eBPF-specific monitoring
        └── metadata_{timestamp}.json
```

## Usage

### 1. Configure Test Environment

Edit configuration files in `config/`:

- `ssh-config.yaml`: SSH connection details
- `test-env-config.yaml`: Test environment definitions
- `performance-test-spec.yaml`: Performance test parameters
- `ebpf-tools-config.yaml`: eBPF tool definitions

### 2. Generate Workflow

```bash
cd scripts
python generate_workflow.py --config-dir ../config --output workflow.json --pretty
```

### 3. Execute Tests

```bash
# Full execution
python run_automation.py --config-dir ../config

# Specific tools/environments
python run_automation.py --tools system_network_perfomance_metrics --environments host

# Dry run (generate only)
python run_automation.py --dry-run --workflow-output test_workflow.json
```

### 4. Fetch Results

```bash
# Fetch all results from a host
python fetch_remote_results.py --host host-server --local-dir ./results

# Fetch specific path with compression
python fetch_remote_results.py --host vm-server --remote-path /root/lcc/performance-test-results/ebpf/tool_001_case_1 --compress
```

## Test Execution Flow

1. **Global Init**: Create directories, check requirements, cleanup
2. **For each eBPF case**:
   - **Tool Init**: Tool-specific setup
   - **Case Init**: Start eBPF program + monitoring
   - **Test Execution**: Run all performance tests
   - **Case Post**: Stop monitoring + eBPF program
   - **Tool Post**: Tool-specific cleanup
3. **Global Post**: Final cleanup + session summary

## Monitoring Features

- **eBPF Process Monitoring**: CPU usage, memory (VSZ/RSS), log size
- **System Monitoring**: Network stats, CPU/memory usage, disk I/O
- **Timestamped Logging**: All monitoring data includes precise timestamps
- **Lifecycle Synchronization**: Monitoring aligns with test execution

## Configuration Examples

### eBPF Tool Configuration
```yaml
ebpf_tools:
  tool_001:
    id: "system_network_perfomance_metrics"
    testcase_source:
      file: "test/workflow/case/performance-test-cases.json"
      case_ids: [1, 2, 3, 4]
    test_associations:
      applicable_environments: ["host"]
      performance_test_types: ["throughput", "latency", "pps"]
```

### Performance Test Specification
```yaml
performance_tests:
  throughput:
    single_stream:
      duration: 30
      target_bw: ["1G", "10G"]
  latency:
    duration: 20
    ports: [12865]
```

## Requirements

- Python 3.6+
- paramiko (SSH library)
- PyYAML (configuration parsing)
- Remote hosts with iperf3, netperf, and required eBPF tools

## Key Design Principles

1. **Data Collection Only**: Platform focuses on collecting data, not analysis
2. **Remote Execution**: All operations run on remote hosts, local system coordinates
3. **Complete Isolation**: Each test cycle is independent and self-contained
4. **Flexible Combinations**: Any eBPF case can combine with any performance test
5. **Structured Storage**: Clear organization enables easy data analysis