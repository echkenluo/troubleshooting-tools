# Scheduled Automation Test Runner

自动化测试调度工具，支持多次迭代执行测试并自动收集和管理结果。

## 功能特性

- ✅ **多次迭代执行**: 支持运行指定次数的自动化测试
- ✅ **定时启动**: 支持延迟指定时间后再开始执行测试
- ✅ **自动结果收集**: 每次测试完成后自动从所有远程主机收集结果
- ✅ **智能主机识别**: 自动识别并收集 VM/Host 的 server/client 所有主机的日志
- ✅ **本地结果存储**: 按迭代次数组织存储，每个迭代一个独立目录
- ✅ **自动远程清理**: 收集完成后自动删除远程 `performance-test-results` 目录
- ✅ **清理验证**: 验证远程目录已成功删除
- ✅ **压缩传输**: 自动压缩远程结果并传输到本地
- ✅ **详细日志**: 完整的执行日志和摘要报告

## 使用方法

### 基本用法

```bash
cd test/automate-performance-test/
python3 scripts/scheduled_automation.py --config-dir config/phy-620
```

### 多次迭代

运行 5 次测试：

```bash
python3 scripts/scheduled_automation.py --config-dir config/phy-620 --iterations 5
```

### 定时启动

延迟 3600 秒（1小时）后开始执行：

```bash
python3 scripts/scheduled_automation.py --config-dir config/phy-620 --iterations 3 --delay 3600
```

### 自定义结果目录

```bash
python3 scripts/scheduled_automation.py --config-dir config/phy-620 --results-dir /path/to/results
```

### 禁用远程清理

如果不想在每次迭代后删除远程结果：

```bash
python3 scripts/scheduled_automation.py --config-dir config/phy-620 --no-cleanup
```

## 参数说明

| 参数 | 必需 | 默认值 | 说明 |
|------|------|--------|------|
| `--config-dir` | 是 | - | 配置目录路径（如 `config/phy-620`） |
| `--iterations` | 否 | 1 | 测试迭代次数 |
| `--delay` | 否 | 0 | 启动前延迟时间（秒） |
| `--results-dir` | 否 | `./results` | 本地结果存储目录 |
| `--no-cleanup` | 否 | False | 禁用远程清理 |

## 结果目录结构

```
results/
├── iteration_001/
│   ├── host-server/
│   │   └── performance-test-results/
│   │       ├── baseline/
│   │       └── ebpf/
│   ├── host-client/
│   │   └── performance-test-results/
│   ├── vm-server/
│   │   └── performance-test-results/
│   ├── vm-client/
│   │   └── performance-test-results/
│   └── collection_summary.txt
├── iteration_002/
│   └── ...
├── iteration_003/
│   └── ...
├── scheduled_automation_20250120_143000.log
└── overall_summary_20250120_150000.txt
```

### 目录说明

- **iteration_NNN/**: 每次迭代的结果，按编号组织（001, 002, 003...）
- **host-server/host-client/**: 物理主机的结果
- **vm-server/vm-client/**: 虚拟机的结果
- **collection_summary.txt**: 每次迭代的收集摘要
- **scheduled_automation_*.log**: 完整执行日志
- **overall_summary_*.txt**: 所有迭代的汇总报告

## 执行流程

对于每次迭代：

1. **执行测试**: 运行 `run_automation.py` 进行完整的性能测试
2. **收集结果**: 从所有远程主机收集 `performance-test-results` 目录
   - 在远程主机上创建压缩包
   - 下载到本地对应的主机目录
   - 解压并删除压缩包
3. **远程清理**: 删除远程 `performance-test-results` 目录
4. **验证清理**: 验证目录已成功删除
5. **等待间隔**: 等待 10 秒后进入下一次迭代

## 主机识别逻辑

工具会自动从配置文件中识别所有需要收集的主机：

- 从 `test_environments` 中提取所有 `ssh_ref`
- 包括 `server.ssh_ref` 和 `client.ssh_ref`
- 包括 VM 环境的 `physical_host_ref`（物理主机）
- 自动去重，确保每个主机只收集一次

## 日志和摘要

### 执行日志
- 文件名: `scheduled_automation_YYYYMMDD_HHMMSS.log`
- 包含每次迭代的详细执行信息

### 迭代摘要
- 文件名: `collection_summary.txt`（在每个迭代目录下）
- 包含该次迭代的收集统计信息

### 总体摘要
- 文件名: `overall_summary_YYYYMMDD_HHMMSS.txt`
- 包含所有迭代的汇总信息和成功/失败状态

## 错误处理

- 如果某次测试失败，会记录错误并继续下一次迭代
- 如果结果收集失败，会记录错误但不影响下一次迭代
- 如果远程清理失败，会记录警告但继续执行
- 所有错误都会记录到日志文件中

## 后台运行

如果需要长时间运行，可以使用 `nohup` 或 `screen`：

```bash
# 使用 nohup
nohup python3 scripts/scheduled_automation.py \
    --config-dir config/phy-620 \
    --iterations 10 \
    --delay 3600 \
    > scheduler.out 2>&1 &

# 使用 screen
screen -S automation
python3 scripts/scheduled_automation.py --config-dir config/phy-620 --iterations 10
# 按 Ctrl+A, D 分离会话
```

## 注意事项

1. **磁盘空间**: 确保本地有足够空间存储所有迭代的结果
2. **网络稳定**: 结果收集依赖 SSH 连接，确保网络稳定
3. **权限要求**: 需要对远程主机有 SSH 访问权限
4. **超时设置**: 每次测试超时时间为 1 小时，如需调整请修改代码中的 `timeout` 参数
5. **迭代间隔**: 默认每次迭代之间等待 10 秒，可在代码中调整

## 故障排查

### 测试执行失败
- 检查配置文件是否正确
- 查看 `automation_*.log` 文件中的错误信息
- 验证 SSH 连接是否正常

### 结果收集失败
- 检查远程主机上是否有结果目录
- 验证 SSH 用户是否有读取权限
- 检查网络连接是否稳定

### 远程清理失败
- 检查 SSH 用户是否有删除权限
- 手动连接远程主机验证目录是否存在
- 查看详细错误信息

## 示例输出

```
================================================================================
Scheduled Automation Test Runner
================================================================================
Configuration directory: config/phy-620
Iterations: 3
Delay: 0 seconds
Results directory: /path/to/results
Remote cleanup: ENABLED
================================================================================
2025-01-20 14:30:00 - INFO - Starting automation test iteration 1
2025-01-20 14:45:00 - INFO - Iteration 1 completed successfully
2025-01-20 14:45:00 - INFO - Collecting results for iteration 1
2025-01-20 14:46:00 - INFO - Successfully collected results from host-server
2025-01-20 14:46:30 - INFO - Successfully collected results from host-client
2025-01-20 14:47:00 - INFO - Successfully collected results from vm-server
2025-01-20 14:47:30 - INFO - Successfully collected results from vm-client
2025-01-20 14:48:00 - INFO - Cleaning up remote results directories
2025-01-20 14:48:10 - INFO - Iteration 1 completed successfully
================================================================================
FINAL SUMMARY
================================================================================
Total iterations: 3
Successful: 3
Failed: 0
Start time: 2025-01-20T14:30:00
End time: 2025-01-20T15:30:00
================================================================================
```
