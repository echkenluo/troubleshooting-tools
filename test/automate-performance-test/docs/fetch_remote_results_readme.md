# Test Results 管理说明

## `test_results` 目录概述

`scripts/test_results/` 目录用于存储从远程主机手动获取的测试结果。这是一个**手动创建和维护**的目录，不是自动化测试框架的一部分。

## 目录结构

```
scripts/test_results/
├── fetch_summary_YYYYMMDD_HHMMSS.txt    # 获取操作的摘要信息
└── tool_XXX_case_Y/                      # 具体测试用例的结果
    └── host/                             # 主机名称
        ├── ebpf_monitoring/              # eBPF 监控数据
        │   ├── tool_memory_*.log
        │   └── tool_cpu_usage_*.log
        ├── ebpf_output_*.log             # eBPF 工具输出
        └── metadata_*.json               # 测试元数据
```

## 如何生成

### 方式 1: 使用 `fetch_remote_results.py` 脚本

这是**手动**获取远程测试结果的脚本：

```bash
cd test/automate-performance-test/

# 从指定主机获取结果
python3 scripts/fetch_remote_results.py \
    --config-dir config/phy-620 \
    --host host-server \
    --local-dir ./scripts/test_results \
    --remote-path /home/smartx/lcc/performance-test-results/ebpf/tool_001_case_1
```

**参数说明**：
- `--config-dir`: 配置目录（包含 SSH 配置）
- `--host`: 要获取结果的主机引用（如 `host-server`, `vm-server`）
- `--local-dir`: 本地存储目录（默认 `./fetched_results`）
- `--remote-path`: 远程结果路径（可选，默认获取所有结果）
- `--compress`: 是否压缩传输（可选）

**生成的文件**：
- 测试结果会复制到 `--local-dir` 指定的目录
- 创建 `fetch_summary_*.txt` 文件记录获取信息

### 方式 2: 使用 `scheduled_automation.py` 自动收集

新的调度器脚本会**自动**收集所有迭代的结果到 `results/` 目录（不是 `test_results/`）：

```bash
python3 scripts/scheduled_automation.py \
    --config-dir config/phy-620 \
    --iterations 3 \
    --results-dir ./results
```

**结果目录结构**：
```
results/
├── iteration_001/
│   ├── host-server/
│   ├── host-client/
│   ├── vm-server/
│   ├── vm-client/
│   └── collection_summary.txt
├── iteration_002/
└── iteration_003/
```

## 两种方式的区别

| 特性 | `test_results/` | `results/` |
|------|----------------|-----------|
| 生成方式 | 手动运行 `fetch_remote_results.py` | 自动由 `scheduled_automation.py` 创建 |
| 用途 | 临时获取特定测试结果 | 完整的多次迭代测试记录 |
| 组织方式 | 按测试用例组织 | 按迭代次数组织 |
| 主机覆盖 | 单个主机 | 所有主机（自动识别） |
| 维护 | 手动管理 | 自动管理和清理 |

## 维护建议

### `test_results/` 目录

这是一个**临时工作目录**，用于手动调试和分析：

**建议操作**：
1. **定期清理**：手动获取的结果使用完毕后应该删除
2. **不提交到 Git**：这个目录应该添加到 `.gitignore`
3. **按需创建**：需要时才手动运行 `fetch_remote_results.py`

**清理命令**：
```bash
# 删除旧的测试结果
rm -rf scripts/test_results/*

# 或者只保留最近的结果
cd scripts/test_results/
ls -t | tail -n +6 | xargs rm -rf  # 保留最新 5 个
```

### `results/` 目录

这是**正式的测试结果存储**，由自动化调度器管理：

**自动管理**：
- 每次迭代自动创建编号目录
- 自动从所有远程主机收集结果
- 自动生成摘要报告
- 远程结果收集后自动清理远程目录

**维护操作**：
```bash
# 查看所有迭代
ls -la results/

# 查看某次迭代的摘要
cat results/iteration_001/collection_summary.txt

# 清理旧的测试结果（根据需要）
rm -rf results/iteration_00[1-5]  # 删除前 5 次迭代
```

## Git 管理

### 应该提交的文件

- 配置文件：`config/`
- 脚本：`scripts/*.py`
- 源代码：`src/`
- 文档：`*.md`

### 不应该提交的文件

建议在 `.gitignore` 中添加：

```gitignore
# 测试结果目录
test/automate-performance-test/scripts/test_results/
test/automate-performance-test/results/
test/automate-performance-test/fetched_results/

# 生成的 workflow
test/automate-performance-test/generated_workflow.json

# 日志文件
test/automate-performance-test/*.log
test/automate-performance-test/automation_*.log

# Python 缓存
**/__pycache__/
**/*.pyc
```

## 使用场景

### 场景 1: 调试单个测试用例

使用 `fetch_remote_results.py` 手动获取：

```bash
# 1. 运行单个测试
python3 scripts/run_automation.py --config-dir config/phy-620

# 2. 手动获取特定测试结果进行分析
python3 scripts/fetch_remote_results.py \
    --config-dir config/phy-620 \
    --host host-server \
    --local-dir ./scripts/test_results \
    --remote-path /home/smartx/lcc/performance-test-results/ebpf/tool_001_case_1

# 3. 分析结果
cat scripts/test_results/tool_001_case_1/host/ebpf_output_*.log

# 4. 完成后清理
rm -rf scripts/test_results/tool_001_case_1/
```

### 场景 2: 定期自动化测试

使用 `scheduled_automation.py` 自动管理：

```bash
# 运行多次迭代并自动收集结果
python3 scripts/scheduled_automation.py \
    --config-dir config/phy-620 \
    --iterations 10 \
    --results-dir ./results

# 结果会自动保存到 results/iteration_001/ 到 results/iteration_010/
# 每次迭代后远程目录自动清理
```

### 场景 3: 压缩获取大量结果

```bash
# 使用压缩传输节省带宽和时间
python3 scripts/fetch_remote_results.py \
    --config-dir config/phy-620 \
    --host host-server \
    --local-dir ./scripts/test_results \
    --compress
```

## 查看结果示例

### 查看 CPU 使用情况
```bash
cat scripts/test_results/tool_001_case_1/host/ebpf_monitoring/tool_cpu_usage_*.log
```

### 查看内存使用情况
```bash
cat scripts/test_results/tool_001_case_1/host/ebpf_monitoring/tool_memory_*.log
```

### 查看 eBPF 工具输出
```bash
cat scripts/test_results/tool_001_case_1/host/ebpf_output_*.log
```

### 查看测试元数据
```bash
jq '.' scripts/test_results/tool_001_case_1/host/metadata_*.json
```

## 总结

- **`test_results/`**: 手动创建的临时目录，用于调试和分析特定测试
- **`results/`**: 自动化调度器创建，用于保存完整的多次迭代测试记录
- **维护原则**: `test_results/` 定期清理，`results/` 长期保存并管理
- **Git 管理**: 两个目录都应该加入 `.gitignore`，不提交到版本控制

推荐使用 `scheduled_automation.py` 进行正式测试，使用 `fetch_remote_results.py` 进行临时调试。
