# Traffic Analyzer - Claude Implementation

This directory contains the implementation of two network traffic analysis tools based on the detailed design in `docs/design/traffic-analyzer/claude/traffic-analysis-tools-design.md`.

## Architecture Overview

The implementation follows the IEEE 1016 design specification with two independent tools:

### 1. PCAP Analyzer (`pcap_analyzer.py`)
- **Purpose**: Packet-level network behavior and problem analysis
- **Modes**: Summary, Details, Analysis
- **Backend**: tshark

### 2. TCP Socket Analyzer (`tcpsocket_analyzer.py`)
- **Purpose**: Kernel socket state TCP performance bottleneck analysis
- **Modes**: Summary, Detailed, Pipeline
- **Backend**: pandas/numpy

## Directory Structure

```
traffic-analyzer-claude/
├── pcap_analyzer/              # PCAP Analyzer implementation
│   ├── models/                 # Data models (dataclasses)
│   ├── parser/                 # PCAP parser using tshark
│   ├── statistics/             # Statistical analysis engines
│   ├── analyzers/              # TCP analysis, problem detection
│   ├── filters/                # Packet filtering
│   └── formatters/             # Output formatting, progress tracking
├── tcpsocket_analyzer/         # TCP Socket Analyzer implementation
│   ├── models/                 # Data models
│   ├── parser/                 # Socket data parser (dual-side)
│   ├── statistics/             # Time series statistics
│   ├── analyzers/              # Summary, Detailed, Window, Rate analysis
│   ├── reporters/              # Pipeline reporter, recommendations
│   └── rules/                  # Bottleneck detection rules (10 rules)
├── common/                     # Shared utilities
├── pcap_analyzer.py            # CLI entry point for PCAP analyzer
├── tcpsocket_analyzer.py       # CLI entry point for Socket analyzer
└── requirements.txt            # Python dependencies
```

## Implementation Status

### Completed Components
- ✅ Directory structure
- ✅ Core data models for both tools
- ✅ PCAP Parser with tshark integration
- ✅ Requirements specification

### Remaining Implementation

#### PCAP Analyzer
1. **Statistics Components** (3-4 files, ~500 lines)
   - `statistics_engine.py`: L2/L3/L4 statistics computation
   - `flow_aggregator.py`: Five-tuple flow aggregation
   - `timeseries_analyzer.py`: Time-series analysis (pps/bps)
   - `top_talkers.py`: Top N senders/receivers identification

2. **Analysis Components** (4 files, ~800 lines)
   - `tcp_analyzer.py`: TCP deep analysis (retrans, DupACK, Zero Window, SACK)
   - `problem_detector.py`: 7 problem types detection
   - `diagnosis_engine.py`: Root cause analysis and recommendations
   - `problem_classifier.py`: Problem categorization and prioritization

3. **Supporting Components** (3 files, ~300 lines)
   - `filter_engine.py`: IP/Port/Protocol/Time filtering
   - `json_formatter.py`: JSON output formatting
   - `progress_tracker.py`: Progress bar for large files

4. **CLI Interface** (1 file, ~200 lines)
   - `pcap_analyzer.py`: CLI with argparse, mode selection

#### TCP Socket Analyzer
1. **Parser Module** (1 file, ~400 lines)
   - `socket_parser.py`: Dual-side data parsing, time alignment, connection validation

2. **Statistics Module** (1 file, ~150 lines)
   - `timeseries_stats.py`: Min/Max/Mean/Std/CV/P50/P95/P99 computation

3. **Summary Mode** (2 files, ~600 lines)
   - `summary_analyzer.py`: Window/Rate/RTT/Buffer analysis, bottleneck identification
   - `bandwidth_parser.py`: Bandwidth string parsing (Mbps, Gbps, etc.)

4. **Detailed Mode** (3 files, ~800 lines)
   - `detailed_analyzer.py`: Detailed analysis orchestrator
   - `window_analyzer.py`: CWND pattern detection, window limits
   - `rate_analyzer.py`: Rate trends, correlations

5. **Pipeline Mode** (3 files, ~1000 lines)
   - `bottleneck_finder.py`: Send/Recv path bottleneck identification
   - `bottleneck_rules.py`: 10 bottleneck detection rules
   - `pipeline_reporter.py`: Health overview, bottleneck details

6. **Recommendation Engine** (1 file, ~300 lines)
   - `recommendation_engine.py`: Configuration recommendations

7. **CLI Interface** (1 file, ~250 lines)
   - `tcpsocket_analyzer.py`: CLI with mode selection, dual-directory input

## Implementation Guidelines

### Design Principles
1. **Strict adherence to design**: Follow LLD section precisely
2. **No emojis**: Per coding guidelines
3. **English only**: No Chinese in comments/logs
4. **Error handling**: Comprehensive error messages
5. **Type hints**: Use throughout for clarity

### Coding Patterns
```python
# Dataclass for data structures
from dataclasses import dataclass

@dataclass
class AnalysisResult:
    metric: float
    status: str

# Iterator pattern for large data
def process_large_file(path: str) -> Iterator[Record]:
    for line in open(path):
        yield parse(line)

# Component composition
class Analyzer:
    def __init__(self, config):
        self.parser = Parser()
        self.stats = StatsEngine()
```

### Testing Approach
1. Unit tests for each component
2. Integration tests for end-to-end flows
3. Sample PCAP files for validation
4. Sample socket data for validation

## Quick Start (After Implementation)

### PCAP Analyzer
```bash
# Summary mode
python pcap_analyzer.py --mode summary --pcap traffic.pcap

# Details mode with filter
python pcap_analyzer.py --mode details --pcap traffic.pcap --src-ip 192.168.1.1

# Analysis mode (problem detection)
python pcap_analyzer.py --mode analysis --pcap traffic.pcap --output report.json
```

### TCP Socket Analyzer
```bash
# Summary mode
python tcpsocket_analyzer.py --mode summary \\
    --client-dir /path/to/client \\
    --server-dir /path/to/server \\
    --bandwidth 1gbps

# Detailed mode
python tcpsocket_analyzer.py --mode detailed \\
    --client-dir /path/to/client \\
    --server-dir /path/to/server \\
    --export-timeseries

# Pipeline mode (bottleneck analysis)
python tcpsocket_analyzer.py --mode pipeline \\
    --client-dir /path/to/client \\
    --server-dir /path/to/server \\
    --bandwidth 1gbps
```

## Development Workflow

1. **Implement by component**: Complete one component file at a time
2. **Follow LLD**: Each component has detailed pseudocode in design doc
3. **Test incrementally**: Test each component before moving to next
4. **Integrate gradually**: Build CLI after all components are done

## Reference Documents

- Design: `docs/design/traffic-analyzer/claude/traffic-analysis-tools-design.md`
- Requirements: `docs/prd/traffic-analyzer/claude/traffic-analysis-requirements-v3.0.md`
- Coding Guidelines: `claude_local_coding.md`
- Test Plan: `docs/design/traffic-analyzer/claude/traffic-analysis-tools-test-plan.md`

## Estimated Implementation Effort

- **PCAP Analyzer**: ~1800 lines of code, 11 files
- **TCP Socket Analyzer**: ~3500 lines of code, 13 files
- **Total**: ~5300 lines of production code
- **Testing**: ~2000 lines of test code

## Next Steps

1. Complete Statistics Components for PCAP Analyzer
2. Complete Analysis Components for PCAP Analyzer
3. Implement PCAP Analyzer CLI
4. Implement TCP Socket Analyzer (following same pattern)
5. Add comprehensive test suite
6. Create sample data and validation scripts
