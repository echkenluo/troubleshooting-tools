# Traffic Analyzer Implementation Guide

This guide provides step-by-step instructions for completing the implementation based on the design document.

## Implementation Strategy

### Phase 1: PCAP Analyzer Foundation (Current Status: ~30% Complete)

#### ✅ Completed
1. Directory structure created
2. Core data models implemented (`pcap_analyzer/models/data_models.py`)
3. PCAP Parser implemented (`pcap_analyzer/parser/pcap_parser.py`)
4. Flow Aggregator implemented (example component)

#### 🔄 In Progress / TODO

**1. Statistics Components** (`pcap_analyzer/statistics/`)

Create `statistics_engine.py`:
```python
class StatisticsEngine:
    def compute_l2_stats(self, packets: Iterator[Dict]) -> L2Stats:
        # Implement FR-PCAP-SUM-002
        # Count ethernet types, frame sizes
        # See design doc section 1.4.2

    def compute_l3_stats(self, packets: Iterator[Dict]) -> L3Stats:
        # Count IP versions, protocols

    def compute_l4_stats(self, packets: Iterator[Dict]) -> L4Stats:
        # Count TCP/UDP packets, total bytes
```

Create `timeseries_analyzer.py`:
```python
class TimeSeriesAnalyzer:
    def compute_rates(self, packets: Iterator[Dict], interval: float = 1.0) -> TimeSeriesStats:
        # Implement FR-PCAP-SUM-004
        # Time bucket aggregation
        # See design doc section 1.4.4
```

Create `top_talkers.py`:
```python
class TopTalkersAnalyzer:
    def identify_top_talkers(self, flows: Dict[FiveTuple, Flow], n: int = 10) -> TopTalkersResult:
        # Implement FR-PCAP-SUM-005
        # Rank by bytes sent/received
        # See design doc section 1.4.5
```

**2. Filter Engine** (`pcap_analyzer/filters/`)

Create `filter_engine.py`:
```python
class FilterEngine:
    def apply_ip_filter(self, packets: Iterator[Dict], src_ip: Optional[str], dst_ip: Optional[str]) -> Iterator[Dict]:
        # Implement FR-PCAP-DET-001~004
        # Filter by IP addresses
        # See design doc section 1.4.8

    def apply_port_filter(...)
    def apply_protocol_filter(...)
    def apply_time_filter(...)
```

**3. TCP Analyzer** (`pcap_analyzer/analyzers/`)

Create `tcp_analyzer.py` - This is a large file with multiple methods:
```python
class TCPAnalyzer:
    def analyze_retransmissions(self, tcp_flow: Flow) -> RetransStats:
        # Implement FR-PCAP-DET-005
        # Detect fast retrans vs timeout retrans
        # See design doc sections 1.4.9

    def analyze_dupack(self, tcp_flow: Flow) -> DupACKStats:
        # Implement FR-PCAP-DET-006
        # See design doc section 1.4.10

    def analyze_zero_window(self, tcp_flow: Flow) -> ZeroWindowStats:
        # Implement FR-PCAP-DET-007
        # See design doc section 1.4.11

    def analyze_sack(self, tcp_flow: Flow) -> SACKStats:
        # Implement FR-PCAP-DET-008
        # See design doc section 1.4.12

    def analyze_features(self, tcp_flow: Flow) -> TCPFeatures:
        # Implement FR-PCAP-DET-009
        # Parse SYN packet TCP options
        # See design doc section 1.4.13
```

**4. Problem Detection** (`pcap_analyzer/analyzers/`)

Create `problem_detector.py`:
```python
class ProblemDetector:
    def detect_all(self, tcp_flow: Flow) -> List[Problem]:
        # Implement FR-PCAP-ANA-001~007
        # Call individual detection methods
        # See design doc section 1.4.15

    def detect_high_latency(self, tcp_flow: Flow) -> Optional[Problem]:
        # RTT > 100ms threshold

    def detect_packet_loss(self, tcp_flow: Flow) -> Optional[Problem]:
        # Retrans rate > 1%

    def detect_retrans_burst(self, tcp_flow: Flow) -> List[BurstEvent]:
        # Implement FR-PCAP-DET-011
        # See design doc section 1.4.14

    # ... other detection methods
```

Create `diagnosis_engine.py`:
```python
class DiagnosisEngine:
    def analyze_causes(self, problem: Problem, tcp_flow: Flow) -> List[PossibleCause]:
        # Implement FR-PCAP-ANA-008
        # See design doc section 1.4.16

    def generate_recommendations(self, problem: Problem, causes: List[PossibleCause]) -> List[Recommendation]:
        # Implement FR-PCAP-ANA-009
        # See design doc section 1.4.17
```

Create `problem_classifier.py`:
```python
class ProblemClassifier:
    SEVERITY_PRIORITY = {
        'CRITICAL': 1,
        'HIGH': 2,
        # ...
    }

    def classify(self, problem: Problem) -> ProblemClass:
        # Implement FR-PCAP-ANA-010
        # See design doc section 1.4.18

    def rank_by_severity(self, problems: List[Problem]) -> List[Problem]:
        # Sort by priority

    def categorize(self, problems: List[Problem]) -> Dict[str, List[Problem]]:
        # Group by category
```

**5. Formatters** (`pcap_analyzer/formatters/`)

Create `json_formatter.py`:
```python
class JSONFormatter:
    def format(self, analysis_result: Any) -> str:
        # Implement FR-PCAP-SUM-006
        # Handle dataclass serialization
        # See design doc section 1.4.6

    def write_to_file(self, analysis_result: Any, output_path: str) -> None:
        pass
```

Create `progress_tracker.py`:
```python
class ProgressTracker:
    def __init__(self):
        self.total = 0
        self.current = 0
        self.start_time = None

    def update(self, current: int, total: int = None, message: str = "") -> None:
        # Implement FR-PCAP-SUM-007
        # Display progress bar
        # See design doc section 1.4.7
```

**6. CLI Entry Point** (`pcap_analyzer.py` in root)

```python
#!/usr/bin/env python
"""PCAP Analyzer CLI"""

import argparse
from pcap_analyzer.parser import PcapParser
from pcap_analyzer.statistics import StatisticsEngine, FlowAggregator
# ... other imports

def main():
    parser = argparse.ArgumentParser(description='PCAP Traffic Analyzer')
    parser.add_argument('--mode', choices=['summary', 'details', 'analysis'], required=True)
    parser.add_argument('--pcap', required=True, help='Path to PCAP file')
    parser.add_argument('--src-ip', help='Filter source IP')
    parser.add_argument('--dst-ip', help='Filter destination IP')
    parser.add_argument('--output', help='Output file (JSON format)')
    # ... more arguments

    args = parser.parse_args()

    # Mode dispatch
    if args.mode == 'summary':
        run_summary_mode(args)
    elif args.mode == 'details':
        run_details_mode(args)
    elif args.mode == 'analysis':
        run_analysis_mode(args)

def run_summary_mode(args):
    # Parse PCAP
    parser = PcapParser()
    packets = parser.parse_file(args.pcap)

    # Compute statistics
    stats_engine = StatisticsEngine()
    l2_stats = stats_engine.compute_l2_stats(packets)
    # ... more analysis

    # Format output
    if args.output:
        formatter = JSONFormatter()
        formatter.write_to_file(results, args.output)
    else:
        print_summary(results)

# ... implement other modes

if __name__ == '__main__':
    main()
```

---

### Phase 2: TCP Socket Analyzer (Status: 0% Complete)

Follow the same pattern as PCAP Analyzer. Key differences:

**1. Data Models** (`tcpsocket_analyzer/models/data_models.py`)

```python
@dataclass
class FiveTuple:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = 'TCP'

    def reverse(self) -> 'FiveTuple':
        # For matching client/server data

@dataclass
class SamplePoint:
    timestamp: datetime
    connection: FiveTuple
    state: str
    side: str  # 'client' or 'server'
    metrics: Dict[str, float]  # rtt, cwnd, ssthresh, etc.

@dataclass
class BasicStats:
    min: float
    max: float
    mean: float
    std: float
    cv: float  # Coefficient of variation
    p50: float
    p95: float
    p99: float

# ... many more dataclasses for analysis results
```

**2. Socket Parser** (`tcpsocket_analyzer/parser/socket_parser.py`)

This is THE most complex component - implements dual-side parsing:

```python
class SocketDataParser:
    def parse_dual_directories(self, client_dir: str, server_dir: str) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        # Implement FR-SOCKET-SUM-001, FR-SOCKET-SUM-014
        # Parse both sides
        # Validate connection match (five-tuple reversal)
        # Time alignment using merge_asof
        # See design doc section 2.4.1

    def _validate_connection_match(self, client_df: pd.DataFrame, server_df: pd.DataFrame) -> None:
        # Check five-tuple match

    def _align_dual_side_data(self, client_df: pd.DataFrame, server_df: pd.DataFrame, max_offset: float = 1.0) -> pd.DataFrame:
        # Use pandas merge_asof
```

**3. Summary Analyzer** (`tcpsocket_analyzer/analyzers/summary_analyzer.py`)

```python
class SummaryAnalyzer:
    def analyze(self, client_df, server_df, aligned_df, bandwidth) -> SummaryResult:
        # Orchestrate all summary analyses

    def analyze_window(self, client_df, server_df, bandwidth) -> WindowAnalysisResult:
        # Implement FR-SOCKET-SUM-003, FR-SOCKET-SUM-006
        # BDP = Bandwidth × RTT
        # Optimal CWND = BDP / MSS
        # See design doc section 2.4.3

    def analyze_rate(self, client_df, server_df, bandwidth) -> RateAnalysisResult:
        # Implement FR-SOCKET-SUM-004, FR-SOCKET-SUM-007
        # Bandwidth utilization
        # Pacing/Delivery ratio
        # See design doc section 2.4.4

    def analyze_rtt(self, client_df, server_df) -> RTTAnalysisResult:
        # Implement FR-SOCKET-SUM-005
        # CV < 0.3 → STABLE
        # See design doc section 2.4.5

    def analyze_buffer(self, client_df, server_df) -> BufferAnalysisResult:
        # Implement FR-SOCKET-SUM-009
        # Pressure = queue / buffer
        # See design doc section 2.4.9

    def identify_bottlenecks(self, window_result, rate_result, buffer_result) -> BottleneckIdentification:
        # Implement FR-SOCKET-SUM-010
        # CWND/Buffer/Network/App limited
        # See design doc section 2.4.10
```

**4. Detailed Analyzer** (`tcpsocket_analyzer/analyzers/detailed_analyzer.py`)

```python
class DetailedAnalyzer:
    def analyze(self, client_df, server_df, aligned_df, bandwidth) -> DetailedResult:
        # Reuse Summary analysis
        # Add window/rate/retrans/buffer detailed analysis

    def analyze_window_detailed(self, client_df, server_df, bandwidth) -> WindowDetailedResult:
        # Implement FR-SOCKET-DET-001
        # Window limitation time ratio
        # CWND recovery events
        # See design doc section 2.4.14

    def _detect_window_recovery_events(self, df) -> List[WindowRecoveryEvent]:
        # CWND drops > 30%
```

**5. Window Analyzer** (Helper) (`tcpsocket_analyzer/analyzers/window_analyzer.py`)

```python
class WindowAnalyzer:
    def detect_cwnd_patterns(self, df: pd.DataFrame) -> CWNDPatterns:
        # Implement FR-SOCKET-DET-002
        # Slow start, congestion avoidance, fast recovery
        # See design doc section 2.4.15

    def analyze_window_limits(self, df: pd.DataFrame) -> WindowLimits:
        # CWND/RWND/SNDBUF limited time ratio
```

**6. Rate Analyzer** (Helper) (`tcpsocket_analyzer/analyzers/rate_analyzer.py`)

```python
class RateAnalyzer:
    def analyze_trends(self, data: pd.Series, metric_name: str) -> RateTrends:
        # Implement FR-SOCKET-DET-003
        # Sliding window slope calculation
        # Identify rising/falling/stable periods
        # See design doc section 2.4.17

    def identify_rate_limits(self, df: pd.DataFrame, bandwidth: float) -> RateLimits:
        # Implement FR-SOCKET-DET-004
        # Pacing/Network/App limited

    def compute_correlations(self, df: pd.DataFrame) -> Correlations:
        # Implement FR-SOCKET-DET-010
        # Correlation matrix
```

**7. Bottleneck Finder** (`tcpsocket_analyzer/analyzers/bottleneck_finder.py`)

```python
class BottleneckFinder:
    def __init__(self):
        self.rules = [
            SendBufferLimitedRule(),
            CWNDLimitedRule(),
            # ... 10 total rules
        ]

    def find_send_path_bottlenecks(self, df: pd.DataFrame) -> List[Bottleneck]:
        # Implement FR-SOCKET-PIPE-001
        # Apply 6 send-path rules

    def find_recv_path_bottlenecks(self, df: pd.DataFrame) -> List[Bottleneck]:
        # Implement FR-SOCKET-PIPE-002
        # Apply 4 recv-path rules
```

**8. Bottleneck Rules** (`tcpsocket_analyzer/rules/bottleneck_rules.py`)

```python
class BottleneckRule(ABC):
    @abstractmethod
    def detect(self, data: pd.DataFrame) -> Optional[Bottleneck]:
        pass

class SendBufferLimitedRule(BottleneckRule):
    def detect(self, data: pd.DataFrame) -> Optional[Bottleneck]:
        # Rule 1: socket_tx_queue >= socket_tx_buffer × 95%
        # Compute pressure value
        # See design doc section 2.4.26

class CWNDLimitedRule(BottleneckRule):
    def detect(self, data: pd.DataFrame) -> Optional[Bottleneck]:
        # Rule 2: packets_out >= CWND × 95%

# ... 8 more rule classes (10 total)
```

**9. CLI Entry Point** (`tcpsocket_analyzer.py`)

```python
#!/usr/bin/env python
"""TCP Socket Analyzer CLI"""

import argparse
from tcpsocket_analyzer.parser import SocketDataParser
from tcpsocket_analyzer.analyzers import SummaryAnalyzer, DetailedAnalyzer, BottleneckFinder
# ...

def main():
    parser = argparse.ArgumentParser(description='TCP Socket Performance Analyzer')
    parser.add_argument('--mode', choices=['summary', 'detailed', 'pipeline'], required=True)
    parser.add_argument('--client-dir', required=True, help='Client data directory')
    parser.add_argument('--server-dir', required=True, help='Server data directory')
    parser.add_argument('--bandwidth', required=True, help='Bandwidth (e.g., 1gbps)')
    parser.add_argument('--export-timeseries', action='store_true')
    # ...

    args = parser.parse_args()

    # Parse dual-side data
    data_parser = SocketDataParser()
    client_df, server_df, aligned_df = data_parser.parse_dual_directories(
        args.client_dir, args.server_dir
    )

    # Parse bandwidth
    bandwidth_parser = BandwidthParser()
    bandwidth_bps = bandwidth_parser.parse(args.bandwidth)

    # Mode dispatch
    if args.mode == 'summary':
        run_summary_mode(client_df, server_df, aligned_df, bandwidth_bps)
    # ...
```

---

## Implementation Checklist

### PCAP Analyzer
- [x] Data models
- [x] PCAP Parser
- [x] Flow Aggregator
- [ ] Statistics Engine
- [ ] TimeSeriesAnalyzer
- [ ] TopTalkersAnalyzer
- [ ] FilterEngine
- [ ] TCPAnalyzer
- [ ] ProblemDetector
- [ ] DiagnosisEngine
- [ ] ProblemClassifier
- [ ] JSONFormatter
- [ ] ProgressTracker
- [ ] CLI entry point

### TCP Socket Analyzer
- [ ] Data models
- [ ] SocketDataParser
- [ ] TimeSeriesStats
- [ ] BandwidthParser
- [ ] SummaryAnalyzer
- [ ] DetailedAnalyzer
- [ ] WindowAnalyzer
- [ ] RateAnalyzer
- [ ] BottleneckFinder
- [ ] BottleneckRules (10 rules)
- [ ] PipelineReporter
- [ ] RecommendationEngine
- [ ] CLI entry point

## Testing Strategy

1. **Unit Tests**: Test each class independently
2. **Integration Tests**: Test complete analysis flows
3. **Validation**: Use sample data from `traffic-analyzer-original/`

## Estimated Timeline

- **PCAP Analyzer**: 2-3 days (11 files remaining)
- **TCP Socket Analyzer**: 4-5 days (13 files)
- **Testing & Validation**: 2-3 days
- **Total**: ~2 weeks of focused development

## Tips for Implementation

1. **Start small**: Implement one file completely before moving to next
2. **Refer to design**: Section numbers in LLD map directly to code
3. **Test incrementally**: Write simple tests as you go
4. **Use type hints**: Makes debugging easier
5. **Follow patterns**: See `flow_aggregator.py` for example structure
6. **Pandas for Socket Analyzer**: Heavy use of DataFrame operations
7. **Generators for PCAP**: Memory-efficient iteration

## Questions or Issues?

Refer to:
- Design doc for implementation details
- Requirements doc for functional requirements
- Original prototypes in `traffic-analyzer-original/` for reference
