#!/usr/bin/env python
"""
TCP Socket Analyzer Data Models

Dataclasses for all TCP socket analysis components.
Supports Summary, Detailed, and Pipeline modes.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any


@dataclass
class FiveTuple:
    """TCP five-tuple for connection identification"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = 'TCP'

    def reverse(self) -> 'FiveTuple':
        """
        Return reversed five-tuple for matching server-side data

        Returns:
            FiveTuple with source and destination swapped
        """
        return FiveTuple(
            src_ip=self.dst_ip,
            src_port=self.dst_port,
            dst_ip=self.src_ip,
            dst_port=self.src_port,
            protocol=self.protocol
        )

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


@dataclass
class SamplePoint:
    """Single sampling point data"""
    timestamp: datetime
    connection: FiveTuple
    state: str
    side: str  # 'client' or 'server'
    metrics: Dict[str, float]


@dataclass
class BasicStats:
    """Basic statistical analysis result"""
    min: float
    max: float
    mean: float
    std: float
    cv: float  # Coefficient of variation
    p50: float
    p95: float
    p99: float


@dataclass
class WindowAnalysisResult:
    """Window analysis result for Summary mode"""
    # CWND statistics
    client_cwnd_stats: BasicStats
    server_cwnd_stats: BasicStats

    # BDP and optimal CWND
    bdp: float
    optimal_cwnd: float
    actual_cwnd: float
    cwnd_utilization: float
    cwnd_ssthresh_distribution: Dict[str, float]

    # CWND adequacy distribution (per-sample analysis)
    cwnd_adequacy_distribution: Dict[str, float]  # UNDER/OVER percentages
    cwnd_total_samples: int

    # Unacked/CWND utilization distribution (per-sample analysis)
    # unacked = packets_out from ss, approximates in_flight
    # >1.0 means cwnd_limited (inflight >= cwnd)
    unacked_cwnd_distribution: Dict[str, float]  # LOW/OK/LIMITED percentages
    unacked_cwnd_limited_ratio: float  # Ratio of samples where unacked/cwnd > 1.0

    # RWND analysis
    rwnd_min: float
    rwnd_avg: float
    rwnd_limited_ratio: float

    # RWND adequacy distribution (per-sample analysis)
    rwnd_adequacy_distribution: Dict[str, float]  # UNDER/OVER percentages
    rwnd_total_samples: int

    # SSTHRESH analysis
    ssthresh_avg: float
    cwnd_ssthresh_ratio: float


@dataclass
class RateAnalysisResult:
    """Rate analysis result for Summary mode"""
    # Basic statistics
    pacing_rate_stats: BasicStats
    delivery_rate_stats: BasicStats
    send_rate_stats: Optional[BasicStats]

    # Bandwidth utilization
    avg_bandwidth_utilization: float
    peak_bandwidth_utilization: float

    # Rate relationships
    pacing_delivery_ratio: float
    rate_stability: float


@dataclass
class RTTAnalysisResult:
    """RTT analysis result (dual-side)"""
    client_rtt_stats: BasicStats
    server_rtt_stats: BasicStats
    rtt_stability: str  # STABLE/UNSTABLE/HIGHLY_VARIABLE
    jitter: float       # std dev (ms)
    rtt_trend: str      # INCREASING/DECREASING/STABLE
    rtt_diff: float
    asymmetry: str


@dataclass
class BufferAnalysisResult:
    """Buffer analysis result"""
    # Send buffer
    send_buffer_size: float
    send_queue_stats: BasicStats
    send_buffer_pressure: float

    # Receive buffer
    recv_buffer_size: float
    recv_queue_stats: BasicStats
    recv_buffer_pressure: float

    # Additional queue stats (raw send_q/recv_q)
    send_q_stats: BasicStats
    recv_q_stats: BasicStats
    write_queue_stats: BasicStats
    backlog_stats: BasicStats
    dropped_stats: BasicStats
    write_queue_stats_server: BasicStats
    backlog_stats_server: BasicStats
    dropped_stats_server: BasicStats

    # Analysis
    send_buffer_limited_ratio: float
    recv_buffer_limited_ratio: float


@dataclass
class LimitAnalysisResult:
    """Busy/limited time statistics derived directly from socket fields"""
    busy_time_stats_client: BasicStats
    busy_time_stats_server: BasicStats

    cwnd_limited_ratio_client: float
    cwnd_limited_ratio_server: float
    rwnd_limited_ratio_client: float
    rwnd_limited_ratio_server: float
    sndbuf_limited_ratio_client: float
    sndbuf_limited_ratio_server: float

    cwnd_limited_time_stats_client: BasicStats
    cwnd_limited_time_stats_server: BasicStats
    rwnd_limited_time_stats_client: BasicStats
    rwnd_limited_time_stats_server: BasicStats
    sndbuf_limited_time_stats_client: BasicStats
    sndbuf_limited_time_stats_server: BasicStats


@dataclass
class RetransAnalysisResult:
    """Retransmission analysis result"""
    client_retrans_rate_stats: BasicStats
    server_retrans_rate_stats: BasicStats
    total_retrans_client: int
    total_retrans_server: int
    retrans_rate_client: float
    retrans_rate_server: float
    retrans_bytes_rate_client: float
    retrans_bytes_rate_server: float
    spurious_retrans_count_client: int
    spurious_retrans_count_server: int
    spurious_retrans_ratio_client: float
    spurious_retrans_ratio_server: float
    sacked_packets_client: int
    sacked_packets_server: int
    dsack_dups_client: int
    dsack_dups_server: int
    spurious_retrans_rate_stats_client: BasicStats
    spurious_retrans_rate_stats_server: BasicStats


@dataclass
class BottleneckIdentification:
    """Bottleneck identification result for Summary mode"""
    primary_bottleneck: str  # CWND_LIMITED/BUFFER_LIMITED/NETWORK_LIMITED/APP_LIMITED
    bottleneck_confidence: float
    limiting_factors: List[str]


@dataclass
class SummaryResult:
    """Complete Summary mode analysis result"""
    connection: FiveTuple
    window_analysis: WindowAnalysisResult
    rate_analysis: RateAnalysisResult
    rtt_analysis: RTTAnalysisResult
    buffer_analysis: BufferAnalysisResult
    limit_analysis: LimitAnalysisResult
    retrans_analysis: RetransAnalysisResult
    bottleneck: BottleneckIdentification
    recommendations: List['Recommendation']


@dataclass
class WindowRecoveryEvent:
    """CWND recovery event"""
    start_time: datetime
    end_time: datetime
    cwnd_drop_percent: float
    recovery_duration: float
    trigger: str  # LOSS/TIMEOUT/ECN


@dataclass
class WindowDetailedResult:
    """Detailed window analysis result"""
    # Window limitation time ratios
    cwnd_limited_ratio: float
    rwnd_limited_ratio: float
    sndbuf_limited_ratio: float

    # Recovery events
    recovery_events: List[WindowRecoveryEvent]
    avg_recovery_time: float

    # Window patterns
    slow_start_episodes: int
    congestion_avoidance_ratio: float


@dataclass
class RateTrend:
    """Rate trend analysis"""
    metric_name: str
    trend_type: str  # INCREASING/DECREASING/STABLE
    slope: float
    confidence: float


@dataclass
class RateDetailedResult:
    """Detailed rate analysis result"""
    # Trends
    pacing_rate_trend: RateTrend
    delivery_rate_trend: RateTrend

    # Rate limitations
    pacing_limited_ratio: float
    network_limited_ratio: float
    app_limited_ratio: float

    # Correlations
    correlations: Dict[str, float]


@dataclass
class RetransBurstEvent:
    """Retransmission burst event"""
    start_time: datetime
    end_time: datetime
    retrans_count: int
    severity: str  # LOW/MEDIUM/HIGH


@dataclass
class RetransDetailedResult:
    """Detailed retransmission analysis"""
    total_retrans: int
    retrans_rate_pct: float
    bytes_retrans_rate_pct: float
    spurious_retrans_count: int
    spurious_retrans_ratio: float
    sacked_packets: int
    dsack_dups: int
    spurious_retrans_rate_stats: BasicStats
    burst_events: List[RetransBurstEvent]
    spurious_retrans_distribution: Dict[str, int]
    retrans_time_correlation: float


@dataclass
class BufferDetailedResult:
    """Detailed buffer analysis"""
    send_buffer_pressure_series: List[float]
    recv_buffer_pressure_series: List[float]
    send_buffer_pressure_stats: BasicStats
    recv_buffer_pressure_stats: BasicStats
    socket_tx_queue_stats: BasicStats
    socket_rx_queue_stats: BasicStats
    send_q_stats: BasicStats
    recv_q_stats: BasicStats
    socket_write_queue_stats_client: BasicStats
    socket_write_queue_stats_server: BasicStats
    socket_backlog_stats_client: BasicStats
    socket_backlog_stats_server: BasicStats
    socket_dropped_stats_client: BasicStats
    socket_dropped_stats_server: BasicStats
    high_pressure_ratio: float
    buffer_exhaustion_events: int


@dataclass
class DetailedResult:
    """Complete Detailed mode analysis result"""
    connection: FiveTuple
    summary: SummaryResult
    window_detailed: WindowDetailedResult
    rate_detailed: RateDetailedResult
    retrans_detailed: RetransDetailedResult
    buffer_detailed: BufferDetailedResult
    timeseries_export_path: Optional[str]


@dataclass
class Bottleneck:
    """Single bottleneck detection result"""
    location: str  # SEND_BUFFER/CWND/PACING_RATE/NETWORK/RWND/RECV_BUFFER/APP_SEND/APP_RECV/DELAY/OOO
    path: str  # SEND/RECV
    pressure: float  # 0-1
    severity: str  # LOW/MEDIUM/HIGH/CRITICAL
    description: str
    evidence: Dict[str, Any]


@dataclass
class BottleneckRule:
    """Bottleneck detection rule metadata"""
    rule_id: str
    name: str
    path: str  # SEND/RECV
    threshold: float
    description: str


@dataclass
class PipelineResult:
    """Complete Pipeline mode analysis result"""
    connection: FiveTuple
    send_path_bottlenecks: List[Bottleneck]
    recv_path_bottlenecks: List[Bottleneck]
    primary_bottleneck: Optional[Bottleneck]
    health_score: float  # 0-100
    optimization_priority: List[Bottleneck]
    action_plans: Optional[List[Any]] = None


@dataclass
class HealthOverview:
    """Pipeline health overview"""
    overall_health: str  # EXCELLENT/GOOD/FAIR/POOR/CRITICAL
    health_score: float  # 0-100
    bottleneck_count: int
    primary_bottleneck: Optional[str]
    summary: str


@dataclass
class BottleneckReport:
    """Detailed bottleneck report"""
    bottleneck: Bottleneck
    impact_analysis: str
    root_cause: str
    recommendations: List['Recommendation']


@dataclass
class Recommendation:
    """Optimization recommendation"""
    category: str  # BUFFER/WINDOW/RATE/APPLICATION/NETWORK
    action: str
    priority: str  # CRITICAL/HIGH/MEDIUM/LOW
    description: str
    expected_impact: str
    configuration_example: Optional[str]


@dataclass
class CWNDPattern:
    """CWND change pattern"""
    pattern_type: str  # SLOW_START/CONGESTION_AVOIDANCE/FAST_RECOVERY
    start_time: datetime
    end_time: datetime
    duration: float
    cwnd_start: float
    cwnd_end: float


@dataclass
class CWNDPatterns:
    """Collection of CWND patterns"""
    patterns: List[CWNDPattern]
    slow_start_count: int
    congestion_avoidance_count: int
    fast_recovery_count: int
    dominant_pattern: str


@dataclass
class WindowLimits:
    """Window limitation analysis"""
    cwnd_limited_ratio: float
    rwnd_limited_ratio: float
    sndbuf_limited_ratio: float
    unlimited_ratio: float


@dataclass
class RateLimits:
    """Rate limitation analysis"""
    pacing_limited_ratio: float
    network_limited_ratio: float
    app_limited_ratio: float
    unlimited_ratio: float


@dataclass
class Correlations:
    """Metric correlation analysis"""
    correlation_matrix: Dict[str, Dict[str, float]]
    strong_correlations: List[tuple]  # (metric1, metric2, correlation)
    anti_correlations: List[tuple]


@dataclass
class BufferRecommendation:
    """Buffer size recommendation"""
    current_size: int
    recommended_size: int
    justification: str
    kernel_parameter: str
    priority: str
