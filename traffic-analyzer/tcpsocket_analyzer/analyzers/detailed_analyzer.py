#!/usr/bin/env python
"""
Detailed Analyzer

Provides detailed TCP socket analysis including window, rate, retransmission,
and buffer deep-dive analysis. Implements FR-SOCKET-DET-001 through FR-SOCKET-DET-010.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict
import pandas as pd
import numpy as np

from ..models import (
    DetailedResult, SummaryResult, FiveTuple,
    WindowDetailedResult, RateDetailedResult,
    RetransDetailedResult, BufferDetailedResult,
    WindowRecoveryEvent, RetransBurstEvent,
    RateTrend
)
from .summary_analyzer import SummaryAnalyzer
from .window_analyzer import WindowAnalyzer, CWNDPatterns, WindowLimits
from .rate_analyzer import RateAnalyzer, RateTrends, RateLimits, Correlations
from ..statistics.timeseries_stats import TimeSeriesStats


@dataclass
class AnalyzerConfig:
    """Configuration for detailed analyzer"""
    export_timeseries: bool = False
    timeseries_output_path: Optional[str] = None


class DetailedAnalyzer:
    """
    Detailed mode analyzer

    Provides comprehensive analysis of:
    - Window limitation patterns and CWND dynamics
    - Rate trends and limitations
    - Retransmission burst detection
    - Buffer pressure time-series

    Implements:
    - FR-SOCKET-DET-001 through FR-SOCKET-DET-010
    """

    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.config = config or AnalyzerConfig()
        self.summary_analyzer = SummaryAnalyzer()
        self.window_analyzer = WindowAnalyzer()
        self.rate_analyzer = RateAnalyzer()
        self.stats_engine = TimeSeriesStats()

    def analyze(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame,
        aligned_df: pd.DataFrame,
        bandwidth: float,
        connection: FiveTuple
    ) -> DetailedResult:
        """
        Execute detailed mode analysis

        Implementation logic:
        1. Run Summary analysis (reuse)
        2. Deep window analysis
        3. Deep rate analysis
        4. Deep retransmission analysis
        5. Deep buffer analysis
        6. Optional: export time-series data

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame
            aligned_df: Time-aligned DataFrame
            bandwidth: Network bandwidth (bps)
            connection: TCP five-tuple

        Returns:
            DetailedResult with comprehensive analysis

        Implements: FR-SOCKET-DET-001 through FR-SOCKET-DET-010
        """
        # 1. Summary analysis (reuse)
        summary = self.summary_analyzer.analyze(
            client_df, server_df, aligned_df, bandwidth, connection
        )

        # 2. Window deep analysis
        window_detailed = self.analyze_window_detailed(client_df, bandwidth)

        # 3. Rate deep analysis
        rate_detailed = self.analyze_rate_detailed(client_df, bandwidth)

        # 4. Retransmission deep analysis
        retrans_detailed = self.analyze_retrans_detailed(client_df)

        # 5. Buffer deep analysis
        buffer_detailed = self.analyze_buffer_detailed(client_df, server_df)

        # 6. Time-series export (optional)
        timeseries_path = None
        if self.config.export_timeseries:
            timeseries_path = self.export_timeseries(aligned_df)

        return DetailedResult(
            connection=connection,
            summary=summary,
            window_detailed=window_detailed,
            rate_detailed=rate_detailed,
            retrans_detailed=retrans_detailed,
            buffer_detailed=buffer_detailed,
            timeseries_export_path=timeseries_path
        )

    def analyze_window_detailed(
        self,
        df: pd.DataFrame,
        bandwidth: float
    ) -> WindowDetailedResult:
        """
        Deep window analysis

        Implements:
        - FR-SOCKET-DET-001: Window limitation time ratio
        - FR-SOCKET-DET-002: CWND change patterns

        Args:
            df: Client DataFrame
            bandwidth: Network bandwidth

        Returns:
            WindowDetailedResult
        """
        # Window limitation ratios
        window_limits = self.window_analyzer.analyze_window_limits(df)

        # CWND patterns
        cwnd_patterns = self.window_analyzer.detect_cwnd_patterns(df)

        # Window recovery events
        recovery_events = self._detect_window_recovery_events(df)
        avg_recovery_time = self._compute_avg_recovery_time(recovery_events)

        return WindowDetailedResult(
            cwnd_limited_ratio=window_limits.cwnd_limited_ratio,
            rwnd_limited_ratio=window_limits.rwnd_limited_ratio,
            sndbuf_limited_ratio=window_limits.sndbuf_limited_ratio,
            recovery_events=recovery_events,
            avg_recovery_time=avg_recovery_time,
            slow_start_episodes=1 if cwnd_patterns.slow_start_detected else 0,
            congestion_avoidance_ratio=cwnd_patterns.congestion_avoidance_ratio
        )

    def _detect_window_recovery_events(self, df: pd.DataFrame) -> List[WindowRecoveryEvent]:
        """
        Detect window recovery events

        Algorithm:
        1. Detect CWND sudden drops (>30%)
        2. Track recovery duration
        3. Identify trigger (loss/timeout)

        Args:
            df: DataFrame with CWND values

        Returns:
            List of WindowRecoveryEvent

        Implements: FR-SOCKET-DET-002
        """
        events = []
        if 'cwnd' not in df.columns or len(df) < 2:
            return events

        cwnd_values = df['cwnd'].values
        # Use timestamp column if available, otherwise use index
        if 'timestamp' in df.columns:
            timestamps = pd.to_datetime(df['timestamp'])
        elif isinstance(df.index, pd.DatetimeIndex):
            timestamps = df.index
        else:
            # If no datetime available, return empty list
            return events

        i = 1
        while i < len(cwnd_values):
            cwnd_before = cwnd_values[i-1]
            cwnd_after = cwnd_values[i]

            # Detect CWND drop
            if cwnd_before > 0:
                drop_ratio = (cwnd_before - cwnd_after) / cwnd_before

                if drop_ratio > 0.3:  # Drop > 30%
                    # Find recovery end
                    recovery_end_idx = self._find_recovery_end(cwnd_values, i, cwnd_before)
                    recovery_duration = (timestamps.iloc[recovery_end_idx] - timestamps.iloc[i]).total_seconds()

                    # Identify trigger
                    trigger = self._identify_drop_trigger(df, i, drop_ratio)

                    events.append(WindowRecoveryEvent(
                        start_time=timestamps.iloc[i],
                        end_time=timestamps.iloc[recovery_end_idx],
                        cwnd_drop_percent=drop_ratio * 100,
                        recovery_duration=recovery_duration,
                        trigger=trigger
                    ))

                    # Skip to after recovery
                    i = recovery_end_idx

            i += 1

        return events

    def _find_recovery_end(self, cwnd_values: np.ndarray, start_idx: int, target_cwnd: float) -> int:
        """Find when CWND recovers to target level"""
        for i in range(start_idx, len(cwnd_values)):
            if cwnd_values[i] >= target_cwnd * 0.95:
                return i
        return len(cwnd_values) - 1

    def _identify_drop_trigger(self, df: pd.DataFrame, index: int, drop_ratio: float) -> str:
        """
        Identify CWND drop trigger

        Heuristics:
        - ~50% drop: Fast recovery (loss)
        - >70% drop: Timeout
        - Other: ECN or congestion avoidance
        """
        if abs(drop_ratio - 0.5) < 0.05:
            return "LOSS"
        elif drop_ratio > 0.7:
            return "TIMEOUT"
        else:
            return "ECN"

    def _compute_avg_recovery_time(self, events: List[WindowRecoveryEvent]) -> float:
        """Compute average recovery time from events"""
        if not events:
            return 0.0
        return sum(e.recovery_duration for e in events) / len(events)

    def analyze_rate_detailed(
        self,
        df: pd.DataFrame,
        bandwidth: float
    ) -> RateDetailedResult:
        """
        Deep rate analysis

        Implements:
        - FR-SOCKET-DET-003: Rate time-series analysis
        - FR-SOCKET-DET-004: Rate limitation type identification
        - FR-SOCKET-DET-010: Metric correlation analysis

        Args:
            df: Client DataFrame
            bandwidth: Network bandwidth

        Returns:
            RateDetailedResult
        """
        # Trend analysis
        pacing_trends = None
        delivery_trends = None

        if 'pacing_rate' in df.columns:
            pacing_trends = self.rate_analyzer.analyze_trends(df['pacing_rate'], 'Pacing Rate')
        if 'delivery_rate' in df.columns:
            delivery_trends = self.rate_analyzer.analyze_trends(df['delivery_rate'], 'Delivery Rate')

        # Convert to RateTrend objects
        pacing_trend = self._convert_to_rate_trend(pacing_trends, 'Pacing Rate')
        delivery_trend = self._convert_to_rate_trend(delivery_trends, 'Delivery Rate')

        # Rate limitations
        rate_limits = self.rate_analyzer.identify_rate_limits(df, bandwidth)

        # Correlations
        correlations = self.rate_analyzer.compute_correlations(df)
        correlation_dict = {
            'cwnd_delivery': correlations.cwnd_delivery_corr,
            'rtt_delivery': correlations.rtt_delivery_corr,
            'pacing_delivery': correlations.pacing_delivery_corr
        }

        return RateDetailedResult(
            pacing_rate_trend=pacing_trend,
            delivery_rate_trend=delivery_trend,
            pacing_limited_ratio=rate_limits.pacing_limited_ratio,
            network_limited_ratio=rate_limits.network_limited_ratio,
            app_limited_ratio=rate_limits.app_limited_ratio,
            correlations=correlation_dict
        )

    def _convert_to_rate_trend(self, trends: Optional[RateTrends], metric_name: str) -> RateTrend:
        """Convert RateTrends to RateTrend object"""
        if trends is None:
            return RateTrend(
                metric_name=metric_name,
                trend_type='STABLE',
                slope=0.0,
                confidence=0.0
            )

        # Determine dominant trend
        if len(trends.rising_periods) > len(trends.falling_periods):
            trend_type = 'INCREASING'
            slope = 1.0
        elif len(trends.falling_periods) > len(trends.rising_periods):
            trend_type = 'DECREASING'
            slope = -1.0
        else:
            trend_type = 'STABLE'
            slope = 0.0

        return RateTrend(
            metric_name=metric_name,
            trend_type=trend_type,
            slope=slope,
            confidence=0.8
        )

    def analyze_retrans_detailed(self, df: pd.DataFrame) -> RetransDetailedResult:
        """
        Deep retransmission analysis

        Implements:
        - FR-SOCKET-DET-005: Retransmission burst events
        - FR-SOCKET-DET-006: Spurious retransmission distribution

        Args:
            df: Client DataFrame

        Returns:
            RetransDetailedResult
        """
        # Basic aggregates (client-side)
        if 'retrans_total' in df.columns and df['retrans_total'].notna().any():
            base = df['retrans_total'].dropna()
            total_retrans = int(base.max() - base.min()) if len(base) else 0
            incr_series = base.diff().fillna(0).clip(lower=0)
        else:
            series = df['retrans'] if 'retrans' in df.columns else pd.Series([0])
            total_retrans = int(series.max()) if len(series) else 0
            incr_series = series.diff().fillna(series).clip(lower=0)

        # Rate pct over packets
        if 'data_segs_out' in df.columns and df['data_segs_out'].notna().any():
            packets_total = df['data_segs_out'].max() - df['data_segs_out'].min()
        elif 'segs_out' in df.columns and df['segs_out'].notna().any():
            packets_total = df['segs_out'].max() - df['segs_out'].min()
        else:
            packets_total = 0
        retrans_rate_pct = (total_retrans / packets_total * 100) if packets_total > 0 else 0.0

        # Bytes retrans rate
        if 'bytes_retrans' in df.columns and 'bytes_sent' in df.columns and df['bytes_sent'].max() > 0:
            bytes_retrans_rate_pct = (df['bytes_retrans'].max() - df['bytes_retrans'].min()) / df['bytes_sent'].max() * 100
        else:
            bytes_retrans_rate_pct = 0.0

        # Spurious
        spurious_count = int(df['spurious_retrans_rate'].sum()) if 'spurious_retrans_rate' in df.columns else 0
        spurious_ratio = min(1.0, spurious_count / total_retrans) if total_retrans > 0 else 0.0
        spurious_rate_stats = self.stats_engine.compute_basic_stats(
            df['spurious_retrans_rate']
        ) if 'spurious_retrans_rate' in df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        # SACK / DSACK
        sacked_packets = int(df['sacked'].max() - df['sacked'].min()) if 'sacked' in df.columns and df['sacked'].notna().any() else 0
        dsack_dups = int(df['dsack_dups'].max() - df['dsack_dups'].min()) if 'dsack_dups' in df.columns and df['dsack_dups'].notna().any() else 0

        # Detect burst events
        burst_events = self._detect_retrans_bursts(df)

        # Spurious retrans distribution (placeholder)
        spurious_distribution = {}

        # Time correlation (placeholder)
        time_correlation = 0.0

        return RetransDetailedResult(
            total_retrans=total_retrans,
            retrans_rate_pct=retrans_rate_pct,
            bytes_retrans_rate_pct=bytes_retrans_rate_pct,
            spurious_retrans_count=spurious_count,
            spurious_retrans_ratio=spurious_ratio,
            sacked_packets=sacked_packets,
            dsack_dups=dsack_dups,
            spurious_retrans_rate_stats=spurious_rate_stats,
            burst_events=burst_events,
            spurious_retrans_distribution=spurious_distribution,
            retrans_time_correlation=time_correlation
        )

    def _detect_retrans_bursts(self, df: pd.DataFrame) -> List[RetransBurstEvent]:
        """
        Detect retransmission burst events

        Args:
            df: DataFrame with retrans metrics

        Returns:
            List of RetransBurstEvent
        """
        events = []
        if 'retrans' not in df.columns or len(df) < 2:
            return events

        retrans_diff = df['retrans'].diff().fillna(0)
        burst_threshold = 5  # 5+ retransmissions in one sample

        in_burst = False
        burst_start_idx = 0
        burst_count = 0

        for i, retrans_delta in enumerate(retrans_diff):
            if retrans_delta >= burst_threshold and not in_burst:
                # Start of burst
                in_burst = True
                burst_start_idx = i
                burst_count = int(retrans_delta)
            elif retrans_delta >= burst_threshold and in_burst:
                # Continuation of burst
                burst_count += int(retrans_delta)
            elif retrans_delta < burst_threshold and in_burst:
                # End of burst
                in_burst = False
                severity = 'HIGH' if burst_count > 20 else 'MEDIUM' if burst_count > 10 else 'LOW'

                events.append(RetransBurstEvent(
                    start_time=df.index[burst_start_idx],
                    end_time=df.index[i-1],
                    retrans_count=burst_count,
                    severity=severity
                ))
                burst_count = 0

        return events

    def analyze_buffer_detailed(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> BufferDetailedResult:
        """
        Deep buffer analysis

        Implements:
        - FR-SOCKET-DET-007: Buffer pressure time-series

        Args:
            client_df: Client DataFrame
            server_df: Server DataFrame

        Returns:
            BufferDetailedResult
        """
        # Send buffer pressure series + stats
        send_pressure_series: List[float] = []
        if 'socket_tx_queue' in client_df.columns and 'socket_tx_buffer' in client_df.columns:
            send_pressure = client_df['socket_tx_queue'] / client_df['socket_tx_buffer']
            send_pressure_series = send_pressure.fillna(0).tolist()
            send_pressure_stats = self.stats_engine.compute_basic_stats(send_pressure.fillna(0))
            socket_tx_queue_stats = self.stats_engine.compute_basic_stats(client_df['socket_tx_queue'])
        else:
            send_pressure = pd.Series([0])
            send_pressure_stats = self.stats_engine.compute_basic_stats(send_pressure)
            socket_tx_queue_stats = self.stats_engine.compute_basic_stats(send_pressure)

        send_q_stats = self.stats_engine.compute_basic_stats(
            client_df['send_q']
        ) if 'send_q' in client_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        # Recv buffer pressure series + stats (server perspective)
        recv_pressure_series: List[float] = []
        if 'socket_rx_queue' in server_df.columns and 'socket_rx_buffer' in server_df.columns:
            recv_pressure = server_df['socket_rx_queue'] / server_df['socket_rx_buffer']
            recv_pressure_series = recv_pressure.fillna(0).tolist()
            recv_pressure_stats = self.stats_engine.compute_basic_stats(recv_pressure.fillna(0))
            socket_rx_queue_stats = self.stats_engine.compute_basic_stats(server_df['socket_rx_queue'])
        else:
            recv_pressure = pd.Series([0])
            recv_pressure_stats = self.stats_engine.compute_basic_stats(recv_pressure)
            socket_rx_queue_stats = self.stats_engine.compute_basic_stats(recv_pressure)

        recv_q_stats = self.stats_engine.compute_basic_stats(
            server_df['recv_q']
        ) if 'recv_q' in server_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        # High pressure ratio
        high_pressure_ratio = 0.0
        if send_pressure_series:
            high_pressure_count = sum(1 for p in send_pressure_series if p > 0.9)
            high_pressure_ratio = high_pressure_count / len(send_pressure_series)

        # Buffer exhaustion events
        exhaustion_events = sum(1 for p in send_pressure_series if p >= 0.99)

        # Additional queues/backlog/dropped (both sides)
        socket_write_queue_client = self.stats_engine.compute_basic_stats(
            client_df['socket_write_queue']
        ) if 'socket_write_queue' in client_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))
        socket_write_queue_server = self.stats_engine.compute_basic_stats(
            server_df['socket_write_queue']
        ) if 'socket_write_queue' in server_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        socket_backlog_client = self.stats_engine.compute_basic_stats(
            client_df['socket_backlog']
        ) if 'socket_backlog' in client_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))
        socket_backlog_server = self.stats_engine.compute_basic_stats(
            server_df['socket_backlog']
        ) if 'socket_backlog' in server_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        socket_dropped_client = self.stats_engine.compute_basic_stats(
            client_df['socket_dropped']
        ) if 'socket_dropped' in client_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))
        socket_dropped_server = self.stats_engine.compute_basic_stats(
            server_df['socket_dropped']
        ) if 'socket_dropped' in server_df.columns else self.stats_engine.compute_basic_stats(pd.Series([0]))

        return BufferDetailedResult(
            send_buffer_pressure_series=send_pressure_series,
            recv_buffer_pressure_series=recv_pressure_series,
            send_buffer_pressure_stats=send_pressure_stats,
            recv_buffer_pressure_stats=recv_pressure_stats,
            socket_tx_queue_stats=socket_tx_queue_stats,
            socket_rx_queue_stats=socket_rx_queue_stats,
            send_q_stats=send_q_stats,
            recv_q_stats=recv_q_stats,
            socket_write_queue_stats_client=socket_write_queue_client,
            socket_write_queue_stats_server=socket_write_queue_server,
            socket_backlog_stats_client=socket_backlog_client,
            socket_backlog_stats_server=socket_backlog_server,
            socket_dropped_stats_client=socket_dropped_client,
            socket_dropped_stats_server=socket_dropped_server,
            high_pressure_ratio=high_pressure_ratio,
            buffer_exhaustion_events=exhaustion_events
        )

    def export_timeseries(self, aligned_df: pd.DataFrame) -> Optional[str]:
        """
        Export time-series data to file

        Implements: FR-SOCKET-DET-009

        Args:
            aligned_df: Time-aligned DataFrame

        Returns:
            Path to exported file, or None if export disabled
        """
        if not self.config.export_timeseries:
            return None

        output_path = self.config.timeseries_output_path or 'timeseries_export.csv'

        # Select key metrics for export (both client and server sides)
        base_metrics = [
            'cwnd', 'ssthresh', 'rwnd', 'rtt',
            'pacing_rate', 'delivery_rate',
            'socket_tx_queue', 'socket_rx_queue',
            'retrans', 'packets_out'
        ]

        # Build export columns list (include both _client and _server variants)
        export_columns = []
        for metric in base_metrics:
            for suffix in ['_client', '_server']:
                col_name = metric + suffix
                if col_name in aligned_df.columns:
                    export_columns.append(col_name)

        # Filter available columns
        available_columns = export_columns

        if available_columns:
            export_df = aligned_df[available_columns]
            export_df.to_csv(output_path, index=True)
            print(f"INFO: Time-series data exported to: {output_path}")
            print(f"INFO: Exported {len(export_df)} samples with {len(available_columns)} metrics")
            return output_path
        else:
            print("WARNING: No time-series metrics available for export")

        return None
