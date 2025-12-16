#!/usr/bin/env python
"""
Window Analyzer

Provides detailed CWND pattern analysis and window limit detection.
Implements FR-SOCKET-DET-001, FR-SOCKET-DET-002.
"""

from dataclasses import dataclass
from typing import List, Tuple
import pandas as pd
import numpy as np


@dataclass
class CWNDPatterns:
    """CWND variation patterns"""
    slow_start_detected: bool
    congestion_avoidance_ratio: float
    fast_recovery_count: int
    cwnd_growth_rate: float


@dataclass
class WindowLimits:
    """Window limitation statistics"""
    cwnd_limited_ratio: float
    rwnd_limited_ratio: float
    sndbuf_limited_ratio: float


class WindowAnalyzer:
    """
    Window analyzer for detailed CWND pattern detection

    Implements:
    - FR-SOCKET-DET-001: Window limitation time ratio analysis
    - FR-SOCKET-DET-002: CWND variation pattern detection
    """

    def detect_cwnd_patterns(self, df: pd.DataFrame) -> CWNDPatterns:
        """
        Detect CWND variation patterns

        Identifies patterns:
        1. Slow start phase: exponential CWND growth
        2. Congestion avoidance: linear CWND growth
        3. Fast recovery: CWND halving events

        Args:
            df: DataFrame with client-side metrics

        Returns:
            CWNDPatterns object with detected patterns

        Implements: FR-SOCKET-DET-002
        """
        if df.empty or 'cwnd' not in df.columns:
            return CWNDPatterns(
                slow_start_detected=False,
                congestion_avoidance_ratio=0.0,
                fast_recovery_count=0,
                cwnd_growth_rate=0.0
            )

        cwnd = df['cwnd']

        # Detect slow start
        slow_start_detected = False
        if 'ssthresh' in df.columns:
            ssthresh = df['ssthresh']
            slow_start_detected = (cwnd < ssthresh).any()
            congestion_avoidance_ratio = (cwnd >= ssthresh).sum() / len(df)
        else:
            congestion_avoidance_ratio = 0.0

        # Count fast recovery events
        fast_recovery_count = self._count_fast_recovery(df)

        # Compute CWND growth rate
        cwnd_growth_rate = self._compute_cwnd_growth_rate(df)

        return CWNDPatterns(
            slow_start_detected=slow_start_detected,
            congestion_avoidance_ratio=congestion_avoidance_ratio,
            fast_recovery_count=fast_recovery_count,
            cwnd_growth_rate=cwnd_growth_rate
        )

    def _count_fast_recovery(self, df: pd.DataFrame) -> int:
        """
        Count fast recovery events

        Fast recovery signature: CWND suddenly halves

        Args:
            df: DataFrame with CWND values

        Returns:
            Number of fast recovery events detected
        """
        count = 0
        cwnd_values = df['cwnd'].values

        for i in range(1, len(cwnd_values)):
            if cwnd_values[i-1] > 0:
                ratio = cwnd_values[i] / cwnd_values[i-1]
                # Detect ~50% drop (within 5% tolerance)
                if 0.45 < ratio < 0.55:
                    count += 1

        return count

    def _compute_cwnd_growth_rate(self, df: pd.DataFrame) -> float:
        """
        Compute CWND growth rate using linear regression

        Args:
            df: DataFrame with CWND values

        Returns:
            Growth rate (slope of linear regression)
        """
        try:
            from scipy.stats import linregress

            x = np.arange(len(df))
            y = df['cwnd'].values

            slope, _, _, _, _ = linregress(x, y)
            return slope
        except ImportError:
            # Fallback: simple rate calculation
            if len(df) > 1:
                cwnd_first = df['cwnd'].iloc[0]
                cwnd_last = df['cwnd'].iloc[-1]
                return (cwnd_last - cwnd_first) / len(df)
            return 0.0

    def analyze_window_limits(self, df: pd.DataFrame) -> WindowLimits:
        """
        Analyze window limitation time ratio

        Detection logic:
        1. CWND Limited: inflight_data >= CWND x MSS x 95%
        2. RWND Limited: inflight_data >= snd_wnd x 95%
        3. SNDBUF Limited: socket_tx_queue >= socket_tx_buffer x 95%

        Args:
            df: DataFrame with socket metrics

        Returns:
            WindowLimits object with limitation ratios

        Implements: FR-SOCKET-DET-001
        """
        # CWND Limited
        if 'packets_out' in df.columns and 'cwnd' in df.columns:
            cwnd_limited = (df['packets_out'] >= df['cwnd'] * 0.95)
            cwnd_limited_ratio = cwnd_limited.sum() / len(df) if len(df) > 0 else 0.0
        else:
            cwnd_limited_ratio = 0.0

        # RWND Limited
        if 'rwnd' in df.columns and 'cwnd' in df.columns:
            # Simplified: check if RWND is smaller than CWND
            rwnd_limited = (df['rwnd'] < df['cwnd'])
            rwnd_limited_ratio = rwnd_limited.sum() / len(df) if len(df) > 0 else 0.0
        else:
            rwnd_limited_ratio = 0.0

        # SNDBUF Limited
        if 'socket_tx_queue' in df.columns and 'socket_tx_buffer' in df.columns:
            sndbuf_limited = (df['socket_tx_queue'] >= df['socket_tx_buffer'] * 0.95)
            sndbuf_limited_ratio = sndbuf_limited.sum() / len(df) if len(df) > 0 else 0.0
        else:
            sndbuf_limited_ratio = 0.0

        return WindowLimits(
            cwnd_limited_ratio=cwnd_limited_ratio,
            rwnd_limited_ratio=rwnd_limited_ratio,
            sndbuf_limited_ratio=sndbuf_limited_ratio
        )
