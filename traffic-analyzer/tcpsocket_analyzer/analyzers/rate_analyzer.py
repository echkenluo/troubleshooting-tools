#!/usr/bin/env python
"""
Rate Analyzer

Provides detailed rate trend analysis and rate limit identification.
Implements FR-SOCKET-DET-003, FR-SOCKET-DET-004, FR-SOCKET-DET-010.
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict
from datetime import datetime
import pandas as pd
import numpy as np


@dataclass
class RateTrends:
    """Rate trend analysis results"""
    rising_periods: List[Tuple[datetime, datetime]]
    falling_periods: List[Tuple[datetime, datetime]]
    stable_periods: List[Tuple[datetime, datetime]]
    volatility: float


@dataclass
class RateLimits:
    """Rate limitation types"""
    pacing_limited_ratio: float
    network_limited_ratio: float
    app_limited_ratio: float


@dataclass
class Correlations:
    """Metric correlations"""
    cwnd_delivery_corr: float
    rtt_delivery_corr: float
    pacing_delivery_corr: float


class RateAnalyzer:
    """
    Rate analyzer for detailed throughput analysis

    Implements:
    - FR-SOCKET-DET-003: Rate time-series analysis
    - FR-SOCKET-DET-004: Rate limitation type identification
    - FR-SOCKET-DET-010: Metric correlation analysis
    """

    def analyze_trends(self, data: pd.Series, metric_name: str) -> RateTrends:
        """
        Analyze rate trends

        Algorithm:
        1. Use sliding window to compute instantaneous slope
        2. Identify rising/falling/stable periods
        3. Calculate volatility (std/mean)

        Args:
            data: Time-series data
            metric_name: Name of the metric

        Returns:
            RateTrends object

        Implements: FR-SOCKET-DET-003
        """
        if data.empty or len(data) < 2:
            return RateTrends(
                rising_periods=[],
                falling_periods=[],
                stable_periods=[],
                volatility=0.0
            )

        # Compute slopes using sliding window
        window_size = min(10, len(data) // 2)
        slopes = self._compute_slopes(data, window_size)

        # Identify trend periods
        rising_periods = self._identify_periods(data.index, slopes, threshold=0.01)
        falling_periods = self._identify_periods(data.index, slopes, threshold=-0.01, falling=True)
        stable_periods = self._identify_stable_periods(data.index, slopes, threshold=0.01)

        # Calculate volatility
        volatility = data.std() / data.mean() if data.mean() != 0 else 0.0

        return RateTrends(
            rising_periods=rising_periods,
            falling_periods=falling_periods,
            stable_periods=stable_periods,
            volatility=volatility
        )

    def _compute_slopes(self, data: pd.Series, window_size: int) -> np.ndarray:
        """
        Compute slopes using sliding window

        Args:
            data: Time-series data
            window_size: Window size for slope calculation

        Returns:
            Array of slopes
        """
        slopes = []
        values = data.values

        for i in range(len(values) - window_size + 1):
            window = values[i:i+window_size]
            x = np.arange(window_size)
            # Simple slope: (last - first) / window_size
            slope = (window[-1] - window[0]) / window_size if window_size > 0 else 0
            slopes.append(slope)

        # Pad to match original length
        slopes = slopes + [slopes[-1]] * (len(values) - len(slopes))
        return np.array(slopes)

    def _identify_periods(
        self,
        timestamps: pd.Index,
        slopes: np.ndarray,
        threshold: float,
        falling: bool = False
    ) -> List[Tuple[datetime, datetime]]:
        """
        Identify rising or falling periods

        Args:
            timestamps: Timestamp index
            slopes: Slope array
            threshold: Slope threshold
            falling: If True, identify falling periods

        Returns:
            List of (start_time, end_time) tuples
        """
        periods = []
        in_period = False
        start_idx = 0

        for i, slope in enumerate(slopes):
            if falling:
                condition = slope < threshold
            else:
                condition = slope > threshold

            if condition and not in_period:
                # Start of new period
                in_period = True
                start_idx = i
            elif not condition and in_period:
                # End of period
                in_period = False
                if i > start_idx:
                    periods.append((timestamps[start_idx], timestamps[i-1]))

        # Handle period extending to end
        if in_period and len(timestamps) > start_idx:
            periods.append((timestamps[start_idx], timestamps[-1]))

        return periods

    def _identify_stable_periods(
        self,
        timestamps: pd.Index,
        slopes: np.ndarray,
        threshold: float
    ) -> List[Tuple[datetime, datetime]]:
        """
        Identify stable periods (slopes near zero)

        Args:
            timestamps: Timestamp index
            slopes: Slope array
            threshold: Slope threshold

        Returns:
            List of (start_time, end_time) tuples
        """
        periods = []
        in_period = False
        start_idx = 0

        for i, slope in enumerate(slopes):
            if abs(slope) <= threshold and not in_period:
                in_period = True
                start_idx = i
            elif abs(slope) > threshold and in_period:
                in_period = False
                if i > start_idx:
                    periods.append((timestamps[start_idx], timestamps[i-1]))

        if in_period and len(timestamps) > start_idx:
            periods.append((timestamps[start_idx], timestamps[-1]))

        return periods

    def identify_rate_limits(self, df: pd.DataFrame, bandwidth: float) -> RateLimits:
        """
        Identify rate limitation types

        Types:
        1. Pacing limited: pacing_rate < delivery_rate
        2. Network limited: delivery_rate approaches bandwidth

        Args:
            df: DataFrame with rate metrics
            bandwidth: Network bandwidth (bps)

        Returns:
            RateLimits object

        Implements: FR-SOCKET-DET-004
        """
        if df.empty:
            return RateLimits(
                pacing_limited_ratio=0.0,
                network_limited_ratio=0.0,
                app_limited_ratio=0.0
            )

        # Pacing limited
        if 'pacing_rate' in df.columns and 'delivery_rate' in df.columns:
            pacing_limited = (df['pacing_rate'] < df['delivery_rate'] * 0.95)
            pacing_limited_ratio = pacing_limited.sum() / len(df)
        else:
            pacing_limited_ratio = 0.0

        # Network limited
        if 'delivery_rate' in df.columns:
            network_limited = (df['delivery_rate'] >= bandwidth * 0.9)
            network_limited_ratio = network_limited.sum() / len(df)
        else:
            network_limited_ratio = 0.0

        # App limited: disabled (ack-driven delivery_rate causes false positives)
        app_limited_ratio = 0.0

        return RateLimits(
            pacing_limited_ratio=pacing_limited_ratio,
            network_limited_ratio=network_limited_ratio,
            app_limited_ratio=app_limited_ratio
        )

    def compute_correlations(self, df: pd.DataFrame) -> Correlations:
        """
        Compute metric correlations

        Analyzes relationships between:
        - CWND and delivery_rate
        - RTT and delivery_rate
        - pacing_rate and delivery_rate

        Args:
            df: DataFrame with metrics

        Returns:
            Correlations object

        Implements: FR-SOCKET-DET-010
        """
        cwnd_delivery_corr = 0.0
        rtt_delivery_corr = 0.0
        pacing_delivery_corr = 0.0

        if 'delivery_rate' in df.columns:
            delivery = df['delivery_rate'].dropna()

            if 'cwnd' in df.columns and len(delivery) > 0:
                cwnd = df['cwnd'].dropna()
                if len(cwnd) == len(delivery):
                    cwnd_delivery_corr = cwnd.corr(delivery)

            if 'rtt' in df.columns and len(delivery) > 0:
                rtt = df['rtt'].dropna()
                if len(rtt) == len(delivery):
                    rtt_delivery_corr = rtt.corr(delivery)

            if 'pacing_rate' in df.columns and len(delivery) > 0:
                pacing = df['pacing_rate'].dropna()
                if len(pacing) == len(delivery):
                    pacing_delivery_corr = pacing.corr(delivery)

        return Correlations(
            cwnd_delivery_corr=cwnd_delivery_corr if not np.isnan(cwnd_delivery_corr) else 0.0,
            rtt_delivery_corr=rtt_delivery_corr if not np.isnan(rtt_delivery_corr) else 0.0,
            pacing_delivery_corr=pacing_delivery_corr if not np.isnan(pacing_delivery_corr) else 0.0
        )
