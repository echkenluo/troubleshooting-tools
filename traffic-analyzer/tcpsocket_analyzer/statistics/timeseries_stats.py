#!/usr/bin/env python
"""
Time Series Statistics

Computes comprehensive statistics for time-series data.
Implements FR-SOCKET-SUM-002.
"""

from typing import Dict, List
import pandas as pd

from ..models import BasicStats


class TimeSeriesStats:
    """Time-series statistical analysis engine"""

    def compute_basic_stats(self, data: pd.Series) -> BasicStats:
        """
        Compute comprehensive statistics for a data series

        Statistics computed:
        - Min, Max, Mean, Std
        - CV (Coefficient of Variation)
        - P50, P95, P99 (Percentiles)

        Args:
            data: Pandas Series with numeric data

        Returns:
            BasicStats with all computed statistics

        Implements: FR-SOCKET-SUM-002
        """
        # Remove NaN values
        data_clean = data.dropna()

        # Handle empty data
        if len(data_clean) == 0:
            return BasicStats(
                min=0.0,
                max=0.0,
                mean=0.0,
                std=0.0,
                cv=0.0,
                p50=0.0,
                p95=0.0,
                p99=0.0
            )

        # Basic statistics
        min_val = float(data_clean.min())
        max_val = float(data_clean.max())
        mean_val = float(data_clean.mean())
        std_val = float(data_clean.std())

        # Coefficient of variation
        cv_val = std_val / mean_val if mean_val != 0 else 0.0

        # Percentiles
        percentiles = data_clean.quantile([0.5, 0.95, 0.99])

        return BasicStats(
            min=min_val,
            max=max_val,
            mean=mean_val,
            std=std_val,
            cv=cv_val,
            p50=float(percentiles[0.5]),
            p95=float(percentiles[0.95]),
            p99=float(percentiles[0.99])
        )

    def compute_percentiles(
        self,
        data: pd.Series,
        percentiles: List[float]
    ) -> Dict[float, float]:
        """
        Compute specific percentiles

        Args:
            data: Pandas Series with numeric data
            percentiles: List of percentile values (0-1)

        Returns:
            Dictionary mapping percentile to value
        """
        data_clean = data.dropna()

        if len(data_clean) == 0:
            return {p: 0.0 for p in percentiles}

        result = data_clean.quantile(percentiles)

        return {p: float(result[p]) for p in percentiles}

    def compute_stability_score(self, data: pd.Series) -> float:
        """
        Compute stability score based on coefficient of variation

        Score interpretation:
        - > 0.7: STABLE (CV < 0.3)
        - 0.4-0.7: MODERATE (CV 0.3-0.6)
        - < 0.4: UNSTABLE (CV > 0.6)

        Args:
            data: Pandas Series with numeric data

        Returns:
            Stability score (0-1, higher is more stable)
        """
        stats = self.compute_basic_stats(data)

        # Convert CV to stability score (inverse relationship)
        if stats.cv < 0.3:
            return 1.0 - stats.cv / 3  # 0.9-1.0
        elif stats.cv < 0.6:
            return 0.7 - (stats.cv - 0.3) / 0.3 * 0.3  # 0.4-0.7
        else:
            return max(0.0, 0.4 - (stats.cv - 0.6) / 0.4 * 0.4)  # 0.0-0.4

    def detect_trend(self, data: pd.Series, window: int = 10) -> str:
        """
        Detect trend in time-series data

        Uses rolling window slope calculation

        Args:
            data: Pandas Series with numeric data
            window: Window size for trend detection

        Returns:
            Trend type: 'INCREASING', 'DECREASING', or 'STABLE'
        """
        data_clean = data.dropna()

        if len(data_clean) < window:
            return 'STABLE'

        # Calculate rolling mean slope
        rolling_mean = data_clean.rolling(window=window).mean()
        slopes = rolling_mean.diff()

        avg_slope = slopes.mean()
        slope_std = slopes.std()

        # Threshold based on standard deviation
        threshold = slope_std * 0.5 if slope_std > 0 else abs(avg_slope) * 0.1

        if avg_slope > threshold:
            return 'INCREASING'
        elif avg_slope < -threshold:
            return 'DECREASING'
        else:
            return 'STABLE'
