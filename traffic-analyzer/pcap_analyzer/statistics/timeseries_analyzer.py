#!/usr/bin/env python
"""
Time Series Analyzer

Computes time-dimension statistics (pps, bps) for network traffic.
Implements FR-PCAP-SUM-004.
"""

from collections import defaultdict
from typing import Iterator, Dict, List, Tuple
from datetime import datetime

from ..models import TimeSeriesStats


class TimeSeriesAnalyzer:
    """Time-series analysis for packet rates and bandwidth"""

    def compute_rates(self, packets: Iterator[Dict], interval: float = 1.0) -> TimeSeriesStats:
        """
        Compute time-series statistics (pps, bps)

        Algorithm:
        1. Bucket packets by time interval
        2. Compute pps and bps for each bucket
        3. Calculate averages and peak values

        Args:
            packets: Iterator of packet dictionaries
            interval: Time interval in seconds (default: 1.0)

        Returns:
            TimeSeriesStats with pps/bps time series and statistics
        """
        time_buckets = defaultdict(lambda: {'count': 0, 'bytes': 0})

        for packet in packets:
            timestamp = packet.get('timestamp')
            if not timestamp:
                continue

            # Get bucket key for this timestamp
            bucket_key = self._get_bucket_key(timestamp, interval)

            time_buckets[bucket_key]['count'] += 1
            time_buckets[bucket_key]['bytes'] += packet.get('frame_len', 0)

        # Generate time series data
        if not time_buckets:
            return TimeSeriesStats(
                interval=interval,
                timestamps=[],
                pps_series=[],
                bps_series=[],
                avg_pps=0.0,
                peak_pps=0.0,
                avg_bps=0.0,
                peak_bps=0.0
            )

        sorted_buckets = sorted(time_buckets.items())
        timestamps = [bucket[0] for bucket in sorted_buckets]
        pps_series = [bucket[1]['count'] / interval for bucket in sorted_buckets]
        bps_series = [bucket[1]['bytes'] * 8 / interval for bucket in sorted_buckets]

        return TimeSeriesStats(
            interval=interval,
            timestamps=timestamps,
            pps_series=pps_series,
            bps_series=bps_series,
            avg_pps=sum(pps_series) / len(pps_series) if pps_series else 0.0,
            peak_pps=max(pps_series) if pps_series else 0.0,
            avg_bps=sum(bps_series) / len(bps_series) if bps_series else 0.0,
            peak_bps=max(bps_series) if bps_series else 0.0
        )

    def get_pps(self, packets: Iterator[Dict], time_window: Tuple[datetime, datetime]) -> float:
        """
        Calculate packets per second within a specific time window

        Args:
            packets: Iterator of packet dictionaries
            time_window: Tuple of (start_time, end_time)

        Returns:
            Average packets per second
        """
        start_time, end_time = time_window
        duration = (end_time - start_time).total_seconds()

        if duration <= 0:
            return 0.0

        packet_count = 0
        for packet in packets:
            timestamp = packet.get('timestamp')
            if timestamp and start_time <= timestamp <= end_time:
                packet_count += 1

        return packet_count / duration

    def get_bps(self, packets: Iterator[Dict], time_window: Tuple[datetime, datetime]) -> float:
        """
        Calculate bits per second within a specific time window

        Args:
            packets: Iterator of packet dictionaries
            time_window: Tuple of (start_time, end_time)

        Returns:
            Average bits per second
        """
        start_time, end_time = time_window
        duration = (end_time - start_time).total_seconds()

        if duration <= 0:
            return 0.0

        total_bytes = 0
        for packet in packets:
            timestamp = packet.get('timestamp')
            if timestamp and start_time <= timestamp <= end_time:
                total_bytes += packet.get('frame_len', 0)

        return (total_bytes * 8) / duration

    def _get_bucket_key(self, timestamp: datetime, interval: float) -> datetime:
        """
        Map timestamp to time bucket

        Args:
            timestamp: Packet timestamp
            interval: Bucket interval in seconds

        Returns:
            Bucket start time as datetime
        """
        epoch = timestamp.timestamp()
        bucket_epoch = (epoch // interval) * interval
        return datetime.fromtimestamp(bucket_epoch)
