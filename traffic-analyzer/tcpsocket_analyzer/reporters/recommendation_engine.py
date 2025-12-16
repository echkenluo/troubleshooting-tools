#!/usr/bin/env python
"""
Recommendation Engine

Generates optimization recommendations based on analysis results.
Implements FR-SOCKET-SUM-011, FR-SOCKET-DET-008, FR-SOCKET-PIPE-008.
"""

from typing import List
from ..models import (
    Recommendation,
    WindowAnalysisResult,
    RateAnalysisResult,
    BufferAnalysisResult,
    BottleneckIdentification,
    Bottleneck
)


class RecommendationEngine:
    """Generates actionable optimization recommendations"""

    def generate(
        self,
        window_result: WindowAnalysisResult,
        rate_result: RateAnalysisResult,
        buffer_result: BufferAnalysisResult,
        bottleneck: BottleneckIdentification
    ) -> List[Recommendation]:
        """
        Generate recommendations based on analysis results

        Args:
            window_result: Window analysis result
            rate_result: Rate analysis result
            buffer_result: Buffer analysis result
            bottleneck: Bottleneck identification

        Returns:
            List of recommendations

        Implements: FR-SOCKET-SUM-011
        """
        recommendations = []

        # CWND-based recommendations
        if bottleneck.primary_bottleneck == 'CWND_LIMITED':
            recommendations.extend(self._recommend_cwnd_tuning(window_result))

        # Buffer-based recommendations
        if bottleneck.primary_bottleneck == 'BUFFER_LIMITED':
            recommendations.extend(self._recommend_buffer_tuning(buffer_result))

        # Network-based recommendations
        if bottleneck.primary_bottleneck == 'NETWORK_LIMITED':
            recommendations.extend(self._recommend_network_tuning(rate_result))

        # Application-based recommendations
        if bottleneck.primary_bottleneck == 'APP_LIMITED':
            recommendations.extend(self._recommend_app_tuning())

        return recommendations

    def _recommend_cwnd_tuning(self, window_result: WindowAnalysisResult) -> List[Recommendation]:
        """Generate CWND tuning recommendations"""
        recommendations = []

        if window_result.cwnd_utilization > 0.9:
            recommendations.append(Recommendation(
                category='WINDOW',
                action='Increase TCP initial congestion window',
                priority='HIGH',
                description='CWND is near capacity, consider increasing initcwnd',
                expected_impact='Improve throughput by 20-40%',
                configuration_example='ip route change default via <gateway> initcwnd 20'
            ))

        if window_result.cwnd_ssthresh_ratio > 0.9:
            recommendations.append(Recommendation(
                category='WINDOW',
                action='Increase ssthresh value',
                priority='MEDIUM',
                description='CWND frequently hitting ssthresh limit',
                expected_impact='Reduce congestion control oscillations',
                configuration_example='sysctl -w net.ipv4.tcp_slow_start_after_idle=0'
            ))

        return recommendations

    def _recommend_buffer_tuning(self, buffer_result: BufferAnalysisResult) -> List[Recommendation]:
        """Generate buffer tuning recommendations"""
        recommendations = []

        if buffer_result.send_buffer_pressure > 0.8:
            recommended_size = int(buffer_result.send_buffer_size * 2)
            recommendations.append(Recommendation(
                category='BUFFER',
                action=f'Increase send buffer to {recommended_size} bytes',
                priority='CRITICAL',
                description='Send buffer is under high pressure',
                expected_impact='Eliminate send-side buffer bottleneck',
                configuration_example=f'sysctl -w net.ipv4.tcp_wmem="4096 16384 {recommended_size}"'
            ))

        if buffer_result.recv_buffer_pressure > 0.8:
            recommended_size = int(buffer_result.recv_buffer_size * 2)
            recommendations.append(Recommendation(
                category='BUFFER',
                action=f'Increase receive buffer to {recommended_size} bytes',
                priority='CRITICAL',
                description='Receive buffer is under high pressure',
                expected_impact='Eliminate receive-side buffer bottleneck',
                configuration_example=f'sysctl -w net.ipv4.tcp_rmem="4096 87380 {recommended_size}"'
            ))

        return recommendations

    def _recommend_network_tuning(self, rate_result: RateAnalysisResult) -> List[Recommendation]:
        """Generate network tuning recommendations"""
        recommendations = []

        if rate_result.avg_bandwidth_utilization > 0.9:
            recommendations.append(Recommendation(
                category='NETWORK',
                action='Upgrade network bandwidth or enable link aggregation',
                priority='HIGH',
                description='Network bandwidth is fully utilized',
                expected_impact='Eliminate network bandwidth bottleneck',
                configuration_example='Consider upgrading from 1G to 10G links'
            ))

        recommendations.append(Recommendation(
            category='RATE',
            action='Enable TCP BBR congestion control',
            priority='MEDIUM',
            description='BBR provides better throughput in high-bandwidth environments',
            expected_impact='Improve bandwidth utilization by 10-30%',
            configuration_example='sysctl -w net.ipv4.tcp_congestion_control=bbr'
        ))

        return recommendations

    def _recommend_app_tuning(self) -> List[Recommendation]:
        """Generate application tuning recommendations"""
        return [
            Recommendation(
                category='APPLICATION',
                action='Optimize application data processing',
                priority='MEDIUM',
                description='Application appears to be the limiting factor',
                expected_impact='Improve overall throughput',
                configuration_example='Profile application to identify processing bottlenecks'
            )
        ]

    def recommend_buffer_size(self, bdp: float, current_size: int) -> Recommendation:
        """
        Recommend optimal buffer size based on BDP

        Args:
            bdp: Bandwidth-Delay Product in bytes
            current_size: Current buffer size in bytes

        Returns:
            Buffer size recommendation

        Implements: FR-SOCKET-DET-008
        """
        recommended_size = int(bdp * 2)  # 2x BDP for headroom

        if recommended_size > current_size:
            priority = 'HIGH'
            description = f'Current buffer ({current_size}) is smaller than recommended'
        else:
            priority = 'LOW'
            description = f'Current buffer ({current_size}) is adequate'

        return Recommendation(
            category='BUFFER',
            action=f'Set buffer size to {recommended_size} bytes',
            priority=priority,
            description=description,
            expected_impact='Optimize buffer for current BDP',
            configuration_example=f'sysctl -w net.ipv4.tcp_wmem="4096 16384 {recommended_size}"'
        )
