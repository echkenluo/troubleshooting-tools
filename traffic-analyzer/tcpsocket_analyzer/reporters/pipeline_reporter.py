#!/usr/bin/env python
"""
Pipeline Reporter

Generates comprehensive pipeline health reports and bottleneck diagnostics.
Implements FR-SOCKET-PIPE-005, FR-SOCKET-PIPE-006.
"""

from typing import List, Optional, Dict
from ..models import (
    Bottleneck, HealthOverview, BottleneckReport,
    Recommendation, PipelineResult
)


class PipelineReporter:
    """
    Pipeline reporting engine

    Generates:
    - Health overview with scoring
    - Detailed bottleneck diagnostics
    - Optimization recommendations

    Implements:
    - FR-SOCKET-PIPE-005: Pipeline health overview
    - FR-SOCKET-PIPE-006: Bottleneck detailed diagnostics
    """

    def generate_health_overview(
        self,
        bottlenecks: List[Bottleneck],
        primary_bottleneck: Optional[Bottleneck] = None
    ) -> HealthOverview:
        """
        Generate pipeline health overview

        Health scoring:
        - No bottlenecks: 100 points
        - Each CRITICAL: -30 points
        - Each HIGH: -20 points
        - Each MEDIUM: -10 points
        - Each LOW: -5 points

        Health grade:
        - EXCELLENT: 90-100
        - GOOD: 70-89
        - FAIR: 50-69
        - POOR: 30-49
        - CRITICAL: 0-29

        Args:
            bottlenecks: List of detected bottlenecks
            primary_bottleneck: Primary bottleneck (optional)

        Returns:
            HealthOverview object

        Implements: FR-SOCKET-PIPE-005
        """
        # Count by severity
        critical_count = sum(1 for b in bottlenecks if b.severity == 'CRITICAL')
        high_count = sum(1 for b in bottlenecks if b.severity == 'HIGH')
        medium_count = sum(1 for b in bottlenecks if b.severity == 'MEDIUM')
        low_count = sum(1 for b in bottlenecks if b.severity == 'LOW')

        # Compute health score
        health_score = 100
        health_score -= critical_count * 30
        health_score -= high_count * 20
        health_score -= medium_count * 10
        health_score -= low_count * 5
        health_score = max(0, min(100, health_score))

        # Determine health grade
        if health_score >= 90:
            overall_health = 'EXCELLENT'
        elif health_score >= 70:
            overall_health = 'GOOD'
        elif health_score >= 50:
            overall_health = 'FAIR'
        elif health_score >= 30:
            overall_health = 'POOR'
        else:
            overall_health = 'CRITICAL'

        # Generate summary
        if not bottlenecks:
            summary = "No significant bottlenecks detected. Pipeline is healthy."
        elif primary_bottleneck:
            summary = f"Primary bottleneck: {primary_bottleneck.location} ({primary_bottleneck.severity}). {len(bottlenecks)} total issues."
        else:
            summary = f"{len(bottlenecks)} bottlenecks detected."

        return HealthOverview(
            overall_health=overall_health,
            health_score=health_score,
            bottleneck_count=len(bottlenecks),
            primary_bottleneck=primary_bottleneck.location if primary_bottleneck else None,
            summary=summary
        )

    def generate_bottleneck_details(
        self,
        bottleneck: Bottleneck
    ) -> BottleneckReport:
        """
        Generate detailed bottleneck diagnostic report

        Includes:
        1. Impact analysis
        2. Root cause analysis
        3. Optimization recommendations

        Args:
            bottleneck: Bottleneck to analyze

        Returns:
            BottleneckReport with detailed diagnostics

        Implements: FR-SOCKET-PIPE-006
        """
        # Impact analysis
        impact_analysis = self._assess_impact(bottleneck)

        # Root cause analysis
        root_cause = self._analyze_root_cause(bottleneck)

        # Generate recommendations
        recommendations = self._generate_recommendations(bottleneck)

        return BottleneckReport(
            bottleneck=bottleneck,
            impact_analysis=impact_analysis,
            root_cause=root_cause,
            recommendations=recommendations
        )

    def _assess_impact(self, bottleneck: Bottleneck) -> str:
        """
        Assess bottleneck impact

        Args:
            bottleneck: Bottleneck to assess

        Returns:
            Impact description
        """
        severity_impact = {
            'CRITICAL': 'Severe throughput degradation (>50% performance loss)',
            'HIGH': 'Significant throughput impact (20-50% performance loss)',
            'MEDIUM': 'Moderate throughput impact (10-20% performance loss)',
            'LOW': 'Minor throughput impact (<10% performance loss)'
        }

        base_impact = severity_impact.get(bottleneck.severity, 'Unknown impact')

        # Add location-specific impact
        if bottleneck.location == 'CWND':
            specific = ' Due to congestion control limits, expected throughput is capped.'
        elif 'BUFFER' in bottleneck.location:
            specific = ' Buffer exhaustion causes data queuing and potential drops.'
        elif bottleneck.location == 'NETWORK':
            specific = ' Network capacity limits overall throughput ceiling.'
        else:
            specific = ''

        return base_impact + specific

    def _analyze_root_cause(self, bottleneck: Bottleneck) -> str:
        """
        Analyze root cause of bottleneck

        Args:
            bottleneck: Bottleneck to analyze

        Returns:
            Root cause description
        """
        root_causes = {
            'CWND': 'Congestion window limiting send rate. Possible causes: packet loss, network congestion, or conservative congestion control algorithm.',
            'SEND_BUFFER': 'Socket send buffer full. Application sending faster than network can transmit.',
            'RECV_BUFFER': 'Socket receive buffer full. Application not reading data fast enough.',
            'RWND': 'Receiver window limiting send rate. Remote peer has insufficient receive buffer.',
            'NETWORK': 'Network bandwidth saturation. Link capacity is the bottleneck.',
            'APP_SEND': 'Application not sending data fast enough. Possible causes: slow data generation, small write() calls, or synchronous I/O.',
            'APP_RECV': 'Application not reading data fast enough. Possible causes: slow processing, small read() calls, or blocking operations.',
            'TCP_WRITE_QUEUE': 'TCP write queue backlog. Kernel unable to transmit queued data fast enough.',
        }

        return root_causes.get(bottleneck.location, bottleneck.description)

    def _generate_recommendations(self, bottleneck: Bottleneck) -> List[Recommendation]:
        """
        Generate optimization recommendations

        Args:
            bottleneck: Bottleneck to address

        Returns:
            List of Recommendation objects
        """
        recommendations = []

        # Extract recommendation from evidence if available
        if 'recommendation' in bottleneck.evidence:
            rec_text = bottleneck.evidence['recommendation']
            config_example = self._extract_config_example(rec_text)

            recommendations.append(Recommendation(
                category=self._get_category(bottleneck.location),
                action=rec_text,
                priority=bottleneck.severity,
                description=f"Address {bottleneck.location} bottleneck",
                expected_impact=self._estimate_impact(bottleneck),
                configuration_example=config_example
            ))

        # Add generic recommendations based on location
        recommendations.extend(self._get_generic_recommendations(bottleneck))

        return recommendations

    def _get_category(self, location: str) -> str:
        """Map location to recommendation category"""
        if 'BUFFER' in location:
            return 'BUFFER'
        elif location in ['CWND', 'RWND']:
            return 'WINDOW'
        elif 'APP' in location:
            return 'APPLICATION'
        elif location == 'NETWORK':
            return 'NETWORK'
        else:
            return 'RATE'

    def _estimate_impact(self, bottleneck: Bottleneck) -> str:
        """Estimate expected impact of fixing bottleneck"""
        if bottleneck.severity == 'CRITICAL':
            return 'High (30-50% throughput improvement expected)'
        elif bottleneck.severity == 'HIGH':
            return 'Medium (20-30% throughput improvement expected)'
        elif bottleneck.severity == 'MEDIUM':
            return 'Moderate (10-20% throughput improvement expected)'
        else:
            return 'Low (5-10% throughput improvement expected)'

    def _extract_config_example(self, rec_text: str) -> Optional[str]:
        """Extract configuration example from recommendation text"""
        if 'sysctl' in rec_text:
            # Find sysctl command
            start = rec_text.find('sysctl')
            if start != -1:
                end = rec_text.find('\n', start)
                if end == -1:
                    end = len(rec_text)
                return rec_text[start:end].strip()
        return None

    def _get_generic_recommendations(self, bottleneck: Bottleneck) -> List[Recommendation]:
        """Get generic recommendations based on bottleneck type"""
        recommendations = []

        if bottleneck.location == 'CWND':
            recommendations.append(Recommendation(
                category='WINDOW',
                action='Monitor packet loss and RTT',
                priority='MEDIUM',
                description='Investigate network path quality',
                expected_impact='Medium',
                configuration_example='tcpdump -i eth0 -w capture.pcap'
            ))

        elif 'APP' in bottleneck.location:
            recommendations.append(Recommendation(
                category='APPLICATION',
                action='Profile application I/O performance',
                priority='HIGH',
                description='Optimize application read/write patterns',
                expected_impact='Medium to High',
                configuration_example=None
            ))

        return recommendations

    def generate_full_report(self, result: PipelineResult) -> str:
        """
        Generate complete pipeline analysis report

        Args:
            result: PipelineResult object

        Returns:
            Formatted report string
        """
        lines = []
        lines.append("=" * 70)
        lines.append("TCP PIPELINE BOTTLENECK ANALYSIS")
        lines.append("=" * 70)
        lines.append("")

        # Connection info
        lines.append(f"Connection: {result.connection}")
        lines.append("")

        # Health overview
        health = self.generate_health_overview(
            result.send_path_bottlenecks + result.recv_path_bottlenecks,
            result.primary_bottleneck
        )
        lines.append(f"Overall Health: {health.overall_health} (Score: {health.health_score}/100)")
        lines.append(f"Bottlenecks Found: {health.bottleneck_count}")
        lines.append("")

        # Primary bottleneck
        if result.primary_bottleneck:
            lines.append("=== PRIMARY BOTTLENECK ===")
            report = self.generate_bottleneck_details(result.primary_bottleneck)
            lines.append(f"Location: {report.bottleneck.location}")
            lines.append(f"Severity: {report.bottleneck.severity}")
            lines.append(f"Pressure: {report.bottleneck.pressure*100:.1f}%")
            lines.append(f"Impact: {report.impact_analysis}")
            lines.append(f"Root Cause: {report.root_cause}")
            lines.append("")

        # Send path bottlenecks
        if result.send_path_bottlenecks:
            lines.append("=== SEND PATH BOTTLENECKS ===")
            for bn in result.send_path_bottlenecks:
                lines.append(f"- {bn.location} [{bn.severity}]: {bn.description}")
            lines.append("")

        # Recv path bottlenecks
        if result.recv_path_bottlenecks:
            lines.append("=== RECV PATH BOTTLENECKS ===")
            for bn in result.recv_path_bottlenecks:
                lines.append(f"- {bn.location} [{bn.severity}]: {bn.description}")
            lines.append("")

        # Optimization priorities
        if result.optimization_priority:
            lines.append("=== OPTIMIZATION PRIORITIES ===")
            for i, bn in enumerate(result.optimization_priority[:3], 1):
                lines.append(f"{i}. {bn.location} ({bn.severity})")
                report = self.generate_bottleneck_details(bn)
                for rec in report.recommendations[:1]:
                    lines.append(f"   Action: {rec.action}")
            lines.append("")

        # Action plans from DiagnosisEngine
        if result.action_plans:
            lines.append("=== NEXT STEPS ===")
            for plan in result.action_plans:
                lines.append(f"{plan.priority}. [{plan.category}] {plan.action}")
                lines.append(f"   Impact: {plan.expected_impact}; Effort: {plan.estimated_effort}")
            lines.append("")

        return "\n".join(lines)
