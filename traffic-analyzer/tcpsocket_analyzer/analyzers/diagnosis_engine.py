#!/usr/bin/env python
"""
Diagnosis Engine

Provides comprehensive bottleneck diagnosis and optimization action planning.
Implements FR-SOCKET-PIPE-008.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from ..models import Bottleneck, Recommendation


@dataclass
class ActionPlan:
    """Optimization action plan"""
    priority: int
    action: str
    expected_impact: str
    estimated_effort: str
    category: str


@dataclass
class Diagnosis:
    """Bottleneck diagnosis result"""
    summary: str
    details: str
    severity: str
    possible_causes: List[str]
    validation_steps: List[str]


@dataclass
class AnalysisContext:
    """Analysis context information"""
    bdp: float
    bandwidth: float
    avg_rtt: float
    avg_cwnd: float
    avg_delivery_rate: float


class DiagnosisEngine:
    """
    Diagnosis and optimization planning engine

    Provides:
    - Deep bottleneck diagnosis with context
    - Optimization action prioritization
    - Step-by-step resolution guidance

    Implements:
    - FR-SOCKET-PIPE-008: Overall assessment and recommendations
    """

    def generate_next_steps(
        self,
        bottlenecks: List[Bottleneck],
        context: Optional[AnalysisContext] = None
    ) -> List[ActionPlan]:
        """
        Generate prioritized action plan

        Prioritization criteria:
        1. CRITICAL bottlenecks first
        2. Quick wins (low effort, high impact)
        3. Low-cost optimizations

        Args:
            bottlenecks: List of detected bottlenecks
            context: Analysis context (optional)

        Returns:
            List of ActionPlan objects (top 5)

        Implements: FR-SOCKET-PIPE-008
        """
        if not bottlenecks:
            return []

        action_plans = []

        for i, bottleneck in enumerate(bottlenecks[:5], 1):
            # Assess effort and impact
            effort = self._estimate_effort(bottleneck)
            impact = self._estimate_impact(bottleneck)

            # Get action from evidence
            action = self._extract_action(bottleneck)

            action_plans.append(ActionPlan(
                priority=i,
                action=action,
                expected_impact=impact,
                estimated_effort=effort,
                category=self._get_category(bottleneck.location)
            ))

        return action_plans

    def _estimate_effort(self, bottleneck: Bottleneck) -> str:
        """
        Estimate effort required to fix bottleneck

        Args:
            bottleneck: Bottleneck to assess

        Returns:
            Effort level: LOW/MEDIUM/HIGH
        """
        # Buffer tuning: usually low effort
        if 'BUFFER' in bottleneck.location:
            return 'LOW (sysctl tuning, no restart required)'

        # CWND/RWND tuning: medium effort
        elif bottleneck.location in ['CWND', 'RWND']:
            return 'MEDIUM (kernel parameter tuning, may need restart)'

        # Application changes: high effort
        elif 'APP' in bottleneck.location:
            return 'HIGH (application code changes required)'

        # Network upgrades: very high effort
        elif bottleneck.location == 'NETWORK':
            return 'VERY HIGH (network infrastructure upgrade)'

        else:
            return 'MEDIUM'

    def _estimate_impact(self, bottleneck: Bottleneck) -> str:
        """
        Estimate expected impact of fixing bottleneck

        Args:
            bottleneck: Bottleneck to assess

        Returns:
            Impact level with percentage
        """
        if bottleneck.severity == 'CRITICAL':
            return 'HIGH (30-50% throughput improvement expected)'
        elif bottleneck.severity == 'HIGH':
            return 'MEDIUM-HIGH (20-30% throughput improvement expected)'
        elif bottleneck.severity == 'MEDIUM':
            return 'MEDIUM (10-20% throughput improvement expected)'
        else:
            return 'LOW (5-10% throughput improvement expected)'

    def _extract_action(self, bottleneck: Bottleneck) -> str:
        """
        Extract or generate action recommendation

        Args:
            bottleneck: Bottleneck with evidence

        Returns:
            Action description
        """
        # Try to get from evidence
        if 'recommendation' in bottleneck.evidence:
            return bottleneck.evidence['recommendation']

        # Generate generic action
        actions = {
            'CWND': 'Investigate packet loss and consider BBR congestion control',
            'RWND': 'Increase receiver window buffer on remote peer',
            'SEND_BUFFER': 'Increase socket send buffer size (tcp_wmem)',
            'RECV_BUFFER': 'Increase socket receive buffer size (tcp_rmem)',
            'NETWORK': 'Evaluate network capacity upgrade',
            'APP_SEND': 'Optimize application send patterns (larger writes, async I/O)',
            'APP_RECV': 'Optimize application receive patterns (larger reads, async I/O)',
        }

        return actions.get(bottleneck.location, 'Investigate and optimize ' + bottleneck.location)

    def _get_category(self, location: str) -> str:
        """Map location to category"""
        if 'BUFFER' in location:
            return 'BUFFER'
        elif location in ['CWND', 'RWND']:
            return 'WINDOW'
        elif 'APP' in location:
            return 'APPLICATION'
        elif location == 'NETWORK':
            return 'NETWORK'
        else:
            return 'OTHER'

    def diagnose_bottleneck(
        self,
        bottleneck: Bottleneck,
        context: Optional[AnalysisContext] = None
    ) -> Diagnosis:
        """
        Perform deep diagnosis of bottleneck

        Combines bottleneck data with context to provide comprehensive
        root cause analysis.

        Args:
            bottleneck: Bottleneck to diagnose
            context: Analysis context

        Returns:
            Diagnosis object with detailed analysis

        Implements: FR-SOCKET-PIPE-008
        """
        summary = f'{bottleneck.path} path bottleneck at {bottleneck.location}'

        # Build detailed diagnosis
        details_parts = []
        details_parts.append(f'Location: {bottleneck.location}')
        details_parts.append(f'Severity: {bottleneck.severity}')
        details_parts.append(f'Pressure: {bottleneck.pressure*100:.1f}%')
        details_parts.append(f'Description: {bottleneck.description}')

        if bottleneck.evidence:
            details_parts.append('Evidence:')
            for key, value in bottleneck.evidence.items():
                if key != 'recommendation':
                    details_parts.append(f'  - {key}: {value}')

        details = '\n'.join(details_parts)

        # Identify possible causes
        possible_causes = self._identify_causes(bottleneck, context)

        # Generate validation steps
        validation_steps = self._generate_validation_steps(bottleneck)

        return Diagnosis(
            summary=summary,
            details=details,
            severity=bottleneck.severity,
            possible_causes=possible_causes,
            validation_steps=validation_steps
        )

    def _identify_causes(
        self,
        bottleneck: Bottleneck,
        context: Optional[AnalysisContext]
    ) -> List[str]:
        """
        Identify possible root causes

        Args:
            bottleneck: Bottleneck being diagnosed
            context: Analysis context

        Returns:
            List of possible causes
        """
        causes = []

        if bottleneck.location == 'CWND':
            causes.append('Network congestion causing packet loss')
            causes.append('Conservative congestion control algorithm')
            if context and context.avg_cwnd < context.bdp / 1460:
                causes.append(f'CWND ({context.avg_cwnd:.0f}) << BDP ({context.bdp/1460:.0f} packets)')

        elif bottleneck.location == 'SEND_BUFFER':
            causes.append('Default socket buffer too small')
            causes.append('Application sending faster than network can transmit')
            if context:
                causes.append(f'BDP requirement: {context.bdp:.0f} bytes')

        elif bottleneck.location == 'RECV_BUFFER':
            causes.append('Application not reading data fast enough')
            causes.append('Blocking I/O operations')
            causes.append('Insufficient application processing capacity')

        elif bottleneck.location == 'RWND':
            causes.append('Peer has small receive buffer')
            causes.append('Peer application not reading data')

        elif bottleneck.location == 'NETWORK':
            causes.append('Link bandwidth saturation')
            causes.append('Network infrastructure capacity limit')

        elif 'APP' in bottleneck.location:
            causes.append('Small read()/write() call sizes')
            causes.append('Synchronous/blocking I/O')
            causes.append('CPU-bound processing')

        return causes

    def _generate_validation_steps(self, bottleneck: Bottleneck) -> List[str]:
        """
        Generate validation steps for diagnosis

        Args:
            bottleneck: Bottleneck being diagnosed

        Returns:
            List of validation steps
        """
        steps = []

        if bottleneck.location == 'CWND':
            steps.append('Check for packet loss: tcpdump -i eth0 -w capture.pcap')
            steps.append('Monitor RTT variance: ss -ti')
            steps.append('Review congestion control algorithm: sysctl net.ipv4.tcp_congestion_control')

        elif 'BUFFER' in bottleneck.location:
            steps.append('Check current buffer settings: sysctl net.ipv4.tcp_wmem net.ipv4.tcp_rmem')
            steps.append('Monitor buffer utilization: ss -tm')
            steps.append('Calculate required buffer: BDP = bandwidth * RTT')

        elif 'APP' in bottleneck.location:
            steps.append('Profile application with strace: strace -c -p <pid>')
            steps.append('Check I/O patterns: iotop')
            steps.append('Monitor system calls: perf record -e syscalls:*')

        elif bottleneck.location == 'NETWORK':
            steps.append('Measure available bandwidth: iperf3 -c <server>')
            steps.append('Check link utilization: ifstat, nload')
            steps.append('Review QoS policies and traffic shaping')

        return steps

    def generate_optimization_summary(
        self,
        action_plans: List[ActionPlan]
    ) -> str:
        """
        Generate optimization summary report

        Args:
            action_plans: List of action plans

        Returns:
            Formatted summary string
        """
        if not action_plans:
            return "No optimizations required. System is performing well."

        lines = []
        lines.append("OPTIMIZATION ACTION PLAN")
        lines.append("=" * 60)
        lines.append("")

        for plan in action_plans:
            lines.append(f"Priority {plan.priority}: {plan.category}")
            lines.append(f"  Action: {plan.action}")
            lines.append(f"  Expected Impact: {plan.expected_impact}")
            lines.append(f"  Estimated Effort: {plan.estimated_effort}")
            lines.append("")

        return "\n".join(lines)
