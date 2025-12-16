#!/usr/bin/env python
"""
Diagnosis Engine

Root cause analysis and recommendation generation for detected problems.
Implements FR-PCAP-ANA-008, FR-PCAP-ANA-009.
"""

from typing import List

from ..models import Problem, Flow, PossibleCause, Recommendation


class DiagnosisEngine:
    """Problem diagnosis and recommendation engine"""

    def analyze_causes(self, problem: Problem, tcp_flow: Flow) -> List[PossibleCause]:
        """
        Analyze possible causes for detected problem

        Based on problem type and evidence, infer possible root causes

        Args:
            problem: Detected problem
            tcp_flow: Flow object for additional analysis

        Returns:
            List of possible causes with confidence scores

        Implements: FR-PCAP-ANA-008
        """
        causes = []

        if problem.type == 'HIGH_LATENCY':
            causes.extend(self._analyze_latency_causes(problem))

        elif problem.type == 'PACKET_LOSS':
            causes.extend(self._analyze_packet_loss_causes(problem))

        elif problem.type == 'RETRANS_BURST':
            causes.extend(self._analyze_burst_causes(problem))

        elif problem.type == 'WINDOW_ISSUES':
            causes.extend(self._analyze_window_causes(problem))

        elif problem.type == 'OUT_OF_ORDER':
            causes.extend(self._analyze_ooo_causes(problem))

        return causes

    def generate_recommendations(self, problem: Problem, causes: List[PossibleCause]) -> List[Recommendation]:
        """
        Generate actionable recommendations

        Args:
            problem: Detected problem
            causes: Analyzed possible causes

        Returns:
            List of recommendations with priorities

        Implements: FR-PCAP-ANA-009
        """
        recommendations = []

        if problem.type == 'HIGH_LATENCY':
            recommendations.extend(self._recommend_latency_fixes(problem, causes))

        elif problem.type == 'PACKET_LOSS':
            recommendations.extend(self._recommend_packet_loss_fixes(problem, causes))

        elif problem.type == 'RETRANS_BURST':
            recommendations.extend(self._recommend_burst_fixes(problem, causes))

        elif problem.type == 'WINDOW_ISSUES':
            recommendations.extend(self._recommend_window_fixes(problem, causes))

        elif problem.type == 'OUT_OF_ORDER':
            recommendations.extend(self._recommend_ooo_fixes(problem, causes))

        return recommendations

    def _analyze_latency_causes(self, problem: Problem) -> List[PossibleCause]:
        """Analyze high latency causes"""
        causes = []
        avg_rtt = problem.evidence.get('avg_rtt', 0)

        if avg_rtt > 0.5:  # > 500ms
            causes.append(PossibleCause(
                cause='Long geographic distance or cross-region transmission',
                confidence=0.8,
                evidence=['RTT exceeds 500ms, likely long-distance transmission']
            ))
        elif avg_rtt > 0.2:  # > 200ms
            causes.append(PossibleCause(
                cause='Network congestion or suboptimal routing',
                confidence=0.7,
                evidence=['RTT between 200-500ms, possible congestion']
            ))
        else:
            causes.append(PossibleCause(
                cause='Link quality degradation or device processing delay',
                confidence=0.6,
                evidence=['RTT 100-200ms, check intermediate devices']
            ))

        return causes

    def _analyze_packet_loss_causes(self, problem: Problem) -> List[PossibleCause]:
        """Analyze packet loss causes"""
        causes = []
        retrans_rate = problem.evidence.get('retrans_rate', 0)

        if retrans_rate > 0.05:  # > 5%
            causes.append(PossibleCause(
                cause='Severe network congestion or poor link quality',
                confidence=0.9,
                evidence=['Retransmission rate exceeds 5%, network quality severely degraded']
            ))
        else:
            causes.append(PossibleCause(
                cause='Moderate network congestion',
                confidence=0.7,
                evidence=['Retransmission rate 1-5%, experiencing packet loss']
            ))

        return causes

    def _analyze_burst_causes(self, problem: Problem) -> List[PossibleCause]:
        """Analyze retransmission burst causes"""
        causes = [
            PossibleCause(
                cause='Transient network congestion',
                confidence=0.7,
                evidence=['Large number of retransmissions in short time, likely congestion burst']
            ),
            PossibleCause(
                cause='Microbursts or traffic spikes',
                confidence=0.6,
                evidence=['Sudden retransmission cluster may indicate microburst']
            )
        ]
        return causes

    def _analyze_window_causes(self, problem: Problem) -> List[PossibleCause]:
        """Analyze window issue causes"""
        causes = [
            PossibleCause(
                cause='Receiver application slow to read data',
                confidence=0.8,
                evidence=['Multiple zero window events indicate receiver buffer full']
            ),
            PossibleCause(
                cause='Insufficient receive buffer size',
                confidence=0.6,
                evidence=['Receiver buffer may be too small for connection']
            )
        ]
        return causes

    def _analyze_ooo_causes(self, problem: Problem) -> List[PossibleCause]:
        """Analyze out-of-order causes"""
        causes = [
            PossibleCause(
                cause='Multipath routing or load balancing',
                confidence=0.7,
                evidence=['Packets arriving out of order, possible multiple paths']
            )
        ]
        return causes

    def _recommend_latency_fixes(self, problem: Problem, causes: List[PossibleCause]) -> List[Recommendation]:
        """Generate latency fix recommendations"""
        return [
            Recommendation(
                action='Consider using CDN or edge nodes',
                priority='HIGH',
                description='Reduce latency from geographic distance'
            ),
            Recommendation(
                action='Check if routing path is optimal',
                priority='MEDIUM',
                description='Use traceroute to analyze hop count and path'
            ),
            Recommendation(
                action='Enable TCP BBR congestion control',
                priority='MEDIUM',
                description='Better performance on high-latency networks'
            )
        ]

    def _recommend_packet_loss_fixes(self, problem: Problem, causes: List[PossibleCause]) -> List[Recommendation]:
        """Generate packet loss fix recommendations"""
        return [
            Recommendation(
                action='Check network equipment and link quality',
                priority='HIGH',
                description='Investigate switches and routers for packet drops'
            ),
            Recommendation(
                action='Increase TCP buffer sizes',
                priority='MEDIUM',
                description='Increase congestion window upper limit'
            ),
            Recommendation(
                action='Enable SACK if not already active',
                priority='MEDIUM',
                description='Selective acknowledgment improves recovery from loss'
            )
        ]

    def _recommend_burst_fixes(self, problem: Problem, causes: List[PossibleCause]) -> List[Recommendation]:
        """Generate burst fix recommendations"""
        return [
            Recommendation(
                action='Implement traffic shaping or rate limiting',
                priority='HIGH',
                description='Prevent sudden traffic bursts'
            ),
            Recommendation(
                action='Increase switch/router buffer sizes',
                priority='MEDIUM',
                description='Handle transient congestion better'
            )
        ]

    def _recommend_window_fixes(self, problem: Problem, causes: List[PossibleCause]) -> List[Recommendation]:
        """Generate window issue fix recommendations"""
        return [
            Recommendation(
                action='Optimize receiver application performance',
                priority='HIGH',
                description='Reduce data processing latency'
            ),
            Recommendation(
                action='Increase TCP receive buffer size',
                priority='HIGH',
                description='Adjust net.ipv4.tcp_rmem kernel parameter'
            ),
            Recommendation(
                action='Enable TCP window scaling',
                priority='MEDIUM',
                description='Support larger receive windows'
            )
        ]

    def _recommend_ooo_fixes(self, problem: Problem, causes: List[PossibleCause]) -> List[Recommendation]:
        """Generate out-of-order fix recommendations"""
        return [
            Recommendation(
                action='Review load balancing configuration',
                priority='MEDIUM',
                description='Ensure per-flow consistency in load balancing'
            ),
            Recommendation(
                action='Check for asymmetric routing',
                priority='MEDIUM',
                description='Verify forward and return paths are symmetric'
            )
        ]
