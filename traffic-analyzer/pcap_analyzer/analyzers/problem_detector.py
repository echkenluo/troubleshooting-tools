#!/usr/bin/env python
"""
Problem Detector

Intelligent problem identification for 7 types of network issues.
Implements FR-PCAP-ANA-001~007, FR-PCAP-DET-011.
"""

from typing import List, Optional, Dict
from datetime import timedelta

from ..models import Flow, Problem, BurstEvent


class ProblemDetector:
    """Network problem detection engine"""

    # Detection thresholds
    HIGH_LATENCY_THRESHOLD = 0.1  # 100ms
    PACKET_LOSS_THRESHOLD = 0.01  # 1%
    OUT_OF_ORDER_THRESHOLD = 0.005  # 0.5%
    ZERO_WINDOW_THRESHOLD = 3  # 3 events
    BURST_WINDOW_SIZE = 1.0  # 1 second
    BURST_THRESHOLD = 5  # 5 retransmissions

    def detect_all(self, tcp_flow: Flow) -> List[Problem]:
        """
        Detect all 7 types of network problems

        Problem types:
        1. High latency
        2. Packet loss
        3. Out of order
        4. Window issues
        5. Handshake failures
        6. Connection resets
        7. Retransmission bursts

        Args:
            tcp_flow: Flow object containing TCP packets

        Returns:
            List of detected problems

        Implements: FR-PCAP-ANA-001~007
        """
        problems = []

        # 1. High latency detection
        if problem := self.detect_high_latency(tcp_flow):
            problems.append(problem)

        # 2. Packet loss detection
        if problem := self.detect_packet_loss(tcp_flow):
            problems.append(problem)

        # 3. Out of order detection
        if problem := self.detect_out_of_order(tcp_flow):
            problems.append(problem)

        # 4. Window issues
        if problem := self.detect_window_issues(tcp_flow):
            problems.append(problem)

        # 5. Handshake failures (requires multiple flows - handled separately)
        # 6. Connection resets (requires multiple flows - handled separately)

        # 7. Retransmission bursts
        burst_events = self.detect_retrans_burst(tcp_flow)
        if burst_events:
            problems.append(Problem(
                type='RETRANS_BURST',
                severity='HIGH',
                description=f'Detected {len(burst_events)} retransmission burst events',
                evidence={'events': burst_events, 'count': len(burst_events)}
            ))

        return problems

    def detect_high_latency(self, tcp_flow: Flow) -> Optional[Problem]:
        """
        Detect high latency (RTT > 100ms)

        Args:
            tcp_flow: Flow object

        Returns:
            Problem if high latency detected, None otherwise

        Implements: FR-PCAP-ANA-001
        """
        rtt_values = [
            p.get('tcp_analysis_ack_rtt', 0)
            for p in tcp_flow.packets
            if p.get('tcp_analysis_ack_rtt')
        ]

        if not rtt_values:
            return None

        avg_rtt = sum(rtt_values) / len(rtt_values)

        if avg_rtt > self.HIGH_LATENCY_THRESHOLD:
            severity = 'HIGH' if avg_rtt > 0.5 else 'WARNING'
            return Problem(
                type='HIGH_LATENCY',
                severity=severity,
                description=f'Average RTT {avg_rtt*1000:.1f}ms exceeds threshold',
                evidence={'avg_rtt': avg_rtt, 'max_rtt': max(rtt_values)}
            )

        return None

    def detect_packet_loss(self, tcp_flow: Flow) -> Optional[Problem]:
        """
        Detect packet loss (retransmission rate > 1%)

        Args:
            tcp_flow: Flow object

        Returns:
            Problem if packet loss detected, None otherwise

        Implements: FR-PCAP-ANA-002
        """
        total_packets = len(tcp_flow.packets)
        if total_packets == 0:
            return None

        retrans_packets = sum(
            1 for p in tcp_flow.packets
            if p.get('tcp_analysis_retransmission')
        )

        retrans_rate = retrans_packets / total_packets

        if retrans_rate > self.PACKET_LOSS_THRESHOLD:
            severity = 'CRITICAL' if retrans_rate > 0.05 else 'HIGH'
            return Problem(
                type='PACKET_LOSS',
                severity=severity,
                description=f'Retransmission rate {retrans_rate*100:.2f}% exceeds threshold',
                evidence={'retrans_rate': retrans_rate, 'retrans_packets': retrans_packets}
            )

        return None

    def detect_out_of_order(self, tcp_flow: Flow) -> Optional[Problem]:
        """
        Detect out-of-order packets (> 0.5%)

        Args:
            tcp_flow: Flow object

        Returns:
            Problem if out-of-order detected, None otherwise

        Implements: FR-PCAP-ANA-003
        """
        total_packets = len(tcp_flow.packets)
        if total_packets == 0:
            return None

        ooo_packets = sum(
            1 for p in tcp_flow.packets
            if p.get('tcp_analysis_out_of_order')
        )

        ooo_rate = ooo_packets / total_packets

        if ooo_rate > self.OUT_OF_ORDER_THRESHOLD:
            return Problem(
                type='OUT_OF_ORDER',
                severity='WARNING',
                description=f'Out-of-order rate {ooo_rate*100:.2f}% exceeds threshold',
                evidence={'ooo_rate': ooo_rate, 'ooo_packets': ooo_packets}
            )

        return None

    def detect_window_issues(self, tcp_flow: Flow) -> Optional[Problem]:
        """
        Detect TCP window issues (zero window events > 3)

        Args:
            tcp_flow: Flow object

        Returns:
            Problem if window issues detected, None otherwise

        Implements: FR-PCAP-ANA-004
        """
        zero_window_count = sum(
            1 for p in tcp_flow.packets
            if p.get('tcp_analysis_zero_window')
        )

        if zero_window_count > self.ZERO_WINDOW_THRESHOLD:
            return Problem(
                type='WINDOW_ISSUES',
                severity='HIGH',
                description=f'Detected {zero_window_count} zero window events',
                evidence={'zero_window_count': zero_window_count}
            )

        return None

    def detect_handshake_failures(self, flows: List[Flow]) -> List[Problem]:
        """
        Detect TCP handshake failures across multiple flows

        Args:
            flows: List of Flow objects

        Returns:
            List of handshake failure problems

        Implements: FR-PCAP-ANA-005
        """
        problems = []

        for flow in flows:
            # Check for SYN without SYN-ACK
            has_syn = any(
                p.get('tcp_flags_syn') and not p.get('tcp_flags_ack')
                for p in flow.packets
            )
            has_synack = any(
                p.get('tcp_flags_syn') and p.get('tcp_flags_ack')
                for p in flow.packets
            )

            if has_syn and not has_synack:
                problems.append(Problem(
                    type='HANDSHAKE_FAILURE',
                    severity='HIGH',
                    description='SYN sent but no SYN-ACK received',
                    evidence={'flow': flow.five_tuple}
                ))

        return problems

    def detect_connection_resets(self, flows: List[Flow]) -> List[Problem]:
        """
        Detect abnormal connection resets (RST)

        Args:
            flows: List of Flow objects

        Returns:
            List of connection reset problems

        Implements: FR-PCAP-ANA-006
        """
        problems = []

        for flow in flows:
            rst_packets = [
                p for p in flow.packets
                if p.get('tcp_flags_reset')
            ]

            if rst_packets:
                problems.append(Problem(
                    type='CONNECTION_RESET',
                    severity='WARNING',
                    description=f'Connection reset detected ({len(rst_packets)} RST packets)',
                    evidence={'flow': flow.five_tuple, 'rst_count': len(rst_packets)}
                ))

        return problems

    def detect_retrans_burst(self, tcp_flow: Flow) -> List[BurstEvent]:
        """
        Detect retransmission burst events

        Algorithm:
        1. Sliding window detection (1 second window)
        2. Window with > 5 retransmissions is a burst

        Args:
            tcp_flow: Flow object

        Returns:
            List of burst events

        Implements: FR-PCAP-DET-011, FR-PCAP-ANA-007
        """
        burst_events = []

        # Get all retransmission packets
        retrans_packets = [
            p for p in tcp_flow.packets
            if p.get('tcp_analysis_retransmission')
        ]

        if not retrans_packets:
            return burst_events

        i = 0
        while i < len(retrans_packets):
            window_start_time = retrans_packets[i].get('timestamp')
            if not window_start_time:
                i += 1
                continue

            window_end_time = window_start_time + timedelta(seconds=self.BURST_WINDOW_SIZE)

            # Count retransmissions in window
            count = 0
            j = i
            while j < len(retrans_packets):
                packet_time = retrans_packets[j].get('timestamp')
                if packet_time and packet_time < window_end_time:
                    count += 1
                    j += 1
                else:
                    break

            # Check if threshold exceeded
            if count >= self.BURST_THRESHOLD:
                severity = 'CRITICAL' if count > 10 else 'HIGH' if count > 7 else 'MEDIUM'
                burst_events.append(BurstEvent(
                    start_time=window_start_time,
                    end_time=retrans_packets[j-1].get('timestamp') if j > 0 else window_start_time,
                    packet_count=count,
                    severity=severity
                ))
                i = j  # Skip to end of burst
            else:
                i += 1

        return burst_events
