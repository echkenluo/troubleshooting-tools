#!/usr/bin/env python
"""
TCP Analyzer

Deep analysis of TCP flows including retransmissions, DupACK, Zero Window, SACK, and feature negotiation.
Implements FR-PCAP-DET-005~009.
"""

from typing import List, Dict
from datetime import timedelta

from ..models import Flow, RetransStats, DupACKStats, ZeroWindowStats, SACKStats, TCPFeatures


class TCPAnalyzer:
    """TCP deep analysis engine"""

    def analyze_retransmissions(self, tcp_flow: Flow) -> RetransStats:
        """
        Analyze TCP retransmissions using tshark analysis fields

        Uses tshark's tcp.analysis.retransmission, tcp.analysis.fast_retransmission,
        and tcp.analysis.spurious_retransmission fields for accurate detection.

        Args:
            tcp_flow: Flow object containing TCP packets

        Returns:
            RetransStats with retransmission statistics

        Implements: FR-PCAP-DET-005
        """
        total_packets = len(tcp_flow.packets)
        retrans_count = 0
        fast_retrans_count = 0
        spurious_retrans_count = 0

        for packet in tcp_flow.packets:
            # Check tshark analysis fields
            if packet.get('tcp_analysis_retransmission'):
                retrans_count += 1

            if packet.get('tcp_analysis_fast_retransmission'):
                fast_retrans_count += 1

            if packet.get('tcp_analysis_spurious_retransmission'):
                spurious_retrans_count += 1

        # Timeout retrans = total retrans - fast retrans
        timeout_retrans_count = retrans_count - fast_retrans_count

        return RetransStats(
            total_packets=total_packets,
            retrans_packets=retrans_count,
            retrans_rate=retrans_count / total_packets if total_packets > 0 else 0.0,
            fast_retrans=fast_retrans_count,
            timeout_retrans=timeout_retrans_count,
            spurious_retrans=spurious_retrans_count
        )

    def analyze_dupack(self, tcp_flow: Flow) -> DupACKStats:
        """
        Analyze Duplicate ACKs using tshark analysis fields

        Uses tshark's tcp.analysis.duplicate_ack field for accurate detection.
        Also computes max consecutive DupACKs.

        Args:
            tcp_flow: Flow object containing TCP packets

        Returns:
            DupACKStats with duplicate ACK statistics

        Implements: FR-PCAP-DET-006
        """
        dupack_count = 0
        current_consecutive = 0
        max_consecutive = 0

        for packet in tcp_flow.packets:
            # Check tshark analysis field
            if packet.get('tcp_analysis_duplicate_ack'):
                dupack_count += 1
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0

        total_packets = len(tcp_flow.packets)

        return DupACKStats(
            total_dupack=dupack_count,
            dupack_rate=dupack_count / total_packets if total_packets > 0 else 0.0,
            max_consecutive_dupack=max_consecutive,
            avg_dupack_per_flow=float(dupack_count)
        )

    def analyze_zero_window(self, tcp_flow: Flow) -> ZeroWindowStats:
        """
        Analyze Zero Window events

        Algorithm:
        1. Detect tcp_win == 0
        2. Calculate Zero Window duration

        Args:
            tcp_flow: Flow object containing TCP packets

        Returns:
            ZeroWindowStats with zero window event statistics

        Implements: FR-PCAP-DET-007
        """
        zero_window_events = []
        in_zero_window = False
        event_start = None

        for packet in tcp_flow.packets:
            tcp_win = packet.get('tcp_win')

            if tcp_win == 0:
                if not in_zero_window:
                    in_zero_window = True
                    event_start = packet.get('timestamp')
            else:
                if in_zero_window and event_start:
                    event_end = packet.get('timestamp')
                    if event_end:
                        duration = (event_end - event_start).total_seconds()
                        zero_window_events.append(duration)
                    in_zero_window = False

        total_duration = sum(zero_window_events)
        event_count = len(zero_window_events)

        return ZeroWindowStats(
            zero_window_events=event_count,
            total_duration=total_duration,
            avg_duration=total_duration / event_count if event_count > 0 else 0.0,
            max_duration=max(zero_window_events) if zero_window_events else 0.0
        )

    def analyze_sack(self, tcp_flow: Flow) -> SACKStats:
        """
        Analyze SACK and D-SACK

        Algorithm:
        1. Check tcp.options.sack field
        2. Check tcp.options.sack.dsack field
        3. Count SACK blocks

        Args:
            tcp_flow: Flow object containing TCP packets

        Returns:
            SACKStats with SACK statistics

        Implements: FR-PCAP-DET-008
        """
        sack_enabled = False
        sack_packets = 0
        dsack_packets = 0
        total_sack_blocks = 0

        for packet in tcp_flow.packets:
            if packet.get('tcp_options_sack'):
                sack_enabled = True
                sack_packets += 1

                # Count SACK blocks
                sack_blocks = packet.get('tcp_options_sack_count', 0)
                total_sack_blocks += sack_blocks

            if packet.get('tcp_options_sack_dsack'):
                dsack_packets += 1

        return SACKStats(
            sack_enabled=sack_enabled,
            sack_packets=sack_packets,
            dsack_packets=dsack_packets,
            avg_sack_blocks=total_sack_blocks / sack_packets if sack_packets > 0 else 0.0
        )

    def analyze_features(self, tcp_flow: Flow) -> TCPFeatures:
        """
        Analyze TCP feature negotiation

        Algorithm:
        Extract TCP options from SYN packet

        Args:
            tcp_flow: Flow object containing TCP packets

        Returns:
            TCPFeatures with negotiated TCP features

        Implements: FR-PCAP-DET-009
        """
        # Find SYN packet (SYN=1, ACK=0)
        syn_packet = None
        for packet in tcp_flow.packets:
            if packet.get('tcp_flags_syn') and not packet.get('tcp_flags_ack'):
                syn_packet = packet
                break

        # Return default values if no SYN packet found
        if not syn_packet:
            return TCPFeatures(
                window_scaling=False,
                window_scale_factor=0,
                timestamps=False,
                sack_permitted=False,
                mss=1460
            )

        return TCPFeatures(
            window_scaling=bool(syn_packet.get('tcp_options_wscale')),
            window_scale_factor=syn_packet.get('tcp_options_wscale_shift', 0),
            timestamps=bool(syn_packet.get('tcp_options_timestamp')),
            sack_permitted=bool(syn_packet.get('tcp_options_sack_perm')),
            mss=syn_packet.get('tcp_options_mss_val', 1460)
        )

    def _is_fast_retransmission(self, packets: List[Dict], retrans_index: int) -> bool:
        """
        Determine if retransmission is fast retransmission (vs timeout)

        Fast retransmission: 3 or more DupACKs received before retransmission

        Args:
            packets: List of all packets in flow
            retrans_index: Index of retransmission packet

        Returns:
            True if fast retransmission, False if timeout retransmission
        """
        # Look back at previous 10 packets for DupACKs
        lookback = min(10, retrans_index)
        dupack_count = 0

        for i in range(retrans_index - lookback, retrans_index):
            if packets[i].get('tcp_analysis_duplicate_ack'):
                dupack_count += 1

        # Fast retransmission if 3+ DupACKs found
        return dupack_count >= 3
