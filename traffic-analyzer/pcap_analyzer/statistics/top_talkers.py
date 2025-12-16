#!/usr/bin/env python
"""
Top Talkers Analyzer

Identifies top N senders/receivers by traffic volume.
Implements FR-PCAP-SUM-005.
"""

from collections import defaultdict
from typing import Dict, List, Tuple

from ..models import FiveTuple, Flow, TopTalkersResult


class TopTalkersAnalyzer:
    """Identifies top talkers in network traffic"""

    def identify_top_talkers(self, flows: Dict[FiveTuple, Flow], n: int = 10) -> TopTalkersResult:
        """
        Identify top N senders/receivers by bytes transferred

        Algorithm:
        1. Aggregate bytes by source IP (senders)
        2. Aggregate bytes by destination IP (receivers)
        3. Aggregate bytes by conversation (src_ip, dst_ip)
        4. Sort by bytes and return top N

        Args:
            flows: Dictionary mapping FiveTuple to Flow objects
            n: Number of top talkers to return (default: 10)

        Returns:
            TopTalkersResult with top senders, receivers, and conversations
        """
        sender_stats = defaultdict(int)
        receiver_stats = defaultdict(int)
        conversation_stats = defaultdict(int)

        for ft, flow in flows.items():
            # Sender statistics (by source IP)
            sender_stats[ft.src_ip] += flow.total_bytes

            # Receiver statistics (by destination IP)
            receiver_stats[ft.dst_ip] += flow.total_bytes

            # Conversation statistics (by src_ip, dst_ip pair)
            conversation_key = (ft.src_ip, ft.dst_ip)
            conversation_stats[conversation_key] += flow.total_bytes

        # Sort and get top N
        top_senders = sorted(
            sender_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]

        top_receivers = sorted(
            receiver_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]

        top_conversations = [
            (src, dst, bytes_)
            for (src, dst), bytes_ in sorted(
                conversation_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:n]
        ]

        return TopTalkersResult(
            top_senders=top_senders,
            top_receivers=top_receivers,
            top_conversations=top_conversations
        )

    def get_top_senders(self, flows: Dict[FiveTuple, Flow], n: int = 10) -> List[Tuple[str, int]]:
        """
        Get top N senders by bytes sent

        Args:
            flows: Dictionary mapping FiveTuple to Flow objects
            n: Number of top senders to return

        Returns:
            List of tuples (IP address, bytes sent)
        """
        sender_stats = defaultdict(int)

        for ft, flow in flows.items():
            sender_stats[ft.src_ip] += flow.total_bytes

        return sorted(
            sender_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]

    def get_top_receivers(self, flows: Dict[FiveTuple, Flow], n: int = 10) -> List[Tuple[str, int]]:
        """
        Get top N receivers by bytes received

        Args:
            flows: Dictionary mapping FiveTuple to Flow objects
            n: Number of top receivers to return

        Returns:
            List of tuples (IP address, bytes received)
        """
        receiver_stats = defaultdict(int)

        for ft, flow in flows.items():
            receiver_stats[ft.dst_ip] += flow.total_bytes

        return sorted(
            receiver_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]
