#!/usr/bin/env python
"""
Statistics Engine

Computes L2/L3/L4 layer statistics from packet data.
Implements FR-PCAP-SUM-002.
"""

from collections import Counter
from typing import Iterator, Dict

from ..models import L2Stats, L3Stats, L4Stats


class StatisticsEngine:
    """Computes multi-layer network statistics"""

    # Frame size ranges for L2 statistics
    SIZE_RANGES = [
        (0, 64, '<64'),
        (64, 128, '64-127'),
        (128, 256, '128-255'),
        (256, 512, '256-511'),
        (512, 1024, '512-1023'),
        (1024, 1518, '1024-1517'),
        (1518, float('inf'), '>=1518')
    ]

    def compute_l2_stats(self, packets: Iterator[Dict]) -> L2Stats:
        """
        Compute Layer 2 (Data Link) statistics

        Statistics collected:
        1. Ethernet type distribution (IPv4/IPv6/ARP/etc.)
        2. Frame size distribution

        Algorithm: Single-pass iteration using Counter

        Args:
            packets: Iterator of packet dictionaries

        Returns:
            L2Stats with ethernet types and frame size distribution
        """
        ethernet_types = Counter()
        frame_sizes = Counter()
        total_frames = 0

        for packet in packets:
            total_frames += 1

            # Ethernet type statistics
            eth_type = packet.get('eth_type', 'UNKNOWN')
            ethernet_types[eth_type] += 1

            # Frame size statistics
            frame_len = packet.get('frame_len', 0)
            size_range = self._get_size_range(frame_len)
            frame_sizes[size_range] += 1

        return L2Stats(
            ethernet_types=dict(ethernet_types),
            frame_size_distribution=dict(frame_sizes),
            total_frames=total_frames
        )

    def compute_l3_stats(self, packets: Iterator[Dict]) -> L3Stats:
        """
        Compute Layer 3 (Network) statistics

        Statistics collected:
        1. IP version distribution (IPv4/IPv6)
        2. Protocol distribution (TCP/UDP/ICMP/etc.)
        3. Total packets and bytes

        Args:
            packets: Iterator of packet dictionaries

        Returns:
            L3Stats with IP versions and protocol distribution
        """
        ip_versions = Counter()
        protocols = Counter()
        total_packets = 0
        total_bytes = 0

        for packet in packets:
            total_packets += 1
            total_bytes += packet.get('frame_len', 0)

            # IP version statistics
            ip_version = packet.get('ip_version', 'UNKNOWN')
            ip_versions[ip_version] += 1

            # Protocol statistics
            protocol = packet.get('protocol', 'UNKNOWN')
            protocols[protocol] += 1

        return L3Stats(
            ip_versions=dict(ip_versions),
            protocol_distribution=dict(protocols),
            total_packets=total_packets
        )

    def compute_l4_stats(self, packets: Iterator[Dict]) -> L4Stats:
        """
        Compute Layer 4 (Transport) statistics

        Statistics collected:
        1. TCP packet count and total bytes
        2. UDP packet count and total bytes
        3. Other protocol statistics

        Args:
            packets: Iterator of packet dictionaries

        Returns:
            L4Stats with TCP/UDP packet and byte counts
        """
        tcp_packets = 0
        tcp_bytes = 0
        udp_packets = 0
        udp_bytes = 0
        other_packets = 0
        other_bytes = 0

        for packet in packets:
            protocol = packet.get('protocol', '').upper()
            frame_len = packet.get('frame_len', 0)

            if protocol == 'TCP':
                tcp_packets += 1
                tcp_bytes += frame_len
            elif protocol == 'UDP':
                udp_packets += 1
                udp_bytes += frame_len
            else:
                other_packets += 1
                other_bytes += frame_len

        return L4Stats(
            tcp_packets=tcp_packets,
            tcp_bytes=tcp_bytes,
            udp_packets=udp_packets,
            udp_bytes=udp_bytes,
            other_packets=other_packets,
            other_bytes=other_bytes,
            total_bytes=tcp_bytes + udp_bytes + other_bytes
        )

    def _get_size_range(self, frame_len: int) -> str:
        """
        Classify frame size into predefined ranges

        Args:
            frame_len: Frame length in bytes

        Returns:
            String representing the size range (e.g., '64-127')
        """
        for min_size, max_size, label in self.SIZE_RANGES:
            if min_size <= frame_len < max_size:
                return label
        return 'UNKNOWN'
