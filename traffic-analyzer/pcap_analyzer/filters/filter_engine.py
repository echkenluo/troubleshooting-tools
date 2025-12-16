#!/usr/bin/env python
"""
Filter Engine

Provides packet filtering capabilities by IP, port, protocol, and time.
Implements FR-PCAP-DET-001~004, FR-PCAP-DET-010.
"""

from typing import Iterator, Dict, Optional
from datetime import datetime


class FilterEngine:
    """Packet filtering engine with multiple filter types"""

    def apply_ip_filter(
        self,
        packets: Iterator[Dict],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None
    ) -> Iterator[Dict]:
        """
        Filter packets by source and/or destination IP address

        Args:
            packets: Iterator of packet dictionaries
            src_ip: Source IP address to filter (None = no filter)
            dst_ip: Destination IP address to filter (None = no filter)

        Yields:
            Packets matching the IP filter criteria
        """
        for packet in packets:
            # Skip if source IP doesn't match
            if src_ip and packet.get('src_ip') != src_ip:
                continue

            # Skip if destination IP doesn't match
            if dst_ip and packet.get('dst_ip') != dst_ip:
                continue

            yield packet

    def apply_port_filter(
        self,
        packets: Iterator[Dict],
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None
    ) -> Iterator[Dict]:
        """
        Filter packets by source and/or destination port

        Args:
            packets: Iterator of packet dictionaries
            src_port: Source port to filter (None = no filter)
            dst_port: Destination port to filter (None = no filter)

        Yields:
            Packets matching the port filter criteria
        """
        for packet in packets:
            # Get actual source and destination ports
            actual_src_port = packet.get('src_port')
            actual_dst_port = packet.get('dst_port')

            # Skip if source port doesn't match
            if src_port is not None and actual_src_port != src_port:
                continue

            # Skip if destination port doesn't match
            if dst_port is not None and actual_dst_port != dst_port:
                continue

            yield packet

    def apply_protocol_filter(
        self,
        packets: Iterator[Dict],
        protocol: str
    ) -> Iterator[Dict]:
        """
        Filter packets by protocol (TCP, UDP, ICMP, etc.)

        Args:
            packets: Iterator of packet dictionaries
            protocol: Protocol name (case-insensitive)

        Yields:
            Packets matching the protocol
        """
        protocol_lower = protocol.lower()

        for packet in packets:
            packet_protocol = packet.get('protocol', '').lower()
            if packet_protocol == protocol_lower:
                yield packet

    def apply_time_filter(
        self,
        packets: Iterator[Dict],
        start_time: datetime,
        end_time: datetime
    ) -> Iterator[Dict]:
        """
        Filter packets by time range

        Args:
            packets: Iterator of packet dictionaries
            start_time: Start of time window (inclusive)
            end_time: End of time window (inclusive)

        Yields:
            Packets within the time window
        """
        for packet in packets:
            packet_time = packet.get('timestamp')
            if packet_time and start_time <= packet_time <= end_time:
                yield packet

    def apply_combined_filter(
        self,
        packets: Iterator[Dict],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Iterator[Dict]:
        """
        Apply multiple filters in combination

        Args:
            packets: Iterator of packet dictionaries
            src_ip: Source IP filter
            dst_ip: Destination IP filter
            src_port: Source port filter
            dst_port: Destination port filter
            protocol: Protocol filter
            start_time: Start time filter
            end_time: End time filter

        Yields:
            Packets matching all specified filter criteria
        """
        for packet in packets:
            # IP filters
            if src_ip and packet.get('src_ip') != src_ip:
                continue
            if dst_ip and packet.get('dst_ip') != dst_ip:
                continue

            # Port filters
            if src_port is not None and packet.get('src_port') != src_port:
                continue
            if dst_port is not None and packet.get('dst_port') != dst_port:
                continue

            # Protocol filter
            if protocol and packet.get('protocol', '').lower() != protocol.lower():
                continue

            # Time filter
            if start_time or end_time:
                packet_time = packet.get('timestamp')
                if not packet_time:
                    continue
                if start_time and packet_time < start_time:
                    continue
                if end_time and packet_time > end_time:
                    continue

            yield packet
