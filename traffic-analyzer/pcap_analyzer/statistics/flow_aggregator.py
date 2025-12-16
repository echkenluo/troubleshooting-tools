#!/usr/bin/env python
"""
Flow Aggregator

Aggregates TCP/UDP packets by five-tuple.
Implements FR-PCAP-SUM-003.
"""

from collections import defaultdict
from typing import Iterator, Dict
from datetime import datetime

from ..models import Packet, FiveTuple, Flow, FlowStats


class FlowAggregator:
    """Aggregates TCP/UDP flows by five-tuple"""

    def aggregate_flows(self, packets: Iterator[Dict]) -> Dict[FiveTuple, Flow]:
        """
        Aggregate flows by five-tuple

        Algorithm:
        1. Iterate through packets
        2. Extract five-tuple
        3. Group packets by five-tuple

        Args:
            packets: Iterator of packet dictionaries

        Returns:
            Dictionary mapping FiveTuple to Flow
        """
        flows = defaultdict(lambda: {
            'five_tuple': None,
            'packets': [],
            'total_bytes': 0,
            'start_time': None,
            'end_time': None
        })

        for packet in packets:
            # Skip packets without required fields
            if not packet.get('src_ip') or not packet.get('dst_ip'):
                continue
            if packet.get('src_port') is None or packet.get('dst_port') is None:
                continue

            # Extract five-tuple
            ft = FiveTuple(
                src_ip=packet['src_ip'],
                src_port=packet['src_port'],
                dst_ip=packet['dst_ip'],
                dst_port=packet['dst_port'],
                protocol=packet['protocol']
            )

            flow = flows[ft]
            flow['five_tuple'] = ft
            flow['packets'].append(packet)
            flow['total_bytes'] += packet.get('frame_len', 0)

            # Update time range
            packet_time = packet['timestamp']
            if not flow['start_time']:
                flow['start_time'] = packet_time
            flow['end_time'] = packet_time

        # Convert to Flow objects
        result = {}
        for ft, flow_data in flows.items():
            result[ft] = Flow(
                five_tuple=flow_data['five_tuple'],
                packets=flow_data['packets'],
                total_bytes=flow_data['total_bytes'],
                start_time=flow_data['start_time'],
                end_time=flow_data['end_time']
            )

        return result

    def get_flow_statistics(self, flow: Flow) -> FlowStats:
        """
        Compute statistics for a single flow

        Args:
            flow: Flow object

        Returns:
            FlowStats with computed metrics
        """
        duration = (flow.end_time - flow.start_time).total_seconds()
        packet_count = len(flow.packets)

        return FlowStats(
            packet_count=packet_count,
            byte_count=flow.total_bytes,
            duration=duration,
            avg_packet_size=flow.total_bytes / packet_count if packet_count > 0 else 0,
            pps=packet_count / duration if duration > 0 else 0,
            bps=(flow.total_bytes * 8) / duration if duration > 0 else 0
        )
