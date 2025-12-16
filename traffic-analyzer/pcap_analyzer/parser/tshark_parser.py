#!/usr/bin/env python
"""
Tshark Parser

Uses tshark with fields extraction for accurate TCP analysis.
Single-pass extraction with minimal memory footprint.
"""

import subprocess
import os
import csv
from typing import Iterator, Dict, Any, List
from datetime import datetime
from collections import defaultdict
from ..models import Flow, FiveTuple, FileInfo


class TsharkParser:
    """Tshark-based parser for TCP deep analysis"""

    # tshark fields to extract
    FIELDS = [
        'frame.number',
        'frame.time_epoch',
        'frame.len',
        'ip.src',
        'ip.dst',
        'tcp.srcport',
        'tcp.dstport',
        'tcp.stream',
        'tcp.seq',
        'tcp.ack',
        'tcp.len',
        'tcp.window_size',
        'tcp.flags.syn',
        'tcp.flags.ack',
        'tcp.flags.fin',
        'tcp.flags.reset',
        'tcp.flags.push',
        'tcp.analysis.retransmission',
        'tcp.analysis.fast_retransmission',
        'tcp.analysis.spurious_retransmission',
        'tcp.analysis.duplicate_ack',
        'tcp.analysis.zero_window',
        'tcp.options.sack',
        'tcp.options.sack.dsack',
        'tcp.options.sack.count',
        'tcp.options.mss_val',
        'tcp.options.wscale.shift',
        'tcp.options.timestamp',
        'tcp.options.sack_perm',
    ]

    def __init__(self):
        """Initialize tshark parser"""
        self._check_tshark()

    def _check_tshark(self):
        """Check if tshark is available"""
        try:
            subprocess.run(['tshark', '-v'],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("tshark not found. Please install Wireshark/tshark.")

    def parse_file(self, pcap_path: str, display_filter: str = None) -> Dict[FiveTuple, Flow]:
        """
        Parse PCAP file using tshark and aggregate into flows

        Args:
            pcap_path: Path to PCAP file
            display_filter: Optional tshark display filter

        Returns:
            Dictionary mapping FiveTuple to Flow objects
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        # Build tshark command
        cmd = self._build_tshark_command(pcap_path, display_filter)

        # Execute tshark
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark execution failed: {e.stderr}")

        # Parse CSV output and aggregate into flows
        flows = self._aggregate_packets_to_flows(result.stdout)

        return flows

    def _build_tshark_command(self, pcap_path: str, display_filter: str = None) -> List[str]:
        """Build tshark command with fields extraction"""
        cmd = ['tshark', '-r', pcap_path, '-T', 'fields']

        # Add all fields
        for field in self.FIELDS:
            cmd.extend(['-e', field])

        # CSV formatting
        cmd.extend([
            '-E', 'separator=,',
            '-E', 'quote=d',
            '-E', 'occurrence=f'  # First occurrence only
        ])

        # Add display filter if specified
        if display_filter:
            cmd.extend(['-Y', display_filter])

        return cmd

    def _aggregate_packets_to_flows(self, csv_output: str) -> Dict[FiveTuple, Flow]:
        """
        Aggregate packets into flows based on tcp.stream

        Args:
            csv_output: CSV output from tshark

        Returns:
            Dictionary mapping FiveTuple to Flow
        """
        flows = {}
        stream_to_five_tuple = {}

        reader = csv.reader(csv_output.strip().split('\n'))

        for row in reader:
            if len(row) != len(self.FIELDS):
                continue

            packet = self._parse_csv_row(row)

            if not packet:
                continue

            # Get or create flow based on tcp.stream
            stream_id = packet.get('tcp_stream')
            if stream_id is None:
                continue

            # Create five tuple on first packet of stream
            if stream_id not in stream_to_five_tuple:
                five_tuple = FiveTuple(
                    src_ip=packet['src_ip'],
                    dst_ip=packet['dst_ip'],
                    src_port=packet['src_port'],
                    dst_port=packet['dst_port'],
                    protocol='TCP'
                )
                stream_to_five_tuple[stream_id] = five_tuple
                flows[five_tuple] = Flow(
                    five_tuple=five_tuple,
                    packets=[],
                    total_bytes=0,
                    start_time=packet.get('timestamp'),
                    end_time=packet.get('timestamp')
                )

            # Add packet to flow
            five_tuple = stream_to_five_tuple[stream_id]
            flow = flows[five_tuple]
            flow.packets.append(packet)

            # Update flow stats
            frame_len = packet.get('frame_len', 0)
            flow.total_bytes += frame_len
            if packet.get('timestamp'):
                flow.end_time = packet['timestamp']

        return flows

    def _parse_csv_row(self, row: List[str]) -> Dict[str, Any]:
        """
        Parse a CSV row into packet dictionary

        Args:
            row: CSV row values

        Returns:
            Packet dictionary or None if invalid
        """
        try:
            packet = {}

            for i, field_name in enumerate(self.FIELDS):
                value = row[i].strip() if i < len(row) else ''

                # Map field names to packet keys
                if field_name == 'frame.number':
                    packet['frame_number'] = int(value) if value else None
                elif field_name == 'frame.time_epoch':
                    packet['timestamp'] = datetime.fromtimestamp(float(value)) if value else None
                elif field_name == 'frame.len':
                    packet['frame_len'] = int(value) if value else 0
                elif field_name == 'ip.src':
                    packet['src_ip'] = value if value else None
                elif field_name == 'ip.dst':
                    packet['dst_ip'] = value if value else None
                elif field_name == 'tcp.srcport':
                    packet['src_port'] = int(value) if value else None
                elif field_name == 'tcp.dstport':
                    packet['dst_port'] = int(value) if value else None
                elif field_name == 'tcp.stream':
                    packet['tcp_stream'] = int(value) if value else None
                elif field_name == 'tcp.seq':
                    packet['tcp_seq'] = int(value) if value else None
                elif field_name == 'tcp.ack':
                    packet['tcp_ack'] = int(value) if value else None
                elif field_name == 'tcp.len':
                    packet['tcp_data_len'] = int(value) if value else 0
                elif field_name == 'tcp.window_size':
                    packet['tcp_win'] = int(value) if value else None
                elif field_name == 'tcp.flags.syn':
                    packet['tcp_flags_syn'] = (value == '1')
                elif field_name == 'tcp.flags.ack':
                    packet['tcp_flags_ack'] = (value == '1')
                elif field_name == 'tcp.flags.fin':
                    packet['tcp_flags_fin'] = (value == '1')
                elif field_name == 'tcp.flags.reset':
                    packet['tcp_flags_rst'] = (value == '1')
                elif field_name == 'tcp.flags.push':
                    packet['tcp_flags_psh'] = (value == '1')
                elif field_name == 'tcp.analysis.retransmission':
                    packet['tcp_analysis_retransmission'] = (value == '1')
                elif field_name == 'tcp.analysis.fast_retransmission':
                    packet['tcp_analysis_fast_retransmission'] = (value == '1')
                elif field_name == 'tcp.analysis.spurious_retransmission':
                    packet['tcp_analysis_spurious_retransmission'] = (value == '1')
                elif field_name == 'tcp.analysis.duplicate_ack':
                    packet['tcp_analysis_duplicate_ack'] = (value == '1')
                elif field_name == 'tcp.analysis.zero_window':
                    packet['tcp_analysis_zero_window'] = (value == '1')
                elif field_name == 'tcp.options.sack':
                    packet['tcp_options_sack'] = (value == '1')
                elif field_name == 'tcp.options.sack.dsack':
                    packet['tcp_options_sack_dsack'] = (value == '1')
                elif field_name == 'tcp.options.sack.count':
                    packet['tcp_options_sack_count'] = int(value) if value else 0
                elif field_name == 'tcp.options.mss_val':
                    packet['tcp_options_mss_val'] = int(value) if value else None
                elif field_name == 'tcp.options.wscale.shift':
                    packet['tcp_options_wscale_shift'] = int(value) if value else None
                    packet['tcp_options_wscale'] = (value != '')
                elif field_name == 'tcp.options.timestamp':
                    packet['tcp_options_timestamp'] = (value == '1')
                elif field_name == 'tcp.options.sack_perm':
                    packet['tcp_options_sack_perm'] = (value == '1')

            # Add tcp_flags dict for compatibility
            packet['tcp_flags'] = {
                'syn': packet.get('tcp_flags_syn', False),
                'ack': packet.get('tcp_flags_ack', False),
                'fin': packet.get('tcp_flags_fin', False),
                'rst': packet.get('tcp_flags_rst', False),
                'psh': packet.get('tcp_flags_psh', False),
            }

            # Set protocol
            packet['protocol'] = 'TCP'

            return packet

        except (ValueError, IndexError) as e:
            return None

    def get_file_info(self, pcap_path: str) -> FileInfo:
        """
        Get PCAP file information using tshark capinfos

        Args:
            pcap_path: Path to PCAP file

        Returns:
            FileInfo object
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            # Use capinfos for quick stats
            result = subprocess.run(
                ['capinfos', '-T', pcap_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )

            lines = result.stdout.strip().split('\n')
            info = {}
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    info[key.strip()] = value.strip()

            # Extract relevant fields
            file_size = os.path.getsize(pcap_path)
            packet_count = int(info.get('Number of packets', 0))

            # Parse timestamps if available
            first_packet_time = None
            last_packet_time = None
            duration = 0.0

            if 'First packet time' in info:
                # Parse timestamp (format varies, use tshark as fallback)
                pass

            return FileInfo(
                file_path=pcap_path,
                file_size=file_size,
                packet_count=packet_count,
                first_packet_time=first_packet_time,
                last_packet_time=last_packet_time,
                duration=duration
            )

        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: just get file size
            return FileInfo(
                file_path=pcap_path,
                file_size=os.path.getsize(pcap_path),
                packet_count=0
            )
