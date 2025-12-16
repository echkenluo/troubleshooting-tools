#!/usr/bin/env python
"""
PCAP Parser

Uses dpkt library to parse PCAP files with high-performance streaming processing.
Implements FR-PCAP-SUM-001.
"""

import dpkt
import socket
import os
from typing import Iterator, Optional, Dict, Any
from datetime import datetime
from ..models import FileInfo


class PcapParser:
    """PCAP file parser using dpkt library for high-performance parsing"""

    def __init__(self):
        """Initialize PCAP parser"""
        pass

    def parse_file(self,
                   pcap_path: str,
                   fields: Optional[list] = None,
                   filters: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        """
        Parse PCAP file and return packet iterator (streaming mode)

        Design notes:
        - Uses dpkt for native Python parsing (10x faster than tshark)
        - Streaming processing to avoid memory overflow
        - In-memory filtering support
        - Supports multiple link types: Ethernet (1), SLL (113), SLL2 (276)

        Args:
            pcap_path: Path to PCAP file
            fields: Not used (compatibility parameter)
            filters: Not used (compatibility parameter)

        Yields:
            Packet dictionaries
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                linktype = pcap.datalink()

                for ts, buf in pcap:
                    packet = self._parse_packet(ts, buf, linktype)
                    if packet:
                        yield packet

        except Exception as e:
            raise RuntimeError(f"Error parsing PCAP file: {e}")

    def _parse_packet(self, timestamp: float, buf: bytes, linktype: int = 1) -> Optional[Dict[str, Any]]:
        """
        Parse a single packet from raw bytes

        Args:
            timestamp: Unix timestamp (seconds since epoch)
            buf: Raw packet bytes
            linktype: PCAP link type (1=Ethernet, 113=SLL, 276=SLL2)

        Returns:
            Normalized packet dictionary or None if invalid
        """
        try:
            # Convert timestamp to datetime
            dt = datetime.fromtimestamp(timestamp)

            # Parse link layer based on linktype
            eth_type_raw = None
            if linktype == 113:
                # Linux cooked capture (SLL)
                sll = dpkt.sll.SLL(buf)
                frame_len = len(buf)
                ip_data = sll.data
                eth_type_raw = sll.ethtype
            elif linktype == 276:
                # Linux cooked capture v2 (SLL2)
                import struct
                if len(buf) >= 2:
                    eth_type_raw = struct.unpack('!H', buf[0:2])[0]
                ip_data = self._parse_sll2(buf)
                frame_len = len(buf)
            else:
                # Default: Ethernet (linktype 1)
                eth = dpkt.ethernet.Ethernet(buf)
                frame_len = len(buf)
                ip_data = eth.data
                eth_type_raw = eth.type

            # Initialize fields
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None
            protocol = None
            ip_version = None
            eth_type = None
            tcp_flags = None
            tcp_seq = None
            tcp_ack = None
            tcp_win = None
            tcp_data_len = 0

            # Parse IP layer
            if isinstance(ip_data, dpkt.ip.IP):
                ip = ip_data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                ip_version = 'IPv4'
                eth_type = 'IPv4'

                # Parse TCP
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    protocol = 'TCP'

                    # Extract TCP flags
                    tcp_flags = {
                        'syn': bool(tcp.flags & dpkt.tcp.TH_SYN),
                        'ack': bool(tcp.flags & dpkt.tcp.TH_ACK),
                        'fin': bool(tcp.flags & dpkt.tcp.TH_FIN),
                        'rst': bool(tcp.flags & dpkt.tcp.TH_RST),
                        'psh': bool(tcp.flags & dpkt.tcp.TH_PUSH),
                    }

                    # Extract TCP analysis fields for retransmission detection
                    tcp_seq = tcp.seq
                    tcp_ack = tcp.ack
                    tcp_win = tcp.win
                    tcp_data_len = len(tcp.data)

                    # Try to identify application protocol
                    if len(tcp.data) > 0:
                        protocol = self._identify_app_protocol(tcp, src_port, dst_port)

                # Parse UDP
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    protocol = 'UDP'

                    # Try to identify application protocol
                    if len(udp.data) > 0:
                        protocol = self._identify_udp_protocol(udp, src_port, dst_port)

                # Parse ICMP
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    protocol = 'ICMP'

                # Other IP protocols
                else:
                    protocol = f'IP_PROTO_{ip.p}'

            # Parse IPv6
            elif isinstance(ip_data, dpkt.ip6.IP6):
                ip6 = ip_data
                src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                protocol = 'IPv6'
                ip_version = 'IPv6'
                eth_type = 'IPv6'

            # Parse ARP
            elif isinstance(ip_data, dpkt.arp.ARP):
                protocol = 'ARP'
                eth_type = 'ARP'
                ip_version = 'ARP'

            # Other protocols - show raw EtherType value
            else:
                if eth_type_raw is not None:
                    protocol = f'ETH_0x{eth_type_raw:04X}'
                    eth_type = f'ETH_0x{eth_type_raw:04X}'
                    ip_version = f'ETH_0x{eth_type_raw:04X}'
                else:
                    protocol = 'UNKNOWN'
                    eth_type = 'UNKNOWN'

            return {
                'timestamp': dt,
                'frame_len': frame_len,
                'protocol': protocol,
                'ip_version': ip_version,
                'eth_type': eth_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'tcp_flags': tcp_flags,
                'tcp_seq': tcp_seq,
                'tcp_ack': tcp_ack,
                'tcp_win': tcp_win,
                'tcp_data_len': tcp_data_len,
                'raw_data': {'ip_data': ip_data, 'buf': buf}  # Store raw data for detailed analysis
            }

        except Exception as e:
            # Skip malformed packets
            return None

    def _parse_sll2(self, buf: bytes):
        """
        Parse Linux cooked capture v2 (SLL2) header

        SLL2 structure (20 bytes):
        - Protocol type (2 bytes, network byte order)
        - Reserved (2 bytes)
        - Interface index (4 bytes)
        - ARPHRD type (2 bytes)
        - Packet type (1 byte)
        - Address length (1 byte)
        - Address (8 bytes)

        Args:
            buf: Raw packet bytes

        Returns:
            IP layer data
        """
        import struct

        # Skip SLL2 header (20 bytes) and parse protocol
        if len(buf) < 20:
            return None

        # Extract protocol type (bytes 0-1, network byte order)
        proto_type = struct.unpack('!H', buf[0:2])[0]

        # Extract IP data (after 20-byte SLL2 header)
        ip_buf = buf[20:]

        # Parse based on protocol type
        if proto_type == 0x0800:  # IPv4
            return dpkt.ip.IP(ip_buf)
        elif proto_type == 0x86dd:  # IPv6
            return dpkt.ip6.IP6(ip_buf)
        elif proto_type == 0x0806:  # ARP
            return dpkt.arp.ARP(ip_buf)
        else:
            # Unknown protocol, return raw bytes
            return ip_buf

    def _identify_app_protocol(self, tcp, src_port: int, dst_port: int) -> str:
        """
        Identify application protocol from TCP packet

        Args:
            tcp: TCP packet
            src_port: Source port
            dst_port: Destination port

        Returns:
            Protocol name string
        """
        # Common port-based detection
        ports = {
            80: 'HTTP',
            443: 'TLS',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            53: 'DNS',
            3306: 'MYSQL',
            5432: 'POSTGRESQL',
            6379: 'REDIS',
            27017: 'MONGO',
            9200: 'ELASTICSEARCH',
            5201: 'IPERF3',
            2379: 'ETCD',
            2380: 'ETCD',
            6443: 'KUBERNETES',
        }

        # Check well-known ports
        if src_port in ports:
            return ports[src_port]
        if dst_port in ports:
            return ports[dst_port]

        # Payload-based detection
        try:
            data = tcp.data
            if len(data) > 0:
                # HTTP detection
                if data[:4] in [b'GET ', b'POST', b'PUT ', b'DEL', b'HEAD', b'HTTP']:
                    return 'HTTP'
                # TLS detection
                if len(data) >= 3 and data[0] == 0x16 and data[1] == 0x03:
                    return 'TLS'
                # SSH detection
                if data[:4] == b'SSH-':
                    return 'SSH'
        except:
            pass

        return 'TCP'

    def _identify_udp_protocol(self, udp, src_port: int, dst_port: int) -> str:
        """
        Identify application protocol from UDP packet

        Args:
            udp: UDP packet
            src_port: Source port
            dst_port: Destination port

        Returns:
            Protocol name string
        """
        # Common port-based detection
        ports = {
            53: 'DNS',
            123: 'NTP',
            161: 'SNMP',
            162: 'SNMP',
            514: 'SYSLOG',
            67: 'DHCP',
            68: 'DHCP',
        }

        # Check well-known ports
        if src_port in ports:
            return ports[src_port]
        if dst_port in ports:
            return ports[dst_port]

        return 'UDP'

    def get_file_info(self, pcap_path: str) -> FileInfo:
        """
        Get PCAP file information by reading the file

        Args:
            pcap_path: Path to PCAP file

        Returns:
            FileInfo object with file statistics
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        try:
            file_size = os.path.getsize(pcap_path)

            # Quick scan to get packet count and timestamps
            packet_count = 0
            first_packet_time = None
            last_packet_time = None

            with open(pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)

                for ts, buf in pcap:
                    packet_count += 1

                    if first_packet_time is None:
                        first_packet_time = datetime.fromtimestamp(ts)

                    last_packet_time = datetime.fromtimestamp(ts)

            # Calculate duration
            duration = 0.0
            if first_packet_time and last_packet_time:
                duration = (last_packet_time - first_packet_time).total_seconds()

            return FileInfo(
                file_path=pcap_path,
                file_size=file_size,
                packet_count=packet_count,
                first_packet_time=first_packet_time,
                last_packet_time=last_packet_time,
                duration=duration
            )

        except Exception as e:
            # Fallback: get basic info from file system
            return FileInfo(
                file_path=pcap_path,
                file_size=os.path.getsize(pcap_path),
                packet_count=0
            )
