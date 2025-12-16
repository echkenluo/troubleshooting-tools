#!/usr/bin/env python
"""
PCAP Analyzer Data Models

This module defines all data structures used in PCAP analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum


# ==================== Basic Data Structures ====================

@dataclass
class Packet:
    """Represents a single network packet"""
    timestamp: datetime
    frame_len: int
    protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[Dict[str, bool]] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FiveTuple:
    """TCP/UDP five-tuple for flow identification"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str

    def __hash__(self):
        return hash((self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, FiveTuple):
            return False
        return (self.src_ip == other.src_ip and
                self.src_port == other.src_port and
                self.dst_ip == other.dst_ip and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)


@dataclass
class Flow:
    """Network flow aggregated by five-tuple"""
    five_tuple: FiveTuple
    packets: List[Packet]
    total_bytes: int
    start_time: datetime
    end_time: datetime


# ==================== Statistics Results ====================

@dataclass
class L2Stats:
    """Layer 2 statistics"""
    ethernet_types: Dict[str, int]
    frame_size_distribution: Dict[str, int]
    total_frames: int


@dataclass
class L3Stats:
    """Layer 3 statistics"""
    ip_versions: Dict[str, int]
    protocol_distribution: Dict[str, int]
    total_packets: int


@dataclass
class L4Stats:
    """Layer 4 statistics"""
    tcp_packets: int
    tcp_bytes: int
    udp_packets: int
    udp_bytes: int
    other_packets: int
    other_bytes: int
    total_bytes: int


@dataclass
class FlowStats:
    """Flow statistics"""
    packet_count: int
    byte_count: int
    duration: float  # seconds
    avg_packet_size: float
    pps: float  # packets per second
    bps: float  # bits per second


@dataclass
class TimeSeriesStats:
    """Time series statistics"""
    interval: float  # seconds
    timestamps: List[datetime]
    pps_series: List[float]
    bps_series: List[float]
    avg_pps: float
    peak_pps: float
    avg_bps: float
    peak_bps: float


@dataclass
class TopTalkersResult:
    """Top talkers analysis result"""
    top_senders: List[Tuple[str, int]]  # (IP, bytes)
    top_receivers: List[Tuple[str, int]]
    top_conversations: List[Tuple[str, str, int]]  # (src_ip, dst_ip, bytes)


# ==================== TCP Analysis Results ====================

@dataclass
class RetransStats:
    """TCP retransmission statistics"""
    total_packets: int
    retrans_packets: int
    retrans_rate: float
    fast_retrans: int
    timeout_retrans: int
    spurious_retrans: int


@dataclass
class DupACKStats:
    """Duplicate ACK statistics"""
    total_dupack: int
    dupack_rate: float
    max_consecutive_dupack: int
    avg_dupack_per_flow: float


@dataclass
class ZeroWindowStats:
    """Zero Window statistics"""
    zero_window_events: int
    total_duration: float  # seconds
    avg_duration: float
    max_duration: float


@dataclass
class SACKStats:
    """SACK statistics"""
    sack_enabled: bool
    sack_packets: int
    dsack_packets: int
    avg_sack_blocks: float


@dataclass
class TCPFeatures:
    """TCP features negotiated"""
    window_scaling: bool
    window_scale_factor: int
    timestamps: bool
    sack_permitted: bool
    mss: int


# ==================== Problem Detection ====================

class ProblemType(Enum):
    """Network problem types"""
    HIGH_LATENCY = "HIGH_LATENCY"
    PACKET_LOSS = "PACKET_LOSS"
    OUT_OF_ORDER = "OUT_OF_ORDER"
    WINDOW_ISSUES = "WINDOW_ISSUES"
    HANDSHAKE_FAILURE = "HANDSHAKE_FAILURE"
    CONNECTION_RESET = "CONNECTION_RESET"
    RETRANS_BURST = "RETRANS_BURST"


class Severity(Enum):
    """Problem severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    WARNING = "WARNING"
    LOW = "LOW"


@dataclass
class Problem:
    """Network problem"""
    type: ProblemType
    severity: Severity
    description: str
    evidence: Dict[str, Any]


@dataclass
class BurstEvent:
    """Burst event (e.g., retransmission burst)"""
    start_time: datetime
    end_time: datetime
    packet_count: int
    severity: Severity


@dataclass
class PossibleCause:
    """Possible cause of a problem"""
    cause: str
    confidence: float  # 0-1
    evidence: List[str]


@dataclass
class Recommendation:
    """Optimization recommendation"""
    action: str
    priority: str  # HIGH/MEDIUM/LOW
    description: str


@dataclass
class ProblemClass:
    """Problem classification"""
    category: str
    severity: Severity
    priority: int


# ==================== File Information ====================

@dataclass
class FileInfo:
    """PCAP file information"""
    file_path: str
    file_size: int
    packet_count: int
    first_packet_time: Optional[datetime] = None
    last_packet_time: Optional[datetime] = None
    duration: float = 0.0  # seconds
