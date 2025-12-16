#!/usr/bin/env python
"""
Bottleneck Detection Rules

Implements 10 rules for pipeline bottleneck detection:
- Send path: 6 rules (App → Socket → TCP → Network)
- Recv path: 4 rules (Network → TCP → Socket → App)

Implements FR-SOCKET-PIPE-003.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import pandas as pd

from ..models import Bottleneck


class BottleneckRuleBase(ABC):
    """
    Base class for bottleneck detection rules

    Each rule detects a specific bottleneck in the TCP pipeline
    """

    rule_id: str = ""
    rule_name: str = ""
    path: str = ""  # SEND or RECV

    @abstractmethod
    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detect bottleneck based on data

        Args:
            data: DataFrame with socket metrics

        Returns:
            Bottleneck object if detected, None otherwise
        """
        pass

    def get_rule_id(self) -> str:
        return self.rule_id

    def get_description(self) -> str:
        return self.rule_name


# ============================================================================
# SEND PATH RULES (6 rules)
# ============================================================================

class AppSendLimitRule(BottleneckRuleBase):
    """
    Rule 1: Application send limitation detection

    Detects when application is not sending enough data to fill the pipe
    """

    rule_id = "APP_SEND_LIMIT"
    rule_name = "Application Send Limitation"
    path = "SEND"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection logic:
        - Delivery rate << bandwidth (< 50%)
        - CWND not limited
        - No buffer pressure

        This indicates app is not sending fast enough
        """
        if data.empty:
            return None

        # Check if delivery rate data is available
        if 'delivery_rate' not in data.columns:
            return None

        avg_delivery_rate = data['delivery_rate'].mean()

        # Heuristic: If delivery rate is very low and no other bottleneck
        if avg_delivery_rate < 1e6:  # < 1 Mbps suggests app-limited
            return Bottleneck(
                location="APP_SEND",
                path="SEND",
                pressure=0.3,
                severity="MEDIUM",
                description="Application not sending data fast enough",
                evidence={
                    'avg_delivery_rate': avg_delivery_rate,
                    'pattern': 'Low sustained throughput'
                }
            )

        return None


class SocketTxBufferRule(BottleneckRuleBase):
    """
    Rule 2: Socket send buffer bottleneck detection

    Detects when socket send buffer is full
    """

    rule_id = "SOCKET_TX_BUFFER"
    rule_name = "Socket Send Buffer Full"
    path = "SEND"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: socket_tx_queue > 90% socket_tx_buffer
        """
        if 'socket_tx_queue' not in data.columns or 'socket_tx_buffer' not in data.columns:
            return None

        avg_queue = data['socket_tx_queue'].mean()
        buffer_limit = data['socket_tx_buffer'].iloc[0] if len(data) > 0 else 0
        utilization = avg_queue / buffer_limit if buffer_limit > 0 else 0

        if utilization < 0.7:
            return None

        severity = 'CRITICAL' if utilization > 0.9 else 'HIGH' if utilization > 0.8 else 'MEDIUM'

        return Bottleneck(
            location="SEND_BUFFER",
            path="SEND",
            pressure=utilization,
            severity=severity,
            description=f"Send buffer utilization at {utilization*100:.1f}%",
            evidence={
                'avg_queue': avg_queue,
                'buffer_limit': buffer_limit,
                'utilization': utilization,
                'recommendation': f"Increase send buffer: sysctl -w net.ipv4.tcp_wmem=\"4096 16384 {int(buffer_limit * 1.5)}\""
            }
        )


class TCPWriteQueueRule(BottleneckRuleBase):
    """
    Rule 3: TCP write queue bottleneck detection

    Detects when TCP write queue has backlog
    """

    rule_id = "TCP_WRITE_QUEUE"
    rule_name = "TCP Write Queue Backlog"
    path = "SEND"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: packets_out close to limit
        """
        if 'packets_out' not in data.columns:
            return None

        avg_packets_out = data['packets_out'].mean()

        # Heuristic: If sustained high packets_out
        if avg_packets_out > 100:
            utilization = min(avg_packets_out / 200, 1.0)
            severity = 'HIGH' if avg_packets_out > 150 else 'MEDIUM'

            return Bottleneck(
                location="TCP_WRITE_QUEUE",
                path="SEND",
                pressure=utilization,
                severity=severity,
                description=f"TCP write queue backlog: {avg_packets_out:.0f} packets out",
                evidence={
                    'avg_packets_out': avg_packets_out
                }
            )

        return None


class CwndLimitRule(BottleneckRuleBase):
    """
    Rule 4: CWND limitation detection

    Detects when congestion window limits throughput
    """

    rule_id = "CWND_LIMIT"
    rule_name = "Congestion Window Limited"
    path = "SEND"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: packets_out >= 95% CWND
        """
        if 'packets_out' not in data.columns or 'cwnd' not in data.columns:
            return None

        cwnd_limited = (data['packets_out'] >= data['cwnd'] * 0.95)
        cwnd_limited_ratio = cwnd_limited.sum() / len(data) if len(data) > 0 else 0

        if cwnd_limited_ratio < 0.5:
            return None

        severity = 'CRITICAL' if cwnd_limited_ratio > 0.8 else 'HIGH' if cwnd_limited_ratio > 0.6 else 'MEDIUM'

        avg_cwnd = data['cwnd'].mean()
        avg_ssthresh = data['ssthresh'].mean() if 'ssthresh' in data.columns else 0

        return Bottleneck(
            location="CWND",
            path="SEND",
            pressure=cwnd_limited_ratio,
            severity=severity,
            description=f"CWND limited {cwnd_limited_ratio*100:.1f}% of time",
            evidence={
                'cwnd_limited_ratio': cwnd_limited_ratio,
                'avg_cwnd': avg_cwnd,
                'avg_ssthresh': avg_ssthresh,
                'recommendation': 'Check for packet loss or increase initial CWND'
            }
        )


class RwndLimitRule(BottleneckRuleBase):
    """
    Rule 5: RWND (receiver window) limitation detection

    Detects when receiver window limits throughput
    """

    rule_id = "RWND_LIMIT"
    rule_name = "Receiver Window Limited"
    path = "SEND"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: RWND < CWND frequently
        """
        if 'rwnd' not in data.columns or 'cwnd' not in data.columns:
            return None

        rwnd_limited = (data['rwnd'] < data['cwnd'])
        rwnd_limited_ratio = rwnd_limited.sum() / len(data) if len(data) > 0 else 0

        if rwnd_limited_ratio < 0.3:
            return None

        severity = 'HIGH' if rwnd_limited_ratio > 0.7 else 'MEDIUM'
        avg_rwnd = data['rwnd'].mean()

        return Bottleneck(
            location="RWND",
            path="SEND",
            pressure=rwnd_limited_ratio,
            severity=severity,
            description=f"RWND limited {rwnd_limited_ratio*100:.1f}% of time",
            evidence={
                'rwnd_limited_ratio': rwnd_limited_ratio,
                'avg_rwnd': avg_rwnd,
                'recommendation': 'Increase receiver buffer on peer: net.ipv4.tcp_rmem'
            }
        )


class NetworkBandwidthRule(BottleneckRuleBase):
    """
    Rule 6: Network bandwidth limitation detection

    Detects when network bandwidth is the bottleneck
    """

    rule_id = "NETWORK_BANDWIDTH"
    rule_name = "Network Bandwidth Limited"
    path = "SEND"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """Detection: delivery_rate approaches configured bandwidth"""
        if 'delivery_rate' not in data.columns or bandwidth is None or bandwidth <= 0:
            return None

        max_delivery_rate = data['delivery_rate'].max()
        avg_delivery_rate = data['delivery_rate'].mean()

        utilization = avg_delivery_rate / bandwidth if bandwidth else 0.0

        if utilization >= 0.9:
            severity = 'CRITICAL' if utilization > 0.98 else 'HIGH'
            return Bottleneck(
                location="NETWORK",
                path="SEND",
                pressure=min(utilization, 1.0),
                severity=severity,
                description=f"Network bandwidth saturated at {avg_delivery_rate/1e9:.2f} Gbps",
                evidence={
                    'avg_delivery_rate': avg_delivery_rate,
                    'max_delivery_rate': max_delivery_rate,
                    'bandwidth': bandwidth,
                    'utilization': utilization,
                    'recommendation': 'Network capacity upgrade or LAG/ECMP'
                }
            )

        return None


# ============================================================================
# RECV PATH RULES (4 rules)
# ============================================================================

class NetworkRecvRule(BottleneckRuleBase):
    """
    Rule 7: Network receive bottleneck detection

    Detects network issues on receive path (packet loss, delay)
    """

    rule_id = "NETWORK_RECV"
    rule_name = "Network Receive Issues"
    path = "RECV"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: High retransmission rate or RTT variance
        """
        if 'retrans_rate' not in data.columns:
            return None

        avg_retrans_rate = data['retrans_rate'].mean()

        if avg_retrans_rate > 0.01:  # > 1% retransmission rate
            severity = 'CRITICAL' if avg_retrans_rate > 0.05 else 'HIGH' if avg_retrans_rate > 0.02 else 'MEDIUM'

            return Bottleneck(
                location="NETWORK",
                path="RECV",
                pressure=min(avg_retrans_rate * 20, 1.0),
                severity=severity,
                description=f"Network issues: {avg_retrans_rate*100:.2f}% retransmission rate",
                evidence={
                    'avg_retrans_rate': avg_retrans_rate,
                    'recommendation': 'Check network path for packet loss or congestion'
                }
            )

        return None


class TCPRxBufferRule(BottleneckRuleBase):
    """
    Rule 8: TCP receive buffer bottleneck detection

    Detects when TCP receive queue is full
    """

    rule_id = "TCP_RX_BUFFER"
    rule_name = "TCP Receive Buffer Full"
    path = "RECV"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: TCP receive queue approaching limit
        """
        if 'socket_rx_queue' not in data.columns or 'socket_rx_buffer' not in data.columns:
            return None

        buf = data['socket_rx_buffer'].mean() if len(data) else 0
        if buf <= 0:
            return None

        pressure_series = data['socket_rx_queue'] / data['socket_rx_buffer']
        pressure = pressure_series.mean()

        if pressure < 0.7:
            return None

        severity = 'CRITICAL' if pressure > 0.9 else 'HIGH' if pressure > 0.8 else 'MEDIUM'

        return Bottleneck(
            location="TCP_RX_BUFFER",
            path="RECV",
            pressure=pressure,
            severity=severity,
            description=f"TCP receive buffer pressure {pressure*100:.1f}%",
            evidence={
                'avg_rx_queue': data['socket_rx_queue'].mean(),
                'avg_rx_buffer': buf,
                'recommendation': 'Increase tcp_rmem and ensure application drains socket'
            }
        )


class SocketRxBufferRule(BottleneckRuleBase):
    """
    Rule 9: Socket receive buffer bottleneck detection

    Detects when socket receive buffer is full
    """

    rule_id = "SOCKET_RX_BUFFER"
    rule_name = "Socket Receive Buffer Full"
    path = "RECV"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: socket_rx_queue > 90% socket_rx_buffer
        """
        if 'socket_rx_queue' not in data.columns or 'socket_rx_buffer' not in data.columns:
            return None

        avg_queue = data['socket_rx_queue'].mean()
        buffer_limit = data['socket_rx_buffer'].iloc[0] if len(data) > 0 else 0
        utilization = avg_queue / buffer_limit if buffer_limit > 0 else 0

        if utilization < 0.7:
            return None

        severity = 'CRITICAL' if utilization > 0.9 else 'HIGH' if utilization > 0.8 else 'MEDIUM'

        return Bottleneck(
            location="RECV_BUFFER",
            path="RECV",
            pressure=utilization,
            severity=severity,
            description=f"Receive buffer utilization at {utilization*100:.1f}%",
            evidence={
                'avg_queue': avg_queue,
                'buffer_limit': buffer_limit,
                'utilization': utilization,
                'recommendation': f"Increase receive buffer: sysctl -w net.ipv4.tcp_rmem=\"4096 87380 {int(buffer_limit * 1.5)}\""
            }
        )


class AppReadLimitRule(BottleneckRuleBase):
    """
    Rule 10: Application read limitation detection

    Detects when application is not reading fast enough from socket
    """

    rule_id = "APP_READ_LIMIT"
    rule_name = "Application Read Limitation"
    path = "RECV"

    def detect(self, data: pd.DataFrame, bandwidth: Optional[float] = None) -> Optional[Bottleneck]:
        """
        Detection condition: Sustained receive buffer pressure
        """
        if 'socket_rx_queue' not in data.columns or 'socket_rx_buffer' not in data.columns:
            return None

        rx_queue = data['socket_rx_queue']
        rx_buffer = data['socket_rx_buffer']

        # Check sustained pressure
        pressure_ratio = (rx_queue / rx_buffer).fillna(0)
        sustained_pressure = (pressure_ratio > 0.5).sum() / len(data) if len(data) > 0 else 0

        if sustained_pressure > 0.5:  # > 50% of time
            severity = 'HIGH' if sustained_pressure > 0.8 else 'MEDIUM'

            return Bottleneck(
                location="APP_RECV",
                path="RECV",
                pressure=sustained_pressure,
                severity=severity,
                description=f"Application not reading fast enough: {sustained_pressure*100:.1f}% time with pressure",
                evidence={
                    'sustained_pressure': sustained_pressure,
                    'recommendation': 'Optimize application read() calls or use larger buffers'
                }
            )

        return None


# ============================================================================
# Rule Registry
# ============================================================================

ALL_RULES = [
    # Send path (6 rules)
    AppSendLimitRule(),
    SocketTxBufferRule(),
    TCPWriteQueueRule(),
    CwndLimitRule(),
    RwndLimitRule(),
    NetworkBandwidthRule(),
    # Recv path (4 rules)
    NetworkRecvRule(),
    TCPRxBufferRule(),
    SocketRxBufferRule(),
    AppReadLimitRule(),
]

SEND_PATH_RULES = ALL_RULES[:6]
RECV_PATH_RULES = ALL_RULES[6:10]
