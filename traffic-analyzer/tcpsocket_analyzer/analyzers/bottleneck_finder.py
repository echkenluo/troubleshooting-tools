#!/usr/bin/env python
"""
Bottleneck Finder

Pipeline bottleneck identification engine.
Applies 10 detection rules and identifies primary bottlenecks.

Implements FR-SOCKET-PIPE-001, FR-SOCKET-PIPE-002, FR-SOCKET-PIPE-004, FR-SOCKET-PIPE-007.
"""

from typing import List, Optional
import pandas as pd

from ..models import Bottleneck
from .bottleneck_rules import (
    ALL_RULES, SEND_PATH_RULES, RECV_PATH_RULES,
    BottleneckRuleBase
)


class BottleneckFinder:
    """
    Pipeline bottleneck identification engine

    Applies detection rules to identify bottlenecks in send and receive paths,
    then prioritizes and ranks them by severity.

    Implements:
    - FR-SOCKET-PIPE-001: Send path bottleneck identification (6 points)
    - FR-SOCKET-PIPE-002: Recv path bottleneck identification (4 points)
    - FR-SOCKET-PIPE-004: Primary/secondary bottleneck determination
    - FR-SOCKET-PIPE-007: Optimization action prioritization
    """

    def __init__(self):
        self.rules = ALL_RULES
        self.send_rules = SEND_PATH_RULES
        self.recv_rules = RECV_PATH_RULES

    def find_send_path_bottlenecks(self, df: pd.DataFrame, bandwidth: Optional[float] = None) -> List[Bottleneck]:
        """
        Identify send path bottlenecks

        Send path pipeline:
        App write() → Socket layer → TCP layer → Network layer

        Detection points:
        1. App send limitation
        2. Socket send buffer
        3. TCP write queue
        4. CWND limit
        5. RWND limit
        6. Network bandwidth

        Args:
            df: Client-side DataFrame

        Returns:
            List of detected bottlenecks

        Implements: FR-SOCKET-PIPE-001
        """
        bottlenecks = []

        for rule in self.send_rules:
            try:
                result = rule.detect(df, bandwidth)
                if result:
                    bottlenecks.append(result)
            except Exception as e:
                print(f"Warning: Rule {rule.get_rule_id()} failed: {e}")
                continue

        return bottlenecks

    def find_recv_path_bottlenecks(self, df: pd.DataFrame, bandwidth: Optional[float] = None) -> List[Bottleneck]:
        """
        Identify receive path bottlenecks

        Receive path pipeline:
        Network layer → TCP layer → Socket layer → App read()

        Detection points:
        7. Network receive (loss/delay)
        8. TCP receive buffer
        9. Socket receive buffer
        10. App read limitation

        Args:
            df: Server-side DataFrame

        Returns:
            List of detected bottlenecks

        Implements: FR-SOCKET-PIPE-002
        """
        bottlenecks = []

        for rule in self.recv_rules:
            try:
                result = rule.detect(df, bandwidth)
                if result:
                    bottlenecks.append(result)
            except Exception as e:
                print(f"Warning: Rule {rule.get_rule_id()} failed: {e}")
                continue

        return bottlenecks

    def find_all_bottlenecks(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> List[Bottleneck]:
        """
        Find all bottlenecks in both send and receive paths

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame

        Returns:
            Combined list of all bottlenecks
        """
        send_bottlenecks = self.find_send_path_bottlenecks(client_df)
        recv_bottlenecks = self.find_recv_path_bottlenecks(server_df)

        return send_bottlenecks + recv_bottlenecks

    def identify_primary(self, bottlenecks: List[Bottleneck]) -> Optional[Bottleneck]:
        """
        Identify primary bottleneck from multiple detections

        Ranking criteria:
        1. Severity: CRITICAL > HIGH > MEDIUM > LOW
        2. Pressure: Higher pressure wins if same severity

        Args:
            bottlenecks: List of detected bottlenecks

        Returns:
            Primary bottleneck, or None if no bottlenecks

        Implements: FR-SOCKET-PIPE-004
        """
        if not bottlenecks:
            return None

        # Severity weight mapping
        severity_weight = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }

        # Sort by severity (descending) then pressure (descending)
        primary = max(
            bottlenecks,
            key=lambda b: (severity_weight.get(b.severity, 0), b.pressure)
        )

        return primary

    def rank_priority(self, bottlenecks: List[Bottleneck]) -> List[Bottleneck]:
        """
        Rank bottlenecks by optimization priority

        Priority ranking:
        1. CRITICAL severity first
        2. Within same severity, higher pressure first
        3. Send path before recv path (easier to fix)

        Args:
            bottlenecks: List of detected bottlenecks

        Returns:
            Sorted list by priority (highest first)

        Implements: FR-SOCKET-PIPE-007
        """
        if not bottlenecks:
            return []

        # Severity weight
        severity_weight = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }

        # Path weight (send path slightly preferred)
        path_weight = {
            'SEND': 1.1,
            'RECV': 1.0
        }

        # Sort by composite score
        sorted_bottlenecks = sorted(
            bottlenecks,
            key=lambda b: (
                severity_weight.get(b.severity, 0),
                b.pressure,
                path_weight.get(b.path, 1.0)
            ),
            reverse=True
        )

        return sorted_bottlenecks

    def get_secondary_bottlenecks(
        self,
        bottlenecks: List[Bottleneck],
        primary: Bottleneck,
        max_count: int = 3
    ) -> List[Bottleneck]:
        """
        Get secondary bottlenecks (excluding primary)

        Args:
            bottlenecks: All bottlenecks
            primary: Primary bottleneck
            max_count: Maximum secondary bottlenecks to return

        Returns:
            List of secondary bottlenecks (up to max_count)
        """
        if not bottlenecks or not primary:
            return []

        # Filter out primary
        secondary = [b for b in bottlenecks if b != primary]

        # Rank remaining
        ranked_secondary = self.rank_priority(secondary)

        return ranked_secondary[:max_count]
