#!/usr/bin/env python
"""
Bandwidth Parser

Parses bandwidth strings and converts to bits per second.
Implements FR-SOCKET-SUM-012.
"""

import re
from typing import Optional


class BandwidthParser:
    """Bandwidth string parser"""

    # Conversion factors to bits per second
    UNITS = {
        'bps': 1,
        'kbps': 1000,
        'mbps': 1000 * 1000,
        'gbps': 1000 * 1000 * 1000,
        'tbps': 1000 * 1000 * 1000 * 1000,
        # Binary units
        'kibps': 1024,
        'mibps': 1024 * 1024,
        'gibps': 1024 * 1024 * 1024,
    }

    def parse(self, bandwidth_str: str) -> float:
        """
        Parse bandwidth string to bits per second

        Supported formats:
        - "1gbps", "1 Gbps", "1 GBPS"
        - "100mbps", "100 Mbps"
        - "10kbps", "10 Kbps"
        - "1000bps", "1000 bps"
        - Numbers without units assumed to be bps

        Args:
            bandwidth_str: Bandwidth string

        Returns:
            Bandwidth in bits per second

        Raises:
            ValueError: If format is invalid

        Implements: FR-SOCKET-SUM-012
        """
        # Normalize: remove spaces and convert to lowercase
        normalized = bandwidth_str.strip().lower().replace(' ', '')

        # Try to match pattern: number + optional unit
        pattern = r'^(\d+\.?\d*)([a-z]*)$'
        match = re.match(pattern, normalized)

        if not match:
            raise ValueError(f"Invalid bandwidth format: {bandwidth_str}")

        value_str, unit_str = match.groups()
        value = float(value_str)

        # Default to bps if no unit specified
        if not unit_str:
            unit_str = 'bps'

        # Look up conversion factor
        if unit_str not in self.UNITS:
            raise ValueError(f"Unknown bandwidth unit: {unit_str}")

        return value * self.UNITS[unit_str]

    def validate(self, bandwidth_str: str) -> bool:
        """
        Validate bandwidth string format

        Args:
            bandwidth_str: Bandwidth string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            self.parse(bandwidth_str)
            return True
        except ValueError:
            return False

    def format(self, bps: float) -> str:
        """
        Format bits per second as human-readable string

        Args:
            bps: Bits per second

        Returns:
            Formatted string (e.g., "1.5 Gbps")
        """
        if bps >= self.UNITS['tbps']:
            return f"{bps / self.UNITS['tbps']:.2f} Tbps"
        elif bps >= self.UNITS['gbps']:
            return f"{bps / self.UNITS['gbps']:.2f} Gbps"
        elif bps >= self.UNITS['mbps']:
            return f"{bps / self.UNITS['mbps']:.2f} Mbps"
        elif bps >= self.UNITS['kbps']:
            return f"{bps / self.UNITS['kbps']:.2f} Kbps"
        else:
            return f"{bps:.0f} bps"
