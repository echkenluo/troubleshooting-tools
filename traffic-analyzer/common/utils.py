#!/usr/bin/env python
"""
Common Utilities

Shared utility functions for both PCAP and TCP Socket analyzers.
"""

import sys
from datetime import datetime
from typing import Any, Dict


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count as human-readable string

    Args:
        bytes_count: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB", "2.3 GB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_rate(bps: float) -> str:
    """
    Format bit rate as human-readable string

    Args:
        bps: Bits per second

    Returns:
        Formatted string (e.g., "10.5 Mbps", "1.2 Gbps")
    """
    for unit in ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps']:
        if bps < 1000.0:
            return f"{bps:.2f} {unit}"
        bps /= 1000.0
    return f"{bps:.2f} Pbps"


def format_duration(seconds: float) -> str:
    """
    Format duration as human-readable string

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "1h 23m 45s", "45.2s")
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.0f}s"


def print_error(message: str) -> None:
    """
    Print error message to stderr

    Args:
        message: Error message to display
    """
    print(f"ERROR: {message}", file=sys.stderr)


def print_warning(message: str) -> None:
    """
    Print warning message to stderr

    Args:
        message: Warning message to display
    """
    print(f"WARNING: {message}", file=sys.stderr)


def print_info(message: str) -> None:
    """
    Print informational message to stdout

    Args:
        message: Info message to display
    """
    print(f"INFO: {message}")


def validate_file_path(file_path: str) -> bool:
    """
    Check if file exists and is readable

    Args:
        file_path: Path to file

    Returns:
        True if file exists and is readable, False otherwise
    """
    import os
    return os.path.isfile(file_path) and os.access(file_path, os.R_OK)


def validate_directory(dir_path: str) -> bool:
    """
    Check if directory exists and is readable

    Args:
        dir_path: Path to directory

    Returns:
        True if directory exists and is readable, False otherwise
    """
    import os
    return os.path.isdir(dir_path) and os.access(dir_path, os.R_OK)
