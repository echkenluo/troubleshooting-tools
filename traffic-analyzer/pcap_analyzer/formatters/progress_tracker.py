#!/usr/bin/env python
"""
Progress Tracker

Displays progress bar for large file processing.
Implements FR-PCAP-SUM-007.
"""

from datetime import datetime
from typing import Optional


class ProgressTracker:
    """Progress tracking and display for long-running operations"""

    def __init__(self):
        """Initialize progress tracker"""
        self.total = 0
        self.current = 0
        self.start_time = None

    def set_total(self, total: int) -> None:
        """
        Set total number of items to process

        Args:
            total: Total number of items
        """
        self.total = total
        self.start_time = datetime.now()

    def update(self, current: int, total: Optional[int] = None, message: str = "") -> None:
        """
        Update progress display

        Display format:
        [################------------] 55% | 1234/2000 | ETA: 00:23 | Parsing...

        Args:
            current: Current progress count
            total: Optional total count (updates self.total if provided)
            message: Optional message to display
        """
        if total is not None:
            self.total = total

        self.current = current

        # Calculate percentage
        percentage = (current / self.total * 100) if self.total > 0 else 0

        # Calculate ETA
        if self.start_time and current > 0:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            eta = (elapsed / current * (self.total - current)) if current > 0 else 0
        else:
            eta = 0

        # Build progress bar
        bar_length = 40
        filled_length = int(bar_length * current // self.total) if self.total > 0 else 0
        bar = '#' * filled_length + '-' * (bar_length - filled_length)

        # Format ETA as MM:SS
        eta_minutes = int(eta // 60)
        eta_seconds = int(eta % 60)

        # Print progress (overwrite previous line)
        print(
            f'\r[{bar}] {percentage:.0f}% | {current}/{self.total} | '
            f'ETA: {eta_minutes:02d}:{eta_seconds:02d} | {message}',
            end='',
            flush=True
        )

    def finish(self) -> None:
        """
        Mark progress as complete and print newline
        """
        print()  # Move to next line after progress bar
