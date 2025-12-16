#!/usr/bin/env python
"""
JSON Formatter

Converts analysis results to JSON format for output.
Implements FR-PCAP-SUM-006.
"""

import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any


class JSONFormatter:
    """JSON format output generator"""

    def format(self, analysis_result: Any) -> str:
        """
        Convert analysis result to JSON string

        Handles:
        1. Dataclass to dictionary conversion
        2. Datetime to ISO format string
        3. Enum to value
        4. Other objects to string

        Args:
            analysis_result: Analysis result object (can be dataclass or dict)

        Returns:
            JSON formatted string with proper indentation
        """
        return json.dumps(
            analysis_result,
            default=self._default_serializer,
            indent=2,
            ensure_ascii=False
        )

    def write_to_file(self, analysis_result: Any, output_path: str) -> None:
        """
        Write analysis result to JSON file

        Args:
            analysis_result: Analysis result object
            output_path: Path to output JSON file
        """
        json_str = self.format(analysis_result)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_str)

    def _default_serializer(self, obj: Any) -> Any:
        """
        Custom serializer for non-standard JSON types

        Handles:
        - Dataclasses: Convert to dictionary
        - Datetime: Convert to ISO format string
        - Enum: Extract value
        - Other: Convert to string

        Args:
            obj: Object to serialize

        Returns:
            JSON-serializable representation
        """
        # Check if object is a dataclass
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)

        # Handle datetime objects
        elif isinstance(obj, datetime):
            return obj.isoformat()

        # Handle enum objects
        elif isinstance(obj, Enum):
            return obj.value

        # Fallback to string representation
        else:
            return str(obj)
