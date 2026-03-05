"""Utility functions for performance test analysis"""

import os
import re
import glob
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)


def parse_datetime(datetime_str: str) -> datetime:
    """Parse datetime string to datetime object

    Supports formats:
    - 2025-10-21 14:12:43.774
    - Tue, 21 Oct 2025 14:13:41 GMT
    - 2025-10-21 22:12:39.672278096

    Args:
        datetime_str: Datetime string

    Returns:
        datetime object

    Raises:
        ValueError: If format is not recognized
    """
    datetime_str = datetime_str.strip()

    # Format 1: 2025-10-21 14:12:43.774
    # Format 3: 2025-10-21 22:12:39.672278096
    if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', datetime_str):
        # Split on space to handle optional microseconds
        parts = datetime_str.split()
        if len(parts) == 2:
            date_part, time_part = parts
            # Truncate microseconds if too long
            if '.' in time_part:
                time_base, microsec = time_part.split('.')
                microsec = microsec[:6].ljust(6, '0')  # Keep only 6 digits
                time_part = f"{time_base}.{microsec}"
            datetime_str = f"{date_part} {time_part}"

        try:
            return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S")

    # Format 2: Tue, 21 Oct 2025 14:13:41 GMT
    if "GMT" in datetime_str:
        return datetime.strptime(datetime_str, "%a, %d %b %Y %H:%M:%S %Z")

    raise ValueError(f"Unrecognized datetime format: {datetime_str}")


def datetime_to_epoch_with_reference(datetime_str: str, ref_datetime_str: str, ref_epoch: int) -> int:
    """Convert datetime string to Unix timestamp using a reference time pair

    This function calculates epoch by computing the time difference between
    the target datetime and a known reference datetime, then adding that
    offset to the reference epoch. This approach:
    1. Does NOT depend on analysis machine's timezone
    2. Only uses executor's time information (both datetime strings from executor)

    Args:
        datetime_str: Target datetime string (from timing log)
        ref_datetime_str: Reference datetime string (from resource monitor START_DATETIME)
        ref_epoch: Reference epoch (from resource monitor START_EPOCH)

    Returns:
        Unix timestamp (seconds since epoch)

    Example:
        ref_datetime = "2025-12-27 14:11:11.821"
        ref_epoch = 1766815871
        target = "2025-12-27 14:11:22.305"
        # Difference = 10.484 seconds
        # Result = 1766815871 + 10 = 1766815881
    """
    # Parse both datetime strings (naive datetime objects)
    target_dt = parse_datetime(datetime_str)
    ref_dt = parse_datetime(ref_datetime_str)

    # Calculate offset in seconds (can be negative if target is before reference)
    offset_seconds = (target_dt - ref_dt).total_seconds()

    # Apply offset to reference epoch
    return int(ref_epoch + offset_seconds)


def datetime_to_epoch(datetime_str: str, time_reference: Optional[Dict] = None) -> int:
    """Convert datetime string to Unix timestamp

    If time_reference is provided, uses reference-based calculation which
    does not depend on analysis machine's timezone. Otherwise falls back
    to local time interpretation (less accurate across timezones).

    Args:
        datetime_str: Datetime string
        time_reference: Optional dict with 'ref_datetime' and 'ref_epoch' keys
                       extracted from resource monitor log

    Returns:
        Unix timestamp (seconds since epoch)
    """
    if time_reference and 'ref_datetime' in time_reference and 'ref_epoch' in time_reference:
        return datetime_to_epoch_with_reference(
            datetime_str,
            time_reference['ref_datetime'],
            time_reference['ref_epoch']
        )

    # Fallback: treat as local time (only works if analysis machine matches executor timezone)
    dt = parse_datetime(datetime_str)
    return int(dt.timestamp())


def extract_time_reference(resource_monitor_path: str) -> Optional[Dict]:
    """Extract time reference from resource monitor log header

    The resource monitor log contains START_DATETIME and START_EPOCH which
    provide a reliable time reference from the executor. This reference can
    be used to convert other datetime strings to epochs without depending
    on the analysis machine's timezone.

    Args:
        resource_monitor_path: Path to resource monitor log file

    Returns:
        Dictionary with 'ref_datetime' and 'ref_epoch' keys, or None if not found
    """
    try:
        with open(resource_monitor_path, 'r') as f:
            for line in f:
                if line.startswith('#') and 'START_DATETIME:' in line and 'START_EPOCH:' in line:
                    # Extract START_DATETIME (full datetime string)
                    dt_match = re.search(r'START_DATETIME:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)', line)
                    # Extract START_EPOCH
                    epoch_match = re.search(r'START_EPOCH:\s*(\d+)', line)

                    if dt_match and epoch_match:
                        return {
                            'ref_datetime': dt_match.group(1),
                            'ref_epoch': int(epoch_match.group(1))
                        }
                elif line.strip() and not line.startswith('#') and not line.startswith('Linux'):
                    # Stop at first data line
                    break
    except Exception as e:
        logger.warning(f"Failed to extract time reference from {resource_monitor_path}: {e}")

    return None


def epoch_to_datetime(epoch: int) -> str:
    """Convert Unix timestamp to readable datetime string

    Args:
        epoch: Unix timestamp

    Returns:
        Formatted datetime string (YYYY-MM-DD HH:MM:SS)
    """
    dt = datetime.fromtimestamp(epoch)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def humanize_bytes(num_bytes: int) -> str:
    """Convert bytes to human-readable format

    Args:
        num_bytes: Number of bytes

    Returns:
        Human-readable string (e.g., "1.5MB")

    Examples:
        >>> humanize_bytes(0)
        '0B'
        >>> humanize_bytes(1024)
        '1.0KB'
        >>> humanize_bytes(1048576)
        '1.0MB'
    """
    if num_bytes == 0:
        return "0B"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0

    size = float(num_bytes)
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1

    return f"{size:.1f}{units[unit_index]}"


def bps_to_gbps(bps: float) -> float:
    """Convert bits per second to gigabits per second

    Args:
        bps: Bits per second

    Returns:
        Gigabits per second (rounded to 2 decimal places)
    """
    return round(bps / 1e9, 2)


def find_latest_file(pattern: str) -> Optional[str]:
    """Find the latest file matching glob pattern

    Args:
        pattern: Glob pattern

    Returns:
        Path to latest file, or None if no files found
    """
    files = glob.glob(pattern)
    if not files:
        return None
    return sorted(files)[-1]


def safe_read_json(file_path: str) -> Optional[Dict]:
    """Safely read JSON file with error handling

    Args:
        file_path: Path to JSON file

    Returns:
        Parsed JSON data, or None on error
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"JSON file not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in {file_path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error reading JSON {file_path}: {e}")
        return None


def parse_tool_case_name(tool_case_name: str) -> Optional[Dict[str, any]]:
    """Parse tool case name into components

    Args:
        tool_case_name: Tool case name
                       Format: {topic}_case_{number}_{protocol}_{direction}_{hash}

    Returns:
        Dictionary with parsed components, or None if format doesn't match

    Examples:
        >>> parse_tool_case_name("system_network_performance_case_6_tcp_tx_0388a9")
        {
            'topic': 'system_network_performance',
            'case_number': 6,
            'protocol': 'tcp',
            'direction': 'tx',
            'hash': '0388a9'
        }
    """
    # Pattern: {topic}_case_{number}_{protocol}_{direction}_{hash}
    pattern = r"(.+)_case_(\d+)_(\w+)_(\w+)_(\w+)"
    match = re.match(pattern, tool_case_name)

    if not match:
        logger.warning(f"Tool case name doesn't match expected pattern: {tool_case_name}")
        return None

    return {
        "topic": match.group(1),
        "case_number": int(match.group(2)),
        "protocol": match.group(3),
        "direction": match.group(4),
        "hash": match.group(5)
    }


def safe_join_path(base: str, *parts: str) -> str:
    """Safely join path components and verify result is within base

    Args:
        base: Base directory path
        *parts: Path components to join

    Returns:
        Joined absolute path

    Raises:
        ValueError: If resulting path is outside base directory
    """
    path = os.path.join(base, *parts)
    abs_base = os.path.abspath(base)
    abs_path = os.path.abspath(path)

    if not abs_path.startswith(abs_base):
        raise ValueError(f"Invalid path: {path} is outside base {base}")

    return abs_path


def safe_parse(parser_func, *args, default=None, **kwargs):
    """Safely execute parser function with error handling

    Args:
        parser_func: Parser function to execute
        *args: Positional arguments for parser
        default: Default value to return on error
        **kwargs: Keyword arguments for parser

    Returns:
        Parser result or default value on error
    """
    try:
        return parser_func(*args, **kwargs)
    except FileNotFoundError as e:
        logger.warning(f"File not found in {parser_func.__name__}: {e}")
        return default
    except Exception as e:
        logger.error(f"Error in {parser_func.__name__}: {e}")
        return default


def get_file_size(file_path: str) -> int:
    """Get file size in bytes

    Args:
        file_path: Path to file

    Returns:
        File size in bytes, or 0 if file doesn't exist
    """
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0


def load_test_case_metadata(test_case_json_path: str) -> Dict[int, Dict]:
    """Load test case metadata from JSON file

    Args:
        test_case_json_path: Path to test case JSON file

    Returns:
        Dictionary mapping case ID to test case metadata

    Examples:
        >>> metadata = load_test_case_metadata("test-cases.json")
        >>> metadata[6]
        {
            'id': 6,
            'name': 'system_network_latency_details_tx_protocol_tcp',
            'command': 'sudo python3 ebpf-tools/performance/system-network/...',
            'program': 'system_network_latency_details.py'
        }
    """
    test_cases_map = {}

    try:
        data = safe_read_json(test_case_json_path)
        if not data or "test_cases" not in data:
            logger.warning(f"Invalid test case JSON structure: {test_case_json_path}")
            return {}

        for test_case in data["test_cases"]:
            case_id = test_case.get("id")
            command = test_case.get("command", "")

            # Extract program name from command
            # Pattern: ... path/to/program.py ...
            program_name = "N/A"
            if command:
                # Find .py file in the command
                match = re.search(r'([^/\s]+\.py)', command)
                if match:
                    program_name = match.group(1)

            test_cases_map[case_id] = {
                "id": case_id,
                "name": test_case.get("name", ""),
                "command": command,
                "program": program_name
            }

        logger.info(f"Loaded {len(test_cases_map)} test cases from {test_case_json_path}")
        return test_cases_map

    except Exception as e:
        logger.error(f"Failed to load test case metadata: {e}")
        return {}


def get_program_name_for_case(tool_case_name: str, test_cases_metadata: Dict[int, Dict]) -> str:
    """Get program name for a tool case

    Args:
        tool_case_name: Tool case name (e.g., "system_network_performance_case_6_tcp_tx_0388a9")
        test_cases_metadata: Test cases metadata dictionary from load_test_case_metadata

    Returns:
        Program name or "N/A" if not found

    Examples:
        >>> get_program_name_for_case("system_network_performance_case_6_tcp_tx_0388a9", metadata)
        'system_network_latency_details.py'
    """
    # Parse case number from tool case name
    parsed = parse_tool_case_name(tool_case_name)
    if not parsed:
        return "N/A"

    case_number = parsed.get("case_number")
    if case_number is None:
        return "N/A"

    # Look up in metadata
    if case_number in test_cases_metadata:
        return test_cases_metadata[case_number].get("program", "N/A")

    return "N/A"
