"""Resource Monitor Parser - Parse eBPF resource monitoring logs (pidstat output)"""

import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ResourceParser:
    """Parser for eBPF resource monitoring data (pidstat output)"""

    @staticmethod
    def parse(log_path: str, time_ranges: Optional[Dict[str, Tuple[int, int]]] = None) -> Optional[Dict]:
        """Parse resource monitor log file

        Log format (pidstat output):
            # eBPF Resource Monitoring - CPU and Memory statistics using pidstat
            # DEBUG: Starting resource monitoring for PID 47899 with interval 2s
            # START_DATETIME: 2025-10-21 22:12:39.672278096  START_EPOCH: 1761055959  INTERVAL: 2s  PID: 47899
            Linux 4.19.90-2307.3.0.el7.v97.x86_64 (node31)     10/21/2025      _x86_64_        (80 CPU)

            #      Time   UID       PID    %usr %system  %guest    %CPU   CPU  minflt/s  majflt/s     VSZ    RSS   %MEM  Command
             1761055961     0     47899   84.00    7.00    0.00   91.00     5   8292.00      0.00  356276 146004   0.03  python2

        Args:
            log_path: Path to resource monitor log file
            time_ranges: Optional dict of time ranges for filtering
                        Format: {"name": (start_epoch, end_epoch)}

        Returns:
            Dictionary with full cycle stats and time range stats
        """
        # Parse monitor metadata (interval, date, etc.)
        metadata = ResourceParser._parse_monitor_metadata(log_path)
        interval = metadata.get("interval", 2)
        start_date = metadata.get("start_date")

        # Parse all records (pass start_date for AM/PM time conversion)
        records = ResourceParser._parse_records(log_path, start_date)
        if not records:
            logger.warning(f"No records found in {log_path}")
            return None

        # Calculate full cycle statistics
        full_cycle = ResourceParser._calculate_full_cycle_stats(records)

        # Calculate time range statistics
        time_range_stats = {}
        if time_ranges:
            for name, (start_epoch, end_epoch) in time_ranges.items():
                # Adjust filtering to account for pidstat sampling semantics
                # A record at timestamp T contains stats for [T-interval, T]
                # We want records that fully cover the test period [start, end]
                # So we filter: start + interval <= T <= end + interval
                filtered = [r for r in records
                           if start_epoch + interval <= r["timestamp"] <= end_epoch + interval]
                if filtered:
                    time_range_stats[name] = ResourceParser._calculate_stats(filtered)
                else:
                    logger.warning(f"No records in time range {name}: {start_epoch+interval}-{end_epoch+interval} (adjusted for interval={interval}s)")

        return {
            "full_cycle": full_cycle,
            "time_range_stats": time_range_stats
        }

    @staticmethod
    def _parse_monitor_metadata(log_path: str) -> Dict:
        """Parse monitor metadata from log header

        Extracts information from header lines like:
            # START_DATETIME: 2025-10-22 18:25:53.333063770  START_EPOCH: 1761128753  INTERVAL: 2s  PID: 57202

        Args:
            log_path: Path to resource monitor log file

        Returns:
            Dictionary with metadata (interval, start_epoch, start_date, etc.)
        """
        metadata = {"interval": 2}  # Default interval

        try:
            with open(log_path, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        # Parse INTERVAL from header line
                        if "INTERVAL:" in line:
                            match = re.search(r'INTERVAL:\s*(\d+)s', line)
                            if match:
                                metadata["interval"] = int(match.group(1))
                        # Parse START_EPOCH
                        if "START_EPOCH:" in line:
                            match = re.search(r'START_EPOCH:\s*(\d+)', line)
                            if match:
                                metadata["start_epoch"] = int(match.group(1))
                        # Parse START_DATETIME to extract date (for AM/PM time format)
                        if "START_DATETIME:" in line:
                            match = re.search(r'START_DATETIME:\s*(\d{4}-\d{2}-\d{2})', line)
                            if match:
                                metadata["start_date"] = match.group(1)
                    elif line.strip() and not line.startswith('Linux'):
                        # Stop at first data line (after headers)
                        break
        except Exception as e:
            logger.warning(f"Failed to parse monitor metadata from {log_path}: {e}")

        return metadata

    @staticmethod
    def _parse_records(log_path: str, start_date: Optional[str] = None) -> List[Dict]:
        """Parse all pidstat records from log file

        Args:
            log_path: Path to log file
            start_date: Date string (YYYY-MM-DD) for AM/PM time conversion

        Returns:
            List of record dictionaries
        """
        records = []

        try:
            with open(log_path, 'r') as f:
                for line in f:
                    # Skip comments and empty lines
                    if line.startswith('#') or not line.strip():
                        continue

                    # Skip header lines (contains "Time" keyword)
                    if "Time" in line and "UID" in line:
                        continue

                    # Parse data line
                    record = ResourceParser._parse_pidstat_line(line, start_date)
                    if record:
                        records.append(record)

        except FileNotFoundError:
            logger.warning(f"Resource monitor file not found: {log_path}")
            return []
        except Exception as e:
            logger.error(f"Error parsing resource monitor file {log_path}: {e}")
            return []

        logger.info(f"Parsed {len(records)} records from {log_path}")
        return records

    @staticmethod
    def _parse_pidstat_line(line: str, start_date: Optional[str] = None) -> Optional[Dict]:
        """Parse a single pidstat output line

        Format 1 (Unix timestamp):
         1761055961     0     47899   84.00    7.00    0.00   91.00     5   8292.00      0.00  356276 146004   0.03  python2

        Format 2 (Time with AM/PM):
         11:18:30 PM     0    933091   27.36    1.00    0.00   70.65   28.36    58   1567.16      0.00  411996  115192   0.02  python3

        Args:
            line: Line from pidstat output
            start_date: Date string (YYYY-MM-DD) for AM/PM time conversion

        Returns:
            Dictionary with parsed fields, or None if parsing fails
        """
        try:
            parts = line.split()
            if len(parts) < 14:
                return None

            # Detect format by checking if second field is AM/PM
            if parts[1] in ('AM', 'PM'):
                # Format 2: Time AM/PM format
                # Fields: Time, AM/PM, UID, PID, %usr, %system, %guest, %wait, %CPU, CPU, minflt/s, majflt/s, VSZ, RSS, %MEM, Command
                offset = 2  # Skip Time and AM/PM

                # Calculate epoch timestamp from date + time
                timestamp = 0
                if start_date:
                    try:
                        time_str = parts[0]  # HH:MM:SS
                        ampm = parts[1]      # AM/PM
                        datetime_str = f"{start_date} {time_str} {ampm}"
                        dt = datetime.strptime(datetime_str, "%Y-%m-%d %I:%M:%S %p")
                        timestamp = int(dt.timestamp())
                    except ValueError as e:
                        logger.debug(f"Failed to parse datetime: {datetime_str} - {e}")

                return {
                    "timestamp": timestamp,
                    "cpu_percent": float(parts[offset + 6]),   # %CPU
                    "cpu_usr": float(parts[offset + 2]),       # %usr
                    "cpu_system": float(parts[offset + 3]),    # %system
                    "rss_kb": int(parts[offset + 11]),         # RSS
                    "vsz_kb": int(parts[offset + 10]),         # VSZ
                    "minflt_per_sec": float(parts[offset + 8]), # minflt/s
                    "majflt_per_sec": float(parts[offset + 9]), # majflt/s
                    "mem_percent": float(parts[offset + 12])   # %MEM
                }
            else:
                # Format 1: Unix timestamp format
                return {
                    "timestamp": int(parts[0]),
                    "cpu_percent": float(parts[6]),
                    "cpu_usr": float(parts[3]),
                    "cpu_system": float(parts[4]),
                    "rss_kb": int(parts[11]),
                    "vsz_kb": int(parts[10]),
                    "minflt_per_sec": float(parts[8]),
                    "majflt_per_sec": float(parts[9]),
                    "mem_percent": float(parts[12])
                }
        except (ValueError, IndexError) as e:
            logger.debug(f"Failed to parse pidstat line: {line.strip()} - {e}")
            return None

    @staticmethod
    def _calculate_stats(records: List[Dict]) -> Dict:
        """Calculate statistics from a list of records

        Args:
            records: List of parsed pidstat records

        Returns:
            Dictionary with calculated statistics
        """
        if not records:
            return None

        cpu_values = [r["cpu_percent"] for r in records]
        rss_values = [r["rss_kb"] for r in records]
        vsz_values = [r["vsz_kb"] for r in records]
        minflt_values = [r["minflt_per_sec"] for r in records]

        return {
            "cpu": {
                "avg_percent": round(sum(cpu_values) / len(cpu_values), 2),
                "max_percent": round(max(cpu_values), 2),
                "min_percent": round(min(cpu_values), 2)
            },
            "memory": {
                "avg_rss_kb": int(sum(rss_values) / len(rss_values)),
                "max_rss_kb": max(rss_values),
                "avg_vsz_kb": int(sum(vsz_values) / len(vsz_values)),
                "max_vsz_kb": max(vsz_values)
            },
            "page_faults": {
                "avg_minflt_per_sec": round(sum(minflt_values) / len(minflt_values), 2),
                "max_minflt_per_sec": round(max(minflt_values), 2)
            },
            "sample_count": len(records)
        }

    @staticmethod
    def _calculate_full_cycle_stats(records: List[Dict]) -> Dict:
        """Calculate full cycle statistics (CPU avg/max, memory max, etc.)

        Args:
            records: List of all pidstat records

        Returns:
            Dictionary with full cycle statistics
        """
        if not records:
            return None

        max_rss_record = max(records, key=lambda r: r["rss_kb"])
        max_vsz_record = max(records, key=lambda r: r["vsz_kb"])

        # Calculate CPU statistics from all records
        cpu_values = [r["cpu_percent"] for r in records]
        avg_cpu = round(sum(cpu_values) / len(cpu_values), 2)
        max_cpu = round(max(cpu_values), 2)

        return {
            "max_rss_kb": max_rss_record["rss_kb"],
            "max_rss_timestamp": max_rss_record["timestamp"],
            "max_vsz_kb": max_vsz_record["vsz_kb"],
            "max_vsz_timestamp": max_vsz_record["timestamp"],
            "avg_cpu_percent": avg_cpu,
            "max_cpu_percent": max_cpu,
            "total_samples": len(records)
        }
