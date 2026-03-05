"""Log Size Parser - Parse eBPF log size monitoring data"""

import logging
from typing import Dict, Optional

from ..utils import parse_datetime, humanize_bytes

logger = logging.getLogger(__name__)


class LogSizeParser:
    """Parser for eBPF log size monitoring data"""

    @staticmethod
    def parse(log_path: str) -> Optional[Dict]:
        """Parse log size monitor file

        Log format:
            # eBPF Log Size Monitoring - Log file size (instantaneous)
            # Timestamp                     Size_Bytes  Size_Human
            # DEBUG: Starting logsize monitoring for /path/to/ebpf_output.log
            # DEBUG: Monitor process PID: 47972, PGID: 47972
            2025-10-21 22:12:40.118987979 0 0B
            2025-10-21 22:12:42.221254361 0 0B
            ...

        Args:
            log_path: Path to logsize monitor log file

        Returns:
            Dictionary with log size statistics
        """
        records = []

        try:
            with open(log_path, 'r') as f:
                for line in f:
                    # Skip comments and empty lines
                    if line.startswith('#') or not line.strip():
                        continue

                    # Parse data line
                    parts = line.split()
                    if len(parts) < 3:
                        continue

                    try:
                        # Format: timestamp_date timestamp_time size_bytes size_human
                        timestamp_str = parts[0] + ' ' + parts[1]
                        size_bytes = int(parts[2])

                        timestamp = parse_datetime(timestamp_str)
                        records.append({
                            "timestamp": timestamp,
                            "size_bytes": size_bytes
                        })
                    except (ValueError, IndexError) as e:
                        logger.debug(f"Skipping invalid logsize line: {line.strip()} - {e}")
                        continue

        except FileNotFoundError:
            logger.warning(f"Logsize monitor file not found: {log_path}")
            return None
        except Exception as e:
            logger.error(f"Error parsing logsize monitor file {log_path}: {e}")
            return None

        if not records:
            logger.warning(f"No valid records found in {log_path}")
            return None

        # Calculate statistics
        final_size = records[-1]["size_bytes"]
        initial_size = records[0]["size_bytes"]

        # Calculate growth rate
        if len(records) > 1:
            duration = (records[-1]["timestamp"] - records[0]["timestamp"]).total_seconds()
            growth = final_size - initial_size
            growth_rate = growth / duration if duration > 0 else 0
        else:
            growth_rate = 0

        return {
            "final_size_bytes": final_size,
            "final_size_human": humanize_bytes(final_size),
            "initial_size_bytes": initial_size,
            "growth_bytes": final_size - initial_size,
            "growth_rate_bytes_per_sec": round(growth_rate, 2),
            "sample_count": len(records),
            "duration_seconds": duration if len(records) > 1 else 0
        }
