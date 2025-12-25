"""Performance Data Parser - Parse latency, throughput, and PPS test results"""

import logging
from typing import Dict, List, Optional

from ..utils import safe_read_json, parse_datetime, datetime_to_epoch, bps_to_gbps

logger = logging.getLogger(__name__)


class PerformanceParser:
    """Parser for performance test data (latency, throughput, PPS)"""

    @staticmethod
    def parse_latency(file_path: str) -> Optional[Dict]:
        """Parse latency test result file

        File format:
            Line 1: Test description
            Line 2: CSV header (Minimum,Mean,Maximum)
            Line 3: CSV data

        Args:
            file_path: Path to latency_*.txt file

        Returns:
            Dictionary with latency metrics {min_us, mean_us, max_us}
        """
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()

            if len(lines) < 3:
                logger.error(f"Latency file has insufficient lines: {file_path}")
                return None

            # Parse data line (line 3)
            data_line = lines[2].strip()
            if not data_line:
                logger.error(f"Empty data line in latency file: {file_path}")
                return None

            values = data_line.split(',')
            if len(values) < 3:
                logger.error(f"Insufficient values in latency data: {file_path}")
                return None

            return {
                "min_us": float(values[0]),
                "mean_us": float(values[1]),
                "max_us": float(values[2])
            }

        except FileNotFoundError:
            logger.warning(f"Latency file not found: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error parsing latency file {file_path}: {e}")
            return None

    @staticmethod
    def parse_throughput_single(json_path: str, timing_path: str) -> Optional[Dict]:
        """Parse single-stream throughput test result

        Args:
            json_path: Path to iperf3 JSON output file
            timing_path: Path to timing log file

        Returns:
            Dictionary with throughput metrics and timing info
        """
        # Parse iperf3 JSON
        data = safe_read_json(json_path)
        if not data:
            return None

        try:
            bps = data["end"]["sum_sent"]["bits_per_second"]
            throughput_gbps = bps_to_gbps(bps)
        except KeyError as e:
            logger.error(f"Missing key in iperf3 JSON {json_path}: {e}")
            return None

        # Parse timing log
        timing = PerformanceParser._parse_timing_log(timing_path, "throughput")
        if not timing:
            logger.warning(f"Could not parse timing log: {timing_path}")
            return None

        return {
            "throughput_gbps": throughput_gbps,
            "start_time": timing["start_time"],
            "end_time": timing["end_time"],
            "start_epoch": timing["start_epoch"],
            "end_epoch": timing["end_epoch"]
        }

    @staticmethod
    def parse_throughput_multi(json_paths: List[str], timing_paths: List[str]) -> Optional[Dict]:
        """Parse multi-stream throughput test result

        Args:
            json_paths: List of paths to iperf3 JSON output files
            timing_paths: List of paths to timing log files (one per stream)

        Returns:
            Dictionary with aggregated throughput metrics and timing info
        """
        if not json_paths:
            logger.warning("No JSON files provided for multi-stream throughput")
            return None

        total_bps = 0
        for json_path in json_paths:
            data = safe_read_json(json_path)
            if not data:
                logger.warning(f"Skipping invalid JSON: {json_path}")
                continue

            try:
                bps = data["end"]["sum_sent"]["bits_per_second"]
                total_bps += bps
            except KeyError as e:
                logger.error(f"Missing key in iperf3 JSON {json_path}: {e}")
                continue

        throughput_gbps = bps_to_gbps(total_bps)

        # Parse timing logs and aggregate (earliest start, latest end)
        timing = PerformanceParser._parse_timing_logs_aggregated(timing_paths, "pps")
        if not timing:
            return None

        return {
            "throughput_gbps": throughput_gbps,
            "stream_count": len(json_paths),
            "start_time": timing["start_time"],
            "end_time": timing["end_time"],
            "start_epoch": timing["start_epoch"],
            "end_epoch": timing["end_epoch"]
        }

    @staticmethod
    def parse_pps_single(json_path: str, timing_path: str) -> Optional[Dict]:
        """Parse single-stream PPS test result

        Args:
            json_path: Path to iperf3 JSON output file
            timing_path: Path to timing log file

        Returns:
            Dictionary with PPS metrics and timing info
        """
        # Parse iperf3 JSON
        data = safe_read_json(json_path)
        if not data:
            return None

        try:
            bps = data["end"]["sum_sent"]["bits_per_second"]

            # 获取 packet_size（容错处理）
            packet_size = None
            # 尝试从 test_start 获取
            if "test_start" in data and "blksize" in data["test_start"]:
                packet_size = data["test_start"]["blksize"]
            # 尝试从 start.test_start 获取
            elif "start" in data and "test_start" in data["start"] and "blksize" in data["start"]["test_start"]:
                packet_size = data["start"]["test_start"]["blksize"]
            # 默认值
            else:
                logger.warning(f"Cannot find packet size in {json_path}, using default 64 bytes")
                packet_size = 64  # 默认 PPS 测试使用 64 字节包

            pps = int(bps / (packet_size * 8))
            throughput_gbps = bps_to_gbps(bps)
        except KeyError as e:
            logger.error(f"Missing key in iperf3 JSON {json_path}: {e}")
            return None

        # Parse timing log (PPS timing format is different)
        timing = PerformanceParser._parse_timing_log(timing_path, "pps")
        if not timing:
            return None

        return {
            "pps": pps,
            "throughput_gbps": throughput_gbps,
            "packet_size_bytes": packet_size,
            "start_time": timing["start_time"],
            "end_time": timing["end_time"],
            "start_epoch": timing["start_epoch"],
            "end_epoch": timing["end_epoch"]
        }

    @staticmethod
    def parse_pps_multi(json_paths: List[str], timing_paths: List[str]) -> Optional[Dict]:
        """Parse multi-stream PPS test result

        Args:
            json_paths: List of paths to iperf3 JSON output files
            timing_paths: List of paths to timing log files (one per stream)

        Returns:
            Dictionary with aggregated PPS metrics and timing info
        """
        if not json_paths:
            logger.warning("No JSON files provided for multi-stream PPS")
            return None

        total_bps = 0
        packet_size = None

        for json_path in json_paths:
            data = safe_read_json(json_path)
            if not data:
                logger.warning(f"Skipping invalid JSON: {json_path}")
                continue

            try:
                bps = data["end"]["sum_sent"]["bits_per_second"]
                total_bps += bps

                if packet_size is None:
                    if "test_start" in data and "blksize" in data["test_start"]:
                        packet_size = data["test_start"]["blksize"]
                    elif "start" in data and "test_start" in data["start"] and "blksize" in data["start"]["test_start"]:
                        packet_size = data["start"]["test_start"]["blksize"]
            except KeyError as e:
                logger.error(f"Missing key in iperf3 JSON {json_path}: {e}")
                continue

        if packet_size is None:
            logger.warning("Could not determine packet size from JSON files, using default 64 bytes")
            packet_size = 64

        pps = int(total_bps / (packet_size * 8))
        throughput_gbps = bps_to_gbps(total_bps)

        # Parse timing logs and aggregate (earliest start, latest end)
        timing = PerformanceParser._parse_timing_logs_aggregated(timing_paths, "pps")
        if not timing:
            return None

        return {
            "pps": pps,
            "throughput_gbps": throughput_gbps,
            "packet_size_bytes": packet_size,
            "stream_count": len(json_paths),
            "start_time": timing["start_time"],
            "end_time": timing["end_time"],
            "start_epoch": timing["start_epoch"],
            "end_epoch": timing["end_epoch"]
        }

    @staticmethod
    def _parse_timing_log(timing_path: str, test_type: str) -> Optional[Dict]:
        """Parse timing log file

        Timing log formats:
        - Throughput:
            Test: throughput_single_tcp
            Start: 2025-10-21 14:12:43.774
            End: 2025-10-21 14:12:53.890

        - PPS:
            Test: pps_single_stream_process_1_port_5001
            Process_Start: 2025-10-21 14:13:41.897
            Actual_Launch: 2025-10-21 14:13:41.966
            Test_End: 2025-10-21 14:13:54.085

        Args:
            timing_path: Path to timing log file
            test_type: "throughput" or "pps"

        Returns:
            Dictionary with start_time, end_time, start_epoch, end_epoch
        """
        try:
            with open(timing_path, 'r') as f:
                lines = f.readlines()

            if test_type == "throughput":
                # Format: Start: / End:
                start_time = None
                end_time = None

                for line in lines:
                    if line.startswith("Start:"):
                        start_time = line.split("Start:")[1].strip()
                    elif line.startswith("End:"):
                        end_time = line.split("End:")[1].strip()

                if not start_time or not end_time:
                    logger.error(f"Could not parse start/end time from {timing_path}")
                    return None

            elif test_type == "pps":
                # Format: Actual_Launch: / Test_End:
                start_time = None
                end_time = None

                for line in lines:
                    if line.startswith("Actual_Launch:"):
                        start_time = line.split("Actual_Launch:")[1].strip()
                    elif line.startswith("Test_End:"):
                        end_time = line.split("Test_End:")[1].strip()

                if not start_time or not end_time:
                    logger.error(f"Could not parse start/end time from {timing_path}")
                    return None

            else:
                logger.error(f"Unknown test type: {test_type}")
                return None

            # Convert to epoch
            start_epoch = datetime_to_epoch(start_time)
            end_epoch = datetime_to_epoch(end_time)

            return {
                "start_time": start_time,
                "end_time": end_time,
                "start_epoch": start_epoch,
                "end_epoch": end_epoch
            }

        except FileNotFoundError:
            logger.warning(f"Timing file not found: {timing_path}")
            return None
        except Exception as e:
            logger.error(f"Error parsing timing file {timing_path}: {e}")
            return None

    @staticmethod
    def _parse_timing_logs_aggregated(timing_paths: List[str], test_type: str) -> Optional[Dict]:
        """Parse multiple timing log files and aggregate (earliest start, latest end)

        For multi-stream tests, each stream has its own timing file with different
        launch times. This method aggregates them to get the full test duration.

        Args:
            timing_paths: List of paths to timing log files
            test_type: "throughput" or "pps"

        Returns:
            Dictionary with aggregated start_time, end_time, start_epoch, end_epoch
        """
        if not timing_paths:
            logger.warning("No timing paths provided for aggregation")
            return None

        earliest_start_epoch = None
        latest_end_epoch = None
        earliest_start_time = None
        latest_end_time = None

        for timing_path in timing_paths:
            timing = PerformanceParser._parse_timing_log(timing_path, test_type)
            if not timing:
                continue

            # Track earliest start
            if earliest_start_epoch is None or timing["start_epoch"] < earliest_start_epoch:
                earliest_start_epoch = timing["start_epoch"]
                earliest_start_time = timing["start_time"]

            # Track latest end
            if latest_end_epoch is None or timing["end_epoch"] > latest_end_epoch:
                latest_end_epoch = timing["end_epoch"]
                latest_end_time = timing["end_time"]

        if earliest_start_epoch is None or latest_end_epoch is None:
            logger.error(f"Could not parse any timing from {len(timing_paths)} files")
            return None

        return {
            "start_time": earliest_start_time,
            "end_time": latest_end_time,
            "start_epoch": earliest_start_epoch,
            "end_epoch": latest_end_epoch
        }

    @staticmethod
    def parse_all(paths: Dict) -> Dict:
        """Parse all performance data from located paths

        Args:
            paths: Dictionary from DataLocator.locate_tool_case() or locate_baseline()

        Returns:
            Dictionary with all parsed performance data
        """
        result = {
            "client": {},
            "server": {}
        }

        # Parse client data
        if "client" in paths and paths["client"]:
            result["client"] = PerformanceParser._parse_performance_side(paths["client"])

        # Parse server data
        if "server" in paths and "performance" in paths["server"]:
            result["server"] = PerformanceParser._parse_performance_side(paths["server"]["performance"])

        return result

    @staticmethod
    def _parse_performance_side(side_paths: Dict) -> Dict:
        """Parse performance data for one side (client or server)

        Args:
            side_paths: Dictionary with latency/throughput/pps paths

        Returns:
            Dictionary with parsed data
        """
        result = {}

        # Parse latency
        if "latency" in side_paths and side_paths["latency"]:
            latency_data = {}
            if "tcp_rr" in side_paths["latency"]:
                tcp_data = PerformanceParser.parse_latency(side_paths["latency"]["tcp_rr"])
                if tcp_data:
                    latency_data["tcp_rr"] = tcp_data

            if "udp_rr" in side_paths["latency"]:
                udp_data = PerformanceParser.parse_latency(side_paths["latency"]["udp_rr"])
                if udp_data:
                    latency_data["udp_rr"] = udp_data

            if latency_data:
                result["latency"] = latency_data

        # Parse throughput
        if "throughput" in side_paths and side_paths["throughput"]:
            throughput_data = {}

            if "single" in side_paths["throughput"]:
                single = side_paths["throughput"]["single"]
                single_data = PerformanceParser.parse_throughput_single(
                    single["json"], single["timing"]
                )
                if single_data:
                    throughput_data["single"] = single_data

            if "multi" in side_paths["throughput"]:
                multi = side_paths["throughput"]["multi"]
                multi_data = PerformanceParser.parse_throughput_multi(
                    multi["json_files"], multi["timing_files"]
                )
                if multi_data:
                    throughput_data["multi"] = multi_data

            if throughput_data:
                result["throughput"] = throughput_data

        # Parse PPS
        if "pps" in side_paths and side_paths["pps"]:
            pps_data = {}

            if "single" in side_paths["pps"]:
                single = side_paths["pps"]["single"]
                single_data = PerformanceParser.parse_pps_single(
                    single["json"], single["timing"]
                )
                if single_data:
                    pps_data["single"] = single_data

            if "multi" in side_paths["pps"]:
                multi = side_paths["pps"]["multi"]
                multi_data = PerformanceParser.parse_pps_multi(
                    multi["json_files"], multi["timing_files"]
                )
                if multi_data:
                    pps_data["multi"] = multi_data

            if pps_data:
                result["pps"] = pps_data

        return result
