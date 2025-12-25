"""Data Locator - Locate all data files for a tool case"""

import os
import glob
import logging
from typing import Dict, Optional, List

from .utils import find_latest_file, parse_tool_case_name

logger = logging.getLogger(__name__)


class DataLocator:
    """Locate data files for performance test analysis"""

    def __init__(self, iteration_path: str):
        """Initialize DataLocator

        Args:
            iteration_path: Path to iteration directory (e.g., results/1021/iteration_001)
        """
        self.iteration_path = iteration_path
        self.host_server_path = os.path.join(iteration_path, "host-server", "performance-test-results")
        self.host_client_path = os.path.join(iteration_path, "host-client", "performance-test-results")
        self.vm_server_path = os.path.join(iteration_path, "vm-server", "performance-test-results")
        self.vm_client_path = os.path.join(iteration_path, "vm-client", "performance-test-results")

    def locate_tool_case(self, tool_case_name: str) -> Optional[Dict]:
        """Locate all data files for a tool case

        Args:
            tool_case_name: Tool case name (e.g., system_network_performance_case_6_tcp_tx_0388a9)

        Returns:
            Dictionary containing paths to all data files, or None if not found
        """
        # Detect test type (host or vm)
        test_type = self._detect_test_type(tool_case_name)
        if not test_type:
            logger.error(f"Could not detect test type for {tool_case_name}")
            return None

        logger.info(f"Detected test type: {test_type} for {tool_case_name}")

        if test_type == "host":
            return self._locate_host_tool_case(tool_case_name)
        else:  # vm
            return self._locate_vm_tool_case(tool_case_name)

    def locate_baseline(self, test_type: str) -> Optional[Dict]:
        """Locate baseline data files

        Args:
            test_type: Test type ("host" or "vm")

        Returns:
            Dictionary containing paths to baseline data files
        """
        if test_type == "host":
            base_path = os.path.join(self.host_server_path, "baseline", "host")
            client_base = os.path.join(self.host_client_path, "baseline", "host")
        else:  # vm
            base_path = os.path.join(self.vm_server_path, "baseline", "vm")
            client_base = os.path.join(self.vm_client_path, "baseline", "vm")

        if not os.path.exists(client_base):
            logger.warning(f"Baseline path not found: {client_base}")
            return None

        return {
            "test_type": test_type,
            "client": self._locate_performance_data(client_base, "client_results"),
            "server": self._locate_performance_data(base_path, "server_results")
        }

    def _detect_test_type(self, tool_case_name: str) -> Optional[str]:
        """Detect test type (host or vm) for a tool case

        Args:
            tool_case_name: Tool case name

        Returns:
            "host" or "vm", or None if not found
        """
        # Check host test path
        host_path = os.path.join(
            self.host_server_path, "ebpf", tool_case_name, "host"
        )
        if os.path.exists(host_path):
            return "host"

        # Check vm test path
        vm_path = os.path.join(
            self.vm_server_path, "ebpf", tool_case_name, "vm"
        )
        if os.path.exists(vm_path):
            return "vm"

        logger.warning(f"Tool case not found in host or vm paths: {tool_case_name}")
        return None

    def _locate_host_tool_case(self, tool_case_name: str) -> Dict:
        """Locate data files for host test case

        Args:
            tool_case_name: Tool case name

        Returns:
            Dictionary with all file paths
        """
        server_base = os.path.join(
            self.host_server_path, "ebpf", tool_case_name, "host"
        )
        client_base = os.path.join(
            self.host_client_path, "ebpf", tool_case_name, "host"
        )

        # Extract command from ebpf_start file
        command = self._extract_command_from_ebpf_start(server_base)

        return {
            "test_type": "host",
            "tool_case_name": tool_case_name,
            "command": command,
            "client": self._locate_performance_data(client_base, "client_results"),
            "server": {
                "performance": self._locate_performance_data(server_base, "server_results"),
                "ebpf_monitoring": self._locate_ebpf_monitoring(server_base)
            }
        }

    def _locate_vm_tool_case(self, tool_case_name: str) -> Dict:
        """Locate data files for VM test case

        Args:
            tool_case_name: Tool case name

        Returns:
            Dictionary with all file paths
        """
        # VM performance data is in vm-server/vm-client
        # eBPF monitoring data is in host-server (monitoring the host)
        vm_server_base = os.path.join(
            self.vm_server_path, "ebpf", tool_case_name, "vm"
        )
        vm_client_base = os.path.join(
            self.vm_client_path, "ebpf", tool_case_name, "vm"
        )
        host_ebpf_base = os.path.join(
            self.host_server_path, "ebpf", tool_case_name, "vm"
        )

        # Extract command from ebpf_start file (in host-server)
        command = self._extract_command_from_ebpf_start(host_ebpf_base)

        return {
            "test_type": "vm",
            "tool_case_name": tool_case_name,
            "command": command,
            "client": self._locate_performance_data(vm_client_base, "client_results"),
            "server": {
                "performance": self._locate_performance_data(vm_server_base, "server_results"),
                "ebpf_monitoring": self._locate_ebpf_monitoring(host_ebpf_base)
            }
        }

    def _locate_performance_data(self, base_path: str, results_dir: str) -> Dict:
        """Locate performance test data files (latency, throughput, pps)

        Args:
            base_path: Base path containing results directory
            results_dir: Results directory name (client_results or server_results)

        Returns:
            Dictionary with paths to all performance data files
        """
        results_path = os.path.join(base_path, results_dir)

        if not os.path.exists(results_path):
            logger.warning(f"Results path not found: {results_path}")
            return {}

        return {
            "latency": self._locate_latency_data(results_path),
            "throughput": self._locate_throughput_data(results_path),
            "pps": self._locate_pps_data(results_path)
        }

    def _locate_latency_data(self, results_path: str) -> Dict:
        """Locate latency test data files

        Args:
            results_path: Path to client_results or server_results

        Returns:
            Dictionary with paths to latency data files
        """
        latency_path = os.path.join(results_path, "latency")
        if not os.path.exists(latency_path):
            return {}

        data = {}

        # TCP RR
        tcp_rr_pattern = os.path.join(latency_path, "tcp_rr_*", "latency_tcp_rr.txt")
        tcp_rr_file = find_latest_file(tcp_rr_pattern)
        if tcp_rr_file:
            data["tcp_rr"] = tcp_rr_file

        # UDP RR
        udp_rr_pattern = os.path.join(latency_path, "udp_rr_*", "latency_udp_rr.txt")
        udp_rr_file = find_latest_file(udp_rr_pattern)
        if udp_rr_file:
            data["udp_rr"] = udp_rr_file

        return data

    def _locate_throughput_data(self, results_path: str) -> Dict:
        """Locate throughput test data files

        Args:
            results_path: Path to client_results or server_results

        Returns:
            Dictionary with paths to throughput data files
        """
        throughput_path = os.path.join(results_path, "throughput")
        if not os.path.exists(throughput_path):
            return {}

        data = {}

        # Single stream
        single_dir = find_latest_file(os.path.join(throughput_path, "single_*"))
        if single_dir and os.path.isdir(single_dir):
            json_file = find_latest_file(os.path.join(single_dir, "throughput_single_*.json"))
            timing_file = find_latest_file(os.path.join(single_dir, "throughput_*_timing.log"))
            if json_file and timing_file:
                data["single"] = {
                    "json": json_file,
                    "timing": timing_file
                }

        # Multi stream
        multi_dir = find_latest_file(os.path.join(throughput_path, "multi_*"))
        if multi_dir and os.path.isdir(multi_dir):
            json_pattern = os.path.join(multi_dir, "throughput_multi_*.json")
            json_files = sorted(glob.glob(json_pattern))
            # Get ALL timing files for multi-stream (each stream has its own timing)
            timing_pattern = os.path.join(multi_dir, "throughput_*_timing.log")
            timing_files = sorted(glob.glob(timing_pattern))
            if json_files and timing_files:
                data["multi"] = {
                    "json_files": json_files,
                    "timing_files": timing_files  # All timing files for aggregation
                }

        return data

    def _locate_pps_data(self, results_path: str) -> Dict:
        """Locate PPS test data files

        Args:
            results_path: Path to client_results or server_results

        Returns:
            Dictionary with paths to PPS data files
        """
        pps_path = os.path.join(results_path, "pps")
        if not os.path.exists(pps_path):
            return {}

        data = {}

        # Single stream
        single_dir = find_latest_file(os.path.join(pps_path, "single_*"))
        if single_dir and os.path.isdir(single_dir):
            json_file = find_latest_file(os.path.join(single_dir, "pps_single_*.json"))
            timing_file = find_latest_file(os.path.join(single_dir, "pps_*_timing.log"))
            if json_file and timing_file:
                data["single"] = {
                    "json": json_file,
                    "timing": timing_file
                }

        # Multi stream
        multi_dir = find_latest_file(os.path.join(pps_path, "multi_*"))
        if multi_dir and os.path.isdir(multi_dir):
            json_pattern = os.path.join(multi_dir, "pps_multi_*.json")
            json_files = sorted(glob.glob(json_pattern))
            # Get ALL timing files for multi-stream (each stream has its own timing)
            timing_pattern = os.path.join(multi_dir, "pps_*_timing.log")
            timing_files = sorted(glob.glob(timing_pattern))
            if json_files and timing_files:
                data["multi"] = {
                    "json_files": json_files,
                    "timing_files": timing_files  # All timing files for aggregation
                }

        return data

    def _locate_ebpf_monitoring(self, base_path: str) -> Dict:
        """Locate eBPF monitoring data files

        Args:
            base_path: Base path containing ebpf_monitoring directory

        Returns:
            Dictionary with paths to monitoring data files
        """
        monitoring_path = os.path.join(base_path, "ebpf_monitoring")
        if not os.path.exists(monitoring_path):
            logger.warning(f"eBPF monitoring path not found: {monitoring_path}")
            return {}

        data = {}

        # Resource monitor
        resource_pattern = os.path.join(monitoring_path, "ebpf_resource_monitor_*.log")
        resource_file = find_latest_file(resource_pattern)
        if resource_file:
            data["resource_monitor"] = resource_file

        # Log size monitor
        logsize_pattern = os.path.join(monitoring_path, "ebpf_logsize_monitor_*.log")
        logsize_file = find_latest_file(logsize_pattern)
        if logsize_file:
            data["logsize_monitor"] = logsize_file

        return data

    def _extract_command_from_ebpf_start(self, base_path: str) -> Optional[str]:
        """Extract full command from ebpf_start file

        Args:
            base_path: Base path containing ebpf_start file

        Returns:
            Full command string or None
        """
        ebpf_start_pattern = os.path.join(base_path, "ebpf_start_*.log")
        ebpf_start_file = find_latest_file(ebpf_start_pattern)

        if not ebpf_start_file:
            return None

        try:
            with open(ebpf_start_file, 'r') as f:
                for line in f:
                    # Look for the "Command: " line
                    if line.startswith("Command: "):
                        command = line.replace("Command: ", "").strip()
                        return command
        except Exception as e:
            logger.warning(f"Failed to read ebpf_start file {ebpf_start_file}: {e}")

        return None

    def get_all_tool_cases(self, topic: str) -> List[str]:
        """Get all tool case names for a specific topic

        Args:
            topic: Topic name (e.g., "system_network_performance" or tool name like "system_network_perfomance_metrics")

        Returns:
            List of tool case names
        """
        tool_cases = []

        # Try to find tool cases in both host and vm paths
        # First check host-server ebpf path
        host_ebpf_path = os.path.join(self.host_server_path, "ebpf")
        vm_ebpf_path = os.path.join(self.vm_server_path, "ebpf")

        ebpf_path = None

        # Check host path first
        if os.path.exists(host_ebpf_path):
            for item in os.listdir(host_ebpf_path):
                if item.startswith(topic + "_case_"):
                    ebpf_path = host_ebpf_path
                    break

        # If not found in host, check vm path
        if ebpf_path is None and os.path.exists(vm_ebpf_path):
            for item in os.listdir(vm_ebpf_path):
                if item.startswith(topic + "_case_"):
                    ebpf_path = vm_ebpf_path
                    break

        if ebpf_path is None:
            logger.warning(f"No tool cases found for topic: {topic}")
            return []

        # Find all directories matching the topic pattern
        for item in os.listdir(ebpf_path):
            item_path = os.path.join(ebpf_path, item)
            if os.path.isdir(item_path) and item.startswith(topic + "_case_"):
                tool_cases.append(item)

        tool_cases.sort()
        logger.info(f"Found {len(tool_cases)} tool cases for topic {topic}")
        return tool_cases
