#!/usr/bin/env python3
"""Remote path manager"""

import hashlib
from datetime import datetime
from typing import Dict, Optional


class RemotePathManager:
    """Remote path manager"""

    def __init__(self, base_workdir: str):
        """Initialize path manager

        Args:
            base_workdir: Base working directory
        """
        self.base_workdir = base_workdir
        self.results_dir = f"{base_workdir}/performance-test-results"

    def get_timestamp(self, format_type: str = "file") -> str:
        """Get timestamp

        Args:
            format_type: Timestamp format type (file/log/precise)

        Returns:
            Formatted timestamp string
        """
        now = datetime.now()

        if format_type == "file":
            return now.strftime("%Y%m%d_%H%M%S")
        elif format_type == "log":
            return now.strftime("%Y-%m-%d %H:%M:%S")
        elif format_type == "precise":
            return now.strftime("%Y-%m-%d %H:%M:%S.%f")
        else:
            return now.strftime("%Y%m%d_%H%M%S")

    def generate_params_hash(self, protocol: str, direction: str,
                           other_params: Optional[str] = None) -> str:
        """Generate parameter hash

        Args:
            protocol: Protocol type
            direction: Direction (rx/tx)
            other_params: Other parameters

        Returns:
            6-character hash
        """
        params_str = f"{protocol}_{direction}"
        if other_params:
            params_str += f"_{other_params}"

        hash_value = hashlib.md5(params_str.encode()).hexdigest()[:6]
        return hash_value

    def get_baseline_path(self, test_env: str, perf_test_type: str,
                         conn_type: str, timestamp: Optional[str] = None) -> str:
        """Get baseline test path

        Args:
            test_env: Test environment (host/vm)
            perf_test_type: Performance test type
            conn_type: Connection type
            timestamp: Timestamp

        Returns:
            Full path
        """
        if timestamp is None:
            timestamp = self.get_timestamp()

        return f"{self.results_dir}/baseline/{test_env}/{perf_test_type}/{conn_type}_{timestamp}"

    def get_ebpf_test_path(self, tool_id: str, case_id: str,
                          test_params: Dict, test_env: str,
                          perf_test_type: str, conn_type: str,
                          timestamp: Optional[str] = None) -> str:
        """Get eBPF test path

        Args:
            tool_id: Tool ID
            case_id: Case ID
            test_params: Test parameters
            test_env: Test environment
            perf_test_type: Performance test type
            conn_type: Connection type
            timestamp: Timestamp

        Returns:
            Full path
        """
        if timestamp is None:
            timestamp = self.get_timestamp()

        # Generate parameter hash
        params_hash = self.generate_params_hash(
            test_params.get('protocol', 'tcp'),
            test_params.get('direction', 'rx'),
            test_params.get('extra', '')
        )

        tool_case_dir = f"{tool_id}_case_{case_id}_{test_params.get('protocol', 'tcp')}_{test_params.get('direction', 'rx')}_{params_hash}"

        return f"{self.results_dir}/ebpf/{tool_case_dir}/{test_env}/{perf_test_type}/{conn_type}_{timestamp}"

    def get_monitoring_path(self, base_path: str, monitoring_type: str) -> str:
        """Get monitoring data path

        Args:
            base_path: Base path
            monitoring_type: Monitoring type

        Returns:
            Monitoring path
        """
        if monitoring_type == "ebpf":
            return f"{base_path}/ebpf_monitoring"
        else:
            return f"{base_path}/monitoring"

    def get_client_results_path(self, base_path: str) -> str:
        """Get client results path"""
        return f"{base_path}/client_results"

    def get_server_results_path(self, base_path: str) -> str:
        """Get server results path"""
        return f"{base_path}/server_results"

    def format_connection_type(self, is_multi: bool, stream_count: int = 0) -> str:
        """Format connection type

        Args:
            is_multi: Multi-connection flag
            stream_count: Stream count

        Returns:
            Formatted connection type string
        """
        if is_multi:
            return f"multi_{stream_count}"
        else:
            return "single"

    def get_metadata_path(self, base_path: str, timestamp: Optional[str] = None) -> str:
        """Get metadata file path

        Args:
            base_path: Base path
            timestamp: Timestamp

        Returns:
            Metadata file path
        """
        if timestamp is None:
            timestamp = self.get_timestamp()

        return f"{base_path}/metadata_{timestamp}.json"

    def get_hook_result_path(self, base_path: str, hook_type: str,
                           timestamp: Optional[str] = None) -> str:
        """Get hook result path

        Args:
            base_path: Base path
            hook_type: Hook type
            timestamp: Timestamp

        Returns:
            Hook result path
        """
        if timestamp is None:
            timestamp = self.get_timestamp()

        return f"{base_path}/{hook_type}_{timestamp}.log"