#!/usr/bin/env python3
"""Remote eBPF monitoring module"""

import logging
from typing import Dict, Optional


logger = logging.getLogger(__name__)


class RemoteEBPFMonitor:
    """Remote eBPF program monitoring"""

    def __init__(self, ssh_manager, path_manager):
        """Initialize monitor

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager

    def start_monitoring(self, host_ref: str, ebpf_pid: str,
                        result_path: str) -> Dict:
        """Start comprehensive eBPF monitoring

        Args:
            host_ref: SSH host reference
            ebpf_pid: eBPF process ID
            result_path: Result storage path

        Returns:
            Monitoring start results
        """
        timestamp = self.path_manager.get_timestamp()
        monitoring_path = f"{result_path}/ebpf_monitoring"

        # Ensure monitoring directory exists
        self.ssh_manager.execute_command(
            host_ref, f"mkdir -p {monitoring_path}"
        )

        results = {
            "monitoring_start": timestamp,
            "ebpf_pid": ebpf_pid,
            "monitors": []
        }

        # CPU monitoring
        cpu_result = self._start_cpu_monitoring(
            host_ref, ebpf_pid, monitoring_path, timestamp
        )
        results["monitors"].append(cpu_result)

        # Memory monitoring
        memory_result = self._start_memory_monitoring(
            host_ref, ebpf_pid, monitoring_path, timestamp
        )
        results["monitors"].append(memory_result)

        # Log size monitoring
        log_file = f"{result_path}/ebpf_output_{timestamp}.log"
        logsize_result = self._start_logsize_monitoring(
            host_ref, ebpf_pid, log_file, monitoring_path, timestamp
        )
        results["monitors"].append(logsize_result)

        return results

    def stop_monitoring(self, host_ref: str) -> Dict:
        """Stop all eBPF monitoring processes

        Args:
            host_ref: SSH host reference

        Returns:
            Stop results
        """
        # Kill all monitoring processes
        stop_commands = [
            "pkill -f 'tool_cpu_usage' || true",
            "pkill -f 'tool_memory' || true",
            "pkill -f 'tool_logsize' || true"
        ]

        results = {"stopped_monitors": []}

        for cmd in stop_commands:
            stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
            results["stopped_monitors"].append({
                "command": cmd,
                "success": status == 0
            })

        return results

    def _start_cpu_monitoring(self, host_ref: str, ebpf_pid: str,
                             monitoring_path: str, timestamp: str) -> Dict:
        """Start CPU monitoring"""
        cmd = f"""
            nohup bash -c '
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(top -b -n 1 -p {ebpf_pid} | tail -1 | awk "{{print \\$9}}")"
                    sleep 1
                done
            ' > {monitoring_path}/tool_cpu_usage_{timestamp}.log 2>&1 &
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)

        return {
            "type": "cpu_monitoring",
            "log_file": f"{monitoring_path}/tool_cpu_usage_{timestamp}.log",
            "started": status == 0
        }

    def _start_memory_monitoring(self, host_ref: str, ebpf_pid: str,
                                monitoring_path: str, timestamp: str) -> Dict:
        """Start memory monitoring"""
        cmd = f"""
            nohup bash -c '
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(ps -p {ebpf_pid} -o vsz,rss,pmem --no-headers)"
                    sleep 1
                done
            ' > {monitoring_path}/tool_memory_{timestamp}.log 2>&1 &
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)

        return {
            "type": "memory_monitoring",
            "log_file": f"{monitoring_path}/tool_memory_{timestamp}.log",
            "started": status == 0
        }

    def _start_logsize_monitoring(self, host_ref: str, ebpf_pid: str,
                                 log_file: str, monitoring_path: str,
                                 timestamp: str) -> Dict:
        """Start log size monitoring"""
        cmd = f"""
            nohup bash -c '
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    SIZE=$(stat -c %s "{log_file}" 2>/dev/null || echo 0)
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$SIZE"
                    sleep 1
                done
            ' > {monitoring_path}/tool_logsize_{timestamp}.log 2>&1 &
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)

        return {
            "type": "logsize_monitoring",
            "target_file": log_file,
            "log_file": f"{monitoring_path}/tool_logsize_{timestamp}.log",
            "started": status == 0
        }
