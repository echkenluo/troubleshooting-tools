#!/usr/bin/env python3
"""Custom hooks - remote monitoring during test execution"""

import logging
from typing import Dict, List, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class CustomHooks:
    """Custom hooks for remote monitoring and specialized tasks"""

    def __init__(self, ssh_manager, path_manager):
        """Initialize custom hooks

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager
        self.monitoring_processes = {}

    def start_case_level_monitoring(self, context: Dict) -> Dict:
        """Start case-level monitoring

        Args:
            context: Monitoring context

        Returns:
            Monitoring start results
        """
        results = {"hook_type": "case_level_monitoring", "action": "start", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        case_id = context.get('case_id')
        ebpf_pid = context.get('ebpf_pid')
        environment = context.get('environment')
        host_ref = context.get('host_ref')
        result_path = context.get('result_path')

        if not ebpf_pid:
            results['error'] = "No eBPF process to monitor"
            return results

        monitoring_path = f"{result_path}/ebpf_monitoring"

        # eBPF CPU monitoring
        cpu_monitor_result = self._start_ebpf_cpu_monitoring(
            host_ref, ebpf_pid, monitoring_path, timestamp
        )
        results['tasks'].append(cpu_monitor_result)

        # eBPF memory monitoring
        memory_monitor_result = self._start_ebpf_memory_monitoring(
            host_ref, ebpf_pid, monitoring_path, timestamp
        )
        results['tasks'].append(memory_monitor_result)

        # eBPF log size monitoring
        log_file = f"{result_path}/ebpf_output_{timestamp}.log"
        logsize_monitor_result = self._start_ebpf_log_size_monitoring(
            host_ref, ebpf_pid, log_file, monitoring_path, timestamp
        )
        results['tasks'].append(logsize_monitor_result)

        # Store monitoring context
        self.monitoring_processes[case_id] = {
            'host_ref': host_ref,
            'ebpf_pid': ebpf_pid,
            'monitoring_path': monitoring_path,
            'timestamp': timestamp
        }

        return results

    def start_test_level_monitoring(self, context: Dict) -> Dict:
        """Start test-level monitoring

        Args:
            context: Monitoring context

        Returns:
            Monitoring start results
        """
        results = {"hook_type": "test_level_monitoring", "action": "start", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        test_type = context.get('test_type')
        test_duration = context.get('test_duration', 30)
        interface = context.get('interface', 'eth0')
        host_ref = context.get('host_ref')
        result_path = context.get('result_path')

        monitoring_path = f"{result_path}/monitoring"

        # Network performance monitoring
        network_result = self._start_network_performance_monitoring(
            host_ref, interface, test_duration, monitoring_path, test_type, timestamp
        )
        results['tasks'].append(network_result)

        # System performance monitoring
        system_result = self._start_system_performance_monitoring(
            host_ref, test_duration, monitoring_path, test_type, timestamp
        )
        results['tasks'].append(system_result)

        return results

    def stop_case_level_monitoring(self, case_id: str) -> Dict:
        """Stop case-level monitoring

        Args:
            case_id: Case ID to stop monitoring for

        Returns:
            Stop results
        """
        results = {"hook_type": "case_level_monitoring", "action": "stop", "tasks": []}

        if case_id not in self.monitoring_processes:
            results['error'] = f"No monitoring found for case {case_id}"
            return results

        context = self.monitoring_processes[case_id]
        host_ref = context['host_ref']
        timestamp = context['timestamp']

        # Stop all monitoring processes
        stop_commands = [
            "pkill -f 'ebpf_cpu_monitor' || true",
            "pkill -f 'ebpf_memory_monitor' || true",
            "pkill -f 'ebpf_logsize_monitor' || true"
        ]

        for cmd in stop_commands:
            self.ssh_manager.execute_command(host_ref, cmd)

        results['tasks'].append({
            'name': 'stop_all_case_monitoring',
            'status': True
        })

        # Remove from tracking
        del self.monitoring_processes[case_id]

        return results

    def _start_ebpf_cpu_monitoring(self, host_ref: str, ebpf_pid: str,
                                  monitoring_path: str, timestamp: str) -> Dict:
        """Start eBPF CPU monitoring"""
        cmd = f"""
            nohup bash -c '
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(top -b -n 1 -p {ebpf_pid} | tail -1 | awk "{{print \\$9}}")"
                    sleep 1
                done
            ' > {monitoring_path}/tool_cpu_usage_{timestamp}.log 2>&1 &
            echo $!
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
        monitor_pid = stdout.strip() if status == 0 else None

        return {
            'name': 'ebpf_cpu_monitoring',
            'status': status == 0,
            'monitor_pid': monitor_pid,
            'log_file': f"{monitoring_path}/tool_cpu_usage_{timestamp}.log"
        }

    def _start_ebpf_memory_monitoring(self, host_ref: str, ebpf_pid: str,
                                     monitoring_path: str, timestamp: str) -> Dict:
        """Start eBPF memory monitoring"""
        cmd = f"""
            nohup bash -c '
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$(ps -p {ebpf_pid} -o vsz,rss,pmem --no-headers)"
                    sleep 1
                done
            ' > {monitoring_path}/tool_memory_{timestamp}.log 2>&1 &
            echo $!
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
        monitor_pid = stdout.strip() if status == 0 else None

        return {
            'name': 'ebpf_memory_monitoring',
            'status': status == 0,
            'monitor_pid': monitor_pid,
            'log_file': f"{monitoring_path}/tool_memory_{timestamp}.log"
        }

    def _start_ebpf_log_size_monitoring(self, host_ref: str, ebpf_pid: str,
                                       log_file: str, monitoring_path: str,
                                       timestamp: str) -> Dict:
        """Start eBPF log size monitoring"""
        cmd = f"""
            nohup bash -c '
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    SIZE=$(stat -c %s "{log_file}" 2>/dev/null || echo 0)
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$SIZE"
                    sleep 1
                done
            ' > {monitoring_path}/tool_logsize_{timestamp}.log 2>&1 &
            echo $!
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
        monitor_pid = stdout.strip() if status == 0 else None

        return {
            'name': 'ebpf_log_size_monitoring',
            'status': status == 0,
            'monitor_pid': monitor_pid,
            'log_file': f"{monitoring_path}/tool_logsize_{timestamp}.log"
        }

    def _start_network_performance_monitoring(self, host_ref: str, interface: str,
                                             duration: int, monitoring_path: str,
                                             test_type: str, timestamp: str) -> Dict:
        """Start network performance monitoring"""
        cmd = f"""
            timeout {duration} sar -n DEV 1 | grep {interface} | while read line; do
                echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "$line"
            done > {monitoring_path}/network_perf_monitor_{test_type}_{timestamp}.log 2>&1 &
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)

        return {
            'name': 'network_performance_monitoring',
            'status': status == 0,
            'duration': duration,
            'log_file': f"{monitoring_path}/network_perf_monitor_{test_type}_{timestamp}.log"
        }

    def _start_system_performance_monitoring(self, host_ref: str, duration: int,
                                           monitoring_path: str, test_type: str,
                                           timestamp: str) -> Dict:
        """Start system performance monitoring"""
        cmd = f"""
            timeout {duration} bash -c '
                while true; do
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "CPU:" "$(top -bn1 | grep "Cpu(s)" | awk "{{print \\$2}}")"
                    echo "$(date "+%Y-%m-%d %H:%M:%S.%N")" "MEM:" "$(free | grep Mem | awk "{{print \\$3/\\$2*100}}")"
                    sleep 1
                done
            ' > {monitoring_path}/system_perf_monitor_{test_type}_{timestamp}.log 2>&1 &
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)

        return {
            'name': 'system_performance_monitoring',
            'status': status == 0,
            'duration': duration,
            'log_file': f"{monitoring_path}/system_perf_monitor_{test_type}_{timestamp}.log"
        }

    def execute_custom_command(self, host_ref: str, command: str,
                              result_path: str, command_name: str) -> Dict:
        """Execute custom command with timestamped logging

        Args:
            host_ref: SSH host reference
            command: Command to execute
            result_path: Path to store results
            command_name: Name for this command

        Returns:
            Execution results
        """
        timestamp = self.path_manager.get_timestamp()
        log_file = f"{result_path}/custom_{command_name}_{timestamp}.log"

        # Wrap command with timestamp logging
        wrapped_cmd = f"""
            echo "Custom command '{command_name}' started at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {log_file}
            echo "Command: {command}" >> {log_file}
            echo "--- Output ---" >> {log_file}
            {command} >> {log_file} 2>&1
            EXIT_CODE=$?
            echo "--- End Output ---" >> {log_file}
            echo "Exit code: $EXIT_CODE" >> {log_file}
            echo "Custom command '{command_name}' completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {log_file}
            exit $EXIT_CODE
        """

        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, wrapped_cmd)

        return {
            'command_name': command_name,
            'original_command': command,
            'log_file': log_file,
            'exit_code': status,
            'success': status == 0,
            'timestamp': timestamp
        }
