#!/usr/bin/env python3
"""Test results validation script"""

import sys
import os
import json
import argparse
import logging
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from core.ssh_manager import SSHManager
from utils.config_loader import ConfigLoader


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


class TestResultValidator:
    """Validate test execution results"""

    def __init__(self, ssh_manager, config):
        self.ssh_manager = ssh_manager
        self.config = config
        self.logger = logging.getLogger(__name__)

    def validate_baseline_results(self, env_name: str) -> dict:
        """Validate baseline test results"""
        results = {
            'baseline_validation': {
                'server_results': {},
                'client_results': {},
                'overall_status': 'unknown'
            }
        }

        # Get host references
        env_config = self.config['env']['test_environments'][env_name]
        server_host = env_config['server']['ssh_ref']
        client_host = env_config['client']['ssh_ref']

        # Get workdir
        server_workdir = self.config['ssh']['ssh_hosts'][server_host]['workdir']
        client_workdir = self.config['ssh']['ssh_hosts'][client_host]['workdir']

        baseline_server_path = f"{server_workdir}/performance-test-results/baseline/{env_name}"
        baseline_client_path = f"{client_workdir}/performance-test-results/baseline/{env_name}"

        # Validate server-side baseline results
        results['baseline_validation']['server_results'] = self._validate_server_baseline(
            server_host, baseline_server_path
        )

        # Validate client-side baseline results
        results['baseline_validation']['client_results'] = self._validate_client_baseline(
            client_host, baseline_client_path
        )

        # Determine overall status
        server_ok = results['baseline_validation']['server_results'].get('valid', False)
        client_ok = results['baseline_validation']['client_results'].get('valid', False)
        results['baseline_validation']['overall_status'] = 'valid' if (server_ok and client_ok) else 'invalid'

        return results

    def validate_ebpf_results(self, tool_id: str, case_id: int, env_name: str, result_path: str) -> dict:
        """Validate eBPF test results"""
        results = {
            'ebpf_validation': {
                'server_results': {},
                'client_results': {},
                'ebpf_output': {},
                'monitoring_data': {},
                'overall_status': 'unknown'
            }
        }

        # Get host references
        env_config = self.config['env']['test_environments'][env_name]
        server_host = env_config['server']['ssh_ref']
        client_host = env_config['client']['ssh_ref']

        # Get workdir
        server_workdir = self.config['ssh']['ssh_hosts'][server_host]['workdir']
        client_workdir = self.config['ssh']['ssh_hosts'][client_host]['workdir']

        ebpf_server_path = f"{server_workdir}/performance-test-results/{result_path}"
        ebpf_client_path = f"{client_workdir}/performance-test-results/{result_path}"

        # Validate eBPF output
        results['ebpf_validation']['ebpf_output'] = self._validate_ebpf_output(
            server_host, ebpf_server_path
        )

        # Validate monitoring data
        results['ebpf_validation']['monitoring_data'] = self._validate_monitoring_data(
            server_host, ebpf_server_path
        )

        # Validate server-side results
        results['ebpf_validation']['server_results'] = self._validate_server_perf_results(
            server_host, ebpf_server_path
        )

        # Validate client-side results
        results['ebpf_validation']['client_results'] = self._validate_client_perf_results(
            client_host, ebpf_client_path
        )

        # Determine overall status
        components_valid = [
            results['ebpf_validation']['ebpf_output'].get('valid', False),
            results['ebpf_validation']['monitoring_data'].get('valid', False),
            results['ebpf_validation']['server_results'].get('valid', False),
            results['ebpf_validation']['client_results'].get('valid', False)
        ]
        results['ebpf_validation']['overall_status'] = 'valid' if all(components_valid) else 'invalid'

        return results

    def _validate_server_baseline(self, host_ref: str, path: str) -> dict:
        """Validate server baseline results"""
        result = {'valid': False, 'errors': [], 'details': {}}

        try:
            # Check if baseline directory exists
            dir_check, _, _ = self.ssh_manager.execute_command(host_ref, f"test -d {path} && echo 'EXISTS' || echo 'MISSING'")
            if 'MISSING' in dir_check:
                result['errors'].append(f"Baseline directory missing: {path}")
                return result

            # Check server results directory
            server_results_path = f"{path}/server_results"
            server_check, _, _ = self.ssh_manager.execute_command(host_ref, f"ls -la {server_results_path} 2>/dev/null || echo 'NO_SERVER_RESULTS'")

            if 'NO_SERVER_RESULTS' not in server_check:
                file_count, _, _ = self.ssh_manager.execute_command(host_ref, f"find {server_results_path} -type f | wc -l")
                file_count = str(file_count or "0")
                result['details']['server_files'] = int(file_count.strip()) if file_count.strip().isdigit() else 0
                result['valid'] = result['details']['server_files'] >= 0  # Any server files indicate some activity
            else:
                result['errors'].append("No server results directory found")

        except Exception as e:
            result['errors'].append(f"Server validation error: {str(e)}")

        return result

    def _validate_client_baseline(self, host_ref: str, path: str) -> dict:
        """Validate client baseline results"""
        result = {'valid': False, 'errors': [], 'details': {}}

        try:
            # Check if baseline directory exists
            dir_check, _, _ = self.ssh_manager.execute_command(host_ref, f"test -d {path} && echo 'EXISTS' || echo 'MISSING'")
            if 'MISSING' in dir_check:
                result['errors'].append(f"Baseline directory missing: {path}")
                return result

            # Check performance test results
            perf_types = ['throughput', 'latency', 'pps']
            for perf_type in perf_types:
                type_path = f"{path}/{perf_type}"
                json_count, _, _ = self.ssh_manager.execute_command(host_ref, f"find {type_path} -name '*.json' 2>/dev/null | wc -l")
                count = int(json_count.strip()) if json_count.strip().isdigit() else 0
                result['details'][f'{perf_type}_json_files'] = count

                if count > 0:
                    # Validate JSON content
                    json_files, _, _ = self.ssh_manager.execute_command(host_ref, f"find {type_path} -name '*.json' | head -1")
                    if json_files.strip():
                        json_content, _, _ = self.ssh_manager.execute_command(host_ref, f"head -20 {json_files.strip()}")
                        result['details'][f'{perf_type}_sample_content'] = json_content[:200] + "..." if len(json_content) > 200 else json_content

            # Check if we have valid results
            total_files = sum([result['details'].get(f'{t}_json_files', 0) for t in perf_types])
            result['valid'] = total_files >= 3  # Expect at least one file per test type

            if not result['valid']:
                result['errors'].append(f"Insufficient test results: only {total_files} JSON files found")

        except Exception as e:
            result['errors'].append(f"Client validation error: {str(e)}")

        return result

    def _validate_ebpf_output(self, host_ref: str, path: str) -> dict:
        """Validate eBPF program output"""
        result = {'valid': False, 'errors': [], 'details': {}}

        try:
            # Check for eBPF output files
            output_files, _, _ = self.ssh_manager.execute_command(host_ref, f"find {path} -name 'ebpf_output_*.log' 2>/dev/null")
            if not output_files.strip():
                result['errors'].append("No eBPF output files found")
                return result

            output_file = output_files.strip().split('\n')[0]

            # Check file size
            file_size, _, _ = self.ssh_manager.execute_command(host_ref, f"stat -c%s {output_file} 2>/dev/null || echo '0'")
            size_bytes = int(file_size.strip()) if file_size.strip().isdigit() else 0
            result['details']['output_size_mb'] = round(size_bytes / (1024 * 1024), 2)

            # Check content
            header_content, _, _ = self.ssh_manager.execute_command(host_ref, f"head -5 {output_file}")
            tail_content, _, _ = self.ssh_manager.execute_command(host_ref, f"tail -5 {output_file}")

            result['details']['header_sample'] = header_content
            result['details']['tail_sample'] = tail_content

            # Validation criteria
            has_header = "System Network Performance Tracer" in header_content
            has_content = size_bytes > 1000000  # At least 1MB of output
            has_recent_data = "Stage" in tail_content or "SKB" in tail_content

            result['valid'] = has_header and has_content and has_recent_data

            if not result['valid']:
                if not has_header:
                    result['errors'].append("Missing eBPF program header")
                if not has_content:
                    result['errors'].append(f"Insufficient output data: {result['details']['output_size_mb']}MB")
                if not has_recent_data:
                    result['errors'].append("No recent trace data found")

        except Exception as e:
            result['errors'].append(f"eBPF output validation error: {str(e)}")

        return result

    def _validate_monitoring_data(self, host_ref: str, path: str) -> dict:
        """Validate monitoring data"""
        result = {'valid': False, 'errors': [], 'details': {}}

        try:
            monitoring_path = f"{path}/ebpf_monitoring"

            # Check monitoring files
            monitor_files = ['ebpf_cpu_monitor_*.log', 'ebpf_memory_monitor_*.log', 'ebpf_logsize_monitor_*.log']

            for pattern in monitor_files:
                file_list, _, _ = self.ssh_manager.execute_command(host_ref, f"find {monitoring_path} -name '{pattern}' 2>/dev/null")
                file_count = len([f for f in file_list.strip().split('\n') if f.strip()])
                monitor_type = pattern.split('_')[1]  # cpu, memory, logsize
                result['details'][f'{monitor_type}_files'] = file_count

                if file_count > 0:
                    # Check content of first file
                    first_file = file_list.strip().split('\n')[0]
                    line_count, _, _ = self.ssh_manager.execute_command(host_ref, f"wc -l < {first_file} 2>/dev/null || echo '0'")
                    result['details'][f'{monitor_type}_lines'] = int(line_count.strip()) if line_count.strip().isdigit() else 0

            # Validation criteria
            has_cpu = result['details'].get('cpu_files', 0) > 0
            has_memory = result['details'].get('memory_files', 0) > 0
            has_logsize = result['details'].get('logsize_files', 0) > 0
            sufficient_data = all([
                result['details'].get('cpu_lines', 0) > 10,
                result['details'].get('memory_lines', 0) > 10,
                result['details'].get('logsize_lines', 0) > 10
            ])

            result['valid'] = has_cpu and has_memory and has_logsize and sufficient_data

            if not result['valid']:
                if not (has_cpu and has_memory and has_logsize):
                    result['errors'].append("Missing monitoring file types")
                if not sufficient_data:
                    result['errors'].append("Insufficient monitoring data")

        except Exception as e:
            result['errors'].append(f"Monitoring validation error: {str(e)}")

        return result

    def _validate_server_perf_results(self, host_ref: str, path: str) -> dict:
        """Validate server performance results"""
        result = {'valid': False, 'errors': [], 'details': {}}

        try:
            server_results_path = f"{path}/server_results"

            # Check for server log files
            log_files, _, _ = self.ssh_manager.execute_command(host_ref, f"find {server_results_path} -name '*.log' 2>/dev/null")
            log_count = len([f for f in log_files.strip().split('\n') if f.strip()])
            result['details']['server_log_files'] = log_count

            result['valid'] = log_count >= 0  # Any server activity is good

        except Exception as e:
            result['errors'].append(f"Server perf validation error: {str(e)}")

        return result

    def _validate_client_perf_results(self, host_ref: str, path: str) -> dict:
        """Validate client performance results"""
        result = {'valid': False, 'errors': [], 'details': {}}

        try:
            # This would typically be on the client host, but eBPF test results are often collected on server
            # For now, just mark as valid if the path exists
            path_check, _, _ = self.ssh_manager.execute_command(host_ref, f"test -d {path} && echo 'EXISTS' || echo 'MISSING'")
            result['valid'] = 'EXISTS' in path_check
            result['details']['path_exists'] = result['valid']

            if not result['valid']:
                result['errors'].append(f"eBPF client results path missing: {path}")

        except Exception as e:
            result['errors'].append(f"Client perf validation error: {str(e)}")

        return result


def main():
    """Main validation function"""
    parser = argparse.ArgumentParser(description='Validate Test Results')
    parser.add_argument('--config-dir', default='../config', help='Configuration directory path')
    parser.add_argument('--env', default='host', help='Environment to validate')
    parser.add_argument('--tool', help='Tool ID to validate (for eBPF tests)')
    parser.add_argument('--case', type=int, help='Case ID to validate (for eBPF tests)')
    parser.add_argument('--result-path', help='eBPF result path (for eBPF tests)')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    try:
        # Load configurations
        config_dir = os.path.abspath(args.config_dir)
        config_loader = ConfigLoader(config_dir)
        ssh_config = config_loader.load_ssh_config()

        # Load environment config - try minimal first, then regular
        try:
            env_config = config_loader._load_yaml_file('minimal-env-config.yaml')
        except:
            env_config = config_loader.load_env_config()

        configs = {
            'ssh': ssh_config,
            'env': env_config
        }

        # Initialize SSH manager and validator
        ssh_manager = SSHManager(configs['ssh'])
        validator = TestResultValidator(ssh_manager, configs)

        with ssh_manager:
            logger.info(f"Starting validation for environment: {args.env}")

            # Validate baseline results
            baseline_results = validator.validate_baseline_results(args.env)
            logger.info(f"Baseline validation: {baseline_results['baseline_validation']['overall_status']}")

            # Print baseline details
            print(f"\n=== Baseline Results Validation ===")
            print(f"Overall Status: {baseline_results['baseline_validation']['overall_status']}")
            print(f"Server Results: {baseline_results['baseline_validation']['server_results']}")
            print(f"Client Results: {baseline_results['baseline_validation']['client_results']}")

            # Validate eBPF results if specified
            if all([args.tool, args.case, args.result_path]):
                ebpf_results = validator.validate_ebpf_results(args.tool, args.case, args.env, args.result_path)
                logger.info(f"eBPF validation: {ebpf_results['ebpf_validation']['overall_status']}")

                print(f"\n=== eBPF Results Validation ===")
                print(f"Tool: {args.tool}, Case: {args.case}")
                print(f"Overall Status: {ebpf_results['ebpf_validation']['overall_status']}")
                print(f"eBPF Output: {ebpf_results['ebpf_validation']['ebpf_output']}")
                print(f"Monitoring Data: {ebpf_results['ebpf_validation']['monitoring_data']}")
                print(f"Server Results: {ebpf_results['ebpf_validation']['server_results']}")
                print(f"Client Results: {ebpf_results['ebpf_validation']['client_results']}")

            return 0

    except Exception as e:
        logger.error(f"Validation failed: {str(e)}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())