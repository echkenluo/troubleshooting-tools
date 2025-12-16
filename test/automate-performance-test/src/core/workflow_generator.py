#!/usr/bin/env python3
"""eBPF-centric workflow generator.

Supports two modes:
1. Legacy: Generate workflow from ebpf_config (ebpf-tools-config.yaml)
2. Unified: Generate workflow from pre-generated test cases (cases.json)
"""

import json
import hashlib
import os
import re
from datetime import datetime
from typing import Dict, List, Optional


class EBPFCentricWorkflowGenerator:
    """Generate eBPF-centric test workflow"""

    def __init__(self, testcase_loader=None, base_path=None):
        """Initialize workflow generator

        Args:
            testcase_loader: TestcaseLoader instance
            base_path: Base path for testcase files
        """
        self.testcase_loader = testcase_loader
        # Auto-detect base_path if not provided
        if base_path is None:
            # Try to auto-detect from current file location
            # This file is at: <repo>/test/automate-performance-test/src/core/workflow_generator.py
            current_file = os.path.abspath(__file__)
            # Go up: core -> src -> automate-performance-test -> test -> repo
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(current_file)))))
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"WorkflowGenerator auto-detected base_path: {base_path}")
        self.base_path = base_path

    def generate_workflow_spec(self, ssh_config: Dict, env_config: Dict,
                             perf_spec: Dict, ebpf_config: Dict) -> Dict:
        """Generate complete test workflow spec

        Args:
            ssh_config: SSH configuration
            env_config: Environment configuration
            perf_spec: Performance test specs
            ebpf_config: eBPF tools configuration

        Returns:
            Complete workflow specification
        """
        workflow_spec = {
            "metadata": {
                "generation_time": datetime.now().isoformat(),
                "total_test_cycles": 0,
                "environments": list(env_config['test_environments'].keys())
            },
            "test_sequence": [],
            "global_config": {
                "ssh_hosts": ssh_config['ssh_hosts'],
                "performance_specs": perf_spec['performance_tests']
            }
        }

        # Generate baseline test cycles
        for env_name in env_config['test_environments'].keys():
            baseline_cycle = self._generate_baseline_test_cycle(
                env_name, env_config, perf_spec
            )
            workflow_spec["test_sequence"].append(baseline_cycle)

        # Generate eBPF case test cycles
        for tool_id, tool_config in ebpf_config['ebpf_tools'].items():
            for case_id in tool_config['testcase_source']['case_ids']:
                for env_name in tool_config['test_associations']['applicable_environments']:
                    ebpf_cycle = self._generate_ebpf_test_cycle(
                        tool_id, case_id, env_name, tool_config,
                        env_config, perf_spec
                    )
                    workflow_spec["test_sequence"].append(ebpf_cycle)

        workflow_spec["metadata"]["total_test_cycles"] = len(workflow_spec["test_sequence"])
        return workflow_spec

    def _generate_baseline_test_cycle(self, env_name: str, env_config: Dict,
                                     perf_spec: Dict) -> Dict:
        """Generate baseline test cycle (no eBPF program)"""
        return {
            "cycle_id": f"baseline_{env_name}",
            "cycle_type": "baseline",
            "environment": env_name,
            "ebpf_case": {
                "case_id": "baseline",
                "program": None,
                "command": None,
                "duration": None
            },
            "test_cycle": {
                "init_hook": {
                    "tasks": [
                        "prepare_test_environment",
                        "start_performance_servers",
                        "prepare_monitoring_tools"
                    ],
                    "custom_monitoring": False
                },
                "performance_tests": self._get_performance_tests_for_env(env_name, perf_spec),
                "post_hook": {
                    "tasks": [
                        "collect_baseline_results",
                        "stop_performance_servers",
                        "cleanup_environment"
                    ]
                }
            },
            "expected_duration": self._calculate_cycle_duration(perf_spec),
            "result_path": f"baseline/{env_name}"
        }

    def _generate_ebpf_test_cycle(self, tool_id: str, case_id: int, env_name: str,
                                 tool_config: Dict, env_config: Dict,
                                 perf_spec: Dict) -> Dict:
        """Generate eBPF tool test cycle"""
        # Load case details from testcase file
        case_details = self._load_case_details(
            tool_config['testcase_source']['file'], case_id
        )

        # Extract parameters from case for path generation
        test_params = self._extract_test_params(case_details)

        return {
            "cycle_id": f"{tool_id}_case_{case_id}_{env_name}",
            "cycle_type": "ebpf_test",
            "environment": env_name,
            "ebpf_case": {
                "case_id": case_id,
                "tool_id": tool_id,
                "program": case_details.get("name", ""),
                "command": case_details.get("command", ""),
                "duration": case_details.get("duration", 30),
                "test_params": test_params
            },
            "test_cycle": {
                "init_hook": {
                    "tasks": [
                        "prepare_test_environment",
                        "start_performance_servers",
                        f"start_ebpf_case_{case_id}",
                        "start_custom_monitoring"
                    ],
                    "custom_monitoring": True,
                    "ebpf_startup_command": case_details.get("command", "")
                },
                "performance_tests": self._get_applicable_performance_tests(
                    tool_config['test_associations']['performance_test_types'],
                    perf_spec
                ),
                "post_hook": {
                    "tasks": [
                        "stop_custom_monitoring",
                        f"stop_ebpf_case_{case_id}",
                        f"collect_ebpf_results_{tool_id}_{case_id}",
                        "cleanup_environment"
                    ]
                }
            },
            "monitoring_config": tool_config['resource_monitoring'],
            "expected_duration": self._calculate_cycle_duration(perf_spec) + case_details.get("duration", 30),
            "result_path": self._generate_ebpf_result_path(tool_id, case_id, test_params, env_name)
        }

    def _get_performance_tests_for_env(self, env_name: str, perf_spec: Dict) -> List[Dict]:
        """Get performance test configurations for environment"""
        # Generate PPS configs - unified style (no stream count in config name)
        pps_configs = []
        if 'pps' in perf_spec['performance_tests']:
            pps_config = perf_spec['performance_tests']['pps']
            # Add single_stream if it exists
            if 'single_stream' in pps_config:
                pps_configs.append('single_stream')
            # Add multi_stream config (without stream count suffix)
            if 'multi_stream' in pps_config:
                pps_configs.append('multi_stream')

        return [
            {
                "type": "throughput",
                "configs": ["single_stream", "multi_stream"]
            },
            {
                "type": "latency",
                "configs": ["tcp_rr", "udp_rr"]
            },
            {
                "type": "pps",
                "configs": pps_configs
            }
        ]

    def _get_applicable_performance_tests(self, test_types: List[str],
                                         perf_spec: Dict) -> List[Dict]:
        """Get applicable performance tests"""
        tests = []
        for test_type in test_types:
            if test_type == "throughput":
                tests.append({
                    "type": "throughput",
                    "configs": ["single_stream", "multi_stream"]
                })
            elif test_type == "latency":
                tests.append({
                    "type": "latency",
                    "configs": ["tcp_rr", "udp_rr"]
                })
            elif test_type == "pps":
                # Generate PPS configs - unified style (no stream count in config name)
                pps_configs = []
                if 'pps' in perf_spec['performance_tests']:
                    pps_config = perf_spec['performance_tests']['pps']
                    # Add single_stream if it exists
                    if 'single_stream' in pps_config:
                        pps_configs.append('single_stream')
                    # Add multi_stream config (without stream count suffix)
                    if 'multi_stream' in pps_config:
                        pps_configs.append('multi_stream')
                tests.append({
                    "type": "pps",
                    "configs": pps_configs
                })
        return tests

    def _calculate_cycle_duration(self, perf_spec: Dict) -> int:
        """Calculate total duration for test cycle"""
        total_duration = 0

        # Throughput test duration
        if 'throughput' in perf_spec['performance_tests']:
            throughput = perf_spec['performance_tests']['throughput']
            total_duration += throughput.get('single_stream', {}).get('duration', 30)
            total_duration += throughput.get('multi_stream', {}).get('duration', 30) * 3

        # Latency test duration
        if 'latency' in perf_spec['performance_tests']:
            latency = perf_spec['performance_tests']['latency']
            total_duration += latency.get('duration', 20) * 2  # TCP and UDP

        # PPS test duration
        if 'pps' in perf_spec['performance_tests']:
            pps = perf_spec['performance_tests']['pps']
            total_duration += pps.get('duration', 30) * 2  # Multiple streams

        return total_duration

    def _load_case_details(self, testcase_file: str, case_id: int) -> Dict:
        """Load case details from testcase file

        Args:
            testcase_file: Path to testcase file
            case_id: Case ID to load

        Returns:
            Case details dictionary
        """
        if self.testcase_loader:
            # Use TestcaseLoader if available
            return self.testcase_loader.get_case_details(testcase_file, case_id)
        else:
            # Try to load directly
            try:
                from utils.testcase_loader import TestcaseLoader
                loader = TestcaseLoader(self.base_path)
                return loader.get_case_details(testcase_file, case_id)
            except:
                # Fallback to placeholder
                return {
                    "name": f"case_{case_id}",
                    "command": f"python ebpf_tool.py --case {case_id}",
                    "duration": 30
                }

    def _extract_test_params(self, case_details: Dict) -> Dict:
        """Extract test parameters from case details

        Args:
            case_details: Case details from testcase

        Returns:
            Test parameters dict
        """
        params = {}
        command = case_details.get('command', '')

        # Extract protocol
        if '--protocol tcp' in command or 'tcp' in case_details.get('name', '').lower():
            params['protocol'] = 'tcp'
        elif '--protocol udp' in command or 'udp' in case_details.get('name', '').lower():
            params['protocol'] = 'udp'
        else:
            params['protocol'] = 'tcp'  # default

        # Extract direction
        if '--direction rx' in command or '_rx_' in case_details.get('name', ''):
            params['direction'] = 'rx'
        elif '--direction tx' in command or '_tx_' in case_details.get('name', ''):
            params['direction'] = 'tx'
        else:
            params['direction'] = 'rx'  # default

        # Extract other params from command
        params['extra'] = ''
        if '--internal-interface' in command:
            match = re.search(r'--internal-interface\s+(\S+)', command)
            if match:
                params['extra'] += f"iface_{match.group(1)}"

        return params

    def _generate_ebpf_result_path(self, tool_id: str, case_id: int,
                                   test_params: Dict, env_name: str) -> str:
        """Generate eBPF result path with params hash

        Args:
            tool_id: Tool ID
            case_id: Case ID
            test_params: Test parameters
            env_name: Environment name

        Returns:
            Result path string
        """
        # Generate params hash
        protocol = test_params.get('protocol', 'tcp')
        direction = test_params.get('direction', 'rx')
        extra = test_params.get('extra', '')

        params_str = f"{protocol}_{direction}"
        if extra:
            params_str += f"_{extra}"

        params_hash = hashlib.md5(params_str.encode()).hexdigest()[:6]

        return f"ebpf/{tool_id}_case_{case_id}_{protocol}_{direction}_{params_hash}/{env_name}"

    def export_workflow(self, workflow_spec: Dict, output_file: str):
        """Export workflow to JSON file

        Args:
            workflow_spec: Workflow specification
            output_file: Output file path
        """
        with open(output_file, 'w') as f:
            json.dump(workflow_spec, f, indent=2)

    def validate_workflow(self, workflow_spec: Dict) -> bool:
        """Validate workflow specification

        Args:
            workflow_spec: Workflow to validate

        Returns:
            Validation status
        """
        required_keys = ['metadata', 'test_sequence', 'global_config']

        # Check required keys
        for key in required_keys:
            if key not in workflow_spec:
                return False

        # Check test sequence
        if not workflow_spec['test_sequence']:
            return False

        # Check each test cycle
        for cycle in workflow_spec['test_sequence']:
            if 'cycle_id' not in cycle or 'cycle_type' not in cycle:
                return False

        return True

    # ==================== Unified Test Cases Support ====================

    def generate_workflow_from_cases(self, ssh_config: Dict, env_config: Dict,
                                     perf_spec: Dict, test_cases: List[Dict]) -> Dict:
        """Generate workflow spec from pre-generated test cases.

        This method supports the new unified config format where test cases
        are generated by ConfigBootstrap and stored in a JSON file.

        Args:
            ssh_config: SSH configuration
            env_config: Environment configuration
            perf_spec: Performance test specs
            test_cases: List of test case dictionaries from cases.json

        Returns:
            Complete workflow specification
        """
        workflow_spec = {
            "metadata": {
                "generation_time": datetime.now().isoformat(),
                "total_test_cycles": 0,
                "environments": list(env_config['test_environments'].keys()),
                "source": "unified_test_cases"
            },
            "test_sequence": [],
            "global_config": {
                "ssh_hosts": ssh_config['ssh_hosts'],
                "performance_specs": perf_spec['performance_tests']
            }
        }

        # Generate baseline test cycles for each environment
        for env_name in env_config['test_environments'].keys():
            baseline_cycle = self._generate_baseline_test_cycle(
                env_name, env_config, perf_spec
            )
            workflow_spec["test_sequence"].append(baseline_cycle)

        # Generate eBPF test cycles from pre-generated cases
        for case in test_cases:
            env_name = case.get('environment', 'host')

            # Skip if environment not in config
            if env_name not in env_config['test_environments']:
                continue

            ebpf_cycle = self._generate_ebpf_cycle_from_case(
                case, env_name, env_config, perf_spec
            )
            workflow_spec["test_sequence"].append(ebpf_cycle)

        workflow_spec["metadata"]["total_test_cycles"] = len(workflow_spec["test_sequence"])
        return workflow_spec

    def _generate_ebpf_cycle_from_case(self, case: Dict, env_name: str,
                                       env_config: Dict, perf_spec: Dict) -> Dict:
        """Generate eBPF test cycle from a pre-generated test case.

        Args:
            case: Test case dictionary from cases.json
            env_name: Environment name
            env_config: Environment configuration
            perf_spec: Performance test specs

        Returns:
            eBPF test cycle specification
        """
        case_id = case.get('id', 0)
        tool_id = case.get('script', '').replace('.py', '').replace('.bt', '').replace('-', '_')
        params = case.get('parameters', {})

        # Extract test params
        test_params = {
            'protocol': params.get('protocol', 'tcp'),
            'direction': params.get('direction', 'rx'),
            'extra': ''
        }

        return {
            "cycle_id": f"{tool_id}_case_{case_id}_{env_name}",
            "cycle_type": "ebpf_test",
            "environment": env_name,
            "ebpf_case": {
                "case_id": case_id,
                "tool_id": tool_id,
                "program": case.get('name', ''),
                "command": case.get('command', ''),
                "duration": case.get('duration', 10),
                "test_params": test_params,
                "category": case.get('category', ''),
                "script": case.get('script', '')
            },
            "test_cycle": {
                "init_hook": {
                    "tasks": [
                        "prepare_test_environment",
                        "start_performance_servers",
                        f"start_ebpf_case_{case_id}",
                        "start_custom_monitoring"
                    ],
                    "custom_monitoring": True,
                    "ebpf_startup_command": case.get('command', '')
                },
                "performance_tests": self._get_performance_tests_for_env(env_name, perf_spec),
                "post_hook": {
                    "tasks": [
                        "stop_custom_monitoring",
                        f"stop_ebpf_case_{case_id}",
                        f"collect_ebpf_results_{tool_id}_{case_id}",
                        "cleanup_environment"
                    ]
                }
            },
            "monitoring_config": {
                "cpu": True,
                "memory": True,
                "log_size": True
            },
            "expected_duration": self._calculate_cycle_duration(perf_spec) + case.get('duration', 10),
            "result_path": self._generate_ebpf_result_path(tool_id, case_id, test_params, env_name)
        }

    def generate_workflow_auto(self, ssh_config: Dict, env_config: Dict,
                              perf_spec: Dict, ebpf_config: Dict = None,
                              test_cases: List[Dict] = None) -> Dict:
        """Auto-detect format and generate workflow.

        Args:
            ssh_config: SSH configuration
            env_config: Environment configuration
            perf_spec: Performance test specs
            ebpf_config: eBPF tools configuration (legacy format)
            test_cases: Pre-generated test cases (unified format)

        Returns:
            Complete workflow specification
        """
        # Prefer test_cases if available
        if test_cases and len(test_cases) > 0:
            return self.generate_workflow_from_cases(
                ssh_config, env_config, perf_spec, test_cases
            )

        # Fall back to legacy format
        if ebpf_config and 'ebpf_tools' in ebpf_config and ebpf_config['ebpf_tools']:
            return self.generate_workflow_spec(
                ssh_config, env_config, perf_spec, ebpf_config
            )

        # No test cases - generate baseline only
        return self._generate_baseline_only_workflow(
            ssh_config, env_config, perf_spec
        )

    def _generate_baseline_only_workflow(self, ssh_config: Dict, env_config: Dict,
                                        perf_spec: Dict) -> Dict:
        """Generate workflow with only baseline tests (no eBPF cases)."""
        workflow_spec = {
            "metadata": {
                "generation_time": datetime.now().isoformat(),
                "total_test_cycles": 0,
                "environments": list(env_config['test_environments'].keys()),
                "source": "baseline_only"
            },
            "test_sequence": [],
            "global_config": {
                "ssh_hosts": ssh_config['ssh_hosts'],
                "performance_specs": perf_spec['performance_tests']
            }
        }

        for env_name in env_config['test_environments'].keys():
            baseline_cycle = self._generate_baseline_test_cycle(
                env_name, env_config, perf_spec
            )
            workflow_spec["test_sequence"].append(baseline_cycle)

        workflow_spec["metadata"]["total_test_cycles"] = len(workflow_spec["test_sequence"])
        return workflow_spec