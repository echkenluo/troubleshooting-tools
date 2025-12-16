#!/usr/bin/env python3
"""Test execution engine - remote execution"""

import json
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

from .ssh_manager import SSHManager
from .remote_path_manager import RemotePathManager
from hooks.init_hooks import InitHooks
from hooks.post_hooks import PostHooks
from hooks.custom_hooks import CustomHooks


logger = logging.getLogger(__name__)


class TestExecutor:
    """Test execution engine for remote test runs"""

    def __init__(self, ssh_manager: SSHManager, path_manager: RemotePathManager, config=None):
        """Initialize test executor

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
            config: Full configuration dict
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager
        self.config = config or {}
        self.current_test_context = {}
        self.ebpf_processes = {}

        # Initialize hooks with config
        self.init_hooks = InitHooks(ssh_manager, path_manager, config)
        self.post_hooks = PostHooks(ssh_manager, path_manager, self.init_hooks)
        self.custom_hooks = CustomHooks(ssh_manager, path_manager)

    def execute_workflow(self, workflow_spec: Dict) -> Dict:
        """Execute complete workflow

        Args:
            workflow_spec: Workflow specification

        Returns:
            Execution results
        """
        results = {
            "start_time": datetime.now().isoformat(),
            "test_cycles": [],
            "status": "running"
        }

        try:
            # Execute global init using hooks
            global_context = self._prepare_global_context(workflow_spec)
            global_init_result = self.init_hooks.execute_hook(
                "global", "init", global_context
            )
            logger.info(f"Global init completed: {global_init_result}")

            # Execute each test cycle
            for cycle in workflow_spec['test_sequence']:
                logger.info(f"Executing test cycle: {cycle['cycle_id']}")
                cycle_result = self._execute_test_cycle(cycle, workflow_spec)
                results['test_cycles'].append(cycle_result)

            # Execute global post using hooks
            global_post_result = self.post_hooks.execute_hook(
                "global", "post", global_context
            )
            logger.info(f"Global post completed: {global_post_result}")

            results['status'] = "completed"
        except Exception as e:
            logger.error(f"Workflow execution failed: {str(e)}")
            results['status'] = "failed"
            results['error'] = str(e)
        finally:
            results['end_time'] = datetime.now().isoformat()

        return results

    def _execute_test_cycle(self, cycle: Dict, workflow_spec: Dict) -> Dict:
        """Execute single test cycle using layered hooks

        Args:
            cycle: Test cycle configuration
            workflow_spec: Complete workflow spec

        Returns:
            Cycle execution results
        """
        cycle_result = {
            "cycle_id": cycle['cycle_id'],
            "start_time": datetime.now().isoformat(),
            "status": "running"
        }

        try:
            # Prepare cycle context
            cycle_context = self._prepare_cycle_context(cycle, workflow_spec)

            # Tool-level init (if new tool)
            tool_id = cycle.get('ebpf_case', {}).get('tool_id')
            if tool_id and tool_id not in self.ebpf_processes:
                tool_context = self._prepare_tool_context(tool_id, cycle, workflow_spec)
                tool_init_result = self.init_hooks.execute_hook(
                    "tool", "init", tool_context
                )
                logger.info(f"Tool init for {tool_id}: {tool_init_result}")

            # Case-level init
            case_init_result = self.init_hooks.execute_hook(
                "case", "init", cycle_context
            )
            logger.info(f"Case init: {case_init_result}")

            # Execute performance tests with test-level hooks
            perf_results = self._execute_performance_tests(
                cycle['test_cycle']['performance_tests'], cycle_context
            )
            cycle_result['performance_results'] = perf_results

            # Case-level post
            case_post_result = self.post_hooks.execute_hook(
                "case", "post", cycle_context
            )
            logger.info(f"Case post: {case_post_result}")

            cycle_result['status'] = "completed"
        except Exception as e:
            logger.error(f"Test cycle failed: {str(e)}")
            cycle_result['status'] = "failed"
            cycle_result['error'] = str(e)
            # Re-raise exception to stop workflow execution
            raise
        finally:
            cycle_result['end_time'] = datetime.now().isoformat()

        return cycle_result

    def _execute_global_init(self, workflow_spec: Dict):
        """Execute global initialization"""
        env_config = workflow_spec.get('global_config', {})

        for host_ref in env_config.get('ssh_hosts', {}).keys():
            # Create base directories
            workdir = env_config['ssh_hosts'][host_ref]['workdir']
            commands = [
                f"mkdir -p {workdir}/performance-test-results/{{baseline,ebpf}}",
                f"pkill -f 'iperf3.*-s' || true",
                f"pkill -f 'netserver' || true"
            ]

            for cmd in commands:
                self.ssh_manager.execute_command(host_ref, cmd)

            logger.info(f"Global init completed for {host_ref}")

    def _execute_global_post(self, workflow_spec: Dict):
        """Execute global cleanup"""
        env_config = workflow_spec.get('global_config', {})

        for host_ref in env_config.get('ssh_hosts', {}).keys():
            # Final cleanup
            commands = [
                "pkill -f 'iperf3.*-s' || true",
                "pkill -f 'netserver' || true",
                "pkill -f 'python.*ebpf' || true"
            ]

            for cmd in commands:
                self.ssh_manager.execute_command(host_ref, cmd)

            logger.info(f"Global post completed for {host_ref}")

    def _execute_baseline_init(self, cycle: Dict):
        """Execute baseline test initialization"""
        timestamp = self.path_manager.get_timestamp()
        env_name = cycle['environment']

        # Prepare test environment
        logger.info(f"Initializing baseline test for {env_name}")

        # No eBPF program to start for baseline
        self.current_test_context['ebpf_pid'] = None
        self.current_test_context['timestamp'] = timestamp

    def _execute_ebpf_init(self, cycle: Dict):
        """Execute eBPF test initialization"""
        timestamp = self.path_manager.get_timestamp()
        env_name = cycle['environment']
        ebpf_case = cycle['ebpf_case']

        logger.info(f"Initializing eBPF test: {ebpf_case['case_id']}")

        # Get host reference from environment
        host_ref = self._get_host_ref_for_env(env_name, 'server')

        # Create result directories
        result_path = self._get_result_path(cycle)
        self.ssh_manager.execute_command(
            host_ref,
            f"mkdir -p {result_path}/{{client_results,server_results,monitoring,ebpf_monitoring}}"
        )

        # Start eBPF program
        if ebpf_case['command']:
            ebpf_log = f"{result_path}/ebpf_output_{timestamp}.log"
            pid = self.ssh_manager.execute_command(
                host_ref,
                f"cd {self._get_workdir(host_ref)} && {ebpf_case['command']} > {ebpf_log} 2>&1",
                background=True
            )[0]

            self.ebpf_processes[ebpf_case['case_id']] = {
                'pid': pid,
                'host': host_ref,
                'log_file': ebpf_log
            }

            self.current_test_context['ebpf_pid'] = pid
            logger.info(f"Started eBPF program with PID: {pid}")

            # Start custom monitoring
            if cycle['test_cycle']['init_hook'].get('custom_monitoring'):
                self._start_custom_monitoring(host_ref, pid, result_path, timestamp)

        self.current_test_context['timestamp'] = timestamp

    def _execute_baseline_post(self, cycle: Dict):
        """Execute baseline test cleanup"""
        logger.info(f"Cleaning up baseline test for {cycle['environment']}")

        # Collect results
        result_path = self._get_result_path(cycle)
        timestamp = self.current_test_context.get('timestamp')

        # Write metadata
        self._write_test_metadata(cycle, result_path, timestamp)

    def _execute_ebpf_post(self, cycle: Dict):
        """Execute eBPF test cleanup"""
        ebpf_case = cycle['ebpf_case']
        case_id = ebpf_case['case_id']

        logger.info(f"Cleaning up eBPF test: {case_id}")

        if case_id in self.ebpf_processes:
            proc_info = self.ebpf_processes[case_id]

            # Stop monitoring
            self._stop_custom_monitoring(proc_info['host'])

            # Stop eBPF program
            if self.ssh_manager.check_process(proc_info['host'], proc_info['pid']):
                self.ssh_manager.kill_process(proc_info['host'], proc_info['pid'])
                logger.info(f"Stopped eBPF program PID: {proc_info['pid']}")

            del self.ebpf_processes[case_id]

        # Collect results
        result_path = self._get_result_path(cycle)
        timestamp = self.current_test_context.get('timestamp')

        # Write metadata
        self._write_test_metadata(cycle, result_path, timestamp)

    def _execute_performance_tests(self, perf_tests: List[Dict], cycle_context: Dict) -> List[Dict]:
        """Execute performance tests using test-level hooks

        Args:
            perf_tests: Performance test configurations
            cycle_context: Current cycle context

        Returns:
            Test results
        """
        results = []

        for test in perf_tests:
            test_type = test['type']
            configs = test.get('configs', [])

            logger.info(f"Executing {test_type} tests")

            for config in configs:
                # Prepare test context
                test_context = self._prepare_test_context(test_type, config, cycle_context)

                # Test-level init (start servers)
                test_init_result = self.init_hooks.execute_hook(
                    "test", "init", test_context
                )
                logger.info(f"Test init for {test_type}/{config}: {test_init_result}")

                # Execute actual performance test
                test_result = self._run_performance_test(test_type, config, test_context)

                # Test-level post (stop servers)
                test_post_result = self.post_hooks.execute_hook(
                    "test", "post", test_context
                )
                logger.info(f"Test post for {test_type}/{config}: {test_post_result}")

                results.append({
                    "test_type": test_type,
                    "config": config,
                    "result": test_result,
                    "init_status": test_init_result.get('tasks', []),
                    "post_status": test_post_result.get('tasks', [])
                })

        return results

    def _run_single_performance_test(self, test_type: str, config: str) -> Dict:
        """Run single performance test

        Args:
            test_type: Test type (throughput/latency/pps)
            config: Test configuration

        Returns:
            Test result
        """
        result = {
            "test_type": test_type,
            "config": config,
            "start_time": datetime.now().isoformat()
        }

        try:
            if test_type == "throughput":
                self._run_throughput_test(config)
            elif test_type == "latency":
                self._run_latency_test(config)
            elif test_type == "pps":
                self._run_pps_test(config)

            result['status'] = "completed"
        except Exception as e:
            logger.error(f"Performance test failed: {str(e)}")
            result['status'] = "failed"
            result['error'] = str(e)
        finally:
            result['end_time'] = datetime.now().isoformat()

        return result

    def _run_throughput_test(self, config: str):
        """Run throughput performance test"""
        # Implementation placeholder
        logger.info(f"Running throughput test: {config}")
        time.sleep(2)  # Simulate test execution

    def _run_latency_test(self, config: str):
        """Run latency performance test"""
        # Implementation placeholder
        logger.info(f"Running latency test: {config}")
        time.sleep(2)  # Simulate test execution

    def _run_pps_test(self, config: str):
        """Run PPS performance test"""
        # Implementation placeholder
        logger.info(f"Running PPS test: {config}")
        time.sleep(2)  # Simulate test execution

    def _start_custom_monitoring(self, host_ref: str, ebpf_pid: str,
                                result_path: str, timestamp: str):
        """Start custom monitoring for eBPF program"""
        monitoring_path = f"{result_path}/ebpf_monitoring"

        # CPU monitoring
        cpu_cmd = f"""nohup bash -c 'while ps -p {ebpf_pid} >/dev/null 2>&1; do \
            echo "$(date +\\"%Y-%m-%d %H:%M:%S.%N\\")" $(top -b -n 1 -p {ebpf_pid} | tail -1 | awk "{{print \\$9}}"); \
            sleep 1; done' > {monitoring_path}/tool_cpu_usage_{timestamp}.log 2>&1 &"""
        self.ssh_manager.execute_command(host_ref, cpu_cmd)

        # Memory monitoring
        mem_cmd = f"""nohup bash -c 'while ps -p {ebpf_pid} >/dev/null 2>&1; do \
            echo "$(date +\\"%Y-%m-%d %H:%M:%S.%N\\")" $(ps -p {ebpf_pid} -o vsz,rss --no-headers); \
            sleep 1; done' > {monitoring_path}/tool_memory_{timestamp}.log 2>&1 &"""
        self.ssh_manager.execute_command(host_ref, mem_cmd)

        logger.info(f"Started custom monitoring for PID: {ebpf_pid}")

    def _stop_custom_monitoring(self, host_ref: str):
        """Stop custom monitoring processes"""
        # Kill monitoring processes
        commands = [
            "pkill -f 'tool_cpu_usage' || true",
            "pkill -f 'tool_memory' || true"
        ]

        for cmd in commands:
            self.ssh_manager.execute_command(host_ref, cmd)

        logger.info("Stopped custom monitoring")

    def _set_test_context(self, cycle: Dict, workflow_spec: Dict):
        """Set current test context"""
        self.current_test_context = {
            'cycle': cycle,
            'workflow': workflow_spec,
            'environment': cycle['environment']
        }

    def _get_result_path(self, cycle: Dict) -> str:
        """Get result path for test cycle"""
        base_workdir = "/home/smartx/lcc"  # Default, should be from config
        results_dir = f"{base_workdir}/performance-test-results"

        if cycle['cycle_type'] == 'baseline':
            return f"{results_dir}/{cycle['result_path']}"
        else:
            return f"{results_dir}/{cycle['result_path']}"

    def _get_workdir(self, host_ref: str) -> str:
        """Get working directory for host"""
        # Should get from config
        if 'vm' in host_ref:
            return "/root/lcc"
        else:
            return "/home/smartx/lcc"

    def _get_host_ref_for_env(self, env_name: str, role: str) -> str:
        """Get host reference for environment and role"""
        # Map environment and role to host reference
        return f"{env_name}-{role}"

    def _write_test_metadata(self, cycle: Dict, result_path: str, timestamp: str):
        """Write test metadata to remote"""
        metadata = {
            "cycle_id": cycle['cycle_id'],
            "cycle_type": cycle['cycle_type'],
            "environment": cycle['environment'],
            "timestamp": timestamp,
            "execution_time": datetime.now().isoformat()
        }

        metadata_file = f"{result_path}/metadata_{timestamp}.json"
        metadata_json = json.dumps(metadata, indent=2)

        host_ref = self._get_host_ref_for_env(cycle['environment'], 'server')
        self.ssh_manager.execute_command(
            host_ref,
            f"echo '{metadata_json}' > {metadata_file}"
        )

        logger.info(f"Wrote metadata to {metadata_file}")

    def _prepare_global_context(self, workflow_spec: Dict) -> Dict:
        """Prepare global context for hooks"""
        context = {
            'targets': ['server', 'client'],
            'workflow': workflow_spec
        }

        # Add host references from config if available
        if 'ssh' in self.config and 'env' in self.config:
            ssh_hosts = self.config['ssh']['ssh_hosts']
            for env_name, env_config in self.config['env']['test_environments'].items():
                server_ref = env_config['server']['ssh_ref']
                client_ref = env_config['client']['ssh_ref']

                context[f'{env_name}_server_host_ref'] = server_ref
                context[f'{env_name}_client_host_ref'] = client_ref

                if server_ref in ssh_hosts:
                    context[f'{env_name}_server_workdir'] = ssh_hosts[server_ref]['workdir']
                if client_ref in ssh_hosts:
                    context[f'{env_name}_client_workdir'] = ssh_hosts[client_ref]['workdir']

        return context

    def _prepare_cycle_context(self, cycle: Dict, workflow_spec: Dict) -> Dict:
        """Prepare cycle context for hooks"""
        timestamp = self.path_manager.get_timestamp()
        env_name = cycle['environment']

        # DEBUG: Log cycle data
        logger.info(f"DEBUG: _prepare_cycle_context for cycle_id={cycle.get('cycle_id')}")
        logger.info(f"DEBUG: cycle['ebpf_case'] = {cycle.get('ebpf_case')}")

        # Get workdir from SSH config if available
        workdir = "/tmp"  # default
        host_ref = "host-server"  # default
        ebpf_host_ref = "host-server"  # default
        ebpf_workdir = "/tmp"  # default

        if 'ssh' in self.config and 'env' in self.config:
            env_config = self.config['env']['test_environments'].get(env_name, {})
            server_config = env_config.get('server', {})

            # Get performance test host_ref (where tests run, could be VM or physical host)
            host_ref = server_config.get('ssh_ref', host_ref)

            if host_ref in self.config['ssh']['ssh_hosts']:
                workdir = self.config['ssh']['ssh_hosts'][host_ref]['workdir']

            # Get eBPF monitoring host_ref (where eBPF programs run)
            # For VM environment, use physical_host_ref; otherwise use same as host_ref
            ebpf_host_ref = server_config.get('physical_host_ref', host_ref)

            if ebpf_host_ref in self.config['ssh']['ssh_hosts']:
                ebpf_workdir = self.config['ssh']['ssh_hosts'][ebpf_host_ref]['workdir']

        # Generate result path for performance tests (on VM or physical host)
        if cycle['cycle_type'] == 'baseline':
            result_path = f"{workdir}/performance-test-results/baseline/{env_name}"
        else:
            result_path = f"{workdir}/performance-test-results/{cycle['result_path']}"

        # Generate result path for eBPF monitoring (on physical host)
        if cycle['cycle_type'] == 'baseline':
            ebpf_result_path = f"{ebpf_workdir}/performance-test-results/baseline/{env_name}"
        else:
            ebpf_result_path = f"{ebpf_workdir}/performance-test-results/{cycle['result_path']}"

        context = {
            'cycle': cycle,
            'timestamp': timestamp,
            'environment': env_name,
            'host_ref': host_ref,              # Performance test host (VM or physical)
            'ebpf_host_ref': ebpf_host_ref,    # eBPF monitoring host (physical host)
            'workdir': workdir,                # Performance test workdir
            'ebpf_workdir': ebpf_workdir,      # eBPF monitoring workdir
            'result_path': result_path,        # Performance test result path
            'ebpf_result_path': ebpf_result_path,  # eBPF monitoring result path
            'tool_id': cycle.get('ebpf_case', {}).get('tool_id'),
            'case_id': cycle.get('ebpf_case', {}).get('case_id'),
            'ebpf_command': cycle.get('ebpf_case', {}).get('command'),
            'workflow': workflow_spec  # Add workflow_spec to context
        }

        # DEBUG: Log final context
        logger.info(f"DEBUG: Prepared context - tool_id={context['tool_id']}, case_id={context['case_id']}")
        logger.info(f"DEBUG: Prepared context - ebpf_command={repr(context['ebpf_command'])}")

        return context

    def _prepare_tool_context(self, tool_id: str, cycle: Dict, workflow_spec: Dict) -> Dict:
        """Prepare tool context for hooks"""
        env_name = cycle['environment']
        host_ref = "host-server"
        workdir = "/tmp"

        if 'ssh' in self.config and 'env' in self.config:
            env_config = self.config['env']['test_environments'].get(env_name, {})
            server_config = env_config.get('server', {})
            host_ref = server_config.get('ssh_ref', host_ref)

            if host_ref in self.config['ssh']['ssh_hosts']:
                workdir = self.config['ssh']['ssh_hosts'][host_ref]['workdir']

        return {
            'tool_id': tool_id,
            'environment': env_name,
            'host_ref': host_ref,
            'workdir': workdir
        }

    def _prepare_test_context(self, test_type: str, config: str, cycle_context: Dict) -> Dict:
        """Prepare test context for hooks"""
        env_name = cycle_context['environment']
        timestamp = self.path_manager.get_timestamp()

        # Default values
        server_ip = "127.0.0.1"
        client_ip = "127.0.0.1"
        server_host_ref = "host-server"
        client_host_ref = "host-client"
        interface = "eth0"

        if 'env' in self.config:
            env_config = self.config['env']['test_environments'].get(env_name, {})
            server_config = env_config.get('server', {})
            client_config = env_config.get('client', {})

            server_ip = server_config.get('test_ip', server_ip)
            client_ip = client_config.get('test_ip', client_ip)
            server_host_ref = server_config.get('ssh_ref', server_host_ref)
            client_host_ref = client_config.get('ssh_ref', client_host_ref)
            interface = server_config.get('interface', interface)

        # Read duration, streams, and target_bw from workflow's global_config.performance_specs FIRST
        workflow_spec = cycle_context.get('workflow', {})
        perf_specs = workflow_spec.get('global_config', {}).get('performance_specs', {})

        duration = None
        streams = None
        target_bw = None

        if test_type == "throughput":
            throughput_spec = perf_specs.get('throughput', {})
            if config == "single_stream":
                single_spec = throughput_spec.get('single_stream', {})
                duration = single_spec.get('duration', 30)
                # Read target_bw if configured, otherwise None (unlimited)
                target_bw = self._get_config_value(single_spec.get('target_bw'), None)
            elif config == "multi_stream":
                multi_spec = throughput_spec.get('multi_stream', {})
                duration = multi_spec.get('duration', 30)
                streams = self._get_config_value(multi_spec.get('streams'), 2)
                # Read target_bw if configured, otherwise None (unlimited)
                target_bw = self._get_config_value(multi_spec.get('target_bw'), None)

        elif test_type == "latency":
            latency_spec = perf_specs.get('latency', {})
            duration = latency_spec.get('duration', 20)

        elif test_type == "pps":
            pps_spec = perf_specs.get('pps', {})
            if config == "single_stream":
                single_spec = pps_spec.get('single_stream', {})
                duration = single_spec.get('duration', 5)
                target_bw = self._get_config_value(single_spec.get('target_bw'), '1G')
            elif config == "multi_stream":
                multi_spec = pps_spec.get('multi_stream', {})
                duration = multi_spec.get('duration', 5)
                streams = self._get_config_value(multi_spec.get('streams'), 2)
                target_bw = self._get_config_value(multi_spec.get('target_bw'), '1G')

        # NOW determine result path after we have streams - organized by test_type then config
        conn_type = self._get_connection_type(config, streams)
        base_result_path = cycle_context['result_path']
        # Create test_type subdirectory within server_results for better organization
        result_path = f"{base_result_path}/server_results/{test_type}/{conn_type}_{timestamp}"

        return {
            'test_type': test_type,
            'test_config': config,
            'server_ip': server_ip,
            'client_ip': client_ip,
            'server_host_ref': server_host_ref,
            'client_host_ref': client_host_ref,
            'result_path': result_path,
            'interface': interface,
            'timestamp': timestamp,
            'duration': duration,      # From workflow config
            'streams': streams,        # From workflow config
            'target_bw': target_bw     # From workflow config
        }

    def _run_performance_test(self, test_type: str, config: str, test_context: Dict) -> Dict:
        """Run actual performance test with real commands"""
        result = {
            "test_type": test_type,
            "config": config,
            "start_time": datetime.now().isoformat()
        }

        try:
            if test_type == "throughput":
                result = self._run_throughput_test(config, test_context)
            elif test_type == "latency":
                result = self._run_latency_test(config, test_context)
            elif test_type == "pps":
                result = self._run_pps_test(config, test_context)

            result['status'] = "completed"
        except Exception as e:
            logger.error(f"Performance test failed: {str(e)}")
            result['status'] = "failed"
            result['error'] = str(e)
        finally:
            result['end_time'] = datetime.now().isoformat()

        return result

    def _run_throughput_test(self, config: str, test_context: Dict) -> Dict:
        """Run throughput test with iperf3"""
        result = {"type": "throughput", "config": config}

        client_host = test_context['client_host_ref']
        server_host = test_context['server_host_ref']
        server_ip = test_context['server_ip']
        client_ip = test_context['client_ip']
        result_path = test_context['result_path']

        # Ensure result directories exist on both client and server
        client_result_path = result_path.replace('server_results', 'client_results')
        mkdir_cmd = f"mkdir -p {client_result_path}"
        self.ssh_manager.execute_command(client_host, mkdir_cmd)
        # Also ensure server result path exists
        server_mkdir_cmd = f"mkdir -p {result_path}"
        self.ssh_manager.execute_command(server_host, server_mkdir_cmd)

        if config == "single_stream":
            # Get configuration from test_context
            duration = test_context.get('duration', 30)
            target_bw = test_context.get('target_bw', None)

            # Record test start time and run TCP throughput test
            start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            result_file = f"{client_result_path}/throughput_single_tcp.json"
            timing_file = f"{client_result_path}/throughput_single_timing.log"

            # Record test timing
            timing_cmd = f"echo 'Test: throughput_single_tcp' > {timing_file} && echo 'Start: {start_time}' >> {timing_file}"
            self.ssh_manager.execute_command(client_host, timing_cmd)

            # Build command with optional -b parameter
            if target_bw:
                cmd = f"iperf3 -c {server_ip} -B {client_ip} -p 5001 -t {duration} -b {target_bw} -l 65520 -J > {result_file} 2>&1"
            else:
                cmd = f"iperf3 -c {server_ip} -B {client_ip} -p 5001 -t {duration} -l 65520 -J > {result_file} 2>&1"
            stdout, stderr, status = self.ssh_manager.execute_command(client_host, cmd)

            # Record test end time
            end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            end_timing_cmd = f"echo 'End: {end_time}' >> {timing_file}"
            self.ssh_manager.execute_command(client_host, end_timing_cmd)

            if status == 0:
                result['tcp_output'] = result_file
                result['timing_file'] = timing_file
            else:
                result['tcp_error'] = stderr

        elif config == "multi_stream":
            # Get configuration from test_context
            streams = test_context.get('streams', 2)  # Default 2 streams
            duration = test_context.get('duration', 30)
            target_bw = test_context.get('target_bw', None)  # Read from config, None = unlimited

            base_port = 5001
            result['client_files'] = []
            result['timing_files'] = []
            result['process_start_times'] = []
            result['streams'] = streams

            # Record multi-stream test start
            test_start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

            # Launch multiple client processes in parallel
            client_cmds = []
            for i in range(streams):
                port = base_port + i
                client_file = f"{client_result_path}/throughput_multi_stream_{i+1}_port_{port}.json"
                timing_file = f"{client_result_path}/throughput_multi_stream_{i+1}_port_{port}_timing.log"

                # Record per-process timing
                process_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                timing_cmd = f"echo 'Test: throughput_multi_stream_process_{i+1}_port_{port}' > {timing_file} && echo 'Process_Start: {process_start}' >> {timing_file}"
                self.ssh_manager.execute_command(client_host, timing_cmd)

                # Build command with optional -b parameter
                if target_bw:
                    client_cmd = f"iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -J > {client_file} 2>&1 &"
                else:
                    client_cmd = f"iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -J > {client_file} 2>&1 &"
                client_cmds.append(client_cmd)
                result['client_files'].append(client_file)
                result['timing_files'].append(timing_file)
                result['process_start_times'].append(process_start)

            # Start all client processes
            for i, cmd in enumerate(client_cmds):
                self.ssh_manager.execute_command(client_host, cmd)
                # Record actual launch time
                launch_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                timing_file = result['timing_files'][i]
                launch_cmd = f"echo 'Actual_Launch: {launch_time}' >> {timing_file}"
                self.ssh_manager.execute_command(client_host, launch_cmd)

            # Wait for all processes to complete (duration + 2 seconds buffer)
            wait_cmd = f"sleep {duration + 2}"
            self.ssh_manager.execute_command(client_host, wait_cmd)

            # Record multi-stream test end
            test_end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            for timing_file in result['timing_files']:
                end_cmd = f"echo 'Test_End: {test_end_time}' >> {timing_file}"
                self.ssh_manager.execute_command(client_host, end_cmd)

            result['test_start_time'] = test_start_time
            result['test_end_time'] = test_end_time
            result['success'] = True

        return result

    def _run_latency_test(self, config: str, test_context: Dict) -> Dict:
        """Run latency test with netperf"""
        result = {"type": "latency", "config": config}

        client_host = test_context['client_host_ref']
        server_host = test_context['server_host_ref']
        server_ip = test_context['server_ip']
        result_path = test_context['result_path']

        # Get configuration from test_context
        duration = test_context.get('duration', 20)

        # Ensure result directories exist on both client and server
        client_result_path = result_path.replace('server_results', 'client_results')
        mkdir_cmd = f"mkdir -p {client_result_path}"
        self.ssh_manager.execute_command(client_host, mkdir_cmd)
        # Also ensure server result path exists
        server_mkdir_cmd = f"mkdir -p {result_path}"
        self.ssh_manager.execute_command(server_host, server_mkdir_cmd)

        test_type = "TCP_RR" if config == "tcp_rr" else "UDP_RR"
        protocol = "tcp" if config == "tcp_rr" else "udp"
        result_file = f"{client_result_path}/latency_{protocol}_rr.txt"
        cmd = f"netperf -H {server_ip} -p 12865 -t {test_type} -l {duration} -- -o min_latency,mean_latency,max_latency > {result_file} 2>&1"

        stdout, stderr, status = self.ssh_manager.execute_command(client_host, cmd)

        if status == 0:
            result['output'] = result_file
        else:
            result['error'] = stderr

        return result

    def _run_pps_test(self, config: str, test_context: Dict) -> Dict:
        """Run PPS test with iperf3 small packets"""
        result = {"type": "pps", "config": config}

        # Get configuration from test_context
        duration = test_context.get('duration', 5)
        target_bw = test_context.get('target_bw', '1G')  # Read from config

        # Determine stream count from test_context
        if config == "single_stream":
            streams = 1
        else:
            # For multi_stream, read from test_context (which reads from global_config)
            streams = test_context.get('streams', 2)

        client_host = test_context['client_host_ref']
        server_host = test_context['server_host_ref']
        server_ip = test_context['server_ip']
        client_ip = test_context['client_ip']
        result_path = test_context['result_path']
        base_port = 5001

        # Ensure result directories exist on both client and server
        client_result_path = result_path.replace('server_results', 'client_results')
        mkdir_cmd = f"mkdir -p {client_result_path}"
        self.ssh_manager.execute_command(client_host, mkdir_cmd)
        # Also ensure server result path exists
        server_mkdir_cmd = f"mkdir -p {result_path}"
        self.ssh_manager.execute_command(server_host, server_mkdir_cmd)

        result['client_files'] = []
        result['streams'] = streams

        # Record PPS test start time
        test_start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        result['timing_files'] = []
        result['process_start_times'] = []

        # Launch client processes for PPS test
        client_cmds = []
        for i in range(streams):
            port = base_port + i
            if config == "single_stream":
                client_file = f"{client_result_path}/pps_single_tcp.json"
                timing_file = f"{client_result_path}/pps_single_timing.log"
            else:
                client_file = f"{client_result_path}/pps_multi_stream_{i+1}_port_{port}.json"
                timing_file = f"{client_result_path}/pps_multi_stream_{i+1}_port_{port}_timing.log"

            # Record per-process timing
            process_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            timing_cmd = f"echo 'Test: pps_{config}_process_{i+1}_port_{port}' > {timing_file} && echo 'Process_Start: {process_start}' >> {timing_file}"
            self.ssh_manager.execute_command(client_host, timing_cmd)

            # Use small packets (64 bytes) for PPS testing with configured target_bw
            client_cmd = f"iperf3 -c {server_ip} -B {client_ip} -p {port} -t {duration} -b {target_bw} -l 64 -J > {client_file} 2>&1 &"
            client_cmds.append(client_cmd)
            result['client_files'].append(client_file)
            result['timing_files'].append(timing_file)
            result['process_start_times'].append(process_start)

        # Start all client processes
        for i, cmd in enumerate(client_cmds):
            self.ssh_manager.execute_command(client_host, cmd)
            # Record actual launch time
            launch_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            timing_file = result['timing_files'][i]
            launch_cmd = f"echo 'Actual_Launch: {launch_time}' >> {timing_file}"
            self.ssh_manager.execute_command(client_host, launch_cmd)

        # Wait for all processes to complete (duration + 2 seconds buffer)
        wait_cmd = f"sleep {duration + 2}"
        self.ssh_manager.execute_command(client_host, wait_cmd)

        # Record test end time
        test_end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        for timing_file in result['timing_files']:
            end_cmd = f"echo 'Test_End: {test_end_time}' >> {timing_file}"
            self.ssh_manager.execute_command(client_host, end_cmd)

        result['test_start_time'] = test_start_time
        result['test_end_time'] = test_end_time
        result['success'] = True

        return result

    def _get_config_value(self, raw_value, default=None):
        """Extract config value from either scalar or list format.

        Handles both formats for backward compatibility:
        - Scalar: target_bw: "1G" -> returns "1G"
        - List: target_bw: ["1G", "5G"] -> returns "1G" (first element)

        Args:
            raw_value: Value from config (can be scalar, list, or None)
            default: Default value if raw_value is None or empty

        Returns:
            Extracted value or default
        """
        if raw_value is None:
            return default
        if isinstance(raw_value, list):
            return raw_value[0] if raw_value else default
        return raw_value

    def _get_connection_type(self, config: str, streams: Optional[int] = None) -> str:
        """Get connection type from config string and streams count

        Args:
            config: Test configuration name (e.g., 'single_stream', 'multi_stream', 'tcp_rr')
            streams: Number of streams for multi-stream tests (optional)

        Returns:
            Connection type string for result path
        """
        if 'single' in config:
            return 'single'
        elif 'multi' in config:
            # Use provided streams count if available
            if streams is not None:
                return f"multi_{streams}"
            # Otherwise try to parse from config string
            parts = config.split('_')
            for part in parts:
                if part.isdigit():
                    return f"multi_{part}"
            return 'multi_2'  # Default to 2 streams
        elif 'tcp_rr' in config:
            return 'tcp_rr'
        elif 'udp_rr' in config:
            return 'udp_rr'
        else:
            return 'single'
