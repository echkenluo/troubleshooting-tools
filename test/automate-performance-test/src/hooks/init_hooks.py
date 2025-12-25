#!/usr/bin/env python3
"""Initialization hooks - remote execution"""

import logging
from typing import Dict, List, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class InitHooks:
    """Layered initialization hooks for remote execution"""

    def __init__(self, ssh_manager, path_manager, config=None):
        """Initialize hooks

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
            config: Full configuration dict (optional)
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager
        self.config = config or {}

    def execute_hook(self, stage: str, action: str, context: Dict) -> Dict:
        """Execute hook based on stage and action

        Args:
            stage: Hook stage (global/tool/case/test)
            action: Hook action (init/post)
            context: Execution context

        Returns:
            Execution results
        """
        if action != "init":
            return {"error": "Invalid action for init hooks"}

        if stage == "global":
            return self._execute_global_init(context)
        elif stage == "tool":
            return self._execute_tool_init(context)
        elif stage == "case":
            return self._execute_case_init(context)
        elif stage == "test":
            return self._execute_test_init(context)
        else:
            return {"error": f"Unknown stage: {stage}"}

    def _execute_global_init(self, context: Dict) -> Dict:
        """Execute global initialization"""
        results = {"stage": "global", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()
        targets = context.get('targets', ['server', 'client'])

        for target in targets:
            host_ref = context.get(f'{target}_host_ref')
            if not host_ref:
                continue

            workdir = context.get('workdir', '/home/smartx/lcc')
            result_base = f"{workdir}/performance-test-results"

            # Create base directories
            cmd = f"mkdir -p {result_base}/{{baseline,ebpf}}"
            stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
            results['tasks'].append({
                'name': 'create_base_directories',
                'target': target,
                'status': status == 0
            })

            # Check system requirements
            check_cmd = f"""
                echo "Checking system requirements at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/system_check_{timestamp}.log
                which iperf3 netperf python3 >> {result_base}/system_check_{timestamp}.log 2>&1
            """
            stdout, stderr, status = self.ssh_manager.execute_command(host_ref, check_cmd)
            results['tasks'].append({
                'name': 'check_system_requirements',
                'target': target,
                'status': status == 0
            })

            # Cleanup previous processes
            cleanup_cmd = """
                pkill -f "iperf3.*-s" || true
                pkill -f "netserver" || true
            """
            self.ssh_manager.execute_command(host_ref, cleanup_cmd)
            results['tasks'].append({
                'name': 'cleanup_previous_processes',
                'target': target,
                'status': True
            })

        return results

    def _execute_tool_init(self, context: Dict) -> Dict:
        """Execute tool-level initialization"""
        results = {"stage": "tool", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        environment = context.get('environment')
        host_ref = context.get('host_ref')
        workdir = context.get('workdir', '/home/smartx/lcc')

        if not all([tool_id, environment, host_ref]):
            results['error'] = "Missing required context"
            return results

        result_base = f"{workdir}/performance-test-results"

        # Create tool directories
        cmd = f"mkdir -p {result_base}/ebpf/{tool_id}"
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, cmd)
        results['tasks'].append({
            'name': 'create_tool_directories',
            'status': status == 0
        })

        # Tool specific setup
        setup_cmd = f"""
            echo "Starting tool {tool_id} in environment {environment} at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/ebpf/{tool_id}/tool_start_{timestamp}.log
        """
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, setup_cmd)
        results['tasks'].append({
            'name': 'tool_specific_setup',
            'status': status == 0
        })

        # Store tool context for monitoring cleanup
        self.tool_context = {
            'tool_id': tool_id,
            'environment': environment,
            'host_ref': host_ref,
            'workdir': workdir,
            'timestamp': timestamp
        }

        return results

    def _execute_case_init(self, context: Dict) -> Dict:
        """Execute case-level initialization"""
        results = {"stage": "case", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        case_id = context.get('case_id')
        ebpf_command = context.get('ebpf_command')
        environment = context.get('environment')

        # DEBUG: Log context to verify ebpf_command is passed correctly
        logger.info(f"DEBUG: _execute_case_init called with tool_id={tool_id}, case_id={case_id}, environment={environment}")
        logger.info(f"DEBUG: ebpf_command = {repr(ebpf_command)}")
        logger.info(f"DEBUG: ebpf_command type = {type(ebpf_command)}, bool = {bool(ebpf_command)}")

        # Performance test host (VM or physical host)
        host_ref = context.get('host_ref')
        workdir = context.get('workdir', '/home/smartx/lcc')
        result_path = context.get('result_path')

        # eBPF monitoring host (physical host, may be different from host_ref)
        ebpf_host_ref = context.get('ebpf_host_ref', host_ref)
        ebpf_workdir = context.get('ebpf_workdir', workdir)
        ebpf_result_path = context.get('ebpf_result_path', result_path)

        if not result_path:
            result_path = f"{workdir}/performance-test-results/ebpf/{tool_id}_case_{case_id}/{environment}"
        if not ebpf_result_path:
            ebpf_result_path = f"{ebpf_workdir}/performance-test-results/ebpf/{tool_id}_case_{case_id}/{environment}"

        # Create performance test directories (server_results, client_results) on test host
        # Note: client_results will be created on client host by test_init hook
        perf_cmd = f"mkdir -p {result_path}/server_results"
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, perf_cmd)
        results['tasks'].append({
            'name': 'create_performance_directories',
            'status': status == 0
        })

        # Create eBPF monitoring directories on eBPF monitoring host (physical host)
        ebpf_cmd = f"mkdir -p {ebpf_result_path}/ebpf_monitoring"
        stdout, stderr, status = self.ssh_manager.execute_command(ebpf_host_ref, ebpf_cmd)
        results['tasks'].append({
            'name': 'create_ebpf_monitoring_directories',
            'status': status == 0
        })

        # Start eBPF program if provided (on eBPF monitoring host - physical host)
        logger.info(f"DEBUG: Checking if ebpf_command exists: ebpf_command={repr(ebpf_command)}, will_execute={bool(ebpf_command)}")
        if ebpf_command:
            logger.info(f"DEBUG: ENTERED if ebpf_command block! About to start eBPF program")

            # Escape single quotes in ebpf_command for safe embedding in bash single-quoted string
            ebpf_command_escaped = ebpf_command.replace("'", "'\"'\"'")

            start_cmd = f"""
                cd {ebpf_workdir}
                echo "Starting eBPF case {case_id}: {ebpf_command}" > {ebpf_result_path}/ebpf_start_{timestamp}.log
                echo "eBPF case start time: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                echo "Command: {ebpf_command}" >> {ebpf_result_path}/ebpf_start_{timestamp}.log

                # Use setsid to create a new process group for the eBPF tool
                # This ensures all processes (sudo + python) are in the same group for easy cleanup
                setsid bash -c '
                    # Save the session leader PID (this bash process)
                    BASH_PID=$$
                    echo $BASH_PID > {ebpf_result_path}/ebpf_pgid_{timestamp}.txt
                    echo "Process group leader PID: $BASH_PID" >> {ebpf_result_path}/ebpf_start_{timestamp}.log

                    # Start the eBPF tool
                    {ebpf_command_escaped} > {ebpf_result_path}/ebpf_output_{timestamp}.log 2>&1 &
                    TOOL_PID=$!
                    echo "Tool wrapper PID: $TOOL_PID" >> {ebpf_result_path}/ebpf_start_{timestamp}.log

                    # Detect actual python process if using sudo
                    # Poll for python child process (max 10 seconds)
                    ACTUAL_PID=""
                    MAX_ATTEMPTS=20
                    ATTEMPT=0

                    while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
                        # Prefer direct child python processes (handles python, python2, python3)
                        # Match both measurement-tools/ and ebpf-tools/ for compatibility
                        FOUND_PID=$(ps -eo pid,ppid,comm,args --no-headers | awk -v target="$TOOL_PID" "(\$2 == target && \$3 ~ /^python/ && (index(\$0, \\\"measurement-tools/\\\") || index(\$0, \\\"ebpf-tools/\\\"))) {{print \$1; exit}}")
                        if [ -n "$FOUND_PID" ]; then
                            echo "DEBUG: Direct child lookup located python PID $FOUND_PID" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                        fi

                        # Fallback: search entire process group for python (covers sudo -> bash -> python)
                        if [ -z "$FOUND_PID" ]; then
                            PGID=$(ps -o pgid= -p $TOOL_PID 2>/dev/null | tr -d " ")
                            if [ -n "$PGID" ]; then
                                FOUND_PID=$(ps -eo pid,pgid,comm,args --no-headers | awk -v target="$PGID" "(\$2 == target && \$3 ~ /^python/ && (index(\$0, \\\"measurement-tools/\\\") || index(\$0, \\\"ebpf-tools/\\\"))) {{print \$1; exit}}")
                                if [ -n "$FOUND_PID" ]; then
                                    echo "DEBUG: Process-group lookup located python child PID $FOUND_PID" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                                fi
                            fi
                        fi

                        if [ -n "$FOUND_PID" ]; then
                            ACTUAL_PID=$FOUND_PID
                            echo "DEBUG: Found python child process PID $ACTUAL_PID after $((ATTEMPT * 500))ms" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                            break
                        fi

                        ATTEMPT=$((ATTEMPT + 1))
                        sleep 0.5
                    done

                    if [ -z "$ACTUAL_PID" ]; then
                        echo "DEBUG: Could not detect python child PID after 10s, using wrapper PID" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                        ACTUAL_PID=$TOOL_PID
                    else
                        # Verify process exists and get PGID
                        VERIFY_INFO=$(ps -p $ACTUAL_PID -o pid,pgid,cmd 2>/dev/null | tail -1)
                        if [ -n "$VERIFY_INFO" ]; then
                            echo "DEBUG: Verified process: $VERIFY_INFO" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                        fi
                    fi

                    # Save PIDs
                    echo $TOOL_PID > {ebpf_result_path}/wrapper_pid_{timestamp}.txt
                    echo $ACTUAL_PID > {ebpf_result_path}/ebpf_pid_{timestamp}.txt
                    echo "Wrapper PID: $TOOL_PID, Actual eBPF PID: $ACTUAL_PID" >> {ebpf_result_path}/ebpf_start_{timestamp}.log

                    # Verify all processes are in the same process group
                    echo "DEBUG: Process group info:" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                    ps -o pid,pgid,sid,comm -p $BASH_PID,$TOOL_PID,$ACTUAL_PID 2>&1 >> {ebpf_result_path}/ebpf_start_{timestamp}.log || true

                    echo "eBPF program started at $(date +%Y-%m-%d_%H:%M:%S)" >> {ebpf_result_path}/ebpf_start_{timestamp}.log

                    # Setup signal handlers to forward signals to child processes
                    # This ensures we can cleanly kill the entire process group
                    cleanup() {{
                        echo "Received termination signal at $(date +%Y-%m-%d_%H:%M:%S)" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                        # Kill child processes first (sudo and python)
                        if [ -n "$TOOL_PID" ] && ps -p $TOOL_PID >/dev/null 2>&1; then
                            echo "Killing wrapper process $TOOL_PID (with sudo)" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                            sudo -n kill -TERM $TOOL_PID 2>/dev/null || true
                        fi
                        if [ -n "$ACTUAL_PID" ] && ps -p $ACTUAL_PID >/dev/null 2>&1; then
                            echo "Killing actual process $ACTUAL_PID (with sudo)" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                            sudo -n kill -TERM $ACTUAL_PID 2>/dev/null || true
                        fi
                        # Wait a moment for processes to exit
                        sleep 1
                        # Force kill if still alive
                        if [ -n "$TOOL_PID" ] && ps -p $TOOL_PID >/dev/null 2>&1; then
                            sudo -n kill -KILL $TOOL_PID 2>/dev/null || true
                        fi
                        if [ -n "$ACTUAL_PID" ] && ps -p $ACTUAL_PID >/dev/null 2>&1; then
                            sudo -n kill -KILL $ACTUAL_PID 2>/dev/null || true
                        fi
                        echo "Cleanup completed at $(date +%Y-%m-%d_%H:%M:%S)" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                        exit 0
                    }}
                    trap cleanup SIGTERM SIGINT

                    # Keep this bash process alive to maintain the process group
                    # Wait for the actual eBPF process to complete
                    while ps -p $ACTUAL_PID >/dev/null 2>&1; do
                        sleep 2
                    done

                    echo "eBPF process $ACTUAL_PID exited at $(date +%Y-%m-%d_%H:%M:%S)" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                ' >> {ebpf_result_path}/ebpf_start_{timestamp}.log 2>&1 &

                # Wait longer for PID files to be created (轮询最多 10 秒,所以等待至少 1 秒)
                sleep 1

                # Read and output the actual PID for monitoring (轮询等待 PID 文件创建)
                MAX_WAIT=20
                WAITED=0
                while [ ! -f {ebpf_result_path}/ebpf_pid_{timestamp}.txt ] && [ $WAITED -lt $MAX_WAIT ]; do
                    sleep 0.5
                    WAITED=$((WAITED + 1))
                done

                if [ -f {ebpf_result_path}/ebpf_pid_{timestamp}.txt ]; then
                    cat {ebpf_result_path}/ebpf_pid_{timestamp}.txt
                else
                    echo "ERROR: Failed to create PID file after $((WAITED / 2))s" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                    echo ""
                fi
            """
            logger.info(f"DEBUG: About to execute SSH command to start eBPF on host {ebpf_host_ref}")
            stdout, stderr, status = self.ssh_manager.execute_command(ebpf_host_ref, start_cmd)
            logger.info(f"DEBUG: SSH command returned - status={status}, stdout={repr(stdout)}, stderr={repr(stderr)}")
            ebpf_pid = (stdout or "").strip()
            if status == 0 and ebpf_pid:
                logger.info(f"DEBUG: SSH command succeeded and detected eBPF PID {ebpf_pid}, continuing with monitoring setup")
                results['ebpf_pid'] = ebpf_pid
                results['tasks'].append({
                    'name': 'start_ebpf_program',
                    'status': True,
                    'pid': ebpf_pid
                })

                # Wait for BPF compilation to complete and check process health
                # This ensures we detect compilation failures before starting monitoring
                bpf_compile_wait = self.config.get('perf', {}).get('performance_tests', {}).get('bpf_compile_wait', 15)
                logger.info(f"Waiting {bpf_compile_wait}s for BPF compilation to complete...")

                health_check_cmd = f"""
                    echo "BPF compilation wait: {bpf_compile_wait}s" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                    echo "Waiting for BPF compilation at $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_start_{timestamp}.log

                    # Wait for BPF compilation
                    sleep {bpf_compile_wait}

                    # Check if process is still alive
                    if ps -p {ebpf_pid} >/dev/null 2>&1; then
                        echo "BPF compilation check PASSED: process {ebpf_pid} still alive at $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                        echo "ALIVE"
                    else
                        echo "BPF compilation check FAILED: process {ebpf_pid} exited during compilation at $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_start_{timestamp}.log
                        echo "EXITED"
                    fi
                """
                stdout, stderr, status = self.ssh_manager.execute_command(ebpf_host_ref, health_check_cmd)
                process_status = (stdout or "").strip()

                if process_status == "EXITED":
                    logger.warning(f"eBPF process {ebpf_pid} exited during BPF compilation (within {bpf_compile_wait}s)")
                    results['tasks'].append({
                        'name': 'bpf_compile_check',
                        'status': False,
                        'error': f'Process exited during BPF compilation'
                    })
                    results['ebpf_process_healthy'] = False
                else:
                    logger.info(f"eBPF process {ebpf_pid} is healthy after BPF compilation wait")
                    results['tasks'].append({
                        'name': 'bpf_compile_check',
                        'status': True
                    })
                    results['ebpf_process_healthy'] = True

                # Start tool-level monitoring (covers entire tool lifecycle) on eBPF host
                monitor_start_cmd = f'echo "eBPF monitoring start time: $(date "+%Y-%m-%d %H:%M:%S.%N"), PID: {ebpf_pid}" > {ebpf_result_path}/ebpf_monitoring/monitor_start_{timestamp}.log'
                logger.info(f"DEBUG: monitor_start_cmd = {monitor_start_cmd}")
                self.ssh_manager.execute_command(ebpf_host_ref, monitor_start_cmd)

                self._start_tool_monitoring(ebpf_host_ref, ebpf_pid, ebpf_result_path, timestamp)

                # Annotate monitor_start with monitor PIDs (resource + logsize)
                monitor_pid_annotate_cmd = f"""
                    RESOURCE_PID_FILE="{ebpf_result_path}/ebpf_monitoring/resource_monitor_pid_{timestamp}.txt"
                    LOGSIZE_PID_FILE="{ebpf_result_path}/ebpf_monitoring/logsize_monitor_pid_{timestamp}.txt"
                    MONITOR_START_FILE="{ebpf_result_path}/ebpf_monitoring/monitor_start_{timestamp}.log"

                    # Wait briefly for PID files to appear
                    ATTEMPTS=0
                    while [ ! -f "$RESOURCE_PID_FILE" ] && [ $ATTEMPTS -lt 20 ]; do
                        sleep 0.2
                        ATTEMPTS=$((ATTEMPTS + 1))
                    done

                    if [ -f "$RESOURCE_PID_FILE" ]; then
                        RESOURCE_PID=$(cat "$RESOURCE_PID_FILE" 2>/dev/null)
                        if [ -n "$RESOURCE_PID" ]; then
                            echo "Resource monitor PID: $RESOURCE_PID" >> "$MONITOR_START_FILE"
                        else
                            echo "Resource monitor PID: unavailable" >> "$MONITOR_START_FILE"
                        fi
                    else
                        echo "Resource monitor PID file missing: $RESOURCE_PID_FILE" >> "$MONITOR_START_FILE"
                    fi

                    if [ -f "$LOGSIZE_PID_FILE" ]; then
                        LOGSIZE_PID=$(cat "$LOGSIZE_PID_FILE" 2>/dev/null)
                        if [ -n "$LOGSIZE_PID" ]; then
                            echo "Logsize monitor PID: $LOGSIZE_PID" >> "$MONITOR_START_FILE"
                        else
                            echo "Logsize monitor PID: unavailable" >> "$MONITOR_START_FILE"
                        fi
                    else
                        echo "Logsize monitor PID file missing: $LOGSIZE_PID_FILE" >> "$MONITOR_START_FILE"
                    fi
                """
                self.ssh_manager.execute_command(ebpf_host_ref, monitor_pid_annotate_cmd)
                results['tasks'].append({
                    'name': 'start_tool_monitoring',
                    'status': True
                })

                # Store case context with consistent timestamp for cleanup
                if not hasattr(self, 'case_context'):
                    self.case_context = {}
                self.case_context[f"{tool_id}_{case_id}"] = {
                    'case_timestamp': timestamp,
                    'result_path': result_path,
                    'ebpf_result_path': ebpf_result_path,  # Store eBPF result path
                    'ebpf_host_ref': ebpf_host_ref,        # Store eBPF host ref
                    'ebpf_pid': ebpf_pid,
                    'tool_id': tool_id,
                    'case_id': case_id
                }
                logger.info(f"DEBUG: Stored case context for {tool_id}_{case_id}: timestamp={timestamp}, result_path={result_path}, ebpf_result_path={ebpf_result_path}, ebpf_host_ref={ebpf_host_ref}, ebpf_pid={ebpf_pid}")
            else:
                logger.warning(f"DEBUG: SSH command failed or did not return a PID - status={status}, stdout={repr(stdout)}, stderr={repr(stderr)}. Skipping monitoring setup.")

        logger.info(f"DEBUG: Returning from _execute_case_init with results={results}")
        return results

    def _execute_test_init(self, context: Dict) -> Dict:
        """Execute test-level initialization"""
        results = {"stage": "test", "action": "init", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        test_type = context.get('test_type')
        test_config = context.get('test_config')
        server_ip = context.get('server_ip')
        server_host_ref = context.get('server_host_ref')
        result_path = context.get('result_path')

        if not all([test_type, server_ip, server_host_ref]):
            results['error'] = "Missing required context"
            return results

        # Start performance servers based on test type
        if test_type in ["throughput", "pps"]:
            # Get test config to determine if multi-stream
            test_config = context.get('test_config', 'single_stream')

            # Get streams from context (already read from global_config by test_executor)
            # Default to 1 for single_stream, 2 for multi_stream if not specified
            if 'multi_stream' in test_config:
                streams = context.get('streams', 2)  # Use value from global_config
            else:
                streams = 1

            # Kill any existing iperf3 servers
            self.ssh_manager.execute_command(server_host_ref, "pkill -f 'iperf3.*-s' || true")

            # Ensure log directory exists (result_path now already points to server_results)
            self.ssh_manager.execute_command(server_host_ref, f"mkdir -p {result_path}")

            # Read server command from config with fallback
            # Try: test_type.test_config.server_cmd first, then test_type.server_cmd
            test_type_config = self.config.get('perf', {}).get('performance_tests', {}).get(test_type, {})
            server_cmd_template = test_type_config.get(test_config, {}).get('server_cmd')
            if not server_cmd_template:
                server_cmd_template = test_type_config.get('server_cmd', 'iperf3 -s -p {port} -B {server_ip}')
            logger.info(f"DEBUG: Using server_cmd_template for {test_type}/{test_config}: {server_cmd_template}")

            # Start multiple servers for multi-stream tests
            base_port = 5001
            started_ports = []

            for i in range(streams):
                port = base_port + i
                # Format server command from config template
                server_cmd_base = server_cmd_template.format(port=port, server_ip=server_ip)
                # Add nohup and output redirection
                server_cmd = f"nohup {server_cmd_base} > {result_path}/iperf3_server_{test_type}_port_{port}_{timestamp}.log 2>&1 &"
                self.ssh_manager.execute_command(server_host_ref, server_cmd)
                started_ports.append(port)

            # Wait and verify server startup
            self.ssh_manager.execute_command(server_host_ref, "sleep 3")

            # Check all ports
            all_listening = True
            for port in started_ports:
                stdout, stderr, exit_code = self.ssh_manager.execute_command(server_host_ref, f"ss -tln | grep ':{port} ' || echo 'NOT_LISTENING'")
                if 'NOT_LISTENING' in stdout:
                    all_listening = False
                    break

            results['tasks'].append({
                'name': 'start_iperf3_server',
                'status': all_listening,
                'details': f"Ports {started_ports} listening: {all_listening}",
                'ports': started_ports
            })

        elif test_type == "latency":
            # Get port from config, default to 12865
            port = self.config.get('perf', {}).get('performance_tests', {}).get('latency', {}).get('ports', [12865])[0]

            # Kill any existing netserver processes on the port
            self.ssh_manager.execute_command(server_host_ref, f"pkill -f 'netserver.*-p {port}' || true")

            # Ensure log directory exists (result_path now already points to server_results)
            self.ssh_manager.execute_command(server_host_ref, f"mkdir -p {result_path}")

            # Read server command from config
            server_cmd_template = self.config.get('perf', {}).get('performance_tests', {}).get('latency', {}).get('server_cmd', 'netserver -L {server_ip} -p {port} -D')
            logger.info(f"DEBUG: Using server_cmd_template for latency: {server_cmd_template}")
            # Format server command from config template
            server_cmd_base = server_cmd_template.format(port=port, server_ip=server_ip)
            # Add nohup and output redirection
            server_cmd = f"nohup {server_cmd_base} > {result_path}/netserver_{test_type}_{timestamp}.log 2>&1 &"
            self.ssh_manager.execute_command(server_host_ref, server_cmd)

            # Wait and verify server startup
            self.ssh_manager.execute_command(server_host_ref, "sleep 3")
            stdout, stderr, exit_code = self.ssh_manager.execute_command(server_host_ref, f"ss -tln | grep ':{port} ' || echo 'NOT_LISTENING'")

            server_status = 'NOT_LISTENING' not in stdout
            results['tasks'].append({
                'name': 'start_netserver',
                'status': server_status,
                'details': f"Port {port} listening: {server_status}"
            })

        return results

    def get_case_context(self, tool_id, case_id):
        """Get stored case context for cleanup"""
        if hasattr(self, 'case_context'):
            key = f"{tool_id}_{case_id}"
            context = self.case_context.get(key, {})
            logger.info(f"DEBUG: Retrieved case context for {key}: {context}")
            return context
        return {}

    def _start_tool_monitoring(self, host_ref: str, ebpf_pid: str,
                              result_path: str, timestamp: str):
        """Start tool-level monitoring with headers and configurable interval (covers entire tool lifecycle)"""
        # Get monitoring interval from config (default 2 seconds)
        interval = self.config.get('perf', {}).get('performance_tests', {}).get('monitoring', {}).get('interval', 2)

        # Combined CPU and Memory monitoring using pidstat
        # NEW APPROACH: Use a script file to avoid bash -lc and complex quoting issues
        # This eliminates the problems with nested quotes and command substitutions

        monitor_script_path = f"{result_path}/ebpf_monitoring/resource_monitor_{timestamp}.sh"
        monitor_log_file = f"{result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log"

        # Generate monitoring script content (without START_DATETIME - will be written after script starts)
        monitor_script_content = f"""#!/bin/bash
# eBPF Resource Monitor Script
# Auto-generated at {timestamp}

RESULT_PATH="{result_path}/ebpf_monitoring"
TIMESTAMP="{timestamp}"
EBPF_PID="{ebpf_pid}"
INTERVAL="{interval}"

# Save our PID
echo $$ > "$RESULT_PATH/resource_monitor_pid_$TIMESTAMP.txt"

# Write log headers
echo '# eBPF Resource Monitoring - CPU and Memory statistics using pidstat' > "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log"
echo "# DEBUG: Starting resource monitoring for PID $EBPF_PID with interval ${{INTERVAL}}s" >> "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log"

# Get and log our PGID
MY_PGID=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
echo "# DEBUG: Resource monitor process PID: $$, PGID: $MY_PGID" >> "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log"

# Check pidstat availability
if ! command -v pidstat >/dev/null 2>&1; then
    echo '# ERROR: pidstat binary not found in PATH' >> "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log"
    exit 1
fi

# Signal ready for Executor to write timestamp
echo "READY" > "$RESULT_PATH/resource_monitor_ready_$TIMESTAMP.txt"

# Wait for Executor to write START_DATETIME (max 5 seconds)
WAIT_COUNT=0
while [ ! -f "$RESULT_PATH/resource_monitor_timestamp_$TIMESTAMP.txt" ] && [ $WAIT_COUNT -lt 50 ]; do
    sleep 0.1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

# Read timestamp from file (written by Executor)
if [ -f "$RESULT_PATH/resource_monitor_timestamp_$TIMESTAMP.txt" ]; then
    source "$RESULT_PATH/resource_monitor_timestamp_$TIMESTAMP.txt"
else
    # Fallback to local time if Executor timestamp not available
    START_DATETIME=$(date '+%Y-%m-%d %H:%M:%S.%N')
    START_EPOCH=$(date +%s)
fi

echo "# START_DATETIME: $START_DATETIME  START_EPOCH: $START_EPOCH  INTERVAL: ${{INTERVAL}}s  PID: $EBPF_PID" >> "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log"

# Run pidstat monitoring
pidstat -h -u -r -p "$EBPF_PID" "$INTERVAL" >> "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log" 2>&1
PIDSTAT_STATUS=$?

# Log exit status
echo "# DEBUG: pidstat exit code: $PIDSTAT_STATUS" >> "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log"
echo "# DEBUG: resource monitoring ended for PID $EBPF_PID" >> "$RESULT_PATH/ebpf_resource_monitor_$TIMESTAMP.log"

exit 0
"""

        # Write script to remote file using heredoc
        write_script_cmd = f"""cat > {monitor_script_path} << 'MONITOR_SCRIPT_EOF'
{monitor_script_content}
MONITOR_SCRIPT_EOF
chmod +x {monitor_script_path}"""

        logger.info(f"DEBUG: Writing resource monitor script to {monitor_script_path}")
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, write_script_cmd)
        if status != 0:
            logger.error(f"Failed to create resource monitor script: {stderr}")
            return

        # Execute script in background with setsid for process group management
        execute_script_cmd = f"""
            setsid bash {monitor_script_path} >> {result_path}/ebpf_monitoring/ebpf_resource_monitor_{timestamp}.log 2>&1 &
        """

        logger.info(f"DEBUG: Executing resource monitor script: {monitor_script_path}")
        self.ssh_manager.execute_command(host_ref, execute_script_cmd)

        # Wait for script to signal ready, then write Executor timestamp
        ready_file = f"{result_path}/ebpf_monitoring/resource_monitor_ready_{timestamp}.txt"
        timestamp_file = f"{result_path}/ebpf_monitoring/resource_monitor_timestamp_{timestamp}.txt"

        wait_ready_cmd = f"""
            WAIT_COUNT=0
            while [ ! -f "{ready_file}" ] && [ $WAIT_COUNT -lt 30 ]; do
                sleep 0.1
                WAIT_COUNT=$((WAIT_COUNT + 1))
            done
            [ -f "{ready_file}" ] && echo "READY" || echo "TIMEOUT"
        """
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, wait_ready_cmd)

        if stdout.strip() == "READY":
            # Generate Executor timestamp NOW - after script is ready and waiting
            executor_start_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            executor_start_epoch = int(datetime.now().timestamp())

            # Write timestamp to file for script to read
            write_timestamp_cmd = f'echo "START_DATETIME=\\"{executor_start_datetime}\\"" > {timestamp_file} && echo "START_EPOCH=\\"{executor_start_epoch}\\"" >> {timestamp_file}'
            self.ssh_manager.execute_command(host_ref, write_timestamp_cmd)
            logger.info(f"DEBUG: Wrote Executor timestamp to {timestamp_file}: {executor_start_datetime}")
        else:
            logger.warning(f"DEBUG: Script ready signal timeout, script will use local timestamp")

        # Verify PID file creation
        verify_cmd = f"""
            if [ -f {result_path}/ebpf_monitoring/resource_monitor_pid_{timestamp}.txt ]; then
                cat {result_path}/ebpf_monitoring/resource_monitor_pid_{timestamp}.txt
            else
                echo "ERROR: PID file not created"
            fi
        """
        stdout, stderr, status = self.ssh_manager.execute_command(host_ref, verify_cmd)
        if status == 0 and stdout.strip() and "ERROR" not in stdout:
            logger.info(f"DEBUG: Resource monitor started with PID: {stdout.strip()}")
        else:
            logger.warning(f"DEBUG: Could not verify resource monitor PID: {stdout.strip()}")

        # Log size monitoring with header and human-readable conversion
        # IMPORTANT: Use setsid to create new process group for reliable cleanup
        # Strategy: Monitor process runs in its own process group
        log_file = f"{result_path}/ebpf_output_{timestamp}.log"
        logsize_cmd = f"""
            # Start monitoring in background with new process group
            setsid bash -c '
                # Save process group ID
                echo $$ > {result_path}/ebpf_monitoring/logsize_monitor_pid_{timestamp}.txt
                echo "# eBPF Log Size Monitoring - Log file size (instantaneous)" > {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                echo "# Timestamp                     Size_Bytes  Size_Human" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                echo "# DEBUG: Starting logsize monitoring for {log_file}" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                echo "# DEBUG: Monitor process PID: $$, PGID: $(ps -o pgid= -p $$ | tr -d \" \")" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log

                # Monitoring loop
                while ps -p {ebpf_pid} >/dev/null 2>&1; do
                    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S.%N")
                    SIZE=$(stat -c %s "{log_file}" 2>/dev/null || echo 0)
                    if [ $SIZE -lt 1024 ]; then
                        HUMAN="${{SIZE}}B"
                    elif [ $SIZE -lt 1048576 ]; then
                        HUMAN="$((SIZE/1024))K"
                    elif [ $SIZE -lt 1073741824 ]; then
                        HUMAN="$((SIZE/1048576))M"
                    else
                        HUMAN="$((SIZE/1073741824))G"
                    fi
                    echo "$TIMESTAMP $SIZE $HUMAN" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
                    sleep {interval}
                done

                echo "# DEBUG: logsize monitoring ended for {log_file}" >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log
            ' >> {result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log 2>&1 &

            # Wait a moment for PID file to be created
            sleep 0.2
        """
        logger.info(f"DEBUG: logsize_cmd = {logsize_cmd}")
        self.ssh_manager.execute_command(host_ref, logsize_cmd)
