#!/usr/bin/env python3
"""Post-processing hooks - remote execution"""

import logging
from typing import Dict, List, Optional
from datetime import datetime


logger = logging.getLogger(__name__)


class PostHooks:
    """Layered post-processing hooks for remote execution"""

    def __init__(self, ssh_manager, path_manager, init_hooks=None):
        """Initialize hooks

        Args:
            ssh_manager: SSH connection manager
            path_manager: Remote path manager
            init_hooks: Reference to init_hooks for getting case context
        """
        self.ssh_manager = ssh_manager
        self.path_manager = path_manager
        self.init_hooks = init_hooks

    def execute_hook(self, stage: str, action: str, context: Dict) -> Dict:
        """Execute hook based on stage and action

        Args:
            stage: Hook stage (global/tool/case/test)
            action: Hook action (init/post)
            context: Execution context

        Returns:
            Execution results
        """
        if action != "post":
            return {"error": "Invalid action for post hooks"}

        if stage == "global":
            return self._execute_global_post(context)
        elif stage == "tool":
            return self._execute_tool_post(context)
        elif stage == "case":
            return self._execute_case_post(context)
        elif stage == "test":
            return self._execute_test_post(context)
        else:
            return {"error": f"Unknown stage: {stage}"}

    def _execute_test_post(self, context: Dict) -> Dict:
        """Execute test-level cleanup"""
        results = {"stage": "test", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        test_type = context.get('test_type')
        server_ip = context.get('server_ip')
        server_host_ref = context.get('server_host_ref')
        result_path = context.get('result_path')

        # Stop performance servers
        if test_type in ["throughput", "pps"]:
            stop_cmd = f'pkill -f "iperf3.*-s.*{server_ip}" || true'
            self.ssh_manager.execute_command(server_host_ref, stop_cmd)
            results['tasks'].append({
                'name': 'stop_iperf3_server',
                'status': True
            })

        elif test_type == "latency":
            stop_cmd = f'pkill -f "netserver.*{server_ip}" || true'
            self.ssh_manager.execute_command(server_host_ref, stop_cmd)
            results['tasks'].append({
                'name': 'stop_netserver',
                'status': True
            })

        elif test_type == "icmp_ping":
            client_host_ref = context.get('client_host_ref')
            client_ip = context.get('client_ip')
            self.ssh_manager.execute_command(server_host_ref, f'pkill -f "ping.*{client_ip}" || true')
            if client_host_ref:
                self.ssh_manager.execute_command(client_host_ref, f'pkill -f "ping.*{server_ip}" || true')
            results['tasks'].append({
                'name': 'stop_icmp_ping',
                'status': True
            })

        # Collect test results
        collect_cmd = f"""
            echo "Test {test_type} completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/test_complete_{test_type}_{timestamp}.log
            sync
        """
        self.ssh_manager.execute_command(server_host_ref, collect_cmd)
        results['tasks'].append({
            'name': 'collect_test_results',
            'status': True
        })

        return results

    def _execute_case_post(self, context: Dict) -> Dict:
        """Execute case-level cleanup"""
        results = {"stage": "case", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        case_id = context.get('case_id')
        environment = context.get('environment')

        # Performance test host (VM or physical host)
        host_ref = context.get('host_ref')
        result_path = context.get('result_path')

        # eBPF monitoring host (physical host, may be different from host_ref)
        ebpf_host_ref = context.get('ebpf_host_ref', host_ref)
        ebpf_result_path = context.get('ebpf_result_path', result_path)
        ebpf_command = context.get('ebpf_command')

        # Get case context with consistent timestamp from init_hooks
        case_context = {}
        if self.init_hooks and hasattr(self.init_hooks, 'get_case_context'):
            case_context = self.init_hooks.get_case_context(tool_id, case_id)
            if case_context:
                # Use the timestamp from case init, not current timestamp
                case_timestamp = case_context.get('case_timestamp', timestamp)
                logger.info(f"DEBUG: Using case timestamp {case_timestamp} instead of current {timestamp}")
                timestamp = case_timestamp

                # Override eBPF paths from case_context if available
                if 'ebpf_result_path' in case_context:
                    ebpf_result_path = case_context['ebpf_result_path']
                    logger.info(f"DEBUG: Using ebpf_result_path from case_context: {ebpf_result_path}")
                if 'ebpf_host_ref' in case_context:
                    ebpf_host_ref = case_context['ebpf_host_ref']
                    logger.info(f"DEBUG: Using ebpf_host_ref from case_context: {ebpf_host_ref}")

        # Stop case monitoring if eBPF program was running (on eBPF monitoring host - physical host)
        if ebpf_command:
            # Record monitoring stop time
            monitor_stop_timestamp = f"""
                echo "Monitor stop time: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
            """
            self.ssh_manager.execute_command(ebpf_host_ref, monitor_stop_timestamp)

            # Stop monitoring processes using saved PID files
            monitoring_cmd = f"""
                # Function to kill process and its entire process group by PID file
                kill_by_pidfile() {{
                    local PIDFILE=$1
                    local NAME=$2
                    if [ -f "$PIDFILE" ]; then
                        PID=$(cat "$PIDFILE")
                        if [ -z "$PID" ]; then
                            echo "$NAME PID file $PIDFILE did not contain a PID" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                        elif ps -p $PID >/dev/null 2>&1; then
                            # Get process group ID
                            PGID=$(ps -o pgid= -p $PID 2>/dev/null | tr -d ' ')
                            echo "Stopping $NAME process PID $PID (PGID: $PGID)" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log

                            # Kill the entire process group (negative PID = process group)
                            # This ensures all child processes (like pidstat) are also killed
                            if [ -n "$PGID" ]; then
                                echo "Sending SIGTERM to process group -$PGID" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                                kill -TERM -$PGID 2>/dev/null || true
                                sleep 1

                                # Check if any process in the group is still alive
                                if ps -g $PGID >/dev/null 2>&1; then
                                    echo "Force killing process group -$PGID" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                                    kill -KILL -$PGID 2>/dev/null || true
                                fi
                            else
                                # Fallback: kill just the process
                                echo "WARNING: Could not get PGID, killing process $PID only" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                                kill -TERM $PID 2>/dev/null || true
                                sleep 1
                                if ps -p $PID >/dev/null 2>&1; then
                                    kill -KILL $PID 2>/dev/null || true
                                fi
                            fi

                            echo "$NAME process stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                        else
                            echo "$NAME process PID $PID already exited before cleanup" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                        fi
                        rm -f "$PIDFILE"
                    else
                        echo "$NAME PID file not found: $PIDFILE" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                    fi
                }}

                echo "DEBUG: Stopping monitoring processes for case {case_id} with timestamp {timestamp}" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log

                # Stop resource monitor using PID file
                kill_by_pidfile "{ebpf_result_path}/ebpf_monitoring/resource_monitor_pid_{timestamp}.txt" "Resource Monitor"

                # Stop logsize monitor using PID file
                kill_by_pidfile "{ebpf_result_path}/ebpf_monitoring/logsize_monitor_pid_{timestamp}.txt" "Logsize Monitor"

                # Fallback: try to find and kill by any timestamp if exact timestamp fails
                if [ ! -f "{ebpf_result_path}/ebpf_monitoring/resource_monitor_pid_{timestamp}.txt" ]; then
                    for pidfile in {ebpf_result_path}/ebpf_monitoring/resource_monitor_pid_*.txt; do
                        if [ -f "$pidfile" ]; then
                            kill_by_pidfile "$pidfile" "Resource Monitor (fallback)"
                        fi
                    done
                    for pidfile in {ebpf_result_path}/ebpf_monitoring/logsize_monitor_pid_*.txt; do
                        if [ -f "$pidfile" ]; then
                            kill_by_pidfile "$pidfile" "Logsize Monitor (fallback)"
                        fi
                    done
                fi

                echo "Case monitoring stopped at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
                echo "DEBUG: Monitoring stop commands completed" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log

                # Clean up monitoring script files
                rm -f {ebpf_result_path}/ebpf_monitoring/resource_monitor_{timestamp}.sh
                echo "DEBUG: Cleaned up monitoring script files" >> {ebpf_result_path}/ebpf_monitoring/monitor_stop_{timestamp}.log
            """
            logger.info(f"DEBUG: monitoring_cmd = {monitoring_cmd}")
            self.ssh_manager.execute_command(ebpf_host_ref, monitoring_cmd)
            results['tasks'].append({
                'name': 'stop_case_monitoring',
                'status': True
            })

            # Enhanced eBPF program cleanup using process group kill (on eBPF monitoring host)
            stop_ebpf_cmd = f"""
                # Function to kill process group
                kill_process_group() {{
                    local PGID_FILE=$1
                    local NAME=$2

                    if [ -f "$PGID_FILE" ]; then
                        PGID=$(cat "$PGID_FILE")
                        if [ -n "$PGID" ]; then
                            echo "Stopping $NAME process group $PGID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log

                            # Helper: check if any process in group alive
                            group_alive() {{
                                if command -v pgrep >/dev/null 2>&1; then
                                    pgrep -g "$1" >/dev/null 2>&1
                                else
                                    ps -o pid= --pgrp "$1" >/dev/null 2>&1
                                fi
                            }}

                            # Check if any process in the group exists
                            if group_alive "$PGID"; then
                                # List all processes in the group before killing
                                echo "Processes in group $PGID:" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                (ps -o pid,pgid,stat,cmd --pgrp "$PGID" 2>/dev/null || true) >> {ebpf_result_path}/ebpf_stop_{timestamp}.log

                                # Kill the entire process group (use sudo for root-run processes)
                                echo "Sending SIGTERM to process group -$PGID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                sudo -n kill -TERM -- -$PGID 2>/dev/null || true
                                sleep 2

                                # Check if any process in the group is still alive
                                if group_alive "$PGID"; then
                                    echo "Processes still alive after SIGTERM, sending SIGKILL to process group -$PGID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                    (ps -o pid,pgid,stat,cmd --pgrp "$PGID" 2>/dev/null || true) >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                    sudo -n kill -KILL -- -$PGID 2>/dev/null || true

                                    # Poll for process termination (max 10 seconds)
                                    MAX_WAIT=20
                                    WAIT_COUNT=0
                                    while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
                                        if ! group_alive "$PGID"; then
                                            echo "Process group $PGID terminated after $((WAIT_COUNT / 2)) seconds" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                            break
                                        fi
                                        sleep 0.5
                                        WAIT_COUNT=$((WAIT_COUNT + 1))
                                    done
                                fi

                                # Final verification - CRITICAL for preventing concurrent eBPF programs
                                if group_alive "$PGID"; then
                                    echo "ERROR: Failed to kill process group $PGID after 10 seconds!" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                    echo "ERROR: Still running processes:" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                    (ps -o pid,pgid,stat,time,cmd --pgrp "$PGID" 2>/dev/null || true) >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                    echo "ERROR: Cannot proceed to next test case - processes still running" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                    # Return non-zero exit code to signal failure
                                    exit 1
                                else
                                    echo "Process group $PGID terminated successfully" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                fi
                            else
                                echo "$NAME process group $PGID already stopped" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                            fi

                            rm -f "$PGID_FILE"
                        else
                            echo "WARNING: Empty PGID in file $PGID_FILE" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                        fi
                    else
                        echo "WARNING: PGID file not found: $PGID_FILE" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                    fi
                }}

                echo "eBPF case stop time: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {ebpf_result_path}/ebpf_stop_{timestamp}.log

                # DEBUG: List available PID/PGID files
                echo "DEBUG: Available PID/PGID files in {ebpf_result_path}:" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                ls -la {ebpf_result_path}/*pid*.txt >> {ebpf_result_path}/ebpf_stop_{timestamp}.log 2>&1 || echo "No PID files found" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log

                # Stop eBPF process group using PGID file
                PGID_FILE="{ebpf_result_path}/ebpf_pgid_{timestamp}.txt"
                if [ -f "$PGID_FILE" ]; then
                    echo "DEBUG: Found PGID file, using process group kill" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                    kill_process_group "$PGID_FILE" "eBPF tool"
                else
                    echo "DEBUG: PGID file not found, falling back to individual PID kill" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log

                    # Fallback: try to kill by individual PIDs (old method, for compatibility)
                    EBPF_PID_FILE="{ebpf_result_path}/ebpf_pid_{timestamp}.txt"
                    if [ -f "$EBPF_PID_FILE" ]; then
                        EBPF_PID=$(cat "$EBPF_PID_FILE")
                        echo "DEBUG: Found eBPF PID file with PID: $EBPF_PID" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log

                        if [ -n "$EBPF_PID" ] && ps -p $EBPF_PID >/dev/null 2>&1; then
                            # Get PGID from the process
                            PGID=$(ps -o pgid= -p $EBPF_PID 2>/dev/null | tr -d ' ')
                            if [ -n "$PGID" ]; then
                                echo "Detected PGID $PGID from process $EBPF_PID, killing process group" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                sudo -n kill -TERM -- -$PGID 2>/dev/null || true
                                sleep 2
                                if command -v pgrep >/dev/null 2>&1; then
                                    if pgrep -g "$PGID" >/dev/null 2>&1; then sudo -n kill -KILL -- -$PGID 2>/dev/null || true; fi
                                else
                                    if ps -o pid= --pgrp "$PGID" >/dev/null 2>&1; then sudo -n kill -KILL -- -$PGID 2>/dev/null || true; fi
                                fi
                            else
                                # Last resort: kill just the process
                                echo "Could not get PGID, killing process $EBPF_PID only" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                                sudo -n kill -TERM $EBPF_PID 2>/dev/null || true
                                sleep 1
                                if ps -p $EBPF_PID >/dev/null 2>&1; then
                                    sudo -n kill -KILL $EBPF_PID 2>/dev/null || true
                                fi
                            fi
                        fi
                        rm -f "$EBPF_PID_FILE"
                    fi

                    # Also try wrapper PID file
                    WRAPPER_PID_FILE="{ebpf_result_path}/wrapper_pid_{timestamp}.txt"
                    if [ -f "$WRAPPER_PID_FILE" ]; then
                        WRAPPER_PID=$(cat "$WRAPPER_PID_FILE")
                        if [ -n "$WRAPPER_PID" ] && ps -p $WRAPPER_PID >/dev/null 2>&1; then
                            echo "Killing wrapper process $WRAPPER_PID (with sudo)" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
                            sudo -n kill -TERM $WRAPPER_PID 2>/dev/null || true
                            sleep 1
                            if ps -p $WRAPPER_PID >/dev/null 2>&1; then
                                sudo -n kill -KILL $WRAPPER_PID 2>/dev/null || true
                            fi
                        fi
                        rm -f "$WRAPPER_PID_FILE"
                    fi
                fi

                echo "eBPF case cleanup completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_stop_{timestamp}.log
            """
            stdout, stderr, status = self.ssh_manager.execute_command(ebpf_host_ref, stop_ebpf_cmd)

            # CRITICAL: Check if cleanup succeeded
            if status != 0:
                error_msg = f"CRITICAL: Failed to stop eBPF program for {tool_id}_case_{case_id}. Exit code: {status}"
                logger.error(error_msg)
                logger.error(f"stderr: {stderr}")
                results['tasks'].append({
                    'name': 'stop_ebpf_program',
                    'status': False,
                    'error': error_msg
                })
                # Raise exception to stop test execution
                raise RuntimeError(f"{error_msg}. Previous eBPF program still running - cannot start next test case!")
            else:
                logger.info(f"eBPF program stopped successfully for {tool_id}_case_{case_id}")
                results['tasks'].append({
                    'name': 'stop_ebpf_program',
                    'status': True
                })

        # Generate time range statistics (on eBPF monitoring host)
        if ebpf_command:
            self._generate_time_statistics(ebpf_host_ref, ebpf_result_path, timestamp)
            results['tasks'].append({
                'name': 'generate_time_statistics',
                'status': True
            })

        # Collect eBPF case data (on eBPF monitoring host)
        if ebpf_command:
            ebpf_collect_cmd = f"""
                echo "eBPF case {case_id} data collection completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {ebpf_result_path}/ebpf_case_complete_{timestamp}.log
                du -sh {ebpf_result_path}/* > {ebpf_result_path}/ebpf_case_data_size_{timestamp}.log 2>/dev/null || true
                sync
            """
            self.ssh_manager.execute_command(ebpf_host_ref, ebpf_collect_cmd)
            results['tasks'].append({
                'name': 'collect_ebpf_case_data',
                'status': True
            })

            # Delete or keep eBPF output file based on keep_tool_logs setting
            keep_tool_logs = context.get('keep_tool_logs', False)
            if not keep_tool_logs:
                delete_output_cmd = f"""
                    OUTPUT_FILE="{ebpf_result_path}/ebpf_output_{timestamp}.log"
                    if [ -f "$OUTPUT_FILE" ]; then
                        OUTPUT_SIZE=$(stat -c %s "$OUTPUT_FILE" 2>/dev/null || echo 0)
                        echo "Deleting eBPF output file: $OUTPUT_FILE (size: $OUTPUT_SIZE bytes)" >> {ebpf_result_path}/ebpf_case_complete_{timestamp}.log
                        rm -f "$OUTPUT_FILE"
                        echo "eBPF output file deleted at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> {ebpf_result_path}/ebpf_case_complete_{timestamp}.log
                    else
                        echo "eBPF output file not found: $OUTPUT_FILE" >> {ebpf_result_path}/ebpf_case_complete_{timestamp}.log
                    fi
                """
                self.ssh_manager.execute_command(ebpf_host_ref, delete_output_cmd)
                results['tasks'].append({
                    'name': 'delete_ebpf_output_file',
                    'status': True
                })
            else:
                keep_output_cmd = f"""
                    OUTPUT_FILE="{ebpf_result_path}/ebpf_output_{timestamp}.log"
                    if [ -f "$OUTPUT_FILE" ]; then
                        OUTPUT_SIZE=$(stat -c %s "$OUTPUT_FILE" 2>/dev/null || echo 0)
                        echo "Keeping eBPF output file: $OUTPUT_FILE (size: $OUTPUT_SIZE bytes)" >> {ebpf_result_path}/ebpf_case_complete_{timestamp}.log
                    fi
                """
                self.ssh_manager.execute_command(ebpf_host_ref, keep_output_cmd)
                results['tasks'].append({
                    'name': 'keep_ebpf_output_file',
                    'status': True
                })

        # Collect performance test data (on performance test host)
        perf_collect_cmd = f"""
            echo "Performance test {case_id} data collection completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_path}/perf_case_complete_{timestamp}.log
            du -sh {result_path}/* > {result_path}/perf_case_data_size_{timestamp}.log 2>/dev/null || true
            sync
        """
        self.ssh_manager.execute_command(host_ref, perf_collect_cmd)
        results['tasks'].append({
            'name': 'collect_performance_case_data',
            'status': True
        })

        return results

    def _execute_tool_post(self, context: Dict) -> Dict:
        """Execute tool-level cleanup"""
        results = {"stage": "tool", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()

        tool_id = context.get('tool_id')
        environment = context.get('environment')
        host_ref = context.get('host_ref')
        workdir = context.get('workdir', '/home/smartx/lcc')

        result_base = f"{workdir}/performance-test-results"

        # Collect tool summary
        summary_cmd = f"""
            echo "Tool {tool_id} testing completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/ebpf/{tool_id}/tool_complete_{timestamp}.log
            find {result_base}/ebpf/{tool_id}* -name "*.log" 2>/dev/null | wc -l > {result_base}/ebpf/{tool_id}/total_files_{timestamp}.txt || true
        """
        self.ssh_manager.execute_command(host_ref, summary_cmd)
        results['tasks'].append({
            'name': 'collect_tool_summary',
            'status': True
        })

        # Tool specific cleanup
        cleanup_cmd = f"""
            echo "Tool {tool_id} cleanup completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/ebpf/{tool_id}/tool_cleanup_{timestamp}.log
        """
        self.ssh_manager.execute_command(host_ref, cleanup_cmd)
        results['tasks'].append({
            'name': 'tool_specific_cleanup',
            'status': True
        })

        return results

    def _generate_time_statistics(self, host_ref: str, result_path: str, timestamp: str):
        """Generate time range statistics for eBPF monitoring and performance tests"""
        stats_cmd = f"""
            # Generate time range statistics
            STATS_FILE="{result_path}/ebpf_monitoring/time_range_statistics_{timestamp}.log"

            echo "# eBPF Tool Time Range Statistics" > $STATS_FILE
            echo "# Generated at: $(date '+%Y-%m-%d %H:%M:%S.%N')" >> $STATS_FILE
            echo "" >> $STATS_FILE

            # eBPF Monitoring Time Range
            echo "## eBPF Monitoring Time Range" >> $STATS_FILE
            if [ -f "{result_path}/ebpf_monitoring/ebpf_cpu_monitor_{timestamp}.log" ]; then
                FIRST_CPU=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_cpu_monitor_{timestamp}.log" | head -1 | awk '{{print $1" "$2}}')
                LAST_CPU=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_cpu_monitor_{timestamp}.log" | tail -1 | awk '{{print $1" "$2}}')
                echo "CPU Monitoring Start: $FIRST_CPU" >> $STATS_FILE
                echo "CPU Monitoring End: $LAST_CPU" >> $STATS_FILE
            fi

            if [ -f "{result_path}/ebpf_monitoring/ebpf_memory_monitor_{timestamp}.log" ]; then
                FIRST_MEM=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_memory_monitor_{timestamp}.log" | head -1 | awk '{{print $1" "$2}}')
                LAST_MEM=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_memory_monitor_{timestamp}.log" | tail -1 | awk '{{print $1" "$2}}')
                echo "Memory Monitoring Start: $FIRST_MEM" >> $STATS_FILE
                echo "Memory Monitoring End: $LAST_MEM" >> $STATS_FILE
            fi

            if [ -f "{result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log" ]; then
                FIRST_LOG=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log" | head -1 | awk '{{print $1" "$2}}')
                LAST_LOG=$(grep -v '^#' "{result_path}/ebpf_monitoring/ebpf_logsize_monitor_{timestamp}.log" | tail -1 | awk '{{print $1" "$2}}')
                echo "LogSize Monitoring Start: $FIRST_LOG" >> $STATS_FILE
                echo "LogSize Monitoring End: $LAST_LOG" >> $STATS_FILE
            fi

            echo "" >> $STATS_FILE
            echo "## Performance Test Time Ranges (from client timing files)" >> $STATS_FILE

            # Find and process all timing files
            find {result_path}/../../ -name '*_timing.log' -type f 2>/dev/null | while read timing_file; do
                if [ -f "$timing_file" ]; then
                    echo "" >> $STATS_FILE
                    echo "### Test: $(basename "$timing_file" _timing.log)" >> $STATS_FILE
                    cat "$timing_file" >> $STATS_FILE
                fi
            done
        """
        self.ssh_manager.execute_command(host_ref, stats_cmd)

    def _execute_global_post(self, context: Dict) -> Dict:
        """Execute global cleanup"""
        results = {"stage": "global", "action": "post", "tasks": []}
        timestamp = self.path_manager.get_timestamp()
        targets = context.get('targets', ['server', 'client'])

        for target in targets:
            host_ref = context.get(f'{target}_host_ref')
            if not host_ref:
                continue

            workdir = context.get('workdir', '/home/smartx/lcc')
            result_base = f"{workdir}/performance-test-results"

            # Final cleanup
            final_cleanup_cmd = """
                pkill -f "iperf3.*-s" || true
                pkill -f "netserver" || true
                pkill -f "ping.*-i.*-c" || true
                pkill -f "python.*ebpf" || true
            """
            self.ssh_manager.execute_command(host_ref, final_cleanup_cmd)

            # Log cleanup completion
            log_cmd = f'echo "All test processes cleaned at: $(date \'+%Y-%m-%d %H:%M:%S.%N\')" > {result_base}/final_cleanup_{timestamp}.log'
            self.ssh_manager.execute_command(host_ref, log_cmd)

            results['tasks'].append({
                'name': 'final_cleanup',
                'target': target,
                'status': True
            })

            # Generate session summary
            summary_cmd = f"""
                echo "Test session completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')" > {result_base}/session_summary_{timestamp}.json
                echo "Total result files: $(find {result_base} -name "*.log" -o -name "*.json" 2>/dev/null | wc -l)" >> {result_base}/session_summary_{timestamp}.json
                echo "Total disk usage: $(du -sh {result_base} 2>/dev/null | cut -f1)" >> {result_base}/session_summary_{timestamp}.json
                sync
            """
            self.ssh_manager.execute_command(host_ref, summary_cmd)

            results['tasks'].append({
                'name': 'generate_session_summary',
                'target': target,
                'status': True
            })

        return results
