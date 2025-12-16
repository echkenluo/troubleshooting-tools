#!/usr/bin/env python3
"""Main execution script for automated performance testing.

Supports two configuration modes:
1. Legacy: 4 separate YAML files (ssh-config.yaml, test-env-config.yaml, etc.)
2. Unified: Bootstrap from minimal config to generate full config + test cases

Usage:
    # Bootstrap mode: generate full config from minimal input
    python run_automation.py --bootstrap --minimal-input config/my-env/minimal-input.yaml

    # Run with unified config (auto-detected)
    python run_automation.py --config-dir config/my-env

    # Run with legacy config
    python run_automation.py --config-dir config/nested-5.4
"""

import sys
import os
import logging
import argparse
import signal
import atexit
import subprocess
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from core.ssh_manager import SSHManager
from core.remote_path_manager import RemotePathManager
from core.workflow_generator import EBPFCentricWorkflowGenerator
from core.test_executor import TestExecutor
from utils.config_loader import ConfigLoader
from utils.testcase_loader import TestcaseLoader

# Global variables for cleanup
_ssh_manager = None
_test_executor = None
_cleanup_executed = False


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f'automation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
        ]
    )


def cleanup_on_exit():
    """Cleanup function called on exit or interruption"""
    global _cleanup_executed

    if _cleanup_executed:
        return

    _cleanup_executed = True
    logger = logging.getLogger(__name__)

    logger.warning("=" * 60)
    logger.warning("Performing emergency cleanup...")
    logger.warning("=" * 60)

    if _ssh_manager and _test_executor:
        try:
            logger.info("Attempting to stop all running eBPF tools and monitoring processes...")

            # Get all configured hosts
            for host_ref in _ssh_manager.clients.keys():
                logger.info(f"Cleaning up processes on {host_ref}...")

                cleanup_cmd = """
                    echo "Emergency cleanup started at: $(date '+%Y-%m-%d %H:%M:%S.%N')"

                    # Stop all eBPF tool processes
                    echo "Stopping eBPF tool processes..."
                    sudo pkill -f "python2.*ebpf-tools/performance" 2>/dev/null || true
                    sudo pkill -f "python.*ebpf-tools/performance" 2>/dev/null || true

                    # Stop monitoring processes (as smartx user)
                    echo "Stopping monitoring processes..."
                    pkill -f "pidstat.*ebpf" 2>/dev/null || true
                    pkill -f "while ps -p.*ebpf" 2>/dev/null || true

                    # Stop performance test servers
                    echo "Stopping performance test servers..."
                    sudo pkill -f "iperf3.*-s" 2>/dev/null || true
                    sudo pkill -f "netserver" 2>/dev/null || true

                    echo "Emergency cleanup completed at: $(date '+%Y-%m-%d %H:%M:%S.%N')"
                """

                try:
                    _ssh_manager.execute_command(host_ref, cleanup_cmd)
                    logger.info(f"Cleanup completed on {host_ref}")
                except Exception as e:
                    logger.error(f"Failed to cleanup {host_ref}: {e}")

            logger.warning("Emergency cleanup finished")

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    if _ssh_manager:
        try:
            _ssh_manager.close_all()
        except:
            pass


def signal_handler(signum, frame):
    """Handle interrupt signals"""
    logger = logging.getLogger(__name__)
    logger.warning(f"\nReceived signal {signum}, initiating cleanup...")
    cleanup_on_exit()
    sys.exit(130)


def run_bootstrap(minimal_input: str, output_dir: str, logger) -> tuple:
    """Run bootstrap to generate full config from minimal input.

    Args:
        minimal_input: Path to minimal input config
        output_dir: Output directory for generated files
        logger: Logger instance

    Returns:
        Tuple of (full_config_path, test_cases_path)
    """
    from config.config_bootstrap import ConfigBootstrap

    logger.info(f"Bootstrapping from minimal input: {minimal_input}")

    bootstrap = ConfigBootstrap(minimal_input)
    try:
        # Discover network environment
        logger.info("Discovering network environment...")
        bootstrap.discover_all()

        # Generate full config
        full_config = bootstrap.generate_full_config()
        env_name = full_config.get('environment', 'generated')

        # Generate test cases
        test_cases = bootstrap.generate_test_cases()

        # Save outputs
        os.makedirs(output_dir, exist_ok=True)
        full_config_path = os.path.join(output_dir, f'{env_name}-full.yaml')
        test_cases_path = os.path.join(output_dir, f'{env_name}-cases.json')

        bootstrap.save_full_config(full_config_path)
        bootstrap.save_test_cases(test_cases_path)

        logger.info(f"Generated full config: {full_config_path}")
        logger.info(f"Generated {len(test_cases)} test cases: {test_cases_path}")

        return full_config_path, test_cases_path

    finally:
        bootstrap.close()


def sync_tools_to_remote(ssh_config: dict, local_tools_path: str, remote_tools_dir: str, logger) -> bool:
    """Sync measurement tools to all remote hosts before test execution.

    Args:
        ssh_config: SSH configuration with host definitions
        local_tools_path: Local path to measurement-tools directory
        remote_tools_dir: Remote directory name (e.g., 'ebpf-tools')
        logger: Logger instance

    Returns:
        True if all syncs succeeded, False otherwise
    """
    if not os.path.exists(local_tools_path):
        logger.error(f"Local tools path does not exist: {local_tools_path}")
        return False

    all_success = True
    synced_hosts = set()

    for host_ref, host_config in ssh_config.get('ssh_hosts', {}).items():
        host = host_config.get('host')
        user = host_config.get('user')
        workdir = host_config.get('workdir', '/home/smartx/lcc')

        # Skip if already synced to this host
        host_key = f"{user}@{host}"
        if host_key in synced_hosts:
            logger.debug(f"Skipping {host_ref} - already synced to {host_key}")
            continue

        remote_path = f"{workdir}/{remote_tools_dir}"
        logger.info(f"Syncing tools to {host_ref} ({host_key}:{remote_path})...")

        try:
            # Use rsync for efficient sync
            rsync_cmd = [
                'rsync', '-az', '--delete',
                f"{local_tools_path}/",
                f"{user}@{host}:{remote_path}/"
            ]
            result = subprocess.run(rsync_cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                logger.info(f"  Synced to {host_ref} successfully")
                synced_hosts.add(host_key)
            else:
                logger.error(f"  Failed to sync to {host_ref}: {result.stderr}")
                all_success = False

        except subprocess.TimeoutExpired:
            logger.error(f"  Sync to {host_ref} timed out")
            all_success = False
        except Exception as e:
            logger.error(f"  Sync to {host_ref} failed: {e}")
            all_success = False

    logger.info(f"Tool sync completed: {len(synced_hosts)} hosts synced")
    return all_success


def main():
    """Main execution function"""
    global _ssh_manager, _test_executor

    parser = argparse.ArgumentParser(
        description='Automated eBPF Performance Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Bootstrap from minimal config (generate full config + test cases)
  python run_automation.py --bootstrap --minimal-input config/my-env/minimal-input.yaml

  # Run with auto-detected config format
  python run_automation.py --config-dir config/my-env

  # Dry run (generate workflow only)
  python run_automation.py --config-dir config/my-env --dry-run

  # Filter by tools and environments
  python run_automation.py --config-dir config/my-env --tools vm_network_latency_summary --environments vm
        """
    )

    # Config options
    parser.add_argument('--config-dir', default='../config',
                       help='Configuration directory path')
    parser.add_argument('--bootstrap', action='store_true',
                       help='Bootstrap mode: generate full config from minimal input')
    parser.add_argument('--minimal-input',
                       help='Path to minimal input config (for bootstrap mode)')
    parser.add_argument('--unified-config',
                       help='Path to unified config file (full config)')
    parser.add_argument('--test-cases',
                       help='Path to test cases JSON file')

    # Execution options
    parser.add_argument('--log-level', default='INFO',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Logging level')
    parser.add_argument('--dry-run', action='store_true',
                       help='Generate workflow without executing')
    parser.add_argument('--workflow-output', default='generated_workflow.json',
                       help='Output file for generated workflow')

    # Filter options
    parser.add_argument('--tools', nargs='+',
                       help='Specific tools to test (default: all)')
    parser.add_argument('--environments', nargs='+',
                       help='Specific environments to test (default: all)')
    parser.add_argument('--category',
                       help='Filter by tool category (e.g., performance/vm-network)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp'],
                       help='Filter by protocol')
    parser.add_argument('--direction', choices=['rx', 'tx'],
                       help='Filter by direction')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    # Register signal handlers and cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(cleanup_on_exit)

    try:
        # Get absolute config directory path
        config_dir = os.path.abspath(args.config_dir)

        # Bootstrap mode
        if args.bootstrap:
            if not args.minimal_input:
                logger.error("--minimal-input required for bootstrap mode")
                return 1

            minimal_path = os.path.abspath(args.minimal_input)
            if not os.path.exists(minimal_path):
                logger.error(f"Minimal input file not found: {minimal_path}")
                return 1

            full_config_path, test_cases_path = run_bootstrap(
                minimal_path, config_dir, logger
            )

            # Update paths for subsequent processing
            args.unified_config = full_config_path
            args.test_cases = test_cases_path

            logger.info("Bootstrap completed successfully")

            if args.dry_run:
                logger.info("Bootstrap dry-run completed - config generated but not executed")
                return 0

        logger.info(f"Loading configurations from: {config_dir}")

        # Load configurations
        config_loader = ConfigLoader(
            config_dir,
            unified_config_path=args.unified_config
        )

        configs = config_loader.load_all_configs()

        # Load test cases if using unified format
        test_cases = []
        if config_loader.is_unified_format():
            logger.info("Detected unified config format")
            _, test_cases = config_loader.load_test_cases(args.test_cases)
            logger.info(f"Loaded {len(test_cases)} test cases")
        else:
            logger.info("Using legacy config format")
            # Validate legacy configurations
            for config_type, config in configs.items():
                if not config_loader.validate_config(config_type, config):
                    logger.error(f"Invalid {config_type} configuration")
                    return 1

        logger.info("All configurations loaded successfully")

        # Filter test cases if using unified format
        if test_cases:
            original_count = len(test_cases)

            # Filter by environment
            if args.environments:
                test_cases = [c for c in test_cases if c.get('environment') in args.environments]

            # Filter by category
            if args.category:
                test_cases = [c for c in test_cases
                             if c.get('category', '').startswith(args.category)]

            # Filter by protocol
            if args.protocol:
                test_cases = [c for c in test_cases
                             if c.get('parameters', {}).get('protocol') == args.protocol]

            # Filter by direction
            if args.direction:
                test_cases = [c for c in test_cases
                             if c.get('parameters', {}).get('direction') == args.direction]

            # Filter by tool name
            if args.tools:
                def _normalize_tool_id(value: str) -> str:
                    return value.strip().lower().replace('-', '_').replace('.py', '')

                requested_tools = {_normalize_tool_id(t) for t in args.tools}
                test_cases = [c for c in test_cases
                             if _normalize_tool_id(c.get('script', '')) in requested_tools]

            if len(test_cases) != original_count:
                logger.info(f"Filtered test cases: {original_count} -> {len(test_cases)}")

        # Filter legacy format configurations
        if not config_loader.is_unified_format():
            if args.tools:
                def _normalize_tool_id(value: str) -> str:
                    return value.strip().lower().replace('-', '_')

                requested_tool_ids = {_normalize_tool_id(tool) for tool in args.tools}
                available_tools = configs['ebpf'].get('ebpf_tools', {})
                matched_tool_ids = {
                    tool_def['id']
                    for tool_def in available_tools.values()
                    if _normalize_tool_id(tool_def['id']) in requested_tool_ids
                }

                filtered_tools = {
                    key: tool_def
                    for key, tool_def in available_tools.items()
                    if tool_def['id'] in matched_tool_ids
                }

                unmatched = requested_tool_ids - {_normalize_tool_id(tid) for tid in matched_tool_ids}
                if unmatched:
                    logger.warning(f"No matching tool definitions found for: {sorted(unmatched)}")

                configs['ebpf']['ebpf_tools'] = filtered_tools
                logger.info(f"Filtered to tools: {sorted(matched_tool_ids) if matched_tool_ids else []}")

        if args.environments:
            filtered_envs = {k: v for k, v in configs['env']['test_environments'].items()
                           if k in args.environments}
            configs['env']['test_environments'] = filtered_envs
            logger.info(f"Filtered to environments: {args.environments}")

        # Initialize testcase loader
        script_dir = os.path.dirname(os.path.dirname(__file__))
        base_path = os.path.dirname(os.path.dirname(script_dir))
        logger.info(f"Auto-detected base path: {base_path}")
        testcase_loader = TestcaseLoader(base_path)

        # Generate workflow
        logger.info("Generating test workflow...")
        workflow_generator = EBPFCentricWorkflowGenerator(
            testcase_loader=testcase_loader,
            base_path=base_path
        )

        # Use auto-detect method to choose appropriate generation
        workflow_spec = workflow_generator.generate_workflow_auto(
            configs['ssh'], configs['env'], configs['perf'],
            ebpf_config=configs['ebpf'],
            test_cases=test_cases
        )

        # Validate workflow
        if not workflow_generator.validate_workflow(workflow_spec):
            logger.error("Generated workflow is invalid")
            return 1

        # Export workflow
        workflow_generator.export_workflow(workflow_spec, args.workflow_output)
        logger.info(f"Workflow exported to: {args.workflow_output}")
        logger.info(f"Total test cycles: {workflow_spec['metadata']['total_test_cycles']}")

        if args.dry_run:
            logger.info("Dry run completed - workflow generated but not executed")
            return 0

        # Sync measurement tools to remote hosts before execution
        logger.info("Syncing measurement tools to remote hosts...")
        # Get paths from config (unified format stores in 'paths' key)
        paths_config = configs.get('paths', {})
        remote_tools_dir = paths_config.get('tools_dir', 'measurement-tools')
        local_tools_path = os.path.join(base_path, 'measurement-tools')

        logger.info(f"  Local tools: {local_tools_path}")
        logger.info(f"  Remote dir: {remote_tools_dir}")

        if not sync_tools_to_remote(configs['ssh'], local_tools_path, remote_tools_dir, logger):
            logger.warning("Some tool syncs failed, but continuing with execution...")

        # Execute workflow
        logger.info("Starting workflow execution...")

        # Initialize managers
        ssh_manager = SSHManager(configs['ssh'])
        _ssh_manager = ssh_manager

        # Get workdir from first available host
        first_host = list(configs['ssh']['ssh_hosts'].keys())[0]
        workdir = configs['ssh']['ssh_hosts'][first_host]['workdir']
        path_manager = RemotePathManager(workdir)

        # Initialize test executor with full config
        test_executor = TestExecutor(ssh_manager, path_manager, configs)
        _test_executor = test_executor

        # Execute workflow
        with ssh_manager:
            execution_results = test_executor.execute_workflow(workflow_spec)

        # Log results
        logger.info(f"Workflow execution completed with status: {execution_results['status']}")
        if execution_results['status'] == 'failed':
            logger.error(f"Execution error: {execution_results.get('error', 'Unknown error')}")
            return 1

        # Summary
        total_cycles = len(execution_results['test_cycles'])
        successful_cycles = sum(1 for cycle in execution_results['test_cycles']
                              if cycle['status'] == 'completed')

        logger.info(f"Execution Summary:")
        logger.info(f"  Total test cycles: {total_cycles}")
        logger.info(f"  Successful cycles: {successful_cycles}")
        logger.info(f"  Failed cycles: {total_cycles - successful_cycles}")
        logger.info(f"  Start time: {execution_results['start_time']}")
        logger.info(f"  End time: {execution_results['end_time']}")

        return 0 if successful_cycles == total_cycles else 1

    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
