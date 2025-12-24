#!/usr/bin/env python3
"""Scheduled automation test runner with result collection"""

import sys
import os
import argparse
import logging
import time
import subprocess
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from core.ssh_manager import SSHManager
from utils.config_loader import ConfigLoader


def setup_logging(log_file: str):
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file)
        ]
    )


def run_automation_test(config_dir: str, iteration: int, logger: logging.Logger,
                        filter_options: dict = None) -> bool:
    """Run single automation test iteration

    Args:
        config_dir: Configuration directory path
        iteration: Current iteration number
        logger: Logger instance
        filter_options: Optional dict with filter options (tools, environments, etc.)

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Starting automation test iteration {iteration}")

    # Change to test directory
    test_dir = os.path.dirname(os.path.dirname(__file__))
    original_dir = os.getcwd()

    try:
        os.chdir(test_dir)
        logger.info(f"Changed directory to: {test_dir}")

        # Run automation script
        cmd = [
            sys.executable,
            "scripts/run_automation.py",
            "--config-dir", config_dir
        ]

        # Add filter options if provided
        if filter_options:
            if filter_options.get('tools'):
                cmd.extend(['--tools'] + filter_options['tools'])
            if filter_options.get('environments'):
                cmd.extend(['--environments'] + filter_options['environments'])
            if filter_options.get('category'):
                cmd.extend(['--category'] + filter_options['category'])
            if filter_options.get('protocol'):
                cmd.extend(['--protocol', filter_options['protocol']])
            if filter_options.get('direction'):
                cmd.extend(['--direction', filter_options['direction']])

        logger.info(f"Executing command: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            logger.info(f"Iteration {iteration} completed successfully")
            return True
        else:
            logger.error(f"Iteration {iteration} failed with return code {result.returncode}")
            logger.error(f"stdout: {result.stdout}")
            logger.error(f"stderr: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Iteration {iteration} timed out")
        return False
    except Exception as e:
        logger.error(f"Iteration {iteration} failed with exception: {str(e)}")
        return False
    finally:
        os.chdir(original_dir)


def collect_remote_results(ssh_manager: SSHManager, configs: dict,
                          local_results_dir: Path, iteration: int,
                          logger: logging.Logger) -> bool:
    """Collect results from all remote hosts

    Args:
        ssh_manager: SSH manager instance
        configs: Configuration dictionary
        local_results_dir: Local directory to store results
        iteration: Current iteration number
        logger: Logger instance

    Returns:
        True if successful, False otherwise
    """
    logger.info(f"Collecting results for iteration {iteration}")

    # Create iteration directory
    iter_dir = local_results_dir / f"iteration_{iteration:03d}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    success = True

    # Get all unique host references from environments
    host_refs = set()
    for env_name, env_config in configs['env']['test_environments'].items():
        # Add server host
        host_refs.add(env_config['server']['ssh_ref'])
        # Add client host
        host_refs.add(env_config['client']['ssh_ref'])
        # Add physical host if exists (for VM environments)
        if 'physical_host_ref' in env_config['server']:
            host_refs.add(env_config['server']['physical_host_ref'])
        if 'physical_host_ref' in env_config['client']:
            host_refs.add(env_config['client']['physical_host_ref'])

    logger.info(f"Collecting from hosts: {host_refs}")

    # Collect from each host
    for host_ref in host_refs:
        if host_ref not in configs['ssh']['ssh_hosts']:
            logger.warning(f"Host reference not found in SSH config: {host_ref}")
            continue

        try:
            logger.info(f"Collecting results from {host_ref}")

            # Create host directory
            host_dir = iter_dir / host_ref
            host_dir.mkdir(parents=True, exist_ok=True)

            # Get workdir for host
            workdir = configs['ssh']['ssh_hosts'][host_ref]['workdir']
            remote_results_path = f"{workdir}/performance-test-results"

            # Check if remote path exists
            stdout, stderr, status = ssh_manager.execute_command(
                host_ref, f"test -d {remote_results_path} && echo 'exists'"
            )

            if status != 0 or 'exists' not in stdout:
                logger.warning(f"Remote results directory does not exist on {host_ref}: {remote_results_path}")
                continue

            # Create compressed archive on remote
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            archive_name = f"results_{host_ref}_{timestamp}.tar.gz"
            remote_archive = f"/tmp/{archive_name}"

            logger.info(f"Creating compressed archive on {host_ref}...")
            stdout, stderr, status = ssh_manager.execute_command(
                host_ref,
                f"cd {workdir} && tar -czf {remote_archive} performance-test-results/ 2>&1"
            )

            if status != 0:
                logger.error(f"Failed to create archive on {host_ref}: {stderr}")
                success = False
                continue

            # Copy compressed archive to local
            local_archive = host_dir / archive_name
            logger.info(f"Copying archive from {host_ref} to {local_archive}...")

            if ssh_manager.copy_file_from_remote(host_ref, remote_archive, str(local_archive)):
                logger.info(f"Successfully copied results from {host_ref}")

                # Extract archive locally
                logger.info(f"Extracting archive for {host_ref}...")
                extract_cmd = f"tar -xzf {local_archive} -C {host_dir}"
                result = subprocess.run(extract_cmd, shell=True, capture_output=True, text=True)

                if result.returncode == 0:
                    logger.info(f"Successfully extracted results for {host_ref}")
                    # Remove archive after extraction
                    local_archive.unlink()
                else:
                    logger.error(f"Failed to extract archive for {host_ref}: {result.stderr}")
                    success = False

                # Clean up remote archive
                ssh_manager.execute_command(host_ref, f"rm -f {remote_archive}")
            else:
                logger.error(f"Failed to copy archive from {host_ref}")
                success = False

        except Exception as e:
            logger.error(f"Failed to collect results from {host_ref}: {str(e)}")
            success = False

    # Create collection summary
    summary_file = iter_dir / "collection_summary.txt"
    with open(summary_file, 'w') as f:
        f.write(f"Result Collection Summary\n")
        f.write(f"========================\n")
        f.write(f"Iteration: {iteration}\n")
        f.write(f"Collection time: {datetime.now().isoformat()}\n")
        f.write(f"Hosts collected: {len(host_refs)}\n")
        f.write(f"Status: {'SUCCESS' if success else 'FAILED'}\n")
        f.write(f"\nCollected hosts:\n")
        for host_ref in sorted(host_refs):
            host_dir = iter_dir / host_ref
            if host_dir.exists():
                f.write(f"  - {host_ref}: {sum(1 for _ in host_dir.rglob('*') if _.is_file())} files\n")
            else:
                f.write(f"  - {host_ref}: NOT COLLECTED\n")

    logger.info(f"Collection summary saved to: {summary_file}")
    return success


def cleanup_remote_results(ssh_manager: SSHManager, configs: dict,
                           logger: logging.Logger) -> bool:
    """Clean up remote performance-test-results directories

    Args:
        ssh_manager: SSH manager instance
        configs: Configuration dictionary
        logger: Logger instance

    Returns:
        True if successful, False otherwise
    """
    logger.info("Cleaning up remote results directories")

    # Get all unique host references
    host_refs = set()
    for env_name, env_config in configs['env']['test_environments'].items():
        host_refs.add(env_config['server']['ssh_ref'])
        host_refs.add(env_config['client']['ssh_ref'])
        if 'physical_host_ref' in env_config['server']:
            host_refs.add(env_config['server']['physical_host_ref'])
        if 'physical_host_ref' in env_config['client']:
            host_refs.add(env_config['client']['physical_host_ref'])

    success = True

    for host_ref in host_refs:
        if host_ref not in configs['ssh']['ssh_hosts']:
            continue

        try:
            workdir = configs['ssh']['ssh_hosts'][host_ref]['workdir']
            remote_results_path = f"{workdir}/performance-test-results"

            logger.info(f"Deleting {remote_results_path} on {host_ref}")

            # Delete directory
            stdout, stderr, status = ssh_manager.execute_command(
                host_ref, f"rm -rf {remote_results_path}"
            )

            if status != 0:
                logger.error(f"Failed to delete directory on {host_ref}: {stderr}")
                success = False
                continue

            # Verify deletion
            stdout, stderr, status = ssh_manager.execute_command(
                host_ref, f"test -d {remote_results_path} && echo 'exists' || echo 'deleted'"
            )

            if 'deleted' in stdout:
                logger.info(f"Successfully verified deletion on {host_ref}")
            else:
                logger.error(f"Directory still exists on {host_ref} after deletion")
                success = False

        except Exception as e:
            logger.error(f"Failed to cleanup {host_ref}: {str(e)}")
            success = False

    return success


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Scheduled Automation Test Runner with Result Collection'
    )
    parser.add_argument('--config-dir', required=True,
                       help='Configuration directory path (e.g., config/phy-620)')
    parser.add_argument('--iterations', type=int, default=1,
                       help='Number of test iterations to run (default: 1)')
    parser.add_argument('--delay', type=int, default=0,
                       help='Delay in seconds before starting tests (default: 0)')
    parser.add_argument('--results-dir', default='./results',
                       help='Local directory to store results (default: ./results)')
    parser.add_argument('--no-cleanup', action='store_true',
                       help='Skip remote cleanup after collecting results')

    # Filter options (passed to run_automation.py)
    parser.add_argument('--tools', nargs='+',
                       help='Specific tools to test (passed to run_automation.py)')
    parser.add_argument('--environments', nargs='+',
                       help='Specific environments to test: host, vm (passed to run_automation.py)')
    parser.add_argument('--category', nargs='+',
                       help='Filter by tool category, supports multiple (passed to run_automation.py)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp'],
                       help='Filter by protocol (passed to run_automation.py)')
    parser.add_argument('--direction', choices=['rx', 'tx'],
                       help='Filter by direction (passed to run_automation.py)')

    args = parser.parse_args()

    # Setup paths
    results_dir = Path(args.results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    # Setup logging
    log_file = results_dir / f"scheduled_automation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    setup_logging(str(log_file))
    logger = logging.getLogger(__name__)

    logger.info("="*80)
    logger.info("Scheduled Automation Test Runner")
    logger.info("="*80)
    logger.info(f"Configuration directory: {args.config_dir}")
    logger.info(f"Iterations: {args.iterations}")
    logger.info(f"Delay: {args.delay} seconds")
    logger.info(f"Results directory: {results_dir}")
    logger.info(f"Remote cleanup: {'DISABLED' if args.no_cleanup else 'ENABLED'}")

    # Build filter options
    filter_options = {}
    if args.tools:
        filter_options['tools'] = args.tools
        logger.info(f"Filter - tools: {args.tools}")
    if args.environments:
        filter_options['environments'] = args.environments
        logger.info(f"Filter - environments: {args.environments}")
    if args.category:
        filter_options['category'] = args.category
        logger.info(f"Filter - category: {args.category}")
    if args.protocol:
        filter_options['protocol'] = args.protocol
        logger.info(f"Filter - protocol: {args.protocol}")
    if args.direction:
        filter_options['direction'] = args.direction
        logger.info(f"Filter - direction: {args.direction}")

    logger.info("="*80)

    try:
        # Initial delay if specified
        if args.delay > 0:
            logger.info(f"Waiting {args.delay} seconds before starting...")
            time.sleep(args.delay)

        # Load configurations
        config_dir = os.path.abspath(args.config_dir)
        logger.info(f"Loading configurations from: {config_dir}")

        config_loader = ConfigLoader(config_dir)
        configs = config_loader.load_all_configs()

        logger.info("Configurations loaded successfully")

        # Initialize SSH manager
        ssh_manager = SSHManager(configs['ssh'])

        # Track overall results
        overall_results = {
            'total_iterations': args.iterations,
            'successful_iterations': 0,
            'failed_iterations': 0,
            'start_time': datetime.now().isoformat(),
            'iterations': []
        }

        # Run iterations
        with ssh_manager:
            for iteration in range(1, args.iterations + 1):
                logger.info("="*80)
                logger.info(f"ITERATION {iteration}/{args.iterations}")
                logger.info("="*80)

                iteration_start = datetime.now()

                # Run automation test
                test_success = run_automation_test(args.config_dir, iteration, logger,
                                                   filter_options if filter_options else None)

                if not test_success:
                    logger.error(f"Iteration {iteration} test execution failed")
                    overall_results['failed_iterations'] += 1
                    overall_results['iterations'].append({
                        'iteration': iteration,
                        'status': 'TEST_FAILED',
                        'start_time': iteration_start.isoformat(),
                        'end_time': datetime.now().isoformat()
                    })
                    continue

                # Collect results
                collection_success = collect_remote_results(
                    ssh_manager, configs, results_dir, iteration, logger
                )

                if not collection_success:
                    logger.error(f"Iteration {iteration} result collection failed")
                    overall_results['failed_iterations'] += 1
                    overall_results['iterations'].append({
                        'iteration': iteration,
                        'status': 'COLLECTION_FAILED',
                        'start_time': iteration_start.isoformat(),
                        'end_time': datetime.now().isoformat()
                    })
                    continue

                # Cleanup remote results (unless disabled)
                if not args.no_cleanup:
                    cleanup_success = cleanup_remote_results(ssh_manager, configs, logger)

                    if not cleanup_success:
                        logger.warning(f"Iteration {iteration} cleanup had issues")
                else:
                    logger.info("Remote cleanup skipped (--no-cleanup specified)")
                    cleanup_success = True

                # Record iteration result
                if test_success and collection_success and cleanup_success:
                    logger.info(f"Iteration {iteration} completed successfully")
                    overall_results['successful_iterations'] += 1
                    status = 'SUCCESS'
                else:
                    logger.error(f"Iteration {iteration} completed with errors")
                    overall_results['failed_iterations'] += 1
                    status = 'FAILED'

                overall_results['iterations'].append({
                    'iteration': iteration,
                    'status': status,
                    'test_success': test_success,
                    'collection_success': collection_success,
                    'cleanup_success': cleanup_success,
                    'start_time': iteration_start.isoformat(),
                    'end_time': datetime.now().isoformat()
                })

                # Wait before next iteration (except last)
                if iteration < args.iterations:
                    logger.info("Waiting 10 seconds before next iteration...")
                    time.sleep(10)

        overall_results['end_time'] = datetime.now().isoformat()

        # Generate final summary
        logger.info("="*80)
        logger.info("FINAL SUMMARY")
        logger.info("="*80)
        logger.info(f"Total iterations: {overall_results['total_iterations']}")
        logger.info(f"Successful: {overall_results['successful_iterations']}")
        logger.info(f"Failed: {overall_results['failed_iterations']}")
        logger.info(f"Start time: {overall_results['start_time']}")
        logger.info(f"End time: {overall_results['end_time']}")

        # Write summary to file
        summary_file = results_dir / f"overall_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(summary_file, 'w') as f:
            f.write("Scheduled Automation Test Summary\n")
            f.write("="*80 + "\n")
            f.write(f"Total iterations: {overall_results['total_iterations']}\n")
            f.write(f"Successful: {overall_results['successful_iterations']}\n")
            f.write(f"Failed: {overall_results['failed_iterations']}\n")
            f.write(f"Start time: {overall_results['start_time']}\n")
            f.write(f"End time: {overall_results['end_time']}\n")
            f.write("\nIteration Details:\n")
            f.write("-"*80 + "\n")
            for iter_result in overall_results['iterations']:
                f.write(f"\nIteration {iter_result['iteration']}: {iter_result['status']}\n")
                f.write(f"  Start: {iter_result['start_time']}\n")
                f.write(f"  End: {iter_result['end_time']}\n")
                if 'test_success' in iter_result:
                    f.write(f"  Test: {'SUCCESS' if iter_result['test_success'] else 'FAILED'}\n")
                    f.write(f"  Collection: {'SUCCESS' if iter_result['collection_success'] else 'FAILED'}\n")
                    f.write(f"  Cleanup: {'SUCCESS' if iter_result['cleanup_success'] else 'FAILED'}\n")

        logger.info(f"Overall summary saved to: {summary_file}")
        logger.info("="*80)

        return 0 if overall_results['failed_iterations'] == 0 else 1

    except KeyboardInterrupt:
        logger.info("Execution interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
