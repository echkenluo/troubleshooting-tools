#!/usr/bin/env python3
"""Script to fetch remote test results"""

import sys
import os
import argparse
import logging
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from core.ssh_manager import SSHManager
from utils.config_loader import ConfigLoader


def main():
    """Main fetch function"""
    parser = argparse.ArgumentParser(description='Fetch Remote Test Results')
    parser.add_argument('--config-dir', default='../config',
                       help='Configuration directory path')
    parser.add_argument('--local-dir', default='./fetched_results',
                       help='Local directory to store results')
    parser.add_argument('--host', required=True,
                       help='Host reference to fetch from')
    parser.add_argument('--remote-path',
                       help='Specific remote path to fetch (default: all results)')
    parser.add_argument('--compress', action='store_true',
                       help='Compress results before transfer')

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    try:
        # Load SSH configuration
        config_dir = os.path.abspath(args.config_dir)
        config_loader = ConfigLoader(config_dir)
        ssh_config = config_loader.load_ssh_config()

        logger.info(f"Fetching results from host: {args.host}")

        # Create local directory
        os.makedirs(args.local_dir, exist_ok=True)

        # Initialize SSH manager
        ssh_manager = SSHManager(ssh_config)

        with ssh_manager:
            # Get workdir for host
            if args.host not in ssh_config['ssh_hosts']:
                logger.error(f"Unknown host reference: {args.host}")
                return 1

            workdir = ssh_config['ssh_hosts'][args.host]['workdir']
            remote_base = f"{workdir}/performance-test-results"

            # Determine what to fetch
            if args.remote_path:
                remote_path = args.remote_path
                local_name = os.path.basename(args.remote_path)
            else:
                remote_path = remote_base
                local_name = f"results_{args.host}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            local_path = os.path.join(args.local_dir, local_name)

            # Check if remote path exists
            stdout, stderr, status = ssh_manager.execute_command(
                args.host, f"test -d {remote_path} && echo 'exists'"
            )

            if status != 0 or 'exists' not in stdout:
                logger.error(f"Remote path does not exist: {remote_path}")
                return 1

            if args.compress:
                # Create compressed archive on remote
                archive_name = f"{local_name}.tar.gz"
                remote_archive = f"/tmp/{archive_name}"

                logger.info("Creating compressed archive on remote...")
                stdout, stderr, status = ssh_manager.execute_command(
                    args.host,
                    f"cd {os.path.dirname(remote_path)} && tar -czf {remote_archive} {os.path.basename(remote_path)}"
                )

                if status != 0:
                    logger.error(f"Failed to create archive: {stderr}")
                    return 1

                # Copy compressed archive
                local_archive = os.path.join(args.local_dir, archive_name)
                if ssh_manager.copy_file_from_remote(args.host, remote_archive, local_archive):
                    logger.info(f"Results fetched to: {local_archive}")

                    # Clean up remote archive
                    ssh_manager.execute_command(args.host, f"rm -f {remote_archive}")
                else:
                    logger.error("Failed to copy compressed archive")
                    return 1

            else:
                # Direct recursive copy using rsync
                rsync_cmd = f"rsync -avz {ssh_config['ssh_hosts'][args.host]['user']}@{ssh_config['ssh_hosts'][args.host]['host']}:{remote_path}/ {local_path}/"

                import subprocess
                logger.info("Copying results using rsync...")
                result = subprocess.run(rsync_cmd, shell=True, capture_output=True, text=True)

                if result.returncode == 0:
                    logger.info(f"Results fetched to: {local_path}")
                else:
                    logger.error(f"Rsync failed: {result.stderr}")
                    return 1

            # Generate summary
            summary_file = os.path.join(args.local_dir, f"fetch_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(summary_file, 'w') as f:
                f.write(f"Fetch Summary\n")
                f.write(f"=============\n")
                f.write(f"Host: {args.host}\n")
                f.write(f"Remote path: {remote_path}\n")
                f.write(f"Local path: {local_path if not args.compress else local_archive}\n")
                f.write(f"Compressed: {args.compress}\n")
                f.write(f"Fetch time: {datetime.now().isoformat()}\n")

            logger.info(f"Fetch summary saved to: {summary_file}")

        return 0

    except Exception as e:
        logger.error(f"Fetch failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())