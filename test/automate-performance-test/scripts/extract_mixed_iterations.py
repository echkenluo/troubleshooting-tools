#!/usr/bin/env python3
"""Extract and separate mixed iteration data from remote hosts.

This script downloads mixed test results from remote hosts and separates
them into individual iteration directories based on timestamps.
"""

import os
import sys
import re
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# Iteration time boundaries (based on scheduled_automation.py logs)
# Format: (iteration_num, start_timestamp, end_timestamp)
# Timestamps are in YYYYMMDD_HHMMSS format for comparison
ITERATION_BOUNDARIES = [
    (2, "20251223_151800", "20251223_190600"),
    (3, "20251223_190600", "20251223_215100"),
    (4, "20251223_215100", "20251224_003500"),
    (5, "20251224_003500", "20251224_240000"),  # End of day
]

# SSH hosts configuration
SSH_HOSTS = {
    "host-server": {"host": "172.21.128.40", "user": "smartx", "workdir": "/home/smartx/lcc"},
    "host-client": {"host": "172.21.128.42", "user": "smartx", "workdir": "/home/smartx/lcc"},
    "vm-server": {"host": "172.21.153.32", "user": "smartx", "workdir": "/home/smartx/lcc"},
    "vm-client": {"host": "172.21.153.102", "user": "smartx", "workdir": "/home/smartx/lcc"},
}

# Jump host for SSH access
JUMP_HOST = "echken@192.168.76.198"


def get_iteration_for_timestamp(timestamp: str) -> int:
    """Determine which iteration a timestamp belongs to.

    Args:
        timestamp: Timestamp string in YYYYMMDD_HHMMSS format

    Returns:
        Iteration number (2-5) or 0 if not matched
    """
    for iter_num, start_ts, end_ts in ITERATION_BOUNDARIES:
        if start_ts <= timestamp < end_ts:
            return iter_num
    return 0


def extract_timestamp_from_name(name: str) -> str:
    """Extract timestamp from file or directory name.

    Args:
        name: File or directory name

    Returns:
        Timestamp string or empty string if not found
    """
    # Match pattern like _20251223_153450 or _20251223_153450.log
    match = re.search(r'_(\d{8}_\d{6})(?:\.|$|/)', name)
    if match:
        return match.group(1)
    return ""


def download_from_host(host_ref: str, local_base: Path) -> Path:
    """Download performance-test-results from a remote host.

    Args:
        host_ref: Host reference name
        local_base: Local base directory

    Returns:
        Path to downloaded data
    """
    host_config = SSH_HOSTS[host_ref]
    remote_path = f"{host_config['workdir']}/performance-test-results/"
    local_path = local_base / "raw" / host_ref

    local_path.mkdir(parents=True, exist_ok=True)

    # Use rsync through jump host
    cmd = [
        "rsync", "-avz", "--progress",
        "-e", f"ssh -J {JUMP_HOST}",
        f"{host_config['user']}@{host_config['host']}:{remote_path}",
        str(local_path) + "/"
    ]

    print(f"Downloading from {host_ref}...")
    print(f"  Command: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  Warning: rsync returned {result.returncode}")
        print(f"  stderr: {result.stderr}")
    else:
        print(f"  Downloaded to {local_path}")

    return local_path / "performance-test-results"


def separate_iteration_data(source_dir: Path, output_base: Path, host_ref: str):
    """Separate mixed iteration data into individual iteration directories.

    Args:
        source_dir: Source directory with mixed data
        output_base: Output base directory
        host_ref: Host reference name
    """
    print(f"\nSeparating data for {host_ref}...")

    # Track statistics
    stats = {i: {"files": 0, "dirs": 0} for i in range(2, 6)}
    unmatched = []

    # Walk through all files
    for root, dirs, files in os.walk(source_dir):
        rel_root = Path(root).relative_to(source_dir)

        for filename in files:
            src_file = Path(root) / filename

            # Try to get timestamp from filename
            timestamp = extract_timestamp_from_name(filename)

            # If not in filename, try parent directory names
            if not timestamp:
                for part in str(rel_root).split(os.sep):
                    timestamp = extract_timestamp_from_name(part)
                    if timestamp:
                        break

            if timestamp:
                iteration = get_iteration_for_timestamp(timestamp)
                if iteration > 0:
                    # Create destination path
                    iter_dir = output_base / f"iteration_{iteration:03d}" / host_ref / "performance-test-results"
                    dest_dir = iter_dir / rel_root
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest_file = dest_dir / filename

                    # Copy file
                    shutil.copy2(src_file, dest_file)
                    stats[iteration]["files"] += 1
                else:
                    unmatched.append((str(rel_root / filename), timestamp))
            else:
                unmatched.append((str(rel_root / filename), "no timestamp"))

    # Print statistics
    for i in range(2, 6):
        print(f"  Iteration {i}: {stats[i]['files']} files")

    if unmatched:
        print(f"  Unmatched: {len(unmatched)} files")
        if len(unmatched) <= 10:
            for path, reason in unmatched:
                print(f"    - {path} ({reason})")


def main():
    parser = argparse.ArgumentParser(
        description="Extract and separate mixed iteration data from remote hosts"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./results",
        help="Output directory for extracted data (default: ./results)"
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Skip download, use existing raw data"
    )
    parser.add_argument(
        "--hosts",
        nargs="+",
        choices=list(SSH_HOSTS.keys()) + ["all"],
        default=["all"],
        help="Hosts to process (default: all)"
    )

    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Determine which hosts to process
    if "all" in args.hosts:
        hosts = list(SSH_HOSTS.keys())
    else:
        hosts = args.hosts

    print("=" * 60)
    print("Mixed Iteration Data Extractor")
    print("=" * 60)
    print(f"Output directory: {output_dir}")
    print(f"Hosts to process: {hosts}")
    print()

    # Download data from each host
    if not args.skip_download:
        print("Phase 1: Downloading data from remote hosts")
        print("-" * 60)
        for host_ref in hosts:
            download_from_host(host_ref, output_dir)
    else:
        print("Phase 1: Skipping download (--skip-download)")

    # Separate data for each host
    print()
    print("Phase 2: Separating data by iteration")
    print("-" * 60)

    for host_ref in hosts:
        raw_dir = output_dir / "raw" / host_ref / "performance-test-results"
        if raw_dir.exists():
            separate_iteration_data(raw_dir, output_dir, host_ref)
        else:
            print(f"  Warning: No raw data found for {host_ref}")

    print()
    print("=" * 60)
    print("Extraction complete!")
    print("=" * 60)

    # Show output structure
    print("\nOutput structure:")
    for i in range(2, 6):
        iter_dir = output_dir / f"iteration_{i:03d}"
        if iter_dir.exists():
            host_count = len(list(iter_dir.iterdir()))
            print(f"  iteration_{i:03d}/: {host_count} hosts")


if __name__ == "__main__":
    main()
