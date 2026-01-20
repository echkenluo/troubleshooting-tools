#!/usr/bin/env python -u
# -*- coding: utf-8 -*-
"""
PPS Monitor with Conditional Packet Capture

Monitor network interface PPS (packets per second) using sar and trigger
tcpdump capture when PPS exceeds threshold for a sustained duration.

Usage:
    sudo python -u pps_monitor_capture.py --nics enp24s0f0np0,enp24s0f1np1 \
        --direction rx --interval 1 --threshold 10000 --duration 3 \
        --capture-time 10 --max-captures 2 --output-dir /tmp/captures
"""

from __future__ import print_function, division

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime


def flush_print(msg):
    """Print with immediate flush for unbuffered output"""
    print(msg)
    sys.stdout.flush()

# Global state for signal handling
running = True
capture_processes = []
sar_process = None


def signal_handler(sig, frame):
    """Handle interrupt signals gracefully"""
    global running, capture_processes, sar_process
    flush_print("\n[INFO] Received signal %d, stopping..." % sig)
    running = False

    # Terminate capture processes
    for proc in capture_processes:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

    # Terminate sar process
    if sar_process and sar_process.poll() is None:
        try:
            sar_process.terminate()
            sar_process.wait(timeout=2)
        except Exception:
            sar_process.kill()


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Monitor PPS and capture packets when threshold exceeded',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Monitor rx PPS on single NIC:
    sudo python %(prog)s --nics eth0 --direction rx --threshold 5000

  Monitor both directions on multiple NICs:
    sudo python %(prog)s --nics eth0,eth1 --direction both --threshold 10000

  Custom capture settings:
    sudo python %(prog)s --nics eth0 --direction rx --threshold 5000 \\
        --capture-time 30 --capture-count 10000 --max-captures 3
        ''')

    parser.add_argument('--nics', required=True,
                        help='Comma-separated list of NICs to monitor')
    parser.add_argument('--direction', choices=['rx', 'tx', 'both'], default='rx',
                        help='Direction to monitor: rx, tx, or both (default: rx)')
    parser.add_argument('--interval', type=int, default=1,
                        help='Monitoring interval in seconds (default: 1)')
    parser.add_argument('--threshold', type=int, required=True,
                        help='PPS threshold to trigger capture')
    parser.add_argument('--duration', type=int, default=3,
                        help='Number of consecutive intervals exceeding threshold (default: 3)')
    parser.add_argument('--capture-time', type=int, default=10,
                        help='Capture duration in seconds (default: 10)')
    parser.add_argument('--capture-count', type=int, default=0,
                        help='Max packets to capture per NIC (0=no limit, default: 0)')
    parser.add_argument('--max-captures', type=int, default=1,
                        help='Maximum number of capture sessions (default: 1)')
    parser.add_argument('--output-dir', default='/tmp/pps_captures',
                        help='Directory for capture files (default: /tmp/pps_captures)')
    parser.add_argument('--snaplen', type=int, default=128,
                        help='Capture snaplen bytes per packet (default: 128)')

    return parser.parse_args()


def ensure_output_dir(output_dir):
    """Create output directory if it doesn't exist"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        flush_print("[INFO] Created output directory: %s" % output_dir)


def get_pps_from_sar_line(line, direction):
    """
    Parse sar output line and extract PPS value.
    Returns (nic_name, pps_value) or (None, None) if parsing fails.
    """
    # sar -n DEV output format (12-hour clock):
    # HH:MM:SS AM/PM  IFACE  rxpck/s  txpck/s  rxkB/s  txkB/s  rxcmp/s  txcmp/s  rxmcst/s
    # sar -n DEV output format (24-hour clock):
    # HH:MM:SS  IFACE  rxpck/s  txpck/s  rxkB/s  txkB/s  rxcmp/s  txcmp/s  rxmcst/s
    parts = line.split()
    if len(parts) < 4:
        return None, None

    # Skip header lines
    if 'IFACE' in line or 'Average' in line or 'Linux' in line:
        return None, None

    try:
        # Determine if 12-hour or 24-hour format based on AM/PM
        if len(parts) > 1 and parts[1] in ('AM', 'PM'):
            # 12-hour format: HH:MM:SS AM/PM IFACE rxpck/s txpck/s ...
            nic = parts[2]
            rxpps = float(parts[3])
            txpps = float(parts[4])
        else:
            # 24-hour format: HH:MM:SS IFACE rxpck/s txpck/s ...
            nic = parts[1]
            rxpps = float(parts[2])
            txpps = float(parts[3])

        if direction == 'rx':
            return nic, rxpps
        elif direction == 'tx':
            return nic, txpps
        else:  # both
            return nic, rxpps + txpps
    except (IndexError, ValueError):
        return None, None


def start_tcpdump(nics, output_dir, capture_time, capture_count, snaplen, capture_num):
    """
    Start tcpdump on all specified NICs.
    Returns list of subprocess objects.
    """
    global capture_processes
    processes = []
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    for nic in nics:
        filename = os.path.join(output_dir,
                               'capture_%s_%s_%d.pcap' % (nic, timestamp, capture_num))

        # Build tcpdump command
        # timeout must be after sudo for proper signal handling
        cmd = ['sudo', 'timeout', str(capture_time),
               'tcpdump', '-i', nic, '-s', str(snaplen), '-w', filename]

        if capture_count > 0:
            cmd.extend(['-c', str(capture_count)])

        flush_print("[CAPTURE] Starting tcpdump on %s -> %s" % (nic, filename))

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            processes.append(proc)
            capture_processes.append(proc)
        except Exception as e:
            flush_print("[ERROR] Failed to start tcpdump on %s: %s" % (nic, str(e)))

    return processes


def wait_for_captures(processes, timeout):
    """Wait for all capture processes to complete"""
    start_time = time.time()
    while time.time() - start_time < timeout + 5:  # Extra 5s buffer
        all_done = True
        for proc in processes:
            if proc.poll() is None:
                all_done = False
                break
        if all_done:
            break
        time.sleep(0.5)

    # Force terminate any remaining
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def monitor_pps(args):
    """Main monitoring loop using sar"""
    global running, sar_process

    nics = [n.strip() for n in args.nics.split(',')]
    ensure_output_dir(args.output_dir)

    # Initialize state tracking
    pps_history = {nic: deque(maxlen=args.duration) for nic in nics}
    capture_count = 0
    capturing = False
    capture_end_time = 0

    flush_print("=" * 70)
    flush_print("PPS Monitor with Conditional Packet Capture")
    flush_print("=" * 70)
    flush_print("NICs:         %s" % ', '.join(nics))
    flush_print("Direction:    %s" % args.direction)
    flush_print("Interval:     %d seconds" % args.interval)
    flush_print("Threshold:    %d pps" % args.threshold)
    flush_print("Duration:     %d intervals" % args.duration)
    flush_print("Capture time: %d seconds" % args.capture_time)
    flush_print("Max captures: %d" % args.max_captures)
    flush_print("Output dir:   %s" % args.output_dir)
    flush_print("=" * 70)
    flush_print("")

    # Start sar process with stdbuf to force line buffering
    sar_cmd = ['stdbuf', '-oL', 'sar', '-n', 'DEV', str(args.interval)]
    flush_print("[INFO] Starting sar monitoring...")

    try:
        sar_process = subprocess.Popen(sar_cmd, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       universal_newlines=True,
                                       bufsize=1)
    except Exception as e:
        flush_print("[ERROR] Failed to start sar: %s" % str(e))
        return 1

    # Header printed flag
    header_printed = False

    while running:
        try:
            line = sar_process.stdout.readline()
            if not line:
                if sar_process.poll() is not None:
                    flush_print("[ERROR] sar process terminated unexpectedly")
                    break
                continue

            line = line.strip()
            if not line:
                continue

            # Parse sar output
            nic, pps = get_pps_from_sar_line(line, args.direction)

            if nic is None or nic not in nics:
                continue

            # Update history
            pps_history[nic].append(pps)
            current_time = datetime.now().strftime('%H:%M:%S')

            # Print header once
            if not header_printed:
                flush_print("\n%-10s %-20s %-12s %-8s %-10s" %
                            ('Time', 'NIC', 'PPS', 'Status', 'Captures'))
                flush_print("-" * 70)
                header_printed = True

            # Check if capturing is done
            if capturing and time.time() >= capture_end_time:
                capturing = False
                flush_print("[INFO] Capture session %d completed" % capture_count)

            # Determine status
            if pps >= args.threshold:
                status = "HIGH"
            else:
                status = "normal"

            flush_print("%-10s %-20s %-12.0f %-8s %-10s" %
                        (current_time, nic, pps, status,
                         "%d/%d" % (capture_count, args.max_captures)))

            # Check trigger condition
            if not capturing and capture_count < args.max_captures:
                # Check if all NICs have sustained high PPS
                all_high = True
                for check_nic in nics:
                    history = pps_history[check_nic]
                    if len(history) < args.duration:
                        all_high = False
                        break
                    if not all(p >= args.threshold for p in history):
                        all_high = False
                        break

                if all_high:
                    capture_count += 1
                    capturing = True
                    capture_end_time = time.time() + args.capture_time

                    flush_print("\n" + "=" * 70)
                    flush_print("[TRIGGER] PPS exceeded %d for %d intervals on all NICs!" %
                                (args.threshold, args.duration))
                    flush_print("[TRIGGER] Starting capture session %d/%d" %
                                (capture_count, args.max_captures))
                    flush_print("=" * 70 + "\n")

                    # Start capture in background thread
                    capture_procs = start_tcpdump(nics, args.output_dir,
                                                  args.capture_time,
                                                  args.capture_count,
                                                  args.snaplen, capture_count)

                    # Clear history after trigger
                    for h in pps_history.values():
                        h.clear()

        except KeyboardInterrupt:
            break
        except Exception as e:
            flush_print("[ERROR] %s" % str(e))
            continue

    # Cleanup
    flush_print("\n[INFO] Stopping monitoring...")
    if sar_process and sar_process.poll() is None:
        sar_process.terminate()
        try:
            sar_process.wait(timeout=2)
        except Exception:
            sar_process.kill()

    # Wait for any ongoing captures
    if capturing:
        flush_print("[INFO] Waiting for capture to complete...")
        time.sleep(max(0, capture_end_time - time.time()) + 2)

    flush_print("\n" + "=" * 70)
    flush_print("Summary")
    flush_print("=" * 70)
    flush_print("Total captures triggered: %d" % capture_count)
    flush_print("Capture files in: %s" % args.output_dir)

    # List capture files
    if os.path.exists(args.output_dir):
        files = [f for f in os.listdir(args.output_dir) if f.endswith('.pcap')]
        if files:
            flush_print("\nCapture files:")
            for f in sorted(files):
                filepath = os.path.join(args.output_dir, f)
                size = os.path.getsize(filepath)
                flush_print("  - %s (%d bytes)" % (f, size))

    flush_print("=" * 70)
    return 0


def main():
    """Main entry point"""
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_args()

    # Validate arguments
    if args.interval < 1:
        flush_print("[ERROR] Interval must be at least 1 second")
        return 1

    if args.duration < 1:
        flush_print("[ERROR] Duration must be at least 1 interval")
        return 1

    if args.threshold < 0:
        flush_print("[ERROR] Threshold must be non-negative")
        return 1

    return monitor_pps(args)


if __name__ == '__main__':
    sys.exit(main())
