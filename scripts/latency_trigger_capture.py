#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Latency-Triggered Packet Capture Tool

Monitor Prometheus metrics or alerts and trigger tcpdump capture when
conditions are met. Filters by local hostname to capture only relevant traffic.

Trigger Modes:
    alert   - Poll Prometheus alerts API, trigger when specified alert is firing
    metric  - Poll Prometheus query API, trigger when metric exceeds threshold

Trigger Conditions (mutually exclusive):
    --trigger-count N     - Trigger after N consecutive occurrences (default: 3)
    --trigger-duration N  - Trigger after N seconds of continuous condition

Password Handling:
    Use --prometheus-pass-file to avoid shell escaping issues with special
    characters. Create password file: echo 'password' > ~/.prometheus_pass

Options:
    --nic               NIC to capture packets on (required)
    --local-hostname    Local hostname for filtering src/dst (required)
    --prometheus-url    Prometheus API URL (required)
    --prometheus-user   Basic auth username
    --prometheus-pass   Basic auth password (direct input)
    --prometheus-pass-file  Read password from file (recommended)
    --trigger-mode      alert or metric (default: metric)
    --alert-name        Alert name for alert mode
    --metric-query      PromQL query for metric mode
    --metric-threshold  Threshold in nanoseconds (default: 2000000 = 2ms)
    --poll-interval     Seconds between polls (default: 5)
    --max-captures      Maximum capture sessions (default: 1)
    --capture-time      Capture duration in seconds (default: 10)
    --output-dir        Output directory (default: /tmp/latency_captures)

Usage:
    # Create password file (recommended for passwords with special characters)
    echo 'HC!r0cks' > ~/.prometheus_pass && chmod 600 ~/.prometheus_pass

    # Alert-based: trigger when Prometheus alert fires
    sudo python -u latency_trigger_capture.py --nic enp24s0f0np0 \
        --local-hostname node31 \
        --prometheus-url http://<management-ip>:9091 \
        --prometheus-user prometheus --prometheus-pass-file ~/.prometheus_pass \
        --trigger-mode alert \
        --alert-name 'host_to_host_max_ping_time_ns:critical' \
        --trigger-count 3 --max-captures 2

    # Metric-based: trigger when p90 latency > 2ms (before 5ms alert threshold)
    sudo python -u latency_trigger_capture.py --nic enp24s0f0np0 \
        --local-hostname node31 \
        --prometheus-url http://<management-ip>:9091 \
        --prometheus-user prometheus --prometheus-pass-file ~/.prometheus_pass \
        --trigger-mode metric \
        --metric-threshold 2000000 \
        --trigger-count 3 --max-captures 2
"""

from __future__ import print_function, division

import argparse
import base64
import json
import os
import signal
import subprocess
import sys
import time
from collections import deque
from datetime import datetime

try:
    from urllib.request import Request, urlopen
    from urllib.parse import urlencode, quote
    from urllib.error import URLError, HTTPError
except ImportError:
    from urllib2 import Request, urlopen, URLError, HTTPError
    from urllib import urlencode, quote

# Default metric query for storage network p90 latency
DEFAULT_METRIC_QUERY = 'histogram_quantile(0.9,rate(host_to_host_max_ping_time_ns_bucket[5m]))'
DEFAULT_ALERT_NAME = 'host_to_host_max_ping_time_ns:critical'

# Global state
running = True
capture_processes = []


def flush_print(msg):
    """Print with immediate flush"""
    print(msg)
    sys.stdout.flush()


def signal_handler(sig, frame):
    """Handle interrupt signals"""
    global running, capture_processes
    flush_print("\n[INFO] Received signal %d, stopping..." % sig)
    running = False

    for proc in capture_processes:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Latency-triggered packet capture using Prometheus metrics/alerts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Alert mode: trigger on Prometheus alert
  sudo python %(prog)s --nic eth0 --local-hostname node31 \\
      --prometheus-url http://<management-ip>:9091 \\
      --prometheus-user prometheus --prometheus-pass-file ~/.prometheus_pass \\
      --trigger-mode alert --alert-name 'my_alert' --trigger-count 3

  # Metric mode: trigger when p90 > 2ms
  sudo python %(prog)s --nic eth0 --local-hostname node31 \\
      --prometheus-url http://<management-ip>:9091 \\
      --prometheus-user prometheus --prometheus-pass-file ~/.prometheus_pass \\
      --trigger-mode metric --metric-threshold 2000000 --trigger-count 3
        ''')

    # Required options
    parser.add_argument('--nic', required=True,
                        help='NIC to capture packets on')
    parser.add_argument('--local-hostname', required=True,
                        help='Local hostname for filtering (e.g., node31)')
    parser.add_argument('--prometheus-url', required=True,
                        help='Prometheus API URL (e.g., http://192.168.70.31:9091)')

    # Authentication
    parser.add_argument('--prometheus-user', default='',
                        help='Prometheus basic auth username')
    parser.add_argument('--prometheus-pass', default='',
                        help='Prometheus basic auth password')
    parser.add_argument('--prometheus-pass-file', default='',
                        help='File containing Prometheus password (read first line)')

    # Trigger mode
    parser.add_argument('--trigger-mode', choices=['alert', 'metric'],
                        default='metric',
                        help='Trigger mode: alert or metric (default: metric)')

    # Alert mode options
    parser.add_argument('--alert-name', default=DEFAULT_ALERT_NAME,
                        help='Alert name to monitor (default: %s)' % DEFAULT_ALERT_NAME)

    # Metric mode options
    parser.add_argument('--metric-query', default=DEFAULT_METRIC_QUERY,
                        help='PromQL query for metric mode')
    parser.add_argument('--metric-threshold', type=float, default=2000000,
                        help='Metric threshold in nanoseconds (default: 2000000 = 2ms)')

    # Trigger conditions (mutually exclusive)
    trigger_group = parser.add_mutually_exclusive_group()
    trigger_group.add_argument('--trigger-count', type=int, default=0,
                               help='Consecutive occurrences to trigger capture')
    trigger_group.add_argument('--trigger-duration', type=int, default=0,
                               help='Continuous duration (seconds) to trigger capture')

    # Polling and capture settings
    parser.add_argument('--poll-interval', type=int, default=5,
                        help='Seconds between API polls (default: 5)')
    parser.add_argument('--max-captures', type=int, default=1,
                        help='Maximum capture sessions (default: 1)')
    parser.add_argument('--capture-time', type=int, default=10,
                        help='Capture duration in seconds (default: 10)')
    parser.add_argument('--capture-count', type=int, default=0,
                        help='Max packets to capture (0=no limit, default: 0)')
    parser.add_argument('--output-dir', default='/tmp/latency_captures',
                        help='Directory for capture files')
    parser.add_argument('--snaplen', type=int, default=128,
                        help='Capture snaplen bytes per packet (default: 128)')

    args = parser.parse_args()

    # Password priority: file > direct
    if args.prometheus_pass_file:
        try:
            with open(args.prometheus_pass_file, 'r') as f:
                args.prometheus_pass = f.readline().rstrip('\n\r')
            if not args.prometheus_pass:
                flush_print("[ERROR] Password file %s is empty" % args.prometheus_pass_file)
                sys.exit(1)
        except IOError as e:
            flush_print("[ERROR] Failed to read password file: %s" % str(e))
            sys.exit(1)

    # Default trigger condition
    if args.trigger_count == 0 and args.trigger_duration == 0:
        args.trigger_count = 3

    return args


def prometheus_request(url, user, password, endpoint, params=None):
    """Make authenticated request to Prometheus API"""
    full_url = url.rstrip('/') + endpoint
    if params:
        full_url += '?' + urlencode(params)

    req = Request(full_url)

    if user and password:
        credentials = base64.b64encode(
            ('%s:%s' % (user, password)).encode('utf-8')
        ).decode('utf-8')
        req.add_header('Authorization', 'Basic %s' % credentials)

    try:
        response = urlopen(req, timeout=10)
        data = json.loads(response.read().decode('utf-8'))
        return data
    except (URLError, HTTPError) as e:
        flush_print("[ERROR] Prometheus request failed: %s" % str(e))
        return None
    except Exception as e:
        flush_print("[ERROR] Unexpected error: %s" % str(e))
        return None


def check_alert_firing(args):
    """
    Check if the specified alert is firing for the local hostname.
    Returns list of matching alerts (with hostname info).
    """
    data = prometheus_request(
        args.prometheus_url,
        args.prometheus_user,
        args.prometheus_pass,
        '/api/v1/alerts'
    )

    if not data or data.get('status') != 'success':
        return []

    alerts = data.get('data', {}).get('alerts', [])
    matching = []

    for alert in alerts:
        labels = alert.get('labels', {})
        alert_name = labels.get('alertname', '')

        if alert_name != args.alert_name:
            continue

        if alert.get('state') != 'firing':
            continue

        # Check if local hostname is involved (as source or destination)
        hostname = labels.get('hostname', '')
        to_hostname = labels.get('to_hostname', '')

        if args.local_hostname in (hostname, to_hostname):
            matching.append({
                'alert': alert_name,
                'hostname': hostname,
                'to_hostname': to_hostname,
                'value': alert.get('value', 'N/A')
            })

    return matching


def check_metric_threshold(args):
    """
    Check if the metric exceeds threshold for the local hostname.
    Returns list of matching metrics (with hostname info and values).
    """
    data = prometheus_request(
        args.prometheus_url,
        args.prometheus_user,
        args.prometheus_pass,
        '/api/v1/query',
        {'query': args.metric_query}
    )

    if not data or data.get('status') != 'success':
        return []

    results = data.get('data', {}).get('result', [])
    matching = []

    for result in results:
        metric = result.get('metric', {})
        value_pair = result.get('value', [])

        if len(value_pair) < 2:
            continue

        try:
            value = float(value_pair[1])
        except (ValueError, TypeError):
            continue

        # Check if local hostname is involved
        hostname = metric.get('hostname', '')
        to_hostname = metric.get('to_hostname', '')

        if args.local_hostname not in (hostname, to_hostname):
            continue

        # Check threshold
        if value > args.metric_threshold:
            matching.append({
                'hostname': hostname,
                'to_hostname': to_hostname,
                'value': value,
                'value_ms': value / 1000000.0
            })

    return matching


def ensure_output_dir(output_dir):
    """Create output directory if needed"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        flush_print("[INFO] Created output directory: %s" % output_dir)


def start_tcpdump(nic, output_dir, capture_time, capture_count, snaplen, capture_num):
    """Start tcpdump capture"""
    global capture_processes
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(output_dir,
                           'latency_capture_%s_%s_%d.pcap' % (nic, timestamp, capture_num))

    cmd = ['sudo', 'timeout', str(capture_time),
           'tcpdump', '-i', nic, '-s', str(snaplen), '-w', filename]

    if capture_count > 0:
        cmd.extend(['-c', str(capture_count)])

    flush_print("[CAPTURE] Starting tcpdump on %s -> %s" % (nic, filename))

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        capture_processes.append(proc)
        return proc
    except Exception as e:
        flush_print("[ERROR] Failed to start tcpdump: %s" % str(e))
        return None


def format_trigger_info(trigger_mode, matches):
    """Format trigger information for display"""
    lines = []
    for m in matches[:3]:  # Show max 3 matches
        if trigger_mode == 'alert':
            lines.append("  %s -> %s (alert: %s)" % (
                m['hostname'], m['to_hostname'], m['alert']))
        else:
            lines.append("  %s -> %s (p90: %.3f ms)" % (
                m['hostname'], m['to_hostname'], m['value_ms']))
    if len(matches) > 3:
        lines.append("  ... and %d more" % (len(matches) - 3))
    return '\n'.join(lines)


def main():
    global running

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_args()
    ensure_output_dir(args.output_dir)

    # State tracking
    trigger_history = deque(maxlen=max(args.trigger_count, 100))
    first_trigger_time = None
    capture_count = 0
    capturing = False
    capture_end_time = 0

    # Print configuration
    flush_print("=" * 80)
    flush_print("Latency-Triggered Packet Capture")
    flush_print("=" * 80)
    flush_print("NIC:            %s" % args.nic)
    flush_print("Local hostname: %s" % args.local_hostname)
    flush_print("Prometheus:     %s" % args.prometheus_url)
    flush_print("Trigger mode:   %s" % args.trigger_mode)

    if args.trigger_mode == 'alert':
        flush_print("Alert name:     %s" % args.alert_name)
    else:
        flush_print("Metric query:   %s" % args.metric_query[:60])
        flush_print("Threshold:      %.0f ns (%.2f ms)" % (
            args.metric_threshold, args.metric_threshold / 1000000.0))

    if args.trigger_count > 0:
        flush_print("Trigger:        %d consecutive occurrences" % args.trigger_count)
    else:
        flush_print("Trigger:        %d seconds continuous" % args.trigger_duration)

    flush_print("Poll interval:  %d seconds" % args.poll_interval)
    flush_print("Max captures:   %d" % args.max_captures)
    flush_print("Capture time:   %d seconds" % args.capture_time)
    flush_print("Output dir:     %s" % args.output_dir)
    flush_print("=" * 80)
    flush_print("")

    # Column header
    header = "%-10s %-12s %-8s %-10s %s" % (
        "Time", "Status", "Count", "Captures", "Details")
    flush_print(header)
    flush_print("-" * 80)

    while running:
        try:
            current_time = datetime.now().strftime('%H:%M:%S')

            # Check condition based on trigger mode
            if args.trigger_mode == 'alert':
                matches = check_alert_firing(args)
                triggered = len(matches) > 0
                status = "ALERT" if triggered else "normal"
            else:
                matches = check_metric_threshold(args)
                triggered = len(matches) > 0
                status = "HIGH" if triggered else "normal"

            # Update trigger history
            trigger_history.append(triggered)

            # Check if capturing is done
            if capturing and time.time() >= capture_end_time:
                capturing = False
                flush_print("[INFO] Capture session %d completed" % capture_count)

            # Build details string
            if triggered and matches:
                details = "%s->%s" % (matches[0]['hostname'], matches[0]['to_hostname'])
                if args.trigger_mode == 'metric':
                    details += " (%.2fms)" % matches[0]['value_ms']
            else:
                details = "-"

            # Print status line
            consecutive = sum(1 for t in reversed(list(trigger_history)) if t)
            if not triggered:
                consecutive = 0

            flush_print("%-10s %-12s %-8d %-10s %s" % (
                current_time, status, consecutive,
                "%d/%d" % (capture_count, args.max_captures),
                details))

            # Check trigger condition
            should_capture = False

            if not capturing and capture_count < args.max_captures and triggered:
                if args.trigger_count > 0:
                    # Count-based trigger
                    recent = list(trigger_history)[-args.trigger_count:]
                    if len(recent) >= args.trigger_count and all(recent):
                        should_capture = True
                else:
                    # Duration-based trigger
                    if first_trigger_time is None:
                        first_trigger_time = time.time()
                    elif time.time() - first_trigger_time >= args.trigger_duration:
                        should_capture = True

            # Reset duration timer if condition cleared
            if not triggered:
                first_trigger_time = None

            # Start capture if triggered
            if should_capture:
                capture_count += 1
                capturing = True
                capture_end_time = time.time() + args.capture_time

                flush_print("")
                flush_print("=" * 80)
                if args.trigger_mode == 'alert':
                    flush_print("[TRIGGER] Alert '%s' firing for %s!" % (
                        args.alert_name,
                        "count=%d" % args.trigger_count if args.trigger_count > 0
                        else "duration=%ds" % args.trigger_duration))
                else:
                    flush_print("[TRIGGER] Metric exceeded %.2f ms for %s!" % (
                        args.metric_threshold / 1000000.0,
                        "count=%d" % args.trigger_count if args.trigger_count > 0
                        else "duration=%ds" % args.trigger_duration))
                flush_print("[TRIGGER] Matching conditions:")
                flush_print(format_trigger_info(args.trigger_mode, matches))
                flush_print("[TRIGGER] Starting capture session %d/%d" % (
                    capture_count, args.max_captures))
                flush_print("=" * 80)
                flush_print("")

                start_tcpdump(args.nic, args.output_dir,
                             args.capture_time, args.capture_count,
                             args.snaplen, capture_count)

                # Clear history after trigger
                trigger_history.clear()
                first_trigger_time = None

            time.sleep(args.poll_interval)

        except KeyboardInterrupt:
            break
        except Exception as e:
            flush_print("[ERROR] %s" % str(e))
            time.sleep(args.poll_interval)

    # Cleanup
    flush_print("\n[INFO] Stopping monitor...")

    if capturing:
        flush_print("[INFO] Waiting for capture to complete...")
        time.sleep(max(0, capture_end_time - time.time()) + 2)

    # Summary
    flush_print("")
    flush_print("=" * 80)
    flush_print("Summary")
    flush_print("=" * 80)
    flush_print("Total captures triggered: %d" % capture_count)

    if os.path.exists(args.output_dir):
        files = [f for f in os.listdir(args.output_dir)
                 if f.startswith('latency_capture_') and f.endswith('.pcap')]
        if files:
            flush_print("Capture files:")
            for f in sorted(files):
                filepath = os.path.join(args.output_dir, f)
                size = os.path.getsize(filepath)
                flush_print("  - %s (%d bytes)" % (f, size))

    flush_print("=" * 80)
    return 0


if __name__ == '__main__':
    sys.exit(main())
