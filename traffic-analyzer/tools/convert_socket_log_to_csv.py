#!/usr/bin/env python3
"""
Convert Socket Log to CSV Format

Converts human-readable TCP socket analyzer log output to CSV format
compatible with SocketDataParser.

Usage:
    python3 convert_socket_log_to_csv.py <input_log> <output_csv>
"""

import re
import sys
import csv
from datetime import datetime
from typing import Dict, List, Optional


def parse_timestamp(line: str) -> Optional[float]:
    """Extract timestamp from header line"""
    match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
    if match:
        dt = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S.%f')
        return dt.timestamp()
    return None


def parse_connection(line: str) -> Optional[str]:
    """Extract connection string from Connection line"""
    match = re.search(r'Connection: (.+)', line)
    if match:
        # Convert "IP1:PORT1 -> IP2:PORT2" to "IP1:PORT1->IP2:PORT2"
        conn_str = match.group(1).strip()
        conn_str = conn_str.replace(' -> ', '->')
        conn_str = conn_str.replace(' ', '')
        # Remove IPv4-mapped IPv6 prefix ::ffff:
        conn_str = conn_str.replace('::ffff:', '')
        return conn_str
    return None


def parse_state(line: str) -> Optional[str]:
    """Extract state from State line"""
    match = re.search(r'State: (\w+)', line)
    if match:
        return match.group(1)
    return None


def extract_numeric_value(value_str: str) -> Optional[float]:
    """Extract numeric value from string like '10.5 Gbps' or '123 bytes'"""
    if not value_str:
        return None

    # Remove commas
    value_str = value_str.replace(',', '')

    # Handle bandwidth units (Gbps, Mbps, Kbps)
    if 'Gbps' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1)) * 1e9  # Convert to bps
    elif 'Mbps' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1)) * 1e6
    elif 'Kbps' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1)) * 1e3

    # Handle size units (KB, MB, GB, bytes)
    elif 'bytes' in value_str or 'KB' in value_str or 'MB' in value_str or 'GB' in value_str:
        # Pick the number *next to its unit* to avoid mixing "14480 bytes (14.1 KB)"
        size_match = re.search(r'([\d.]+)\s*(bytes?|KB|MB|GB)\b', value_str, re.IGNORECASE)
        if size_match:
            value = float(size_match.group(1))
            unit = size_match.group(2).lower()
            if unit.startswith('kb'):
                value *= 1024
            elif unit.startswith('mb'):
                value *= 1024 * 1024
            elif unit.startswith('gb'):
                value *= 1024 * 1024 * 1024
            return value

    # Handle time units (ms, s)
    elif 'ms' in value_str:
        match = re.search(r'([\d.]+)', value_str)
        if match:
            return float(match.group(1))

    # Handle percentages
    elif '%' in value_str:
        match = re.search(r'([\d.]+)%', value_str)
        if match:
            return float(match.group(1)) / 100.0  # Convert to ratio

    # Handle fractions like "0/590"
    elif '/' in value_str:
        match = re.search(r'(\d+)/(\d+)', value_str)
        if match:
            current = int(match.group(1))
            total = int(match.group(2))
            # Return both as separate values (we'll handle this specially)
            return (current, total)

    # Try to extract plain number
    match = re.search(r'([\d.]+)', value_str)
    if match:
        return float(match.group(1))

    return None


def parse_metric_line(line: str) -> tuple:
    """Parse metric line: '  key  : value'"""
    if ':' not in line:
        return None, None

    parts = line.split(':', 1)
    if len(parts) == 2:
        key = parts[0].strip()
        value = parts[1].strip()
        return key, value
    return None, None


def parse_timer_info(value: str) -> tuple:
    """Parse timer information from format like 'on, 200ms, retrans=5, backoff=2'"""
    timer_state = ""
    timer_expires = 0
    timer_retrans = 0
    backoff = 0

    # Extract state (on/off/keepalive)
    if value.startswith('on') or value.startswith('keepalive') or value.startswith('off'):
        parts = value.split(',')
        if len(parts) > 0:
            timer_state = parts[0].strip()
        if len(parts) > 1:
            # Parse expires time
            expires_match = re.search(r'([\d.]+)\s*ms', parts[1])
            if expires_match:
                timer_expires = float(expires_match.group(1))
        # Parse retrans and backoff if present
        for part in parts[2:]:
            retrans_match = re.search(r'retrans[=:](\d+)', part)
            if retrans_match:
                timer_retrans = int(retrans_match.group(1))
            backoff_match = re.search(r'backoff[=:](\d+)', part)
            if backoff_match:
                backoff = int(backoff_match.group(1))

    return timer_state, timer_expires, timer_retrans, backoff


def parse_wscale(value: str) -> tuple:
    """Parse window scale from format like '9,9' to (snd, rcv)"""
    try:
        parts = value.split(',')
        if len(parts) == 2:
            return int(parts[0].strip()), int(parts[1].strip())
    except (ValueError, AttributeError):
        pass
    return 0, 0


def parse_bbr_info(value: str) -> tuple:
    """Parse BBR info from format like 'bw:10000000bps, mrtt:10.5, pacing_gain:1.25, cwnd_gain:2.0'"""
    bbr_bw = 0
    bbr_mrtt = 0.0
    bbr_pacing_gain = 0.0
    bbr_cwnd_gain = 0.0

    # Parse bandwidth
    bw_match = re.search(r'bw:([\d.]+)([KMG]?)bps', value)
    if bw_match:
        bbr_bw = extract_numeric_value(bw_match.group(0))

    # Parse minimum RTT
    mrtt_match = re.search(r'mrtt:([\d.]+)', value)
    if mrtt_match:
        bbr_mrtt = float(mrtt_match.group(1))

    # Parse pacing gain
    pacing_match = re.search(r'pacing_gain:([\d.]+)', value)
    if pacing_match:
        bbr_pacing_gain = float(pacing_match.group(1))

    # Parse cwnd gain
    cwnd_match = re.search(r'cwnd_gain:([\d.]+)', value)
    if cwnd_match:
        bbr_cwnd_gain = float(cwnd_match.group(1))

    return bbr_bw, bbr_mrtt, bbr_pacing_gain, bbr_cwnd_gain


def parse_dctcp_info(value: str) -> tuple:
    """Parse DCTCP info from format like 'ce_state:1, alpha:128, ab_ecn:1000, ab_tot:10000'"""
    dctcp_ce_state = 0
    dctcp_alpha = 0
    dctcp_ab_ecn = 0
    dctcp_ab_tot = 0

    ce_match = re.search(r'ce_state:(\d+)', value)
    if ce_match:
        dctcp_ce_state = int(ce_match.group(1))

    alpha_match = re.search(r'alpha:(\d+)', value)
    if alpha_match:
        dctcp_alpha = int(alpha_match.group(1))

    ecn_match = re.search(r'ab_ecn:(\d+)', value)
    if ecn_match:
        dctcp_ab_ecn = int(ecn_match.group(1))

    tot_match = re.search(r'ab_tot:(\d+)', value)
    if tot_match:
        dctcp_ab_tot = int(tot_match.group(1))

    return dctcp_ce_state, dctcp_alpha, dctcp_ab_ecn, dctcp_ab_tot


def parse_socket_log_to_records(input_file: str) -> List[Dict]:
    """
    Parse socket log file and return list of records

    Args:
        input_file: Path to socket log file

    Returns:
        List of dictionaries, each representing one record
    """
    records = []
    current_record = {}
    in_metrics_section = False

    with open(input_file, 'r') as f:
        for line in f:
            line = line.strip()

            # Detect new record
            if line.startswith('TCP Connection Analysis'):
                # Save previous record
                if current_record and 'timestamp' in current_record:
                    records.append(current_record)

                # Start new record
                current_record = {}
                timestamp = parse_timestamp(line)
                if timestamp:
                    current_record['timestamp'] = timestamp
                in_metrics_section = False
                continue

            # Parse connection
            if line.startswith('Connection:'):
                conn = parse_connection(line)
                if conn:
                    current_record['connection'] = conn
                continue

            # Parse state
            if line.startswith('State:'):
                state = parse_state(line)
                if state:
                    current_record['state'] = state
                continue

            # Enter metrics section
            if line.startswith('Metrics:'):
                in_metrics_section = True
                continue

            # Parse metrics
            if in_metrics_section and line:
                key, value = parse_metric_line(line)
                if key:
                    # Map to expected column names
                    key_mapping = {
                        'rtt': 'rtt', 'rttvar': 'rttvar', 'minrtt': 'minrtt', 'rto': 'rto',
                        'cwnd': 'cwnd', 'ssthresh': 'ssthresh',
                        'rcv_space': 'rwnd', 'rcv_ssthresh': 'rcv_ssthresh', 'snd_wnd': 'snd_wnd',
                        'mss': 'mss', 'pmtu': 'pmtu', 'advmss': 'advmss', 'rcvmss': 'rcvmss',
                        'wscale': 'wscale',  # Combined wscale string
                        'send_rate': 'send_rate', 'pacing_rate': 'pacing_rate', 'delivery_rate': 'delivery_rate',
                        'max_pacing_rate': 'max_pacing_rate',
                        'send_q': 'send_q', 'recv_q': 'recv_q',
                        'socket_tx_queue': 'socket_tx_queue', 'socket_tx_buffer': 'socket_tx_buffer',
                        'socket_rx_queue': 'socket_rx_queue', 'socket_rx_buffer': 'socket_rx_buffer',
                        'socket_forward_alloc': 'socket_forward_alloc', 'socket_write_queue': 'socket_write_queue',
                        'socket_opt_mem': 'socket_opt_mem', 'socket_backlog': 'socket_backlog', 'socket_dropped': 'socket_dropped',
                        'unacked': 'packets_out', 'inflight_data': 'inflight_data',
                        'retrans': 'retrans', 'retrans_ratio': 'retrans_rate',
                        'lost': 'lost', 'sacked': 'sacked',
                        'dsack_dups': 'dsack_dups', 'spurious_retrans_rate': 'spurious_retrans_rate',
                        'segs_out': 'segs_out', 'segs_in': 'segs_in',
                        'data_segs_out': 'data_segs_out', 'data_segs_in': 'data_segs_in',
                        'bytes_sent': 'bytes_sent', 'bytes_acked': 'bytes_acked', 'bytes_received': 'bytes_received',
                        'bytes_retrans': 'bytes_retrans',
                        'lastsnd': 'lastsnd', 'lastrcv': 'lastrcv', 'lastack': 'lastack',
                        'app_limited': 'app_limited', 'rcv_rtt': 'rcv_rtt', 'ato': 'ato',
                        'congestion_algorithm': 'congestion_algorithm', 'ca_state': 'ca_state',
                        'reordering': 'reordering', 'rcv_ooopack': 'rcv_ooopack',
                        'reord_seen': 'reord_seen', 'notsent': 'notsent',
                        'delivered': 'delivered', 'delivered_ce': 'delivered_ce',
                        'busy_time': 'busy_time',
                        'rwnd_limited_time': 'rwnd_limited_time', 'rwnd_limited_ratio': 'rwnd_limited_ratio',
                        'sndbuf_limited_time': 'sndbuf_limited_time', 'sndbuf_limited_ratio': 'sndbuf_limited_ratio',
                        'cwnd_limited_time': 'cwnd_limited_time', 'cwnd_limited_ratio': 'cwnd_limited_ratio',
                        'tcp_features': 'tcp_features', 'bdp': 'bdp', 'recommended_window': 'recommended_window',
                        # Socket identity fields
                        'uid': 'uid', 'ino': 'ino', 'sk_cookie': 'sk_cookie', 'bpf_id': 'bpf_id',
                        'cgroup_path': 'cgroup_path', 'tos': 'tos', 'tclass': 'tclass', 'priority': 'priority',
                        # TCP options
                        'tcp_ecn': 'tcp_ecn', 'tcp_ecnseen': 'tcp_ecnseen', 'tcp_fastopen': 'tcp_fastopen',
                        # Timer fields (will be parsed separately)
                        'timer_state': 'timer_state', 'timer_expires_ms': 'timer_expires_ms',
                        'timer_retrans': 'timer_retrans', 'backoff': 'backoff',
                        # BBR fields (will be parsed separately)
                        'bbr_bw': 'bbr_bw', 'bbr_mrtt': 'bbr_mrtt',
                        'bbr_pacing_gain': 'bbr_pacing_gain', 'bbr_cwnd_gain': 'bbr_cwnd_gain',
                        # DCTCP fields (will be parsed separately)
                        'dctcp_ce_state': 'dctcp_ce_state', 'dctcp_alpha': 'dctcp_alpha',
                        'dctcp_ab_ecn': 'dctcp_ab_ecn', 'dctcp_ab_tot': 'dctcp_ab_tot',
                        # MPTCP fields
                        'mptcp_flags': 'mptcp_flags', 'mptcp_token': 'mptcp_token',
                        'mptcp_seq': 'mptcp_seq', 'mptcp_maplen': 'mptcp_maplen'
                    }

                    mapped_key = key_mapping.get(key)
                    if mapped_key:
                        # Handle special parsing cases
                        if key == 'wscale':
                            # Parse wscale and split into snd/rcv
                            wscale_snd, wscale_rcv = parse_wscale(value)
                            current_record['wscale'] = value.strip()
                            current_record['wscale_snd'] = wscale_snd
                            current_record['wscale_rcv'] = wscale_rcv
                        elif 'timer' in value.lower() and ('on' in value or 'off' in value or 'keepalive' in value):
                            # Parse timer info
                            timer_state, timer_expires, timer_retrans, backoff = parse_timer_info(value)
                            current_record['timer_state'] = timer_state
                            current_record['timer_expires_ms'] = timer_expires
                            current_record['timer_retrans'] = timer_retrans
                            current_record['backoff'] = backoff
                        elif 'bw:' in value and 'mrtt:' in value:
                            # Parse BBR info
                            bbr_bw, bbr_mrtt, bbr_pacing_gain, bbr_cwnd_gain = parse_bbr_info(value)
                            current_record['bbr_bw'] = bbr_bw
                            current_record['bbr_mrtt'] = bbr_mrtt
                            current_record['bbr_pacing_gain'] = bbr_pacing_gain
                            current_record['bbr_cwnd_gain'] = bbr_cwnd_gain
                        elif 'ce_state:' in value and 'alpha:' in value:
                            # Parse DCTCP info
                            dctcp_ce_state, dctcp_alpha, dctcp_ab_ecn, dctcp_ab_tot = parse_dctcp_info(value)
                            current_record['dctcp_ce_state'] = dctcp_ce_state
                            current_record['dctcp_alpha'] = dctcp_alpha
                            current_record['dctcp_ab_ecn'] = dctcp_ab_ecn
                            current_record['dctcp_ab_tot'] = dctcp_ab_tot
                        # Handle string values
                        elif key in ['congestion_algorithm', 'ca_state', 'app_limited', 'tcp_features',
                                    'cgroup_path', 'mptcp_flags', 'timer_state']:
                            current_record[mapped_key] = value.strip()
                        # Handle boolean flags (YES/NO)
                        elif key in ['tcp_ecn', 'tcp_ecnseen', 'tcp_fastopen']:
                            current_record[mapped_key] = 1 if value.strip().upper() in ['YES', 'TRUE', '1'] else 0
                        else:
                            numeric_value = extract_numeric_value(value)
                            if isinstance(numeric_value, tuple):
                                # Handle retrans format "current/total"
                                current_record['retrans'] = numeric_value[0]
                                current_record['retrans_total'] = numeric_value[1]
                            elif numeric_value is not None:
                                current_record[mapped_key] = numeric_value

    # Save last record
    if current_record and 'timestamp' in current_record:
        records.append(current_record)

    return records


def convert_log_to_csv(input_file: str, output_file: str, add_statistics: bool = True) -> Optional[object]:
    """
    Convert socket log to CSV format

    Args:
        input_file: Path to socket log file
        output_file: Path to output CSV file
        add_statistics: Whether to append statistics to CSV (default: True)

    Returns:
        Statistics DataFrame if add_statistics=True, otherwise None
    """

    records = parse_socket_log_to_records(input_file)

    if not records:
        print(f"No records found in {input_file}")
        return None

    # Define CSV columns - comprehensive list of all TCP socket metrics (120+ fields)
    columns = [
        # Basic identification
        'timestamp', 'connection', 'state',
        # RTT and timeout metrics
        'rtt', 'rttvar', 'minrtt', 'rto',
        # Window metrics
        'cwnd', 'ssthresh', 'rwnd', 'rcv_ssthresh', 'snd_wnd',
        # MSS and MTU
        'mss', 'pmtu', 'advmss', 'rcvmss',
        # Window scaling
        'wscale', 'wscale_snd', 'wscale_rcv',
        # Rate metrics
        'send_rate', 'pacing_rate', 'delivery_rate', 'max_pacing_rate',
        # Queue sizes
        'send_q', 'recv_q',
        # Socket memory
        'socket_tx_queue', 'socket_tx_buffer',
        'socket_rx_queue', 'socket_rx_buffer',
        'socket_forward_alloc', 'socket_write_queue',
        'socket_opt_mem', 'socket_backlog', 'socket_dropped',
        # Packet metrics
        'packets_out', 'inflight_data',
        # Retransmission metrics
        'retrans', 'retrans_rate', 'retrans_total',
        'lost', 'sacked', 'dsack_dups', 'spurious_retrans_rate',
        # Segment counters
        'segs_out', 'segs_in',
        'data_segs_out', 'data_segs_in',
        # Byte counters
        'bytes_sent', 'bytes_acked', 'bytes_received', 'bytes_retrans',
        # Delivery metrics
        'delivered', 'delivered_ce',
        # Reordering metrics
        'reordering', 'rcv_ooopack', 'reord_seen',
        # Not sent bytes
        'notsent',
        # Timing metrics
        'lastsnd', 'lastrcv', 'lastack',
        # Application and receiver metrics
        'app_limited', 'rcv_rtt', 'ato',
        # Congestion control
        'congestion_algorithm', 'ca_state',
        # Limitation statistics
        'busy_time',
        'rwnd_limited_time', 'rwnd_limited_ratio',
        'sndbuf_limited_time', 'sndbuf_limited_ratio',
        'cwnd_limited_time', 'cwnd_limited_ratio',
        # TCP features
        'tcp_features',
        # TCP options
        'tcp_ecn', 'tcp_ecnseen', 'tcp_fastopen',
        # BDP calculation
        'bdp', 'recommended_window',
        # Timer information
        'timer_state', 'timer_expires_ms', 'timer_retrans', 'backoff',
        # Socket identity
        'uid', 'ino', 'sk_cookie', 'bpf_id',
        'cgroup_path', 'tos', 'tclass', 'priority',
        # BBR specific metrics
        'bbr_bw', 'bbr_mrtt', 'bbr_pacing_gain', 'bbr_cwnd_gain',
        # DCTCP specific metrics
        'dctcp_ce_state', 'dctcp_alpha', 'dctcp_ab_ecn', 'dctcp_ab_tot',
        # MPTCP specific metrics
        'mptcp_flags', 'mptcp_token', 'mptcp_seq', 'mptcp_maplen'
    ]

    # Write CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()

        for record in records:
            # Fill missing columns with defaults
            row = {}
            string_cols = [
                'connection', 'state', 'congestion_algorithm', 'ca_state',
                'app_limited', 'tcp_features', 'wscale',
                'timer_state', 'cgroup_path', 'mptcp_flags'
            ]
            for col in columns:
                if col in record:
                    row[col] = record[col]
                elif col in string_cols:
                    row[col] = record.get(col, '')
                else:
                    row[col] = 0.0
            writer.writerow(row)

    print(f"Converted {len(records)} records from {input_file} to {output_file}")

    # Add statistics if requested
    if add_statistics:
        try:
            import os
            import sys
            # Add parent directory to path for imports
            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)

            from tcpsocket_analyzer.analyzer.csv_statistics import append_statistics_to_csv
            stats_df = append_statistics_to_csv(output_file)
            print(f"Statistics appended to {output_file}")
            return stats_df
        except Exception as e:
            print(f"Warning: Failed to append statistics: {e}")
            return None

    return None


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 convert_socket_log_to_csv.py <input_log> <output_csv>")
        print("\nExample:")
        print("  python3 convert_socket_log_to_csv.py client-socket.log client-socket.csv")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        convert_log_to_csv(input_file, output_file)
        print("\nConversion successful!")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
