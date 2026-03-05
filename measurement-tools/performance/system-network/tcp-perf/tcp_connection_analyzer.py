#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TCP Connection Analyzer

Collects and analyzes TCP connection details for performance troubleshooting.
Supports both client and server side analysis with bottleneck detection.

Features:
- Collect detailed TCP connection metrics using ss/netstat
- Calculate bandwidth-delay product (BDP) and recommended buffer sizes
- Detect performance bottlenecks (rwnd_limited, cwnd_limited, etc.)
- Provide actionable recommendations
- Support both single connection and continuous monitoring

Usage:
    # Analyze client-side connection to iperf3 server
    sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client

    # Analyze server-side connections on port 5201
    sudo python3 tcp_connection_analyzer.py --local-port 5201 --role server

    # Filter by specific local IP (multi-homed hosts)
    sudo python3 tcp_connection_analyzer.py --local-ip 70.0.0.31 --local-port 2181 --role server

    # Filter both local and remote endpoints
    sudo python3 tcp_connection_analyzer.py --local-ip 70.0.0.31 --remote-ip 70.0.0.32 --local-port 2181 --role server

    # Continuous monitoring
    sudo python3 tcp_connection_analyzer.py --remote-ip 1.1.1.5 --remote-port 5201 --role client --interval 2
"""

import subprocess
import re
import sys
import argparse
import time
import json
from datetime import datetime
from collections import defaultdict


class TCPConnectionInfo:
    """Store TCP connection information"""

    def __init__(self):
        # Connection tuple
        self.local_addr = ""
        self.local_port = 0
        self.remote_addr = ""
        self.remote_port = 0
        self.state = ""

        # Queue status
        self.recv_q = 0
        self.send_q = 0

        # Timer information
        self.timer_state = ""
        self.timer_expires_ms = 0
        self.timer_retrans = 0
        self.backoff = 0

        # RTT metrics
        self.rtt = 0.0
        self.rttvar = 0.0
        self.rto = 0

        # Congestion control
        self.cwnd = 0
        self.ssthresh = 0
        self.ca_state = ""
        self.congestion_algorithm = ""  # cubic/reno/bbr/vegas

        # Window sizes
        self.rcv_space = 0
        self.rcv_ssthresh = 0
        self.snd_wnd = 0
        self.advmss = 0
        self.rcvmss = 0
        self.wscale_snd = 0
        self.wscale_rcv = 0

        # Rate metrics
        self.send_rate = 0
        self.pacing_rate = 0
        self.max_pacing_rate = 0
        self.delivery_rate = 0

        # Retransmission
        self.retrans = 0
        self.retrans_total = 0
        self.lost = 0
        self.unacked = 0  # Unacknowledged segments in flight
        self.sacked = 0  # SACKed segments
        self.dsack_dups = 0  # D-SACK duplicate reports
        self.fackets = 0  # Forward acknowledgment
        self.reord_seen = 0
        self.notsent = 0
        self.delivered = 0
        self.delivered_ce = 0

        # Time limited statistics
        self.busy_time = 0
        self.rwnd_limited_time = 0
        self.rwnd_limited_ratio = 0.0
        self.sndbuf_limited_time = 0
        self.sndbuf_limited_ratio = 0.0
        self.cwnd_limited_time = 0
        self.cwnd_limited_ratio = 0.0

        # Bytes statistics
        self.bytes_sent = 0
        self.bytes_acked = 0
        self.bytes_received = 0
        self.bytes_retrans = 0

        # Other metrics
        self.mss = 0
        self.pmtu = 0
        self.wscale = ""
        self.minrtt = 0.0
        self.reordering = 0
        self.ato = 0  # ACK timeout

        # Segment counters
        self.segs_out = 0
        self.segs_in = 0
        self.data_segs_out = 0
        self.data_segs_in = 0

        # Timing metrics (milliseconds since last activity)
        self.lastsnd = 0
        self.lastrcv = 0
        self.lastack = 0

        # Application and receiver metrics
        self.app_limited = False
        self.rcv_rtt = 0.0
        self.rcv_ooopack = 0  # Out-of-order packets received

        # Socket memory (skmem)
        self.skmem_r = 0  # RX queue
        self.skmem_rb = 0  # RX buffer size
        self.skmem_t = 0  # TX queue
        self.skmem_tb = 0  # TX buffer size
        self.skmem_f = 0  # Forward alloc
        self.skmem_w = 0  # Write buffer
        self.skmem_o = 0  # Option memory
        self.skmem_bl = 0  # Backlog
        self.skmem_d = 0  # Dropped packets (CRITICAL!)

        # TCP options/features
        self.tcp_ts = False  # TCP timestamps enabled
        self.tcp_sack = False  # SACK enabled
        self.tcp_ecn = False
        self.tcp_ecnseen = False
        self.tcp_fastopen = False

        # Process and socket identity information
        self.process_name = ""
        self.process_pid = 0
        self.process_fd = 0
        self.uid = 0
        self.ino = 0
        self.sk_cookie = 0
        self.bpf_id = 0
        self.cgroup_path = ""
        self.tos = 0
        self.tclass = 0
        self.priority = 0

        # BBR congestion control specific
        self.bbr_bw = 0
        self.bbr_mrtt = 0.0
        self.bbr_pacing_gain = 0.0
        self.bbr_cwnd_gain = 0.0

        # DCTCP congestion control specific
        self.dctcp_ce_state = 0
        self.dctcp_alpha = 0
        self.dctcp_ab_ecn = 0
        self.dctcp_ab_tot = 0

        # MPTCP specific
        self.mptcp_flags = ""
        self.mptcp_token = 0
        self.mptcp_seq = 0
        self.mptcp_maplen = 0

        # Timestamp
        self.timestamp = datetime.now()


class TCPConnectionAnalyzer:
    """Analyze TCP connection performance"""

    def __init__(self, args):
        self.args = args
        self.system_config = {}
        self.system_stats = {}
        self.prev_system_stats = {}  # Store previous stats for delta calculation
        self._load_system_config()
        # Don't load stats in __init__, load on-demand in run() for freshness

    def _find_ss_command(self):
        """Find ss command path"""
        # Try common paths
        possible_paths = [
            '/usr/sbin/ss',
            '/sbin/ss',
            '/usr/bin/ss',
            '/bin/ss',
            'ss'  # Try PATH
        ]

        for path in possible_paths:
            try:
                result = subprocess.run(
                    [path, '-V'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=2
                )
                if result.returncode == 0:
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return None

    def _load_system_config(self):
        """Load system TCP configuration"""
        configs = [
            'net.core.rmem_max',
            'net.core.wmem_max',
            'net.ipv4.tcp_rmem',
            'net.ipv4.tcp_wmem',
            'net.ipv4.tcp_moderate_rcvbuf',
            'net.ipv4.tcp_window_scaling',
            'net.ipv4.tcp_congestion_control',
            'net.ipv4.tcp_mem'
        ]

        for config in configs:
            try:
                result = subprocess.run(
                    ['sysctl', '-n', config],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.system_config[config] = result.stdout.strip()
            except Exception:
                pass

    def _load_system_stats(self):
        """Load system-wide TCP statistics from netstat -s"""
        try:
            result = subprocess.run(
                ['netstat', '-s'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )
            if result.returncode == 0:
                self._parse_netstat_stats(result.stdout)
        except Exception as e:
            # netstat not available, skip
            pass

    def _calculate_stats_delta(self):
        """Calculate delta between current and previous stats"""
        delta_stats = {}

        if not self.prev_system_stats:
            # First run, no previous data, return current as delta
            return dict(self.system_stats)

        # Calculate delta for each metric
        for key, current_value in self.system_stats.items():
            prev_value = self.prev_system_stats.get(key, 0)
            delta_stats[key] = current_value - prev_value

        return delta_stats

    def _save_current_stats_as_previous(self):
        """Save current stats as previous for next delta calculation"""
        self.prev_system_stats = dict(self.system_stats)

    def _parse_netstat_stats(self, output):
        """Parse netstat -s output for TCP statistics"""
        lines = output.split('\n')
        in_tcp_section = False

        # Key statistics to extract
        stats_patterns = {
            # === Retransmission Type Breakdown ===
            'segments_retransmitted': r'(\d+) segments retransmit',
            'fast_retransmits': r'(\d+) fast retransmits',
            'retrans_in_slowstart': r'(\d+) retransmits in slow start',
            'tcp_loss_probes': r'TCPLossProbes:\s*(\d+)',
            'tcp_loss_probe_recovery': r'TCPLossProbeRecovery:\s*(\d+)',
            'tcp_lost_retransmit': r'TCPLostRetransmit:\s*(\d+)',
            'tcp_spurious_rtos': r'TCPSpuriousRTOs:\s*(\d+)',
            'tcp_syn_retrans': r'TCPSynRetrans:\s*(\d+)',

            # === Timeout Types ===
            'timeout_after_sack': r'(\d+) timeouts after SACK recovery',
            'timeout_in_loss': r'(\d+) timeouts in loss state',
            'other_tcp_timeouts': r'(\d+) other TCP timeouts',

            # === Stack Packet Drops ===
            'rcv_pruned': r'(\d+) packets pruned from receive queue because of socket buffer overrun',
            'rcv_collapsed': r'(\d+) packets collapsed in receive queue due to low socket buffer',
            'tcp_backlog_drop': r'TCPBacklogDrop:\s*(\d+)',
            'listen_overflows': r'(\d+) times the listen queue of a socket overflowed',
            'listen_drops': r'(\d+) SYNs to LISTEN sockets dropped',
            'sack_retrans_fail': r'(\d+) SACK retransmits failed',

            # === SACK & Reordering ===
            'sack_recovery': r'(\d+) times recovered from packet loss by selective acknowledgements',
            'sack_reordering': r'Detected reordering (\d+) times using SACK',
            'reordering_ts': r'Detected reordering (\d+) times using time stamp',

            # === Congestion Window Recovery ===
            'tcp_full_undo': r'(\d+) congestion windows fully recovered without slow start',
            'tcp_partial_undo': r'(\d+) congestion windows partially recovered using Hoe heuristic',
            'tcp_dsack_undo': r'(\d+) congestion windows recovered without slow start by DSACK',

            # === Connection Issues ===
            'failed_connection_attempts': r'(\d+) failed connection attempts',
            'connection_resets_received': r'(\d+) connection resets received',
            'connection_resets_sent': r'(\d+) resets sent',
            'reset_due_to_unexpected_data': r'(\d+) connections reset due to unexpected data',
            'reset_due_to_early_close': r'(\d+) connections reset due to early user close',
            'abort_on_timeout': r'(\d+) connections aborted due to timeout',

            # === Basic Counters ===
            'segments_sent': r'(\d+) segments s[e]?nd out',
            'segments_received': r'(\d+) segments received',
            'bad_segments': r'(\d+) bad segments received',
            'delayed_acks_sent': r'(\d+) delayed acks sent',
        }

        for line in lines:
            line_stripped = line.strip()

            # Detect TCP or TcpExt section
            if 'Tcp:' in line_stripped or 'TCP:' in line_stripped or 'TcpExt:' in line_stripped:
                in_tcp_section = True
                continue
            elif line_stripped and len(line_stripped) > 0 and line_stripped[0].isupper() and ':' in line_stripped and 'TCP' not in line_stripped:
                # New section started (e.g., "Udp:", "Ip:")
                # But don't exit if it's a TCP* counter like "TCPLossProbes:"
                in_tcp_section = False
                continue

            if in_tcp_section:
                # Try to match patterns
                for key, pattern in stats_patterns.items():
                    match = re.search(pattern, line_stripped, re.IGNORECASE)
                    if match:
                        self.system_stats[key] = int(match.group(1))
                        break

    def collect_connection_info(self):
        """Collect TCP connection information using ss"""
        connections = []

        # Determine ss command path
        ss_cmd = self._find_ss_command()
        if not ss_cmd:
            print("Error: ss command not found. Please install iproute/iproute2 package.")
            return connections

        # Build ss filter expression (in parentheses for older ss versions)
        # Build filter conditions list
        conditions = []

        if self.args.local_ip:
            conditions.append(f"src {self.args.local_ip}")
        if self.args.local_port:
            conditions.append(f"sport = :{self.args.local_port}")
        if self.args.remote_ip:
            conditions.append(f"dst {self.args.remote_ip}")
        if self.args.remote_port:
            conditions.append(f"dport = :{self.args.remote_port}")

        # Role-based validation and defaults
        if self.args.role == 'client':
            # Client role: typically filter by destination
            if not self.args.remote_port and not self.args.remote_ip:
                print("Error: client role requires at least --remote-port or --remote-ip")
                return connections
        else:  # server
            # Server role: typically filter by source port (local listening port)
            if not self.args.local_port and not self.args.local_ip:
                print("Error: server role requires at least --local-port or --local-ip")
                return connections

        # Combine conditions
        if not conditions:
            print("Error: no filter conditions specified")
            return connections

        filter_expr = "( " + " and ".join(conditions) + " )"

        # Build complete ss command
        # Format: ss -tinopm [state STATE] 'filter_expression'
        if self.args.all:
            cmd = [ss_cmd, '-tinopm', filter_expr]
        else:
            cmd = [ss_cmd, '-tinopm', 'state', 'established', filter_expr]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=10
            )

            if result.returncode != 0:
                print(f"Error executing ss: {result.stderr}")
                return connections

            # Parse ss output
            connections = self._parse_ss_output(result.stdout)

        except subprocess.TimeoutExpired:
            print("Error: ss command timeout")
        except Exception as e:
            print(f"Error executing ss: {e}")

        return connections

    def _parse_ss_output(self, output):
        """Parse ss command output"""
        connections = []
        lines = output.strip().split('\n')

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Skip header and empty lines
            if not line or line.startswith('State') or line.startswith('Netid') or line.startswith('Recv-Q'):
                i += 1
                continue

            # Parse connection line
            conn = TCPConnectionInfo()

            # First line: Recv-Q Send-Q Local Remote (or State Recv-Q Send-Q Local Remote)
            parts = line.split()
            if len(parts) < 4:
                i += 1
                continue

            # Try to parse based on whether first column is numeric (Recv-Q) or text (State)
            try:
                # Old format: Recv-Q Send-Q Local Remote
                conn.recv_q = int(parts[0])
                conn.send_q = int(parts[1])
                conn.state = "ESTAB"  # Default state
                local_idx = 2
                remote_idx = 3
            except ValueError:
                # Newer format: State Recv-Q Send-Q Local Remote
                if len(parts) < 5:
                    i += 1
                    continue
                conn.state = parts[0]
                try:
                    conn.recv_q = int(parts[1])
                    conn.send_q = int(parts[2])
                except ValueError:
                    # Skip malformed lines
                    i += 1
                    continue
                local_idx = 3
                remote_idx = 4

            if len(parts) > remote_idx:
                # Parse local address
                local_parts = parts[local_idx].rsplit(':', 1)
                if len(local_parts) == 2:
                    conn.local_addr = local_parts[0].strip('[]')
                    try:
                        conn.local_port = int(local_parts[1])
                    except ValueError:
                        pass

                # Parse remote address
                remote_parts = parts[remote_idx].rsplit(':', 1)
                if len(remote_parts) == 2:
                    conn.remote_addr = remote_parts[0].strip('[]')
                    try:
                        conn.remote_port = int(remote_parts[1])
                    except ValueError:
                        pass

            # Parse subsequent lines with metrics
            i += 1
            while i < len(lines) and not lines[i].strip().split()[0].isupper():
                metric_line = lines[i].strip()
                self._parse_metrics(conn, metric_line)
                i += 1

            connections.append(conn)

        return connections

    def _parse_metrics(self, conn, line):
        """Parse metrics from ss output line"""

        # Timer: timer:(on,200ms,0)
        match = re.search(r'timer:\((\w+),([\d.]+)ms,(\d+)\)', line)
        if match:
            conn.timer_state = match.group(1)
            conn.timer_expires_ms = int(float(match.group(2)))
            conn.timer_retrans = int(match.group(3))

        # Backoff: backoff:5
        match = re.search(r'backoff:(\d+)', line)
        if match:
            conn.backoff = int(match.group(1))

        # RTT: rtt:0.078/0.036
        match = re.search(r'rtt:([\d.]+)/([\d.]+)', line)
        if match:
            conn.rtt = float(match.group(1))
            conn.rttvar = float(match.group(2))

        # RTO: rto:201
        match = re.search(r'rto:(\d+)', line)
        if match:
            conn.rto = int(match.group(1))

        # CWND: cwnd:10
        match = re.search(r'cwnd:(\d+)', line)
        if match:
            conn.cwnd = int(match.group(1))

        # SSTHRESH: ssthresh:285
        match = re.search(r'ssthresh:(\d+)', line)
        if match:
            conn.ssthresh = int(match.group(1))

        # MSS: mss:1448
        match = re.search(r'mss:(\d+)', line)
        if match:
            conn.mss = int(match.group(1))

        # PMTU: pmtu:1500
        match = re.search(r'pmtu:(\d+)', line)
        if match:
            conn.pmtu = int(match.group(1))

        # Window scale: wscale:9,9
        match = re.search(r'wscale:([\d,]+)', line)
        if match:
            conn.wscale = match.group(1)
            parts = match.group(1).split(',')
            if len(parts) == 2:
                try:
                    conn.wscale_snd = int(parts[0])
                    conn.wscale_rcv = int(parts[1])
                except ValueError:
                    pass

        # Send rate: send 148512820bps
        match = re.search(r'send ([\d.]+)([KMG]?)bps', line)
        if match:
            conn.send_rate = self._parse_rate(match.group(1), match.group(2))

        # Pacing rate: pacing_rate 257809520bps
        match = re.search(r'pacing_rate ([\d.]+)([KMG]?)bps', line)
        if match:
            conn.pacing_rate = self._parse_rate(match.group(1), match.group(2))

        # Max pacing rate: max_pacing_rate 300000000bps
        match = re.search(r'max_pacing_rate ([\d.]+)([KMG]?)bps', line)
        if match:
            conn.max_pacing_rate = self._parse_rate(match.group(1), match.group(2))

        # Delivery rate: delivery_rate 3200000000bps
        match = re.search(r'delivery_rate ([\d.]+)([KMG]?)bps', line)
        if match:
            conn.delivery_rate = self._parse_rate(match.group(1), match.group(2))

        # Retransmissions: retrans:0/1195
        match = re.search(r'retrans:(\d+)/(\d+)', line)
        if match:
            conn.retrans = int(match.group(1))
            conn.retrans_total = int(match.group(2))

        # Lost packets: lost:5
        match = re.search(r'lost:(\d+)', line)
        if match:
            conn.lost = int(match.group(1))

        # Unacknowledged segments: unacked:675
        match = re.search(r'unacked:(\d+)', line)
        if match:
            conn.unacked = int(match.group(1))

        # SACKed segments: sacked:10
        match = re.search(r'sacked:(\d+)', line)
        if match:
            conn.sacked = int(match.group(1))

        # D-SACK duplicates: dsack_dups:9
        match = re.search(r'dsack_dups:(\d+)', line)
        if match:
            conn.dsack_dups = int(match.group(1))

        # Forward ACK: fackets:5
        match = re.search(r'fackets:(\d+)', line)
        if match:
            conn.fackets = int(match.group(1))

        # Reordering seen: reord_seen:10
        match = re.search(r'reord_seen:(\d+)', line)
        if match:
            conn.reord_seen = int(match.group(1))

        # Not sent bytes: notsent:1024
        match = re.search(r'notsent:(\d+)', line)
        if match:
            conn.notsent = int(match.group(1))

        # Delivered packets: delivered:100
        match = re.search(r'delivered:(\d+)', line)
        if match:
            conn.delivered = int(match.group(1))

        # Delivered CE packets: delivered_ce:5
        match = re.search(r'delivered_ce:(\d+)', line)
        if match:
            conn.delivered_ce = int(match.group(1))

        # Receive space: rcv_space:14480
        match = re.search(r'rcv_space:(\d+)', line)
        if match:
            conn.rcv_space = int(match.group(1))

        # Receive ssthresh: rcv_ssthresh:65535
        match = re.search(r'rcv_ssthresh:(\d+)', line)
        if match:
            conn.rcv_ssthresh = int(match.group(1))

        # Min RTT: minrtt:0.042
        match = re.search(r'minrtt:([\d.]+)', line)
        if match:
            conn.minrtt = float(match.group(1))

        # Busy time: busy:60000ms
        match = re.search(r'busy:(\d+)ms', line)
        if match:
            conn.busy_time = int(match.group(1))

        # rwnd_limited: rwnd_limited:157971ms(95.6%)
        match = re.search(r'rwnd_limited:(\d+)ms\(([\d.]+)%\)', line)
        if match:
            conn.rwnd_limited_time = int(match.group(1))
            conn.rwnd_limited_ratio = float(match.group(2))

        # sndbuf_limited: sndbuf_limited:1000ms(5.0%)
        match = re.search(r'sndbuf_limited:(\d+)ms\(([\d.]+)%\)', line)
        if match:
            conn.sndbuf_limited_time = int(match.group(1))
            conn.sndbuf_limited_ratio = float(match.group(2))

        # cwnd_limited: cwnd_limited:500ms(2.5%)
        match = re.search(r'cwnd_limited:(\d+)ms\(([\d.]+)%\)', line)
        if match:
            conn.cwnd_limited_time = int(match.group(1))
            conn.cwnd_limited_ratio = float(match.group(2))

        # Bytes sent: bytes_sent:189
        match = re.search(r'bytes_sent:(\d+)', line)
        if match:
            conn.bytes_sent = int(match.group(1))

        # Bytes acked: bytes_acked:190
        match = re.search(r'bytes_acked:(\d+)', line)
        if match:
            conn.bytes_acked = int(match.group(1))

        # Bytes received: bytes_received:4
        match = re.search(r'bytes_received:(\d+)', line)
        if match:
            conn.bytes_received = int(match.group(1))

        # Bytes retransmitted: bytes_retrans:1024
        match = re.search(r'bytes_retrans:(\d+)', line)
        if match:
            conn.bytes_retrans = int(match.group(1))

        # Reordering: reordering:56
        match = re.search(r'reordering:(\d+)', line)
        if match:
            conn.reordering = int(match.group(1))

        # ACK timeout: ato:40
        match = re.search(r'ato:(\d+)', line)
        if match:
            conn.ato = int(match.group(1))

        # Segment counters: segs_out:10 segs_in:9
        match = re.search(r'segs_out:(\d+)', line)
        if match:
            conn.segs_out = int(match.group(1))

        match = re.search(r'segs_in:(\d+)', line)
        if match:
            conn.segs_in = int(match.group(1))

        # Data segment counters: data_segs_out:1 data_segs_in:1
        match = re.search(r'data_segs_out:(\d+)', line)
        if match:
            conn.data_segs_out = int(match.group(1))

        match = re.search(r'data_segs_in:(\d+)', line)
        if match:
            conn.data_segs_in = int(match.group(1))

        # Timing metrics: lastsnd:100 lastrcv:100 lastack:100
        match = re.search(r'lastsnd:(\d+)', line)
        if match:
            conn.lastsnd = int(match.group(1))

        match = re.search(r'lastrcv:(\d+)', line)
        if match:
            conn.lastrcv = int(match.group(1))

        match = re.search(r'lastack:(\d+)', line)
        if match:
            conn.lastack = int(match.group(1))

        # Application limited flag: app_limited
        if 'app_limited' in line:
            conn.app_limited = True

        # Receiver RTT: rcv_rtt:1000 or rcv_rtt:1000.5
        match = re.search(r'rcv_rtt:([\d.]+)', line)
        if match:
            conn.rcv_rtt = float(match.group(1))

        # Advertised MSS: advmss:1448
        match = re.search(r'advmss:(\d+)', line)
        if match:
            conn.advmss = int(match.group(1))

        # Received MSS: rcvmss:536
        match = re.search(r'rcvmss:(\d+)', line)
        if match:
            conn.rcvmss = int(match.group(1))

        # Congestion control algorithm: cubic, reno, bbr, vegas, etc.
        # Appears as: "ts sack cubic wscale:9,9" or just "cubic"
        ca_match = re.search(r'\b(cubic|reno|bbr|vegas|westwood|hybla|htcp|veno|yeah|illinois|dctcp)\b', line, re.IGNORECASE)
        if ca_match:
            conn.congestion_algorithm = ca_match.group(1).lower()

        # TCP options/features
        line_words = line.split()
        if 'ts' in line_words:
            conn.tcp_ts = True
        if 'sack' in line_words:
            conn.tcp_sack = True
        if 'ecn' in line_words:
            conn.tcp_ecn = True
        if 'ecnseen' in line_words:
            conn.tcp_ecnseen = True
        if 'fastopen' in line_words:
            conn.tcp_fastopen = True

        # Socket memory: skmem:(r0,rb87380,t0,tb87040,f0,w0,o0,bl0,d0)
        match = re.search(r'skmem:\(r(\d+),rb(\d+),t(\d+),tb(\d+),f(\d+),w(\d+),o(\d+),bl(\d+),d(\d+)\)', line)
        if match:
            conn.skmem_r = int(match.group(1))
            conn.skmem_rb = int(match.group(2))
            conn.skmem_t = int(match.group(3))
            conn.skmem_tb = int(match.group(4))
            conn.skmem_f = int(match.group(5))
            conn.skmem_w = int(match.group(6))
            conn.skmem_o = int(match.group(7))
            conn.skmem_bl = int(match.group(8))
            conn.skmem_d = int(match.group(9))

        # Process information: users:(("iperf3",pid=12345,fd=3))
        match = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)\)\)', line)
        if match:
            conn.process_name = match.group(1)
            conn.process_pid = int(match.group(2))
            conn.process_fd = int(match.group(3))

        # UID: uid:1000
        match = re.search(r'uid:(\d+)', line)
        if match:
            conn.uid = int(match.group(1))

        # Inode: ino:12345
        match = re.search(r'ino:(\d+)', line)
        if match:
            conn.ino = int(match.group(1))

        # Socket cookie: sk:abc123
        match = re.search(r'sk:([0-9a-fA-F]+)', line)
        if match:
            conn.sk_cookie = int(match.group(1), 16)

        # BPF program ID: bpf:15
        match = re.search(r'bpf:(\d+)', line)
        if match:
            conn.bpf_id = int(match.group(1))

        # Cgroup path: cgroup:/system.slice/docker-abc123.scope
        match = re.search(r'cgroup:([^\s]+)', line)
        if match:
            conn.cgroup_path = match.group(1)

        # TOS: tos:0x10
        match = re.search(r'tos:(0x[0-9a-fA-F]+|\d+)', line)
        if match:
            tos_str = match.group(1)
            conn.tos = int(tos_str, 16) if tos_str.startswith('0x') else int(tos_str)

        # Traffic class: tclass:0x20
        match = re.search(r'tclass:(0x[0-9a-fA-F]+|\d+)', line)
        if match:
            tclass_str = match.group(1)
            conn.tclass = int(tclass_str, 16) if tclass_str.startswith('0x') else int(tclass_str)

        # Priority: priority:6
        match = re.search(r'priority:(\d+)', line)
        if match:
            conn.priority = int(match.group(1))

        # BBR specific: bbr:(bw:10000000bps,mrtt:10.5,pacing_gain:1.25,cwnd_gain:2.0)
        match = re.search(r'bbr:\(bw:([\d.]+)([KMG]?)bps,mrtt:([\d.]+),pacing_gain:([\d.]+),cwnd_gain:([\d.]+)\)', line)
        if match:
            conn.bbr_bw = self._parse_rate(match.group(1), match.group(2))
            conn.bbr_mrtt = float(match.group(3))
            conn.bbr_pacing_gain = float(match.group(4))
            conn.bbr_cwnd_gain = float(match.group(5))

        # DCTCP specific: dctcp:(ce_state:1,alpha:128,ab_ecn:1000,ab_tot:10000)
        match = re.search(r'dctcp:\(ce_state:(\d+),alpha:(\d+),ab_ecn:(\d+),ab_tot:(\d+)\)', line)
        if match:
            conn.dctcp_ce_state = int(match.group(1))
            conn.dctcp_alpha = int(match.group(2))
            conn.dctcp_ab_ecn = int(match.group(3))
            conn.dctcp_ab_tot = int(match.group(4))

        # MPTCP specific: mptcp:<flags> token:abc123 seq:12345 maplen:100
        match = re.search(r'mptcp:([^\s]+)', line)
        if match:
            conn.mptcp_flags = match.group(1)

        match = re.search(r'token:([0-9a-fA-F]+)', line)
        if match:
            conn.mptcp_token = int(match.group(1), 16)

        match = re.search(r'seq:(\d+)', line)
        if match:
            conn.mptcp_seq = int(match.group(1))

        match = re.search(r'maplen:(\d+)', line)
        if match:
            conn.mptcp_maplen = int(match.group(1))

        # CA state: ca_state:Open
        match = re.search(r'ca_state:(\w+)', line)
        if match:
            conn.ca_state = match.group(1)

        # Out-of-order packets: rcv_ooopack:715154
        match = re.search(r'rcv_ooopack:(\d+)', line)
        if match:
            conn.rcv_ooopack = int(match.group(1))

    def _parse_rate(self, value, unit):
        """Parse rate value with unit (K/M/G)"""
        value = float(value)
        if unit == 'K':
            return int(value * 1000)
        elif unit == 'M':
            return int(value * 1000000)
        elif unit == 'G':
            return int(value * 1000000000)
        else:
            return int(value)

    def analyze_connection(self, conn):
        """Analyze connection and detect bottlenecks"""
        analysis = {
            'connection': f"{conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port}",
            'state': conn.state,
            'timestamp': conn.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'metrics': {},
            'bottlenecks': [],
            'recommendations': []
        }

        # Basic metrics
        analysis['metrics']['recv_q'] = conn.recv_q
        analysis['metrics']['send_q'] = conn.send_q
        analysis['metrics']['rtt'] = f"{conn.rtt:.3f} ms" if conn.rtt > 0 else "0.000 ms"
        analysis['metrics']['rttvar'] = f"{conn.rttvar:.3f} ms" if conn.rttvar > 0 else "0.000 ms"
        analysis['metrics']['minrtt'] = f"{conn.minrtt:.3f} ms" if conn.minrtt > 0 else ""
        analysis['metrics']['rto'] = f"{conn.rto} ms" if conn.rto > 0 else ""
        analysis['metrics']['cwnd'] = conn.cwnd
        analysis['metrics']['ssthresh'] = conn.ssthresh
        analysis['metrics']['rcv_space'] = f"{conn.rcv_space} bytes ({conn.rcv_space/1024:.1f} KB)"
        analysis['metrics']['rcv_ssthresh'] = f"{conn.rcv_ssthresh} bytes" if conn.rcv_ssthresh > 0 else ""
        analysis['metrics']['snd_wnd'] = f"{conn.snd_wnd} bytes" if conn.snd_wnd > 0 else ""
        analysis['metrics']['mss'] = conn.mss
        analysis['metrics']['pmtu'] = conn.pmtu
        analysis['metrics']['advmss'] = conn.advmss if conn.advmss > 0 else ""
        analysis['metrics']['rcvmss'] = conn.rcvmss if conn.rcvmss > 0 else ""
        analysis['metrics']['wscale'] = conn.wscale if conn.wscale else ""

        # Rate metrics (always output)
        analysis['metrics']['send_rate'] = f"{conn.send_rate/1000000000:.2f} Gbps" if conn.send_rate > 0 else ""
        analysis['metrics']['pacing_rate'] = f"{conn.pacing_rate/1000000000:.2f} Gbps" if conn.pacing_rate > 0 else ""
        analysis['metrics']['delivery_rate'] = f"{conn.delivery_rate/1000000000:.2f} Gbps" if conn.delivery_rate > 0 else ""

        # Retransmission (always output)
        analysis['metrics']['retrans'] = f"{conn.retrans}/{conn.retrans_total}"
        analysis['metrics']['lost'] = conn.lost if conn.lost > 0 else ""

        # Unacknowledged and SACK metrics (always output)
        analysis['metrics']['unacked'] = conn.unacked if conn.unacked > 0 else ""
        # Calculate in-flight data
        if conn.unacked > 0 and conn.mss > 0:
            inflight_bytes = conn.unacked * conn.mss
            analysis['metrics']['inflight_data'] = f"{inflight_bytes} bytes ({inflight_bytes/1024:.1f} KB)"
        else:
            analysis['metrics']['inflight_data'] = ""

        analysis['metrics']['sacked'] = conn.sacked if conn.sacked > 0 else ""
        analysis['metrics']['dsack_dups'] = conn.dsack_dups if conn.dsack_dups > 0 else ""

        # Calculate spurious retransmission rate
        if conn.dsack_dups > 0 and conn.retrans_total > 0:
            spurious_rate = (conn.dsack_dups / conn.retrans_total) * 100
            analysis['metrics']['spurious_retrans_rate'] = f"{spurious_rate:.3f}%"
        else:
            analysis['metrics']['spurious_retrans_rate'] = ""

        analysis['metrics']['fackets'] = conn.fackets if conn.fackets > 0 else ""

        # Bytes metrics (always output)
        analysis['metrics']['bytes_sent'] = conn.bytes_sent if conn.bytes_sent > 0 else ""
        analysis['metrics']['bytes_acked'] = conn.bytes_acked if conn.bytes_acked > 0 else ""
        analysis['metrics']['bytes_received'] = conn.bytes_received if conn.bytes_received > 0 else ""

        # NEW: Segment counters and retransmission ratio
        if conn.segs_out > 0:
            analysis['metrics']['segs_out'] = conn.segs_out
            analysis['metrics']['segs_in'] = conn.segs_in
            if conn.retrans_total > 0:
                retrans_ratio = (conn.retrans_total / conn.segs_out) * 100
                analysis['metrics']['retrans_ratio'] = f"{retrans_ratio:.3f}%"

        if conn.data_segs_out > 0:
            analysis['metrics']['data_segs_out'] = conn.data_segs_out
            analysis['metrics']['data_segs_in'] = conn.data_segs_in
            if conn.segs_out > 0:
                data_efficiency = (conn.data_segs_out / conn.segs_out) * 100
                analysis['metrics']['data_efficiency'] = f"{data_efficiency:.1f}%"

        # Timing metrics (always output)
        analysis['metrics']['lastsnd'] = f"{conn.lastsnd} ms ago" if conn.lastsnd > 0 else ""
        analysis['metrics']['lastrcv'] = f"{conn.lastrcv} ms ago" if conn.lastrcv > 0 else ""
        analysis['metrics']['lastack'] = f"{conn.lastack} ms ago" if conn.lastack > 0 else ""

        # Application and receiver metrics (always output)
        analysis['metrics']['app_limited'] = "YES" if conn.app_limited else ""
        analysis['metrics']['rcv_rtt'] = f"{conn.rcv_rtt:.3f} ms" if conn.rcv_rtt > 0 else ""
        analysis['metrics']['ato'] = f"{conn.ato} ms" if conn.ato > 0 else ""

        # Congestion control (always output)
        analysis['metrics']['congestion_algorithm'] = conn.congestion_algorithm if conn.congestion_algorithm else ""
        analysis['metrics']['ca_state'] = conn.ca_state if conn.ca_state else ""

        # Reordering (always output)
        analysis['metrics']['reordering'] = conn.reordering if conn.reordering > 0 else ""

        # Out-of-order packets received (always output)
        if conn.rcv_ooopack > 0:
            analysis['metrics']['rcv_ooopack'] = f"{conn.rcv_ooopack:,} packets"
            # Calculate OOO ratio if we have total received segments
            if conn.segs_in > 0:
                ooo_ratio = (conn.rcv_ooopack / conn.segs_in) * 100
                analysis['metrics']['ooo_ratio'] = f"{ooo_ratio:.3f}%"
            else:
                analysis['metrics']['ooo_ratio'] = ""
        else:
            analysis['metrics']['rcv_ooopack'] = ""
            analysis['metrics']['ooo_ratio'] = ""

        # Limited statistics (always output - may be empty if kernel doesn't support)
        analysis['metrics']['busy_time'] = f"{conn.busy_time} ms" if conn.busy_time > 0 else ""
        analysis['metrics']['rwnd_limited_time'] = f"{conn.rwnd_limited_time} ms" if conn.rwnd_limited_time > 0 else ""
        analysis['metrics']['rwnd_limited_ratio'] = f"{conn.rwnd_limited_ratio:.1f}%" if conn.rwnd_limited_ratio > 0 else ""
        analysis['metrics']['sndbuf_limited_time'] = f"{conn.sndbuf_limited_time} ms" if conn.sndbuf_limited_time > 0 else ""
        analysis['metrics']['sndbuf_limited_ratio'] = f"{conn.sndbuf_limited_ratio:.1f}%" if conn.sndbuf_limited_ratio > 0 else ""
        analysis['metrics']['cwnd_limited_time'] = f"{conn.cwnd_limited_time} ms" if conn.cwnd_limited_time > 0 else ""
        analysis['metrics']['cwnd_limited_ratio'] = f"{conn.cwnd_limited_ratio:.1f}%" if conn.cwnd_limited_ratio > 0 else ""

        # NEW: Socket memory - display all fields (even if 0)
        # Note: only display if at least one skmem field is parsed (skmem_rb or skmem_tb typically present)
        if conn.skmem_rb > 0 or conn.skmem_tb > 0:
            analysis['metrics']['socket_rx_queue'] = f"{conn.skmem_r} bytes ({conn.skmem_r/1024:.1f} KB)" if conn.skmem_r > 0 else "0 bytes"
            analysis['metrics']['socket_rx_buffer'] = f"{conn.skmem_rb} bytes ({conn.skmem_rb/1024:.1f} KB)"
            analysis['metrics']['socket_tx_queue'] = f"{conn.skmem_t} bytes ({conn.skmem_t/1024:.1f} KB)" if conn.skmem_t > 0 else "0 bytes"
            analysis['metrics']['socket_tx_buffer'] = f"{conn.skmem_tb} bytes ({conn.skmem_tb/1024:.1f} KB)"
            analysis['metrics']['socket_forward_alloc'] = f"{conn.skmem_f} bytes ({conn.skmem_f/1024:.1f} KB)" if conn.skmem_f > 0 else "0 bytes"
            analysis['metrics']['socket_write_queue'] = f"{conn.skmem_w} bytes ({conn.skmem_w/1024:.1f} KB)" if conn.skmem_w > 0 else "0 bytes"
            analysis['metrics']['socket_opt_mem'] = f"{conn.skmem_o} bytes ({conn.skmem_o/1024:.1f} KB)" if conn.skmem_o > 0 else "0 bytes"
            analysis['metrics']['socket_backlog'] = f"{conn.skmem_bl} bytes ({conn.skmem_bl/1024:.1f} KB)" if conn.skmem_bl > 0 else "0 bytes"
            analysis['metrics']['socket_dropped'] = f"{conn.skmem_d} packets"

        # NEW: TCP options
        tcp_features = []
        if conn.tcp_ts:
            tcp_features.append("timestamps")
        if conn.tcp_sack:
            tcp_features.append("SACK")
        if tcp_features:
            analysis['metrics']['tcp_features'] = ", ".join(tcp_features)

        # NEW: Process information
        if conn.process_name:
            analysis['metrics']['process'] = f"{conn.process_name} (pid={conn.process_pid}, fd={conn.process_fd})"

        # Calculate BDP and recommended window
        if conn.rtt > 0:
            bdp_bytes = self._calculate_bdp(conn.rtt / 1000, self.args.target_bandwidth)
            analysis['metrics']['bdp'] = f"{bdp_bytes} bytes ({bdp_bytes/1024:.1f} KB)"
            analysis['metrics']['recommended_window'] = f"{bdp_bytes * 4} bytes ({bdp_bytes * 4 / 1024:.1f} KB)"

        # NEW: Timer information
        if conn.timer_state:
            analysis['metrics']['timer_state'] = conn.timer_state
            if conn.timer_expires_ms > 0:
                analysis['metrics']['timer_expires_ms'] = f"{conn.timer_expires_ms} ms"
            if conn.timer_retrans > 0:
                analysis['metrics']['timer_retrans'] = conn.timer_retrans
            if conn.backoff > 0:
                analysis['metrics']['backoff'] = conn.backoff

        # NEW: Window scale separation
        if conn.wscale_snd > 0 or conn.wscale_rcv > 0:
            analysis['metrics']['wscale_snd'] = conn.wscale_snd
            analysis['metrics']['wscale_rcv'] = conn.wscale_rcv

        # NEW: Max pacing rate
        if conn.max_pacing_rate > 0:
            analysis['metrics']['max_pacing_rate'] = f"{conn.max_pacing_rate/1000000000:.2f} Gbps"

        # NEW: Retransmission/delivery metrics
        if conn.bytes_retrans > 0:
            analysis['metrics']['bytes_retrans'] = f"{conn.bytes_retrans} bytes ({conn.bytes_retrans/1024:.1f} KB)"
        if conn.reord_seen > 0:
            analysis['metrics']['reord_seen'] = conn.reord_seen
        if conn.notsent > 0:
            analysis['metrics']['notsent'] = f"{conn.notsent} bytes ({conn.notsent/1024:.1f} KB)"
        if conn.delivered > 0:
            analysis['metrics']['delivered'] = conn.delivered
        if conn.delivered_ce > 0:
            analysis['metrics']['delivered_ce'] = conn.delivered_ce

        # NEW: TCP options (ECN, Fast Open)
        if conn.tcp_ecn:
            analysis['metrics']['tcp_ecn'] = "YES"
        if conn.tcp_ecnseen:
            analysis['metrics']['tcp_ecnseen'] = "YES"
        if conn.tcp_fastopen:
            analysis['metrics']['tcp_fastopen'] = "YES"

        # NEW: Socket identity
        if conn.uid > 0:
            analysis['metrics']['uid'] = conn.uid
        if conn.ino > 0:
            analysis['metrics']['ino'] = conn.ino
        if conn.sk_cookie > 0:
            analysis['metrics']['sk_cookie'] = f"0x{conn.sk_cookie:x}"
        if conn.bpf_id > 0:
            analysis['metrics']['bpf_id'] = conn.bpf_id
        if conn.cgroup_path:
            analysis['metrics']['cgroup_path'] = conn.cgroup_path
        if conn.tos > 0:
            analysis['metrics']['tos'] = f"0x{conn.tos:x}"
        if conn.tclass > 0:
            analysis['metrics']['tclass'] = f"0x{conn.tclass:x}"
        if conn.priority > 0:
            analysis['metrics']['priority'] = conn.priority

        # NEW: BBR specific metrics
        if conn.bbr_bw > 0:
            analysis['metrics']['bbr_bw'] = f"{conn.bbr_bw/1000000000:.2f} Gbps"
            analysis['metrics']['bbr_mrtt'] = f"{conn.bbr_mrtt:.3f} ms"
            analysis['metrics']['bbr_pacing_gain'] = f"{conn.bbr_pacing_gain:.2f}"
            analysis['metrics']['bbr_cwnd_gain'] = f"{conn.bbr_cwnd_gain:.2f}"

        # NEW: DCTCP specific metrics
        if conn.dctcp_alpha > 0:
            analysis['metrics']['dctcp_ce_state'] = conn.dctcp_ce_state
            analysis['metrics']['dctcp_alpha'] = conn.dctcp_alpha
            analysis['metrics']['dctcp_ab_ecn'] = conn.dctcp_ab_ecn
            analysis['metrics']['dctcp_ab_tot'] = conn.dctcp_ab_tot

        # NEW: MPTCP specific metrics
        if conn.mptcp_flags:
            analysis['metrics']['mptcp_flags'] = conn.mptcp_flags
        if conn.mptcp_token > 0:
            analysis['metrics']['mptcp_token'] = f"0x{conn.mptcp_token:x}"
        if conn.mptcp_seq > 0:
            analysis['metrics']['mptcp_seq'] = conn.mptcp_seq
        if conn.mptcp_maplen > 0:
            analysis['metrics']['mptcp_maplen'] = conn.mptcp_maplen

        # Bottleneck detection
        self._detect_bottlenecks(conn, analysis)

        return analysis

    def _calculate_bdp(self, rtt_sec, bandwidth_bps):
        """Calculate Bandwidth-Delay Product"""
        return int(bandwidth_bps * rtt_sec / 8)

    def _detect_bottlenecks(self, conn, analysis):
        """Detect performance bottlenecks"""

        # NEW: Check for high unacked segments (potential buffer bloat or cwnd issue)
        if conn.unacked > 0 and conn.cwnd > 0:
            unacked_ratio = (conn.unacked / conn.cwnd) * 100
            if unacked_ratio > 90:
                analysis['bottlenecks'].append({
                    'type': 'cwnd_saturation',
                    'severity': 'WARNING',
                    'value': f"{conn.unacked}/{conn.cwnd} ({unacked_ratio:.1f}%)",
                    'description': f"Congestion window {unacked_ratio:.1f}% utilized - sender is cwnd-limited"
                })

        # NEW: Check for high spurious retransmission rate
        if conn.dsack_dups > 0 and conn.retrans_total > 0:
            spurious_rate = (conn.dsack_dups / conn.retrans_total) * 100
            if spurious_rate > 5:  # More than 5% spurious retransmissions
                severity = 'CRITICAL' if spurious_rate > 20 else 'WARNING'
                analysis['bottlenecks'].append({
                    'type': 'high_spurious_retrans',
                    'severity': severity,
                    'value': f"{spurious_rate:.1f}%",
                    'description': f"{spurious_rate:.1f}% of retransmissions were spurious (unnecessary)"
                })

                analysis['recommendations'].append({
                    'issue': 'High spurious retransmission rate',
                    'current': f"dsack_dups={conn.dsack_dups}, retrans_total={conn.retrans_total}",
                    'evidence': f"{spurious_rate:.1f}% of retransmissions were false positives",
                    'action': 'RTO may be too aggressive or high RTT variance',
                    'commands': [
                        "# Check RTT variance",
                        "ss -tinopm | grep rtt",
                        "# Consider tuning TCP RTO parameters (advanced)",
                        "# sysctl net.ipv4.tcp_rto_min (default: 200ms)",
                    ]
                })

        # NEW: Check for application-limited condition
        if conn.app_limited:
            analysis['bottlenecks'].append({
                'type': 'application_limited',
                'severity': 'WARNING',
                'value': 'YES',
                'description': 'Application not providing data fast enough'
            })

            recommendations = {
                'issue': 'Application bottleneck detected',
                'evidence': []
            }

            if conn.lastsnd > 1000:
                recommendations['evidence'].append(f"No data sent for {conn.lastsnd}ms")
            if conn.busy_time > 0 and conn.segs_out > 0:
                # Estimate connection age from other metrics if available
                recommendations['evidence'].append("Connection is app_limited during active periods")

            recommendations['action'] = 'Check application performance: CPU usage, I/O wait, processing delays'
            recommendations['commands'] = [
                f"# Check process CPU and I/O (if process info available)",
                "pidstat -p <pid> -u -r -d 1",
                "strace -p <pid> -e trace=read,write -T",
            ]

            analysis['recommendations'].append(recommendations)

        # NEW: Check for socket buffer drops (CRITICAL!)
        if conn.skmem_d > 0:
            analysis['bottlenecks'].append({
                'type': 'socket_drops',
                'severity': 'CRITICAL',
                'value': f"{conn.skmem_d} packets",
                'description': f"Socket layer dropped {conn.skmem_d} packets due to buffer overflow"
            })

            analysis['recommendations'].append({
                'issue': 'Socket buffer overflow - packets dropped!',
                'current': f"RX buffer: {conn.skmem_rb} bytes, TX buffer: {conn.skmem_tb} bytes",
                'action': 'Increase socket buffers immediately',
                'commands': [
                    "sudo sysctl -w net.core.rmem_max=134217728",
                    "sudo sysctl -w net.core.wmem_max=134217728",
                    "sudo sysctl -w net.ipv4.tcp_rmem=\"4096 87380 134217728\"",
                    "sudo sysctl -w net.ipv4.tcp_wmem=\"4096 87380 134217728\""
                ]
            })

        # NEW: Check for connection stalls (lastsnd/lastrcv very high)
        if conn.lastsnd > 5000 and not conn.app_limited:
            analysis['bottlenecks'].append({
                'type': 'send_stall',
                'severity': 'CRITICAL',
                'value': f"{conn.lastsnd} ms",
                'description': f"No data sent for {conn.lastsnd}ms but not app-limited"
            })

            analysis['recommendations'].append({
                'issue': 'Connection send stalled',
                'evidence': f"lastsnd={conn.lastsnd}ms, but app_limited=False",
                'action': 'Check network path and peer responsiveness',
                'commands': [
                    f"# Check if peer is responding",
                    f"ping -c 5 {conn.remote_addr}",
                    f"# Check for network issues",
                    "ethtool -S <interface> | grep -E 'drop|error'",
                ]
            })

        if conn.lastrcv > 5000:
            analysis['bottlenecks'].append({
                'type': 'receive_stall',
                'severity': 'CRITICAL',
                'value': f"{conn.lastrcv} ms",
                'description': f"No packets received for {conn.lastrcv}ms"
            })

            analysis['recommendations'].append({
                'issue': 'Not receiving packets from peer',
                'evidence': f"lastrcv={conn.lastrcv}ms, lastack={conn.lastack}ms",
                'action': 'Network path may be broken or peer crashed',
                'commands': [
                    f"ping -c 5 {conn.remote_addr}",
                    f"traceroute -n {conn.remote_addr}",
                    "Check peer system status"
                ]
            })

        # NEW: Check for high reordering
        if conn.reordering > 20:
            severity = 'CRITICAL' if conn.reordering > 50 else 'WARNING'
            analysis['bottlenecks'].append({
                'type': 'high_reordering',
                'severity': severity,
                'value': conn.reordering,
                'description': f"High packet reordering detected ({conn.reordering} packets)"
            })

            analysis['recommendations'].append({
                'issue': 'Excessive packet reordering',
                'current': f"reordering = {conn.reordering}",
                'action': 'Check for multi-path routing or per-packet load balancing',
                'commands': [
                    f"# Check routing",
                    f"traceroute -n {conn.remote_addr}",
                    f"mtr -r -c 100 {conn.remote_addr}",
                    "# May indicate ECMP or per-packet load balancing"
                ]
            })

        # NEW: Check for high out-of-order packets
        if conn.rcv_ooopack > 1000:
            severity = 'CRITICAL' if conn.rcv_ooopack > 10000 else 'WARNING'
            ooo_ratio = (conn.rcv_ooopack / conn.segs_in * 100) if conn.segs_in > 0 else 0

            analysis['bottlenecks'].append({
                'type': 'high_ooo_packets',
                'severity': severity,
                'value': f"{conn.rcv_ooopack:,} ({ooo_ratio:.2f}%)",
                'description': f"High out-of-order packets: {conn.rcv_ooopack:,} packets ({ooo_ratio:.2f}% of received)"
            })

            recommendations = {
                'issue': f'Severe packet reordering ({conn.rcv_ooopack:,} OOO packets)',
                'current': f"rcv_ooopack={conn.rcv_ooopack:,}, ratio={ooo_ratio:.2f}%",
                'action': 'Fix packet ordering issues',
                'commands': []
            }

            # Provide specific recommendations based on the scenario
            if 'ovs' in conn.local_addr.lower() or 'port-' in conn.local_addr.lower():
                recommendations['commands'].extend([
                    "# OVS multi-queue may cause reordering",
                    "ovs-vsctl list Interface port-storage | grep n_rxq",
                    "# Set to single queue if needed:",
                    "sudo ovs-vsctl set Interface port-storage options:n_rxq=1",
                ])

            recommendations['commands'].extend([
                "# Check CPU interrupt distribution",
                "cat /proc/interrupts | grep -E 'virtio|vhost|eth'",
                "# Disable irqbalance if running",
                "sudo systemctl stop irqbalance",
                "# Check for RSS/RPS settings",
                "cat /sys/class/net/*/queues/rx-*/rps_cpus"
            ])

            analysis['recommendations'].append(recommendations)

        # NEW: Check for MSS mismatch
        if conn.rcvmss > 0 and conn.advmss > 0 and abs(conn.rcvmss - conn.advmss) > 500:
            analysis['bottlenecks'].append({
                'type': 'mss_mismatch',
                'severity': 'WARNING',
                'value': f"rcvmss={conn.rcvmss}, advmss={conn.advmss}",
                'description': f"Large MSS mismatch: received {conn.rcvmss} vs advertised {conn.advmss}"
            })

            analysis['recommendations'].append({
                'issue': 'MSS negotiation mismatch',
                'current': f"rcvmss={conn.rcvmss}, advmss={conn.advmss}, mss={conn.mss}",
                'action': 'Check MTU settings and path MTU discovery',
                'commands': [
                    f"ip link show | grep mtu",
                    f"tracepath {conn.remote_addr}",
                ]
            })

        # Check rwnd_limited
        if conn.rwnd_limited_ratio > 50:
            severity = 'CRITICAL' if conn.rwnd_limited_ratio > 80 else 'WARNING'
            analysis['bottlenecks'].append({
                'type': 'rwnd_limited',
                'severity': severity,
                'value': f"{conn.rwnd_limited_ratio:.1f}%",
                'description': f"Receive window limited for {conn.rwnd_limited_ratio:.1f}% of the time"
            })

            # Get recommended buffer size
            if conn.rtt > 0:
                bdp = self._calculate_bdp(conn.rtt / 1000, self.args.target_bandwidth)
                recommended = bdp * 4

                analysis['recommendations'].append({
                    'issue': 'Receive window too small',
                    'current': f"rcv_space = {conn.rcv_space} bytes ({conn.rcv_space/1024:.1f} KB)",
                    'recommended': f"{recommended} bytes ({recommended/1024:.1f} KB, {recommended/1024/1024:.1f} MB)",
                    'action': 'Increase tcp_rmem on the receiver side',
                    'commands': [
                        f"sudo sysctl -w net.core.rmem_max={recommended * 2}",
                        f"sudo sysctl -w net.ipv4.tcp_rmem=\"4096 131072 {recommended * 2}\""
                    ]
                })

        # Check cwnd_limited
        if conn.cwnd_limited_ratio > 50:
            severity = 'CRITICAL' if conn.cwnd_limited_ratio > 80 else 'WARNING'
            analysis['bottlenecks'].append({
                'type': 'cwnd_limited',
                'severity': severity,
                'value': f"{conn.cwnd_limited_ratio:.1f}%",
                'description': f"Congestion window limited for {conn.cwnd_limited_ratio:.1f}% of the time"
            })

            analysis['recommendations'].append({
                'issue': 'Congestion window limiting throughput',
                'current': f"cwnd = {conn.cwnd}",
                'action': 'Check for packet loss and network congestion',
                'commands': [
                    "ethtool -S <interface> | grep -E 'drop|error'",
                    "netstat -s | grep -i retrans"
                ]
            })

        # Check sndbuf_limited
        if conn.sndbuf_limited_ratio > 50:
            severity = 'CRITICAL' if conn.sndbuf_limited_ratio > 80 else 'WARNING'
            analysis['bottlenecks'].append({
                'type': 'sndbuf_limited',
                'severity': severity,
                'value': f"{conn.sndbuf_limited_ratio:.1f}%",
                'description': f"Send buffer limited for {conn.sndbuf_limited_ratio:.1f}% of the time"
            })

            analysis['recommendations'].append({
                'issue': 'Send buffer too small',
                'action': 'Increase tcp_wmem on the sender side',
                'commands': [
                    "sudo sysctl -w net.core.wmem_max=268435456",
                    "sudo sysctl -w net.ipv4.tcp_wmem=\"4096 65536 268435456\""
                ]
            })

        # Check small cwnd (only for client/sender role)
        # Server-side only sends ACKs, small cwnd is normal
        if self.args.role == 'client' and conn.cwnd < 100 and conn.cwnd > 0:
            analysis['bottlenecks'].append({
                'type': 'small_cwnd',
                'severity': 'WARNING',
                'value': conn.cwnd,
                'description': f"Congestion window very small ({conn.cwnd}), possibly in slow start or recovery"
            })

        # Check retransmissions
        if conn.retrans_total > 100:
            analysis['bottlenecks'].append({
                'type': 'high_retransmissions',
                'severity': 'WARNING',
                'value': conn.retrans_total,
                'description': f"High retransmission count ({conn.retrans_total})"
            })

            # Analyze retransmission causes from system stats
            retrans_analysis = []
            if self.system_stats:
                total_retrans = self.system_stats.get('segments_retransmitted', 0)

                # Retransmission type analysis
                if 'tcp_loss_probes' in self.system_stats and self.system_stats['tcp_loss_probes'] > 0:
                    tlp_count = self.system_stats['tcp_loss_probes']
                    tlp_pct = (tlp_count / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_analysis.append(
                        f"TLP probe retrans: {tlp_count:,} ({tlp_pct:.1f}%) - Window too small (rwnd/cwnd), cannot trigger fast retransmit"
                    )

                if 'fast_retransmits' in self.system_stats and self.system_stats['fast_retransmits'] > 0:
                    fast_count = self.system_stats['fast_retransmits']
                    fast_pct = (fast_count / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_analysis.append(
                        f"Fast retransmits: {fast_count:,} ({fast_pct:.1f}%) - Network packet loss or reordering"
                    )

                if 'retrans_in_slowstart' in self.system_stats and self.system_stats['retrans_in_slowstart'] > 0:
                    slow_count = self.system_stats['retrans_in_slowstart']
                    slow_pct = (slow_count / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_analysis.append(
                        f"Retrans in slow start: {slow_count:,} ({slow_pct:.1f}%) - Initial congestion window is small"
                    )

                if 'tcp_lost_retransmit' in self.system_stats and self.system_stats['tcp_lost_retransmit'] > 0:
                    lost_retrans = self.system_stats['tcp_lost_retransmit']
                    retrans_analysis.append(
                        f"WARNING: Retransmitted packets lost again: {lost_retrans:,} - Severe congestion or poor path quality"
                    )

                if 'tcp_spurious_rtos' in self.system_stats and self.system_stats['tcp_spurious_rtos'] > 0:
                    spurious = self.system_stats['tcp_spurious_rtos']
                    retrans_analysis.append(
                        f"Spurious RTOs: {spurious:,} - False positives, likely due to high RTT variance"
                    )

                # Timeout related
                timeout_total = (self.system_stats.get('timeout_after_sack', 0) +
                               self.system_stats.get('timeout_in_loss', 0) +
                               self.system_stats.get('other_tcp_timeouts', 0))
                if timeout_total > 0:
                    retrans_analysis.append(
                        f"Timeout retrans: {timeout_total:,} - After SACK recovery/loss state/other timeouts"
                    )

            recommendation = {
                'issue': 'High retransmissions detected',
                'action': 'Investigate retransmission causes',
                'commands': [
                    "# Check system-wide retrans breakdown:",
                    "netstat -s | grep -iE 'retrans|loss probe|spurious'",
                    "",
                    "# Check NIC drops:",
                    "ethtool -S <interface> | grep -E 'drop|error|miss'",
                    "",
                    "# Use eBPF tools for detailed tracing:",
                    "# sudo python3 ebpf-tools/linux-network-stack/packet-drop/*.py"
                ]
            }

            if retrans_analysis:
                recommendation['likely_causes'] = retrans_analysis

            analysis['recommendations'].append(recommendation)

        # Check Recv-Q
        if conn.recv_q > 0:
            analysis['bottlenecks'].append({
                'type': 'recv_queue_backlog',
                'severity': 'WARNING',
                'value': conn.recv_q,
                'description': f"Receive queue has backlog ({conn.recv_q} bytes), application may be slow"
            })

        # Check Send-Q
        if conn.send_q > conn.mss * 10:
            analysis['bottlenecks'].append({
                'type': 'send_queue_backlog',
                'severity': 'INFO',
                'value': conn.send_q,
                'description': f"Send queue has backlog ({conn.send_q} bytes)"
            })

        # Check pacing rate vs target bandwidth
        if conn.pacing_rate > 0 and self.args.target_bandwidth > 0:
            ratio = conn.pacing_rate / self.args.target_bandwidth
            if ratio < 0.5:
                analysis['bottlenecks'].append({
                    'type': 'low_pacing_rate',
                    'severity': 'WARNING',
                    'value': f"{conn.pacing_rate/1000000000:.2f} Gbps",
                    'description': f"Pacing rate ({conn.pacing_rate/1000000000:.2f} Gbps) much lower than target ({self.args.target_bandwidth/1000000000:.1f} Gbps)"
                })

    def print_analysis(self, analysis):
        """Print analysis results"""
        print(f"\n{'='*80}")
        print(f"TCP Connection Analysis - {analysis['timestamp']}")
        print(f"{'='*80}")
        print(f"Connection: {analysis['connection']}")
        print(f"State: {analysis['state']}")
        print()

        # Print metrics
        print("Metrics:")
        print("-" * 80)
        for key, value in analysis['metrics'].items():
            print(f"  {key:25s}: {value}")
        print()

        # Print bottlenecks (only if --show-analysis is enabled)
        if self.args.show_analysis:
            if analysis['bottlenecks']:
                print("Bottlenecks Detected:")
                print("-" * 80)
                for bottleneck in analysis['bottlenecks']:
                    severity_symbol = '🔴' if bottleneck['severity'] == 'CRITICAL' else '⚠️' if bottleneck['severity'] == 'WARNING' else 'ℹ️'
                    print(f"  {severity_symbol} [{bottleneck['severity']}] {bottleneck['type']}")
                    print(f"     Value: {bottleneck['value']}")
                    print(f"     {bottleneck['description']}")
                    print()
            else:
                print("✅ No obvious bottlenecks detected")
                print()

            # Print recommendations (only if --show-analysis is enabled)
            if analysis['recommendations']:
                print("Recommendations:")
                print("-" * 80)
                for i, rec in enumerate(analysis['recommendations'], 1):
                    print(f"  {i}. Issue: {rec['issue']}")
                    if 'current' in rec:
                        print(f"     Current: {rec['current']}")
                    if 'recommended' in rec:
                        print(f"     Recommended: {rec['recommended']}")
                    if 'likely_causes' in rec:
                        print(f"     Likely Causes:")
                        for cause in rec['likely_causes']:
                            print(f"       - {cause}")
                    print(f"     Action: {rec['action']}")
                    if 'commands' in rec:
                        print(f"     Commands:")
                        for cmd in rec['commands']:
                            print(f"       {cmd}")
                    print()

        print(f"{'='*80}\n")

    def print_system_config(self):
        """Print system TCP configuration"""
        print(f"\n{'='*80}")
        print("System TCP Configuration")
        print(f"{'='*80}")

        for key, value in self.system_config.items():
            print(f"  {key:40s}: {value}")

        # Parse and highlight important values
        if 'net.ipv4.tcp_rmem' in self.system_config:
            values = self.system_config['net.ipv4.tcp_rmem'].split()
            if len(values) == 3:
                max_bytes = int(values[2])
                print(f"\n  TCP Receive Buffer Max: {max_bytes} bytes ({max_bytes/1024/1024:.1f} MB)")

        if 'net.ipv4.tcp_wmem' in self.system_config:
            values = self.system_config['net.ipv4.tcp_wmem'].split()
            if len(values) == 3:
                max_bytes = int(values[2])
                print(f"  TCP Send Buffer Max: {max_bytes} bytes ({max_bytes/1024/1024:.1f} MB)")

        print(f"{'='*80}\n")

    def print_system_stats(self, show_delta=False, interval_seconds=0):
        """Print system-wide TCP statistics from netstat -s

        Args:
            show_delta: If True, show delta (changes) instead of cumulative values
            interval_seconds: Monitoring interval for rate calculation
        """
        if not self.system_stats:
            return

        # Determine which stats to display
        if show_delta:
            display_stats = self._calculate_stats_delta()
            stats_type = "Delta (changes in this interval)"
        else:
            display_stats = self.system_stats
            stats_type = "Cumulative (since system boot)"

        print(f"\n{'='*80}")
        if show_delta and interval_seconds > 0:
            print(f"System TCP Statistics - {stats_type} [{interval_seconds}s interval]")
        else:
            print(f"System TCP Statistics - {stats_type}")
        print(f"{'='*80}")

        # Group statistics by category
        categories = {
            '=== Retransmission Type Breakdown ===': [
                'segments_retransmitted',
                'fast_retransmits',
                'retrans_in_slowstart',
                'tcp_loss_probes',
                'tcp_loss_probe_recovery',
                'tcp_lost_retransmit',
                'tcp_spurious_rtos',
                'tcp_syn_retrans'
            ],
            '=== Timeout Types ===': [
                'timeout_after_sack',
                'timeout_in_loss',
                'other_tcp_timeouts'
            ],
            '=== Stack Packet Drops ===': [
                'rcv_pruned',
                'rcv_collapsed',
                'tcp_backlog_drop',
                'listen_overflows',
                'listen_drops',
                'sack_retrans_fail'
            ],
            '=== SACK & Reordering ===': [
                'sack_recovery',
                'sack_reordering',
                'reordering_ts'
            ],
            '=== Congestion Window Recovery ===': [
                'tcp_full_undo',
                'tcp_partial_undo',
                'tcp_dsack_undo'
            ],
            '=== Connection Issues ===': [
                'failed_connection_attempts',
                'connection_resets_received',
                'connection_resets_sent',
                'reset_due_to_unexpected_data',
                'reset_due_to_early_close',
                'abort_on_timeout'
            ],
            '=== Basic Counters ===': [
                'segments_sent',
                'segments_received',
                'bad_segments',
                'delayed_acks_sent'
            ]
        }

        # Descriptions for statistics
        descriptions = {
            # Retransmission types
            'segments_retransmitted': 'Total retransmitted segments (all causes)',
            'fast_retransmits': 'Fast retransmits (packet loss/reordering, 3 DupACKs)',
            'retrans_in_slowstart': 'Retrans during slow start (initial cwnd small)',
            'tcp_loss_probes': 'TLP probe retrans (window too small for fast retransmit)',
            'tcp_loss_probe_recovery': 'TLP probe successful recovery',
            'tcp_lost_retransmit': 'Retransmitted packet lost again (severe congestion or path issue)',
            'tcp_spurious_rtos': 'Spurious RTO (false positive, high RTT variance)',
            'tcp_syn_retrans': 'SYN retransmits (during connection establishment)',

            # Timeout types
            'timeout_after_sack': 'Timeout after SACK recovery (packets still lost)',
            'timeout_in_loss': 'Timeout in loss state (persistent congestion)',
            'other_tcp_timeouts': 'Other TCP timeouts',

            # Stack packet drops
            'rcv_pruned': 'Rcv queue pruned (socket buffer overflow)',
            'rcv_collapsed': 'Rcv queue collapsed (memory pressure)',
            'tcp_backlog_drop': 'Backlog queue drop (processing overload)',
            'listen_overflows': 'Listen queue overflow count',
            'listen_drops': 'SYN dropped (listen queue full)',
            'sack_retrans_fail': 'SACK retransmit failed',

            # SACK and reordering
            'sack_recovery': 'SACK recovery count (recovered from loss)',
            'sack_reordering': 'SACK detected reordering',
            'reordering_ts': 'Timestamp detected reordering',

            # Congestion window recovery
            'tcp_full_undo': 'Cwnd fully recovered (undo slow start)',
            'tcp_partial_undo': 'Cwnd partially recovered (Hoe heuristic)',
            'tcp_dsack_undo': 'DSACK undo cwnd reduction',

            # Connection issues
            'failed_connection_attempts': 'Failed connection attempts',
            'connection_resets_received': 'RST received',
            'connection_resets_sent': 'RST sent',
            'reset_due_to_unexpected_data': 'RST (unexpected data received)',
            'reset_due_to_early_close': 'RST (early close)',
            'abort_on_timeout': 'Connection aborted on timeout',

            # Basic counters
            'segments_sent': 'Total segments sent',
            'segments_received': 'Total segments received',
            'bad_segments': 'Bad segments (checksum error, etc.)',
            'delayed_acks_sent': 'Delayed ACKs sent'
        }

        for category, stats in categories.items():
            # Check if any stat in this category exists
            has_data = any(stat in display_stats for stat in stats)
            if not has_data:
                continue

            print(f"\n{category}:")
            print("-" * 80)

            for stat in stats:
                if stat in display_stats:
                    value = display_stats[stat]
                    desc = descriptions.get(stat, '')
                    print(f"  {stat:35s}: {value:12d}  # {desc}")

        # ========== Intelligent Analysis Section ==========
        # Only show if --show-analysis is enabled
        if not self.args.show_analysis:
            print(f"{'='*80}\n")
            return

        print(f"\n{'='*80}")
        print("=== Intelligent Analysis ===")
        print(f"{'='*80}")

        # 1. Retransmission ratio and breakdown
        if 'segments_retransmitted' in display_stats and 'segments_sent' in display_stats:
            total_retrans = display_stats['segments_retransmitted']
            total_sent = display_stats['segments_sent']
            if total_sent > 0:
                retrans_ratio = (total_retrans / total_sent) * 100
                print(f"\nRetransmission Ratio: {retrans_ratio:.4f}% ({total_retrans:,} / {total_sent:,})")

                # Retransmission type breakdown analysis
                print(f"\nRetransmission Type Breakdown:")
                retrans_breakdown = []

                tlp = display_stats.get('tcp_loss_probes', 0)
                if tlp > 0:
                    tlp_pct = (tlp / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_breakdown.append(('TLP probe retrans', tlp, tlp_pct, 'Window too small'))

                fast = display_stats.get('fast_retransmits', 0)
                if fast > 0:
                    fast_pct = (fast / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_breakdown.append(('Fast retransmit', fast, fast_pct, 'Packet loss/reordering'))

                slow = display_stats.get('retrans_in_slowstart', 0)
                if slow > 0:
                    slow_pct = (slow / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_breakdown.append(('Slow start retrans', slow, slow_pct, 'Small cwnd'))

                lost = display_stats.get('tcp_lost_retransmit', 0)
                if lost > 0:
                    lost_pct = (lost / total_retrans * 100) if total_retrans > 0 else 0
                    retrans_breakdown.append(('Retrans pkt lost', lost, lost_pct, 'Severe congestion WARNING'))

                for name, count, pct, reason in retrans_breakdown:
                    print(f"  {name:20s}: {count:12,}  ({pct:5.1f}%)  - {reason}")

        # 2. Stack packet drop analysis
        stack_drops = []
        pruned = display_stats.get('rcv_pruned', 0)
        if pruned > 0:
            stack_drops.append(('Rcv queue pruned', pruned, 'Socket buffer overflow, increase tcp_rmem'))

        collapsed = display_stats.get('rcv_collapsed', 0)
        if collapsed > 0:
            stack_drops.append(('Rcv queue collapsed', collapsed, 'Memory pressure'))

        backlog = display_stats.get('tcp_backlog_drop', 0)
        if backlog > 0:
            stack_drops.append(('Backlog drop', backlog, 'App processing slow, increase tcp_max_syn_backlog'))

        listen_drop = display_stats.get('listen_drops', 0)
        if listen_drop > 0:
            stack_drops.append(('SYN dropped', listen_drop, 'Listen queue full, increase somaxconn'))

        if stack_drops:
            print(f"\nWARNING: Stack packet drops detected:")
            for name, count, suggestion in stack_drops:
                print(f"  {name:22s}: {count:12,}  - {suggestion}")

        # 3. Timeout analysis
        timeout_after_sack = display_stats.get('timeout_after_sack', 0)
        timeout_in_loss = display_stats.get('timeout_in_loss', 0)
        other_timeouts = display_stats.get('other_tcp_timeouts', 0)
        timeout_total = timeout_after_sack + timeout_in_loss + other_timeouts

        if timeout_total > 0:
            print(f"\nTimeout Events:")
            if timeout_after_sack > 0:
                print(f"  After SACK recovery     : {timeout_after_sack:12,}  - Packets still lost")
            if timeout_in_loss > 0:
                print(f"  In loss state           : {timeout_in_loss:12,}  - Persistent congestion")
            if other_timeouts > 0:
                print(f"  Other timeouts          : {other_timeouts:12,}")

        # 4. Reordering detection
        sack_reorder = display_stats.get('sack_reordering', 0)
        ts_reorder = display_stats.get('reordering_ts', 0)
        if sack_reorder > 0 or ts_reorder > 0:
            print(f"\nPacket Reordering:")
            if sack_reorder > 0:
                print(f"  SACK detected reordering    : {sack_reorder:12,}")
            if ts_reorder > 0:
                print(f"  Timestamp detected reordering: {ts_reorder:12,}")

        # 5. Critical warnings
        print(f"\n{'='*80}")
        warnings = []

        # High retransmission ratio
        if 'segments_retransmitted' in display_stats and 'segments_sent' in display_stats:
            retrans_ratio = (display_stats['segments_retransmitted'] / display_stats['segments_sent']) * 100 if display_stats['segments_sent'] > 0 else 0
            if retrans_ratio > 1.0:
                warnings.append(f"CRITICAL: High retransmission ratio: {retrans_ratio:.2f}% (normal <1%)")

        # TLP ratio too high
        total_retrans = display_stats.get('segments_retransmitted', 0)
        if total_retrans > 0:
            tlp = display_stats.get('tcp_loss_probes', 0)
            if tlp > 0 and (tlp / total_retrans) > 0.3:
                warnings.append(f"CRITICAL: TLP ratio too high: {(tlp/total_retrans)*100:.1f}% - Check receive window (rwnd)")

        # Retransmitted packets lost
        if display_stats.get('tcp_lost_retransmit', 0) > 1000:
            warnings.append(f"CRITICAL: Many retrans packets lost: {display_stats['tcp_lost_retransmit']:,} - Poor path quality")

        # Socket buffer overflow
        if pruned > 1000:
            warnings.append(f"WARNING: Socket buffer overflow: {pruned:,} - Increase tcp_rmem")

        # Listen queue overflow
        if listen_drop > 1000:
            warnings.append(f"WARNING: Listen queue overflow: {listen_drop:,} - Increase net.core.somaxconn")

        if warnings:
            print("Critical Warnings:")
            for warning in warnings:
                print(f"  {warning}")
        else:
            print("OK: No serious issues found")

        print(f"{'='*80}\n")

    def run(self):
        """Main execution"""

        # Print system configuration (once, doesn't change)
        if self.args.show_config:
            self.print_system_config()

        if self.args.interval > 0:
            # Continuous monitoring
            print(f"Starting continuous monitoring (interval: {self.args.interval}s)")
            print("Press Ctrl+C to stop...")

            # Load initial stats for baseline
            self._load_system_stats()

            # Display initial cumulative stats if requested
            if self.args.show_stats:
                print("\n" + "="*80)
                print("INITIAL BASELINE - Cumulative statistics since system boot")
                print("="*80)
                self.print_system_stats(show_delta=False, interval_seconds=0)

            # Save baseline for delta calculation
            self._save_current_stats_as_previous()

            try:
                iteration = 0
                while True:
                    time.sleep(self.args.interval)
                    iteration += 1

                    # Reload system stats each interval (cumulative counters)
                    # Always load stats for retrans analysis context, even if not displaying
                    self._load_system_stats()

                    # Display system stats delta if requested
                    if self.args.show_stats:
                        print(f"\n{'='*80}")
                        print(f"Interval #{iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        print(f"{'='*80}")
                        self.print_system_stats(show_delta=True, interval_seconds=self.args.interval)

                    # Collect and analyze connections
                    connections = self.collect_connection_info()

                    if not connections:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] No connections found")
                    else:
                        for conn in connections:
                            analysis = self.analyze_connection(conn)
                            self.print_analysis(analysis)

                    # Save current stats for next delta calculation
                    self._save_current_stats_as_previous()

            except KeyboardInterrupt:
                print("\nStopped by user")

                # Display final cumulative stats if requested
                if self.args.show_stats:
                    print("\n" + "="*80)
                    print("FINAL SUMMARY - Cumulative statistics since system boot")
                    print("="*80)
                    self.print_system_stats(show_delta=False, interval_seconds=0)
        else:
            # Single shot
            # Always load system stats for retrans analysis context
            self._load_system_stats()

            # Display system stats if requested
            if self.args.show_stats:
                self.print_system_stats()

            connections = self.collect_connection_info()

            if not connections:
                print("No connections found matching the criteria")
                return

            for conn in connections:
                analysis = self.analyze_connection(conn)
                self.print_analysis(analysis)


def main():
    parser = argparse.ArgumentParser(
        description='TCP Connection Analyzer - Collect and analyze TCP connection performance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze client-side connection to iperf3 server
  %(prog)s --remote-ip 1.1.1.5 --remote-port 5201 --role client

  # Analyze server-side connections on port 5201
  %(prog)s --local-port 5201 --role server

  # Filter by specific local IP (useful for multi-homed hosts)
  %(prog)s --local-ip 70.0.0.31 --local-port 2181 --role server

  # Filter both local and remote
  %(prog)s --local-ip 70.0.0.31 --remote-ip 70.0.0.32 --local-port 2181 --role server

  # Continuous monitoring every 2 seconds
  %(prog)s --remote-ip 1.1.1.5 --remote-port 5201 --role client --interval 2

  # Monitor all connections to a remote IP (any port)
  %(prog)s --remote-ip 1.1.1.5 --role client --all

  # Show system TCP configuration (sysctl values)
  %(prog)s --show-config --role server --local-port 5201

  # Show system TCP statistics (netstat -s analysis)
  %(prog)s --show-stats --role server --local-port 5201

  # Show both config and stats
  %(prog)s --show-config --show-stats --role server --local-port 5201

  # Continuous monitoring with stats refresh
  %(prog)s --show-stats --role server --local-port 5201 --interval 5
        """
    )

    parser.add_argument('--role', type=str, choices=['client', 'server'],
                        required=True,
                        help='Role: client (initiator) or server (listener)')
    parser.add_argument('--local-ip', type=str,
                        help='Local IP address filter')
    parser.add_argument('--local-port', type=int,
                        help='Local port number (for server role, or additional filter)')
    parser.add_argument('--remote-ip', type=str,
                        help='Remote IP address (for client role, or additional filter)')
    parser.add_argument('--remote-port', type=int,
                        help='Remote port number (for client role, or additional filter)')
    parser.add_argument('--interval', type=int, default=0,
                        help='Monitoring interval in seconds (0 = single shot)')
    parser.add_argument('--all', action='store_true',
                        help='Monitor all connections (not just ESTABLISHED)')
    parser.add_argument('--target-bandwidth', type=float, default=25,
                        help='Target bandwidth in Gbps (default: 25)')
    parser.add_argument('--show-config', action='store_true',
                        help='Show system TCP configuration')
    parser.add_argument('--show-stats', action='store_true',
                        help='Show system TCP statistics (netstat -s)')
    parser.add_argument('--show-analysis', action='store_true',
                        help='Show bottlenecks and recommendations analysis')
    parser.add_argument('--json', action='store_true',
                        help='Output in JSON format')

    args = parser.parse_args()

    # Convert bandwidth to bps
    args.target_bandwidth = int(args.target_bandwidth * 1000000000)

    # Create analyzer
    analyzer = TCPConnectionAnalyzer(args)

    # Run analysis
    analyzer.run()


if __name__ == '__main__':
    main()
