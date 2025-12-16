#!/usr/bin/env python
"""
Socket Data Parser

Parses dual-side TCP socket data, validates connection matching, and performs time alignment.
Supports raw socket log format only.
Implements FR-SOCKET-SUM-001, FR-SOCKET-SUM-014.
"""

import os
import sys
import re
from typing import Tuple, Optional, Dict, List
import pandas as pd

from ..models import FiveTuple

# Import unified conversion logic
tools_path = os.path.join(os.path.dirname(__file__), '../../tools')
sys.path.insert(0, tools_path)
from convert_socket_log_to_csv import parse_socket_log_to_records


class ConnectionMismatchError(Exception):
    """Exception raised when client and server connections don't match"""
    pass


class SocketDataParser:
    """TCP Socket data parser with dual-side support (log format only)"""

    def parse_dual_directories(
        self,
        client_dir: str,
        server_dir: str
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Parse client and server directories and align data by timestamp

        Algorithm:
        1. Parse client-side data from all files in directory
        2. Parse server-side data from all files in directory
        3. Validate connection match (five-tuple reversal)
        4. Perform time alignment using merge_asof

        Args:
            client_dir: Directory containing client-side socket data files
            server_dir: Directory containing server-side socket data files

        Returns:
            Tuple of (client_df, server_df, aligned_df)

        Raises:
            ConnectionMismatchError: If client and server connections don't match

        Implements: FR-SOCKET-SUM-001, FR-SOCKET-SUM-014
        """
        # Parse both sides
        client_df = self.parse_directory(client_dir, side='client')
        server_df = self.parse_directory(server_dir, side='server')

        # Validate connection match
        self._validate_connection_match(client_df, server_df)

        # Time alignment
        aligned_df = self._align_dual_side_data(client_df, server_df)

        return client_df, server_df, aligned_df

    def parse_directory(self, path: str, side: str) -> pd.DataFrame:
        """
        Parse socket log data from a directory or single file

        Args:
            path: Path to directory containing socket log files, or path to single log file
            side: 'client' or 'server'

        Returns:
            DataFrame with all parsed data

        Raises:
            FileNotFoundError: If path doesn't exist
            ValueError: If no valid log files found
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path not found: {path}")

        # Handle single file
        if os.path.isfile(path):
            df = self.parse_file(path, side)
            if df is None or df.empty:
                raise ValueError(f"No valid data could be parsed from {path}")
            return df

        # Handle directory
        if not os.path.isdir(path):
            raise FileNotFoundError(f"Path is neither file nor directory: {path}")

        # Find all data files (skip hidden files)
        data_files = [
            os.path.join(path, f)
            for f in os.listdir(path)
            if not f.startswith('.') and os.path.isfile(os.path.join(path, f))
        ]

        if not data_files:
            raise ValueError(f"No data files found in {path}")

        # Parse each file and concatenate
        dfs = []
        for file_path in data_files:
            try:
                df = self.parse_file(file_path, side)
                if df is not None and not df.empty:
                    dfs.append(df)
            except Exception as e:
                print(f"Warning: Failed to parse {file_path}: {e}")
                continue

        if not dfs:
            raise ValueError(f"No valid data could be parsed from {path}")

        # Concatenate all DataFrames
        combined_df = pd.concat(dfs, ignore_index=True)

        # Sort by timestamp
        combined_df.sort_values('timestamp', inplace=True)
        combined_df.reset_index(drop=True, inplace=True)

        return combined_df

    def parse_file(self, file_path: str, side: str) -> Optional[pd.DataFrame]:
        """
        Parse a socket log file

        Supported format:
        - Raw log format: Human-readable TCP socket analyzer output

        Args:
            file_path: Path to socket log file
            side: 'client' or 'server'

        Returns:
            DataFrame with parsed data, or None if parsing fails
        """
        try:
            df = self._parse_raw_log_file(file_path)
            if df is None or df.empty:
                return None

            # Add side column
            df['side'] = side

            return df

        except Exception as e:
            print(f"Error parsing file {file_path}: {e}")
            return None

    def _parse_raw_log_file(self, file_path: str) -> Optional[pd.DataFrame]:
        """
        Parse raw socket log file into DataFrame

        Uses unified conversion logic from convert_socket_log_to_csv.py

        Args:
            file_path: Path to raw socket log file

        Returns:
            DataFrame with parsed data, or None if parsing fails
        """
        try:
            # Use unified conversion logic
            records = parse_socket_log_to_records(file_path)

            if not records:
                return None

            # Convert to DataFrame
            df = pd.DataFrame(records)

            # Convert timestamp to datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

            # Define complete column list (102 fields total)
            # String columns
            string_columns = [
                'connection', 'state', 'congestion_algorithm', 'ca_state',
                'app_limited', 'tcp_features', 'wscale',
                'timer_state', 'cgroup_path', 'mptcp_flags'
            ]

            # Numeric columns
            numeric_columns = [
                # RTT and timeout metrics
                'rtt', 'rttvar', 'minrtt', 'rto',
                # Window metrics
                'cwnd', 'ssthresh', 'rwnd', 'rcv_ssthresh', 'snd_wnd',
                # MSS and MTU
                'mss', 'pmtu', 'advmss', 'rcvmss',
                # Window scaling
                'wscale_snd', 'wscale_rcv',
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
                'segs_out', 'segs_in', 'data_segs_out', 'data_segs_in',
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
                # Receiver metrics
                'rcv_rtt', 'ato',
                # Limitation statistics
                'busy_time',
                'rwnd_limited_time', 'rwnd_limited_ratio',
                'sndbuf_limited_time', 'sndbuf_limited_ratio',
                'cwnd_limited_time', 'cwnd_limited_ratio',
                # TCP options (boolean, stored as 0/1)
                'tcp_ecn', 'tcp_ecnseen', 'tcp_fastopen',
                # BDP calculation
                'bdp', 'recommended_window',
                # Timer information
                'timer_expires_ms', 'timer_retrans', 'backoff',
                # Socket identity
                'uid', 'ino', 'sk_cookie', 'bpf_id',
                'tos', 'tclass', 'priority',
                # BBR specific metrics
                'bbr_bw', 'bbr_mrtt', 'bbr_pacing_gain', 'bbr_cwnd_gain',
                # DCTCP specific metrics
                'dctcp_ce_state', 'dctcp_alpha', 'dctcp_ab_ecn', 'dctcp_ab_tot',
                # MPTCP specific metrics
                'mptcp_token', 'mptcp_seq', 'mptcp_maplen'
            ]

            # Add missing string columns with empty string
            for col in string_columns:
                if col not in df.columns:
                    df[col] = ''

            # Add missing numeric columns with 0.0
            for col in numeric_columns:
                if col not in df.columns:
                    df[col] = 0.0
                else:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

            return df

        except Exception as e:
            print(f"Error parsing raw log file {file_path}: {e}")
            return None

    def _validate_connection_match(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame
    ) -> None:
        """
        Validate that client and server connections match

        Validation logic:
        Client's src->dst should equal Server's dst<-src

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame

        Raises:
            ConnectionMismatchError: If connections don't match
        """
        if client_df.empty or server_df.empty:
            raise ConnectionMismatchError("Empty DataFrame provided")

        # Require single connection per side
        if client_df['connection'].nunique() != 1 or server_df['connection'].nunique() != 1:
            raise ConnectionMismatchError("Multiple connections detected in input; only single-flow analysis supported")

        # Get first connection from each side
        client_conn_str = client_df['connection'].iloc[0]
        server_conn_str = server_df['connection'].iloc[0]

        # Parse five-tuples
        client_ft = self._parse_connection_str(client_conn_str)
        server_ft = self._parse_connection_str(server_conn_str)

        # Check if they're reverse connections
        if not self._is_reverse_connection(client_ft, server_ft):
            raise ConnectionMismatchError(
                f"Connection mismatch:\n"
                f"  Client: {client_conn_str}\n"
                f"  Server: {server_conn_str}\n"
                f"  Expected server connection to be reverse of client"
            )

    def _align_dual_side_data(
        self,
        client_df: pd.DataFrame,
        server_df: pd.DataFrame,
        max_offset: float = 1.0
    ) -> pd.DataFrame:
        """
        Align client and server time-series data

        Algorithm:
        1. Add suffixes to all columns except timestamp (before merge)
        2. Use pandas merge_asof for nearest-neighbor timestamp matching
        3. Remove all-zero and all-null columns from aligned data
        4. Tolerance is max_offset seconds (default 1 second)

        Args:
            client_df: Client-side DataFrame
            server_df: Server-side DataFrame
            max_offset: Maximum time offset for matching (seconds)

        Returns:
            Aligned DataFrame with both client and server metrics
            All columns have _client or _server suffix (except timestamp)
        """
        # Reset index to ensure timestamp is a column
        client_reset = client_df.reset_index(drop=True).copy()
        server_reset = server_df.reset_index(drop=True).copy()

        # Manually add suffixes to all columns except timestamp
        # This ensures ALL columns get suffixes, even if they only exist on one side
        client_cols_to_rename = {col: f'{col}_client' for col in client_reset.columns if col != 'timestamp'}
        server_cols_to_rename = {col: f'{col}_server' for col in server_reset.columns if col != 'timestamp'}

        client_reset.rename(columns=client_cols_to_rename, inplace=True)
        server_reset.rename(columns=server_cols_to_rename, inplace=True)

        # Perform merge_asof (requires sorted data)
        # Now suffixes parameter won't be used since all columns already have suffixes
        aligned = pd.merge_asof(
            client_reset,
            server_reset,
            on='timestamp',
            direction='nearest',
            tolerance=pd.Timedelta(seconds=max_offset)
        )

        # Drop rows with missing data (no match within tolerance)
        aligned = aligned.dropna()

        # Remove all-zero and all-null columns
        # Keep only columns that have at least one non-zero, non-null value
        cols_to_keep = ['timestamp']  # Always keep timestamp
        for col in aligned.columns:
            if col == 'timestamp':
                continue

            # Check if column is all zeros or all nulls
            col_data = pd.to_numeric(aligned[col], errors='coerce')
            has_nonzero = (col_data != 0).any()
            has_nonnull = col_data.notna().any()

            # Keep if it has any non-zero or non-null values
            if has_nonzero or has_nonnull:
                # Additional check: if column is string type, check for non-empty strings
                if aligned[col].dtype == 'object':
                    has_nonempty = (aligned[col].astype(str).str.strip() != '').any()
                    if has_nonempty:
                        cols_to_keep.append(col)
                else:
                    cols_to_keep.append(col)

        aligned = aligned[cols_to_keep]

        # Set timestamp as index
        aligned.set_index('timestamp', inplace=True)

        return aligned

    def _parse_connection_str(self, conn_str: str) -> FiveTuple:
        """
        Parse connection string to FiveTuple

        Supported formats:
        - IPv4: "192.168.1.1:12345->192.168.1.2:80"
        - IPv4-mapped IPv6: "::ffff:192.168.1.1:12345->::ffff:192.168.1.2:80"

        Args:
            conn_str: Connection string

        Returns:
            FiveTuple object

        Raises:
            ValueError: If connection string format is invalid
        """
        # Normalize IPv4-mapped IPv6 to IPv4
        # Remove ::ffff: prefix if present
        normalized = conn_str.replace('::ffff:', '')

        # Match pattern: IP:PORT->IP:PORT
        pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)'
        match = re.match(pattern, normalized)

        if not match:
            raise ValueError(f"Invalid connection string format: {conn_str}")

        src_ip, src_port, dst_ip, dst_port = match.groups()

        return FiveTuple(
            src_ip=src_ip,
            src_port=int(src_port),
            dst_ip=dst_ip,
            dst_port=int(dst_port),
            protocol='TCP'
        )

    def _is_reverse_connection(self, ft1: FiveTuple, ft2: FiveTuple) -> bool:
        """
        Check if two five-tuples are reverse connections

        Args:
            ft1: First FiveTuple
            ft2: Second FiveTuple

        Returns:
            True if ft2 is reverse of ft1, False otherwise
        """
        return (
            ft1.src_ip == ft2.dst_ip and
            ft1.src_port == ft2.dst_port and
            ft1.dst_ip == ft2.src_ip and
            ft1.dst_port == ft2.src_port
        )
