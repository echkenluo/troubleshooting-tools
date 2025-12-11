#!/usr/bin/env python3
"""
Grafana CPU Statistics Tool

Query OVS and Network Cgroup CPU utilization statistics from Grafana/VictoriaMetrics.
Outputs percentile analysis (P50, P95, P99, Max) for each node in a cluster.

Usage:
    python3 grafana_cpu_stats.py --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG"
    python3 grafana_cpu_stats.py --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG" --hours 48
    python3 grafana_cpu_stats.py --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG" --start "2025-12-08 00:00:00" --end "2025-12-09 00:00:00"

Author: Claude Code
"""

import argparse
import base64
import json
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta


class GrafanaCPUStats:
    """Query and analyze CPU statistics from Grafana/VictoriaMetrics."""

    def __init__(self, server, user="o11y", password="HC!r0cks", step=30):
        self.server = server
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.step = step
        self.base_url = f"http://{server}/grafana/api/datasources/proxy/1/api/v1"

    def _request(self, endpoint, params=None):
        """Make authenticated request to Grafana API."""
        url = f"{self.base_url}/{endpoint}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Basic {self.auth}')

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            print(f"HTTP Error {e.code}: {e.reason}", file=sys.stderr)
            return None
        except Exception as e:
            print(f"Request error: {e}", file=sys.stderr)
            return None

    def get_clusters(self):
        """Get list of all available clusters."""
        query = 'cpu_cpuset_state_percent{_cpu="cpuset:/zbs/network",_state="idle"}'
        result = self._request("query", {"query": query})

        if not result or result.get('status') != 'success':
            return []

        clusters = sorted(set(
            r['metric'].get('cluster', '')
            for r in result.get('data', {}).get('result', [])
            if r['metric'].get('cluster')
        ))
        return clusters

    def get_cluster_info(self):
        """Get cluster information with node counts."""
        query = 'cpu_cpuset_state_percent{_cpu="cpuset:/zbs/network",_state="idle"}'
        result = self._request("query", {"query": query})

        if not result or result.get('status') != 'success':
            return {}

        cluster_nodes = {}
        for r in result.get('data', {}).get('result', []):
            cluster = r['metric'].get('cluster', '')
            hostname = r['metric'].get('hostname', '')
            if cluster and hostname:
                if cluster not in cluster_nodes:
                    cluster_nodes[cluster] = set()
                cluster_nodes[cluster].add(hostname)

        return {c: sorted(nodes) for c, nodes in cluster_nodes.items()}

    def get_cluster_nodes(self, cluster):
        """Get list of nodes in a cluster."""
        query = f'cpu_cpuset_state_percent{{cluster="{cluster}",_cpu="cpuset:/zbs/network",_state="idle"}}'
        result = self._request("query", {"query": query})

        if not result or result.get('status') != 'success':
            return []

        nodes = sorted(set(
            r['metric'].get('hostname', '')
            for r in result.get('data', {}).get('result', [])
        ))
        return nodes

    def query_range(self, query, start, end):
        """Execute range query and return results."""
        params = {
            'query': query,
            'start': int(start),
            'end': int(end),
            'step': self.step
        }
        return self._request("query_range", params)

    @staticmethod
    def calculate_percentiles(values):
        """Calculate percentile statistics for a list of values."""
        if not values:
            return {'p50': 0, 'p95': 0, 'p99': 0, 'max': 0, 'min': 0, 'count': 0}

        sorted_vals = sorted(values)
        n = len(sorted_vals)

        return {
            'p50': sorted_vals[int(n * 0.50)],
            'p95': sorted_vals[int(n * 0.95)] if n > 1 else sorted_vals[0],
            'p99': sorted_vals[int(n * 0.99)] if n > 1 else sorted_vals[0],
            'max': max(sorted_vals),
            'min': min(sorted_vals),
            'count': n
        }

    def get_ovs_cpu_stats(self, nodes, start, end):
        """Query OVS CPU utilization for nodes."""
        hostname_regex = "|".join(nodes)
        query = f'host_service_cpu_usage_percent{{hostname=~"{hostname_regex}",_service="ovs-vswitchd"}}'

        result = self.query_range(query, start, end)
        if not result or result.get('status') != 'success':
            return {}

        stats = {}
        for series in result['data']['result']:
            hostname = series['metric'].get('hostname', 'unknown')
            values = [float(v[1]) for v in series['values'] if v[1] != 'NaN']
            stats[hostname] = self.calculate_percentiles(values)

        return stats

    def get_network_cgroup_cpu_stats(self, cluster, start, end):
        """Query Network Cgroup CPU utilization for cluster."""
        query = f'(1 - cpu_cpuset_state_percent{{cluster="{cluster}",_cpu="cpuset:/zbs/network",_state="idle"}}) * 100'

        result = self.query_range(query, start, end)
        if not result or result.get('status') != 'success':
            return {}

        stats = {}
        for series in result['data']['result']:
            hostname = series['metric'].get('hostname', 'unknown')
            values = [float(v[1]) for v in series['values'] if v[1] != 'NaN']
            stats[hostname] = self.calculate_percentiles(values)

        return stats


def format_table(title, stats, short_names=True):
    """Format statistics as a table."""
    if not stats:
        return f"\n{title}\n  No data available\n"

    lines = []
    lines.append(f"\n{title}")
    lines.append("-" * 75)
    lines.append(f"{'Node':<30} | {'Count':>6} | {'P50':>7} | {'P95':>7} | {'P99':>7} | {'Max':>7}")
    lines.append("-" * 75)

    all_values_p50 = []
    all_values_p95 = []
    all_values_p99 = []
    all_values_max = []
    total_count = 0

    for hostname in sorted(stats.keys()):
        s = stats[hostname]
        name = hostname.replace('dogfood-idc-elf-', '') if short_names else hostname
        lines.append(f"{name:<30} | {s['count']:>6} | {s['p50']:>6.1f}% | {s['p95']:>6.1f}% | {s['p99']:>6.1f}% | {s['max']:>6.1f}%")

        all_values_p50.append(s['p50'])
        all_values_p95.append(s['p95'])
        all_values_p99.append(s['p99'])
        all_values_max.append(s['max'])
        total_count += s['count']

    # Cluster aggregate (average of node percentiles)
    if all_values_p50:
        lines.append("-" * 75)
        avg_p50 = sum(all_values_p50) / len(all_values_p50)
        avg_p95 = sum(all_values_p95) / len(all_values_p95)
        avg_p99 = sum(all_values_p99) / len(all_values_p99)
        max_max = max(all_values_max)
        lines.append(f"{'CLUSTER (avg/max)':<30} | {total_count:>6} | {avg_p50:>6.1f}% | {avg_p95:>6.1f}% | {avg_p99:>6.1f}% | {max_max:>6.1f}%")

    return "\n".join(lines)


def parse_datetime(dt_str):
    """Parse datetime string to timestamp."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt).timestamp()
        except ValueError:
            continue

    raise ValueError(f"Cannot parse datetime: {dt_str}")


def main():
    parser = argparse.ArgumentParser(
        description='Query OVS and Network Cgroup CPU statistics from Grafana',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # List all available clusters
  python3 %(prog)s --server 192.168.18.52 --list-clusters

  # List nodes in a cluster
  python3 %(prog)s --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG" --list-nodes

  # Query last 24 hours (default)
  python3 %(prog)s --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG"

  # Query last 48 hours
  python3 %(prog)s --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG" --hours 48

  # Query specific time range
  python3 %(prog)s --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG" \\
      --start "2025-12-08 00:00:00" --end "2025-12-09 00:00:00"

  # Output in JSON format
  python3 %(prog)s --server 192.168.18.52 --cluster "Dogfood-SMTXOS-63x-17.99-MLAG" --json
        '''
    )

    parser.add_argument('--server', '-s', required=True,
                        help='Grafana server address (e.g., 192.168.18.52)')
    parser.add_argument('--cluster', '-c',
                        help='Cluster name to query')
    parser.add_argument('--hours', '-H', type=int, default=24,
                        help='Number of hours to query (default: 24)')
    parser.add_argument('--start', type=str,
                        help='Start time (e.g., "2025-12-08 00:00:00")')
    parser.add_argument('--end', type=str,
                        help='End time (e.g., "2025-12-09 00:00:00")')
    parser.add_argument('--step', type=int, default=30,
                        help='Query step in seconds (default: 30, minimum granularity)')
    parser.add_argument('--user', '-u', default='o11y',
                        help='Grafana username (default: o11y)')
    parser.add_argument('--password', '-p', default='HC!r0cks',
                        help='Grafana password')
    parser.add_argument('--full-names', '-f', action='store_true',
                        help='Show full hostnames instead of short names')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output in JSON format')
    parser.add_argument('--list-clusters', '-L', action='store_true',
                        help='List all available clusters')
    parser.add_argument('--list-nodes', '-l', action='store_true',
                        help='List nodes in the cluster')

    args = parser.parse_args()

    # Initialize client
    client = GrafanaCPUStats(args.server, args.user, args.password, args.step)

    # Handle --list-clusters
    if args.list_clusters:
        sys.stderr.write(f"Querying clusters from {args.server}...\n")
        sys.stderr.flush()
        cluster_info = client.get_cluster_info()

        if not cluster_info:
            print("Error: No clusters found", file=sys.stderr)
            sys.exit(1)

        if args.json:
            print(json.dumps(cluster_info, indent=2))
        else:
            print("\n" + "=" * 60)
            print(f"Available Clusters on {args.server}")
            print("=" * 60)
            print(f"{'Cluster':<45} | {'Nodes':>6}")
            print("-" * 60)
            for cluster in sorted(cluster_info.keys()):
                node_count = len(cluster_info[cluster])
                print(f"{cluster:<45} | {node_count:>6}")
            print("-" * 60)
            print(f"Total: {len(cluster_info)} clusters")
            print("=" * 60)
        sys.exit(0)

    # Require --cluster for other operations
    if not args.cluster:
        print("Error: --cluster is required (use --list-clusters to see available clusters)", file=sys.stderr)
        sys.exit(1)

    # Get cluster nodes
    sys.stderr.write(f"Querying cluster: {args.cluster}\n")
    sys.stderr.flush()
    nodes = client.get_cluster_nodes(args.cluster)

    if not nodes:
        sys.stderr.write(f"Error: No nodes found in cluster '{args.cluster}'\n")
        sys.exit(1)

    sys.stderr.write(f"Found {len(nodes)} nodes\n")
    sys.stderr.flush()

    if args.list_nodes:
        if args.json:
            print(json.dumps({'cluster': args.cluster, 'nodes': nodes}, indent=2))
        else:
            print(f"\nCluster: {args.cluster}")
            print(f"Nodes ({len(nodes)}):")
            for node in nodes:
                print(f"  - {node}")
        sys.exit(0)

    # Determine time range
    if args.start and args.end:
        start_ts = parse_datetime(args.start)
        end_ts = parse_datetime(args.end)
    else:
        end_ts = time.time()
        start_ts = end_ts - (args.hours * 3600)

    # Calculate expected data points
    duration = end_ts - start_ts
    expected_points = int(duration / args.step) + 1

    # Print header
    start_dt = datetime.fromtimestamp(start_ts)
    end_dt = datetime.fromtimestamp(end_ts)

    print("=" * 75)
    print(f"Cluster: {args.cluster}")
    print(f"Server:  {args.server}")
    print(f"Period:  {start_dt} to {end_dt}")
    print(f"Step:    {args.step}s (expected points per node: {expected_points})")
    print(f"Nodes:   {len(nodes)}")
    print("=" * 75)

    # Query OVS CPU
    sys.stderr.write("Querying OVS CPU utilization...\n")
    sys.stderr.flush()
    ovs_stats = client.get_ovs_cpu_stats(nodes, start_ts, end_ts)

    time.sleep(0.5)  # Small delay to avoid rate limiting

    # Query Network Cgroup CPU
    sys.stderr.write("Querying Network Cgroup CPU utilization...\n")
    sys.stderr.flush()
    net_stats = client.get_network_cgroup_cpu_stats(args.cluster, start_ts, end_ts)

    if args.json:
        output = {
            'cluster': args.cluster,
            'server': args.server,
            'period': {
                'start': start_dt.isoformat(),
                'end': end_dt.isoformat(),
                'step': args.step
            },
            'nodes': nodes,
            'ovs_cpu': ovs_stats,
            'network_cgroup_cpu': net_stats
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_table(
            "OVS CPU Utilization (host_service_cpu_usage_percent{_service='ovs-vswitchd'})",
            ovs_stats,
            short_names=not args.full_names
        ))

        print(format_table(
            "\nNetwork Cgroup CPU Utilization ((1 - idle) * 100, 2 cores allocated)",
            net_stats,
            short_names=not args.full_names
        ))

    print("\n" + "=" * 75)


if __name__ == '__main__':
    main()
