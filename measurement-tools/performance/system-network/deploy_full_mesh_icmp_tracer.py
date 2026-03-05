#!/usr/bin/env python3
"""
Full Mesh ICMP RTT Tracer Deployment Tool

Deploys system_network_icmp_rtt.py across a cluster in full mesh topology for
monitoring ICMP latency between all node pairs through OVS datapath.

Usage:
    # Dry-run mode (generate commands without executing)
    python deploy_full_mesh_icmp_tracer.py --nodes 172.21.128.40,172.21.128.41,172.21.128.42 \
        --user smartx --network-type storage --tx-latency 4 --rx-latency 1 --dry-run

    # Execute deployment
    python deploy_full_mesh_icmp_tracer.py --nodes 172.21.128.40,172.21.128.41,172.21.128.42 \
        --user smartx --network-type storage --tx-latency 4 --rx-latency 1

    # Stop all tracers
    python deploy_full_mesh_icmp_tracer.py --nodes 172.21.128.40,172.21.128.41,172.21.128.42 \
        --user smartx --stop

Requirements:
    - Python 3.6+
    - SSH key-based auth configured between nodes (or provide --password)
    - system_network_icmp_rtt.py deployed to target nodes

Full Mesh Topology (3 nodes example):
    Node A monitors:
      - TX to B: traces when A pings B
      - TX to C: traces when A pings C
      - RX from B: traces when B pings A
      - RX from C: traces when C pings A

    Total: n*(n-1)*2 tracers for n nodes (TX and RX for each pair)
"""

import argparse
import json
import os
import sys

# Python 3.6 compatibility - avoid dataclasses
try:
    from typing import Dict, List, Optional, Tuple
except ImportError:
    pass

import subprocess
import re

script_dir = os.path.dirname(os.path.abspath(__file__))


class SimpleSSHExecutor:
    """Simple SSH executor using subprocess (no paramiko dependency)"""

    def __init__(self, host, user, password=None, timeout=60):
        self.host = host
        self.user = user
        self.password = password
        self.timeout = timeout

    def execute(self, cmd):
        """Execute command via SSH"""
        ssh_cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            "-o", "BatchMode=yes",
            "%s@%s" % (self.user, self.host),
            cmd
        ]
        try:
            # Python 3.6 compatible version (no capture_output)
            proc = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(timeout=self.timeout)
            return stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace'), proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1

    def execute_sudo(self, cmd):
        """Execute command with sudo via SSH"""
        return self.execute("sudo %s" % cmd)

    def close(self):
        pass


class SimpleNetworkCollector:
    """Simple network collector using subprocess SSH"""

    def __init__(self, executor):
        self.executor = executor

    def get_system_network_info(self, network_type):
        """Get system network info for specified type"""
        port_name = "port-%s" % network_type

        # Get IP address (try multiple paths for ip command)
        stdout, _, ret = self.executor.execute(
            "/sbin/ip addr show %s 2>/dev/null | grep 'inet ' || "
            "/usr/sbin/ip addr show %s 2>/dev/null | grep 'inet '" % (port_name, port_name)
        )
        ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', stdout)
        ip_address = ip_match.group(1) if ip_match else ""

        # Get OVS bridge
        stdout, _, _ = self.executor.execute_sudo(
            "ovs-vsctl port-to-br %s 2>/dev/null" % port_name
        )
        ovs_bridge = stdout.strip()

        # Check for uplink bridge
        uplink_bridge = "%s-uplink" % ovs_bridge if ovs_bridge else ""
        stdout, _, ret = self.executor.execute_sudo(
            "ovs-vsctl br-exists %s 2>/dev/null" % uplink_bridge
        )
        if ret != 0:
            uplink_bridge = ovs_bridge

        # Get physical NICs on uplink bridge
        physical_nics = []
        if uplink_bridge:
            stdout, _, _ = self.executor.execute_sudo(
                "ovs-vsctl list-ports %s 2>/dev/null" % uplink_bridge
            )
            ports = [p.strip() for p in stdout.strip().split('\n') if p.strip()]

            for port in ports:
                # Check if OVS bond
                stdout, _, ret = self.executor.execute_sudo(
                    "ovs-appctl bond/show %s 2>/dev/null" % port
                )
                if ret == 0 and 'member' in stdout.lower():
                    # Parse bond members
                    for line in stdout.split('\n'):
                        match = re.match(r'(?:member|slave)\s+(\S+):', line.strip())
                        if match:
                            physical_nics.append(match.group(1))
                else:
                    # Check if physical port (not vnet, internal, patch)
                    stdout, _, ret = self.executor.execute_sudo(
                        "ovs-vsctl get interface %s type 2>/dev/null" % port
                    )
                    port_type = stdout.strip().strip('"')
                    if port_type in ['', 'system'] and not port.startswith('vnet'):
                        physical_nics.append(port)

        return {
            "port_name": port_name,
            "port_type": network_type,
            "ip_address": ip_address,
            "ovs_bridge": ovs_bridge,
            "uplink_bridge": uplink_bridge,
            "physical_nics": physical_nics
        }


class NodeInfo:
    """Node network information"""
    def __init__(self, mgt_ip, network_ip="", network_type="", ovs_bridge="",
                 uplink_bridge="", physical_nics=None):
        self.mgt_ip = mgt_ip
        self.network_ip = network_ip
        self.network_type = network_type
        self.ovs_bridge = ovs_bridge
        self.uplink_bridge = uplink_bridge
        self.physical_nics = physical_nics if physical_nics is not None else []

    def to_dict(self):
        return {
            "mgt_ip": self.mgt_ip,
            "network_ip": self.network_ip,
            "network_type": self.network_type,
            "ovs_bridge": self.ovs_bridge,
            "uplink_bridge": self.uplink_bridge,
            "physical_nics": self.physical_nics
        }


class TracerCommand:
    """Single tracer command configuration"""
    def __init__(self, node_mgt_ip, src_ip, dst_ip, direction, interfaces,
                 latency_ms, log_file, full_command=""):
        self.node_mgt_ip = node_mgt_ip
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.direction = direction
        self.interfaces = interfaces
        self.latency_ms = latency_ms
        self.log_file = log_file
        self.full_command = full_command

    def to_dict(self):
        return {
            "node_mgt_ip": self.node_mgt_ip,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "direction": self.direction,
            "interfaces": self.interfaces,
            "latency_ms": self.latency_ms,
            "log_file": self.log_file,
            "full_command": self.full_command
        }


class FullMeshDeployer:
    """Full mesh ICMP RTT tracer deployer"""

    def __init__(self, nodes: List[str], user: str, password: Optional[str] = None,
                 network_type: str = "storage", tx_latency_ms: float = 0,
                 rx_latency_ms: float = 0, tool_path: str = None,
                 log_dir: str = "/tmp/icmp_tracer_logs", timeout: int = 60):
        self.nodes = nodes
        self.user = user
        self.password = password
        self.network_type = network_type
        self.tx_latency_ms = tx_latency_ms
        self.rx_latency_ms = rx_latency_ms
        self.log_dir = log_dir
        self.timeout = timeout

        # Default tool path (relative to current script)
        if tool_path is None:
            self.tool_path = os.path.join(script_dir, "system_network_icmp_rtt.py")
        else:
            self.tool_path = tool_path

        # Node info cache
        self.node_info: Dict[str, NodeInfo] = {}

    def collect_node_info(self, mgt_ip):
        """Collect network information from a single node"""
        if mgt_ip in self.node_info:
            return self.node_info[mgt_ip]

        print("Collecting network info from %s..." % mgt_ip)

        executor = SimpleSSHExecutor(mgt_ip, self.user, self.password, timeout=self.timeout)
        collector = SimpleNetworkCollector(executor)

        try:
            info = collector.get_system_network_info(self.network_type)

            if not info.get("ip_address"):
                raise ValueError("No %s network IP found on %s" % (self.network_type, mgt_ip))

            node_info = NodeInfo(
                mgt_ip=mgt_ip,
                network_ip=info["ip_address"],
                network_type=info["port_type"],
                ovs_bridge=info["ovs_bridge"],
                uplink_bridge=info["uplink_bridge"],
                physical_nics=info["physical_nics"]
            )

            self.node_info[mgt_ip] = node_info
            return node_info

        finally:
            executor.close()

    def collect_all_nodes(self) -> bool:
        """Collect network information from all nodes"""
        success = True
        for mgt_ip in self.nodes:
            try:
                self.collect_node_info(mgt_ip)
            except Exception as e:
                print("Error collecting info from %s: %s" % (mgt_ip, e))
                success = False
        return success

    def generate_log_filename(self, src_ip: str, dst_ip: str, direction: str) -> str:
        """Generate log filename: src-dst-direction.log"""
        # Convert IP to filename-safe format
        src_safe = src_ip.replace('.', '-')
        dst_safe = dst_ip.replace('.', '-')
        return "%s-%s-%s.log" % (src_safe, dst_safe, direction)

    def generate_tracer_command(self, node: NodeInfo, src_ip: str, dst_ip: str,
                                direction: str, latency_ms: float) -> TracerCommand:
        """Generate a single tracer command"""
        # Interface list (comma-separated for bond scenarios)
        if not node.physical_nics:
            raise ValueError("No physical NICs found for node %s, --phy-interface is required" % node.mgt_ip)

        iface_arg = ','.join(node.physical_nics)

        log_file = self.generate_log_filename(src_ip, dst_ip, direction)
        log_path = os.path.join(self.log_dir, log_file)

        # Build command (nohup first, then sudo)
        cmd_parts = [
            "nohup",
            "sudo",
            "python3",
            self.tool_path,
            "--src-ip", src_ip,
            "--dst-ip", dst_ip,
            "--direction", direction,
            "--disable-kernel-stacks",
            "--phy-interface", iface_arg
        ]

        if latency_ms > 0:
            cmd_parts.extend(["--latency-ms", str(int(latency_ms))])

        cmd_parts.extend([">", log_path, "2>&1", "&"])

        full_cmd = ' '.join(cmd_parts)

        return TracerCommand(
            node_mgt_ip=node.mgt_ip,
            src_ip=src_ip,
            dst_ip=dst_ip,
            direction=direction,
            interfaces=node.physical_nics,
            latency_ms=latency_ms,
            log_file=log_path,
            full_command=full_cmd
        )

    def generate_all_commands(self) -> Dict[str, List[TracerCommand]]:
        """Generate all tracer commands for full mesh deployment

        Returns:
            Dict mapping node mgt_ip to list of TracerCommand
        """
        commands: Dict[str, List[TracerCommand]] = {}

        for node_mgt_ip in self.nodes:
            commands[node_mgt_ip] = []
            node = self.node_info.get(node_mgt_ip)

            if not node:
                print("Warning: No info for node %s, skipping" % node_mgt_ip)
                continue

            # For each other node
            for other_mgt_ip in self.nodes:
                if other_mgt_ip == node_mgt_ip:
                    continue

                other = self.node_info.get(other_mgt_ip)
                if not other:
                    print("Warning: No info for node %s, skipping" % other_mgt_ip)
                    continue

                # TX mode: local (this node) pings remote (other node)
                # src=local, dst=remote
                tx_cmd = self.generate_tracer_command(
                    node=node,
                    src_ip=node.network_ip,
                    dst_ip=other.network_ip,
                    direction="tx",
                    latency_ms=self.tx_latency_ms
                )
                commands[node_mgt_ip].append(tx_cmd)

                # RX mode: remote (other node) pings local (this node)
                # src=remote, dst=local
                rx_cmd = self.generate_tracer_command(
                    node=node,
                    src_ip=other.network_ip,
                    dst_ip=node.network_ip,
                    direction="rx",
                    latency_ms=self.rx_latency_ms
                )
                commands[node_mgt_ip].append(rx_cmd)

        return commands

    def print_dry_run(self, commands: Dict[str, List[TracerCommand]]):
        """Print dry-run output"""
        print("\n" + "=" * 80)
        print("DRY-RUN: Full Mesh ICMP Tracer Deployment Plan")
        print("=" * 80)

        print("\nCluster Nodes:")
        for mgt_ip, node in self.node_info.items():
            print("  %s:" % mgt_ip)
            print("    Network Type: %s" % node.network_type)
            print("    Network IP:   %s" % node.network_ip)
            print("    OVS Bridge:   %s" % node.ovs_bridge)
            print("    Uplink:       %s" % node.uplink_bridge)
            print("    Physical NICs: %s" % ', '.join(node.physical_nics))

        print("\nLatency Thresholds:")
        print("  TX Latency: %.1f ms" % self.tx_latency_ms)
        print("  RX Latency: %.1f ms" % self.rx_latency_ms)

        print("\nLog Directory: %s" % self.log_dir)
        print("Tool Path:     %s" % self.tool_path)

        total_cmds = 0
        for mgt_ip, cmd_list in commands.items():
            print("\n" + "-" * 80)
            print("Node: %s (%s)" % (mgt_ip, self.node_info.get(mgt_ip, NodeInfo(mgt_ip)).network_ip))
            print("-" * 80)

            for cmd in cmd_list:
                print("\n  [%s] %s -> %s" % (cmd.direction.upper(), cmd.src_ip, cmd.dst_ip))
                print("    Interfaces: %s" % ', '.join(cmd.interfaces))
                print("    Latency:    %.1f ms" % cmd.latency_ms)
                print("    Log File:   %s" % cmd.log_file)
                print("    Command:")
                print("      %s" % cmd.full_command)
                total_cmds += 1

        print("\n" + "=" * 80)
        print("Summary: %d tracers across %d nodes" % (total_cmds, len(commands)))
        print("=" * 80)

    def execute_deployment(self, commands):
        """Execute deployment on all nodes"""
        print("\nStarting deployment...")

        success = True
        for mgt_ip, cmd_list in commands.items():
            print("\nDeploying to %s..." % mgt_ip)

            try:
                executor = SimpleSSHExecutor(mgt_ip, self.user, self.password, timeout=self.timeout)

                # Create log directory with write permission for current user
                stdout, stderr, ret = executor.execute_sudo("mkdir -p %s && chmod 777 %s" % (self.log_dir, self.log_dir))
                if ret != 0:
                    print("  Warning: Failed to create log directory: %s" % stderr)

                # Execute each command using setsid for proper daemon-style background execution
                for cmd in cmd_list:
                    print("  Starting %s tracer: %s -> %s" % (cmd.direction, cmd.src_ip, cmd.dst_ip))
                    # Use setsid inside sudo bash -c to ensure redirection works with root permissions
                    # Remove nohup/sudo from full_command, keep redirection
                    inner_cmd = cmd.full_command.replace("nohup sudo ", "").replace(" &", "")
                    # Wrap in sudo bash -c with setsid for proper daemon-style background
                    escaped_cmd = inner_cmd.replace("'", "'\\''")
                    wrapped_cmd = "sudo bash -c 'setsid %s </dev/null &'" % escaped_cmd
                    stdout, stderr, ret = executor.execute(wrapped_cmd)

                    if ret != 0:
                        print("    Error: %s" % stderr)
                        success = False
                    else:
                        print("    OK: Log -> %s" % cmd.log_file)

                executor.close()

            except Exception as e:
                print("  Error connecting to %s: %s" % (mgt_ip, e))
                success = False

        return success

    def stop_all_tracers(self):
        """Stop all system_network_icmp_rtt.py processes on all nodes"""
        print("\nStopping all tracers...")

        success = True
        for mgt_ip in self.nodes:
            print("\nStopping tracers on %s..." % mgt_ip)

            try:
                executor = SimpleSSHExecutor(mgt_ip, self.user, self.password, timeout=self.timeout)

                # Find and kill all system_network_icmp_rtt.py processes
                stdout, stderr, ret = executor.execute_sudo(
                    "pkill -f 'python3.*system_network_icmp_rtt.py' || true"
                )

                # Verify
                stdout, stderr, ret = executor.execute(
                    "pgrep -f 'system_network_icmp_rtt.py'"
                )

                if ret == 0 and stdout.strip():
                    print("  Warning: Some processes still running: %s" % stdout.strip())
                else:
                    print("  OK: All tracers stopped")

                executor.close()

            except Exception as e:
                print("  Error: %s" % e)
                success = False

        return success

    def check_status(self):
        """Check tracer status on all nodes"""
        print("\nChecking tracer status...")

        for mgt_ip in self.nodes:
            print("\n%s:" % mgt_ip)

            try:
                executor = SimpleSSHExecutor(mgt_ip, self.user, self.password, timeout=self.timeout)

                # Check running processes
                stdout, stderr, ret = executor.execute(
                    "ps aux | grep '[s]ystem_network_icmp_rtt.py'"
                )

                if ret == 0 and stdout.strip():
                    lines = stdout.strip().split('\n')
                    print("  Running tracers: %d" % len(lines))
                    for line in lines:
                        # Extract key info
                        parts = line.split()
                        if len(parts) > 10:
                            cmd_start = line.find('python')
                            if cmd_start >= 0:
                                print("    %s" % line[cmd_start:])
                else:
                    print("  No tracers running")

                executor.close()

            except Exception as e:
                print("  Error: %s" % e)

        return True


def main():
    parser = argparse.ArgumentParser(
        description="Deploy system_network_icmp_rtt.py in full mesh topology",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--nodes', type=str, required=True,
                        help='Comma-separated list of node management IPs')
    parser.add_argument('--user', type=str, default='smartx',
                        help='SSH username (default: smartx)')
    parser.add_argument('--password', type=str, default=None,
                        help='SSH password (optional, uses key auth if not provided)')
    parser.add_argument('--network-type', type=str, default='storage',
                        help='Network type to monitor (default: storage)')
    parser.add_argument('--tx-latency', type=float, default=0,
                        help='TX mode latency threshold in ms (default: 0, report all)')
    parser.add_argument('--rx-latency', type=float, default=0,
                        help='RX mode latency threshold in ms (default: 0, report all)')
    parser.add_argument('--tool-path', type=str, default=None,
                        help='Path to system_network_icmp_rtt.py on target nodes')
    parser.add_argument('--log-dir', type=str, default='/tmp/icmp_tracer_logs',
                        help='Log directory on target nodes (default: /tmp/icmp_tracer_logs)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Print commands without executing')
    parser.add_argument('--stop', action='store_true',
                        help='Stop all running tracers')
    parser.add_argument('--status', action='store_true',
                        help='Check tracer status on all nodes')
    parser.add_argument('--timeout', type=int, default=60,
                        help='SSH command timeout in seconds (default: 60)')
    parser.add_argument('--json', action='store_true',
                        help='Output in JSON format (for dry-run)')

    args = parser.parse_args()

    # Parse node list
    nodes = [n.strip() for n in args.nodes.split(',') if n.strip()]

    if len(nodes) < 2:
        print("Error: At least 2 nodes required for full mesh deployment")
        sys.exit(1)

    deployer = FullMeshDeployer(
        nodes=nodes,
        user=args.user,
        password=args.password,
        network_type=args.network_type,
        tx_latency_ms=args.tx_latency,
        rx_latency_ms=args.rx_latency,
        tool_path=args.tool_path,
        log_dir=args.log_dir,
        timeout=args.timeout
    )

    # Handle stop command
    if args.stop:
        deployer.stop_all_tracers()
        sys.exit(0)

    # Handle status command
    if args.status:
        deployer.check_status()
        sys.exit(0)

    # Collect node info
    if not deployer.collect_all_nodes():
        print("\nError: Failed to collect info from all nodes")
        sys.exit(1)

    # Generate commands
    commands = deployer.generate_all_commands()

    if args.dry_run:
        if args.json:
            # JSON output
            output = {
                "nodes": {ip: info.to_dict() for ip, info in deployer.node_info.items()},
                "commands": {
                    ip: [cmd.to_dict() for cmd in cmds]
                    for ip, cmds in commands.items()
                }
            }
            print(json.dumps(output, indent=2))
        else:
            deployer.print_dry_run(commands)
    else:
        # Execute deployment
        if deployer.execute_deployment(commands):
            print("\nDeployment completed successfully")
        else:
            print("\nDeployment completed with errors")
            sys.exit(1)


if __name__ == '__main__':
    main()
