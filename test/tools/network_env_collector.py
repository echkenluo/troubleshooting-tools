#!/usr/bin/env python3
"""
Network Environment Information Collector

Collects network environment information from KVM virtualization hosts:
1. System Network: OVS internal ports, bridges, physical NICs (single/bond)
2. VM Network: All virtio NICs info including vnet, tap fds, vhost fds, vhost PIDs

Usage:
    # System network info
    python network_env_collector.py system --host 192.168.75.101 --user smartx [--password xxx]
    python network_env_collector.py system --host 192.168.75.101 --user smartx --type mgt

    # VM network info (by UUID, collects all NICs)
    python network_env_collector.py vm --vm-host 192.168.73.72 --vm-user smartx \
        --host-ip 192.168.75.101 --host-user smartx --uuid ae6aa164-604c-4cb0-84b8-2dea034307f1
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


@dataclass
class PhysicalNIC:
    """Physical NIC information"""
    name: str
    speed: str = ""
    is_bond: bool = False
    bond_type: str = ""  # "ovs" or "linux"
    bond_members: List[str] = field(default_factory=list)
    member_speeds: Dict[str, str] = field(default_factory=dict)


@dataclass
class SystemNetworkInfo:
    """System network (OVS internal port) information"""
    port_name: str
    port_type: str  # mgt, storage, access, vpc, etc.
    ip_address: str = ""
    ovs_bridge: str = ""
    uplink_bridge: str = ""  # may be different from ovs_bridge for patch port cases
    physical_nics: List[PhysicalNIC] = field(default_factory=list)


@dataclass
class VhostInfo:
    """Vhost process information"""
    pid: int
    name: str = ""


@dataclass
class VMNicInfo:
    """Single VM NIC information"""
    mac: str
    vm_nic_name: str = ""       # NIC name inside VM (e.g., ens4, eth0)
    vm_ip: str = ""             # IP address inside VM
    host_vnet: str = ""         # vnet interface on host
    tap_fds: List[int] = field(default_factory=list)
    vhost_fds: List[int] = field(default_factory=list)
    vhost_pids: List[VhostInfo] = field(default_factory=list)
    ovs_bridge: str = ""
    uplink_bridge: str = ""
    physical_nics: List[PhysicalNIC] = field(default_factory=list)


@dataclass
class VMInfo:
    """VM information with all NICs"""
    vm_uuid: str
    vm_name: str = ""
    qemu_pid: int = 0
    nics: List[VMNicInfo] = field(default_factory=list)


class SSHExecutor:
    """SSH command executor with persistent paramiko connection"""

    def __init__(self, host: str, user: str, password: Optional[str] = None, timeout: int = 60):
        self.host = host
        self.user = user
        self.password = password
        self.timeout = timeout
        self._client = None
        self._connect()

    def _connect(self):
        """Establish persistent SSH connection using paramiko"""
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("paramiko is required. Install with: pip install paramiko")

        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Try key-based auth first, then password
        try:
            if self.password:
                self._client.connect(
                    hostname=self.host,
                    username=self.user,
                    password=self.password,
                    timeout=min(30, self.timeout),
                    allow_agent=True,
                    look_for_keys=True
                )
            else:
                self._client.connect(
                    hostname=self.host,
                    username=self.user,
                    timeout=min(30, self.timeout),
                    allow_agent=True,
                    look_for_keys=True
                )
        except Exception as e:
            raise RuntimeError(f"Failed to connect to {self.user}@{self.host}: {e}")

    def _ensure_connected(self):
        """Ensure connection is still active, reconnect if needed"""
        if self._client is None:
            self._connect()
            return

        try:
            transport = self._client.get_transport()
            if transport is None or not transport.is_active():
                self._connect()
        except Exception:
            self._connect()

    def execute(self, cmd: str) -> Tuple[str, str, int]:
        """Execute command via persistent SSH connection"""
        self._ensure_connected()

        try:
            stdin, stdout, stderr = self._client.exec_command(cmd, timeout=self.timeout)
            exit_status = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')
            return stdout_data, stderr_data, exit_status
        except Exception as e:
            # Try to reconnect and retry once
            try:
                self._connect()
                stdin, stdout, stderr = self._client.exec_command(cmd, timeout=self.timeout)
                exit_status = stdout.channel.recv_exit_status()
                stdout_data = stdout.read().decode('utf-8', errors='replace')
                stderr_data = stderr.read().decode('utf-8', errors='replace')
                return stdout_data, stderr_data, exit_status
            except Exception as e2:
                return "", str(e2), 1

    def execute_sudo(self, cmd: str) -> Tuple[str, str, int]:
        """Execute command with sudo via SSH"""
        return self.execute(f"sudo {cmd}")

    def close(self):
        """Close SSH connection"""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __del__(self):
        self.close()


class NetworkEnvCollector:
    """Network environment information collector"""

    def __init__(self, executor: SSHExecutor):
        self.executor = executor
        self._bridge_nics_cache: Dict[str, List[PhysicalNIC]] = {}  # Cache for get_physical_nics_on_bridge

    def get_ovs_internal_ports(self) -> List[Tuple[str, str]]:
        """Get all OVS internal ports (port-xxx pattern)

        Returns:
            List of (port_name, bridge_name) tuples
        """
        stdout, _, _ = self.executor.execute_sudo("ovs-vsctl show")

        ports = []
        current_bridge = None

        for line in stdout.split('\n'):
            line = line.strip()
            # Match Bridge line
            if line.startswith('Bridge '):
                # Extract bridge name, handling both quoted and unquoted
                match = re.match(r'Bridge\s+"?([^"\s]+)"?', line)
                if match:
                    current_bridge = match.group(1)
            # Match Port line with port- prefix
            elif line.startswith('Port ') and current_bridge:
                match = re.match(r'Port\s+"?(port-[^"\s]+)"?', line)
                if match:
                    port_name = match.group(1)
                    ports.append((port_name, current_bridge))

        return ports

    def get_port_ip(self, port_name: str) -> str:
        """Get IP address of an interface"""
        # Try multiple paths for ip command
        stdout, _, ret = self.executor.execute(f"/sbin/ip addr show {port_name} 2>/dev/null || /usr/sbin/ip addr show {port_name} 2>/dev/null || ip addr show {port_name} 2>/dev/null")
        if ret != 0:
            return ""

        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', stdout)
        return match.group(1) if match else ""

    def get_bridge_ports(self, bridge: str) -> List[str]:
        """Get all ports on an OVS bridge"""
        stdout, _, _ = self.executor.execute_sudo(f"ovs-vsctl list-ports {bridge}")
        return [p.strip() for p in stdout.strip().split('\n') if p.strip()]

    def get_patch_peer_bridge(self, bridge: str) -> Optional[str]:
        """Find peer bridge connected via patch ports

        Look for bridge with name pattern: {bridge}-uplink
        """
        uplink_bridge = f"{bridge}-uplink"
        stdout, _, ret = self.executor.execute_sudo(f"ovs-vsctl br-exists {uplink_bridge}")
        if ret == 0:
            return uplink_bridge
        return None

    def is_ovs_bond(self, port: str) -> bool:
        """Check if a port is an OVS bond"""
        stdout, _, ret = self.executor.execute_sudo(
            f"ovs-vsctl get port {port} bond_mode 2>/dev/null"
        )
        bond_mode = stdout.strip().strip('"').strip('[]')
        # If bond_mode is not empty, it's a bond
        return ret == 0 and bond_mode != ''

    def is_physical_port(self, port: str, bridge: str) -> bool:
        """Check if a port is a physical port or OVS bond (not internal, patch, vnet, etc.)"""
        # First check if it's an OVS bond
        if self.is_ovs_bond(port):
            return True

        # Get interface type
        stdout, _, ret = self.executor.execute_sudo(
            f"ovs-vsctl get interface {port} type 2>/dev/null"
        )
        if ret != 0:
            # Interface doesn't exist (might be bond), skip
            return False

        port_type = stdout.strip().strip('"')

        # Physical ports have empty type or "system" type
        if port_type in ['', 'system']:
            # Additional check: not vnet* pattern
            if not port.startswith('vnet'):
                return True
        return False

    def get_ovs_bond_info(self, bond_name: str) -> Tuple[List[str], str]:
        """Get OVS bond member ports

        Returns:
            Tuple of (member_ports, bond_mode)
        """
        # Get bond members using ovs-appctl
        stdout, _, ret = self.executor.execute_sudo(
            f"ovs-appctl bond/show {bond_name}"
        )
        if ret != 0:
            return [], ""

        members = []
        bond_mode = ""

        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('bond_mode:'):
                bond_mode = line.split(':')[1].strip()
            elif line.startswith('member ') or line.startswith('slave '):
                # Format: "member eth0: enabled" or "slave eth0: enabled"
                match = re.match(r'(?:member|slave)\s+(\S+):', line)
                if match:
                    members.append(match.group(1))

        return members, bond_mode

    def get_linux_bond_info(self, bond_name: str) -> Tuple[List[str], str]:
        """Get Linux bond member ports

        Returns:
            Tuple of (member_ports, bond_mode)
        """
        # Check if it's a Linux bond
        stdout, _, ret = self.executor.execute(f"cat /sys/class/net/{bond_name}/bonding/slaves 2>/dev/null")
        if ret != 0:
            return [], ""

        members = stdout.strip().split()

        # Get bond mode
        stdout, _, _ = self.executor.execute(f"cat /sys/class/net/{bond_name}/bonding/mode 2>/dev/null")
        bond_mode = stdout.strip().split()[0] if stdout.strip() else ""

        return members, bond_mode

    def get_nic_speed(self, nic: str) -> str:
        """Get NIC speed using ethtool"""
        stdout, _, ret = self.executor.execute_sudo(f"ethtool {nic} 2>/dev/null | grep Speed")
        if ret != 0 or not stdout.strip():
            return "unknown"

        match = re.search(r'Speed:\s*(\S+)', stdout)
        return match.group(1) if match else "unknown"

    def get_physical_nics_on_bridge(self, bridge: str) -> List[PhysicalNIC]:
        """Get physical NICs on a bridge (handles bonds)

        Optimized version using batch OVS queries to reduce SSH calls.
        """
        # Check cache first
        if bridge in self._bridge_nics_cache:
            return self._bridge_nics_cache[bridge]

        # Get all ports on bridge
        ports = self.get_bridge_ports(bridge)
        if not ports:
            self._bridge_nics_cache[bridge] = []
            return []

        # Batch get interface types and bond modes in one command
        ports_str = ' '.join(ports)
        stdout, _, _ = self.executor.execute_sudo(
            f"bash -c 'for p in {ports_str}; do "
            f"t=$(ovs-vsctl get interface $p type 2>/dev/null); "
            f"b=$(ovs-vsctl get port $p bond_mode 2>/dev/null); "
            f"echo \"PORT:$p TYPE:$t BOND:$b\"; done'"
        )

        # Parse results to find physical ports and bonds
        port_info = {}
        for line in stdout.strip().split('\n'):
            if not line.startswith('PORT:'):
                continue
            # Parse: PORT:eth0 TYPE:"" BOND:[]
            parts = line.split()
            port_name = parts[0].replace('PORT:', '')
            port_type = ''
            is_bond = False
            for part in parts[1:]:
                if part.startswith('TYPE:'):
                    port_type = part.replace('TYPE:', '').strip('"')
                elif part.startswith('BOND:'):
                    bond_val = part.replace('BOND:', '').strip('"[]')
                    is_bond = bool(bond_val)
            port_info[port_name] = {'type': port_type, 'is_bond': is_bond}

        # Identify physical ports (empty type or system, not vnet*)
        physical_port_names = []
        for port, info in port_info.items():
            if info['is_bond'] or (info['type'] in ['', 'system'] and not port.startswith('vnet')):
                physical_port_names.append(port)

        if not physical_port_names:
            self._bridge_nics_cache[bridge] = []
            return []

        # Batch get bond info and speeds
        physical_nics = []
        for port in physical_port_names:
            if port_info[port]['is_bond']:
                # Get OVS bond info
                ovs_members, ovs_mode = self.get_ovs_bond_info(port)
                if ovs_members:
                    nic = PhysicalNIC(
                        name=port,
                        is_bond=True,
                        bond_type="ovs",
                        bond_members=ovs_members
                    )
                    # Batch get speeds for members
                    members_str = ' '.join(ovs_members)
                    stdout, _, _ = self.executor.execute_sudo(
                        f"bash -c 'for n in {members_str}; do echo \"NIC:$n $(ethtool $n 2>/dev/null | grep Speed)\"; done'"
                    )
                    for line in stdout.strip().split('\n'):
                        if line.startswith('NIC:'):
                            parts = line.split()
                            member = parts[0].replace('NIC:', '')
                            speed_match = re.search(r'Speed:\s*(\S+)', line)
                            nic.member_speeds[member] = speed_match.group(1) if speed_match else "unknown"
                    if ovs_members:
                        nic.speed = nic.member_speeds.get(ovs_members[0], "unknown")
                    physical_nics.append(nic)
                    continue

            # Check Linux bond
            linux_members, linux_mode = self.get_linux_bond_info(port)
            if linux_members:
                nic = PhysicalNIC(
                    name=port,
                    is_bond=True,
                    bond_type="linux",
                    bond_members=linux_members
                )
                members_str = ' '.join(linux_members)
                stdout, _, _ = self.executor.execute_sudo(
                    f"bash -c 'for n in {members_str}; do echo \"NIC:$n $(ethtool $n 2>/dev/null | grep Speed)\"; done'"
                )
                for line in stdout.strip().split('\n'):
                    if line.startswith('NIC:'):
                        parts = line.split()
                        member = parts[0].replace('NIC:', '')
                        speed_match = re.search(r'Speed:\s*(\S+)', line)
                        nic.member_speeds[member] = speed_match.group(1) if speed_match else "unknown"
                if linux_members:
                    nic.speed = nic.member_speeds.get(linux_members[0], "unknown")
                physical_nics.append(nic)
                continue

            # Single physical NIC
            nic = PhysicalNIC(
                name=port,
                speed=self.get_nic_speed(port),
                is_bond=False
            )
            physical_nics.append(nic)

        # Store in cache
        self._bridge_nics_cache[bridge] = physical_nics
        return physical_nics

    def collect_system_network_info(self, port_type: Optional[str] = None) -> List[SystemNetworkInfo]:
        """Collect system network information

        Args:
            port_type: Optional filter for specific port type (mgt, storage, etc.)

        Returns:
            List of SystemNetworkInfo
        """
        results = []
        internal_ports = self.get_ovs_internal_ports()

        for port_name, bridge in internal_ports:
            # Extract type from port name (port-xxx -> xxx)
            match = re.match(r'port-(\w+)', port_name)
            if not match:
                continue

            p_type = match.group(1)

            # Filter by type if specified
            if port_type and p_type != port_type:
                continue

            info = SystemNetworkInfo(
                port_name=port_name,
                port_type=p_type,
                ip_address=self.get_port_ip(port_name),
                ovs_bridge=bridge
            )

            # Check for uplink bridge (patch port case)
            uplink_bridge = self.get_patch_peer_bridge(bridge)
            if uplink_bridge:
                info.uplink_bridge = uplink_bridge
                info.physical_nics = self.get_physical_nics_on_bridge(uplink_bridge)
            else:
                info.uplink_bridge = bridge
                info.physical_nics = self.get_physical_nics_on_bridge(bridge)

            results.append(info)

        return results

    def get_vm_nic_info_by_mac(self, mac: str) -> Tuple[str, str]:
        """Get VM NIC name and IP by MAC address (run inside VM)

        Returns:
            Tuple of (nic_name, ip_address)
        """
        # Get all interfaces
        stdout, _, _ = self.executor.execute("/sbin/ip -o link show 2>/dev/null || /usr/sbin/ip -o link show 2>/dev/null || ip -o link show")

        nic_name = ""
        mac_lower = mac.lower()

        for line in stdout.split('\n'):
            if mac_lower in line.lower():
                # Format: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                match = re.match(r'\d+:\s+(\S+):', line)
                if match:
                    nic_name = match.group(1)
                    break

        if not nic_name:
            return "", ""

        # Get IP address
        ip_addr = self.get_port_ip(nic_name)

        return nic_name, ip_addr

    def get_vnet_by_mac(self, mac: str) -> Tuple[str, str]:
        """Get host vnet interface and VM name by MAC (run on host)

        Returns:
            Tuple of (vnet_name, vm_name)
        """
        # List all running VMs
        stdout, _, _ = self.executor.execute_sudo("virsh list --name")
        vms = [v.strip() for v in stdout.strip().split('\n') if v.strip()]

        mac_lower = mac.lower()

        for vm in vms:
            # Get VM XML
            stdout, _, ret = self.executor.execute_sudo(f"virsh dumpxml {vm}")
            if ret != 0:
                continue

            # Look for interface with matching MAC
            # Pattern: <mac address='52:54:00:51:a3:8b'/>
            #          <target dev='vnet0'/>
            if mac_lower in stdout.lower():
                # Find the interface block containing this MAC
                # Parse XML-like content (simplified, not full XML parsing)
                interfaces = re.findall(
                    r"<interface[^>]*>.*?</interface>",
                    stdout, re.DOTALL
                )

                for iface in interfaces:
                    if mac_lower in iface.lower():
                        # Extract target dev
                        match = re.search(r"<target\s+dev='([^']+)'", iface)
                        if match:
                            return match.group(1), vm

        return "", ""

    def get_vnet_bridge(self, vnet: str) -> str:
        """Get OVS bridge for a vnet interface"""
        stdout, _, ret = self.executor.execute_sudo(f"ovs-vsctl port-to-br {vnet}")
        if ret != 0:
            return ""
        return stdout.strip()

    def get_qemu_pid_by_vm_name(self, vm_name: str) -> int:
        """Get qemu-kvm process PID by VM name (run on host)

        Args:
            vm_name: VM name (domain name)

        Returns:
            qemu-kvm process PID, 0 if not found
        """
        # Method 1: Use virsh dompid (most reliable)
        stdout, _, ret = self.executor.execute_sudo(f"virsh dompid {vm_name}")
        if ret == 0 and stdout.strip():
            try:
                return int(stdout.strip())
            except ValueError:
                pass

        # Method 2: Read PID file
        stdout, _, ret = self.executor.execute_sudo(
            f"cat /var/run/libvirt/qemu/{vm_name}.pid"
        )
        if ret == 0 and stdout.strip():
            try:
                return int(stdout.strip())
            except ValueError:
                pass

        # Method 3: Fallback to ps + grep (filter for actual qemu-kvm process)
        stdout, _, ret = self.executor.execute(
            f"ps aux | grep '[q]emu.*guest={vm_name}' | awk '{{print $2}}' | head -1"
        )
        if ret == 0 and stdout.strip():
            try:
                return int(stdout.strip())
            except ValueError:
                pass

        return 0

    def get_vhost_pids_by_qemu_pid(self, qemu_pid: int) -> List[VhostInfo]:
        """Get vhost process PIDs associated with a qemu process (run on host)

        Args:
            qemu_pid: qemu-kvm process PID

        Returns:
            List of VhostInfo with vhost process PIDs
        """
        if qemu_pid <= 0:
            return []

        # vhost threads are kernel threads named [vhost-<qemu_pid>]
        stdout, _, ret = self.executor.execute(
            f"ps -eo pid,comm | grep 'vhost-{qemu_pid}'"
        )
        if ret != 0 or not stdout.strip():
            return []

        vhost_list = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[0])
                    name = parts[1] if len(parts) > 1 else f"vhost-{qemu_pid}"
                    vhost_list.append(VhostInfo(pid=pid, name=name))
                except ValueError:
                    continue

        return vhost_list

    def get_all_vm_nics_from_xml(self, vm_name: str) -> List[Dict]:
        """Get all VM NICs info from virsh dumpxml

        Args:
            vm_name: VM name (domain name)

        Returns:
            List of dicts with mac, vnet, queues for each NIC
        """
        stdout, _, ret = self.executor.execute_sudo(f"virsh dumpxml {vm_name}")
        if ret != 0:
            return []

        nics = []
        # Find all interface blocks
        interfaces = re.findall(
            r"<interface[^>]*type='bridge'[^>]*>.*?</interface>",
            stdout, re.DOTALL
        )

        for iface in interfaces:
            nic_info = {}

            # Extract MAC
            mac_match = re.search(r"<mac\s+address='([^']+)'", iface)
            if mac_match:
                nic_info['mac'] = mac_match.group(1)

            # Extract vnet (target dev)
            vnet_match = re.search(r"<target\s+dev='([^']+)'", iface)
            if vnet_match:
                nic_info['vnet'] = vnet_match.group(1)

            # Extract queue count
            queues_match = re.search(r"queues='(\d+)'", iface)
            nic_info['queues'] = int(queues_match.group(1)) if queues_match else 1

            if 'mac' in nic_info and 'vnet' in nic_info:
                nics.append(nic_info)

        return nics

    def get_tap_fd_to_vnet_mapping(self, qemu_pid: int) -> Dict[str, List[int]]:
        """Get mapping of vnet to tap fds from /proc/fdinfo

        Args:
            qemu_pid: qemu-kvm process PID

        Returns:
            Dict mapping vnet name to list of tap fds
        """
        if qemu_pid <= 0:
            return {}

        # Get all fds pointing to /dev/net/tun
        stdout, _, ret = self.executor.execute_sudo(
            f"ls -la /proc/{qemu_pid}/fd 2>/dev/null | grep '/dev/net/tun'"
        )
        if ret != 0 or not stdout.strip():
            return {}

        tap_fds = []
        for line in stdout.strip().split('\n'):
            # Extract fd number from: "lrwx------ 1 qemu qemu 64 ... 47 -> /dev/net/tun"
            match = re.search(r'\s(\d+)\s+->', line)
            if match:
                tap_fds.append(int(match.group(1)))

        if not tap_fds:
            return {}

        # Batch read all fdinfo files in one command
        fd_list = ' '.join(str(fd) for fd in tap_fds)
        stdout, _, ret = self.executor.execute_sudo(
            f"bash -c 'for fd in {fd_list}; do echo FD:$fd; grep \"^iff:\" /proc/{qemu_pid}/fdinfo/$fd 2>/dev/null; done'"
        )

        vnet_to_fds = {}
        current_fd = None
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('FD:'):
                current_fd = int(line[3:])
            elif line.startswith('iff:') and current_fd is not None:
                vnet = line.split()[-1]
                if vnet not in vnet_to_fds:
                    vnet_to_fds[vnet] = []
                vnet_to_fds[vnet].append(current_fd)

        # Sort fds for each vnet
        for vnet in vnet_to_fds:
            vnet_to_fds[vnet].sort()

        return vnet_to_fds

    def get_vhost_fd_to_vnet_mapping(self, qemu_pid: int, tap_fd_mapping: Dict[str, List[int]]) -> Dict[str, List[int]]:
        """Get mapping of vnet to vhost fds based on fd ordering

        Uses fd ordering instead of timestamps - fd allocation is sequential within a process.

        Args:
            qemu_pid: qemu-kvm process PID
            tap_fd_mapping: mapping of vnet to tap fds

        Returns:
            Dict mapping vnet name to list of vhost fds
        """
        if qemu_pid <= 0 or not tap_fd_mapping:
            return {}

        # Get all vhost fds
        stdout, _, ret = self.executor.execute_sudo(
            f"ls -la /proc/{qemu_pid}/fd 2>/dev/null | grep '/dev/vhost-net'"
        )
        if ret != 0 or not stdout.strip():
            return {}

        vhost_fds = []
        for line in stdout.strip().split('\n'):
            match = re.search(r'\s(\d+)\s+->', line)
            if match:
                vhost_fds.append(int(match.group(1)))
        vhost_fds.sort()

        # Sort vnets by minimum tap fd (fd allocation order is reliable)
        vnets_sorted = sorted(
            tap_fd_mapping.items(),
            key=lambda x: min(x[1]) if x[1] else float('inf')
        )

        # Assign vhost fds to vnets sequentially based on queue count
        vnet_to_vhost_fds = {}
        fd_index = 0

        for vnet, tap_fds in vnets_sorted:
            queue_count = len(tap_fds)
            if fd_index + queue_count <= len(vhost_fds):
                vnet_to_vhost_fds[vnet] = vhost_fds[fd_index:fd_index + queue_count]
                fd_index += queue_count

        return vnet_to_vhost_fds

    def get_vhost_pids_grouped_by_vnet(self, qemu_pid: int, tap_fd_mapping: Dict[str, List[int]]) -> Dict[str, List[VhostInfo]]:
        """Get vhost PIDs grouped by vnet based on fd and PID ordering

        Strategy:
        1. Sort vnets by minimum tap fd (fd allocation order is reliable)
        2. Sort all vhost threads by PID (PID allocation order is reliable within single boot)
        3. Assign vhost threads to vnets sequentially based on queue count

        This works because:
        - QEMU creates NICs in order defined in XML
        - Each NIC's tap fds and vhost threads are created together
        - fd and PID allocation is sequential

        Args:
            qemu_pid: qemu-kvm process PID
            tap_fd_mapping: mapping of vnet to tap fds (queue count = len(fds))

        Returns:
            Dict mapping vnet name to list of VhostInfo
        """
        if qemu_pid <= 0 or not tap_fd_mapping:
            return {}

        # Get all vhost threads
        stdout, _, ret = self.executor.execute(
            f"ps -eo pid,comm | grep 'vhost-{qemu_pid}'"
        )
        if ret != 0 or not stdout.strip():
            return {}

        vhost_threads = []
        for line in stdout.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    pid = int(parts[0])
                    name = parts[1]
                    vhost_threads.append(VhostInfo(pid=pid, name=name))
                except ValueError:
                    continue

        # Sort vhost threads by PID (ascending)
        vhost_threads.sort(key=lambda x: x.pid)

        # Sort vnets by minimum tap fd (lower fd = earlier created NIC)
        vnets_sorted = sorted(
            tap_fd_mapping.items(),
            key=lambda x: min(x[1]) if x[1] else float('inf')
        )

        # Assign vhost threads to vnets sequentially based on queue count
        vnet_to_vhost_pids = {}
        thread_index = 0

        for vnet, tap_fds in vnets_sorted:
            queue_count = len(tap_fds)
            if thread_index + queue_count <= len(vhost_threads):
                vnet_to_vhost_pids[vnet] = vhost_threads[thread_index:thread_index + queue_count]
                thread_index += queue_count

        return vnet_to_vhost_pids

    def get_vm_nic_ip_by_mac(self, mac: str) -> Tuple[str, str]:
        """Get VM NIC name and IP by MAC address (run inside VM)

        Args:
            mac: MAC address to look up

        Returns:
            Tuple of (nic_name, ip_address)
        """
        return self.get_vm_nic_info_by_mac(mac)


def collect_system_network(args):
    """Collect system network information"""
    executor = SSHExecutor(args.host, args.user, args.password, timeout=args.timeout)
    collector = NetworkEnvCollector(executor)

    results = collector.collect_system_network_info(args.type)

    # Convert to dict for JSON output
    output = []
    for info in results:
        d = asdict(info)
        output.append(d)

    print(json.dumps(output, indent=2, ensure_ascii=False))
    return results


def collect_vm_network(args):
    """Collect VM network information for all NICs"""
    # Connect to host first to get VM info
    host_executor = SSHExecutor(args.host_ip, args.host_user, args.host_password, timeout=args.timeout)
    host_collector = NetworkEnvCollector(host_executor)

    vm_uuid = args.uuid
    vm_name = vm_uuid  # Use UUID as VM name (domain name)

    # Get qemu PID
    qemu_pid = host_collector.get_qemu_pid_by_vm_name(vm_name)
    if qemu_pid <= 0:
        print(f"Error: Cannot find qemu process for VM {vm_uuid}", file=sys.stderr)
        sys.exit(1)

    # Get all NICs from virsh dumpxml
    nics_from_xml = host_collector.get_all_vm_nics_from_xml(vm_name)
    if not nics_from_xml:
        print(f"Error: No NICs found for VM {vm_uuid}", file=sys.stderr)
        sys.exit(1)

    # Get tap fd to vnet mapping
    tap_fd_mapping = host_collector.get_tap_fd_to_vnet_mapping(qemu_pid)

    # Get vhost fd to vnet mapping
    vhost_fd_mapping = host_collector.get_vhost_fd_to_vnet_mapping(qemu_pid, tap_fd_mapping)

    # Get vhost PIDs grouped by vnet (use tap_fd_mapping for ordering)
    vhost_pid_mapping = host_collector.get_vhost_pids_grouped_by_vnet(qemu_pid, tap_fd_mapping)

    # Connect to VM to get NIC names and IPs
    vm_executor = None
    vm_collector = None
    if args.vm_host and args.vm_user:
        try:
            vm_executor = SSHExecutor(args.vm_host, args.vm_user, args.vm_password, timeout=args.timeout)
            vm_collector = NetworkEnvCollector(vm_executor)
        except Exception as e:
            print(f"Warning: Cannot connect to VM: {e}", file=sys.stderr)

    # Build VMInfo with all NICs
    vm_info = VMInfo(
        vm_uuid=vm_uuid,
        vm_name=vm_name,
        qemu_pid=qemu_pid
    )

    for nic_xml in nics_from_xml:
        mac = nic_xml['mac']
        vnet = nic_xml['vnet']

        nic_info = VMNicInfo(
            mac=mac,
            host_vnet=vnet,
            tap_fds=tap_fd_mapping.get(vnet, []),
            vhost_fds=vhost_fd_mapping.get(vnet, []),
            vhost_pids=vhost_pid_mapping.get(vnet, [])
        )

        # Get NIC name and IP from inside VM
        if vm_collector:
            try:
                nic_name, ip_addr = vm_collector.get_vm_nic_ip_by_mac(mac)
                nic_info.vm_nic_name = nic_name
                nic_info.vm_ip = ip_addr
            except Exception:
                pass

        # Get OVS bridge info
        bridge = host_collector.get_vnet_bridge(vnet)
        nic_info.ovs_bridge = bridge

        if bridge:
            uplink_bridge = host_collector.get_patch_peer_bridge(bridge)
            if uplink_bridge:
                nic_info.uplink_bridge = uplink_bridge
                nic_info.physical_nics = host_collector.get_physical_nics_on_bridge(uplink_bridge)
            else:
                nic_info.uplink_bridge = bridge
                nic_info.physical_nics = host_collector.get_physical_nics_on_bridge(bridge)

        vm_info.nics.append(nic_info)

    output = asdict(vm_info)
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return vm_info


def main():
    parser = argparse.ArgumentParser(
        description="Network Environment Information Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # System network subcommand
    sys_parser = subparsers.add_parser('system', help='Collect system network info')
    sys_parser.add_argument('--host', required=True, help='Host IP address')
    sys_parser.add_argument('--user', required=True, help='SSH username')
    sys_parser.add_argument('--password', help='SSH password (for auto ssh-copy-id)')
    sys_parser.add_argument('--type', help='Filter by port type (mgt, storage, access, vpc)')
    sys_parser.add_argument('--timeout', type=int, default=60, help='SSH command timeout (default: 60s)')

    # VM network subcommand
    vm_parser = subparsers.add_parser('vm', help='Collect VM network info')
    vm_parser.add_argument('--uuid', required=True, help='VM UUID (domain name)')
    vm_parser.add_argument('--host-ip', required=True, help='Host (hypervisor) IP address')
    vm_parser.add_argument('--host-user', required=True, help='Host SSH username')
    vm_parser.add_argument('--host-password', help='Host SSH password')
    vm_parser.add_argument('--vm-host', help='VM IP address (optional, for getting NIC names/IPs inside VM)')
    vm_parser.add_argument('--vm-user', help='VM SSH username (optional)')
    vm_parser.add_argument('--vm-password', help='VM SSH password (optional)')
    vm_parser.add_argument('--timeout', type=int, default=60, help='SSH command timeout (default: 60s)')

    args = parser.parse_args()

    if args.command == 'system':
        collect_system_network(args)
    elif args.command == 'vm':
        collect_vm_network(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
