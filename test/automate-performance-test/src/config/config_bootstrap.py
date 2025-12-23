#!/usr/bin/env python3
"""Config Bootstrap - Auto-discover network environment and generate full config.

Takes minimal input config and auto-discovers:
- Host: internal interface, physical interface, test IP
- VM: qemu_pid, vhost_pids, vnet interface, physical interface

Generates:
- Full unified config (replaces ssh-config.yaml + test-env-config.yaml)
- Test cases JSON (replaces ebpf-tools-config.yaml + testcase files)

Usage:
    from src.config import ConfigBootstrap, bootstrap_config

    # Bootstrap from minimal config
    bootstrap = ConfigBootstrap('config/my-env/minimal-input.yaml')
    bootstrap.discover_all()
    full_config = bootstrap.generate_full_config()
    test_cases = bootstrap.generate_test_cases()
"""

import copy
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from itertools import product
from typing import Dict, List, Optional, Tuple, Any

try:
    import yaml
except ImportError:
    yaml = None

# Add test/tools to path for network_env_collector
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '../../../tools'))
sys.path.insert(0, TOOLS_DIR)

from network_env_collector import (
    SSHExecutor, NetworkEnvCollector,
    SystemNetworkInfo, VMInfo, VMNicInfo
)

logger = logging.getLogger(__name__)


@dataclass
class NodeInfo:
    """Collected node information."""
    name: str
    role: str  # 'host' or 'vm'
    ssh_host: str
    ssh_user: str
    workdir: str
    host_ref: Optional[str] = None  # For VMs: which host they run on
    uuid: Optional[str] = None  # For VMs: libvirt domain UUID/name
    test_ip_input: Optional[str] = None  # User-provided test IP (for VMs)

    # Auto-discovered fields
    test_ip: str = ""  # Final test IP (user-provided for VM, auto for host)
    internal_interface: str = ""  # Host: OVS internal port
    physical_interface: str = ""  # Physical NIC name (bond or single NIC)
    physical_nic_members: List[str] = field(default_factory=list)  # Bond member ports
    vm_interface: str = ""  # vnet on host side
    vm_nic_name: str = ""  # NIC name inside VM (e.g., ens4, eth1)
    vm_nic_mac: str = ""  # MAC address of VM NIC
    qemu_pid: int = 0
    vhost_pids: List[str] = field(default_factory=list)
    python_interpreter: str = "python3"


class ConfigBootstrap:
    """Bootstrap full config from minimal input."""

    # Default tools template path (relative to automate-performance-test/)
    DEFAULT_TOOLS_TEMPLATE = os.path.join(SCRIPT_DIR, '../../config/tools-template.yaml')
    DEFAULT_PERF_TEMPLATE = os.path.join(SCRIPT_DIR, '../../config/performance-test-template.yaml')

    def __init__(self, minimal_config_path: str,
                 tools_template_path: str = None,
                 perf_template_path: str = None):
        if yaml is None:
            raise ImportError("PyYAML required. Install: pip install pyyaml")

        self.minimal_config_path = minimal_config_path
        self.tools_template_path = tools_template_path or self.DEFAULT_TOOLS_TEMPLATE
        self.perf_template_path = perf_template_path or self.DEFAULT_PERF_TEMPLATE

        self.config = self._load_config()
        self.tools_template = self._load_tools_template()
        self.perf_template = self._load_perf_template()

        self.nodes: Dict[str, NodeInfo] = {}
        self.executors: Dict[str, SSHExecutor] = {}
        self.collectors: Dict[str, NetworkEnvCollector] = {}

        # Generated data
        self._full_config: Optional[Dict] = None
        self._test_cases: Optional[List[Dict]] = None

    def _load_config(self) -> dict:
        """Load minimal input config."""
        with open(self.minimal_config_path, 'r') as f:
            return yaml.safe_load(f) or {}

    def _load_tools_template(self) -> dict:
        """Load tools registration template."""
        if os.path.exists(self.tools_template_path):
            with open(self.tools_template_path, 'r') as f:
                return yaml.safe_load(f) or {}
        logger.warning(f"Tools template not found: {self.tools_template_path}")
        return {}

    def _load_perf_template(self) -> dict:
        """Load performance test template."""
        if os.path.exists(self.perf_template_path):
            with open(self.perf_template_path, 'r') as f:
                return yaml.safe_load(f) or {}
        # Return default performance test spec
        return {
            'performance_tests': {
                'throughput': {
                    'single_stream': {'duration': 3, 'target_bw': '1G'},
                    'multi_stream': {'duration': 3, 'streams': 4}
                },
                'latency': {
                    'duration': 3,
                    'tcp_rr': {},
                    'udp_rr': {}
                },
                'pps': {
                    'duration': 3,
                    'single_stream': {},
                    'multi_stream': {'streams': 4}
                }
            }
        }

    def _parse_ssh(self, ssh_str: str) -> Tuple[str, str]:
        """Parse 'user@host' format."""
        if '@' in ssh_str:
            user, host = ssh_str.split('@', 1)
            return user, host
        return 'root', ssh_str

    def _get_executor(self, node_name: str) -> SSHExecutor:
        """Get or create SSH executor for node."""
        if node_name not in self.executors:
            node = self.nodes[node_name]
            self.executors[node_name] = SSHExecutor(
                node.ssh_host, node.ssh_user, timeout=60
            )
        return self.executors[node_name]

    def _get_collector(self, node_name: str) -> NetworkEnvCollector:
        """Get or create collector for node."""
        if node_name not in self.collectors:
            executor = self._get_executor(node_name)
            self.collectors[node_name] = NetworkEnvCollector(executor)
        return self.collectors[node_name]

    def _detect_python(self, executor: SSHExecutor) -> str:
        """Detect available Python interpreter."""
        for py in ['python3', 'python']:
            stdout, _, ret = executor.execute(f"which {py} 2>/dev/null")
            if ret == 0 and stdout.strip():
                return py
        return 'python3'

    def discover_host(self, node_name: str) -> NodeInfo:
        """Discover host node information."""
        node = self.nodes[node_name]
        collector = self._get_collector(node_name)
        executor = self._get_executor(node_name)

        hints = self.config.get('discovery_hints', {})
        port_type = hints.get('internal_port_type', 'mgt')

        # Collect system network info
        sys_info_list = collector.collect_system_network_info(port_type)

        if sys_info_list:
            sys_info = sys_info_list[0]
            node.test_ip = sys_info.ip_address
            node.internal_interface = sys_info.port_name

            # Get physical NIC name and bond members
            if sys_info.physical_nics:
                phy_nic = sys_info.physical_nics[0]
                node.physical_interface = phy_nic.name
                if phy_nic.is_bond and phy_nic.bond_members:
                    node.physical_nic_members = phy_nic.bond_members
        else:
            # Fallback: use SSH host IP as test IP
            node.test_ip = node.ssh_host
            logger.warning(f"No OVS internal port found for {node_name}, using SSH IP")

        # Detect Python
        node.python_interpreter = self._detect_python(executor)

        logger.info(f"Discovered host {node_name}: test_ip={node.test_ip}, "
                   f"internal={node.internal_interface}, phy={node.physical_interface}")

        return node

    def _find_nic_by_ip(self, executor: SSHExecutor, target_ip: str) -> Tuple[str, str]:
        """Find NIC name and MAC by IP address inside VM."""
        stdout, _, ret = executor.execute("ip -o addr show | grep 'inet '")
        if ret != 0:
            return "", ""

        for line in stdout.strip().split('\n'):
            if target_ip in line:
                match = re.match(r'\d+:\s+(\S+)\s+inet', line)
                if match:
                    nic_name = match.group(1)
                    stdout2, _, _ = executor.execute(
                        f"ip link show {nic_name} | grep 'link/ether'"
                    )
                    mac_match = re.search(r'link/ether\s+([0-9a-fA-F:]+)', stdout2)
                    mac = mac_match.group(1) if mac_match else ""
                    return nic_name, mac

        return "", ""

    def _find_vnet_by_mac(self, host_collector: NetworkEnvCollector,
                          vm_uuid: str, mac: str) -> str:
        """Find vnet interface on host by MAC address."""
        nics_from_xml = host_collector.get_all_vm_nics_from_xml(vm_uuid)
        mac_lower = mac.lower()

        for nic in nics_from_xml:
            if nic.get('mac', '').lower() == mac_lower:
                return nic.get('vnet', '')

        return ""

    def discover_vm(self, node_name: str) -> NodeInfo:
        """Discover VM node information using test_ip -> MAC -> vnet chain."""
        node = self.nodes[node_name]
        host_ref = node.host_ref

        if not host_ref:
            raise ValueError(f"VM {node_name} must have host_ref defined")

        if not node.uuid:
            raise ValueError(f"VM {node_name} must have uuid defined (use: virsh list --all)")

        if host_ref not in self.nodes:
            raise ValueError(f"Host {host_ref} not found for VM {node_name}")

        host_executor = self._get_executor(host_ref)
        host_collector = self._get_collector(host_ref)
        vm_executor = self._get_executor(node_name)

        vm_uuid = node.uuid
        node.test_ip = node.test_ip_input or node.ssh_host

        # Step 1: Find NIC and MAC by test_ip inside VM
        node.vm_nic_name, node.vm_nic_mac = self._find_nic_by_ip(vm_executor, node.test_ip)
        logger.info(f"VM {node_name}: test_ip={node.test_ip} -> nic={node.vm_nic_name}, mac={node.vm_nic_mac}")

        # Step 2: Get qemu PID using UUID
        node.qemu_pid = host_collector.get_qemu_pid_by_vm_name(vm_uuid)

        if node.qemu_pid > 0:
            # Step 3: Find vnet by MAC
            if node.vm_nic_mac:
                node.vm_interface = self._find_vnet_by_mac(host_collector, vm_uuid, node.vm_nic_mac)

            # Fallback: use first vnet
            if not node.vm_interface:
                nics_from_xml = host_collector.get_all_vm_nics_from_xml(vm_uuid)
                if nics_from_xml:
                    node.vm_interface = nics_from_xml[0].get('vnet', '')

            logger.info(f"VM {node_name}: mac={node.vm_nic_mac} -> vnet={node.vm_interface}")

            # Step 4: Get vhost PIDs for the specific vnet
            if node.vm_interface:
                tap_fd_mapping = host_collector.get_tap_fd_to_vnet_mapping(node.qemu_pid)
                vhost_by_vnet = host_collector.get_vhost_pids_grouped_by_vnet(
                    node.qemu_pid, tap_fd_mapping
                )
                vhost_infos = vhost_by_vnet.get(node.vm_interface, [])
                node.vhost_pids = [str(v.pid) for v in vhost_infos]
                logger.info(f"VM {node_name}: vnet={node.vm_interface} -> vhost_pids={node.vhost_pids}")

            # Step 5: Get physical interface and bond members
            if node.vm_interface:
                bridge = host_collector.get_vnet_bridge(node.vm_interface)
                if bridge:
                    uplink = host_collector.get_patch_peer_bridge(bridge)
                    target_bridge = uplink or bridge
                    phys = host_collector.get_physical_nics_on_bridge(target_bridge)
                    if phys:
                        phy_nic = phys[0]
                        node.physical_interface = phy_nic.name
                        if phy_nic.is_bond and phy_nic.bond_members:
                            node.physical_nic_members = phy_nic.bond_members

        # Detect Python in VM
        node.python_interpreter = self._detect_python(vm_executor)

        logger.info(f"Discovered VM {node_name}: test_ip={node.test_ip}, nic={node.vm_nic_name}, "
                   f"qemu_pid={node.qemu_pid}, vhost_pids={node.vhost_pids}, "
                   f"vnet={node.vm_interface}, phy={node.physical_interface}")

        return node

    def discover_all(self):
        """Discover all nodes from minimal config."""
        nodes_config = self.config.get('nodes', {})

        # Parse node definitions
        for name, cfg in nodes_config.items():
            ssh_user, ssh_host = self._parse_ssh(cfg.get('ssh', ''))
            self.nodes[name] = NodeInfo(
                name=name,
                role=cfg.get('role', 'host'),
                ssh_host=ssh_host,
                ssh_user=ssh_user,
                workdir=cfg.get('workdir', '/tmp'),
                host_ref=cfg.get('host_ref'),
                uuid=cfg.get('uuid'),
                test_ip_input=cfg.get('test_ip')
            )

        # Discover hosts first
        for name, node in self.nodes.items():
            if node.role == 'host':
                self.discover_host(name)

        # Then discover VMs
        for name, node in self.nodes.items():
            if node.role == 'vm':
                self.discover_vm(name)

    def generate_full_config(self) -> dict:
        """Generate full unified config from discovered information."""
        env_name = self.config.get('environment', 'auto-discovered')
        test_pairs = self.config.get('test_pairs', {})
        hints = self.config.get('discovery_hints', {})

        # Build SSH hosts section
        ssh_hosts = {}
        for name, node in self.nodes.items():
            ssh_hosts[name] = {
                'host': node.ssh_host,
                'user': node.ssh_user,
                'workdir': node.workdir
            }

        # Build environments section
        environments = {}

        # Host environment
        if 'host' in test_pairs:
            host_pair = test_pairs['host']
            server_name = host_pair.get('server')
            client_name = host_pair.get('client')

            if server_name and client_name:
                server = self.nodes.get(server_name)
                client = self.nodes.get(client_name)

                if server and client:
                    environments['host'] = {
                        'description': f"Host-to-host testing on {env_name}",
                        'server': {
                            'ssh_ref': server_name,
                            'test_ip': server.test_ip,
                            'interface': server.internal_interface
                        },
                        'client': {
                            'ssh_ref': client_name,
                            'test_ip': client.test_ip,
                            'interface': client.internal_interface
                        },
                        'network_config': {
                            'server_ip': server.test_ip,
                            'client_ip': client.test_ip,
                            'internal_interface': server.internal_interface,
                            'server_physical_interface': server.physical_interface,
                            'server_physical_nic_members': list(server.physical_nic_members),
                            'client_physical_interface': client.physical_interface,
                            'client_physical_nic_members': list(client.physical_nic_members)
                        }
                    }

        # VM environment
        if 'vm' in test_pairs:
            vm_pair = test_pairs['vm']
            server_name = vm_pair.get('server')
            client_name = vm_pair.get('client')

            if server_name and client_name:
                server = self.nodes.get(server_name)
                client = self.nodes.get(client_name)

                if server and client:
                    environments['vm'] = {
                        'description': f"VM-to-VM testing on {env_name}",
                        'server': {
                            'ssh_ref': server_name,
                            'test_ip': server.test_ip,
                            'interface': server.vm_nic_name or 'ens4',
                            'vm_interface': server.vm_interface,
                            'physical_host_ref': server.host_ref
                        },
                        'client': {
                            'ssh_ref': client_name,
                            'test_ip': client.test_ip,
                            'interface': client.vm_nic_name or 'ens4',
                            'vm_interface': client.vm_interface,
                            'physical_host_ref': client.host_ref
                        },
                        'network_config': {
                            'server_ip': server.test_ip,
                            'client_ip': client.test_ip,
                            'server_physical_interface': server.physical_interface,
                            'server_physical_nic_members': list(server.physical_nic_members),
                            'server_vm_interface': server.vm_interface,
                            'client_physical_interface': client.physical_interface,
                            'client_physical_nic_members': list(client.physical_nic_members),
                            'client_vm_interface': client.vm_interface
                        }
                    }

                    # KVM config for both server and client VMs
                    kvm_config = {}
                    if server.qemu_pid > 0:
                        kvm_config['server'] = {
                            'qemu_pid': str(server.qemu_pid),
                            'vhost_pids': list(server.vhost_pids)
                        }
                    if client.qemu_pid > 0:
                        kvm_config['client'] = {
                            'qemu_pid': str(client.qemu_pid),
                            'vhost_pids': list(client.vhost_pids)
                        }
                    if kvm_config:
                        environments['vm']['kvm_config'] = kvm_config

        # Get tools from template with dynamic parameters
        tools_config = self._prepare_tools_config()

        # Build full config
        self._full_config = {
            'version': '1.0',
            'environment': env_name,
            'ssh': {'ssh_hosts': ssh_hosts},
            'environments': environments,
            'paths': {
                'tools_dir': 'measurement-tools',
                'results_dir': 'ebpf-test-results',
                'measurement_tools_dir': '../../../measurement-tools'
            },
            'defaults': {
                'duration': 10,
                'timeout': 120,
                'use_sudo': True,
                'python_interpreter': hints.get('python_interpreter', 'python3')
            },
            'monitoring': {
                'enabled': True,
                'cpu': True,
                'memory': True,
                'memory_types': ['virt', 'rss'],
                'log_size': True,
                'cpu_stats': ['avg', 'peak']
            },
            'tools': tools_config,
            'performance_tests': self.perf_template.get('performance_tests', {})
        }

        return self._full_config

    def _prepare_tools_config(self) -> dict:
        """Prepare tools config with dynamic parameters (e.g., vhost_pids)."""
        tools = copy.deepcopy(self.tools_template.get('tools', {}))

        # Get vhost_pids from VM server node
        test_pairs = self.config.get('test_pairs', {})
        vm_pair = test_pairs.get('vm', {})
        server_name = vm_pair.get('server')

        vhost_pids = []
        if server_name and server_name in self.nodes:
            vhost_pids = list(self.nodes[server_name].vhost_pids)

        # Update dynamic parameters in KVM tools
        categories = tools.get('categories', {})
        kvm_category = categories.get('kvm-virt-network/kvm', {})
        kvm_tools = kvm_category.get('tools', [])

        for tool in kvm_tools:
            params = tool.get('parameters', {})
            if 'vhost_pid' in params and params['vhost_pid'] == '{vhost_pids}':
                params['vhost_pid'] = list(vhost_pids) if vhost_pids else ['0']

        return tools

    def generate_test_cases(self) -> List[Dict]:
        """Generate test cases from tools template.

        Returns:
            List of test case dictionaries compatible with testcase_loader
        """
        if self._full_config is None:
            self.generate_full_config()

        cases = []
        case_id = 1

        environments = self._full_config.get('environments', {})
        tools_config = self._full_config.get('tools', {})
        categories = tools_config.get('categories', {})
        # Use tools_dir from config paths (default to measurement-tools for consistency)
        paths_config = self._full_config.get('paths', {})
        remote_base = paths_config.get('tools_dir', 'measurement-tools')

        for category_name, category_config in categories.items():
            env_name = category_config.get('environment', 'host')
            env_config = environments.get(env_name, {})
            if not env_config:
                continue

            directions = category_config.get('directions', {})
            tools_list = category_config.get('tools', [])

            # Build environment variables
            env_vars = self._build_env_variables(env_name, env_config)

            for tool_config in tools_list:
                script = tool_config.get('script', '')
                template = tool_config.get('template', '')
                parameters = tool_config.get('parameters', {})
                defaults = {k: v for k, v in tool_config.items()
                           if k not in ('script', 'template', 'parameters', 'directions')}

                # Build local path
                local_path = f"{category_name}/{script}"

                # Expand parameters
                param_combos = self._expand_parameters(parameters, directions, template)

                for params in param_combos:
                    # Resolve template
                    all_vars = {'path': f"{remote_base}/{local_path}"}
                    all_vars.update(env_vars)
                    all_vars.update(defaults)

                    # Resolve direction-specific IPs
                    if 'direction' in params and directions:
                        dir_vars = directions.get(params['direction'], {})
                        for var_name, var_value in dir_vars.items():
                            if isinstance(var_value, str) and var_value.startswith('{') and var_value.endswith('}'):
                                ref_name = var_value[1:-1]
                                all_vars[var_name] = env_vars.get(ref_name, var_value)
                            else:
                                all_vars[var_name] = var_value

                    all_vars.update(params)

                    command = self._resolve_template(template, all_vars)
                    case_name = self._generate_case_name(script, params)

                    case = {
                        'id': case_id,
                        'name': case_name,
                        'command': command,
                        'script': script,
                        'category': category_name,
                        'environment': env_name,
                        'parameters': params.copy(),
                        'duration': int(params.get('duration', 10))
                    }
                    cases.append(case)
                    case_id += 1

        self._test_cases = cases
        logger.info(f"Generated {len(cases)} test cases")
        return cases

    def _build_env_variables(self, env_name: str, env_config: Dict) -> Dict:
        """Build environment-specific variables."""
        server = env_config.get('server', {})
        client = env_config.get('client', {})
        network = env_config.get('network_config', {})
        kvm = env_config.get('kvm_config', {})
        # Support both old flat structure and new nested structure
        kvm_server = kvm.get('server', kvm) if isinstance(kvm.get('server'), dict) else kvm

        prefix = env_name  # 'host' or 'vm'

        # Get physical interface and bond members
        # PHY_INTERFACE: comma-separated list of interfaces for bond scenarios (e.g., "eth0,eth1")
        #                or single interface name (e.g., "enp94s0f0np0")
        phy_interface = network.get('server_physical_interface', '')
        phy_members = network.get('server_physical_nic_members', [])

        if phy_members and len(phy_members) >= 1:
            # Bond scenario: use comma-separated member interfaces
            phy_interface_value = ','.join(phy_members)
        else:
            # Single NIC scenario: use physical interface name directly
            phy_interface_value = phy_interface

        variables = {
            f'{prefix}_LOCAL_IP': server.get('test_ip', ''),
            f'{prefix}_REMOTE_IP': client.get('test_ip', ''),
            'INTERNAL_INTERFACE': network.get('internal_interface', ''),
            'PHY_INTERFACE': phy_interface_value,
            'VM_INTERFACE': network.get('server_vm_interface', network.get('vm_interface', '')),
            'QEMU_PID': kvm_server.get('qemu_pid', ''),
        }

        return variables

    def _expand_parameters(self, parameters: Dict, directions: Dict, template: str) -> List[Dict]:
        """Expand parameter matrix into all combinations."""
        expandable = {}

        for param_name, param_values in parameters.items():
            if isinstance(param_values, list):
                expandable[param_name] = param_values

        # Add directions if template uses direction variables
        if directions and any(v in template for v in ['{SRC_IP}', '{DST_IP}', '{direction}']):
            expandable['direction'] = list(directions.keys())

        if not expandable:
            return [{}]

        param_names = list(expandable.keys())
        param_values = [expandable[name] for name in param_names]

        combinations = []
        for combo in product(*param_values):
            combinations.append(dict(zip(param_names, combo)))

        return combinations

    def _resolve_template(self, template: str, variables: Dict) -> str:
        """Resolve command template with variables."""
        if not template:
            return ""

        resolved = template

        # Replace variables
        for var_name, var_value in variables.items():
            resolved = resolved.replace(f'{{{var_name}}}', str(var_value))

        # Remove unresolved optional parameters (still have {var} placeholder)
        option_pattern = r'--(\w+[-\w]*)\s+\{(\w+)\}'
        matches = re.findall(option_pattern, resolved)
        for option_name, var_name in matches:
            full_pattern = r'--' + re.escape(option_name) + r'\s+\{' + var_name + r'\}'
            resolved = re.sub(full_pattern, '', resolved)

        # Remove options with empty values (e.g., "--phy-iface2 " with no value)
        resolved = re.sub(r'--[\w-]+\s+(?=--|$)', '', resolved)

        # Clean up extra spaces
        resolved = re.sub(r'\s+', ' ', resolved).strip()

        return resolved

    def _generate_case_name(self, script: str, params: Dict) -> str:
        """Generate human-readable test case name."""
        base_name = script.replace('.py', '').replace('.bt', '').replace('-', '_')

        parts = []
        if 'direction' in params:
            parts.append(params['direction'])
        if 'protocol' in params:
            parts.append(f"protocol_{params['protocol']}")

        # Add other parameters
        excluded = {'direction', 'protocol', 'duration', 'SRC_IP', 'DST_IP'}
        for key, value in params.items():
            if key not in excluded and value:
                clean_value = str(value).replace(' ', '_').replace('-', '_')
                parts.append(f"{key}_{clean_value}")

        if parts:
            return f"{base_name}_{'_'.join(parts)}"
        return base_name

    def save_full_config(self, output_path: str):
        """Save full config to YAML file."""
        if self._full_config is None:
            self.generate_full_config()

        with open(output_path, 'w') as f:
            yaml.dump(self._full_config, f, default_flow_style=False, sort_keys=False)
        logger.info(f"Saved full config to: {output_path}")

    def save_test_cases(self, output_path: str):
        """Save test cases to JSON file."""
        if self._test_cases is None:
            self.generate_test_cases()

        output = {
            'metadata': {
                'environment': self._full_config.get('environment', ''),
                'total_cases': len(self._test_cases)
            },
            'test_cases': self._test_cases
        }

        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        logger.info(f"Saved {len(self._test_cases)} test cases to: {output_path}")

    def close(self):
        """Close all SSH connections."""
        for executor in self.executors.values():
            executor.close()


def bootstrap_config(input_path: str, output_dir: str = None) -> Tuple[dict, List[dict]]:
    """Bootstrap full config and test cases from minimal input.

    Args:
        input_path: Path to minimal input config
        output_dir: Directory to write generated files (optional)

    Returns:
        Tuple of (full_config, test_cases)
    """
    bootstrap = ConfigBootstrap(input_path)

    try:
        logger.info(f"Starting discovery from {input_path}")
        bootstrap.discover_all()

        full_config = bootstrap.generate_full_config()
        test_cases = bootstrap.generate_test_cases()

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            env_name = full_config.get('environment', 'generated')

            config_path = os.path.join(output_dir, f'{env_name}-full.yaml')
            cases_path = os.path.join(output_dir, f'{env_name}-cases.json')

            bootstrap.save_full_config(config_path)
            bootstrap.save_test_cases(cases_path)

        return full_config, test_cases

    finally:
        bootstrap.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Bootstrap full config from minimal input")
    parser.add_argument('--input', '-i', required=True, help='Minimal input config path')
    parser.add_argument('--output-dir', '-o', help='Output directory for generated files')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--list-cases', action='store_true', help='List generated test cases')

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    full_config, test_cases = bootstrap_config(args.input, args.output_dir)

    if args.list_cases:
        print(f"\nGenerated {len(test_cases)} test cases:")
        for case in test_cases:
            print(f"  [{case['id']:3d}] {case['name']}")
            print(f"        env={case['environment']}, category={case['category']}")

    if not args.output_dir:
        print("\n--- Full Config ---")
        print(yaml.dump(full_config, default_flow_style=False, sort_keys=False))


if __name__ == '__main__':
    main()
