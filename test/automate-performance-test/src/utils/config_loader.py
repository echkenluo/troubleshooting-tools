#!/usr/bin/env python3
"""Configuration loader for YAML configs.

Supports both legacy format (4 separate files) and unified format (single file).
"""

import json
import os
import logging
from typing import Dict, Any, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Configuration loader for YAML files.

    Supports two config formats:
    1. Legacy: 4 separate files (ssh-config.yaml, test-env-config.yaml,
       ebpf-tools-config.yaml, performance-test-spec.yaml)
    2. Unified: Single generated file with all sections combined

    When using unified format, the loader converts to legacy format internally
    for backward compatibility with existing execution logic.
    """

    def __init__(self, config_dir: str, unified_config_path: str = None):
        """Initialize config loader.

        Args:
            config_dir: Configuration directory path (for legacy format)
            unified_config_path: Path to unified config file (optional)
        """
        self.config_dir = config_dir
        self.unified_config_path = unified_config_path
        self._unified_config: Optional[Dict] = None
        self._is_unified = False

        # Auto-detect config format
        if unified_config_path and os.path.exists(unified_config_path):
            self._load_unified_config(unified_config_path)
            self._is_unified = True
        elif self._detect_unified_config():
            self._is_unified = True

    def _detect_unified_config(self) -> bool:
        """Detect if unified config exists in config_dir."""
        # Check for *-full.yaml files
        if os.path.isdir(self.config_dir):
            for f in os.listdir(self.config_dir):
                if f.endswith('-full.yaml'):
                    full_path = os.path.join(self.config_dir, f)
                    self._load_unified_config(full_path)
                    return True
        return False

    def _load_unified_config(self, config_path: str):
        """Load unified configuration file."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                self._unified_config = yaml.safe_load(f)
            logger.info(f"Loaded unified config: {config_path}")
        except yaml.YAMLError as e:
            logger.error(f"Error parsing unified config: {str(e)}")
            raise

    def is_unified_format(self) -> bool:
        """Check if using unified config format."""
        return self._is_unified

    def get_unified_config(self) -> Optional[Dict]:
        """Get raw unified config if available."""
        return self._unified_config

    def load_ssh_config(self) -> Dict[str, Any]:
        """Load SSH configuration."""
        if self._is_unified and self._unified_config:
            return self._unified_config.get('ssh', {})
        return self._load_yaml_file("ssh-config.yaml")

    def load_env_config(self) -> Dict[str, Any]:
        """Load environment configuration."""
        if self._is_unified and self._unified_config:
            # Convert unified 'environments' to legacy 'test_environments' format
            envs = self._unified_config.get('environments', {})
            return {'test_environments': envs}
        return self._load_yaml_file("test-env-config.yaml")

    def load_perf_spec(self) -> Dict[str, Any]:
        """Load performance test specifications."""
        if self._is_unified and self._unified_config:
            perf = self._unified_config.get('performance_tests', {})
            return {'performance_tests': perf}
        return self._load_yaml_file("performance-test-spec.yaml")

    def load_ebpf_config(self) -> Dict[str, Any]:
        """Load eBPF tools configuration.

        For unified format, this returns an empty ebpf_tools dict since
        test cases are loaded separately via TestCaseGenerator.
        """
        if self._is_unified and self._unified_config:
            # Return minimal config - actual cases loaded via TestCaseGenerator
            return {'ebpf_tools': {}}
        return self._load_yaml_file("ebpf-tools-config.yaml")

    def load_test_cases(self, cases_path: str = None) -> Tuple[Dict, list]:
        """Load test cases from JSON file.

        Args:
            cases_path: Path to test cases JSON file

        Returns:
            Tuple of (metadata, test_cases list)
        """
        if cases_path is None:
            # Auto-detect cases file
            if os.path.isdir(self.config_dir):
                for f in os.listdir(self.config_dir):
                    if f.endswith('-cases.json'):
                        cases_path = os.path.join(self.config_dir, f)
                        break

        if cases_path and os.path.exists(cases_path):
            with open(cases_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if 'test_cases' in data:
                return data.get('metadata', {}), data['test_cases']
            elif isinstance(data, list):
                return {}, data

        logger.warning(f"Test cases file not found: {cases_path}")
        return {}, []

    def load_all_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load all configuration files.

        Returns:
            Dictionary containing all configs
        """
        return {
            'ssh': self.load_ssh_config(),
            'env': self.load_env_config(),
            'perf': self.load_perf_spec(),
            'ebpf': self.load_ebpf_config()
        }

    def _load_yaml_file(self, filename: str) -> Dict[str, Any]:
        """Load YAML file.

        Args:
            filename: YAML filename

        Returns:
            Parsed YAML content
        """
        filepath = os.path.join(self.config_dir, filename)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Config file not found: {filepath}")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                logger.info(f"Loaded config: {filename}")
                return content
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML file {filename}: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error loading config file {filename}: {str(e)}")
            raise

    def validate_config(self, config_type: str, config: Dict[str, Any]) -> bool:
        """Validate configuration.

        Args:
            config_type: Type of config (ssh/env/perf/ebpf)
            config: Configuration to validate

        Returns:
            Validation status
        """
        if config_type == 'ssh':
            return self._validate_ssh_config(config)
        elif config_type == 'env':
            return self._validate_env_config(config)
        elif config_type == 'perf':
            return self._validate_perf_config(config)
        elif config_type == 'ebpf':
            return self._validate_ebpf_config(config)
        else:
            logger.warning(f"Unknown config type: {config_type}")
            return False

    def _validate_ssh_config(self, config: Dict[str, Any]) -> bool:
        """Validate SSH configuration."""
        if 'ssh_hosts' not in config:
            return False

        for host_ref, host_config in config['ssh_hosts'].items():
            required_keys = ['host', 'user', 'workdir']
            if not all(key in host_config for key in required_keys):
                logger.error(f"Missing required keys in SSH config for {host_ref}")
                return False

        return True

    def _validate_env_config(self, config: Dict[str, Any]) -> bool:
        """Validate environment configuration."""
        if 'test_environments' not in config:
            return False

        for env_name, env_config in config['test_environments'].items():
            if 'server' not in env_config or 'client' not in env_config:
                logger.error(f"Missing server/client config for environment {env_name}")
                return False

        return True

    def _validate_perf_config(self, config: Dict[str, Any]) -> bool:
        """Validate performance test configuration."""
        if 'performance_tests' not in config:
            return False

        required_tests = ['throughput', 'latency', 'pps']
        for test_type in required_tests:
            if test_type not in config['performance_tests']:
                logger.error(f"Missing performance test type: {test_type}")
                return False

        return True

    def _validate_ebpf_config(self, config: Dict[str, Any]) -> bool:
        """Validate eBPF tools configuration.

        For unified format with generated cases, always returns True.
        """
        if self._is_unified:
            return True

        if 'ebpf_tools' not in config:
            return False

        for tool_id, tool_config in config['ebpf_tools'].items():
            required_keys = ['id', 'name', 'testcase_source', 'test_associations']
            if not all(key in tool_config for key in required_keys):
                logger.error(f"Missing required keys in eBPF config for {tool_id}")
                return False

        return True

    # Helper methods for unified config access

    def get_ssh_host(self, host_ref: str) -> Optional[Dict]:
        """Get SSH host configuration by reference."""
        ssh_config = self.load_ssh_config()
        return ssh_config.get('ssh_hosts', {}).get(host_ref)

    def get_environment(self, env_name: str) -> Optional[Dict]:
        """Get environment configuration by name."""
        env_config = self.load_env_config()
        return env_config.get('test_environments', {}).get(env_name)

    def get_defaults(self) -> Dict:
        """Get default values from unified config."""
        if self._is_unified and self._unified_config:
            return self._unified_config.get('defaults', {})
        return {}

    def get_monitoring_config(self) -> Dict:
        """Get monitoring configuration from unified config."""
        if self._is_unified and self._unified_config:
            return self._unified_config.get('monitoring', {})
        return {}

    def get_paths_config(self) -> Dict:
        """Get paths configuration from unified config."""
        if self._is_unified and self._unified_config:
            return self._unified_config.get('paths', {})
        return {}
