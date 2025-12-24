#!/usr/bin/env python3
"""SSH connection manager"""

import paramiko
import logging
from typing import Dict, Optional, Tuple
import time

logger = logging.getLogger(__name__)


class SSHManager:
    """SSH connection manager"""

    def __init__(self, ssh_config: Dict, keepalive_interval: int = 30):
        """Initialize SSH manager

        Args:
            ssh_config: SSH config dict
            keepalive_interval: SSH keepalive interval in seconds (default: 30)
        """
        self.ssh_config = ssh_config
        self.connections = {}
        self.clients = {}
        self.keepalive_interval = keepalive_interval

    def _is_connection_alive(self, client: paramiko.SSHClient) -> bool:
        """Check if SSH connection is still alive

        Args:
            client: SSH client instance

        Returns:
            True if connection is active, False otherwise
        """
        try:
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                return False
            # Send a keepalive packet to verify connection
            transport.send_ignore()
            return True
        except Exception:
            return False

    def connect(self, host_ref: str) -> paramiko.SSHClient:
        """Establish SSH connection

        Args:
            host_ref: SSH host reference

        Returns:
            SSH client instance
        """
        # Check if cached connection is still valid
        if host_ref in self.clients:
            client = self.clients[host_ref]
            if self._is_connection_alive(client):
                return client
            else:
                # Connection is stale, close and remove it
                logger.warning(f"Connection to {host_ref} is stale, reconnecting...")
                try:
                    client.close()
                except Exception:
                    pass
                del self.clients[host_ref]

        if host_ref not in self.ssh_config['ssh_hosts']:
            raise ValueError(f"Unknown host reference: {host_ref}")

        host_config = self.ssh_config['ssh_hosts'][host_ref]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=host_config['host'],
                username=host_config['user'],
                timeout=10
            )
            # Enable SSH keepalive to prevent connection timeout
            transport = client.get_transport()
            if transport:
                transport.set_keepalive(self.keepalive_interval)
                logger.debug(f"SSH keepalive set to {self.keepalive_interval}s for {host_ref}")
            self.clients[host_ref] = client
            logger.info(f"Connected to {host_ref} ({host_config['host']})")
            return client
        except Exception as e:
            logger.error(f"Failed to connect to {host_ref}: {str(e)}")
            raise

    def execute_command(self, host_ref: str, command: str,
                       timeout: Optional[int] = None,
                       background: bool = False) -> Tuple[str, str, int]:
        """Execute remote command

        Args:
            host_ref: SSH host reference
            command: Command to execute
            timeout: Timeout in seconds
            background: Run in background

        Returns:
            (stdout, stderr, exit_status)
        """
        client = self.connect(host_ref)

        if background:
            # Run command in background
            bg_command = f"nohup {command} > /dev/null 2>&1 & echo $!"
            stdin, stdout, stderr = client.exec_command(bg_command)
            pid = stdout.read().decode().strip()
            return pid, "", 0

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

        # Wait for command completion
        exit_status = stdout.channel.recv_exit_status()

        stdout_data = stdout.read().decode()
        stderr_data = stderr.read().decode()

        return stdout_data, stderr_data, exit_status

    def execute_batch_commands(self, host_ref: str, commands: list,
                             stop_on_error: bool = True) -> list:
        """Execute batch commands

        Args:
            host_ref: SSH host reference
            commands: Command list
            stop_on_error: Stop on error

        Returns:
            Execution results list
        """
        results = []
        for cmd in commands:
            try:
                stdout, stderr, status = self.execute_command(host_ref, cmd)
                results.append({
                    'command': cmd,
                    'stdout': stdout,
                    'stderr': stderr,
                    'status': status,
                    'success': status == 0
                })

                if stop_on_error and status != 0:
                    logger.error(f"Command failed: {cmd}")
                    break
            except Exception as e:
                results.append({
                    'command': cmd,
                    'error': str(e),
                    'success': False
                })
                if stop_on_error:
                    break

        return results

    def copy_file_to_remote(self, host_ref: str, local_path: str,
                           remote_path: str) -> bool:
        """Copy file to remote host

        Args:
            host_ref: SSH host reference
            local_path: Local file path
            remote_path: Remote file path

        Returns:
            Success status
        """
        client = self.connect(host_ref)

        try:
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            logger.info(f"Copied {local_path} to {host_ref}:{remote_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to copy file: {str(e)}")
            return False

    def copy_file_from_remote(self, host_ref: str, remote_path: str,
                             local_path: str) -> bool:
        """Copy file from remote host

        Args:
            host_ref: SSH host reference
            remote_path: Remote file path
            local_path: Local file path

        Returns:
            Success status
        """
        client = self.connect(host_ref)

        try:
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            logger.info(f"Copied {host_ref}:{remote_path} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to copy file: {str(e)}")
            return False

    def check_process(self, host_ref: str, pid: str) -> bool:
        """Check if remote process exists

        Args:
            host_ref: SSH host reference
            pid: Process ID

        Returns:
            Process exists status
        """
        stdout, _, status = self.execute_command(
            host_ref, f"ps -p {pid} >/dev/null 2>&1"
        )
        return status == 0

    def kill_process(self, host_ref: str, pid: str, signal: str = "TERM") -> bool:
        """Kill remote process

        Args:
            host_ref: SSH host reference
            pid: Process ID
            signal: Signal type

        Returns:
            Success status
        """
        _, _, status = self.execute_command(
            host_ref, f"kill -{signal} {pid}"
        )
        return status == 0

    def close_all(self):
        """Close all SSH connections"""
        for host_ref, client in self.clients.items():
            try:
                client.close()
                logger.info(f"Closed connection to {host_ref}")
            except Exception as e:
                logger.error(f"Error closing connection to {host_ref}: {str(e)}")
        self.clients.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_all()
