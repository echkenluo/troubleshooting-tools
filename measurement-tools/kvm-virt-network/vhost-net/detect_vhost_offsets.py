#!/usr/bin/env python
# -*- coding: utf-8 -*-
# detect_vhost_offsets.py - Detect vhost_virtqueue field offsets from BTF or pahole
# Use this script on kernel 5.10+ to get accurate field offsets

from __future__ import print_function
import subprocess
import sys
import os
import re

def run_command(cmd):
    """Run command and return output"""
    try:
        result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
        stdout, stderr = result.communicate()
        if isinstance(stdout, bytes):
            stdout = stdout.decode('utf-8', errors='replace')
        return stdout, result.returncode
    except Exception as e:
        return str(e), -1

def detect_using_pahole():
    """Detect offsets using pahole (dwarves package)"""
    print("Trying pahole...")

    # Try different vmlinux locations
    vmlinux_paths = [
        '/sys/kernel/btf/vmlinux',
        '/usr/lib/debug/boot/vmlinux-' + os.uname()[2],
        '/boot/vmlinux-' + os.uname()[2],
        '/usr/lib/debug/lib/modules/' + os.uname()[2] + '/vmlinux',
    ]

    for vmlinux in vmlinux_paths:
        if os.path.exists(vmlinux):
            # For BTF file, use bpftool
            if vmlinux == '/sys/kernel/btf/vmlinux':
                cmd = "bpftool btf dump file {} format c 2>/dev/null | grep -A 500 'struct vhost_virtqueue {{'"
                stdout, rc = run_command(cmd.format(vmlinux))
                if rc == 0 and stdout:
                    return parse_bpftool_output(stdout)
            else:
                cmd = "pahole -C vhost_virtqueue {} 2>/dev/null"
                stdout, rc = run_command(cmd.format(vmlinux))
                if rc == 0 and stdout:
                    return parse_pahole_output(stdout)

    return None

def parse_pahole_output(output):
    """Parse pahole output to extract field offsets"""
    offsets = {}

    # Pattern: fieldname; /* offset size */
    # or: type fieldname; /* offset size */
    pattern = r'(\w+)\s*;\s*/\*\s*(\d+)\s+\d+\s*\*/'

    for line in output.split('\n'):
        match = re.search(pattern, line)
        if match:
            field_name = match.group(1)
            offset = int(match.group(2))
            offsets[field_name] = offset

    return offsets

def parse_bpftool_output(output):
    """Parse bpftool btf dump output to extract field offsets"""
    offsets = {}
    current_offset = 0

    # This is a simplified parser - in production use proper BTF parsing
    # Look for field declarations
    for line in output.split('\n'):
        # Match field declarations
        if '/*' in line and '*/' in line:
            # Try to extract field name and offset
            parts = line.strip().split()
            for i, part in enumerate(parts):
                if part.endswith(';'):
                    field_name = part.rstrip(';').lstrip('*')
                    # Look for offset in comment
                    offset_match = re.search(r'/\*\s*(\d+)', line)
                    if offset_match:
                        offsets[field_name] = int(offset_match.group(1))
                    break

    return offsets

def detect_using_crash():
    """Detect offsets using crash utility (if available)"""
    print("Trying crash utility...")

    cmd = "crash -s /dev/mem /boot/vmlinux-{} << 'EOF'\nstruct vhost_virtqueue\nquit\nEOF".format(os.uname()[2])
    stdout, rc = run_command(cmd)

    if rc == 0 and 'struct vhost_virtqueue' in stdout:
        return parse_crash_output(stdout)

    return None

def parse_crash_output(output):
    """Parse crash utility output"""
    offsets = {}

    # Pattern: [offset] type fieldname;
    pattern = r'\[(\d+)\]\s+\S+\s+(\w+);'

    for line in output.split('\n'):
        match = re.search(pattern, line)
        if match:
            offset = int(match.group(1))
            field_name = match.group(2)
            offsets[field_name] = offset

    return offsets

def detect_using_kernel_module():
    """
    Detect offsets by analyzing a kernel module.
    This requires a helper kernel module to be compiled and loaded.
    """
    print("Kernel module method not implemented")
    return None

def estimate_offsets_from_analysis():
    """
    Provide estimated offsets based on kernel source analysis.
    These are approximate and may need adjustment.
    """
    kernel_release = os.uname()[2]

    # Check kernel version
    version_match = re.match(r'(\d+)\.(\d+)', kernel_release)
    if not version_match:
        return None

    major = int(version_match.group(1))
    minor = int(version_match.group(2))

    print("Providing estimated offsets for kernel {}.{}".format(major, minor))
    print("WARNING: These are estimates and may not be accurate!")
    print("Use --pahole or --bpftool for accurate offsets")

    if major >= 5 and minor >= 10:
        # Kernel 5.10+ estimates
        # Based on structure analysis with vhost_vring_call struct
        return {
            'dev': 0,
            'mutex': 8,
            'num': 40,
            'desc': 48,
            'avail': 56,
            'used': 64,
            'meta_iotlb': 72,
            'kick': 96,
            'call_ctx': 104,  # struct vhost_vring_call in 5.10+
            'error_ctx': 160,
            'log_ctx': 168,
            'poll': 176,
            'handle_kick': 368,
            'last_avail_idx': 376,
            'avail_idx': 378,
            'last_used_idx': 380,
            'used_flags': 382,
            'signalled_used': 384,
            'signalled_used_valid': 386,
            'log_used': 387,
            'log_addr': 392,
            # After iov[1024] and other arrays
            'private_data': 9216,
            'acked_features': 9224,
            'acked_backend_features': 9232,
        }
    else:
        # Kernel 4.19 style
        return {
            'dev': 0,
            'mutex': 8,
            'num': 40,
            'desc': 48,
            'avail': 56,
            'used': 64,
            'meta_iotlb': 72,
            'kick': 96,
            'call_ctx': 104,  # pointer in 4.19
            'error_ctx': 112,
            'log_ctx': 120,
            'poll': 128,
            'handle_kick': 320,
            'last_avail_idx': 328,
            'avail_idx': 330,
            'last_used_idx': 332,
            'used_flags': 334,
            'signalled_used': 336,
            'signalled_used_valid': 338,
            'log_used': 339,
            'log_addr': 344,
            'private_data': 9168,
            'acked_features': 9176,
            'acked_backend_features': 9184,
        }

def print_env_exports(offsets):
    """Print environment variable exports for the BCC tool"""
    print("\n# Environment variables for vhost_queue_correlation_simple_k510.py:")
    print("# Copy and paste these or add to your shell profile\n")

    field_mapping = {
        'private_data': 'VHOST_VQ_PRIVATE_DATA_OFFSET',
        'last_avail_idx': 'VHOST_VQ_LAST_AVAIL_IDX_OFFSET',
        'avail_idx': 'VHOST_VQ_AVAIL_IDX_OFFSET',
        'last_used_idx': 'VHOST_VQ_LAST_USED_IDX_OFFSET',
        'used_flags': 'VHOST_VQ_USED_FLAGS_OFFSET',
        'signalled_used': 'VHOST_VQ_SIGNALLED_USED_OFFSET',
        'signalled_used_valid': 'VHOST_VQ_SIGNALLED_USED_VALID_OFFSET',
        'log_used': 'VHOST_VQ_LOG_USED_OFFSET',
        'log_addr': 'VHOST_VQ_LOG_ADDR_OFFSET',
        'acked_features': 'VHOST_VQ_ACKED_FEATURES_OFFSET',
        'acked_backend_features': 'VHOST_VQ_ACKED_BACKEND_FEATURES_OFFSET',
        'num': 'VHOST_VQ_NUM_OFFSET',
        'avail': 'VHOST_VQ_AVAIL_OFFSET',
    }

    for field, env_var in field_mapping.items():
        if field in offsets:
            print("export {}={}".format(env_var, offsets[field]))

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Detect vhost_virtqueue field offsets for BCC tool compatibility"
    )
    parser.add_argument("--pahole", action="store_true", help="Use pahole for detection")
    parser.add_argument("--bpftool", action="store_true", help="Use bpftool btf dump")
    parser.add_argument("--estimate", action="store_true", help="Use estimated offsets")
    parser.add_argument("--all", action="store_true", help="Try all methods")
    parser.add_argument("--export", action="store_true", help="Print as shell exports")

    args = parser.parse_args()

    print("Kernel: {}".format(os.uname()[2]))
    print("")

    offsets = None

    if args.all or args.pahole:
        offsets = detect_using_pahole()
        if offsets:
            print("Successfully detected offsets using pahole/bpftool")

    if not offsets and (args.all or args.estimate):
        offsets = estimate_offsets_from_analysis()
        if offsets:
            print("Using estimated offsets (may need verification)")

    if offsets:
        print("\nvhost_virtqueue field offsets:")
        print("-" * 40)
        for field, offset in sorted(offsets.items(), key=lambda x: x[1]):
            print("  {:30s} : {:6d} (0x{:04x})".format(field, offset, offset))

        if args.export:
            print_env_exports(offsets)
    else:
        print("Could not detect offsets.")
        print("\nManual detection methods:")
        print("1. Install dwarves package and run: pahole -C vhost_virtqueue")
        print("2. Use bpftool: bpftool btf dump file /sys/kernel/btf/vmlinux format c")
        print("3. Check kernel source for your version")

if __name__ == "__main__":
    main()
