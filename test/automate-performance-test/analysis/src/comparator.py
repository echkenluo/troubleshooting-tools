"""Baseline Comparator - Compare eBPF tool case performance with baseline"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class BaselineComparator:
    """Comparator for eBPF tool case vs baseline performance"""

    @staticmethod
    def compare(ebpf_data: Dict, baseline_data: Dict) -> Dict:
        """Compare eBPF tool case performance with baseline

        Args:
            ebpf_data: Performance data from eBPF tool case
            baseline_data: Performance data from baseline

        Returns:
            Dictionary with comparison results
        """
        result = {}

        # Compare latency (lower is better)
        if "client" in ebpf_data and "client" in baseline_data:
            if "latency" in ebpf_data["client"] and "latency" in baseline_data["client"]:
                result["latency"] = BaselineComparator._compare_latency(
                    ebpf_data["client"]["latency"],
                    baseline_data["client"]["latency"]
                )

        # Compare throughput (higher is better)
        # Both client and server side
        for side in ["client", "server"]:
            if side in ebpf_data and side in baseline_data:
                if "throughput" in ebpf_data[side] and "throughput" in baseline_data[side]:
                    key = f"throughput_{side}"
                    result[key] = BaselineComparator._compare_throughput(
                        ebpf_data[side]["throughput"],
                        baseline_data[side]["throughput"]
                    )

        # Compare PPS (higher is better)
        # Both client and server side
        for side in ["client", "server"]:
            if side in ebpf_data and side in baseline_data:
                if "pps" in ebpf_data[side] and "pps" in baseline_data[side]:
                    key = f"pps_{side}"
                    result[key] = BaselineComparator._compare_pps(
                        ebpf_data[side]["pps"],
                        baseline_data[side]["pps"]
                    )

        return result

    @staticmethod
    def _compare_latency(ebpf_latency: Dict, baseline_latency: Dict) -> Dict:
        """Compare latency metrics

        Args:
            ebpf_latency: eBPF latency data
            baseline_latency: Baseline latency data

        Returns:
            Dictionary with comparison results
        """
        result = {}

        for protocol in ["tcp_rr", "udp_rr"]:
            if protocol in ebpf_latency and protocol in baseline_latency:
                ebpf_mean = ebpf_latency[protocol]["mean_us"]
                baseline_mean = baseline_latency[protocol]["mean_us"]

                result[f"{protocol}_mean_us"] = BaselineComparator._calculate_diff(
                    ebpf_mean, baseline_mean
                )

                # Also compare max latency
                ebpf_max = ebpf_latency[protocol]["max_us"]
                baseline_max = baseline_latency[protocol]["max_us"]

                result[f"{protocol}_max_us"] = BaselineComparator._calculate_diff(
                    ebpf_max, baseline_max
                )

        return result

    @staticmethod
    def _compare_throughput(ebpf_throughput: Dict, baseline_throughput: Dict) -> Dict:
        """Compare throughput metrics

        Args:
            ebpf_throughput: eBPF throughput data
            baseline_throughput: Baseline throughput data

        Returns:
            Dictionary with comparison results
        """
        result = {}

        for stream_type in ["single", "multi"]:
            if stream_type in ebpf_throughput and stream_type in baseline_throughput:
                ebpf_val = ebpf_throughput[stream_type]["throughput_gbps"]
                baseline_val = baseline_throughput[stream_type]["throughput_gbps"]

                result[f"{stream_type}_gbps"] = BaselineComparator._calculate_diff(
                    ebpf_val, baseline_val
                )

        return result

    @staticmethod
    def _compare_pps(ebpf_pps: Dict, baseline_pps: Dict) -> Dict:
        """Compare PPS metrics

        Args:
            ebpf_pps: eBPF PPS data
            baseline_pps: Baseline PPS data

        Returns:
            Dictionary with comparison results
        """
        result = {}

        for stream_type in ["single", "multi"]:
            if stream_type in ebpf_pps and stream_type in baseline_pps:
                ebpf_val = ebpf_pps[stream_type]["pps"]
                baseline_val = baseline_pps[stream_type]["pps"]

                result[f"{stream_type}_pps"] = BaselineComparator._calculate_diff(
                    ebpf_val, baseline_val
                )

        return result

    @staticmethod
    def _calculate_diff(ebpf_val: float, baseline_val: float) -> Dict:
        """Calculate difference between eBPF and baseline values

        Args:
            ebpf_val: Value from eBPF tool case
            baseline_val: Value from baseline

        Returns:
            Dictionary with ebpf, baseline, diff_absolute, diff_percent
        """
        diff_absolute = ebpf_val - baseline_val

        if baseline_val != 0:
            diff_percent = (diff_absolute / baseline_val) * 100
        else:
            diff_percent = 0 if diff_absolute == 0 else float('inf')

        return {
            "ebpf": round(ebpf_val, 2) if isinstance(ebpf_val, float) else ebpf_val,
            "baseline": round(baseline_val, 2) if isinstance(baseline_val, float) else baseline_val,
            "diff_absolute": round(diff_absolute, 2) if isinstance(diff_absolute, float) else diff_absolute,
            "diff_percent": round(diff_percent, 2)
        }
