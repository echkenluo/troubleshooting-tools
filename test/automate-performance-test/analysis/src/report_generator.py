"""Report Generator - Generate separated analysis reports"""

import os
import csv
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Report generator with separated report types and hierarchical headers"""

    def __init__(self, output_dir: str, test_cases_metadata: Dict = None):
        """Initialize ReportGenerator

        Args:
            output_dir: Output directory for reports
            test_cases_metadata: Optional test cases metadata for program names
        """
        self.output_dir = output_dir
        self.test_cases_metadata = test_cases_metadata or {}
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(self, topic: str, results: List[Dict], iteration: str):
        """Generate all types of reports

        Args:
            topic: Topic name
            results: List of analysis results for all tool cases
            iteration: Iteration name
        """
        logger.info(f"Generating separated reports for {topic}")

        # Generate separated reports
        self.generate_latency_report(topic, results, iteration)
        self.generate_throughput_report(topic, results, iteration)
        self.generate_pps_report(topic, results, iteration)
        self.generate_resources_report(topic, results, iteration)

        # Generate summary report (all metrics combined)
        self.generate_summary_report(topic, results, iteration)

        # Generate overview markdown
        self.generate_overview_markdown(topic, results, iteration)

        logger.info(f"Generated 6 report files for topic {topic}")

    def _get_command(self, result: Dict) -> str:
        """Get full command for a tool case

        Args:
            result: Analysis result dictionary

        Returns:
            Full command or "N/A"
        """
        return result.get("command", "N/A")

    def generate_latency_report(self, topic: str, results: List[Dict], iteration: str):
        """Generate latency-only report

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_latency_{iteration}.csv")

        headers = [
            "Tool Case",
            "Command",
            "TCP RR Min (us)",
            "TCP RR Mean (us)",
            "TCP RR Max (us)",
            "TCP RR Baseline (us)",
            "TCP RR Diff (%)",
            "UDP RR Min (us)",
            "UDP RR Mean (us)",
            "UDP RR Max (us)",
            "UDP RR Baseline (us)",
            "UDP RR Diff (%)"
        ]

        rows = []
        for result in results:
            row = self._extract_latency_row(result)
            if row:
                rows.append(row)

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            logger.info(f"Generated latency report: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate latency report: {e}")

    def generate_throughput_report(self, topic: str, results: List[Dict], iteration: str):
        """Generate throughput report

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_throughput_{iteration}.csv")

        headers = [
            "Tool Case",
            "Command",
            # Client
            "Client Single (Gbps)",
            "Client Single Baseline (Gbps)",
            "Client Single Diff (%)",
            "Client Multi (Gbps)",
            "Client Multi Baseline (Gbps)",
            "Client Multi Diff (%)",
            # Server
            "Server Single (Gbps)",
            "Server Single Baseline (Gbps)",
            "Server Single Diff (%)",
            "Server Multi (Gbps)",
            "Server Multi Baseline (Gbps)",
            "Server Multi Diff (%)"
        ]

        rows = []
        for result in results:
            row = self._extract_throughput_row(result)
            if row:
                rows.append(row)

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            logger.info(f"Generated throughput report: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate throughput report: {e}")

    def generate_pps_report(self, topic: str, results: List[Dict], iteration: str):
        """Generate PPS report

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_pps_{iteration}.csv")

        headers = [
            "Tool Case",
            "Command",
            # Client
            "Client Single PPS",
            "Client Single Baseline",
            "Client Single Diff (%)",
            "Client Multi PPS",
            "Client Multi Baseline",
            "Client Multi Diff (%)",
            # Server
            "Server Single PPS",
            "Server Single Baseline",
            "Server Single Diff (%)",
            "Server Multi PPS",
            "Server Multi Baseline",
            "Server Multi Diff (%)"
        ]

        rows = []
        for result in results:
            row = self._extract_pps_row(result)
            if row:
                rows.append(row)

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            logger.info(f"Generated PPS report: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate PPS report: {e}")

    def generate_resources_report(self, topic: str, results: List[Dict], iteration: str):
        """Generate eBPF resources report

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_resources_{iteration}.csv")

        # Create hierarchical headers
        # Row 1: Main categories
        header_row1 = [
            "Tool Case",
            "Command",
            "PPS Single", "", "",  # CPU Avg, CPU Max, Mem Max
            "PPS Multi", "", "",
            "TP Single", "", "",
            "TP Multi", "", "",
            "Full Cycle", "", "", "", "",
            "Log Size", ""
        ]

        # Row 2: Sub-column headers
        header_row2 = [
            "",  # Tool Case
            "",  # Command
            "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # PPS Single
            "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # PPS Multi
            "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # TP Single
            "CPU Avg (%)", "CPU Max (%)", "Mem Max (KB)",  # TP Multi
            "Max RSS (KB)", "Max VSZ (KB)", "CPU Avg (%)", "CPU Max (%)", "Total Samples",  # Full Cycle
            "Size (Bytes)", "Size (Human)"  # Log Size
        ]

        rows = []
        for result in results:
            row = self._extract_resources_row(result)
            if row:
                rows.append(row)

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(header_row1)
                writer.writerow(header_row2)
                writer.writerows(rows)
            logger.info(f"Generated resources report: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate resources report: {e}")

    def generate_summary_report(self, topic: str, results: List[Dict], iteration: str):
        """Generate comprehensive summary report with all metrics

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_summary_{iteration}.csv")

        # Define comprehensive headers
        headers = [
            "Tool Case",
            "Command",
            # Latency metrics
            "TCP RR Mean (us)",
            "TCP RR Baseline (us)",
            "TCP RR Diff (%)",
            "UDP RR Mean (us)",
            "UDP RR Baseline (us)",
            "UDP RR Diff (%)",
            # Throughput metrics
            "Client TP Single (Gbps)",
            "Client TP Single Baseline (Gbps)",
            "Client TP Single Diff (%)",
            "Client TP Multi (Gbps)",
            "Client TP Multi Baseline (Gbps)",
            "Client TP Multi Diff (%)",
            # PPS metrics
            "Client PPS Single",
            "Client PPS Single Baseline",
            "Client PPS Single Diff (%)",
            "Client PPS Multi",
            "Client PPS Multi Baseline",
            "Client PPS Multi Diff (%)",
            # Resource metrics (key metrics only)
            "CPU Avg (%)",
            "CPU Max (%)",
            "Mem Max (KB)",
            "Log Size (MB)"
        ]

        rows = []
        for result in results:
            row = self._extract_summary_all_row(result)
            if row:
                rows.append(row)

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            logger.info(f"Generated summary report: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate summary report: {e}")

    def generate_overview_markdown(self, topic: str, results: List[Dict], iteration: str):
        """Generate overview markdown report

        Args:
            topic: Topic name
            results: List of analysis results
            iteration: Iteration name
        """
        output_path = os.path.join(self.output_dir, f"{topic}_overview_{iteration}.md")

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write(f"# {topic.replace('_', ' ').title()} - Analysis Overview\n\n")
                f.write(f"**Iteration:** {iteration}\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"**Total Cases:** {len(results)}\n\n")

                # Write summary statistics
                f.write("## Summary Statistics\n\n")
                stats = self._calculate_summary_stats(results)
                f.write(f"- Total test cases: {stats['total_cases']}\n")
                f.write(f"- Cases with latency data: {stats['latency_count']}\n")
                f.write(f"- Cases with throughput data: {stats['throughput_count']}\n")
                f.write(f"- Cases with PPS data: {stats['pps_count']}\n")
                f.write(f"- Cases with resource data: {stats['resource_count']}\n\n")

                # Write performance summary table
                f.write("## Performance Summary\n\n")
                f.write("| Tool Case | Command | Latency Diff (%) | Throughput Diff (%) | PPS Diff (%) |\n")
                f.write("|-----------|---------|------------------|---------------------|---------------|\n")

                for result in results:
                    row = self._extract_summary_row(result)
                    f.write("| " + " | ".join(str(v) for v in row) + " |\n")

                # Write notes
                f.write("\n## Notes\n\n")
                f.write("- Positive diff% for latency indicates performance degradation (higher latency)\n")
                f.write("- Negative diff% for throughput/PPS indicates performance degradation\n")
                f.write("- N/A indicates missing data\n\n")

                # Write report file list
                f.write("## Detailed Reports\n\n")
                f.write(f"1. **Latency Report**: `{topic}_latency_{iteration}.csv`\n")
                f.write(f"2. **Throughput Report**: `{topic}_throughput_{iteration}.csv`\n")
                f.write(f"3. **PPS Report**: `{topic}_pps_{iteration}.csv`\n")
                f.write(f"4. **Resources Report**: `{topic}_resources_{iteration}.csv`\n")

            logger.info(f"Generated overview markdown: {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate overview markdown: {e}")

    def _extract_latency_row(self, result: Dict) -> List:
        """Extract latency data row"""
        def safe_get(d, *keys, default="N/A"):
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        metadata = result.get("metadata", {})
        perf = result.get("performance", {})
        comparison = result.get("comparison", {})

        # Get client latency data
        client_latency = safe_get(perf, "client", "latency", default={})
        tcp_rr = safe_get(client_latency, "tcp_rr", default={})
        udp_rr = safe_get(client_latency, "udp_rr", default={})

        # Get comparison data
        tcp_comp = safe_get(comparison, "latency", "tcp_rr_mean_us", default={})
        udp_comp = safe_get(comparison, "latency", "udp_rr_mean_us", default={})

        return [
            result.get("tool_case", "N/A"),
            self._get_command(result),
            safe_get(tcp_rr, "min_us"),
            safe_get(tcp_rr, "mean_us"),
            safe_get(tcp_rr, "max_us"),
            safe_get(tcp_comp, "baseline"),
            safe_get(tcp_comp, "diff_percent"),
            safe_get(udp_rr, "min_us"),
            safe_get(udp_rr, "mean_us"),
            safe_get(udp_rr, "max_us"),
            safe_get(udp_comp, "baseline"),
            safe_get(udp_comp, "diff_percent")
        ]

    def _extract_throughput_row(self, result: Dict) -> List:
        """Extract throughput data row"""
        def safe_get(d, *keys, default="N/A"):
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        metadata = result.get("metadata", {})
        comparison = result.get("comparison", {})

        # Client data
        client_single = safe_get(comparison, "throughput_client", "single_gbps", default={})
        client_multi = safe_get(comparison, "throughput_client", "multi_gbps", default={})

        # Server data
        server_single = safe_get(comparison, "throughput_server", "single_gbps", default={})
        server_multi = safe_get(comparison, "throughput_server", "multi_gbps", default={})

        return [
            result.get("tool_case", "N/A"),
            self._get_command(result),
            safe_get(client_single, "ebpf"),
            safe_get(client_single, "baseline"),
            safe_get(client_single, "diff_percent"),
            safe_get(client_multi, "ebpf"),
            safe_get(client_multi, "baseline"),
            safe_get(client_multi, "diff_percent"),
            safe_get(server_single, "ebpf"),
            safe_get(server_single, "baseline"),
            safe_get(server_single, "diff_percent"),
            safe_get(server_multi, "ebpf"),
            safe_get(server_multi, "baseline"),
            safe_get(server_multi, "diff_percent")
        ]

    def _extract_pps_row(self, result: Dict) -> List:
        """Extract PPS data row"""
        def safe_get(d, *keys, default="N/A"):
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        metadata = result.get("metadata", {})
        comparison = result.get("comparison", {})

        # Client data
        client_single = safe_get(comparison, "pps_client", "single_pps", default={})
        client_multi = safe_get(comparison, "pps_client", "multi_pps", default={})

        # Server data
        server_single = safe_get(comparison, "pps_server", "single_pps", default={})
        server_multi = safe_get(comparison, "pps_server", "multi_pps", default={})

        return [
            result.get("tool_case", "N/A"),
            self._get_command(result),
            safe_get(client_single, "ebpf"),
            safe_get(client_single, "baseline"),
            safe_get(client_single, "diff_percent"),
            safe_get(client_multi, "ebpf"),
            safe_get(client_multi, "baseline"),
            safe_get(client_multi, "diff_percent"),
            safe_get(server_single, "ebpf"),
            safe_get(server_single, "baseline"),
            safe_get(server_single, "diff_percent"),
            safe_get(server_multi, "ebpf"),
            safe_get(server_multi, "baseline"),
            safe_get(server_multi, "diff_percent")
        ]

    def _extract_resources_row(self, result: Dict) -> List:
        """Extract resources data row for each test type"""
        def safe_get(d, *keys, default="N/A"):
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        resources = result.get("resources", {})
        logs = result.get("logs", {})

        time_range_stats = safe_get(resources, "time_range_stats", default={})
        full_cycle = safe_get(resources, "full_cycle", default={})
        log_size = safe_get(logs, "log_size", default={})

        return [
            result.get("tool_case", "N/A"),
            self._get_command(result),
            # PPS Single metrics
            safe_get(time_range_stats, "pps_single", "cpu", "avg_percent"),
            safe_get(time_range_stats, "pps_single", "cpu", "max_percent"),
            safe_get(time_range_stats, "pps_single", "memory", "max_rss_kb"),
            # PPS Multi metrics
            safe_get(time_range_stats, "pps_multi", "cpu", "avg_percent"),
            safe_get(time_range_stats, "pps_multi", "cpu", "max_percent"),
            safe_get(time_range_stats, "pps_multi", "memory", "max_rss_kb"),
            # TP Single metrics
            safe_get(time_range_stats, "throughput_single", "cpu", "avg_percent"),
            safe_get(time_range_stats, "throughput_single", "cpu", "max_percent"),
            safe_get(time_range_stats, "throughput_single", "memory", "max_rss_kb"),
            # TP Multi metrics
            safe_get(time_range_stats, "throughput_multi", "cpu", "avg_percent"),
            safe_get(time_range_stats, "throughput_multi", "cpu", "max_percent"),
            safe_get(time_range_stats, "throughput_multi", "memory", "max_rss_kb"),
            # Full cycle
            safe_get(full_cycle, "max_rss_kb"),
            safe_get(full_cycle, "max_vsz_kb"),
            safe_get(full_cycle, "avg_cpu_percent"),
            safe_get(full_cycle, "max_cpu_percent"),
            safe_get(full_cycle, "total_samples"),
            # Log size
            safe_get(log_size, "final_size_bytes"),
            safe_get(log_size, "final_size_human")
        ]


    def _extract_summary_row(self, result: Dict) -> List:
        """Extract summary row for markdown overview"""
        def safe_get(d, *keys, default="N/A"):
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        metadata = result.get("metadata", {})
        comparison = result.get("comparison", {})

        tool_case = result.get("tool_case", "N/A")
        if len(tool_case) > 30:
            tool_case = tool_case[:27] + "..."

        command = self._get_command(result)

        # Get representative diff values
        latency_diff = safe_get(comparison, "latency", "tcp_rr_mean_us", "diff_percent")
        tp_diff = safe_get(comparison, "throughput_client", "single_gbps", "diff_percent")
        pps_diff = safe_get(comparison, "pps_client", "single_pps", "diff_percent")

        return [
            tool_case,
            command,
            latency_diff,
            tp_diff,
            pps_diff
        ]

    def _calculate_summary_stats(self, results: List[Dict]) -> Dict:
        """Calculate summary statistics"""
        stats = {
            "total_cases": len(results),
            "latency_count": 0,
            "throughput_count": 0,
            "pps_count": 0,
            "resource_count": 0
        }

        for result in results:
            perf = result.get("performance", {})
            resources = result.get("resources")

            if perf.get("client", {}).get("latency"):
                stats["latency_count"] += 1

            if perf.get("client", {}).get("throughput"):
                stats["throughput_count"] += 1

            if perf.get("client", {}).get("pps"):
                stats["pps_count"] += 1

            if resources:
                stats["resource_count"] += 1

        return stats

    def _extract_summary_all_row(self, result: Dict) -> List:
        """Extract comprehensive summary row with all metrics

        Args:
            result: Analysis result dictionary

        Returns:
            List of all metric values
        """
        def safe_get(d, *keys, default="N/A"):
            for key in keys:
                if isinstance(d, dict) and key in d:
                    d = d[key]
                else:
                    return default
            return d if d is not None else default

        perf = result.get("performance", {})
        comparison = result.get("comparison", {})
        resources = result.get("resources", {})
        logs = result.get("logs", {})

        # Latency data
        client_latency = safe_get(perf, "client", "latency", default={})
        tcp_rr = safe_get(client_latency, "tcp_rr", default={})
        udp_rr = safe_get(client_latency, "udp_rr", default={})
        tcp_comp = safe_get(comparison, "latency", "tcp_rr_mean_us", default={})
        udp_comp = safe_get(comparison, "latency", "udp_rr_mean_us", default={})

        # Throughput data
        client_tp_single = safe_get(comparison, "throughput_client", "single_gbps", default={})
        client_tp_multi = safe_get(comparison, "throughput_client", "multi_gbps", default={})

        # PPS data
        client_pps_single = safe_get(comparison, "pps_client", "single_pps", default={})
        client_pps_multi = safe_get(comparison, "pps_client", "multi_pps", default={})

        # Resource data - aggregate across all time ranges
        time_range_stats = safe_get(resources, "time_range_stats", default={})
        full_cycle = safe_get(resources, "full_cycle", default={})
        log_size = safe_get(logs, "log_size", default={})

        # Calculate average CPU across all time ranges
        cpu_avgs = []
        cpu_maxs = []
        mem_maxs = []
        for range_name in ["pps_single", "pps_multi", "throughput_single", "throughput_multi"]:
            cpu_avg = safe_get(time_range_stats, range_name, "cpu", "avg_percent")
            cpu_max = safe_get(time_range_stats, range_name, "cpu", "max_percent")
            mem_max = safe_get(time_range_stats, range_name, "memory", "max_rss_kb")
            if cpu_avg != "N/A":
                cpu_avgs.append(float(cpu_avg))
            if cpu_max != "N/A":
                cpu_maxs.append(float(cpu_max))
            if mem_max != "N/A":
                mem_maxs.append(float(mem_max))

        avg_cpu = round(sum(cpu_avgs) / len(cpu_avgs), 2) if cpu_avgs else "N/A"
        max_cpu = round(max(cpu_maxs), 2) if cpu_maxs else "N/A"
        max_mem = round(max(mem_maxs), 2) if mem_maxs else "N/A"

        # Fallback to full_cycle data if time_range_stats is empty
        if avg_cpu == "N/A":
            full_cycle_cpu_avg = safe_get(full_cycle, "avg_cpu_percent")
            if full_cycle_cpu_avg != "N/A":
                avg_cpu = full_cycle_cpu_avg
        if max_cpu == "N/A":
            full_cycle_cpu_max = safe_get(full_cycle, "max_cpu_percent")
            if full_cycle_cpu_max != "N/A":
                max_cpu = full_cycle_cpu_max
        if max_mem == "N/A":
            full_cycle_mem = safe_get(full_cycle, "max_rss_kb")
            if full_cycle_mem != "N/A":
                max_mem = full_cycle_mem  # Keep in KB, consistent with header

        # Log size in MB
        log_size_bytes = safe_get(log_size, "final_size_bytes")
        log_size_mb = round(int(log_size_bytes) / (1024 * 1024), 2) if log_size_bytes != "N/A" else "N/A"

        return [
            result.get("tool_case", "N/A"),
            self._get_command(result),
            # Latency
            safe_get(tcp_rr, "mean_us"),
            safe_get(tcp_comp, "baseline"),
            safe_get(tcp_comp, "diff_percent"),
            safe_get(udp_rr, "mean_us"),
            safe_get(udp_comp, "baseline"),
            safe_get(udp_comp, "diff_percent"),
            # Throughput
            safe_get(client_tp_single, "ebpf"),
            safe_get(client_tp_single, "baseline"),
            safe_get(client_tp_single, "diff_percent"),
            safe_get(client_tp_multi, "ebpf"),
            safe_get(client_tp_multi, "baseline"),
            safe_get(client_tp_multi, "diff_percent"),
            # PPS
            safe_get(client_pps_single, "ebpf"),
            safe_get(client_pps_single, "baseline"),
            safe_get(client_pps_single, "diff_percent"),
            safe_get(client_pps_multi, "ebpf"),
            safe_get(client_pps_multi, "baseline"),
            safe_get(client_pps_multi, "diff_percent"),
            # Resources
            avg_cpu,
            max_cpu,
            max_mem,
            log_size_mb
        ]
