#!/usr/bin/env python3
"""Performance Test Analysis Tool - Main Program"""

import os
import sys
import yaml
import logging
import argparse
from typing import Dict, List, Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.data_locator import DataLocator
from src.parsers import PerformanceParser, ResourceParser, LogSizeParser
from src.comparator import BaselineComparator
from src.report_generator import ReportGenerator
from src.iteration_aggregator import IterationAggregator
from src.utils import parse_tool_case_name, load_test_case_metadata, extract_time_reference

logger = logging.getLogger(__name__)


def setup_logging(config: Dict):
    """Setup logging configuration

    Args:
        config: Configuration dictionary
    """
    log_config = config.get("logging", {})
    level = getattr(logging, log_config.get("level", "INFO"))
    format_str = log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    log_file = log_config.get("file", None)

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers
    )


def load_config(config_path: str) -> Dict:
    """Load configuration from YAML file

    Args:
        config_path: Path to config file

    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Loaded configuration from {config_path}")
        return config
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)


def extract_time_ranges(perf_data: Dict) -> Dict:
    """Extract time ranges from performance data for resource monitoring

    Args:
        perf_data: Performance data dictionary

    Returns:
        Dictionary of time ranges {name: (start_epoch, end_epoch)}
    """
    time_ranges = {}

    # Extract from client side (used for resource correlation)
    if "client" not in perf_data:
        return time_ranges

    client = perf_data["client"]

    # PPS time ranges
    if "pps" in client:
        if "single" in client["pps"]:
            single = client["pps"]["single"]
            time_ranges["pps_single"] = (single["start_epoch"], single["end_epoch"])

        if "multi" in client["pps"]:
            multi = client["pps"]["multi"]
            time_ranges["pps_multi"] = (multi["start_epoch"], multi["end_epoch"])

    # Throughput time ranges
    if "throughput" in client:
        if "single" in client["throughput"]:
            single = client["throughput"]["single"]
            time_ranges["throughput_single"] = (single["start_epoch"], single["end_epoch"])

        if "multi" in client["throughput"]:
            multi = client["throughput"]["multi"]
            time_ranges["throughput_multi"] = (multi["start_epoch"], multi["end_epoch"])

    return time_ranges


def process_tool_case(locator: DataLocator, tool_case_name: str,
                     baseline_data: Dict, config: Dict) -> Dict:
    """Process a single tool case

    Args:
        locator: DataLocator instance
        tool_case_name: Tool case name
        baseline_data: Baseline performance data
        config: Configuration dictionary

    Returns:
        Analysis result dictionary
    """
    logger.info(f"Processing tool case: {tool_case_name}")

    # 1. Locate data files
    paths = locator.locate_tool_case(tool_case_name)
    if not paths:
        logger.error(f"Failed to locate data for {tool_case_name}")
        return None

    # 2. Extract time reference from resource monitor (for timezone-independent time conversion)
    time_reference = None
    if "server" in paths and "ebpf_monitoring" in paths["server"]:
        monitoring = paths["server"]["ebpf_monitoring"]
        if "resource_monitor" in monitoring:
            time_reference = extract_time_reference(monitoring["resource_monitor"])
            if time_reference:
                logger.debug(f"Extracted time reference: {time_reference}")

    # 3. Parse performance data (using time reference for accurate epoch calculation)
    perf_data = PerformanceParser.parse_all(paths, time_reference)
    logger.debug(f"Parsed performance data for {tool_case_name}")

    # 4. Parse resource monitoring data
    resource_data = None
    if "server" in paths and "ebpf_monitoring" in paths["server"]:
        monitoring = paths["server"]["ebpf_monitoring"]

        if "resource_monitor" in monitoring:
            time_ranges = extract_time_ranges(perf_data)
            resource_data = ResourceParser.parse(
                monitoring["resource_monitor"],
                time_ranges
            )
            logger.debug(f"Parsed resource monitoring data for {tool_case_name}")

    # 5. Parse log size data
    log_data = None
    if "server" in paths and "ebpf_monitoring" in paths["server"]:
        monitoring = paths["server"]["ebpf_monitoring"]

        if "logsize_monitor" in monitoring:
            log_data = LogSizeParser.parse(monitoring["logsize_monitor"])
            logger.debug(f"Parsed log size data for {tool_case_name}")

    # 6. Compare with baseline
    comparison = BaselineComparator.compare(perf_data, baseline_data)
    logger.debug(f"Completed baseline comparison for {tool_case_name}")

    # 7. Parse metadata
    metadata = parse_tool_case_name(tool_case_name)

    # 8. Get command from paths
    command = paths.get("command", "N/A")

    # 9. Return complete result
    return {
        "tool_case": tool_case_name,
        "metadata": metadata,
        "command": command,
        "performance": perf_data,
        "resources": resource_data,
        "logs": {"log_size": log_data} if log_data else {},
        "comparison": comparison
    }


def get_all_topics(iteration_path: str, config: Dict) -> List[str]:
    """Get all topics to analyze

    Args:
        iteration_path: Path to iteration directory
        config: Configuration dictionary

    Returns:
        List of topic names
    """
    topics = []

    for test_type, topic_list in config["topics"].items():
        topics.extend(topic_list)

    return topics


def detect_test_type_for_topic(topic: str) -> str:
    """Detect test type (host or vm) for a topic

    Args:
        topic: Topic name

    Returns:
        "host" or "vm"
    """
    host_topics = ["system_network_performance", "linux_network_stack"]
    vm_topics = ["kvm_virt_network", "ovs_monitoring", "vm_network_performance"]

    if topic in host_topics:
        return "host"
    elif topic in vm_topics:
        return "vm"
    else:
        logger.warning(f"Unknown topic type: {topic}, defaulting to host")
        return "host"


def find_test_case_json(script_dir: str, topic: str) -> Optional[str]:
    """Find test case JSON file for a topic

    Args:
        script_dir: Script directory
        topic: Topic name

    Returns:
        Path to test case JSON file or None
    """
    # Map topic to JSON file name
    topic_json_map = {
        "system_network_performance": "performance-test-cases.json",
        "vm_network_performance": "performance-test-cases.json",
        "linux_network_stack": "linux-network-stack-test-cases.json",
        "kvm_virt_network": "kvm-virt-network-test-cases.json",
        "ovs_monitoring": "ovs-test-cases.json",
    }

    json_filename = topic_json_map.get(topic)
    if not json_filename:
        logger.warning(f"Unknown topic: {topic}")
        return None

    # Try different possible locations
    possible_base_paths = [
        os.path.join(script_dir, "..", "..", "workflow", "case", "nested-5.4"),
        os.path.join(script_dir, "..", "..", "workflow", "case", "phy-620"),
        os.path.join(script_dir, "..", "..", "workflow", "case"),
    ]

    for base_path in possible_base_paths:
        json_path = os.path.join(base_path, json_filename)
        abs_path = os.path.abspath(json_path)
        if os.path.exists(abs_path):
            logger.info(f"Found test case JSON for {topic}: {abs_path}")
            return abs_path

    logger.warning(f"Could not find test case JSON for topic: {topic}")
    return None


def main():
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Analyze performance test results"
    )

    parser.add_argument(
        "--iteration",
        type=str,
        default=None,
        help="Single iteration to analyze (overrides config, backward compatible)"
    )

    parser.add_argument(
        "--iterations",
        type=str,
        default=None,
        help="Iterations to analyze: 'all', 'iteration_001', or 'iteration_001,iteration_002'"
    )

    parser.add_argument(
        "--topic",
        type=str,
        default=None,
        help="Specific topic to analyze (default: all topics)"
    )

    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Base output directory (default: from config)"
    )

    parser.add_argument(
        "--output-subdir",
        type=str,
        default=None,
        help="Subdirectory name under output-dir (default: auto-generate from data_root)"
    )

    parser.add_argument(
        "--format",
        type=str,
        default=None,
        help="Output formats, comma-separated (default: from config)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Load configuration
    config_path = os.path.join(os.path.dirname(__file__), args.config)
    config = load_config(config_path)

    # Override config with command line arguments
    # Handle --iteration (backward compatible, single iteration)
    if args.iteration:
        config["selected_iterations"] = args.iteration

    # Handle --iterations (new, supports multiple)
    if args.iterations:
        config["selected_iterations"] = args.iterations

    if args.output_dir:
        config["output_dir"] = args.output_dir

    if args.output_subdir:
        config["output_subdir"] = args.output_subdir

    if args.format:
        config["output_formats"] = args.format.split(",")

    if args.verbose:
        config["logging"]["level"] = "DEBUG"

    # Setup logging
    setup_logging(config)

    logger.info("=" * 60)
    logger.info("Performance Test Analysis Tool")
    logger.info("=" * 60)

    # Parse selected iterations
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_root = os.path.join(script_dir, config["data_root"])

    # Handle selected_iterations configuration
    selected_iterations_config = config.get("selected_iterations", config.get("selected_iteration"))

    if selected_iterations_config == "all":
        # Use all iterations from config
        iterations_to_process = config["iterations"]
        logger.info("Processing all iterations")
    elif isinstance(selected_iterations_config, list):
        # Already a list
        iterations_to_process = selected_iterations_config
    elif isinstance(selected_iterations_config, str):
        # Single iteration or comma-separated list
        if "," in selected_iterations_config:
            iterations_to_process = [it.strip() for it in selected_iterations_config.split(",")]
        else:
            iterations_to_process = [selected_iterations_config]
    else:
        logger.error(f"Invalid selected_iterations configuration: {selected_iterations_config}")
        sys.exit(1)

    logger.info(f"Iterations to process: {', '.join(iterations_to_process)}")

    # Validate all iterations exist
    for iteration in iterations_to_process:
        iteration_path = os.path.join(data_root, iteration)
        if not os.path.exists(iteration_path):
            logger.error(f"Iteration path not found: {iteration_path}")
            sys.exit(1)

    # Determine output subdirectory name
    output_subdir = config.get("output_subdir", "")
    if not output_subdir:
        # Auto-generate from data_root: extract last component
        # e.g., "../results/1022" -> "1022"
        data_root_normalized = os.path.normpath(data_root)
        output_subdir = os.path.basename(data_root_normalized)
        logger.info(f"Auto-generated output_subdir from data_root: {output_subdir}")

    # Determine topics to analyze (same for all iterations)
    if args.topic:
        topics = [args.topic]
    else:
        # Get topics from first iteration
        first_iteration_path = os.path.join(data_root, iterations_to_process[0])
        topics = get_all_topics(first_iteration_path, config)

    logger.info(f"Topics to analyze: {', '.join(topics)}")

    # Process each iteration
    for iteration_idx, iteration in enumerate(iterations_to_process, 1):
        logger.info("")
        logger.info("=" * 60)
        logger.info(f"Processing Iteration [{iteration_idx}/{len(iterations_to_process)}]: {iteration}")
        logger.info("=" * 60)

        iteration_path = os.path.join(data_root, iteration)
        logger.info(f"Iteration path: {iteration_path}")

        # Initialize components for this iteration
        locator = DataLocator(iteration_path)

        # Set up output directory structure: {output_dir}/{output_subdir}/iteration_XXX/
        base_output = os.path.join(script_dir, config["output_dir"])
        output_dir = os.path.join(base_output, output_subdir, iteration)

        logger.info(f"Output directory: {output_dir}")

        # Process each topic
        for topic in topics:
            logger.info("")
            logger.info(f"{'=' * 60}")
            logger.info(f"Processing topic: {topic}")
            logger.info(f"{'=' * 60}")

            # Load test case metadata for this specific topic
            test_case_json_path = find_test_case_json(script_dir, topic)
            test_cases_metadata = {}
            if test_case_json_path:
                test_cases_metadata = load_test_case_metadata(test_case_json_path)
            else:
                logger.warning(f"No test case JSON found for topic: {topic}")

            # Get all tool cases for this topic
            tool_cases = locator.get_all_tool_cases(topic)
            if not tool_cases:
                logger.warning(f"No tool cases found for topic: {topic}")
                continue

            logger.info(f"Found {len(tool_cases)} tool cases")

            # Parse baseline
            test_type = detect_test_type_for_topic(topic)
            logger.info(f"Test type: {test_type}")

            baseline_paths = locator.locate_baseline(test_type)
            if not baseline_paths:
                logger.warning(f"Baseline not found for {test_type}, skipping comparison")
                baseline_data = {}
            else:
                baseline_data = PerformanceParser.parse_all(baseline_paths)
                logger.info("Parsed baseline data")

            # Process each tool case
            results = []
            for i, tool_case in enumerate(tool_cases, 1):
                logger.info(f"[{i}/{len(tool_cases)}] Processing: {tool_case}")

                try:
                    result = process_tool_case(locator, tool_case, baseline_data, config)
                    if result:
                        results.append(result)
                    else:
                        logger.warning(f"No result for {tool_case}")
                except Exception as e:
                    logger.error(f"Failed to process {tool_case}: {e}", exc_info=True)
                    continue

            logger.info(f"Successfully processed {len(results)}/{len(tool_cases)} tool cases")

            # Generate reports
            if results:
                try:
                    # Create report generator with metadata for this topic
                    report_gen = ReportGenerator(output_dir, test_cases_metadata)
                    report_gen.generate_all(topic, results, iteration)
                    logger.info(f"Generated reports for topic: {topic}")
                except Exception as e:
                    logger.error(f"Failed to generate reports for {topic}: {e}", exc_info=True)
            else:
                logger.warning(f"No results to generate report for topic: {topic}")

    logger.info("")
    logger.info("=" * 60)
    logger.info("Analysis completed!")
    logger.info("=" * 60)
    logger.info(f"Processed {len(iterations_to_process)} iteration(s): {', '.join(iterations_to_process)}")
    logger.info(f"Processed {len(topics)} topic(s): {', '.join(topics)}")

    # Show output directory structure
    base_output = os.path.join(script_dir, config["output_dir"])
    logger.info(f"Reports saved to: {base_output}/{output_subdir}/")
    for iteration in iterations_to_process:
        logger.info(f"  - {iteration}/")

    # Aggregate results from multiple iterations if configured
    if len(iterations_to_process) >= 2:
        try:
            aggregator = IterationAggregator(base_output, output_subdir)
            aggregator.aggregate_all(iterations_to_process, topics)
            logger.info(f"  - aggregated/ (from {len(iterations_to_process)} iterations)")
        except Exception as e:
            logger.error(f"Failed to aggregate iterations: {e}", exc_info=True)

    logger.info("=" * 60)


if __name__ == "__main__":
    main()
