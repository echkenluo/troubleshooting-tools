#!/usr/bin/env python
"""
PCAP Analyzer CLI

Command-line interface for PCAP traffic analysis tool.
Supports three modes: summary, details, and analysis.
"""

import argparse
import sys
from datetime import datetime
from typing import Optional

from pcap_analyzer.parser import PcapParser, TsharkParser
from pcap_analyzer.statistics import (
    StatisticsEngine,
    FlowAggregator,
    TimeSeriesAnalyzer,
    TopTalkersAnalyzer
)
from pcap_analyzer.analyzers import (
    TCPAnalyzer,
    ProblemDetector,
    DiagnosisEngine,
    ProblemClassifier
)
from pcap_analyzer.filters import FilterEngine
from pcap_analyzer.formatters import JSONFormatter, ProgressTracker
from common.utils import print_error, print_info, validate_file_path, format_bytes, format_rate


def _build_display_filter(args):
    """
    Build tshark display filter from CLI arguments

    Args:
        args: Command-line arguments

    Returns:
        Display filter string or None
    """
    filters = []

    if args.src_ip:
        filters.append(f"ip.src=={args.src_ip}")

    if args.dst_ip:
        filters.append(f"ip.dst=={args.dst_ip}")

    if args.src_port:
        filters.append(f"tcp.srcport=={args.src_port}")

    if args.dst_port:
        filters.append(f"tcp.dstport=={args.dst_port}")

    if args.protocol:
        protocol_lower = args.protocol.lower()
        if protocol_lower == 'tcp':
            filters.append("tcp")
        elif protocol_lower == 'udp':
            filters.append("udp")
        elif protocol_lower == 'icmp':
            filters.append("icmp")

    return " && ".join(filters) if filters else None


def run_summary_mode(args):
    """
    Execute summary mode analysis

    Provides L2/L3/L4 statistics, flow aggregation, and time-series analysis.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running summary mode on {args.pcap}")

    # Initialize components
    parser = PcapParser()
    stats_engine = StatisticsEngine()
    flow_aggregator = FlowAggregator()
    timeseries_analyzer = TimeSeriesAnalyzer()
    top_talkers_analyzer = TopTalkersAnalyzer()
    filter_engine = FilterEngine()
    progress = ProgressTracker()

    try:
        # Get file info
        file_info = parser.get_file_info(args.pcap)
        print_info(f"Total packets: {file_info.packet_count}")

        # Parse packets (with optional filtering)
        packets = parser.parse_file(args.pcap)

        # Apply filters if specified
        if args.src_ip or args.dst_ip:
            packets = filter_engine.apply_ip_filter(packets, args.src_ip, args.dst_ip)

        if args.src_port or args.dst_port:
            packets = filter_engine.apply_port_filter(packets, args.src_port, args.dst_port)

        if args.protocol:
            packets = filter_engine.apply_protocol_filter(packets, args.protocol)

        # Convert iterator to list for multiple passes
        packets_list = list(packets)
        print_info(f"Packets after filtering: {len(packets_list)}")

        # Compute statistics
        print_info("Computing L2 statistics...")
        l2_stats = stats_engine.compute_l2_stats(iter(packets_list))

        print_info("Computing L3 statistics...")
        l3_stats = stats_engine.compute_l3_stats(iter(packets_list))

        print_info("Computing L4 statistics...")
        l4_stats = stats_engine.compute_l4_stats(iter(packets_list))

        # Aggregate flows
        print_info("Aggregating flows...")
        flows = flow_aggregator.aggregate_flows(iter(packets_list))
        print_info(f"Total flows: {len(flows)}")

        # Classify flows by protocol
        flow_by_protocol = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'OTHER': 0}
        for five_tuple in flows.keys():
            proto = five_tuple.protocol.upper()
            if proto == 'TCP':
                flow_by_protocol['TCP'] += 1
            elif proto == 'UDP':
                flow_by_protocol['UDP'] += 1
            elif proto == 'ICMP':
                flow_by_protocol['ICMP'] += 1
            else:
                flow_by_protocol['OTHER'] += 1

        # Time-series analysis
        print_info("Computing time-series statistics...")
        timeseries_stats = timeseries_analyzer.compute_rates(
            iter(packets_list),
            interval=args.interval
        )

        # Top talkers
        print_info("Identifying top talkers...")
        top_talkers = top_talkers_analyzer.identify_top_talkers(flows, n=args.top_n)

        # Build result
        result = {
            'file_info': file_info,
            'l2_stats': l2_stats,
            'l3_stats': l3_stats,
            'l4_stats': l4_stats,
            'flow_count': len(flows),
            'flow_by_protocol': flow_by_protocol,
            'timeseries': timeseries_stats,
            'top_talkers': top_talkers
        }

        # Output
        if args.output:
            formatter = JSONFormatter()
            formatter.write_to_file(result, args.output)
            print_info(f"Results written to {args.output}")
        else:
            print_summary_results(result)

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def run_details_mode(args):
    """
    Execute details mode analysis

    Provides detailed TCP flow analysis including retransmissions, DupACK, etc.
    Uses tshark for accurate TCP analysis.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running details mode on {args.pcap}")

    # Initialize components
    parser = TsharkParser()
    flow_aggregator = FlowAggregator()
    tcp_analyzer = TCPAnalyzer()

    try:
        # Build tshark display filter from arguments
        display_filter = _build_display_filter(args)

        # Parse PCAP with tshark (automatically aggregates into flows)
        print_info("Parsing PCAP with tshark (this may take a few minutes)...")
        flows = parser.parse_file(args.pcap, display_filter=display_filter)

        print_info(f"Found {len(flows)} TCP flows")

        # Analyze each TCP flow
        detailed_results = []
        for five_tuple, flow in flows.items():
            # Skip if no packets
            if not flow.packets:
                continue

            # TCP deep analysis
            retrans_stats = tcp_analyzer.analyze_retransmissions(flow)
            dupack_stats = tcp_analyzer.analyze_dupack(flow)
            zero_window_stats = tcp_analyzer.analyze_zero_window(flow)
            sack_stats = tcp_analyzer.analyze_sack(flow)
            tcp_features = tcp_analyzer.analyze_features(flow)

            detailed_results.append({
                'five_tuple': five_tuple,
                'flow_stats': flow_aggregator.get_flow_statistics(flow),
                'retrans_stats': retrans_stats,
                'dupack_stats': dupack_stats,
                'zero_window_stats': zero_window_stats,
                'sack_stats': sack_stats,
                'tcp_features': tcp_features
            })

        result = {
            'total_flows': len(flows),
            'tcp_flows': len(detailed_results),
            'detailed_analysis': detailed_results
        }

        # Output
        if args.output:
            formatter = JSONFormatter()
            formatter.write_to_file(result, args.output)
            print_info(f"Results written to {args.output}")
        else:
            print_detailed_results(result, top_n=args.top_n)

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def run_analysis_mode(args):
    """
    Execute analysis mode with problem detection

    Identifies network problems and provides diagnosis/recommendations.
    Uses tshark for accurate TCP analysis.

    Args:
        args: Command-line arguments
    """
    print_info(f"Running analysis mode on {args.pcap}")

    # Initialize components
    parser = TsharkParser()
    flow_aggregator = FlowAggregator()
    problem_detector = ProblemDetector()
    diagnosis_engine = DiagnosisEngine()
    problem_classifier = ProblemClassifier()

    try:
        # Build tshark display filter from arguments
        display_filter = _build_display_filter(args)

        # Parse PCAP with tshark (automatically aggregates into flows)
        print_info("Parsing PCAP with tshark (this may take a few minutes)...")
        flows = parser.parse_file(args.pcap, display_filter=display_filter)

        print_info(f"Found {len(flows)} TCP flows")

        # Analyze each TCP flow for problems
        all_problems = []
        flow_analyses = []

        for five_tuple, flow in flows.items():
            # Skip if no packets
            if not flow.packets:
                continue

            # Detect problems in this flow
            problems = problem_detector.detect_all(flow)

            for problem in problems:
                # Analyze causes
                causes = diagnosis_engine.analyze_causes(problem, flow)

                # Generate recommendations
                recommendations = diagnosis_engine.generate_recommendations(problem, causes)

                flow_analyses.append({
                    'five_tuple': five_tuple,
                    'problem': problem,
                    'causes': causes,
                    'recommendations': recommendations
                })

                all_problems.append(problem)

        # Classify and rank problems
        ranked_problems = problem_classifier.rank_by_severity(all_problems)
        categorized_problems = problem_classifier.classify(all_problems)
        summary = problem_classifier.summarize(all_problems)

        result = {
            'total_flows': len(flows),
            'problems_found': len(all_problems),
            'summary': summary,
            'ranked_problems': ranked_problems,
            'categorized_problems': categorized_problems,
            'detailed_analysis': flow_analyses
        }

        # Output
        if args.output:
            formatter = JSONFormatter()
            formatter.write_to_file(result, args.output)
            print_info(f"Results written to {args.output}")
        else:
            print_analysis_results(result)

    except Exception as e:
        print_error(f"Analysis failed: {str(e)}")
        if args.debug:
            raise
        sys.exit(1)


def print_summary_results(result):
    """Print summary mode results to console"""
    import os
    print("\n" + "="*60)
    print("PCAP SUMMARY ANALYSIS")
    print("="*60)

    # File info
    file_info = result['file_info']
    print(f"\nFile: {os.path.basename(file_info.file_path)}")
    print(f"Total Packets: {file_info.packet_count}")
    if file_info.duration:
        print(f"Duration: {file_info.duration:.3f}s")

    # Layer 2 Statistics
    l2 = result['l2_stats']
    print("\n" + "-"*60)
    print("LAYER 2 STATISTICS (Data Link)")
    print("-"*60)
    print(f"Total Frames: {l2.total_frames}")
    print(f"\nEthernet Types:")
    for eth_type, count in sorted(l2.ethernet_types.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / l2.total_frames * 100) if l2.total_frames > 0 else 0
        print(f"  {eth_type}: {count} ({percentage:.2f}%)")

    print(f"\nFrame Size Distribution:")
    for size_range, count in sorted(l2.frame_size_distribution.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / l2.total_frames * 100) if l2.total_frames > 0 else 0
        print(f"  {size_range} bytes: {count} ({percentage:.2f}%)")

    # Layer 3 Statistics
    l3 = result['l3_stats']
    print("\n" + "-"*60)
    print("LAYER 3 STATISTICS (Network)")
    print("-"*60)
    print(f"Total Packets: {l3.total_packets}")
    print(f"\nIP Versions:")
    for ip_ver, count in sorted(l3.ip_versions.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / l3.total_packets * 100) if l3.total_packets > 0 else 0
        print(f"  {ip_ver}: {count} ({percentage:.2f}%)")

    print(f"\nProtocol Distribution:")
    for proto, count in sorted(l3.protocol_distribution.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / l3.total_packets * 100) if l3.total_packets > 0 else 0
        print(f"  {proto}: {count} ({percentage:.2f}%)")

    # Layer 4 Statistics
    l4 = result['l4_stats']
    print("\n" + "-"*60)
    print("LAYER 4 STATISTICS (Transport)")
    print("-"*60)
    print(f"Total Traffic: {format_bytes(l4.total_bytes)}")
    print(f"\nTCP: {l4.tcp_packets} packets, {format_bytes(l4.tcp_bytes)}")
    print(f"UDP: {l4.udp_packets} packets, {format_bytes(l4.udp_bytes)}")
    print(f"Other: {l4.other_packets} packets, {format_bytes(l4.other_bytes)}")

    # Flow Statistics
    print("\n" + "-"*60)
    print("FLOW STATISTICS")
    print("-"*60)
    print(f"Total Flows: {result['flow_count']}")
    flow_by_proto = result['flow_by_protocol']
    for proto in ['TCP', 'UDP', 'ICMP', 'OTHER']:
        if flow_by_proto[proto] > 0:
            print(f"  {proto} Flows: {flow_by_proto[proto]}")

    # Time-Series Statistics
    ts = result['timeseries']
    print("\n" + "-"*60)
    print("TIME-SERIES STATISTICS")
    print("-"*60)
    print(f"Average Packet Rate: {ts.avg_pps:.2f} pps")
    print(f"Peak Packet Rate: {ts.peak_pps:.2f} pps")
    print(f"Average Throughput: {format_rate(ts.avg_bps)}")
    print(f"Peak Throughput: {format_rate(ts.peak_bps)}")

    # Top Talkers
    tt = result['top_talkers']
    print("\n" + "-"*60)
    print("TOP TALKERS")
    print("-"*60)
    print(f"Top Senders:")
    for ip, bytes_count in tt.top_senders[:5]:
        print(f"  {ip}: {format_bytes(bytes_count)}")


def print_detailed_results(result, top_n=10):
    """Print details mode results to console"""
    print("\n" + "="*60)
    print("PCAP DETAILED ANALYSIS")
    print("="*60)

    print(f"\nTotal Flows: {result['total_flows']}")
    print(f"TCP Flows: {result['tcp_flows']}")

    for i, analysis in enumerate(result['detailed_analysis'][:top_n], 1):
        print(f"\n--- Flow {i} ---")
        ft = analysis['five_tuple']
        print(f"{ft.src_ip}:{ft.src_port} -> {ft.dst_ip}:{ft.dst_port}")

        # Flow statistics
        flow_stats = analysis['flow_stats']
        print(f"Packets: {flow_stats.packet_count}, Bytes: {format_bytes(flow_stats.byte_count)}, Duration: {flow_stats.duration:.3f}s")

        # Retransmission statistics with breakdown
        retrans = analysis['retrans_stats']
        print(f"Retransmissions: {retrans.retrans_packets}/{retrans.total_packets} ({retrans.retrans_rate*100:.2f}%)")
        print(f"  Fast Retrans: {retrans.fast_retrans}, Timeout Retrans: {retrans.timeout_retrans}, Spurious: {retrans.spurious_retrans}")

        # DupACK statistics (always show)
        dupack = analysis['dupack_stats']
        print(f"DupACKs: {dupack.total_dupack} (rate: {dupack.dupack_rate*100:.2f}%), Max consecutive: {dupack.max_consecutive_dupack}")

        # Zero-window statistics (always show)
        zero_win = analysis['zero_window_stats']
        if zero_win.zero_window_events > 0:
            print(f"Zero Windows: {zero_win.zero_window_events} events, Total: {zero_win.total_duration:.2f}s, Avg: {zero_win.avg_duration:.2f}s, Max: {zero_win.max_duration:.2f}s")
        else:
            print(f"Zero Windows: 0 events")

        # SACK statistics (always show)
        sack = analysis['sack_stats']
        if sack.sack_enabled:
            print(f"SACK: Enabled, Packets: {sack.sack_packets}, DSACK: {sack.dsack_packets}, Avg blocks/pkt: {sack.avg_sack_blocks:.2f}")
        else:
            print(f"SACK: Not enabled")

        # TCP features (always show all)
        features = analysis['tcp_features']
        feature_parts = []
        feature_parts.append(f"SACK={'Yes' if features.sack_permitted else 'No'}")
        feature_parts.append(f"WScale={'Yes' if features.window_scaling else 'No'}")
        if features.window_scaling:
            feature_parts.append(f"WScale Factor={features.window_scale_factor}")
        feature_parts.append(f"Timestamps={'Yes' if features.timestamps else 'No'}")
        feature_parts.append(f"MSS={features.mss}")
        print(f"TCP Features: {', '.join(feature_parts)}")


def print_analysis_results(result):
    """Print analysis mode results to console"""
    print("\n" + "="*60)
    print("PCAP PROBLEM ANALYSIS")
    print("="*60)

    summary = result['summary']
    print(f"\nTotal Flows Analyzed: {result['total_flows']}")
    print(f"Problems Found: {result['problems_found']}")

    if result['problems_found'] == 0:
        print("\nNo significant problems detected!")
        return

    print(f"\nProblems by Severity:")
    for severity, count in summary['by_severity'].items():
        print(f"  {severity}: {count}")

    print(f"\nProblems by Category:")
    for category, count in summary['by_category'].items():
        print(f"  {category}: {count}")

    print(f"\nAll Problems (by severity):")
    for i, analysis in enumerate(result['detailed_analysis'], 1):
        problem = analysis['problem']
        five_tuple = analysis['five_tuple']

        print(f"\n{i}. [{problem.severity}] {problem.type}")
        print(f"   Connection: {five_tuple.src_ip}:{five_tuple.src_port} -> {five_tuple.dst_ip}:{five_tuple.dst_port}")
        print(f"   {problem.description}")

        # Show causes if available
        causes = analysis.get('causes', [])
        if causes:
            print(f"   Possible causes:")
            for cause in causes[:3]:  # Show top 3 causes
                print(f"     - {cause}")

        # Show top recommendation if available
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            print(f"   Recommendation: {recommendations[0]}")


def main():
    """Main entry point for PCAP Analyzer CLI"""
    parser = argparse.ArgumentParser(
        description='PCAP Traffic Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required arguments
    parser.add_argument(
        '--mode',
        choices=['summary', 'details', 'analysis'],
        required=True,
        help='Analysis mode'
    )
    parser.add_argument(
        '--pcap',
        required=True,
        help='Path to PCAP file'
    )

    # Filter options
    parser.add_argument('--src-ip', help='Filter by source IP address')
    parser.add_argument('--dst-ip', help='Filter by destination IP address')
    parser.add_argument('--src-port', type=int, help='Filter by source port')
    parser.add_argument('--dst-port', type=int, help='Filter by destination port')
    parser.add_argument('--protocol', help='Filter by protocol (tcp, udp, icmp)')

    # Output options
    parser.add_argument('--output', '-o', help='Output file (JSON format)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    # Mode-specific options
    parser.add_argument('--interval', type=float, default=1.0, help='Time interval for timeseries (seconds)')
    parser.add_argument('--top-n', type=int, default=10, help='Number of top talkers to show')

    args = parser.parse_args()

    # Validate PCAP file
    if not validate_file_path(args.pcap):
        print_error(f"PCAP file not found or not readable: {args.pcap}")
        sys.exit(1)

    # Dispatch to appropriate mode
    if args.mode == 'summary':
        run_summary_mode(args)
    elif args.mode == 'details':
        run_details_mode(args)
    elif args.mode == 'analysis':
        run_analysis_mode(args)


if __name__ == '__main__':
    main()
