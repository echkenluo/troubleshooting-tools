#!/usr/bin/env python3
"""Comprehensive workflow verification script"""

import sys
import os
import json
import yaml
from collections import defaultdict
from typing import Dict, List, Tuple

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from utils.config_loader import ConfigLoader
from utils.testcase_loader import TestcaseLoader


class WorkflowVerifier:
    """Verify workflow correctness"""

    def __init__(self, workflow_file: str, config_dir: str):
        """Initialize verifier

        Args:
            workflow_file: Path to workflow JSON file
            config_dir: Path to configuration directory
        """
        self.workflow_file = workflow_file
        self.config_dir = config_dir
        self.errors = []
        self.warnings = []

    def load_workflow(self) -> Dict:
        """Load workflow file"""
        with open(self.workflow_file, 'r') as f:
            return json.load(f)

    def load_configs(self) -> Dict:
        """Load all configuration files"""
        loader = ConfigLoader(self.config_dir)
        return loader.load_all_configs()

    def verify_structure(self, workflow: Dict) -> bool:
        """Verify basic workflow structure

        Args:
            workflow: Workflow specification

        Returns:
            True if structure is valid
        """
        print("\n" + "="*70)
        print("STRUCTURE VERIFICATION")
        print("="*70)

        required_keys = ['metadata', 'test_sequence', 'global_config']

        # Check required top-level keys
        for key in required_keys:
            if key not in workflow:
                self.errors.append(f"Missing required key: {key}")
                print(f"✗ Missing required key: {key}")
                return False
            else:
                print(f"✓ Found required key: {key}")

        # Check metadata
        metadata_keys = ['generation_time', 'total_test_cycles', 'environments']
        for key in metadata_keys:
            if key not in workflow['metadata']:
                self.warnings.append(f"Missing metadata key: {key}")
                print(f"⚠ Missing metadata key: {key}")
            else:
                print(f"✓ Found metadata key: {key}")

        # Check test sequence is not empty
        if not workflow['test_sequence']:
            self.errors.append("Test sequence is empty")
            print("✗ Test sequence is empty")
            return False
        else:
            print(f"✓ Test sequence contains {len(workflow['test_sequence'])} cycles")

        return len(self.errors) == 0

    def verify_test_cycles(self, workflow: Dict) -> bool:
        """Verify individual test cycles

        Args:
            workflow: Workflow specification

        Returns:
            True if all cycles are valid
        """
        print("\n" + "="*70)
        print("TEST CYCLE VERIFICATION")
        print("="*70)

        cycle_errors = 0
        required_cycle_keys = ['cycle_id', 'cycle_type', 'environment', 'ebpf_case', 'test_cycle']

        for idx, cycle in enumerate(workflow['test_sequence']):
            # Check required keys
            for key in required_cycle_keys:
                if key not in cycle:
                    self.errors.append(f"Cycle {idx}: Missing key {key}")
                    cycle_errors += 1

            # Verify cycle type
            if cycle.get('cycle_type') not in ['baseline', 'ebpf_test']:
                self.errors.append(f"Cycle {idx}: Invalid cycle_type: {cycle.get('cycle_type')}")
                cycle_errors += 1

            # Verify eBPF case structure
            ebpf_case = cycle.get('ebpf_case', {})
            if cycle.get('cycle_type') == 'ebpf_test':
                required_ebpf_keys = ['case_id', 'tool_id', 'program', 'command']
                for key in required_ebpf_keys:
                    if key not in ebpf_case:
                        self.errors.append(f"Cycle {idx}: Missing ebpf_case key {key}")
                        cycle_errors += 1

        if cycle_errors == 0:
            print(f"✓ All {len(workflow['test_sequence'])} test cycles are valid")
        else:
            print(f"✗ Found {cycle_errors} errors in test cycles")

        return cycle_errors == 0

    def verify_case_coverage(self, workflow: Dict, configs: Dict) -> bool:
        """Verify all configured test cases are in workflow

        Args:
            workflow: Workflow specification
            configs: Configuration dictionaries

        Returns:
            True if all cases are covered
        """
        print("\n" + "="*70)
        print("TEST CASE COVERAGE VERIFICATION")
        print("="*70)

        # Extract configured cases from ebpf config
        configured_cases = defaultdict(list)
        for tool_id, tool_config in configs['ebpf']['ebpf_tools'].items():
            case_ids = tool_config['testcase_source']['case_ids']
            environments = tool_config['test_associations']['applicable_environments']
            for case_id in case_ids:
                for env in environments:
                    configured_cases[tool_id].append((case_id, env))

        # Extract cases from workflow
        workflow_cases = defaultdict(list)
        for cycle in workflow['test_sequence']:
            if cycle['cycle_type'] == 'ebpf_test':
                ebpf_case = cycle['ebpf_case']
                tool_id = ebpf_case['tool_id']
                case_id = ebpf_case['case_id']
                env = cycle['environment']
                workflow_cases[tool_id].append((case_id, env))

        # Compare coverage
        all_covered = True
        for tool_id, expected_cases in configured_cases.items():
            actual_cases = workflow_cases.get(tool_id, [])
            expected_set = set(expected_cases)
            actual_set = set(actual_cases)

            if expected_set == actual_set:
                print(f"✓ {tool_id}: All {len(expected_cases)} cases covered")
            else:
                all_covered = False
                missing = expected_set - actual_set
                extra = actual_set - expected_set

                if missing:
                    print(f"✗ {tool_id}: Missing {len(missing)} cases: {missing}")
                    self.errors.append(f"{tool_id}: Missing cases {missing}")

                if extra:
                    print(f"⚠ {tool_id}: Extra {len(extra)} cases: {extra}")
                    self.warnings.append(f"{tool_id}: Extra cases {extra}")

        return all_covered

    def verify_environment_distribution(self, workflow: Dict, configs: Dict) -> bool:
        """Verify environment distribution is correct

        Args:
            workflow: Workflow specification
            configs: Configuration dictionaries

        Returns:
            True if distribution is correct
        """
        print("\n" + "="*70)
        print("ENVIRONMENT DISTRIBUTION VERIFICATION")
        print("="*70)

        # Count expected cases per environment
        expected_env_counts = defaultdict(int)
        for tool_id, tool_config in configs['ebpf']['ebpf_tools'].items():
            case_count = len(tool_config['testcase_source']['case_ids'])
            environments = tool_config['test_associations']['applicable_environments']
            for env in environments:
                expected_env_counts[env] += case_count

        # Count actual cycles per environment
        actual_env_counts = defaultdict(int)
        baseline_env_counts = defaultdict(int)
        ebpf_env_counts = defaultdict(int)

        for cycle in workflow['test_sequence']:
            env = cycle['environment']
            actual_env_counts[env] += 1

            if cycle['cycle_type'] == 'baseline':
                baseline_env_counts[env] += 1
            elif cycle['cycle_type'] == 'ebpf_test':
                ebpf_env_counts[env] += 1

        # Verify counts
        all_correct = True
        for env in configs['env']['test_environments'].keys():
            baseline_count = baseline_env_counts.get(env, 0)
            ebpf_count = ebpf_env_counts.get(env, 0)
            total_count = actual_env_counts.get(env, 0)
            expected_ebpf = expected_env_counts.get(env, 0)
            expected_total = expected_ebpf + 1  # eBPF cases + 1 baseline

            print(f"\nEnvironment: {env}")
            print(f"  Baseline cycles: {baseline_count} (expected: 1) {'✓' if baseline_count == 1 else '✗'}")
            print(f"  eBPF cycles: {ebpf_count} (expected: {expected_ebpf}) {'✓' if ebpf_count == expected_ebpf else '✗'}")
            print(f"  Total cycles: {total_count} (expected: {expected_total}) {'✓' if total_count == expected_total else '✓'}")

            if baseline_count != 1:
                self.errors.append(f"{env}: Expected 1 baseline cycle, got {baseline_count}")
                all_correct = False

            if ebpf_count != expected_ebpf:
                self.errors.append(f"{env}: Expected {expected_ebpf} eBPF cycles, got {ebpf_count}")
                all_correct = False

        return all_correct

    def verify_tool_distribution(self, workflow: Dict, configs: Dict) -> bool:
        """Verify tool distribution is correct

        Args:
            workflow: Workflow specification
            configs: Configuration dictionaries

        Returns:
            True if distribution is correct
        """
        print("\n" + "="*70)
        print("TOOL DISTRIBUTION VERIFICATION")
        print("="*70)

        # Count cycles by tool
        workflow_tool_counts = defaultdict(int)
        for cycle in workflow['test_sequence']:
            if cycle['cycle_type'] == 'ebpf_test':
                tool_id = cycle['ebpf_case']['tool_id']
                workflow_tool_counts[tool_id] += 1

        # Expected counts from config
        all_correct = True
        for tool_id, tool_config in configs['ebpf']['ebpf_tools'].items():
            case_count = len(tool_config['testcase_source']['case_ids'])
            env_count = len(tool_config['test_associations']['applicable_environments'])
            expected_count = case_count * env_count
            actual_count = workflow_tool_counts.get(tool_id, 0)

            status = '✓' if expected_count == actual_count else '✗'
            print(f"{status} {tool_id}: {actual_count} cycles (expected: {expected_count})")

            if expected_count != actual_count:
                self.errors.append(f"{tool_id}: Expected {expected_count} cycles, got {actual_count}")
                all_correct = False

        return all_correct

    def generate_report(self) -> str:
        """Generate verification report

        Returns:
            Report string
        """
        report = []
        report.append("\n" + "="*70)
        report.append("VERIFICATION SUMMARY")
        report.append("="*70)

        if not self.errors and not self.warnings:
            report.append("\n✓ All verifications PASSED")
            report.append("✓ Workflow is VALID and ready to use")
        else:
            if self.errors:
                report.append(f"\n✗ Found {len(self.errors)} ERRORS:")
                for error in self.errors:
                    report.append(f"  ✗ {error}")

            if self.warnings:
                report.append(f"\n⚠ Found {len(self.warnings)} WARNINGS:")
                for warning in self.warnings:
                    report.append(f"  ⚠ {warning}")

        report.append("\n" + "="*70)
        return "\n".join(report)

    def run_all_verifications(self) -> bool:
        """Run all verification checks

        Returns:
            True if all verifications pass
        """
        print("\n" + "="*70)
        print("WORKFLOW VERIFICATION")
        print(f"Workflow file: {self.workflow_file}")
        print("="*70)

        # Load data
        workflow = self.load_workflow()
        configs = self.load_configs()

        # Run verifications
        checks = [
            ("Structure", self.verify_structure(workflow)),
            ("Test Cycles", self.verify_test_cycles(workflow)),
            ("Case Coverage", self.verify_case_coverage(workflow, configs)),
            ("Environment Distribution", self.verify_environment_distribution(workflow, configs)),
            ("Tool Distribution", self.verify_tool_distribution(workflow, configs))
        ]

        # Generate report
        report = self.generate_report()
        print(report)

        # Return overall status
        all_passed = all(result for _, result in checks)
        return all_passed and len(self.errors) == 0


def main():
    """Main verification function"""
    import argparse

    parser = argparse.ArgumentParser(description='Verify workflow correctness')
    parser.add_argument('--workflow', default='../workflow-complete.json',
                       help='Workflow file to verify')
    parser.add_argument('--config-dir', default='../config',
                       help='Configuration directory')

    args = parser.parse_args()

    # Run verification
    verifier = WorkflowVerifier(args.workflow, args.config_dir)
    success = verifier.run_all_verifications()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
