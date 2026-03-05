#!/usr/bin/env python3
"""Testcase loader for existing test cases"""

import json
import os
import logging
from typing import Dict, List, Any, Optional


logger = logging.getLogger(__name__)


class TestcaseLoader:
    """Loader for existing testcase files"""

    def __init__(self, base_path: str = ""):
        """Initialize testcase loader

        Args:
            base_path: Base path for relative testcase files
        """
        self.base_path = base_path

    def load_testcase_file(self, testcase_file: str) -> Dict[str, Any]:
        """Load testcase file

        Args:
            testcase_file: Path to testcase file

        Returns:
            Parsed testcase content
        """
        if not os.path.isabs(testcase_file) and self.base_path:
            filepath = os.path.join(self.base_path, testcase_file)
        else:
            filepath = testcase_file

        if not os.path.exists(filepath):
            logger.warning(f"Testcase file not found: {filepath}")
            return {}

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = json.load(f)
                logger.info(f"Loaded testcase file: {testcase_file}")
                return content
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON file {testcase_file}: {str(e)}")
            return {}
        except Exception as e:
            logger.error(f"Error loading testcase file {testcase_file}: {str(e)}")
            return {}

    def get_case_details(self, testcase_file: str, case_id: int) -> Dict[str, Any]:
        """Get specific case details

        Args:
            testcase_file: Path to testcase file
            case_id: Case ID to retrieve

        Returns:
            Case details or default values
        """
        testcases = self.load_testcase_file(testcase_file)

        # Try different possible structures
        case_details = None

        # Structure 1: Direct list with id field
        if isinstance(testcases, list):
            for case in testcases:
                if case.get('id') == case_id:
                    case_details = case
                    break

        # Structure 2: Dictionary with case keys
        elif isinstance(testcases, dict):
            case_key = f"case_{case_id}"
            if case_key in testcases:
                case_details = testcases[case_key]
            elif str(case_id) in testcases:
                case_details = testcases[str(case_id)]
            elif 'test_cases' in testcases:
                for case in testcases['test_cases']:
                    if case.get('id') == case_id:
                        case_details = case
                        break

        if not case_details:
            logger.warning(f"Case {case_id} not found in {testcase_file}, using defaults")
            return self._get_default_case_details(case_id)

        return self._normalize_case_details(case_details, case_id)

    def get_multiple_cases(self, testcase_file: str, case_ids: List[int]) -> Dict[int, Dict[str, Any]]:
        """Get multiple case details

        Args:
            testcase_file: Path to testcase file
            case_ids: List of case IDs

        Returns:
            Dictionary mapping case_id to case details
        """
        results = {}
        for case_id in case_ids:
            results[case_id] = self.get_case_details(testcase_file, case_id)
        return results

    def list_available_cases(self, testcase_file: str) -> List[int]:
        """List available case IDs

        Args:
            testcase_file: Path to testcase file

        Returns:
            List of available case IDs
        """
        testcases = self.load_testcase_file(testcase_file)
        case_ids = []

        if isinstance(testcases, list):
            for case in testcases:
                if 'id' in case:
                    case_ids.append(case['id'])

        elif isinstance(testcases, dict):
            # Check for direct numeric keys
            for key in testcases.keys():
                if key.isdigit():
                    case_ids.append(int(key))
                elif key.startswith('case_'):
                    try:
                        case_id = int(key[5:])
                        case_ids.append(case_id)
                    except ValueError:
                        pass

            # Check for test_cases array
            if 'test_cases' in testcases:
                for case in testcases['test_cases']:
                    if 'id' in case:
                        case_ids.append(case['id'])

        return sorted(case_ids)

    def _normalize_case_details(self, case_details: Dict[str, Any], case_id: int) -> Dict[str, Any]:
        """Normalize case details to standard format

        Args:
            case_details: Raw case details
            case_id: Case ID

        Returns:
            Normalized case details
        """
        normalized = {
            'id': case_id,
            'name': case_details.get('name', f'case_{case_id}'),
            'command': case_details.get('command', case_details.get('cmd', '')),
            'duration': case_details.get('duration', case_details.get('time', 30)),
            'description': case_details.get('description', case_details.get('desc', '')),
            'parameters': case_details.get('parameters', case_details.get('params', {})),
            'requirements': case_details.get('requirements', case_details.get('reqs', []))
        }

        # Handle different command formats
        if not normalized['command']:
            # Try to build command from components
            tool = case_details.get('tool', '')
            script = case_details.get('script', '')
            args = case_details.get('args', case_details.get('arguments', ''))

            if tool and script:
                normalized['command'] = f"{tool} {script}"
                if args:
                    normalized['command'] += f" {args}"

        return normalized

    def _get_default_case_details(self, case_id: int) -> Dict[str, Any]:
        """Get default case details when case not found

        Args:
            case_id: Case ID

        Returns:
            Default case details
        """
        return {
            'id': case_id,
            'name': f'case_{case_id}',
            'command': f'echo "Case {case_id} command not found"',
            'duration': 30,
            'description': f'Default case {case_id}',
            'parameters': {},
            'requirements': []
        }

    def validate_case_requirements(self, case_details: Dict[str, Any],
                                  environment: str) -> bool:
        """Validate case requirements for environment

        Args:
            case_details: Case details
            environment: Target environment

        Returns:
            Whether requirements are met
        """
        requirements = case_details.get('requirements', [])

        for req in requirements:
            if isinstance(req, str):
                if req == 'root' or req == 'sudo':
                    # Check if running with proper privileges
                    # This is a placeholder - actual implementation would check
                    continue
                elif req.startswith('env:'):
                    required_env = req[4:]
                    if environment != required_env:
                        logger.warning(f"Case requires environment {required_env}, got {environment}")
                        return False

        return True