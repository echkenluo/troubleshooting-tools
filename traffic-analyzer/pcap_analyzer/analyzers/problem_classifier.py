#!/usr/bin/env python
"""
Problem Classifier

Categorizes and prioritizes detected problems.
Implements FR-PCAP-ANA-010.
"""

from typing import List, Dict
from collections import defaultdict

from ..models import Problem


class ProblemClassifier:
    """Problem categorization and prioritization engine"""

    # Severity priority mapping (lower number = higher priority)
    SEVERITY_PRIORITY = {
        'CRITICAL': 1,
        'HIGH': 2,
        'WARNING': 3,
        'MEDIUM': 4,
        'LOW': 5
    }

    # Problem type categories
    PROBLEM_CATEGORIES = {
        'PERFORMANCE': ['HIGH_LATENCY', 'WINDOW_ISSUES'],
        'RELIABILITY': ['PACKET_LOSS', 'RETRANS_BURST', 'OUT_OF_ORDER'],
        'CONNECTIVITY': ['HANDSHAKE_FAILURE', 'CONNECTION_RESET']
    }

    def classify(self, problems: List[Problem]) -> Dict[str, List[Problem]]:
        """
        Classify problems by category

        Args:
            problems: List of detected problems

        Returns:
            Dictionary mapping category names to lists of problems

        Implements: FR-PCAP-ANA-010
        """
        categorized = defaultdict(list)

        for problem in problems:
            category = self._get_category(problem.type)
            categorized[category].append(problem)

        return dict(categorized)

    def rank_by_severity(self, problems: List[Problem]) -> List[Problem]:
        """
        Sort problems by severity (highest priority first)

        Args:
            problems: List of detected problems

        Returns:
            Sorted list of problems (CRITICAL first, LOW last)

        Implements: FR-PCAP-ANA-010
        """
        return sorted(
            problems,
            key=lambda p: self.SEVERITY_PRIORITY.get(p.severity, 99)
        )

    def filter_by_severity(self, problems: List[Problem], min_severity: str) -> List[Problem]:
        """
        Filter problems by minimum severity level

        Args:
            problems: List of detected problems
            min_severity: Minimum severity to include (CRITICAL, HIGH, WARNING, MEDIUM, LOW)

        Returns:
            Filtered list of problems meeting severity threshold
        """
        min_priority = self.SEVERITY_PRIORITY.get(min_severity, 99)

        return [
            p for p in problems
            if self.SEVERITY_PRIORITY.get(p.severity, 99) <= min_priority
        ]

    def summarize(self, problems: List[Problem]) -> Dict[str, int]:
        """
        Generate summary statistics for problems

        Args:
            problems: List of detected problems

        Returns:
            Dictionary with counts by type and severity
        """
        summary = {
            'total': len(problems),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int)
        }

        for problem in problems:
            summary['by_type'][problem.type] += 1
            summary['by_severity'][problem.severity] += 1
            category = self._get_category(problem.type)
            summary['by_category'][category] += 1

        # Convert defaultdicts to regular dicts
        summary['by_type'] = dict(summary['by_type'])
        summary['by_severity'] = dict(summary['by_severity'])
        summary['by_category'] = dict(summary['by_category'])

        return summary

    def _get_category(self, problem_type: str) -> str:
        """
        Get category for problem type

        Args:
            problem_type: Problem type string

        Returns:
            Category name (PERFORMANCE, RELIABILITY, CONNECTIVITY, or OTHER)
        """
        for category, types in self.PROBLEM_CATEGORIES.items():
            if problem_type in types:
                return category

        return 'OTHER'
