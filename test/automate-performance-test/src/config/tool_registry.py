#!/usr/bin/env python3
"""Tool registry for validating registered tools against filesystem.

Simplified version focused on validation. Main tool loading is handled by
ConfigBootstrap.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class ToolMetadata:
    """Metadata for a registered eBPF tool."""
    name: str
    tool_id: str
    category: str
    environment: str  # 'host', 'vm', or 'both'
    local_path: str
    template: str
    parameters: Dict[str, List[Any]] = field(default_factory=dict)
    defaults: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    directions: Optional[List[str]] = None


class ToolRegistry:
    """Registry for validating eBPF tools against filesystem."""

    def __init__(self, tools_config: Dict, measurement_tools_dir: str):
        """Initialize tool registry.

        Args:
            tools_config: Tools configuration from unified config
            measurement_tools_dir: Absolute path to measurement-tools directory
        """
        self.tools_config = tools_config
        self.measurement_tools_dir = measurement_tools_dir
        self.tools: Dict[str, ToolMetadata] = {}
        self._load_tools()

    def _load_tools(self):
        """Load tools from configuration."""
        categories = self.tools_config.get('categories', {})
        tool_id_counts = {}

        for category_name, category_config in categories.items():
            tools_list = category_config.get('tools', [])
            category_env = category_config.get('environment', 'host')
            category_directions = category_config.get('directions', {})

            for tool_config in tools_list:
                script = tool_config.get('script', '')
                if not script:
                    continue

                local_path = f"{category_name}/{script}"
                tool_id = script.replace('.py', '').replace('.bt', '').replace('-', '_')

                # Handle duplicates
                base_id = tool_id
                if base_id in tool_id_counts:
                    tool_id_counts[base_id] += 1
                    tool_id = f"{base_id}_v{tool_id_counts[base_id]}"
                else:
                    tool_id_counts[base_id] = 1

                # Determine directions
                if category_directions:
                    directions = list(category_directions.keys())
                else:
                    directions = None

                tool = ToolMetadata(
                    name=tool_config.get('name', script),
                    tool_id=tool_id,
                    category=category_name,
                    environment=tool_config.get('environment', category_env),
                    local_path=local_path,
                    template=tool_config.get('template', ''),
                    parameters=tool_config.get('parameters', {}),
                    defaults={k: v for k, v in tool_config.items()
                             if k not in ('script', 'template', 'parameters',
                                          'name', 'environment', 'directions')},
                    directions=directions
                )
                self.tools[tool_id] = tool

        logger.info(f"Loaded {len(self.tools)} tools from {len(categories)} categories")

    def validate_filesystem(self) -> Dict[str, bool]:
        """Validate all registered tools exist on filesystem."""
        results = {}
        for tool_id, tool in self.tools.items():
            full_path = os.path.join(self.measurement_tools_dir, tool.local_path)
            exists = os.path.isfile(full_path)
            results[tool_id] = exists
            if not exists:
                logger.warning(f"Tool not found: {tool_id} -> {full_path}")

        valid_count = sum(1 for v in results.values() if v)
        logger.info(f"Validation: {valid_count}/{len(results)} tools found")
        return results

    def get_tool(self, tool_id: str) -> Optional[ToolMetadata]:
        """Get tool by ID."""
        return self.tools.get(tool_id)

    def get_tools_by_category(self, category: str) -> List[ToolMetadata]:
        """Get all tools in a category."""
        return [t for t in self.tools.values() if t.category == category]

    def get_tools_by_environment(self, environment: str) -> List[ToolMetadata]:
        """Get all tools for an environment."""
        return [t for t in self.tools.values()
                if t.environment == environment or t.environment == 'both']

    def list_tools(self) -> List[str]:
        """List all registered tool IDs."""
        return list(self.tools.keys())

    def list_categories(self) -> List[str]:
        """List all categories."""
        return list(set(t.category for t in self.tools.values()))

    def get_all_tools(self) -> List[ToolMetadata]:
        """Get all registered tools."""
        return list(self.tools.values())

    def get_missing_tools(self) -> List[str]:
        """Get list of tools that don't exist on filesystem."""
        validation = self.validate_filesystem()
        return [tool_id for tool_id, exists in validation.items() if not exists]

    def get_scripts_by_category(self) -> Dict[str, List[str]]:
        """Get scripts grouped by category."""
        result = {}
        for tool in self.tools.values():
            if tool.category not in result:
                result[tool.category] = []
            result[tool.category].append(tool.name)
        return result
