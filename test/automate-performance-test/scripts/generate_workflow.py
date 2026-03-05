#!/usr/bin/env python3
"""Workflow generation script"""

import sys
import os
import argparse
import logging
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from core.workflow_generator import EBPFCentricWorkflowGenerator
from utils.config_loader import ConfigLoader


def main():
    """Main workflow generation function"""
    parser = argparse.ArgumentParser(description='Generate eBPF Performance Test Workflow')
    parser.add_argument('--config-dir', default='../config',
                       help='Configuration directory path')
    parser.add_argument('--output', default='workflow.json',
                       help='Output workflow file')
    parser.add_argument('--validate', action='store_true',
                       help='Validate generated workflow')
    parser.add_argument('--pretty', action='store_true',
                       help='Pretty print workflow to stdout')

    args = parser.parse_args()

    # Setup basic logging
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    try:
        # Load configurations
        config_dir = os.path.abspath(args.config_dir)
        config_loader = ConfigLoader(config_dir)
        configs = config_loader.load_all_configs()

        logger.info("Configurations loaded successfully")

        # Generate workflow
        workflow_generator = EBPFCentricWorkflowGenerator()
        workflow_spec = workflow_generator.generate_workflow_spec(
            configs['ssh'], configs['env'], configs['perf'], configs['ebpf']
        )

        logger.info(f"Generated workflow with {len(workflow_spec['test_sequence'])} test cycles")

        # Validate if requested
        if args.validate:
            if workflow_generator.validate_workflow(workflow_spec):
                logger.info("Workflow validation: PASSED")
            else:
                logger.error("Workflow validation: FAILED")
                return 1

        # Export workflow
        workflow_generator.export_workflow(workflow_spec, args.output)
        logger.info(f"Workflow saved to: {args.output}")

        # Pretty print if requested
        if args.pretty:
            import json
            print("\n" + "="*50)
            print("GENERATED WORKFLOW")
            print("="*50)
            print(json.dumps(workflow_spec, indent=2))

        return 0

    except Exception as e:
        logger.error(f"Workflow generation failed: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())