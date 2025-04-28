#!/usr/bin/env python3
"""
GitLab Repository Analyzer - Main Entry Point

This is the main entry point for the GitLab Repository Analyzer.
It handles command-line arguments and launches the interactive menu.
"""

import os
import sys
import argparse
import gitlab
from typing import Dict, Any

from .config import Config
from .core.scanner import GitLabScanner
from .cli.menu import display_main_menu, handle_main_menu
from .cli.display import print_banner, print_error


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="GitLab Repository Analyzer - Detect technologies and analyze relationships."
    )
    parser.add_argument(
        "--config", help="Path to configuration file", default="config.json"
    )
    parser.add_argument(
        "--token", help="GitLab API token (overrides config file)"
    )
    parser.add_argument(
        "--group", help="GitLab group ID to scan (overrides config file)"
    )
    parser.add_argument(
        "--url", help="GitLab URL (default: https://gitlab.com)", default="https://gitlab.com"
    )
    parser.add_argument(
        "--output", help="Output file path"
    )
    parser.add_argument(
        "--non-interactive", action="store_true", help="Run in non-interactive mode"
    )
    
    return parser.parse_args()


def get_gitlab_client(config: Config, args: Any) -> gitlab.Gitlab:
    """Initialize GitLab client from config and arguments."""
    # Get token from arguments, environment, or config in that order
    token = args.token or os.environ.get('GITLAB_TOKEN') or config.get('gitlab', 'token')
    
    if not token:
        print_error("GitLab token not found. Please set via --token argument, GITLAB_TOKEN environment variable, or config file.")
        sys.exit(1)
    
    # Get GitLab URL
    url = args.url or config.get('gitlab', 'url', default='https://gitlab.com')
    
    try:
        # Connect to GitLab
        return gitlab.Gitlab(url, private_token=token)
    except Exception as e:
        print_error(f"Failed to connect to GitLab: {str(e)}")
        sys.exit(1)


def get_group_id(config: Config, args: Any) -> str:
    """Get GitLab group ID from arguments, environment, or config."""
    group_id = args.group or os.environ.get('GITLAB_GROUP_ID') or config.get('gitlab', 'group_id')
    
    if not group_id:
        print_error("GitLab group ID not found. Please set via --group argument, GITLAB_GROUP_ID environment variable, or config file.")
        sys.exit(1)
    
    return group_id


def run_non_interactive(gitlab_client, group_id: str, config: Config, args: Any) -> None:
    """Run the analyzer in non-interactive mode."""
    from .core.scanner import GitLabScanner
    
    # Create scanner
    scanner = GitLabScanner(
        gitlab_instance=gitlab_client,
        group_id=group_id,
        config=config
    )
    
    # Run scan
    scanner.scan()
    
    # Generate report
    output_file = args.output or "gitlab_analysis_report.json"
    scanner.generate_report(output_file)
    
    print(f"Analysis complete. Report saved to {output_file}")


def main():
    """Main entry point for the application."""
    # Parse command-line arguments
    args = parse_arguments()
    
    # Load configuration
    config = Config(args.config)
    
    # Initialize GitLab client
    gitlab_client = get_gitlab_client(config, args)
    
    # Get group ID
    group_id = get_group_id(config, args)
    
    # Check if running in non-interactive mode
    if args.non_interactive:
        run_non_interactive(gitlab_client, group_id, config, args)
        return
    
    # Show banner
    print_banner()
    
    # Start interactive menu
    handle_main_menu(gitlab_client, group_id, config)


if __name__ == "__main__":
    main()
