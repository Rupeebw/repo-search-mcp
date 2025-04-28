"""
Interactive menu system for GitLab Repository Analyzer.
Provides a user-friendly interface for configuring and running the analyzer.
"""

import os
import sys
import time
from typing import Dict, List, Tuple, Any, Optional
import gitlab

from ..config import Config
from ..core.scanner import GitLabScanner
from .input import select_multiple_items, toggle_multiple_options, configure_custom_patterns
from .display import print_banner, print_section_header, print_error, print_success, clear_screen


def display_main_menu() -> str:
    """
    Display the main menu.
    
    Returns:
        User's choice
    """
    print("\n===== GitLab Repository Analyzer =====")
    print("1. Scan repositories")
    print("2. Configure analysis options")
    print("3. View previous scan results")
    print("4. Export/generate reports")
    print("5. Help")
    print("6. Exit")
    
    choice = input("\nSelect an option (1-6): ")
    return choice


def handle_main_menu(gitlab_client: gitlab.Gitlab, group_id: str, config: Config) -> None:
    """
    Handle the main menu logic.
    
    Args:
        gitlab_client: GitLab API client
        group_id: GitLab group ID
        config: Current configuration
    """
    while True:
        clear_screen()
        print_banner()
        choice = display_main_menu()
        
        if choice == "1":
            # Scan repositories
            scan_type, scan_config = display_scan_menu(gitlab_client, group_id, config)
            if scan_type != "6":  # Not back to main menu
                perform_scan(gitlab_client, group_id, config, scan_type, scan_config)
                input("\nPress Enter to continue...")
        
        elif choice == "2":
            # Configure options
            handle_configuration_menu(config)
        
        elif choice == "3":
            # View previous results
            display_results_menu(config)
            input("\nPress Enter to continue...")
        
        elif choice == "4":
            # Export/generate reports
            export_format = display_export_menu()
            if export_format:
                file_path = input("\nEnter output file path [gitlab_analysis_report.json]: ").strip()
                if not file_path:
                    file_path = "gitlab_analysis_report.json"
                
                # Handle export
                try:
                    from ..reporting.exporters import export_report
                    export_report({}, file_path, export_format)
                    print_success(f"Report exported to {file_path}")
                except Exception as e:
                    print_error(f"Error exporting report: {str(e)}")
                
                input("\nPress Enter to continue...")
        
        elif choice == "5":
            # Display help
            display_help()
            input("\nPress Enter to continue...")
        
        elif choice == "6":
            # Exit
            print("\nExiting GitLab Repository Analyzer. Goodbye!")
            sys.exit(0)
        
        else:
            print_error("Invalid option selected. Please try again.")
            time.sleep(1)


def display_scan_menu(gitlab_client: gitlab.Gitlab, group_id: str, config: Config) -> Tuple[str, Dict[str, Any]]:
    """
    Display the scan repositories menu.
    
    Args:
        gitlab_client: GitLab API client
        group_id: GitLab group ID
        config: Current configuration
        
    Returns:
        Tuple of (scan type, scan configuration)
    """
    clear_screen()
    print_section_header("Scan Repositories")
    print("1. Scan entire group")
    print("2. Scan specific repositories")
    print("3. Quick scan (basic detection only)")
    print("4. Deep scan (with connection analysis)")
    print("5. Custom scan")
    print("6. Back to main menu")
    
    scan_config = {
        'specific_repos': None,
        'detectors': config.get('detectors').copy(),
        'analyzers': config.get('analyzers').copy(),
        'scanning': config.get('scanning').copy()
    }
    
    choice = input("\nSelect scan type (1-6): ")
    
    if choice == "2":
        # Allow user to select specific repositories
        try:
            print("\nFetching repositories...")
            group = gitlab_client.groups.get(group_id)
            projects = group.projects.list(all=True, include_subgroups=True)
            
            repo_list = [f"{p.name} ({p.path_with_namespace})" for p in projects]
            repo_ids = [p.id for p in projects]
            
            selected_indices = select_multiple_items(repo_list, "Select repositories to scan")
            if selected_indices:
                scan_config['specific_repos'] = [repo_ids[i] for i in selected_indices]
            else:
                print("No repositories selected.")
                return "6", {}  # Back to main menu
                
        except Exception as e:
            print_error(f"Error fetching repositories: {str(e)}")
            return "6", {}  # Back to main menu
    
    elif choice == "3":
        # Quick scan - disable connection analysis
        scan_config['analyzers'] = {
            'connections': False,
            'dependencies': False,
            'documentation': True
        }
    
    elif choice == "4":
        # Deep scan - enable all analyzers
        scan_config['analyzers'] = {
            'connections': True,
            'dependencies': True,
            'documentation': True
        }
        # Increase timeouts for deep scan
        scan_config['scanning']['timeout_seconds'] = 60
    
    elif choice == "5":
        # Custom scan
        scan_config = configure_custom_scan(config)
    
    elif choice == "6":
        # Back to main menu
        return "6", {}
    
    return choice, scan_config


def handle_configuration_menu(config: Config) -> None:
    """
    Handle the configuration menu.
    
    Args:
        config: Current configuration
    """
    while True:
        clear_screen()
        print_section_header("Configure Analysis Options")
        print("1. Technology detection settings")
        print("2. Connection analysis settings")
        print("3. Documentation extraction settings")
        print("4. Performance settings")
        print("5. Output/reporting settings")
        print("6. Save/load configuration profiles")
        print("7. Back to main menu")
        
        choice = input("\nSelect configuration area (1-7): ")
        
        if choice == "1":
            # Technology detection settings
            config.set('detectors', configure_tech_detection(config))
        
        elif choice == "2":
            # Connection analysis settings
            config.set('analyzers', configure_connection_analysis(config))
        
        elif choice == "3":
            # Documentation extraction settings
            config.set('analyzers', 'documentation', configure_documentation_settings(config))
        
        elif choice == "4":
            # Performance settings
            config.set('scanning', configure_performance_settings(config))
        
        elif choice == "5":
            # Output/reporting settings
            config.set('reporting', configure_reporting_settings(config))
        
        elif choice == "6":
            # Save/load configuration
            handle_config_profiles(config)
        
        elif choice == "7":
            # Back to main menu
            break
        
        else:
            print_error("Invalid option selected. Please try again.")
            time.sleep(1)


def configure_tech_detection(config: Config) -> Dict[str, Any]:
    """
    Configure technology detection settings.
    
    Args:
        config: Current configuration
        
    Returns:
        Updated detector configuration
    """
    clear_screen()
    print_section_header("Technology Detection Settings")
    
    # Get current settings
    detectors_config = config.get('detectors', default={}).copy()
    
    # Technologies to detect
    print("\nSelect technologies to detect:")
    techs = [
        ("Frontend frameworks", detectors_config.get('frontend', True)),
        ("Backend technologies", detectors_config.get('backend', True)),
        ("Database systems", detectors_config.get('database', True)),
        ("Infrastructure code", detectors_config.get('infrastructure', True)),
        ("CI/CD configurations", detectors_config.get('cicd', True)),
        ("Custom patterns", bool(detectors_config.get('custom_patterns', [])))
    ]
    
    updated_techs = toggle_multiple_options(techs)
    
    # Update config
    detectors_config['frontend'] = dict(updated_techs).get("Frontend frameworks", True)
    detectors_config['backend'] = dict(updated_techs).get("Backend technologies", True)
    detectors_config['database'] = dict(updated_techs).get("Database systems", True)
    detectors_config['infrastructure'] = dict(updated_techs).get("Infrastructure code", True)
    detectors_config['cicd'] = dict(updated_techs).get("CI/CD configurations", True)
    
    # If custom patterns selected
    if dict(updated_techs).get("Custom patterns", False):
        # Keep existing patterns or create empty list
        if 'custom_patterns' not in detectors_config or not detectors_config['custom_patterns']:
            detectors_config['custom_patterns'] = []
            
        # Allow user to configure custom patterns
        print("\nConfigure custom detection patterns:")
        patterns = configure_custom_patterns(detectors_config.get('custom_patterns', []))
        detectors_config['custom_patterns'] = patterns
    else:
        # Clear custom patterns if option is disabled
        detectors_config['custom_patterns'] = []
    
    print_success("Technology detection settings updated!")
    time.sleep(1)
    
    return detectors_config


def configure_connection_analysis(config: Config) -> Dict[str, Any]:
    """
    Configure connection analysis settings.
    
    Args:
        config: Current configuration
        
    Returns:
        Updated analyzer configuration
    """
    clear_screen()
    print_section_header("Connection Analysis Settings")
    
    # Get current settings
    analyzers_config = config.get('analyzers', default={}).copy()
    
    # Analysis options
    print("\nSelect analysis options:")
    options = [
        ("API connections", analyzers_config.get('connections', True)),
        ("Service dependencies", analyzers_config.get('dependencies', True)),
        ("Documentation extraction", analyzers_config.get('documentation', True))
    ]
    
    updated_options = toggle_multiple_options(options)
    
    # Update config
    analyzers_config['connections'] = dict(updated_options).get("API connections", True)
    analyzers_config['dependencies'] = dict(updated_options).get("Service dependencies", True)
    analyzers_config['documentation'] = dict(updated_options).get("Documentation extraction", True)
    
    print_success("Connection analysis settings updated!")
    time.sleep(1)
    
    return analyzers_config


def configure_documentation_settings(config: Config) -> bool:
    """
    Configure documentation extraction settings.
    
    Args:
        config: Current configuration
        
    Returns:
        Updated documentation setting
    """
    clear_screen()
    print_section_header("Documentation Extraction Settings")
    
    # Get current setting
    current_setting = config.get('analyzers', 'documentation', True)
    
    # Simple toggle for now
    print(f"\nDocumentation extraction is currently: {'ENABLED' if current_setting else 'DISABLED'}")
    choice = input("\nToggle documentation extraction? (y/n): ")
    
    if choice.lower() == 'y':
        updated_setting = not current_setting
        print_success(f"Documentation extraction {'enabled' if updated_setting else 'disabled'}!")
        time.sleep(1)
        return updated_setting
    
    return current_setting


def configure_performance_settings(config: Config) -> Dict[str, Any]:
    """
    Configure performance settings.
    
    Args:
        config: Current configuration
        
    Returns:
        Updated scanning configuration
    """
    clear_screen()
    print_section_header("Performance Settings")
    
    # Get current settings
    scanning_config = config.get('scanning', default={}).copy()
    
    # Configure concurrent scans
    current_concurrency = scanning_config.get('concurrent_scans', 5)
    print(f"\nConcurrent repository scans: {current_concurrency}")
    new_concurrency = input(f"Enter new value (1-20) [{current_concurrency}]: ").strip()
    if new_concurrency and new_concurrency.isdigit():
        scanning_config['concurrent_scans'] = max(1, min(20, int(new_concurrency)))
    
    # Configure timeout
    current_timeout = scanning_config.get('timeout_seconds', 30)
    print(f"\nScan timeout per repository (seconds): {current_timeout}")
    new_timeout = input(f"Enter new value (10-300) [{current_timeout}]: ").strip()
    if new_timeout and new_timeout.isdigit():
        scanning_config['timeout_seconds'] = max(10, min(300, int(new_timeout)))
    
    # Configure file extensions
    current_extensions = scanning_config.get('file_extensions', [
        '.py', '.js', '.java', '.go', '.rb', '.php', '.ts', '.jsx', '.tsx',
        '.yml', '.yaml', '.json', '.tf', '.md', '.html', '.css', '.scss'
    ])
    print(f"\nCurrent file extensions for scanning: {', '.join(current_extensions)}")
    new_extensions = input("Enter extensions to add (comma-separated, e.g., .rs,.kt): ").strip()
    if new_extensions:
        extensions_to_add = [ext.strip() for ext in new_extensions.split(',')]
        scanning_config['file_extensions'] = list(set(current_extensions + extensions_to_add))
    
    print_success("Performance settings updated!")
    time.sleep(1)
    
    return scanning_config


def configure_reporting_settings(config: Config) -> Dict[str, Any]:
    """
    Configure reporting settings.
    
    Args:
        config: Current configuration
        
    Returns:
        Updated reporting configuration
    """
    clear_screen()
    print_section_header("Output/Reporting Settings")
    
    # Get current settings
    reporting_config = config.get('reporting', default={}).copy()
    
    # Configure format
    print("\nSelect output format:")
    formats = [
        ("1", "JSON (detailed)"),
        ("2", "JSON (compact)"),
        ("3", "YAML"),
        ("4", "HTML Report"),
        ("5", "Markdown")
    ]
    
    current_format = reporting_config.get('format', 'json')
    print(f"Current format: {current_format}")
    
    for key, value in formats:
        print(f"{key}. {value}")
    
    choice = input("\nSelect format (1-5): ").strip()
    
    format_mapping = {
        "1": "json",
        "2": "json-compact",
        "3": "yaml",
        "4": "html",
        "5": "markdown"
    }
    
    if choice in format_mapping:
        reporting_config['format'] = format_mapping[choice]
    
    # Configure verbosity
    print("\nSelect verbosity level:")
    verbosity_levels = [
        ("1", "Minimal (summary only)"),
        ("2", "Normal (summary + key findings)"),
        ("3", "Detailed (all information)"),
        ("4", "Debug (includes internal data)")
    ]
    
    current_verbosity = reporting_config.get('verbosity', 'normal')
    print(f"Current verbosity: {current_verbosity}")
    
    for key, value in verbosity_levels:
        print(f"{key}. {value}")
    
    choice = input("\nSelect verbosity level (1-4): ").strip()
    
    verbosity_mapping = {
        "1": "minimal",
        "2": "normal",
        "3": "detailed",
        "4": "debug"
    }
    
    if choice in verbosity_mapping:
        reporting_config['verbosity'] = verbosity_mapping[choice]
    
    print_success("Reporting settings updated!")
    time.sleep(1)
    
    return reporting_config


def handle_config_profiles(config: Config) -> None:
    """
    Handle saving and loading configuration profiles.
    
    Args:
        config: Current configuration
    """
    clear_screen()
    print_section_header("Configuration Profiles")
    print("1. Save current configuration")
    print("2. Load configuration")
    print("3. Reset to defaults")
    print("4. Back to configuration menu")
    
    choice = input("\nSelect option (1-4): ")
    
    if choice == "1":
        # Save configuration
        file_name = input("\nEnter file name [config.json]: ").strip()
        if not file_name:
            file_name = "config.json"
            
        if not file_name.endswith('.json'):
            file_name += '.json'
            
        config.save_config(file_name)
        input("\nPress Enter to continue...")
    
    elif choice == "2":
        # Load configuration
        file_name = input("\nEnter file name to load: ").strip()
        
        if not file_name:
            print_error("No file specified.")
        elif not os.path.exists(file_name):
            print_error(f"File {file_name} not found.")
        else:
            config.load_config(file_name)
            print_success(f"Configuration loaded from {file_name}")
            
        input("\nPress Enter to continue...")
    
    elif choice == "3":
        # Reset to defaults
        confirm = input("\nReset all settings to defaults? (y/n): ")
        
        if confirm.lower() == 'y':
            new_config = Config()
            config.config = new_config.config
            print_success("Configuration reset to defaults.")
            
        input("\nPress Enter to continue...")


def configure_custom_scan(config: Config) -> Dict[str, Any]:
    """
    Configure a custom scan with user-defined options.
    
    Args:
        config: Current configuration
        
    Returns:
        Custom scan configuration
    """
    clear_screen()
    print_section_header("Custom Scan Configuration")
    
    # Start with current config
    scan_config = {
        'specific_repos': None,
        'detectors': config.get('detectors').copy(),
        'analyzers': config.get('analyzers').copy(),
        'scanning': config.get('scanning').copy()
    }
    
    # Configure detection modules
    print("\nSelect detection modules:")
    detection_options = [
        ("Frontend frameworks", scan_config['detectors'].get('frontend', True)),
        ("Backend technologies", scan_config['detectors'].get('backend', True)),
        ("Database systems", scan_config['detectors'].get('database', True)),
        ("Infrastructure code", scan_config['detectors'].get('infrastructure', True)),
        ("CI/CD configurations", scan_config['detectors'].get('cicd', True))
    ]
    
    updated_detection = toggle_multiple_options(detection_options)
    
    # Update detection settings
    scan_config['detectors']['frontend'] = dict(updated_detection).get("Frontend frameworks", True)
    scan_config['detectors']['backend'] = dict(updated_detection).get("Backend technologies", True)
    scan_config['detectors']['database'] = dict(updated_detection).get("Database systems", True)
    scan_config['detectors']['infrastructure'] = dict(updated_detection).get("Infrastructure code", True)
    scan_config['detectors']['cicd'] = dict(updated_detection).get("CI/CD configurations", True)
    
    # Configure analysis modules
    print("\nSelect analysis modules:")
    analysis_options = [
        ("API connections", scan_config['analyzers'].get('connections', True)),
        ("Service dependencies", scan_config['analyzers'].get('dependencies', True)),
        ("Documentation extraction", scan_config['analyzers'].get('documentation', True))
    ]
    
    updated_analysis = toggle_multiple_options(analysis_options)
    
    # Update analysis settings
    scan_config['analyzers']['connections'] = dict(updated_analysis).get("API connections", True)
    scan_config['analyzers']['dependencies'] = dict(updated_analysis).get("Service dependencies", True)
    scan_config['analyzers']['documentation'] = dict(updated_analysis).get("Documentation extraction", True)
    
    # Configure performance settings
    print("\nConfigure scan performance:")
    
    # Concurrent scans
    current_concurrency = scan_config['scanning'].get('concurrent_scans', 5)
    new_concurrency = input(f"Concurrent repository scans (1-20) [{current_concurrency}]: ").strip()
    if new_concurrency and new_concurrency.isdigit():
        scan_config['scanning']['concurrent_scans'] = max(1, min(20, int(new_concurrency)))
    
    # Timeout
    current_timeout = scan_config['scanning'].get('timeout_seconds', 30)
    new_timeout = input(f"Scan timeout per repository in seconds (10-300) [{current_timeout}]: ").strip()
    if new_timeout and new_timeout.isdigit():
        scan_config['scanning']['timeout_seconds'] = max(10, min(300, int(new_timeout)))
    
    print_success("Custom scan configured!")
    time.sleep(1)
    
    return scan_config


def display_results_menu(config: Config) -> None:
    """
    Display the results viewing menu.
    
    Args:
        config: Current configuration
    """
    clear_screen()
    print_section_header("View Previous Results")
    
    # Look for result files
    result_files = [f for f in os.listdir('.') if f.endswith(('.json', '.yaml', '.html', '.md')) 
                   and 'report' in f.lower()]
    
    if not result_files:
        print("No previous result files found.")
        return
    
    print("Select a result file to view:")
    for i, file in enumerate(result_files, 1):
        print(f"{i}. {file}")
    
    choice = input("\nSelect file number or press Enter to return: ")
    
    if not choice:
        return
        
    try:
        file_idx = int(choice) - 1
        if 0 <= file_idx < len(result_files):
            file_path = result_files[file_idx]
            
            # Determine how to display the file
            if file_path.endswith('.json'):
                # Load and display JSON summary
                try:
                    import json
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                    clear_screen()
                    print_section_header(f"Results from {file_path}")
                    
                    if 'summary' in data:
                        print(f"\nRepositories analyzed: {len(data.get('repositories', []))}")
                        print(f"Technologies detected: {len(data.get('technologies', {}))}")
                        
                        # Display top technologies
                        if 'top_technologies' in data['summary']:
                            print("\nTop technologies detected:")
                            for tech, count in data['summary']['top_technologies'].items():
                                print(f"- {tech}: {count} repositories")
                    else:
                        print(json.dumps(data, indent=2))
                        
                except Exception as e:
                    print_error(f"Error displaying results: {str(e)}")
            
            else:
                # For other file types, just mention they should be opened externally
                print(f"\nFile {file_path} should be opened in an appropriate viewer.")
    
    except (ValueError, IndexError):
        print_error("Invalid selection.")


def display_export_menu() -> Optional[str]:
    """
    Display the export menu.
    
    Returns:
        Selected export format or None if cancelled
    """
    clear_screen()
    print_section_header("Export/Generate Reports")
    
    print("Select export format:")
    print("1. JSON (detailed)")
    print("2. JSON (compact)")
    print("3. YAML")
    print("4. HTML Report")
    print("5. Markdown")
    print("6. Cancel")
    
    choice = input("\nSelect format (1-6): ")
    
    format_mapping = {
        "1": "json",
        "2": "json-compact",
        "3": "yaml",
        "4": "html",
        "5": "markdown"
    }
    
    if choice in format_mapping:
        return format_mapping[choice]
    
    return None


def perform_scan(gitlab_client: gitlab.Gitlab, group_id: str, config: Config, 
                scan_type: str, scan_config: Dict[str, Any]) -> None:
    """
    Execute the repository scan.
    
    Args:
        gitlab_client: GitLab API client
        group_id: GitLab group ID
        config: Current configuration
        scan_type: Type of scan to perform
        scan_config: Scan configuration
    """
    # Create temporary config with scan-specific settings
    temp_config = Config()
    
    # Apply scan configuration
    if 'detectors' in scan_config:
        temp_config.set('detectors', scan_config['detectors'])
        
    if 'analyzers' in scan_config:
        temp_config.set('analyzers', scan_config['analyzers'])
        
    if 'scanning' in scan_config:
        temp_config.set('scanning', scan_config['scanning'])
    
    # Create scanner
    scanner = GitLabScanner(
        gitlab_instance=gitlab_client,
        group_id=group_id,
        config=temp_config
    )
    
    # Run scan
    try:
        specific_repos = scan_config.get('specific_repos')
        
        clear_screen()
        print_section_header("Scanning Repositories")
        
        if specific_repos:
            print(f"Scanning {len(specific_repos)} specific repositories...")
        else:
            print("Scanning all repositories in group...")
            
        # Execute scan
        scanner.scan(specific_repos)
        
        # Generate report
        print("\nGenerating report...")
        scanner.generate_report("gitlab_analysis_report.json")
        
        print_success("\nScan completed successfully!")
        print(f"Found {len(scanner.repositories)} repositories")
        
        # Show brief summary
        technologies = {}
        for repo in scanner.repositories:
            for category, techs in repo.technologies.items():
                for tech in techs:
                    name = tech['name']
                    if name in technologies:
                        technologies[name] += 1
                    else:
                        technologies[name] = 1
        
        if technologies:
            print("\nTop technologies detected:")
            sorted_techs = sorted(technologies.items(), key=lambda x: x[1], reverse=True)
            for tech, count in sorted_techs[:10]:  # Show top 10
                print(f"- {tech}: {count} repositories")
                
    except Exception as e:
        print_error(f"Error during scan: {str(e)}")


def display_help() -> None:
    """Display help information."""
    clear_screen()
    print_section_header("GitLab Repository Analyzer Help")
    
    print("""
The GitLab Repository Analyzer is a tool for analyzing repositories in a GitLab group
to discover technologies, detect connections between services, and extract documentation.

Main Features:
--------------
1. Technology Detection
   - Identify frontend frameworks (React, Vue, Angular, etc.)
   - Detect backend technologies (Node.js, Python, Java, etc.)
   - Find database technologies and connections
   - Recognize infrastructure code (Terraform, Docker, etc.)
   - Analyze CI/CD configurations

2. Connection Analysis
   - Discover API endpoints and clients
   - Find service dependencies
   - Map relationships between microservices

3. Documentation Extraction
   - Parse README files for setup instructions
   - Extract API documentation
   - Find architecture information
   - Identify diagrams and visual documentation

Getting Started:
---------------
1. Ensure your GitLab token is set via GITLAB_TOKEN environment variable or config
2. Set your GitLab group ID via GITLAB_GROUP_ID environment variable or config
3. Run a scan from the main menu to analyze your repositories
4. View the results or export to various formats

For issues or feature requests, please open an issue on the project's repository.
""")


if __name__ == "__main__":
    # This allows running the menu system directly for testing
    from ..config import Config
    config = Config()
    
    # Mock GitLab client
    class MockGitLab:
        def __init__(self):
            pass
    
    handle_main_menu(MockGitLab(), "123", config)
