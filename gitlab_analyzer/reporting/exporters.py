"""
Report exporters for GitLab Repository Analyzer.
Handles exporting analysis results in different formats.
"""

import os
import json
import yaml
import re
import time
from typing import Dict, Any, List, Optional


def export_report(report_data: Dict[str, Any], file_path: str, format_type: str = 'json') -> None:
    """
    Export analysis report in the specified format.
    
    Args:
        report_data: Report data to export
        file_path: Path to save the exported report
        format_type: Output format (json, json-compact, yaml, markdown, html)
    """
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(file_path) if os.path.dirname(file_path) else '.', exist_ok=True)
    
    if format_type == 'json':
        export_json(report_data, file_path, pretty=True)
    elif format_type == 'json-compact':
        export_json(report_data, file_path, pretty=False)
    elif format_type == 'yaml':
        export_yaml(report_data, file_path)
    elif format_type == 'markdown':
        export_markdown(report_data, file_path)
    elif format_type == 'html':
        export_html(report_data, file_path)
    else:
        # Default to JSON if format not recognized
        export_json(report_data, file_path)
        
    print(f"Report exported to {file_path}")


def export_json(report_data: Dict[str, Any], file_path: str, pretty: bool = True) -> None:
    """
    Export report as JSON.
    
    Args:
        report_data: Report data to export
        file_path: Path to save the exported report
        pretty: Whether to pretty-print the JSON
    """
    with open(file_path, 'w') as f:
        if pretty:
            json.dump(report_data, f, indent=2)
        else:
            json.dump(report_data, f)


def export_yaml(report_data: Dict[str, Any], file_path: str) -> None:
    """
    Export report as YAML.
    
    Args:
        report_data: Report data to export
        file_path: Path to save the exported report
    """
    with open(file_path, 'w') as f:
        yaml.dump(report_data, f, default_flow_style=False)


def export_markdown(report_data: Dict[str, Any], file_path: str) -> None:
    """
    Export report as Markdown.
    
    Args:
        report_data: Report data to export
        file_path: Path to save the exported report
    """
    with open(file_path, 'w') as f:
        # Title and generation timestamp
        f.write("# GitLab Repository Analysis Report\n\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary section
        f.write("## Summary\n\n")
        summary = report_data.get('summary', {})
        f.write(f"- Total repositories: {summary.get('total_repositories', 0)}\n")
        f.write(f"- Repositories analyzed: {summary.get('scanned_repositories', 0)}\n")
        f.write(f"- Unique technologies detected: {summary.get('total_technologies', 0)}\n\n")
        
        # Top technologies
        f.write("### Top Technologies\n\n")
        f.write("| Technology | Repository Count |\n")
        f.write("|------------|------------------|\n")
        
        top_techs = summary.get('top_technologies', {})
        for tech, count in top_techs.items():
            f.write(f"| {tech} | {count} |\n")
        f.write("\n")
        
        # Technologies by category
        f.write("## Technologies by Category\n\n")
        tech_categories = report_data.get('technologies', {})
        
        for category, technologies in tech_categories.items():
            # Capitalize category name
            category_display = category.capitalize()
            f.write(f"### {category_display}\n\n")
            
            if technologies:
                f.write("| Technology | Repository Count |\n")
                f.write("|------------|------------------|\n")
                
                for tech in technologies:
                    tech_name = tech.get('name', '')
                    tech_count = tech.get('count', 0)
                    f.write(f"| {tech_name} | {tech_count} |\n")
            else:
                f.write("No technologies detected for this category.\n")
            
            f.write("\n")
        
        # Repository details
        f.write("## Repository Details\n\n")
        repositories = report_data.get('repositories', [])
        
        for repo in repositories:
            repo_name = repo.get('name', '')
            repo_path = repo.get('path', '')
            repo_url = repo.get('web_url', '')
            
            f.write(f"### {repo_name}\n\n")
            f.write(f"- Path: `{repo_path}`\n")
            f.write(f"- URL: [{repo_url}]({repo_url})\n")
            
            # Technologies used
            techs = repo.get('technologies', [])
            if techs:
                f.write("- **Technologies:**\n")
                for tech in techs:
                    f.write(f"  - {tech}\n")
            
            # APIs
            api_count = repo.get('apis', 0)
            f.write(f"- **API Endpoints:** {api_count}\n")
            
            # Documentation
            docs = repo.get('documentation', {})
            f.write("- **Documentation:**\n")
            f.write(f"  - README: {'Yes' if docs.get('has_readme', False) else 'No'}\n")
            f.write(f"  - API Docs: {'Yes' if docs.get('has_api_docs', False) else 'No'}\n")
            f.write(f"  - Setup Instructions: {'Yes' if docs.get('has_setup_instructions', False) else 'No'}\n")
            f.write(f"  - Architecture: {'Yes' if docs.get('has_architecture_info', False) else 'No'}\n")
            
            # Dependencies
            connections = repo.get('connections', {})
            repo_deps = connections.get('dependencies', [])
            service_deps = connections.get('services', [])
            
            if repo_deps or service_deps:
                f.write("- **Dependencies:**\n")
                
                if repo_deps:
                    f.write("  - Repository dependencies:\n")
                    for dep in repo_deps:
                        f.write(f"    - {dep}\n")
                
                if service_deps:
                    f.write("  - Service dependencies:\n")
                    for dep in service_deps:
                        f.write(f"    - {dep}\n")
            
            f.write("\n")
        
        # Connections section
        f.write("## Service Connections\n\n")
        connections = report_data.get('connections', {})
        
        # API connections
        api_connections = connections.get('api_connections', [])
        if api_connections:
            f.write("### API Connections\n\n")
            f.write("| Source | Target |\n")
            f.write("|--------|--------|\n")
            
            for conn in api_connections:
                source = conn.get('source', '')
                target = conn.get('target', '')
                f.write(f"| {source} | {target} |\n")
            
            f.write("\n")
        
        # Service dependencies
        service_deps = connections.get('service_dependencies', [])
        if service_deps:
            f.write("### Service Dependencies\n\n")
            f.write("| Source | Target |\n")
            f.write("|--------|--------|\n")
            
            for dep in service_deps:
                source = dep.get('source', '')
                target = dep.get('target', '')
                f.write(f"| {source} | {target} |\n")
            
            f.write("\n")
        
        # Documentation summary
        f.write("## Documentation Summary\n\n")
        docs_summary = report_data.get('documentation', {})
        
        f.write(f"- Repositories with README: {docs_summary.get('repos_with_readme', 0)} / {docs_summary.get('total_repositories', 0)}\n")
        f.write(f"- Repositories with API docs: {docs_summary.get('repos_with_api_docs', 0)} / {docs_summary.get('total_repositories', 0)}\n")
        f.write(f"- Repositories with setup instructions: {docs_summary.get('repos_with_setup', 0)} / {docs_summary.get('total_repositories', 0)}\n")
        f.write(f"- Repositories with architecture documentation: {docs_summary.get('repos_with_architecture', 0)} / {docs_summary.get('total_repositories', 0)}\n\n")


def export_html(report_data: Dict[str, Any], file_path: str) -> None:
    """
    Export report as HTML.
    
    Args:
        report_data: Report data to export
        file_path: Path to save the exported report
    """
    with open(file_path, 'w') as f:
        # HTML header
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitLab Repository Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            border-bottom: 1px solid #ddd;
            padding-bottom: 5px;
            margin-top: 30px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }
        th, td {
            text-align: left;
            padding: 8px;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .summary-card {
            background: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .tech-pill {
            display: inline-block;
            background: #e0f7fa;
            border-radius: 15px;
            padding: 3px 10px;
            margin: 2px;
            font-size: 0.9em;
        }
        .connection-diagram {
            padding: 20px;
            background: #fafafa;
            border-radius: 5px;
            margin: 20px 0;
        }
        .doc-status {
            display: inline-block;
            padding: 3px 6px;
            border-radius: 3px;
            font-size: 0.8em;
        }
        .doc-yes {
            background: #c8e6c9;
            color: #2e7d32;
        }
        .doc-no {
            background: #ffcdd2;
            color: #c62828;
        }
        .repo-card {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
        }
        .repo-header {
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 10px;
        }
        .footer {
            margin-top: 50px;
            border-top: 1px solid #ddd;
            padding-top: 20px;
            text-align: center;
            font-size: 0.9em;
            color: #777;
        }
    </style>
</head>
<body>
    <h1>GitLab Repository Analysis Report</h1>
    <p>Generated: """)
        
        # Add timestamp
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}</p>\n")
        
        # Summary section
        f.write("    <h2>Summary</h2>\n")
        f.write("    <div class=\"summary-card\">\n")
        summary = report_data.get('summary', {})
        f.write(f"        <p><strong>Total repositories:</strong> {summary.get('total_repositories', 0)}</p>\n")
        f.write(f"        <p><strong>Repositories analyzed:</strong> {summary.get('scanned_repositories', 0)}</p>\n")
        f.write(f"        <p><strong>Unique technologies detected:</strong> {summary.get('total_technologies', 0)}</p>\n")
        f.write("    </div>\n")
        
        # Top technologies
        f.write("    <h3>Top Technologies</h3>\n")
        f.write("    <table>\n")
        f.write("        <tr>\n")
        f.write("            <th>Technology</th>\n")
        f.write("            <th>Repository Count</th>\n")
        f.write("        </tr>\n")
        
        top_techs = summary.get('top_technologies', {})
        for tech, count in top_techs.items():
            f.write("        <tr>\n")
            f.write(f"            <td>{tech}</td>\n")
            f.write(f"            <td>{count}</td>\n")
            f.write("        </tr>\n")
        
        f.write("    </table>\n")
        
        # Technologies by category
        f.write("    <h2>Technologies by Category</h2>\n")
        tech_categories = report_data.get('technologies', {})
        
        for category, technologies in tech_categories.items():
            # Capitalize category name
            category_display = category.capitalize()
            f.write(f"    <h3>{category_display}</h3>\n")
            
            if technologies:
                f.write("    <table>\n")
                f.write("        <tr>\n")
                f.write("            <th>Technology</th>\n")
                f.write("            <th>Repository Count</th>\n")
                f.write("        </tr>\n")
                
                for tech in technologies:
                    tech_name = tech.get('name', '')
                    tech_count = tech.get('count', 0)
                    f.write("        <tr>\n")
                    f.write(f"            <td>{tech_name}</td>\n")
                    f.write(f"            <td>{tech_count}</td>\n")
                    f.write("        </tr>\n")
                
                f.write("    </table>\n")
            else:
                f.write("    <p>No technologies detected for this category.</p>\n")
        
        # Repository details
        f.write("    <h2>Repository Details</h2>\n")
        repositories = report_data.get('repositories', [])
        
        for repo in repositories:
            repo_name = repo.get('name', '')
            repo_path = repo.get('path', '')
            repo_url = repo.get('web_url', '')
            
            f.write("    <div class=\"repo-card\">\n")
            f.write("        <div class=\"repo-header\">\n")
            f.write(f"            <h3>{repo_name}</h3>\n")
            f.write(f"            <a href=\"{repo_url}\" target=\"_blank\">View on GitLab</a>\n")
            f.write("        </div>\n")
            
            f.write(f"        <p><strong>Path:</strong> {repo_path}</p>\n")
            
            # Technologies used
            techs = repo.get('technologies', [])
            if techs:
                f.write("        <p><strong>Technologies:</strong></p>\n")
                f.write("        <div>\n")
                for tech in techs:
                    f.write(f"            <span class=\"tech-pill\">{tech}</span>\n")
                f.write("        </div>\n")
            
            # APIs
            api_count = repo.get('apis', 0)
            f.write(f"        <p><strong>API Endpoints:</strong> {api_count}</p>\n")
            
            # Documentation
            docs = repo.get('documentation', {})
            f.write("        <p><strong>Documentation:</strong></p>\n")
            f.write("        <ul>\n")
            f.write(f"            <li>README: <span class=\"doc-status {'doc-yes' if docs.get('has_readme', False) else 'doc-no'}\">{('Yes' if docs.get('has_readme', False) else 'No')}</span></li>\n")
            f.write(f"            <li>API Docs: <span class=\"doc-status {'doc-yes' if docs.get('has_api_docs', False) else 'doc-no'}\">{('Yes' if docs.get('has_api_docs', False) else 'No')}</span></li>\n")
            f.write(f"            <li>Setup Instructions: <span class=\"doc-status {'doc-yes' if docs.get('has_setup_instructions', False) else 'doc-no'}\">{('Yes' if docs.get('has_setup_instructions', False) else 'No')}</span></li>\n")
            f.write(f"            <li>Architecture: <span class=\"doc-status {'doc-yes' if docs.get('has_architecture_info', False) else 'doc-no'}\">{('Yes' if docs.get('has_architecture_info', False) else 'No')}</span></li>\n")
            f.write("        </ul>\n")
            
            # Dependencies
            connections = repo.get('connections', {})
            repo_deps = connections.get('dependencies', [])
            service_deps = connections.get('services', [])
            
            if repo_deps or service_deps:
                f.write("        <p><strong>Dependencies:</strong></p>\n")
                f.write("        <ul>\n")
                
                if repo_deps:
                    f.write("            <li>Repository dependencies:</li>\n")
                    f.write("            <ul>\n")
                    for dep in repo_deps:
                        f.write(f"                <li>{dep}</li>\n")
                    f.write("            </ul>\n")
                
                if service_deps:
                    f.write("            <li>Service dependencies:</li>\n")
                    f.write("            <ul>\n")
                    for dep in service_deps:
                        f.write(f"                <li>{dep}</li>\n")
                    f.write("            </ul>\n")
                
                f.write("        </ul>\n")
            
            f.write("    </div>\n")
        
        # Connections section
        f.write("    <h2>Service Connections</h2>\n")
        connections = report_data.get('connections', {})
        
        # API connections
        api_connections = connections.get('api_connections', [])
        if api_connections:
            f.write("    <h3>API Connections</h3>\n")
            f.write("    <table>\n")
            f.write("        <tr>\n")
            f.write("            <th>Source</th>\n")
            f.write("            <th>Target</th>\n")
            f.write("        </tr>\n")
            
            for conn in api_connections:
                source = conn.get('source', '')
                target = conn.get('target', '')
                f.write("        <tr>\n")
                f.write(f"            <td>{source}</td>\n")
                f.write(f"            <td>{target}</td>\n")
                f.write("        </tr>\n")
            
            f.write("    </table>\n")
        
        # Service dependencies
        service_deps = connections.get('service_dependencies', [])
        if service_deps:
            f.write("    <h3>Service Dependencies</h3>\n")
            f.write("    <table>\n")
            f.write("        <tr>\n")
            f.write("            <th>Source</th>\n")
            f.write("            <th>Target</th>\n")
            f.write("        </tr>\n")
            
            for dep in service_deps:
                source = dep.get('source', '')
                target = dep.get('target', '')
                f.write("        <tr>\n")
                f.write(f"            <td>{source}</td>\n")
                f.write(f"            <td>{target}</td>\n")
                f.write("        </tr>\n")
            
            f.write("    </table>\n")
        
        # Documentation summary
        f.write("    <h2>Documentation Summary</h2>\n")
        f.write("    <div class=\"summary-card\">\n")
        docs_summary = report_data.get('documentation', {})
        
        f.write(f"        <p><strong>Repositories with README:</strong> {docs_summary.get('repos_with_readme', 0)} / {docs_summary.get('total_repositories', 0)}</p>\n")
        f.write(f"        <p><strong>Repositories with API docs:</strong> {docs_summary.get('repos_with_api_docs', 0)} / {docs_summary.get('total_repositories', 0)}</p>\n")
        f.write(f"        <p><strong>Repositories with setup instructions:</strong> {docs_summary.get('repos_with_setup', 0)} / {docs_summary.get('total_repositories', 0)}</p>\n")
        f.write(f"        <p><strong>Repositories with architecture documentation:</strong> {docs_summary.get('repos_with_architecture', 0)} / {docs_summary.get('total_repositories', 0)}</p>\n")
        f.write("    </div>\n")
        
        # Footer
        f.write("    <div class=\"footer\">\n")
        f.write("        <p>Generated by GitLab Repository Analyzer</p>\n")
        f.write("    </div>\n")
        
        # Close HTML
        f.write("</body>\n")
        f.write("</html>\n")
