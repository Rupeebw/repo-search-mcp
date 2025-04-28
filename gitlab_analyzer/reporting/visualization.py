"""
Visualization module for GitLab Repository Analyzer.
Provides data structures and functions for visualizing analysis results.
"""

from typing import Dict, List, Any, Optional
import json


def prepare_technology_chart_data(repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Prepare data for technology distribution charts.
    
    Args:
        repositories: List of repository data dictionaries
        
    Returns:
        Dictionary with chart data for different technology categories
    """
    # Initialize counters for each technology category
    tech_counts = {
        'frontend': {},
        'backend': {},
        'database': {},
        'infrastructure': {},
        'cicd': {}
    }
    
    # Count occurrences of each technology
    for repo in repositories:
        for category in tech_counts.keys():
            for tech in repo.get('technologies', {}).get(category, []):
                tech_name = tech.get('name', 'Unknown')
                if tech_name in tech_counts[category]:
                    tech_counts[category][tech_name] += 1
                else:
                    tech_counts[category][tech_name] = 1
    
    # Convert to chart-friendly format
    chart_data = {}
    for category, counts in tech_counts.items():
        chart_data[category] = {
            'labels': list(counts.keys()),
            'values': list(counts.values())
        }
    
    return chart_data


def prepare_dependency_graph_data(repositories: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Prepare data for repository dependency graph visualization.
    
    Args:
        repositories: List of repository data dictionaries
        
    Returns:
        Dictionary with nodes and edges for dependency graph
    """
    nodes = []
    edges = []
    repo_id_map = {}
    
    # Create nodes for each repository
    for i, repo in enumerate(repositories):
        repo_id = repo.get('id')
        repo_name = repo.get('name')
        repo_id_map[repo_name] = i
        
        nodes.append({
            'id': i,
            'label': repo_name,
            'size': 10 + len(repo.get('technologies', {}).get('backend', [])) * 2,
            'url': repo.get('web_url', '')
        })
    
    # Create edges for dependencies
    for i, repo in enumerate(repositories):
        repo_deps = repo.get('dependencies', {}).get('repositories', [])
        for dep in repo_deps:
            if dep in repo_id_map:
                edges.append({
                    'source': i,
                    'target': repo_id_map[dep],
                    'value': 1
                })
    
    return {
        'nodes': nodes,
        'edges': edges
    }


def prepare_language_distribution_data(repositories: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Prepare data for language distribution visualization.
    
    Args:
        repositories: List of repository data dictionaries
        
    Returns:
        Dictionary mapping language names to total line counts
    """
    languages = {}
    
    for repo in repositories:
        for lang, lines in repo.get('stats', {}).get('languages', {}).items():
            if lang in languages:
                languages[lang] += lines
            else:
                languages[lang] = lines
    
    # Sort by line count
    return dict(sorted(languages.items(), key=lambda x: x[1], reverse=True))


def generate_html_visualization(data: Dict[str, Any], output_file: str) -> None:
    """
    Generate an HTML file with visualizations of the analysis results.
    
    Args:
        data: Visualization data
        output_file: Path to save the HTML file
    """
    # Basic HTML template with Chart.js
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>GitLab Repository Analysis</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .chart-container { width: 80%; margin: 20px auto; }
            h1, h2 { color: #333; }
        </style>
    </head>
    <body>
        <h1>GitLab Repository Analysis</h1>
        
        <div class="chart-container">
            <h2>Frontend Technologies</h2>
            <canvas id="frontendChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>Backend Technologies</h2>
            <canvas id="backendChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>Database Technologies</h2>
            <canvas id="databaseChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>Infrastructure Technologies</h2>
            <canvas id="infrastructureChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>CI/CD Technologies</h2>
            <canvas id="cicdChart"></canvas>
        </div>
        
        <div class="chart-container">
            <h2>Language Distribution</h2>
            <canvas id="languageChart"></canvas>
        </div>
        
        <script>
            // Chart data
            const chartData = {JSON_DATA};
            
            // Create charts
            function createChart(id, labels, values, title, type = 'bar') {
                const ctx = document.getElementById(id).getContext('2d');
                return new Chart(ctx, {
                    type: type,
                    data: {
                        labels: labels,
                        datasets: [{
                            label: title,
                            data: values,
                            backgroundColor: [
                                'rgba(255, 99, 132, 0.6)',
                                'rgba(54, 162, 235, 0.6)',
                                'rgba(255, 206, 86, 0.6)',
                                'rgba(75, 192, 192, 0.6)',
                                'rgba(153, 102, 255, 0.6)',
                                'rgba(255, 159, 64, 0.6)',
                                'rgba(199, 199, 199, 0.6)'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'top',
                            },
                            title: {
                                display: true,
                                text: title
                            }
                        }
                    }
                });
            }
            
            // Initialize charts
            document.addEventListener('DOMContentLoaded', function() {
                if (chartData.frontend) {
                    createChart('frontendChart', 
                                chartData.frontend.labels, 
                                chartData.frontend.values, 
                                'Frontend Technologies');
                }
                
                if (chartData.backend) {
                    createChart('backendChart', 
                                chartData.backend.labels, 
                                chartData.backend.values, 
                                'Backend Technologies');
                }
                
                if (chartData.database) {
                    createChart('databaseChart', 
                                chartData.database.labels, 
                                chartData.database.values, 
                                'Database Technologies');
                }
                
                if (chartData.infrastructure) {
                    createChart('infrastructureChart', 
                                chartData.infrastructure.labels, 
                                chartData.infrastructure.values, 
                                'Infrastructure Technologies');
                }
                
                if (chartData.cicd) {
                    createChart('cicdChart', 
                                chartData.cicd.labels, 
                                chartData.cicd.values, 
                                'CI/CD Technologies');
                }
                
                if (chartData.languages) {
                    createChart('languageChart', 
                                Object.keys(chartData.languages), 
                                Object.values(chartData.languages), 
                                'Language Distribution', 
                                'pie');
                }
            });
        </script>
    </body>
    </html>
    """
    
    # Insert JSON data into template
    html_content = html_template.replace('{JSON_DATA}', json.dumps(data))
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"Visualization saved to {output_file}")


def export_visualization_data(data: Dict[str, Any], output_file: str) -> None:
    """
    Export visualization data to a JSON file.
    
    Args:
        data: Visualization data
        output_file: Path to save the JSON file
    """
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Visualization data exported to {output_file}")
