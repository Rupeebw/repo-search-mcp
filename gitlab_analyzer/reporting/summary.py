"""
Summary report generator for GitLab Repository Analyzer.
Creates a comprehensive summary of repository analysis results.
"""

from typing import Dict, List, Any, Counter
from collections import defaultdict
from ..core.repository import Repository


def generate_summary(repositories: List[Repository]) -> Dict[str, Any]:
    """
    Generate a summary report from repository scan results.
    
    Args:
        repositories: List of analyzed repositories
        
    Returns:
        Dictionary containing summary information
    """
    if not repositories:
        return {
            'summary': {
                'total_repositories': 0,
                'scanned_repositories': 0,
                'total_technologies': 0,
                'top_technologies': {}
            },
            'repositories': [],
            'technologies': {},
            'connections': {
                'api_connections': [],
                'service_dependencies': []
            },
            'documentation': {}
        }
    
    # General statistics
    total_repos = len(repositories)
    scanned_repos = sum(1 for repo in repositories if repo.scanned)
    
    # Process technology categories
    all_technologies = defaultdict(list)
    technology_counts = Counter()
    
    # Connection tracking
    api_connections = []
    service_dependencies = []
    
    # Process each repository
    repos_summary = []
    
    for repo in repositories:
        if not repo.scanned:
            continue
            
        # Gather technologies for this repo
        repo_techs = []
        
        for category, techs in repo.technologies.items():
            for tech in techs:
                tech_name = tech['name']
                
                # Add to counts
                technology_counts[tech_name] += 1
                
                # Add to category list if not already present
                if tech_name not in all_technologies[category]:
                    all_technologies[category].append({
                        'name': tech_name,
                        'count': 1
                    })
                else:
                    # Increment count for this technology
                    for t in all_technologies[category]:
                        if t['name'] == tech_name:
                            t['count'] = t.get('count', 0) + 1
                            break
                
                # Add to repo tech list
                repo_techs.append(tech_name)
        
        # Process connections
        if repo.dependencies.get('repositories', []):
            for dep_repo in repo.dependencies['repositories']:
                api_connections.append({
                    'source': repo.name,
                    'target': dep_repo,
                    'type': 'api'
                })
                
        if repo.dependencies.get('services', []):
            for service in repo.dependencies['services']:
                service_dependencies.append({
                    'source': repo.name,
                    'target': service,
                    'type': 'service'
                })
        
        # Add to repo summary
        repos_summary.append({
            'id': repo.id,
            'name': repo.name,
            'path': repo.path,
            'web_url': repo.web_url,
            'technologies': repo_techs,
            'apis': len(repo.apis),
            'documentation': _summarize_repo_documentation(repo),
            'connections': {
                'dependencies': repo.dependencies.get('repositories', []),
                'services': repo.dependencies.get('services', [])
            }
        })
    
    # Create technology summary
    tech_summary = {}
    
    for category, techs in all_technologies.items():
        tech_summary[category] = sorted(techs, key=lambda x: x.get('count', 0), reverse=True)
    
    # Get top technologies overall
    top_techs = technology_counts.most_common(10)
    top_techs_dict = {name: count for name, count in top_techs}
    
    # Create final summary
    return {
        'summary': {
            'total_repositories': total_repos,
            'scanned_repositories': scanned_repos,
            'total_technologies': len(technology_counts),
            'top_technologies': top_techs_dict
        },
        'repositories': repos_summary,
        'technologies': tech_summary,
        'connections': {
            'api_connections': api_connections,
            'service_dependencies': service_dependencies
        },
        'documentation': _generate_documentation_summary(repositories)
    }


def _summarize_repo_documentation(repo: Repository) -> Dict[str, Any]:
    """
    Create a summary of a repository's documentation.
    
    Args:
        repo: Repository to summarize
        
    Returns:
        Dictionary with documentation summary
    """
    result = {
        'has_readme': repo.documentation['readme'] is not None,
        'has_api_docs': len(repo.documentation['api_docs']) > 0,
        'has_setup_instructions': len(repo.documentation['setup_instructions']) > 0,
        'has_architecture_info': len(repo.documentation['architecture']) > 0
    }
    
    return result


def _generate_documentation_summary(repositories: List[Repository]) -> Dict[str, Any]:
    """
    Generate a summary of documentation across repositories.
    
    Args:
        repositories: List of analyzed repositories
        
    Returns:
        Documentation summary dictionary
    """
    # Track documentation stats
    docs_summary = {
        'repos_with_readme': 0,
        'repos_with_api_docs': 0,
        'repos_with_setup': 0,
        'repos_with_architecture': 0,
        'total_repositories': len(repositories),
        'setup_instructions': [],
        'architecture_overview': []
    }
    
    # Process documentation from all repositories
    for repo in repositories:
        if not repo.scanned:
            continue
            
        # Count documentation types
        if repo.documentation['readme'] is not None:
            docs_summary['repos_with_readme'] += 1
            
        if repo.documentation['api_docs']:
            docs_summary['repos_with_api_docs'] += 1
            
        if repo.documentation['setup_instructions']:
            docs_summary['repos_with_setup'] += 1
            
            # Extract setup instructions for summary
            for setup in repo.documentation['setup_instructions']:
                docs_summary['setup_instructions'].append({
                    'repository': repo.name,
                    'path': setup.get('path', ''),
                    'type': setup.get('type', 'text')
                })
            
        if repo.documentation['architecture']:
            docs_summary['repos_with_architecture'] += 1
            
            # Extract architecture info for summary
            for arch in repo.documentation['architecture']:
                docs_summary['architecture_overview'].append({
                    'repository': repo.name,
                    'path': arch.get('path', ''),
                    'type': arch.get('type', 'text')
                })
    
    return docs_summary


def get_technology_relationships(repositories: List[Repository]) -> Dict[str, List[str]]:
    """
    Find technologies that tend to be used together.
    
    Args:
        repositories: List of analyzed repositories
        
    Returns:
        Dictionary of technology relationships
    """
    # Track which technologies appear together
    tech_relationships = defaultdict(set)
    tech_counts = Counter()
    
    # Process each repository
    for repo in repositories:
        if not repo.scanned:
            continue
            
        # Get all technologies used in this repo
        repo_techs = []
        for category, techs in repo.technologies.items():
            for tech in techs:
                tech_name = tech['name']
                repo_techs.append(tech_name)
                tech_counts[tech_name] += 1
        
        # Add relationships between all technologies in this repo
        for tech1 in repo_techs:
            for tech2 in repo_techs:
                if tech1 != tech2:
                    tech_relationships[tech1].add(tech2)
    
    # Convert sets to lists for JSON serialization
    result = {}
    for tech, related in tech_relationships.items():
        if tech_counts[tech] >= 2:  # Only include techs used in at least 2 repos
            result[tech] = list(related)
    
    return result


def get_ecosystem_hierarchy(repositories: List[Repository]) -> Dict[str, Any]:
    """
    Generate an ecosystem hierarchy based on dependencies.
    
    Args:
        repositories: List of analyzed repositories
        
    Returns:
        Dictionary with ecosystem hierarchy
    """
    # Group repositories by primary technology
    tech_groups = defaultdict(list)
    
    # Map of repository name to object
    repo_map = {repo.name: repo for repo in repositories if repo.scanned}
    
    # Identify primary technology for each repo
    for repo in repositories:
        if not repo.scanned:
            continue
            
        primary_tech = _get_primary_technology(repo)
        if primary_tech:
            tech_groups[primary_tech].append(repo.name)
    
    # Create the ecosystem hierarchy
    ecosystem = {
        'technology_groups': dict(tech_groups),
        'service_groups': _identify_service_groups(repositories),
        'dependency_tree': _build_dependency_tree(repositories, repo_map)
    }
    
    return ecosystem


def _get_primary_technology(repo: Repository) -> str:
    """
    Determine the primary technology used in a repository.
    
    Args:
        repo: Repository to analyze
        
    Returns:
        Primary technology name
    """
    # Count technologies by category
    category_counts = defaultdict(int)
    tech_counts = Counter()
    
    for category, techs in repo.technologies.items():
        category_counts[category] += len(techs)
        for tech in techs:
            tech_counts[tech['name']] += 1
    
    # Determine primary category
    primary_category = max(category_counts.items(), key=lambda x: x[1])[0] if category_counts else None
    
    if not primary_category:
        return "Unknown"
    
    # Find most common technology in primary category
    primary_tech = None
    max_count = 0
    
    for tech in repo.technologies.get(primary_category, []):
        if tech_counts[tech['name']] > max_count:
            max_count = tech_counts[tech['name']]
            primary_tech = tech['name']
    
    return primary_tech or "Unknown"


def _identify_service_groups(repositories: List[Repository]) -> Dict[str, List[str]]:
    """
    Group repositories that might be part of the same service.
    
    Args:
        repositories: List of analyzed repositories
        
    Returns:
        Dictionary mapping service names to repository lists
    """
    # Helper to extract potential service name from repo name
    def extract_service_name(name):
        # Remove suffixes like -api, -service, -backend, etc.
        for suffix in ['-api', '-service', '-backend', '-server', '-client', '-core']:
            if name.lower().endswith(suffix):
                return name[:-len(suffix)]
        return name
    
    # Group repositories by potential service name
    service_groups = defaultdict(list)
    
    for repo in repositories:
        if not repo.scanned:
            continue
            
        service_name = extract_service_name(repo.name)
        service_groups[service_name].append(repo.name)
    
    # Keep only groups with multiple repositories
    return {k: v for k, v in service_groups.items() if len(v) > 1}


def _build_dependency_tree(repositories: List[Repository], repo_map: Dict[str, Repository]) -> Dict[str, Any]:
    """
    Build a dependency tree of repositories.
    
    Args:
        repositories: List of analyzed repositories
        repo_map: Mapping of repository names to Repository objects
        
    Returns:
        Dependency tree
    """
    # Root level services (no dependencies)
    root_services = []
    
    # Identify repositories with no dependencies
    for repo in repositories:
        if not repo.scanned:
            continue
            
        has_dependencies = False
        
        # Check if this repo depends on others
        for dep_type in ['repositories', 'services']:
            if repo.dependencies.get(dep_type, []):
                has_dependencies = True
                break
        
        if not has_dependencies:
            root_services.append(repo.name)
    
    # Build tree starting from root services
    dependency_tree = {}
    
    for root in root_services:
        dependency_tree[root] = _build_subtree(root, repo_map)
    
    return dependency_tree


def _build_subtree(repo_name: str, repo_map: Dict[str, Repository], visited: set = None) -> Dict[str, Any]:
    """
    Recursively build a dependency subtree.
    
    Args:
        repo_name: Repository name to build subtree for
        repo_map: Mapping of repository names to Repository objects
        visited: Set of already visited repositories
        
    Returns:
        Dependency subtree
    """
    if visited is None:
        visited = set()
        
    if repo_name in visited:
        return {}  # Prevent cycles
        
    visited.add(repo_name)
    
    subtree = {}
    
    # Find repositories that depend on this one
    for name, repo in repo_map.items():
        if any(dep == repo_name for dep in repo.dependencies.get('repositories', [])) or \
           any(dep == repo_name for dep in repo.dependencies.get('services', [])):
            subtree[name] = _build_subtree(name, repo_map, visited.copy())
    
    return subtree
