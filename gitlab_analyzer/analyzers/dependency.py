import os
import re
import json
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
import subprocess

logger = logging.getLogger(__name__)

class DependencyAnalyzer:
    """
    Analyzes dependencies between repositories and within a repository.
    """
    
    def __init__(self):
        self.dependency_files = [
            'requirements.txt',  # Python
            'package.json',      # Node.js
            'pom.xml',           # Java/Maven
            'build.gradle',      # Gradle
            'Gemfile',           # Ruby
            'composer.json',     # PHP
            'go.mod'             # Go
        ]
        
    def find_dependency_files(self, repo_path: str) -> List[str]:
        """
        Find all dependency files in the repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            List of paths to dependency files
        """
        dependency_files = []
        
        for root, _, files in os.walk(repo_path):
            for filename in files:
                if filename in self.dependency_files:
                    dependency_files.append(os.path.join(root, filename))
        
        return dependency_files
    
    def parse_dependencies(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse dependencies from a dependency file.
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            List of dependencies with name, version, and type
        """
        filename = os.path.basename(file_path)
        dependencies = []
        
        try:
            if filename == 'requirements.txt':
                # Parse Python requirements.txt
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Handle different formats like package==1.0.0, package>=1.0.0, etc.
                            match = re.match(r'^([a-zA-Z0-9_.-]+)([<>=!~].+)?$', line)
                            if match:
                                name = match.group(1)
                                version = match.group(2) if match.group(2) else "Not specified"
                                dependencies.append({
                                    'name': name,
                                    'version': version,
                                    'type': 'python'
                                })
            
            elif filename == 'package.json':
                # Parse Node.js package.json
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                # Process dependencies
                for dep_type in ['dependencies', 'devDependencies']:
                    if dep_type in data:
                        for name, version in data[dep_type].items():
                            dependencies.append({
                                'name': name,
                                'version': version,
                                'type': 'npm',
                                'dev_dependency': dep_type == 'devDependencies'
                            })
            
            elif filename == 'pom.xml':
                # Basic Maven POM parsing using regex (simplified)
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Extract dependencies using regex
                dependency_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
                for match in re.finditer(dependency_pattern, content, re.DOTALL):
                    group_id, artifact_id, version = match.groups()
                    dependencies.append({
                        'name': f"{group_id}:{artifact_id}",
                        'version': version,
                        'type': 'maven'
                    })
            
            elif filename == 'build.gradle':
                # Basic Gradle parsing using regex (simplified)
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Look for common patterns in Gradle files
                dependency_pattern = r'(implementation|api|compile|testImplementation|testCompile)\s+[\'"]([^:]+):([^:]+):([^\'"]+)[\'"]'
                for match in re.finditer(dependency_pattern, content):
                    scope, group, name, version = match.groups()
                    dependencies.append({
                        'name': f"{group}:{name}",
                        'version': version,
                        'type': 'gradle',
                        'scope': scope
                    })
            
            elif filename == 'Gemfile':
                # Parse Ruby Gemfile
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith('gem '):
                            parts = re.findall(r'[\'"]([^\'"]+)[\'"]', line)
                            if parts:
                                name = parts[0]
                                version = parts[1] if len(parts) > 1 else "Not specified"
                                dependencies.append({
                                    'name': name,
                                    'version': version,
                                    'type': 'ruby'
                                })
            
            elif filename == 'composer.json':
                # Parse PHP Composer.json
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                for dep_type in ['require', 'require-dev']:
                    if dep_type in data:
                        for name, version in data[dep_type].items():
                            dependencies.append({
                                'name': name,
                                'version': version,
                                'type': 'php',
                                'dev_dependency': dep_type == 'require-dev'
                            })
            
            elif filename == 'go.mod':
                # Parse Go modules
                with open(file_path, 'r') as f:
                    content = f.readlines()
                
                for line in content:
                    if re.match(r'^\s*require\s+', line):
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            dependencies.append({
                                'name': parts[1],
                                'version': parts[2],
                                'type': 'go'
                            })
                            
        except Exception as e:
            logger.error(f"Error parsing dependencies from {file_path}: {e}")
        
        return dependencies
    
    def find_internal_imports(self, repo_path: str) -> Dict[str, List[str]]:
        """
        Find internal imports between modules within the repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dictionary mapping files to their internal imports
        """
        internal_imports = {}
        
        # Find all Python files
        python_files = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        # Analyze imports in Python files
        for py_file in python_files:
            relative_path = os.path.relpath(py_file, repo_path)
            imports = []
            
            try:
                with open(py_file, 'r') as f:
                    for line in f:
                        # Look for import statements
                        if line.strip().startswith(('import ', 'from ')):
                            # Skip standard library imports
                            if not any(ext in line for ext in ['os', 'sys', 're', 'datetime', 'json']):
                                imports.append(line.strip())
                
                if imports:
                    internal_imports[relative_path] = imports
            except Exception as e:
                logger.error(f"Error analyzing imports in {py_file}: {e}")
        
        return internal_imports
    
    def find_cross_repo_dependencies(self, repos_data: Dict[str, Dict]) -> Dict[str, List[str]]:
        """
        Find dependencies between different repositories.
        
        Args:
            repos_data: Dictionary mapping repository names to their dependency information
            
        Returns:
            Dictionary mapping repositories to their dependencies
        """
        cross_repo_deps = {}
        
        # Build a dictionary of all packages/modules defined in each repo
        repo_packages = {}
        for repo_name, repo_info in repos_data.items():
            # Extract repository name from potential URLs
            simple_name = repo_name.split('/')[-1].replace('.git', '')
            repo_packages[simple_name] = repo_name
            
            # Also consider the repository name with common prefixes/suffixes
            variations = [
                f"{simple_name}-lib",
                f"{simple_name}-api",
                f"{simple_name}-client",
                f"{simple_name}-service",
                f"lib-{simple_name}",
                f"api-{simple_name}",
                f"{simple_name}-sdk"
            ]
            for var in variations:
                repo_packages[var] = repo_name
        
        # Check dependencies across repositories
        for repo_name, repo_info in repos_data.items():
            dependencies = []
            
            # Check dependencies for matches with other repos
            for dep_file in repo_info.get('dependency_files', []):
                for dep in dep_file.get('dependencies', []):
                    dep_name = dep['name'].lower()
                    
                    # Check if this dependency matches any repo name
                    for package_name, related_repo in repo_packages.items():
                        if package_name.lower() in dep_name and related_repo != repo_name:
                            if related_repo not in dependencies:
                                dependencies.append(related_repo)
            
            if dependencies:
                cross_repo_deps[repo_name] = dependencies
        
        return cross_repo_deps
    
    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Analyze dependencies in a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dictionary with dependency information
        """
        result = {
            'dependency_files': [],
            'internal_imports': {},
            'total_dependencies': 0,
            'dependency_types': {}
        }
        
        # Find dependency files
        dep_files = self.find_dependency_files(repo_path)
        
        # Parse each dependency file
        for file_path in dep_files:
            relative_path = os.path.relpath(file_path, repo_path)
            dependencies = self.parse_dependencies(file_path)
            
            if dependencies:
                result['dependency_files'].append({
                    'path': relative_path,
                    'type': os.path.basename(file_path),
                    'dependencies': dependencies
                })
                
                # Update dependency type counts
                for dep in dependencies:
                    dep_type = dep['type']
                    if dep_type not in result['dependency_types']:
                        result['dependency_types'][dep_type] = 0
                    result['dependency_types'][dep_type] += 1
                    result['total_dependencies'] += 1
        
        # Find internal imports
        result['internal_imports'] = self.find_internal_imports(repo_path)
        
        return result
