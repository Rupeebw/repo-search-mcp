"""
Connection analyzer for GitLab Repository Analyzer.
Identifies relationships between repositories based on API usage and service references.
"""

import re
from typing import Dict, List, Any, Set, Tuple
from ..core.repository import Repository


class ConnectionAnalyzer:
    """Analyzer for connections between repositories."""
    
    def __init__(self):
        """Initialize connection analyzer."""
        # API endpoint patterns
        self.api_patterns = [
            # Express-style endpoints
            r'app\.(get|post|put|delete|patch)\([\'"]([^\'")]+)[\'"]',
            # Flask/Django-style endpoints
            r'@app.route\([\'"]([^\'"]+)[\'"]',
            r'@api_view\(\[[\'"]GET[\'"],[\'"]POST[\'"]\]\)\s+def\s+(\w+)',
            r'path\([\'"]([^\'"]+)[\'"], (\w+).as_view\(\)\)',
            # FastAPI endpoints
            r'@app.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            # Spring Boot controller methods
            r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\([\'"]([^\'"]+)[\'"]',
            # Generic API path detection (with validation to reduce false positives)
            r'[\'"](/api/[^\'"]+)[\'"]',
            r'[\'"](https?://[^\'"]+/api/[^\'"]+)[\'"]'
        ]
        
        # API client patterns
        self.api_client_patterns = [
            # Axios
            r'axios\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            # Fetch API
            r'fetch\([\'"]([^\'"]+)[\'"]',
            # jQuery AJAX
            r'\$\.ajax\(\{.*url:\s*[\'"]([^\'"]+)[\'"]',
            # Request library
            r'request\([\'"]([^\'"]+)[\'"]',
            # Various HTTP clients
            r'http.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            # URL construction
            r'url\s*[=:]\s*[\'"]([^\'"]+/api/[^\'"]+)[\'"]'
        ]
        
        # Service reference patterns
        self.service_patterns = [
            # Docker Compose service names
            r'services:\s*\n\s+(\w+):',
            # Kubernetes service references
            r'kind:\s*Service\s*\n.*\s*name:\s*(\w+)',
            # Environment variables referencing services
            r'(\w+)_SERVICE_HOST',
            r'(\w+)_API_URL',
            # Service imports or requires
            r'from\s+(\w+)\.client\s+import',
            r'require\([\'"]@\w+/(\w+-service)[\'"]',
            # General service references
            r'service[:\s][\'"](\w+)[\'"]',
            r'ServiceName[:\s][\'"](\w+)[\'"]'
        ]
    
    def analyze(self, repositories: List[Repository]) -> None:
        """
        Analyze connections between repositories.
        
        Args:
            repositories: List of repositories to analyze
        """
        if not repositories:
            return
        
        print("Analyzing connections between repositories...")
        
        # Extract API endpoints from all repositories
        api_endpoints = self._extract_api_endpoints(repositories)
        
        # Find API clients and match with endpoints
        self._find_api_connections(repositories, api_endpoints)
        
        # Find service references
        self._find_service_connections(repositories)
    
    def _extract_api_endpoints(self, repositories: List[Repository]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract API endpoints from all repositories.
        
        Args:
            repositories: List of repositories to analyze
            
        Returns:
            Dictionary mapping endpoint paths to repository info
        """
        endpoints: Dict[str, List[Dict[str, Any]]] = {}
        
        for repo in repositories:
            # Skip if not scanned
            if not repo.scanned:
                continue
                
            for file_path in repo.analyzed_files:
                # Skip non-code files
                if not any(file_path.endswith(ext) for ext in ['.py', '.js', '.java', '.go', '.ts', '.rb', '.php']):
                    continue
                
                try:
                    # Get file content
                    file_content = repo.project.files.get(file_path=file_path, ref=repo.default_branch)
                    content = self._clean_content(file_content.decode())
                    
                    # Look for API endpoint patterns
                    for pattern in self.api_patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            # Extract the path portion
                            path = None
                            if len(match.groups()) == 1:
                                path = match.group(1)
                            elif len(match.groups()) >= 2:
                                path = match.group(2)  # Usually the path is in the second group
                                
                            if path:
                                # Normalize path (remove trailing slashes, etc.)
                                path = self._normalize_path(path)
                                
                                # Store endpoint info
                                endpoint_info = {
                                    'repo_id': repo.id,
                                    'repo_name': repo.name,
                                    'file_path': file_path,
                                    'matched_text': match.group(0)
                                }
                                
                                if path in endpoints:
                                    endpoints[path].append(endpoint_info)
                                else:
                                    endpoints[path] = [endpoint_info]
                                
                                # Add to repository's API list
                                # Determine HTTP method if possible
                                method = "GET"  # Default
                                if "post" in match.group(0).lower():
                                    method = "POST"
                                elif "put" in match.group(0).lower():
                                    method = "PUT"
                                elif "delete" in match.group(0).lower():
                                    method = "DELETE"
                                elif "patch" in match.group(0).lower():
                                    method = "PATCH"
                                
                                repo.add_api_endpoint(path, method, file_path)
                    
                except Exception:
                    # Skip files we can't access
                    continue
        
        return endpoints
    
    def _find_api_connections(self, repositories: List[Repository], 
                            api_endpoints: Dict[str, List[Dict[str, Any]]]) -> None:
        """
        Find API client connections between repositories.
        
        Args:
            repositories: List of repositories to analyze
            api_endpoints: Dictionary of API endpoints
        """
        # Process each repository looking for API client calls
        for repo in repositories:
            # Skip if not scanned
            if not repo.scanned:
                continue
                
            for file_path in repo.analyzed_files:
                # Skip non-code files
                if not any(file_path.endswith(ext) for ext in ['.py', '.js', '.java', '.go', '.ts', '.rb', '.php']):
                    continue
                
                try:
                    # Get file content
                    file_content = repo.project.files.get(file_path=file_path, ref=repo.default_branch)
                    content = self._clean_content(file_content.decode())
                    
                    # Look for API client patterns
                    for pattern in self.api_client_patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            # Extract the path portion
                            path = None
                            if len(match.groups()) == 1:
                                path = match.group(1)
                            elif len(match.groups()) >= 2:
                                path = match.group(2)
                                
                            if path:
                                # Normalize path
                                path = self._normalize_path(path)
                                
                                # Check if this matches a known API endpoint
                                connected_endpoints = self._find_matching_endpoints(path, api_endpoints)
                                
                                # Add dependencies for matching endpoints
                                for endpoint_path, endpoint_info in connected_endpoints:
                                    for info in endpoint_info:
                                        # Don't connect to self
                                        if info['repo_id'] != repo.id:
                                            # Add dependency to the target repo
                                            repo.add_dependency('repositories', info['repo_name'])
                    
                except Exception:
                    # Skip files we can't access
                    continue
    
    def _find_service_connections(self, repositories: List[Repository]) -> None:
        """
        Find service references between repositories.
        
        Args:
            repositories: List of repositories to analyze
        """
        # First, collect all repository names and path segments
        repo_names: Set[str] = set()
        for repo in repositories:
            if repo.scanned:
                # Add full name
                repo_names.add(repo.name.lower())
                
                # Add parts of the name (for potential partial matches)
                parts = repo.name.lower().split('-')
                if len(parts) > 1:
                    for part in parts:
                        if len(part) > 3:  # Avoid short parts like 'the', 'and', etc.
                            repo_names.add(part)
        
        # Process each repository looking for service references
        for repo in repositories:
            # Skip if not scanned
            if not repo.scanned:
                continue
                
            for file_path in repo.analyzed_files:
                # Focus on configuration files
                is_config = any(x in file_path.lower() for x in 
                                ['docker', 'kubernetes', 'k8s', '.yml', '.yaml', '.env', 'config'])
                
                if not is_config and not any(file_path.endswith(ext) for ext in 
                                           ['.py', '.js', '.java', '.ts', '.rb', '.php']):
                    continue
                
                try:
                    # Get file content
                    file_content = repo.project.files.get(file_path=file_path, ref=repo.default_branch)
                    content = self._clean_content(file_content.decode())
                    
                    # Look for service references
                    for pattern in self.service_patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            if match.group(1):
                                service_name = match.group(1).lower()
                                
                                # Check if this service name matches a repository
                                for repo_name in repo_names:
                                    # Direct match or contains match for longer names
                                    if service_name == repo_name or (
                                        len(repo_name) > 5 and repo_name in service_name):
                                        
                                        # Find the actual repo with this name
                                        for target_repo in repositories:
                                            if target_repo.name.lower() == repo_name or (
                                                len(repo_name) > 5 and repo_name in target_repo.name.lower()):
                                                
                                                # Don't connect to self
                                                if target_repo.id != repo.id:
                                                    # Add dependency
                                                    repo.add_dependency('services', target_repo.name)
                    
                    # Additional check for URLs or imports with repo names
                    for repo_name in repo_names:
                        if len(repo_name) > 5:  # Avoid short names that could cause false positives
                            pattern = rf'[\'"]https?://[^\'"]*{re.escape(repo_name)}[^\'"]*[\'"]'
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                # Find the actual repo with this name
                                for target_repo in repositories:
                                    if repo_name in target_repo.name.lower():
                                        # Don't connect to self
                                        if target_repo.id != repo.id:
                                            # Add dependency
                                            repo.add_dependency('services', target_repo.name)
                                            
                except Exception:
                    # Skip files we can't access
                    continue
    
    def _clean_content(self, content: Any) -> str:
        """Clean and decode content."""
        if isinstance(content, bytes):
            try:
                return content.decode('utf-8', errors='ignore')
            except:
                return ""
        return str(content)
    
    def _normalize_path(self, path: str) -> str:
        """Normalize API path for comparison."""
        # Remove trailing slashes
        path = path.rstrip('/')
        
        # Remove protocol and domain if present
        if '://' in path:
            path = '/' + '/'.join(path.split('/')[3:])
            
        # Replace path parameters with wildcards
        path = re.sub(r':[^/]+', ':param', path)
        path = re.sub(r'<[^>]+>', ':param', path)
        path = re.sub(r'\{[^}]+\}', ':param', path)
        
        return path
    
    def _find_matching_endpoints(self, client_path: str, 
                               endpoints: Dict[str, List[Dict[str, Any]]]) -> List[Tuple[str, List[Dict[str, Any]]]]:
        """
        Find endpoints that match a client path.
        
        Args:
            client_path: Path from client code
            endpoints: Dictionary of endpoints
            
        Returns:
            List of matching (path, endpoint info) pairs
        """
        matches = []
        
        # Normalize the client path
        norm_client_path = self._normalize_path(client_path)
        
        # Exact match
        if norm_client_path in endpoints:
            matches.append((norm_client_path, endpoints[norm_client_path]))
            return matches
        
        # Try to match with wildcards or partial paths
        for endpoint_path, endpoint_info in endpoints.items():
            # Check if endpoint is part of client path (API base URL)
            if endpoint_path.startswith('/api') and endpoint_path in norm_client_path:
                matches.append((endpoint_path, endpoint_info))
                
            # Check if client path is part of endpoint
            elif norm_client_path.startswith('/api') and norm_client_path in endpoint_path:
                matches.append((endpoint_path, endpoint_info))
                
            # Remove API prefix and check for path match
            elif endpoint_path.startswith('/api/') and norm_client_path.startswith('/api/'):
                endpoint_suffix = endpoint_path[5:]  # Remove '/api/'
                client_suffix = norm_client_path[5:]  # Remove '/api/'
                
                if endpoint_suffix == client_suffix:
                    matches.append((endpoint_path, endpoint_info))
        
        return matches
