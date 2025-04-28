"""
Repository data model for GitLab Repository Analyzer.
Stores all information and analysis results for a single repository.
"""

from typing import Dict, List, Any, Optional
import gitlab


class Repository:
    """Repository data model to store analysis results."""
    
    def __init__(self, gitlab_project):
        """Initialize repository from GitLab project."""
        # Basic properties
        self.id = gitlab_project.id
        self.name = gitlab_project.name
        self.path = gitlab_project.path_with_namespace
        self.default_branch = gitlab_project.default_branch or 'main'
        self.project = gitlab_project
        self.web_url = gitlab_project.web_url
        
        # Store analysis results
        self.scanned = False
        self.analyzed_files: List[str] = []
        
        # Detected technologies
        self.technologies: Dict[str, List[Dict[str, Any]]] = {
            'frontend': [],
            'backend': [],
            'database': [],
            'infrastructure': [],
            'cicd': []
        }
        
        # API endpoints and connections
        self.apis: List[Dict[str, Any]] = []
        
        # Dependencies
        self.dependencies: Dict[str, List[str]] = {
            'imports': [],        # Direct code imports
            'services': [],       # Service references
            'repositories': []    # Other repo references
        }
        
        # Documentation info
        self.documentation: Dict[str, Any] = {
            'readme': None,
            'api_docs': [],
            'setup_instructions': [],
            'architecture': []
        }
        
        # Repository stats
        self.stats: Dict[str, Any] = {
            'total_files': 0,
            'analyzed_files': 0,
            'languages': {}
        }
    
    def add_technology(self, category: str, name: str, confidence: float = 1.0, 
                      version: Optional[str] = None, path: Optional[str] = None, 
                      details: Optional[Dict[str, Any]] = None) -> None:
        """Add a detected technology."""
        if category not in self.technologies:
            self.technologies[category] = []
            
        technology = {
            'name': name,
            'confidence': confidence,
            'detected_in': path or '',
            'version': version
        }
        
        if details:
            technology.update(details)
            
        # Check if already detected (avoid duplicates)
        for existing in self.technologies[category]:
            if existing['name'] == name:
                # Update confidence if higher
                if confidence > existing['confidence']:
                    existing['confidence'] = confidence
                    existing['detected_in'] = path or existing['detected_in']
                    if version:
                        existing['version'] = version
                    if details:
                        existing.update(details)
                return
        
        # Add new technology
        self.technologies[category].append(technology)
    
    def add_api_endpoint(self, path: str, method: str, source_file: str, 
                        description: Optional[str] = None) -> None:
        """Add a detected API endpoint."""
        endpoint = {
            'path': path,
            'method': method,
            'source_file': source_file,
            'description': description or ''
        }
        
        self.apis.append(endpoint)
    
    def add_dependency(self, dep_type: str, name: str, source_file: Optional[str] = None) -> None:
        """Add a detected dependency."""
        if dep_type not in self.dependencies:
            self.dependencies[dep_type] = []
            
        # Check if already added
        if name not in self.dependencies[dep_type]:
            self.dependencies[dep_type].append(name)
    
    def add_documentation(self, doc_type: str, content: Any, path: Optional[str] = None) -> None:
        """Add extracted documentation."""
        if doc_type == 'readme':
            self.documentation['readme'] = {
                'content': content,
                'path': path or 'README.md'
            }
        elif doc_type in self.documentation:
            self.documentation[doc_type].append({
                'content': content,
                'path': path or ''
            })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert repository to dictionary for serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'path': self.path,
            'web_url': self.web_url,
            'default_branch': self.default_branch,
            'technologies': self.technologies,
            'apis': self.apis,
            'dependencies': self.dependencies,
            'documentation': self.documentation,
            'stats': self.stats
        }
