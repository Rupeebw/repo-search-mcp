"""
Documentation analyzer for GitLab Repository Analyzer.
Extracts documentation, setup instructions, and architecture information.
"""

import re
from typing import Dict, List, Any, Optional, Set, Tuple
from ..core.repository import Repository


class DocumentationAnalyzer:
    """Analyzer for extracting documentation from repositories."""
    
    def __init__(self):
        """Initialize documentation analyzer."""
        # Documentation file patterns
        self.readme_patterns = ["README.md", "README.rst", "README.txt", "README", "readme.md"]
        self.api_doc_patterns = ["api.md", "API.md", "docs/api", "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml"]
        self.setup_patterns = ["INSTALL.md", "SETUP.md", "docs/setup", "docs/install", "CONTRIBUTING.md", "dev-setup"]
        self.architecture_patterns = ["ARCHITECTURE.md", "docs/architecture", "design.md", "structure.md"]
        
        # Section markers in README files
        self.setup_section_markers = [
            r'(?i)## (installation|setup|getting started)',
            r'(?i)### (installation|setup|getting started)',
            r'(?i)## (how to install|how to set up|how to run)',
            r'(?i)## (build|deploy)'
        ]
        
        self.api_section_markers = [
            r'(?i)## (api|endpoints|routes)',
            r'(?i)### (api|endpoints|routes)',
            r'(?i)## (rest api|graphql api)',
            r'(?i)## (available methods|available endpoints)'
        ]
        
        self.architecture_section_markers = [
            r'(?i)## (architecture|design|structure)',
            r'(?i)### (architecture|design|structure)',
            r'(?i)## (system design|code structure)',
            r'(?i)## (components|modules|services)'
        ]
    
    def analyze(self, repositories: List[Repository]) -> None:
        """
        Analyze repositories for documentation.
        
        Args:
            repositories: List of repositories to analyze
        """
        if not repositories:
            return
        
        print("Extracting documentation from repositories...")
        
        # Process each repository
        for repo in repositories:
            # Skip if not scanned
            if not repo.scanned:
                continue
                
            # Look for README files
            self._extract_readme(repo)
            
            # Look for API documentation
            self._extract_api_docs(repo)
            
            # Look for setup instructions
            self._extract_setup_instructions(repo)
            
            # Look for architecture information
            self._extract_architecture_info(repo)
    
    def _extract_readme(self, repo: Repository) -> None:
        """
        Extract README from repository.
        
        Args:
            repo: Repository to analyze
        """
        # Look for README files
        for file_pattern in self.readme_patterns:
            try:
                # Try to get README
                file_content = repo.project.files.get(file_path=file_pattern, ref=repo.default_branch)
                content = self._clean_content(file_content.decode())
                
                # Extract sections from README
                sections = self._extract_sections(content)
                
                # Store README content
                repo.add_documentation('readme', {
                    'full_content': content,
                    'sections': sections
                }, file_pattern)
                
                # Extract specific documentation from README
                self._extract_from_readme(repo, content, file_pattern)
                
                # README found, no need to check other patterns
                break
                
            except Exception:
                # README not found with this pattern, try next
                continue
    
    def _extract_api_docs(self, repo: Repository) -> None:
        """
        Extract API documentation from repository.
        
        Args:
            repo: Repository to analyze
        """
        for file_pattern in self.api_doc_patterns:
            try:
                # Try to get API docs
                file_content = repo.project.files.get(file_path=file_pattern, ref=repo.default_branch)
                content = self._clean_content(file_content.decode())
                
                # Store API documentation
                repo.add_documentation('api_docs', {
                    'content': content
                }, file_pattern)
                
            except Exception:
                # API docs not found with this pattern, try next
                continue
            
        # Look for OpenAPI/Swagger docs in subdirectories
        for file_path in repo.analyzed_files:
            if any(pattern in file_path.lower() for pattern in ['swagger', 'openapi', 'api-docs']):
                try:
                    # Get file content
                    file_content = repo.project.files.get(file_path=file_path, ref=repo.default_branch)
                    content = self._clean_content(file_content.decode())
                    
                    # Store API documentation
                    repo.add_documentation('api_docs', {
                        'content': content
                    }, file_path)
                    
                except Exception:
                    # Skip if we can't access the file
                    continue
    
    def _extract_setup_instructions(self, repo: Repository) -> None:
        """
        Extract setup instructions from repository.
        
        Args:
            repo: Repository to analyze
        """
        for file_pattern in self.setup_patterns:
            try:
                # Try to get setup docs
                file_content = repo.project.files.get(file_path=file_pattern, ref=repo.default_branch)
                content = self._clean_content(file_content.decode())
                
                # Store setup instructions
                repo.add_documentation('setup_instructions', {
                    'content': content
                }, file_pattern)
                
            except Exception:
                # Setup docs not found with this pattern, try next
                continue
        
        # Also check for Dockerfiles and docker-compose.yml
        docker_files = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml']
        for file_pattern in docker_files:
            try:
                # Try to get Docker files
                file_content = repo.project.files.get(file_path=file_pattern, ref=repo.default_branch)
                content = self._clean_content(file_content.decode())
                
                # Store as setup instructions
                repo.add_documentation('setup_instructions', {
                    'content': content,
                    'type': 'docker'
                }, file_pattern)
                
            except Exception:
                # Docker files not found, try next
                continue
    
    def _extract_architecture_info(self, repo: Repository) -> None:
        """
        Extract architecture information from repository.
        
        Args:
            repo: Repository to analyze
        """
        for file_pattern in self.architecture_patterns:
            try:
                # Try to get architecture docs
                file_content = repo.project.files.get(file_path=file_pattern, ref=repo.default_branch)
                content = self._clean_content(file_content.decode())
                
                # Store architecture info
                repo.add_documentation('architecture', {
                    'content': content
                }, file_pattern)
                
            except Exception:
                # Architecture docs not found with this pattern, try next
                continue
        
        # Look for diagrams
        for file_path in repo.analyzed_files:
            if 'diagram' in file_path.lower() or any(file_path.endswith(ext) for ext in ['.drawio', '.puml', '.plantuml']):
                try:
                    # Get file content
                    file_content = repo.project.files.get(file_path=file_path, ref=repo.default_branch)
                    content = self._clean_content(file_content.decode())
                    
                    # Store as architecture info
                    repo.add_documentation('architecture', {
                        'content': content,
                        'type': 'diagram'
                    }, file_path)
                    
                except Exception:
                    # Skip if we can't access the file
                    continue
    
    def _extract_from_readme(self, repo: Repository, content: str, file_path: str) -> None:
        """
        Extract specific documentation sections from README.
        
        Args:
            repo: Repository to update
            content: README content
            file_path: Path to the README file
        """
        # Extract setup instructions
        for pattern in self.setup_section_markers:
            section = self._extract_section(content, pattern)
            if section:
                repo.add_documentation('setup_instructions', {
                    'content': section,
                    'source': 'README'
                }, file_path)
        
        # Extract API documentation
        for pattern in self.api_section_markers:
            section = self._extract_section(content, pattern)
            if section:
                repo.add_documentation('api_docs', {
                    'content': section,
                    'source': 'README'
                }, file_path)
        
        # Extract architecture information
        for pattern in self.architecture_section_markers:
            section = self._extract_section(content, pattern)
            if section:
                repo.add_documentation('architecture', {
                    'content': section,
                    'source': 'README'
                }, file_path)
    
    def _extract_section(self, content: str, section_pattern: str) -> Optional[str]:
        """
        Extract a section from markdown content.
        
        Args:
            content: Markdown content
            section_pattern: Regex pattern for section header
            
        Returns:
            Section content or None if not found
        """
        match = re.search(section_pattern, content)
        if not match:
            return None
            
        # Find the starting point of the section
        start = match.end()
        
        # Find the next section header of equal or higher level
        section_level = 0
        header_pattern = r'(^|\n)#{1,3} '
        
        if '##' in match.group(0):
            section_level = 2
        elif '###' in match.group(0):
            section_level = 3
        else:
            section_level = 1
            
        # Build a pattern to find the next section at same or higher level
        next_section_pattern = r'(^|\n)#{1,' + str(section_level) + r'} '
        
        next_match = re.search(next_section_pattern, content[start:])
        if next_match:
            end = start + next_match.start()
            return content[start:end].strip()
        else:
            # No next section, take the rest of the content
            return content[start:].strip()
    
    def _extract_sections(self, content: str) -> Dict[str, str]:
        """
        Extract all sections from markdown content.
        
        Args:
            content: Markdown content
            
        Returns:
            Dictionary of section name to content
        """
        sections = {}
        
        # Find all headers
        headers = re.finditer(r'(^|\n)(#{1,3}) ([^\n]+)', content)
        
        # Store starting points and header info
        header_positions = []
        
        for match in headers:
            level = len(match.group(2))  # Number of # characters
            name = match.group(3).strip()
            pos = match.end()
            
            header_positions.append((pos, level, name))
        
        # Extract content between headers
        for i, (start, level, name) in enumerate(header_positions):
            # Find end of this section (next header of same or higher level)
            end = None
            
            for next_pos, next_level, _ in header_positions[i+1:]:
                if next_level <= level:
                    end = next_pos
                    break
                    
            # Extract section content
            if end:
                section_content = content[start:end].strip()
            else:
                section_content = content[start:].strip()
                
            # Store section
            sections[name] = section_content
        
        return sections
    
    def _clean_content(self, content: Any) -> str:
        """Clean and decode content."""
        if isinstance(content, bytes):
            try:
                return content.decode('utf-8', errors='ignore')
            except:
                return ""
        return str(content)
