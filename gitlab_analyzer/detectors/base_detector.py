"""
Base detector class for technology detection in GitLab Repository Analyzer.
All specific technology detectors inherit from this class.
"""

import os
import re
from typing import Dict, List, Any, Optional, Pattern
from ..core.repository import Repository
from ..core.utils import find_pattern_in_content, find_regex_in_content


class BaseDetector:
    """Base detector class for technology detection."""
    
    def __init__(self, name: str, category: str):
        """
        Initialize base detector.
        
        Args:
            name: Detector name
            category: Technology category (frontend, backend, etc.)
        """
        self.name = name
        self.category = category
        self.file_patterns: List[str] = []
        self.content_patterns: Dict[str, List[str]] = {}
        self.regex_patterns: Dict[str, List[str]] = {}
    
    def should_process_file(self, file_path: str) -> bool:
        """
        Check if file should be processed by this detector.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file should be processed
        """
        # If no file patterns specified, process all files
        if not self.file_patterns:
            return True
        
        # Check if file matches any patterns
        return any(self._matches_pattern(file_path, pattern) for pattern in self.file_patterns)
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """
        Check if file path matches a pattern.
        
        Args:
            file_path: Path to check
            pattern: Pattern to match (can use * as wildcard)
            
        Returns:
            True if path matches pattern
        """
        # Convert glob pattern to regex
        regex_pattern = pattern.replace('.', '\\.').replace('*', '.*')
        return bool(re.search(regex_pattern, file_path))
    
    def detect(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Detect technologies in file content.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Skip if file doesn't match patterns
        if not self.should_process_file(file_path):
            return
            
        # Check simple content patterns
        for tech_name, patterns in self.content_patterns.items():
            if find_pattern_in_content(content, patterns):
                repository.add_technology(
                    category=self.category,
                    name=tech_name,
                    path=file_path
                )
        
        # Check regex patterns
        for tech_name, patterns in self.regex_patterns.items():
            matches = find_regex_in_content(content, patterns)
            if matches:
                # Some regex patterns can extract version info
                version = None
                if len(matches) > 0 and 'version' in tech_name.lower():
                    # Try to extract version from the first match
                    version = matches[0]
                
                repository.add_technology(
                    category=self.category,
                    name=tech_name,
                    path=file_path,
                    version=version,
                    details={'matches': matches[:5]}  # Store first 5 matches
                )
        
        # Call specialized detection
        self._detect_specialized(repository, content, file_path)
    
    def _detect_specialized(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Specialized detection logic to be implemented by subclasses.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # To be implemented by subclasses
        pass


class CustomDetector(BaseDetector):
    """Custom detector created from user-defined patterns."""
    
    def __init__(self, name: str, category: str, file_patterns: List[str], content_patterns: List[str]):
        """
        Initialize custom detector.
        
        Args:
            name: Detector name
            category: Technology category
            file_patterns: List of file patterns to match
            content_patterns: List of content patterns to match
        """
        super().__init__(name, category)
        self.file_patterns = file_patterns
        self.content_patterns = {name: content_patterns}
