"""
Core scanner module for GitLab Repository Analyzer.
Coordinates the scanning of repositories and manages the analysis process.
"""

import concurrent.futures
import os
import sys
import json
import time
from typing import Dict, List, Any, Tuple, Optional, Set
import gitlab
from gitlab.exceptions import GitlabGetError

from ..config import Config
from .repository import Repository
from .utils import timeout, TimeoutError, clean_content


class GitLabScanner:
    """Scanner for GitLab repositories."""
    
    def __init__(self, gitlab_instance: gitlab.Gitlab, group_id: str, config: Config):
        """
        Initialize the GitLab scanner.
        
        Args:
            gitlab_instance: Authenticated GitLab API client
            group_id: GitLab group ID to scan
            config: Scanner configuration
        """
        self.gitlab = gitlab_instance
        self.group_id = group_id
        self.config = config
        self.repositories: List[Repository] = []
        self.detectors = []
        self.analyzers = []
        
        # Load detectors and analyzers
        self._load_detectors()
        self._load_analyzers()
    
    def _load_detectors(self) -> None:
        """Load enabled technology detectors."""
        if self.config.get('detectors', 'frontend'):
            from ..detectors.frontend import FrontendDetector
            self.detectors.append(FrontendDetector())
        
        if self.config.get('detectors', 'backend'):
            from ..detectors.backend import BackendDetector
            self.detectors.append(BackendDetector())
            
        if self.config.get('detectors', 'database'):
            from ..detectors.database import DatabaseDetector
            self.detectors.append(DatabaseDetector())
            
        if self.config.get('detectors', 'infrastructure'):
            from ..detectors.infrastructure import InfrastructureDetector
            self.detectors.append(InfrastructureDetector())
            
        if self.config.get('detectors', 'cicd'):
            from ..detectors.cicd import CICDDetector
            self.detectors.append(CICDDetector())
            
        # Load custom detectors from config
        from ..detectors.base_detector import CustomDetector
        custom_patterns = self.config.get('detectors', 'custom_patterns', [])
        for pattern in custom_patterns:
            self.detectors.append(CustomDetector(
                name=pattern.get('name', 'Custom'),
                category=pattern.get('category', 'custom'),
                file_patterns=[pattern.get('file_pattern', '*')],
                content_patterns=[pattern.get('content_pattern', '')]
            ))
    
    def _load_analyzers(self) -> None:
        """Load enabled analyzers."""
        if self.config.get('analyzers', 'connections'):
            from ..analyzers.connection import ConnectionAnalyzer
            self.analyzers.append(ConnectionAnalyzer())
            
        if self.config.get('analyzers', 'dependencies'):
            from ..analyzers.dependency import DependencyAnalyzer
            self.analyzers.append(DependencyAnalyzer())
            
        if self.config.get('analyzers', 'documentation'):
            from ..analyzers.documentation import DocumentationAnalyzer
            self.analyzers.append(DocumentationAnalyzer())
    
    def scan(self, specific_repos: Optional[List[int]] = None) -> None:
        """
        Scan repositories for technologies and analyze connections.
        
        Args:
            specific_repos: Optional list of specific repository IDs to scan
        """
        # Get the group
        try:
            group = self.gitlab.groups.get(self.group_id)
            print(f"\nScanning group: {group.name}")
        except GitlabGetError as e:
            print(f"Error accessing group: {str(e)}")
            return
        
        # Get projects
        try:
            projects = group.projects.list(all=True, include_subgroups=True)
            if specific_repos:
                projects = [p for p in projects if p.id in specific_repos]
            
            print(f"Found {len(projects)} projects to scan\n")
        except GitlabGetError as e:
            print(f"Error getting projects: {str(e)}")
            return
        
        # Determine concurrency
        max_workers = min(self.config.get('scanning', 'concurrent_scans', 5), len(projects))
        timeout_seconds = self.config.get('scanning', 'timeout_seconds', 30)
        
        # Prepare progress tracking
        total_projects = len(projects)
        completed = 0
        
        # Scan projects concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all projects for scanning
            future_to_project = {
                executor.submit(self._scan_project, project, timeout_seconds): project 
                for project in projects
            }
            
            # Process completed scans
            for future in concurrent.futures.as_completed(future_to_project):
                project = future_to_project[future]
                completed += 1
                
                try:
                    repo = future.result()
                    if repo:
                        self.repositories.append(repo)
                        print(f"[{completed}/{total_projects}] ✓ Scanned: {repo.name}")
                    else:
                        print(f"[{completed}/{total_projects}] ⚠ Failed to scan: {project.name}")
                except Exception as e:
                    print(f"[{completed}/{total_projects}] ⚠ Error scanning {project.name}: {str(e)}")
        
        # Run cross-repository analyzers
        self._run_cross_repo_analysis()
        
        print(f"\nScan completed! Analyzed {len(self.repositories)} repositories.")
    
    @timeout(30)  # Default timeout, will be overridden
    def _scan_project(self, project, timeout_seconds: int) -> Optional[Repository]:
        """
        Scan a single project for technologies.
        
        Args:
            project: GitLab project object
            timeout_seconds: Maximum scan time in seconds
            
        Returns:
            Repository object with scan results or None if failed
        """
        try:
            # Get full project
            full_project = self.gitlab.projects.get(project.id)
            
            # Create repository object
            repo = Repository(full_project)
            
            # Scan files in repository
            self._scan_repository_files(repo)
            
            # Mark as scanned
            repo.scanned = True
            
            return repo
            
        except GitlabGetError as e:
            if '404' not in str(e):
                print(f"Warning: Could not access project {project.name}: {str(e)}")
            return None
        except TimeoutError:
            print(f"Timeout: Scanning {project.name} took too long (>{timeout_seconds} seconds)")
            return None
        except Exception as e:
            print(f"Error processing project {project.name}: {str(e)}")
            return None
    
    def _scan_repository_files(self, repo: Repository) -> None:
        """
        Scan files in a repository to detect technologies.
        
        Args:
            repo: Repository object to update with findings
        """
        try:
            # Get default branch
            default_branch = repo.default_branch
            
            # Get repository file tree
            tree = repo.project.repository_tree(recursive=True, ref=default_branch, all=True)
            
            # Update repository stats
            repo.stats['total_files'] = len(tree)
            
            # Get file extensions for detection
            file_extensions = self.config.get('scanning', 'file_extensions', 
                                             ['.py', '.js', '.java', '.yml', '.yaml'])
            
            # Scan each relevant file
            for item in tree:
                path = item['path']
                
                # Skip files that don't match our extensions
                if not any(path.endswith(ext) for ext in file_extensions):
                    continue
                
                # Get file content
                try:
                    file_content = repo.project.files.get(file_path=path, ref=default_branch)
                    content = clean_content(file_content.decode())
                    
                    # Process file with detectors
                    self._process_file(repo, path, content)
                    
                    # Track analyzed files
                    repo.analyzed_files.append(path)
                    repo.stats['analyzed_files'] += 1
                    
                except (GitlabGetError, Exception) as e:
                    # Skip files we can't access
                    continue
        
        except Exception as e:
            print(f"Error scanning repository {repo.name}: {str(e)}")
    
    def _process_file(self, repo: Repository, file_path: str, content: str) -> None:
        """
        Process a file with all active detectors.
        
        Args:
            repo: Repository to update
            file_path: Path to the file
            content: File content
        """
        for detector in self.detectors:
            detector.detect(repo, content, file_path)
    
    def _run_cross_repo_analysis(self) -> None:
        """Run analyzers that work across repositories."""
        if not self.repositories:
            return
            
        print("\nAnalyzing connections between repositories...")
        
        for analyzer in self.analyzers:
            analyzer.analyze(self.repositories)
    
    def generate_report(self, output_file: str = "gitlab_analysis_report.json") -> None:
        """
        Generate a report of findings.
        
        Args:
            output_file: Path to save the report
        """
        from ..reporting.summary import generate_summary
        from ..reporting.exporters import export_report
        
        # Generate summary data
        summary = generate_summary(self.repositories)
        
        # Export in specified format
        format = self.config.get('reporting', 'format', 'json')
        export_report(summary, output_file, format)
