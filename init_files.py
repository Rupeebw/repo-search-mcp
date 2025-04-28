# Main package __init__.py
# gitlab_repo_analyzer/__init__.py

"""
GitLab Repository Analyzer

A tool for analyzing GitLab repositories, including code structure,
dependencies, CI/CD configurations, and security practices.
"""

__version__ = '0.1.0'
__author__ = 'Your Name'
__email__ = 'your.email@example.com'

from .repo_analyzer import RepoAnalyzer
from .code_analyzer import CodeAnalyzer
from .dependency_analyzer import DependencyAnalyzer
from .ci_cd_detector import CICDDetector
from .security_analyzer import SecurityAnalyzer


# Submodule __init__.py files:

# gitlab_repo_analyzer/utils/__init__.py
"""
Utility functions for GitLab Repository Analyzer.
"""

from .file_utils import find_files_by_extension, count_lines_in_file
from .git_utils import get_commit_history, get_branch_info


# gitlab_repo_analyzer/exporters/__init__.py
"""
Exporters for GitLab Repository Analyzer results.
"""

from .json_exporter import export_as_json
from .csv_exporter import export_as_csv
from .html_exporter import export_as_html
from .report_generator import generate_report


# gitlab_repo_analyzer/utils/file_utils.py
"""
File utilities for GitLab Repository Analyzer.
"""

import os
from typing import List, Dict, Any, Optional


def find_files_by_extension(root_dir: str, extension: str) -> List[str]:
    """
    Find all files with a specific extension in a directory.
    
    Args:
        root_dir: The root directory to search
        extension: File extension to look for (e.g., '.py')
        
    Returns:
        List of file paths matching the extension
    """
    matching_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(extension):
                matching_files.append(os.path.join(root, file))
    return matching_files


def count_lines_in_file(file_path: str, 
                      ignore_empty: bool = True, 
                      ignore_comments: bool = True) -> int:
    """
    Count the number of lines in a file.
    
    Args:
        file_path: Path to the file
        ignore_empty: Whether to ignore empty lines
        ignore_comments: Whether to ignore comment lines
        
    Returns:
        Number of lines in the file
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            
        if ignore_empty:
            lines = [line for line in lines if line.strip()]
            
        if ignore_comments and file_path.endswith(('.py', '.js', '.java')):
            # Simple comment detection - this could be improved
            if file_path.endswith('.py'):
                lines = [line for line in lines if not line.strip().startswith('#')]
            elif file_path.endswith(('.js', '.java')):
                lines = [line for line in lines if not line.strip().startswith('//')]
                
        return len(lines)
    except Exception as e:
        print(f"Error counting lines in {file_path}: {e}")
        return 0


# gitlab_repo_analyzer/utils/git_utils.py
"""
Git utilities for GitLab Repository Analyzer.
"""

import os
import subprocess
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


def get_commit_history(repo_path: str, max_count: int = 100) -> List[Dict[str, Any]]:
    """
    Get the commit history for a Git repository.
    
    Args:
        repo_path: Path to the repository
        max_count: Maximum number of commits to retrieve
        
    Returns:
        List of dictionaries containing commit information
    """
    commits = []
    try:
        # Format: hash, author name, author email, date, subject
        format_str = "--pretty=format:%H,%an,%ae,%ad,%s"
        
        command = [
            "git", "-C", repo_path, "log", 
            format_str, 
            f"-n{max_count}", 
            "--date=iso"
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        for line in result.stdout.strip().split('\n'):
            if line:
                parts = line.split(',', 4)
                if len(parts) == 5:
                    commits.append({
                        'hash': parts[0],
                        'author': parts[1],
                        'email': parts[2],
                        'date': parts[3],
                        'message': parts[4]
                    })
    except subprocess.SubprocessError as e:
        logger.error(f"Error getting commit history: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in get_commit_history: {e}")
        
    return commits


def get_branch_info(repo_path: str) -> Dict[str, Any]:
    """
    Get branch information for a Git repository.
    
    Args:
        repo_path: Path to the repository
        
    Returns:
        Dictionary with branch information
    """
    branch_info = {
        'current_branch': None,
        'all_branches': [],
        'remote_branches': []
    }
    
    try:
        # Get current branch
        command = ["git", "-C", repo_path, "rev-parse", "--abbrev-ref", "HEAD"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        branch_info['current_branch'] = result.stdout.strip()
        
        # Get all local branches
        command = ["git", "-C", repo_path, "branch", "--list"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        branches = [b.strip().replace('* ', '') for b in result.stdout.split('\n') if b.strip()]
        branch_info['all_branches'] = branches
        
        # Get remote branches
        command = ["git", "-C", repo_path, "branch", "-r"]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        remote_branches = [b.strip() for b in result.stdout.split('\n') if b.strip()]
        branch_info['remote_branches'] = remote_branches
        
    except subprocess.SubprocessError as e:
        logger.error(f"Error getting branch information: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in get_branch_info: {e}")
        
    return branch_info
