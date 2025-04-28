"""
Utility functions for GitLab Repository Analyzer.
Includes timeout mechanism, file processing, and other helpers.
"""

import os
import re
import signal
import threading
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Tuple, Optional, Set, Union


class TimeoutError(Exception):
    """Exception raised when an operation times out."""
    pass


def timeout(seconds: int):
    """
    Decorator to add timeout to functions.
    Uses threading which is more portable than SIGALRM.
    
    Args:
        seconds: Maximum execution time in seconds
        
    Returns:
        Function result or raises TimeoutError
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = [None]
            error = [None]
            
            def worker() -> None:
                try:
                    result[0] = func(*args, **kwargs)
                except Exception as e:
                    error[0] = e
            
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            thread.join(seconds)
            
            if thread.is_alive():
                raise TimeoutError(f"Operation timed out after {seconds} seconds")
            
            if error[0] is not None:
                raise error[0]
                
            return result[0]
        return wrapper
    return decorator


def get_file_extension(file_path: str) -> str:
    """Get the file extension from a path."""
    _, ext = os.path.splitext(file_path)
    return ext.lower()


def is_binary_file(file_path: str) -> bool:
    """Check if a file is likely binary based on extension."""
    binary_extensions = {
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.pdf', 
        '.zip', '.tar', '.gz', '.tgz', '.rar', '.7z', '.exe', 
        '.dll', '.so', '.dylib', '.class', '.jar', '.war'
    }
    return get_file_extension(file_path) in binary_extensions


def clean_content(content: Union[str, bytes]) -> str:
    """Clean and decode file content."""
    if isinstance(content, bytes):
        try:
            return content.decode('utf-8', errors='ignore')
        except:
            return ""
    return content


def extract_version_from_string(text: str, package_name: str) -> Optional[str]:
    """
    Extract version information for a package from text.
    Supports multiple formats like:
    - "package": "1.2.3"
    - package==1.2.3
    - package >= 1.2.3
    """
    # Try JSON/package.json style
    json_pattern = rf'["\']({re.escape(package_name)})["\']\\s*:\\s*["\']([\\^~><=]?[\\d\\.]+)["\']'
    match = re.search(json_pattern, text)
    if match:
        return match.group(2)
    
    # Try requirements.txt style
    req_pattern = rf'{re.escape(package_name)}([=~><]+)([\\d\\.]+)'
    match = re.search(req_pattern, text)
    if match:
        return match.group(2)
    
    return None


def find_pattern_in_content(content: str, patterns: List[str], case_sensitive: bool = False) -> bool:
    """Check if any of the patterns exist in content."""
    if not case_sensitive:
        content = content.lower()
        patterns = [p.lower() for p in patterns]
    
    return any(pattern in content for pattern in patterns)


def find_regex_in_content(content: str, patterns: List[str]) -> List[str]:
    """Find all matches of regex patterns in content."""
    results = []
    for pattern in patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            if match.group(0):
                results.append(match.group(0))
    return results


def chunked_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split a list into chunks of specified size."""
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]


def create_path_if_not_exists(path: str) -> None:
    """Create directory path if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary with dot notation for keys."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
