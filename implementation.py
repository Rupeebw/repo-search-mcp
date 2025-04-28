"""
GitLab Repository Analyzer
A comprehensive tool for detecting technologies, analyzing connections,
and mapping relationships across GitLab repositories.
"""

import os
import sys
import json
import time
import signal
import threading
import re
import yaml
from typing import List, Dict, Any, Tuple, Optional, Set
import gitlab
from gitlab.exceptions import GitlabGetError
from functools import wraps

#########################
# CONFIG MANAGEMENT
#########################

class Config:
    """Configuration management for the GitLab analyzer."""
    
    DEFAULT_CONFIG = {
        'gitlab': {
            'url': 'https://gitlab.com',
            'timeout': 30
        },
        'scanning': {
            'concurrent_scans': 5,
            'timeout_seconds': 30,
            'file_extensions': ['.py', '.js', '.java', '.go', '.rb', '.php', '.ts', '.jsx', '.tsx', 
                               '.yml', '.yaml', '.json', '.tf', '.md', '.html', '.css', '.scss']
        },
        'detectors': {
            'frontend': True,
            'backend': True,
            'database': True,
            'infrastructure': True,
            'cicd': True,
            'custom_patterns': []
        },
        'analyzers': {
            'connections': True,
            'dependencies': True,
            'documentation': True
        },
        'reporting': {
            'format': 'json',
            'verbosity': 'normal'
        }
    }
    
    def __init__(self, config_file: str = None):
        """Initialize configuration, optionally loading from file."""
        self.config = self.DEFAULT_CONFIG.copy()
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file: str) -> None:
        """Load configuration from file."""
        try:
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
                # Merge the loaded config with defaults
                self._merge_config(self.config, loaded_config)
        except Exception as e:
            print(f"Error loading config file: {str(e)}")
    
    def save_config(self, config_file: str) -> None:
        """Save current configuration to file."""
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"Configuration saved to {config_file}")
        except Exception as e:
            print(f"Error saving config file: {str(e)}")
    
    def _merge_config(self, base: Dict, update: Dict) -> Dict:
        """Recursively merge configuration dictionaries."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
        return base
    
    def get(self, section: str = None, key: str = None, default: Any = None) -> Any:
        """Get configuration value."""
        if section is None:
            return self.config
        
        if key is None:
            return self.config.get(section, {})
        
        return self.config.get(section, {}).get(key, default