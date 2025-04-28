"""
Configuration management for GitLab Repository Analyzer.
Handles loading/saving config from file and provides access to config values.
"""

import os
import json
from typing import Dict, Any, Optional


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
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration, optionally loading from file."""
        self.config = self.DEFAULT_CONFIG.copy()
        self.config_file = config_file
        
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file: str) -> None:
        """Load configuration from file."""
        try:
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
                # Merge the loaded config with defaults
                self._merge_config(self.config, loaded_config)
            print(f"Configuration loaded from {config_file}")
        except Exception as e:
            print(f"Error loading config file: {str(e)}")
    
    def save_config(self, config_file: Optional[str] = None) -> None:
        """Save current configuration to file."""
        file_to_save = config_file or self.config_file or "config.json"
        
        try:
            with open(file_to_save, 'w') as f:
                json.dump(self.config, f, indent=2)
            print(f"Configuration saved to {file_to_save}")
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
    
    def get(self, section: Optional[str] = None, key: Optional[str] = None, default: Any = None) -> Any:
        """Get configuration value."""
        if section is None:
            return self.config
        
        if key is None:
            return self.config.get(section, {})
        
        return self.config.get(section, {}).get(key, default)
    
    def set(self, section: str, key: Optional[str] = None, value: Any = None) -> None:
        """Set configuration value."""
        if key is None:
            if isinstance(value, dict):
                self.config[section] = value
        else:
            if section not in self.config:
                self.config[section] = {}
            self.config[section][key] = value
    
    def add_custom_pattern(self, name: str, file_pattern: str, content_pattern: str, category: str) -> None:
        """Add a custom detection pattern."""
        pattern = {
            'name': name,
            'file_pattern': file_pattern,
            'content_pattern': content_pattern,
            'category': category
        }
        
        if 'custom_patterns' not in self.config['detectors']:
            self.config['detectors']['custom_patterns'] = []
        
        self.config['detectors']['custom_patterns'].append(pattern)
