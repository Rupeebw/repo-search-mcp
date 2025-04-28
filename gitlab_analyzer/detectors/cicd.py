import os
import yaml
import json
import logging
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

class CICDDetector:
    """
    Class for detecting CI/CD configurations and pipelines in GitLab repositories.
    """
    
    def __init__(self):
        self.ci_config_files = ['.gitlab-ci.yml', '.github/workflows']
        self.pipeline_data = {}
        
    def detect_ci_configurations(self, repo_path: str) -> Dict[str, Any]:
        """
        Detect CI/CD configurations in the repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dictionary containing CI/CD configuration details
        """
        result = {
            'has_ci_config': False,
            'ci_type': None,
            'config_files': [],
            'pipelines': [],
            'stages': [],
            'jobs': []
        }
        
        # Check for GitLab CI configuration
        gitlab_ci_path = os.path.join(repo_path, '.gitlab-ci.yml')
        if os.path.exists(gitlab_ci_path):
            result['has_ci_config'] = True
            result['ci_type'] = 'GitLab CI'
            result['config_files'].append(gitlab_ci_path)
            
            # Parse GitLab CI configuration
            try:
                with open(gitlab_ci_path, 'r') as f:
                    ci_config = yaml.safe_load(f)
                
                if ci_config:
                    # Extract pipeline stages if defined
                    if 'stages' in ci_config:
                        result['stages'] = ci_config['stages']
                    
                    # Extract jobs
                    jobs = []
                    for key, value in ci_config.items():
                        if isinstance(value, dict) and 'stage' in value:
                            jobs.append({
                                'name': key,
                                'stage': value.get('stage'),
                                'script': value.get('script', []),
                                'tags': value.get('tags', [])
                            })
                    result['jobs'] = jobs
            except Exception as e:
                logger.error(f"Error parsing GitLab CI configuration: {e}")
        
        # Check for GitHub Actions
        github_actions_dir = os.path.join(repo_path, '.github', 'workflows')
        if os.path.exists(github_actions_dir):
            result['has_ci_config'] = True
            result['ci_type'] = 'GitHub Actions' if not result['ci_type'] else f"{result['ci_type']}, GitHub Actions"
            
            # Find all workflow files
            workflow_files = []
            for file in os.listdir(github_actions_dir):
                if file.endswith(('.yml', '.yaml')):
                    workflow_path = os.path.join(github_actions_dir, file)
                    result['config_files'].append(workflow_path)
                    workflow_files.append(workflow_path)
            
            # Parse GitHub Actions workflows
            workflows = []
            for workflow_path in workflow_files:
                try:
                    with open(workflow_path, 'r') as f:
                        workflow = yaml.safe_load(f)
                    
                    if workflow and 'jobs' in workflow:
                        workflows.append({
                            'name': os.path.basename(workflow_path),
                            'jobs': list(workflow['jobs'].keys()),
                            'triggers': workflow.get('on', {})
                        })
                except Exception as e:
                    logger.error(f"Error parsing GitHub Actions workflow: {e}")
            
            result['pipelines'] = workflows
                    
        # Check for Jenkins configuration
        jenkins_file = os.path.join(repo_path, 'Jenkinsfile')
        if os.path.exists(jenkins_file):
            result['has_ci_config'] = True
            result['ci_type'] = 'Jenkins' if not result['ci_type'] else f"{result['ci_type']}, Jenkins"
            result['config_files'].append(jenkins_file)
            
        return result
    
    def analyze_pipeline_complexity(self, ci_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the complexity of the CI/CD pipeline.
        
        Args:
            ci_config: CI/CD configuration data
            
        Returns:
            Dictionary with pipeline complexity metrics
        """
        complexity = {
            'num_stages': len(ci_config.get('stages', [])),
            'num_jobs': len(ci_config.get('jobs', [])),
            'complexity_score': 0,
            'has_deployment': False,
            'has_testing': False,
            'has_security_scanning': False
        }
        
        # Analyze jobs for specific patterns
        jobs = ci_config.get('jobs', [])
        for job in jobs:
            script_text = ' '.join(job.get('script', [])).lower()
            
            # Check for deployment indicators
            if any(term in script_text for term in ['deploy', 'kubernetes', 'k8s', 'helm', 'production', 'staging']):
                complexity['has_deployment'] = True
                
            # Check for testing indicators
            if any(term in script_text for term in ['test', 'pytest', 'unittest', 'jest', 'rspec']):
                complexity['has_testing'] = True
                
            # Check for security scanning
            if any(term in script_text for term in ['sonarqube', 'security', 'scan', 'sast', 'dast', 'dependency-check']):
                complexity['has_security_scanning'] = True
        
        # Calculate complexity score (simple heuristic)
        complexity['complexity_score'] = (
            complexity['num_stages'] * 2 + 
            complexity['num_jobs'] + 
            (5 if complexity['has_deployment'] else 0) +
            (3 if complexity['has_testing'] else 0) +
            (4 if complexity['has_security_scanning'] else 0)
        )
        
        return complexity
    
    def get_pipeline_summary(self, repo_path: str) -> Dict[str, Any]:
        """
        Get a summary of CI/CD pipeline configurations in the repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dictionary with pipeline summary
        """
        ci_config = self.detect_ci_configurations(repo_path)
        if ci_config['has_ci_config']:
            complexity = self.analyze_pipeline_complexity(ci_config)
            return {
                'has_ci_cd': True,
                'ci_type': ci_config['ci_type'],
                'num_config_files': len(ci_config['config_files']),
                'stages': ci_config.get('stages', []),
                'num_jobs': len(ci_config.get('jobs', [])),
                'complexity_score': complexity['complexity_score'],
                'has_deployment': complexity['has_deployment'],
                'has_testing': complexity['has_testing'],
                'has_security_scanning': complexity['has_security_scanning']
            }
        else:
            return {
                'has_ci_cd': False
            }
