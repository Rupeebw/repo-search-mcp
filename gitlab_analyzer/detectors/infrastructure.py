"""
Infrastructure technology detector for GitLab Repository Analyzer.
Detects infrastructure-as-code, cloud resources, and deployment configurations.
"""

import json
import re
import yaml
from typing import Dict, List, Any, Optional

from .base_detector import BaseDetector
from ..core.repository import Repository
from ..core.utils import find_pattern_in_content


class InfrastructureDetector(BaseDetector):
    """Detector for infrastructure technologies."""
    
    def __init__(self):
        """Initialize infrastructure detector."""
        super().__init__(name="Infrastructure", category="infrastructure")
        
        # File patterns to match
        self.file_patterns = [
            # Infrastructure as Code
            "*.tf", "*.tfvars", "*.hcl", "terraform.tfstate*",
            "*.cf.json", "*.cf.yaml", "*.cf.yml", "cloudformation/*",
            "*.cdk.ts", "*.cdk.js", "cdk.json",
            "pulumi.yaml", "Pulumi.yaml", "*.pulumi.ts", "*.pulumi.js",
            "serverless.yml", "serverless.yaml", "serverless.json",
            "sam-template.yaml", "sam-template.yml", "template.yaml",
            "*.bicep",
            
            # Kubernetes and container orchestration
            "*.k8s.yaml", "*.k8s.yml", "kubernetes/*.yaml", "kubernetes/*.yml",
            "kustomization.yaml", "kustomization.yml", "kustomize/*",
            "helm/*.yaml", "helm/*.yml", "Chart.yaml", "values.yaml",
            "docker-compose.yml", "docker-compose.yaml", "docker-compose.override.yml",
            "Dockerfile*", ".dockerignore", "docker/*",
            
            # Cloud provider specific
            ".aws/*", "aws-config.json", "aws/*", "aws-sam/*",
            ".gcp/*", "gcp-config.json", "gcp/*", "app.yaml", "app.yml",
            ".azure/*", "azure-config.json", "azure/*", "azure-pipelines.yml",
            ".do/*", "do-config.json",
            
            # Networking and service mesh
            "istio/*.yaml", "istio/*.yml",
            "envoy.yaml", "envoy.yml",
            "consul/*.hcl", "consul/*.json",
            "traefik.yaml", "traefik.yml", "traefik.toml",
            "nginx.conf", "nginx/*.conf",
            "haproxy.cfg",
            
            # Provisioning and configuration management
            "*.pp", "manifests/*.pp", "Puppetfile",
            "*.yml", "*.yaml", "playbook.yml", "playbook.yaml", "roles/*",
            "*.chef", "chef/*", "Berksfile", "Policyfile.rb",
            "Vagrantfile", "vagrant/*",
            "salt/*", "pillar/*", "*.sls",
            
            # Monitoring and observability
            "prometheus.yml", "prometheus.yaml", "alertmanager.yml", "alertmanager.yaml",
            "grafana/*.json", "grafana/dashboards/*",
            "datadog.yaml", "datadog.yml",
            "fluentd.conf", "fluent.conf", "logstash.conf",
            
            # Security
            "*.pem", "*.crt", "*.key", "*.ca", "*.cert",
            "vault.yaml", "vault.yml", "*.vault.yml",
            "keycloak/*", "*.jwk", "*.jks",
            
            # Infrastructure deployment scripts
            "deploy.sh", "deploy/*", "infra/*", "infrastructure/*"
        ]
        
        # Simple content patterns for quick detection
        self.content_patterns = {
            # IaC tools
            "Terraform": ["provider", "resource", "module", "terraform {", "variable", "output"],
            "CloudFormation": ["AWSTemplateFormatVersion", "Resources:", "Outputs:", "aws::"],
            "AWS CDK": ["import * as cdk", "new cdk.", "cdk.Stack", "cdk.Construct"],
            "Pulumi": ["import * as pulumi", "new aws.", "new gcp.", "new azure.", "stack.export"],
            "Serverless Framework": ["service:", "provider:", "functions:", "serverless"],
            "AWS SAM": ["AWSTemplateFormatVersion", "Transform: AWS::Serverless", "AWS::Serverless::"],
            "Azure Bicep": ["param ", "resource ", "module ", "output "],
            
            # Container technologies
            "Docker": ["FROM ", "RUN ", "CMD ", "ENTRYPOINT ", "COPY ", "ADD ", "ENV ", "EXPOSE "],
            "Docker Compose": ["version:", "services:", "volumes:", "networks:", "build:", "image:"],
            "Kubernetes": ["apiVersion:", "kind:", "metadata:", "spec:", "Deployment", "Service", "ConfigMap"],
            "Helm": ["apiVersion: v2", "name:", "version:", "dependencies:", "Chart.yaml"],
            "Kustomize": ["apiVersion: kustomize", "kind: Kustomization", "resources:", "patches:"],
            
            # Cloud provider specific
            "AWS": ["aws_", "AWS::", "amazon", ".amazonaws.com", "AWS_", "Amazon"],
            "Google Cloud": ["google_", "gcp_", "GCP", "Google Cloud", "gcloud", ".googleapis.com"],
            "Azure": ["azurerm_", "Azure::", "AzureRM", "Microsoft.Azure", "azure-"],
            "DigitalOcean": ["digitalocean_", "DigitalOcean", "do_", "doctl"],
            "Heroku": ["heroku", "Heroku", "Procfile", "app.json"],
            
            # Networking and service mesh
            "Istio": ["istio", "VirtualService", "DestinationRule", "Gateway", "ServiceEntry"],
            "Envoy": ["envoy", "listener", "cluster", "filter_chains", "http_filters"],
            "Consul": ["consul", "service", "connect", "sidecar_service", "intentions"],
            "Traefik": ["traefik", "entryPoints", "middlewares", "routers", "services"],
            "NGINX": ["server", "location", "proxy_pass", "upstream", "http {", "events {"],
            "HAProxy": ["frontend", "backend", "listen", "balance", "option httpchk"],
            
            # Provisioning and configuration management
            "Puppet": ["class", "define", "include", "require", "notify", "package", "service", "file"],
            "Ansible": ["hosts:", "tasks:", "vars:", "roles:", "become:", "with_items:", "name:"],
            "Chef": ["cookbook", "recipe", "attribute", "resource", "cookbook_file", "chef_gem"],
            "Vagrant": ["config.vm", "Vagrant.configure", "config.vm.box", "provider"],
            "Salt": ["salt", "pillar", "grain", "state.", "pkg.installed", "service.running"],
            
            # Monitoring and observability
            "Prometheus": ["prometheus", "scrape_configs", "alerting", "rule_files", "job_name"],
            "Grafana": ["grafana", "dashboard", "panel", "datasource", "visualization"],
            "Datadog": ["datadog", "monitors", "metrics", "logs", "apm", "synthetics"],
            "Fluentd": ["fluentd", "fluent", "source", "match", "filter", "log_level"],
            "Elastic Stack": ["elasticsearch", "logstash", "kibana", "beats", "index", "template"],
            
            # Security
            "Vault": ["vault", "secret", "auth", "policy", "token", "certificate"],
            "Keycloak": ["keycloak", "realm", "client", "user", "role", "authentication"],
            "Let's Encrypt": ["letsencrypt", "certbot", "acme", "certificate", "renewal"]
        }
        
        # Regex patterns for more complex matching
        self.regex_patterns = {
            "AWS Region": [r'region\s*[=:]\s*[\'"]([a-z]{2}-[a-z]+-\d)[\'"]'],
            "AWS Resource": [r'resource\s+[\'"]aws_([a-z_]+)[\'"]', r'AWS::([A-Za-z:]+)::'],
            "GCP Resource": [r'resource\s+[\'"]google_([a-z_]+)[\'"]'],
            "Azure Resource": [r'resource\s+[\'"]azurerm_([a-z_]+)[\'"]', r'resource\s+([A-Za-z]+)\s+[\'"]'],
            "IP Address": [r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'],
            "URL Pattern": [r'https?://[a-zA-Z0-9\.\-/]+']
        }
    
    def _detect_specialized(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Specialized detection for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Terraform files
        if file_path.endswith('.tf') or file_path.endswith('.tfvars') or file_path.endswith('.hcl'):
            self._analyze_terraform_file(repository, content, file_path)
        
        # Detect CloudFormation templates
        elif file_path.endswith('.cf.json') or file_path.endswith('.cf.yaml') or file_path.endswith('.cf.yml'):
            self._analyze_cloudformation_file(repository, content, file_path)
        
        # Detect AWS SAM templates
        elif 'sam-template' in file_path or 'template.yaml' in file_path or 'template.yml' in file_path:
            self._analyze_sam_file(repository, content, file_path)
        
        # Detect Kubernetes manifests
        elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
            self._analyze_yaml_file(repository, content, file_path)
        
        # Detect Dockerfiles
        elif 'Dockerfile' in file_path:
            self._analyze_dockerfile(repository, content, file_path)
        
        # Detect Docker Compose files
        elif 'docker-compose' in file_path:
            self._analyze_docker_compose(repository, content, file_path)
        
        # Detect Ansible files
        elif '/roles/' in file_path or 'playbook' in file_path:
            self._analyze_ansible_file(repository, content, file_path)
        
        # Detect Puppet files
        elif file_path.endswith('.pp'):
            self._analyze_puppet_file(repository, content, file_path)
    
    def _analyze_terraform_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Terraform files for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Terraform
        repository.add_technology(
            category='infrastructure',
            name='Terraform',
            path=file_path,
            confidence=1.0
        )
        
        # Detect cloud providers
        if 'provider "aws"' in content or 'aws_' in content:
            repository.add_technology(
                category='infrastructure',
                name='AWS',
                path=file_path
            )
            
            # Detect AWS services
            self._detect_aws_services(repository, content, file_path)
        
        if 'provider "google"' in content or 'google_' in content:
            repository.add_technology(
                category='infrastructure',
                name='Google Cloud',
                path=file_path
            )
            
            # Detect GCP services
            self._detect_gcp_services(repository, content, file_path)
        
        if 'provider "azurerm"' in content or 'azurerm_' in content:
            repository.add_technology(
                category='infrastructure',
                name='Azure',
                path=file_path
            )
            
            # Detect Azure services
            self._detect_azure_services(repository, content, file_path)
        
        if 'provider "kubernetes"' in content or 'kubernetes_' in content:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes',
                path=file_path
            )
        
        if 'provider "helm"' in content or 'helm_' in content:
            repository.add_technology(
                category='infrastructure',
                name='Helm',
                path=file_path
            )
        
        if 'provider "docker"' in content or 'docker_' in content:
            repository.add_technology(
                category='infrastructure',
                name='Docker',
                path=file_path
            )
        
        if 'provider "digitalocean"' in content or 'digitalocean_' in content:
            repository.add_technology(
                category='infrastructure',
                name='DigitalOcean',
                path=file_path
            )
        
        # Check for specific Terraform patterns
        if 'module "' in content:
            repository.add_technology(
                category='infrastructure',
                name='Terraform Modules',
                path=file_path
            )
        
        if 'resource "aws_lambda_function"' in content or 'resource "google_cloudfunctions_function"' in content:
            repository.add_technology(
                category='infrastructure',
                name='Serverless',
                path=file_path
            )
    
    def _analyze_cloudformation_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze CloudFormation templates for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect CloudFormation
        repository.add_technology(
            category='infrastructure',
            name='CloudFormation',
            path=file_path,
            confidence=1.0
        )
        
        # Always mark as AWS
        repository.add_technology(
            category='infrastructure',
            name='AWS',
            path=file_path
        )
        
        # Try to parse as JSON or YAML
        try:
            if file_path.endswith('.json'):
                template = json.loads(content)
            else:
                template = yaml.safe_load(content)
                
            # Check for resources
            if isinstance(template, dict) and 'Resources' in template:
                resources = template['Resources']
                
                for resource_id, resource in resources.items():
                    if 'Type' in resource:
                        resource_type = resource['Type']
                        
                        # Check for specific AWS services
                        if 'AWS::Lambda::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='AWS Lambda',
                                path=file_path
                            )
                            
                            repository.add_technology(
                                category='infrastructure',
                                name='Serverless',
                                path=file_path
                            )
                        
                        elif 'AWS::EC2::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='Amazon EC2',
                                path=file_path
                            )
                        
                        elif 'AWS::S3::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='Amazon S3',
                                path=file_path
                            )
                        
                        elif 'AWS::DynamoDB::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='Amazon DynamoDB',
                                path=file_path
                            )
                        
                        elif 'AWS::RDS::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='Amazon RDS',
                                path=file_path
                            )
                        
                        elif 'AWS::ECS::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='Amazon ECS',
                                path=file_path
                            )
                        
                        elif 'AWS::EKS::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='Amazon EKS',
                                path=file_path
                            )
                            
                            repository.add_technology(
                                category='infrastructure',
                                name='Kubernetes',
                                path=file_path
                            )
                        
                        elif 'AWS::ApiGateway::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='Amazon API Gateway',
                                path=file_path
                            )
                        
                        elif 'AWS::IAM::' in resource_type:
                            repository.add_technology(
                                category='infrastructure',
                                name='AWS IAM',
                                path=file_path
                            )
        except (json.JSONDecodeError, yaml.YAMLError):
            # If parsing fails, fall back to basic pattern detection
            self._detect_aws_services(repository, content, file_path)
    
    def _analyze_sam_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze AWS SAM templates for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect AWS SAM
        repository.add_technology(
            category='infrastructure',
            name='AWS SAM',
            path=file_path,
            confidence=1.0
        )
        
        # Always mark as AWS and Serverless
        repository.add_technology(
            category='infrastructure',
            name='AWS',
            path=file_path
        )
        
        repository.add_technology(
            category='infrastructure',
            name='Serverless',
            path=file_path
        )
        
        repository.add_technology(
            category='infrastructure',
            name='AWS Lambda',
            path=file_path
        )
        
        # Try to parse the YAML
        try:
            template = yaml.safe_load(content)
            
            # Check for API Gateway
            if 'AWS::Serverless::Api' in str(template):
                repository.add_technology(
                    category='infrastructure',
                    name='Amazon API Gateway',
                    path=file_path
                )
            
            # Check for DynamoDB
            if 'AWS::Serverless::SimpleTable' in str(template) or 'AWS::DynamoDB::Table' in str(template):
                repository.add_technology(
                    category='infrastructure',
                    name='Amazon DynamoDB',
                    path=file_path
                )
            
            # Check for S3
            if 'AWS::S3::' in str(template):
                repository.add_technology(
                    category='infrastructure',
                    name='Amazon S3',
                    path=file_path
                )
        except yaml.YAMLError:
            # Fall back to basic pattern detection
            if 'AWS::Serverless::Api' in content or 'AWS::ApiGateway::' in content:
                repository.add_technology(
                    category='infrastructure',
                    name='Amazon API Gateway',
                    path=file_path
                )
            
            if 'AWS::Serverless::SimpleTable' in content or 'AWS::DynamoDB::Table' in content:
                repository.add_technology(
                    category='infrastructure',
                    name='Amazon DynamoDB',
                    path=file_path
                )
            
            if 'AWS::S3::' in content:
                repository.add_technology(
                    category='infrastructure',
                    name='Amazon S3',
                    path=file_path
                )
    
    def _analyze_yaml_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze YAML files for Kubernetes and other infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Skip if not likely an infrastructure file
        if not any(keyword in content for keyword in ['apiVersion:', 'kind:', 'chart:', 'services:', 'stacks:']):
            return
        
        # Detect Kubernetes manifests
        if 'apiVersion:' in content and 'kind:' in content and 'metadata:' in content:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes',
                path=file_path
            )
            
            # Try to parse YAML
            try:
                manifest = yaml.safe_load(content)
                
                # Could be a list of resources
                if isinstance(manifest, list):
                    for item in manifest:
                        if isinstance(item, dict) and 'kind' in item:
                            self._detect_k8s_resource_type(repository, item.get('kind'), file_path)
                # Or a single resource
                elif isinstance(manifest, dict) and 'kind' in manifest:
                    self._detect_k8s_resource_type(repository, manifest.get('kind'), file_path)
            except yaml.YAMLError:
                # Fall back to pattern detection
                if 'kind: Deployment' in content or 'kind: StatefulSet' in content:
                    repository.add_technology(
                        category='infrastructure',
                        name='Kubernetes Workloads',
                        path=file_path
                    )
                
                if 'kind: Service' in content or 'kind: Ingress' in content:
                    repository.add_technology(
                        category='infrastructure',
                        name='Kubernetes Networking',
                        path=file_path
                    )
                
                if 'kind: ConfigMap' in content or 'kind: Secret' in content:
                    repository.add_technology(
                        category='infrastructure',
                        name='Kubernetes Configuration',
                        path=file_path
                    )
        
        # Detect Helm charts
        if ('Chart.yaml' in file_path or 'values.yaml' in file_path) and 'chart:' in content:
            repository.add_technology(
                category='infrastructure',
                name='Helm',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes',
                path=file_path
            )
        
        # Detect Docker Compose
        if 'docker-compose' in file_path or ('services:' in content and 'image:' in content):
            repository.add_technology(
                category='infrastructure',
                name='Docker Compose',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Docker',
                path=file_path
            )
        
        # Detect Serverless Framework
        if 'serverless.yml' in file_path or 'serverless.yaml' in file_path or 'service:' in content and 'provider:' in content and 'functions:' in content:
            repository.add_technology(
                category='infrastructure',
                name='Serverless Framework',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Serverless',
                path=file_path
            )
            
            # Try to determine the provider
            if 'provider:' in content and 'name:' in content:
                if 'aws' in content:
                    repository.add_technology(
                        category='infrastructure',
                        name='AWS',
                        path=file_path
                    )
                elif 'azure' in content:
                    repository.add_technology(
                        category='infrastructure',
                        name='Azure',
                        path=file_path
                    )
                elif 'google' in content:
                    repository.add_technology(
                        category='infrastructure',
                        name='Google Cloud',
                        path=file_path
                    )
        
        # Detect Ansible playbooks
        if ('playbook.yml' in file_path or 'playbook.yaml' in file_path or 
            'site.yml' in file_path or 'site.yaml' in file_path) and 'hosts:' in content:
            repository.add_technology(
                category='infrastructure',
                name='Ansible',
                path=file_path
            )
        
        # Detect Istio
        if ('istio' in file_path.lower() or 'VirtualService' in content or 
            'Gateway' in content or 'DestinationRule' in content):
            repository.add_technology(
                category='infrastructure',
                name='Istio',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Service Mesh',
                path=file_path
            )
        
        # Detect Prometheus
        if 'prometheus.yml' in file_path or 'prometheus.yaml' in file_path or 'scrape_configs:' in content:
            repository.add_technology(
                category='infrastructure',
                name='Prometheus',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Monitoring',
                path=file_path
            )
    
    def _analyze_dockerfile(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Dockerfile for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Docker
        repository.add_technology(
            category='infrastructure',
            name='Docker',
            path=file_path,
            confidence=1.0
        )
        
        # Check for base images to determine technologies
        base_images = {
            'node': 'Node.js',
            'python': 'Python',
            'golang': 'Go',
            'openjdk': 'Java',
            'php': 'PHP',
            'ruby': 'Ruby',
            'nginx': 'NGINX',
            'httpd': 'Apache HTTP Server',
            'postgres': 'PostgreSQL',
            'mysql': 'MySQL',
            'mongo': 'MongoDB',
            'redis': 'Redis',
            'ubuntu': 'Ubuntu',
            'debian': 'Debian',
            'alpine': 'Alpine Linux',
            'centos': 'CentOS',
            'amazonlinux': 'Amazon Linux'
        }
        
        # Look for FROM instructions
        from_matches = re.finditer(r'FROM\s+(\S+)(?::\S+)?', content)
        for match in from_matches:
            image_name = match.group(1).lower()
            
            for keyword, tech in base_images.items():
                if keyword in image_name:
                    repository.add_technology(
                        category='infrastructure',
                        name=tech,
                        path=file_path
                    )
        
        # Check for specific keywords indicating technologies
        if 'ENTRYPOINT ["java"' in content or 'CMD ["java"' in content:
            repository.add_technology(
                category='infrastructure',
                name='Java',
                path=file_path
            )
        
        if 'ENTRYPOINT ["python"' in content or 'CMD ["python"' in content:
            repository.add_technology(
                category='infrastructure',
                name='Python',
                path=file_path
            )
        
        if 'ENTRYPOINT ["node"' in content or 'CMD ["node"' in content:
            repository.add_technology(
                category='infrastructure',
                name='Node.js',
                path=file_path
            )
        
        # Check for multi-stage builds
        if content.count('FROM ') > 1:
            repository.add_technology(
                category='infrastructure',
                name='Docker Multi-Stage Build',
                path=file_path
            )
    
    def _analyze_docker_compose(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Docker Compose file for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Docker Compose
        repository.add_technology(
            category='infrastructure',
            name='Docker Compose',
            path=file_path,
            confidence=1.0
        )
        
        repository.add_technology(
            category='infrastructure',
            name='Docker',
            path=file_path
        )
        
        # Try to parse YAML
        try:
            compose = yaml.safe_load(content)
            
            if isinstance(compose, dict):
                # Check for services
                if 'services' in compose:
                    services = compose['services']
                    
                    for service_name, service in services.items():
                        if isinstance(service, dict):
                            # Check for service image
                            if 'image' in service:
                                image = service['image'].lower()
                                
                                # Detect common technologies from image names
                                self._detect_tech_from_image_name(repository, image, file_path)
                            
                            # Check for service ports
                            if 'ports' in service:
                                repository.add_technology(
                                    category='infrastructure',
                                    name='Container Networking',
                                    path=file_path
                                )
                            
                            # Check for volumes
                            if 'volumes' in service:
                                repository.add_technology(
                                    category='infrastructure',
                                    name='Container Storage',
                                    path=file_path
                                )
                            
                            # Check for environment variables
                            if 'environment' in service or 'env_file' in service:
                                repository.add_technology(
                                    category='infrastructure',
                                    name='Container Configuration',
                                    path=file_path
                                )
                
                # Check for Docker Compose version
                if 'version' in compose:
                    version = str(compose['version'])
                    
                    if version.startswith('3'):
                        repository.add_technology(
                            category='infrastructure',
                            name='Docker Compose v3',
                            path=file_path
                        )
                    elif version.startswith('2'):
                        repository.add_technology(
                            category='infrastructure',
                            name='Docker Compose v2',
                            path=file_path
                        )
                
                # Check for Docker Swarm mode features
                if 'deploy' in str(compose):
                    repository.add_technology(
                        category='infrastructure',
                        name='Docker Swarm',
                        path=file_path
                    )
                
                # Check for networks
                if 'networks' in compose:
                    repository.add_technology(
                        category='infrastructure',
                        name='Container Networking',
                        path=file_path
                    )
        except yaml.YAMLError:
            # Fall back to pattern detection
            if 'image:' in content:
                # Check for common services
                services = {
                    'postgres': 'PostgreSQL',
                    'mysql': 'MySQL',
                    'mongo': 'MongoDB',
                    'redis': 'Redis',
                    'elasticsearch': 'Elasticsearch',
                    'nginx': 'NGINX',
                    'traefik': 'Traefik',
                    'rabbitmq': 'RabbitMQ',
                    'kafka': 'Kafka'
                }
                
                for keyword, tech in services.items():
                    if keyword in content.lower():
                        repository.add_technology(
                            category='infrastructure',
                            name=tech,
                            path=file_path
                        )
    
    def _analyze_ansible_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Ansible files for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Ansible
        repository.add_technology(
            category='infrastructure',
            name='Ansible',
            path=file_path,
            confidence=1.0
        )
        
        # Check for specific modules
        ansible_modules = {
            'apt:': 'Debian/Ubuntu',
            'yum:': 'RHEL/CentOS',
            'dnf:': 'Fedora',
            'apk:': 'Alpine Linux',
            'docker_container:': 'Docker',
            'docker_image:': 'Docker',
            'docker_compose:': 'Docker Compose',
            'k8s:': 'Kubernetes',
            'kubectl:': 'Kubernetes',
            'ec2:': 'AWS',
            'ec2_instance:': 'AWS',
            's3:': 'AWS S3',
            'route53:': 'AWS Route53',
            'rds:': 'AWS RDS',
            'aws_s3:': 'AWS S3',
            'gcp_compute:': 'Google Cloud',
            'azure_rm_virtualmachine:': 'Azure',
            'jenkins_job:': 'Jenkins',
            'mysql_db:': 'MySQL',
            'postgresql_db:': 'PostgreSQL',
            'mongodb:': 'MongoDB',
            'nginx:': 'NGINX',
            'apache2:': 'Apache HTTP Server',
            'systemd:': 'Systemd',
            'service:': 'Linux Service',
            'terraform:': 'Terraform'
        }
        
        for module, tech in ansible_modules.items():
            if module in content:
                repository.add_technology(
                    category='infrastructure',
                    name=tech,
                    path=file_path
                )
    
    def _analyze_puppet_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Puppet files for infrastructure technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Puppet
        repository.add_technology(
            category='infrastructure',
            name='Puppet',
            path=file_path,
            confidence=1.0
        )
        
        # Check for specific resources and modules
        puppet_resources = {
            'package {': 'Package Management',
            'service {': 'Service Management',
            'file {': 'File Management',
            'user {': 'User Management',
            'group {': 'Group Management',
            'exec {': 'Command Execution',
            'cron {': 'Cron Job',
            'mount {': 'Filesystem Mount',
            'host {': 'Host Entry',
            'class {': 'Puppet Class'
        }
        
        puppet_modules = {
            'apache': 'Apache HTTP Server',
            'nginx': 'NGINX',
            'mysql': 'MySQL',
            'postgresql': 'PostgreSQL',
            'docker': 'Docker',
            'kubernetes': 'Kubernetes',
            'aws': 'AWS',
            'azure': 'Azure',
            'gcp': 'Google Cloud',
            'mongodb': 'MongoDB',
            'jenkins': 'Jenkins'
        }
        
        for resource, tech in puppet_resources.items():
            if resource in content:
                repository.add_technology(
                    category='infrastructure',
                    name=tech,
                    path=file_path
                )
        
        for module, tech in puppet_modules.items():
            pattern = f'include {module}' if '{' not in module else module
            if pattern in content.lower():
                repository.add_technology(
                    category='infrastructure',
                    name=tech,
                    path=file_path
                )
    
    def _detect_k8s_resource_type(self, repository: Repository, kind: str, file_path: str) -> None:
        """
        Detect Kubernetes resource types.
        
        Args:
            repository: Repository to update
            kind: Kubernetes resource kind
            file_path: Path to the file
        """
        # Workloads
        if kind in ['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Pod', 'ReplicaSet']:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes Workloads',
                path=file_path
            )
        
        # Services & Networking
        elif kind in ['Service', 'Ingress', 'NetworkPolicy', 'Endpoint']:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes Networking',
                path=file_path
            )
        
        # Config & Storage
        elif kind in ['ConfigMap', 'Secret', 'PersistentVolume', 'PersistentVolumeClaim', 'StorageClass']:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes Configuration',
                path=file_path
            )
        
        # RBAC
        elif kind in ['Role', 'RoleBinding', 'ClusterRole', 'ClusterRoleBinding', 'ServiceAccount']:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes RBAC',
                path=file_path
            )
        
        # CRDs & Operators
        elif kind in ['CustomResourceDefinition', 'Operator', 'ClusterServiceVersion']:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes Operators',
                path=file_path
            )
        
        # Istio resources
        elif kind in ['VirtualService', 'DestinationRule', 'Gateway', 'ServiceEntry']:
            repository.add_technology(
                category='infrastructure',
                name='Istio',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Service Mesh',
                path=file_path
            )
        
        # Knative resources
        elif kind in ['Service', 'Revision', 'Configuration', 'Route'] and 'knative' in file_path:
            repository.add_technology(
                category='infrastructure',
                name='Knative',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Serverless',
                path=file_path
            )
        
        # Cert-manager resources
        elif kind in ['Certificate', 'ClusterIssuer', 'Issuer', 'CertificateRequest']:
            repository.add_technology(
                category='infrastructure',
                name='cert-manager',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes Security',
                path=file_path
            )
    
    def _detect_tech_from_image_name(self, repository: Repository, image: str, file_path: str) -> None:
        """
        Detect technologies from Docker image names.
        
        Args:
            repository: Repository to update
            image: Docker image name
            file_path: Path to the file
        """
        # Common technologies that might be found in image names
        image_techs = {
            'node': 'Node.js',
            'python': 'Python',
            'golang': 'Go',
            'openjdk': 'Java',
            'java': 'Java',
            'php': 'PHP',
            'ruby': 'Ruby',
            'nginx': 'NGINX',
            'httpd': 'Apache HTTP Server',
            'apache': 'Apache HTTP Server',
            'postgres': 'PostgreSQL',
            'mysql': 'MySQL',
            'mariadb': 'MariaDB',
            'mongo': 'MongoDB',
            'redis': 'Redis',
            'elasticsearch': 'Elasticsearch',
            'kibana': 'Kibana',
            'logstash': 'Logstash',
            'rabbitmq': 'RabbitMQ',
            'kafka': 'Kafka',
            'zookeeper': 'ZooKeeper',
            'prometheus': 'Prometheus',
            'grafana': 'Grafana',
            'traefik': 'Traefik',
            'haproxy': 'HAProxy',
            'ubuntu': 'Ubuntu',
            'debian': 'Debian',
            'alpine': 'Alpine Linux',
            'centos': 'CentOS',
            'amazonlinux': 'Amazon Linux'
        }
        
        image_lower = image.lower()
        
        for keyword, tech in image_techs.items():
            if keyword in image_lower:
                repository.add_technology(
                    category='infrastructure',
                    name=tech,
                    path=file_path
                )
    
    def _detect_aws_services(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Detect AWS services in infrastructure code.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Common AWS services
        aws_services = {
            'aws_lambda': 'AWS Lambda',
            'aws_apigateway': 'Amazon API Gateway',
            'aws_s3': 'Amazon S3',
            'aws_dynamodb': 'Amazon DynamoDB',
            'aws_rds': 'Amazon RDS',
            'aws_ec2': 'Amazon EC2',
            'aws_ecs': 'Amazon ECS',
            'aws_eks': 'Amazon EKS',
            'aws_sqs': 'Amazon SQS',
            'aws_sns': 'Amazon SNS',
            'aws_cloudwatch': 'Amazon CloudWatch',
            'aws_iam': 'AWS IAM',
            'aws_route53': 'Amazon Route 53',
            'aws_cloudfront': 'Amazon CloudFront',
            'aws_elasticache': 'Amazon ElastiCache',
            'aws_kinesis': 'Amazon Kinesis',
            'aws_glue': 'AWS Glue',
            'aws_athena': 'Amazon Athena',
            'aws_emr': 'Amazon EMR',
            'aws_msk': 'Amazon MSK',
            'aws_opensearch': 'Amazon OpenSearch Service',
            'aws_elasticsearch': 'Amazon Elasticsearch Service',
            'aws_cognito': 'Amazon Cognito',
            'aws_codecommit': 'AWS CodeCommit',
            'aws_codebuild': 'AWS CodeBuild',
            'aws_codepipeline': 'AWS CodePipeline',
            'aws_codedeploy': 'AWS CodeDeploy',
            'aws_ecr': 'Amazon ECR',
            'aws_batch': 'AWS Batch',
            'aws_step_functions': 'AWS Step Functions',
            'aws_eventbridge': 'Amazon EventBridge'
        }
        
        # Check for AWS services in Terraform resources
        for keyword, service in aws_services.items():
            if f'resource "{keyword}_' in content or f'data "{keyword}_' in content:
                repository.add_technology(
                    category='infrastructure',
                    name=service,
                    path=file_path
                )
        
        # Check for CloudFormation resources
        cf_services = {
            'AWS::Lambda::': 'AWS Lambda',
            'AWS::ApiGateway::': 'Amazon API Gateway',
            'AWS::S3::': 'Amazon S3',
            'AWS::DynamoDB::': 'Amazon DynamoDB',
            'AWS::RDS::': 'Amazon RDS',
            'AWS::EC2::': 'Amazon EC2',
            'AWS::ECS::': 'Amazon ECS',
            'AWS::EKS::': 'Amazon EKS',
            'AWS::SQS::': 'Amazon SQS',
            'AWS::SNS::': 'Amazon SNS',
            'AWS::CloudWatch::': 'Amazon CloudWatch',
            'AWS::IAM::': 'AWS IAM',
            'AWS::Route53::': 'Amazon Route 53',
            'AWS::CloudFront::': 'Amazon CloudFront'
        }
        
        for keyword, service in cf_services.items():
            if keyword in content:
                repository.add_technology(
                    category='infrastructure',
                    name=service,
                    path=file_path
                )
        
        # Check for serverless technologies
        if 'aws_lambda' in content or 'AWS::Lambda::' in content or 'handler:' in content:
            repository.add_technology(
                category='infrastructure',
                name='Serverless',
                path=file_path
            )
        
        # Check for container technologies
        if 'aws_ecs' in content or 'AWS::ECS::' in content:
            repository.add_technology(
                category='infrastructure',
                name='Containers',
                path=file_path
            )
        
        if 'aws_eks' in content or 'AWS::EKS::' in content:
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes',
                path=file_path
            )
    
    def _detect_gcp_services(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Detect Google Cloud services in infrastructure code.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Common GCP services
        gcp_services = {
            'google_compute': 'Google Compute Engine',
            'google_container': 'Google Kubernetes Engine',
            'google_storage': 'Google Cloud Storage',
            'google_bigquery': 'Google BigQuery',
            'google_cloudfunctions': 'Google Cloud Functions',
            'google_cloud_run': 'Google Cloud Run',
            'google_spanner': 'Google Cloud Spanner',
            'google_sql': 'Google Cloud SQL',
            'google_pubsub': 'Google Cloud Pub/Sub',
            'google_dataflow': 'Google Cloud Dataflow',
            'google_dataproc': 'Google Cloud Dataproc',
            'google_app_engine': 'Google App Engine',
            'google_dns': 'Google Cloud DNS',
            'google_kms': 'Google Cloud KMS',
            'google_iam': 'Google Cloud IAM',
            'google_logging': 'Google Cloud Logging',
            'google_monitoring': 'Google Cloud Monitoring',
            'google_firestore': 'Google Cloud Firestore',
            'google_bigtable': 'Google Cloud Bigtable',
            'google_redis': 'Google Cloud Memorystore',
            'google_vpc': 'Google Virtual Private Cloud'
        }
        
        # Check for GCP services in infrastructure code
        for keyword, service in gcp_services.items():
            if f'resource "{keyword}_' in content or f'data "{keyword}_' in content:
                repository.add_technology(
                    category='infrastructure',
                    name=service,
                    path=file_path
                )
        
        # Check for serverless technologies
        if 'google_cloudfunctions' in content or 'google_cloud_run' in content:
            repository.add_technology(
                category='infrastructure',
                name='Serverless',
                path=file_path
            )
        
        # Check for container technologies
        if 'google_container' in content or 'kubernetes' in content.lower():
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Containers',
                path=file_path
            )
    
    def _detect_azure_services(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Detect Azure services in infrastructure code.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Common Azure services
        azure_services = {
            'azurerm_virtual_machine': 'Azure Virtual Machine',
            'azurerm_linux_virtual_machine': 'Azure Virtual Machine',
            'azurerm_windows_virtual_machine': 'Azure Virtual Machine',
            'azurerm_app_service': 'Azure App Service',
            'azurerm_function_app': 'Azure Functions',
            'azurerm_storage_account': 'Azure Storage',
            'azurerm_cosmosdb': 'Azure Cosmos DB',
            'azurerm_sql': 'Azure SQL',
            'azurerm_kubernetes': 'Azure Kubernetes Service',
            'azurerm_container': 'Azure Container Instances',
            'azurerm_eventhub': 'Azure Event Hubs',
            'azurerm_servicebus': 'Azure Service Bus',
            'azurerm_api_management': 'Azure API Management',
            'azurerm_logic_app': 'Azure Logic Apps',
            'azurerm_key_vault': 'Azure Key Vault',
            'azurerm_monitor': 'Azure Monitor',
            'azurerm_application_insights': 'Azure Application Insights',
            'azurerm_cdn': 'Azure CDN',
            'azurerm_dns': 'Azure DNS',
            'azurerm_virtual_network': 'Azure Virtual Network',
            'azurerm_network': 'Azure Networking',
            'azurerm_lb': 'Azure Load Balancer',
            'azurerm_redis': 'Azure Cache for Redis',
            'azurerm_databricks': 'Azure Databricks',
            'azurerm_hdinsight': 'Azure HDInsight',
            'azurerm_data_factory': 'Azure Data Factory'
        }
        
        # Check for Azure services in infrastructure code
        for keyword, service in azure_services.items():
            if f'resource "{keyword}' in content or f'data "{keyword}' in content:
                repository.add_technology(
                    category='infrastructure',
                    name=service,
                    path=file_path
                )
        
        # Check for serverless technologies
        if 'azurerm_function_app' in content or 'azurerm_logic_app' in content:
            repository.add_technology(
                category='infrastructure',
                name='Serverless',
                path=file_path
            )
        
        # Check for container technologies
        if 'azurerm_kubernetes' in content or 'kubernetes' in content.lower():
            repository.add_technology(
                category='infrastructure',
                name='Kubernetes',
                path=file_path
            )
            
            repository.add_technology(
                category='infrastructure',
                name='Containers',
                path=file_path
            )
