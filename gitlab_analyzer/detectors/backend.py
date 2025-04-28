"""
Backend technology detector for GitLab Repository Analyzer.
Detects backend frameworks, languages, and tools.
"""

import json
import re
from typing import Dict, List, Any, Optional

from .base_detector import BaseDetector
from ..core.repository import Repository
from ..core.utils import extract_version_from_string


class BackendDetector(BaseDetector):
    """Detector for backend technologies."""
    
    def __init__(self):
        """Initialize backend detector."""
        super().__init__(name="Backend", category="backend")
        
        # File patterns to match
        self.file_patterns = [
            # Python
            "*.py", "requirements.txt", "Pipfile", "pyproject.toml", "setup.py",
            # Node.js
            "*.js", "*.ts", "package.json", "server.js", "app.js", "index.js",
            # Java
            "*.java", "pom.xml", "build.gradle", "*.jar", "*.war",
            # Ruby
            "*.rb", "Gemfile", "config.ru", "*.rake",
            # PHP
            "*.php", "composer.json", "artisan",
            # Go
            "*.go", "go.mod", "go.sum",
            # C#/.NET
            "*.cs", "*.csproj", "*.sln", "web.config", "Startup.cs", "Program.cs",
            # Configuration files
            "*.yml", "*.yaml", "*.json", "*.toml", "*.ini", "*.conf"
        ]
        
        # Simple content patterns for quick detection
        self.content_patterns = {
            # Python frameworks
            "Django": ["django", "urlpatterns", "INSTALLED_APPS", "settings.py"],
            "Flask": ["from flask import", "@app.route", "flask.Flask", "flask_"],
            "FastAPI": ["from fastapi import", "@app.get", "fastapi.FastAPI"],
            "Pyramid": ["from pyramid", "config.add_route"],
            "SQLAlchemy": ["sqlalchemy", "Base.metadata", "Column(", "relationship("],
            "Celery": ["from celery import", "celery.task", "@task"],
            "Jupyter": ["jupyter", "ipynb"],
            "pandas": ["import pandas", "pd.DataFrame", "pandas."],
            "NumPy": ["import numpy", "np.array", "numpy."],
            "TensorFlow": ["import tensorflow", "tf."],
            "PyTorch": ["import torch", "torch.nn"],
            
            # Node.js frameworks
            "Express": ["express()", "app.get(", "app.use(", "express.Router"],
            "NestJS": ["@Controller", "@Injectable", "@Module", "NestFactory"],
            "Hapi": ["Hapi.server", "server.route", "hapi"],
            "Koa": ["new Koa()", "ctx.", "koa"],
            "Fastify": ["fastify(", "fastify.register", "fastify.get"],
            "Meteor": ["Meteor.", "meteor"],
            "Socket.IO": ["io.on('connection'", "socket.io"],
            "Mongoose": ["mongoose.Schema", "mongoose.model", "mongoose.connect"],
            "Sequelize": ["sequelize", "DataTypes", "define("],
            "TypeORM": ["@Entity", "createConnection", "Repository"],
            
            # Java frameworks
            "Spring Boot": ["@SpringBootApplication", "SpringApplication", "application.properties"],
            "Spring MVC": ["@Controller", "@RequestMapping", "springframework"],
            "Hibernate": ["@Entity", "SessionFactory", "@Table", "hibernate"],
            "Jakarta EE": ["javax.servlet", "beans.xml", "persistence.xml"],
            "Quarkus": ["quarkus", "@Path", "@Produces"],
            "Micronaut": ["micronaut", "@Controller", "@Inject"],
            
            # Ruby frameworks
            "Ruby on Rails": ["ActiveRecord", "rails", "config/routes.rb"],
            "Sinatra": ["sinatra", "get '/'", "Sinatra::Base"],
            "Hanami": ["hanami", "Hanami::Application"],
            
            # PHP frameworks
            "Laravel": ["Illuminate\\", "artisan", "namespace App"],
            "Symfony": ["symfony", "Symfony\\", "symfony.lock"],
            "CodeIgniter": ["defined('BASEPATH')", "CodeIgniter"],
            "WordPress": ["wp_", "wp-config", "add_action"],
            "Drupal": ["drupal", "Drupal\\"],
            
            # Go frameworks
            "Gin": ["gin.Context", "gin.Default", "gin.H{"],
            "Echo": ["echo.New", "e.GET", "echo.Context"],
            "Gorilla": ["gorilla/mux", "gorilla/websocket"],
            "Fiber": ["fiber.New", "app.Get", "fiber.Ctx"],
            
            # .NET frameworks
            "ASP.NET Core": ["Microsoft.AspNetCore", "IApplicationBuilder", "Startup"],
            "ASP.NET MVC": ["System.Web.Mvc", "Controller", "ActionResult"],
            "Entity Framework": ["DbContext", "OnModelCreating", "Microsoft.EntityFrameworkCore"],
            
            # Database technologies (general backend)
            "MongoDB": ["mongodb", "MongoClient", "findOne(", "aggregate("],
            "Redis": ["redis", "RedisClient", "SETEX", "HSET"],
            "PostgreSQL": ["postgresql", "postgres", "pg_"],
            "MySQL": ["mysql", "createConnection", "mysqli"],
            "SQLite": ["sqlite", "sqlite3"],
            "DynamoDB": ["DynamoDB", "DocumentClient", "aws-sdk"],
            "Elasticsearch": ["elasticsearch", "createIndex", "search("],
            
            # API technologies
            "GraphQL": ["graphql", "gql`", "Query {", "type Query"],
            "REST API": ["@RestController", "@RequestMapping", "router.get", "app.get"],
            "gRPC": ["grpc", "service {", "rpc ", ".proto"],
            
            # Message queue systems
            "RabbitMQ": ["amqp", "RabbitMQ", "createChannel"],
            "Kafka": ["kafka", "KafkaConsumer", "KafkaProducer"],
            "ActiveMQ": ["activemq", "JMS"],
            
            # Authentication
            "OAuth": ["OAuth", "oauth", "access_token"],
            "JWT": ["jwt", "sign(", "verify(", "JsonWebToken"],
            "Passport": ["passport.authenticate", "passport.use"]
        }
        
        # Regex patterns for more complex matching
        self.regex_patterns = {
            # Python version detection
            "Python Version": [r'python\s*([0-9]+\.[0-9]+)', r'Python\s*([0-9]+\.[0-9]+)'],
            # Node.js version
            "Node.js Version": [r'"node":\s*"([^"]+)"', r'"engines":\s*{\s*"node":\s*"([^"]+)"'],
            # Java version
            "Java Version": [r'<java.version>([^<]+)</java.version>', r'sourceCompatibility\s*=\s*[\'"]([\d\.]+)[\'"]'],
            # Spring Boot version
            "Spring Boot Version": [r'spring-boot-starter-parent.+?<version>([^<]+)</version>', r'org\.springframework\.boot[^"]+?:([^"]+?)"'],
            # Django version
            "Django Version": [r'Django==([0-9\.]+)', r'django~=([0-9\.]+)', r'django>=([0-9\.]+)'],
            # Express version
            "Express Version": [r'"express":\s*"(?:\^|~)?([^"]+)"'],
            # Laravel version
            "Laravel Version": [r'"laravel/framework":\s*"([^"]+)"'],
            # Database connection patterns
            "Database Connection": [
                r'mysqli_connect\([\'"]([^\'"]+)[\'"]',
                r'new\s+PDO\([\'"]mysql:host=([^\'"]+)[\'"]',
                r'psycopg2\.connect\([\'"]host=([^\'"]+)[\'"]',
                r'mongoose\.connect\([\'"]mongodb://([^\'"]+)[\'"]',
                r'createConnection\({[\s\n]*host:\s*[\'"]([^\'"]+)[\'"]'
            ],
            # API endpoint patterns
            "API Endpoint": [
                r'@RequestMapping\([\'"]([^\'"]+)[\'"]',
                r'@GetMapping\([\'"]([^\'"]+)[\'"]',
                r'app.get\([\'"]([^\'"]+)[\'"]',
                r'router.get\([\'"]([^\'"]+)[\'"]',
                r'@app.route\([\'"]([^\'"]+)[\'"]'
            ]
        }
    
    def _detect_specialized(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Specialized detection for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Python-specific detection
        if file_path.endswith('.py'):
            self._analyze_python_file(repository, content, file_path)
        elif file_path == 'requirements.txt':
            self._analyze_requirements_txt(repository, content, file_path)
        elif file_path == 'Pipfile' or file_path == 'pyproject.toml':
            self._analyze_python_dependency_file(repository, content, file_path)
            
        # Node.js-specific detection
        elif file_path.endswith('package.json'):
            self._analyze_package_json(repository, content, file_path)
        elif file_path.endswith('.js') or file_path.endswith('.ts'):
            self._analyze_js_file(repository, content, file_path)
            
        # Java-specific detection
        elif file_path.endswith('.java'):
            self._analyze_java_file(repository, content, file_path)
        elif file_path == 'pom.xml':
            self._analyze_pom_xml(repository, content, file_path)
        elif file_path.endswith('build.gradle'):
            self._analyze_gradle_file(repository, content, file_path)
            
        # Ruby-specific detection
        elif file_path.endswith('.rb'):
            self._analyze_ruby_file(repository, content, file_path)
        elif file_path == 'Gemfile':
            self._analyze_gemfile(repository, content, file_path)
            
        # PHP-specific detection
        elif file_path.endswith('.php'):
            self._analyze_php_file(repository, content, file_path)
        elif file_path == 'composer.json':
            self._analyze_composer_json(repository, content, file_path)
            
        # Go-specific detection
        elif file_path.endswith('.go'):
            self._analyze_go_file(repository, content, file_path)
        elif file_path == 'go.mod':
            self._analyze_go_mod(repository, content, file_path)
            
        # .NET-specific detection
        elif file_path.endswith('.cs'):
            self._analyze_cs_file(repository, content, file_path)
        elif file_path.endswith('.csproj'):
            self._analyze_csproj(repository, content, file_path)
            
        # Configuration files
        elif file_path.endswith(('.yml', '.yaml')):
            self._analyze_yaml_config(repository, content, file_path)
    
    def _analyze_python_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Python file for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Python language
        repository.add_technology(
            category='backend',
            name='Python',
            path=file_path,
            confidence=1.0
        )
        
        # Check for web frameworks
        frameworks = {
            'Django': [
                'django.urls', 'django.db', 'django.conf', 'django.views',
                'from django', 'import django'
            ],
            'Flask': [
                'from flask import', 'import flask', 'Flask(__name__)', 
                '@app.route', 'flask.Flask'
            ],
            'FastAPI': [
                'from fastapi import', 'import fastapi', 'FastAPI()', 
                '@app.get', '@app.post'
            ],
            'Pyramid': [
                'from pyramid', 'import pyramid', 'config.add_route',
                'config.add_view'
            ],
            'Tornado': [
                'import tornado', 'from tornado', 'tornado.web',
                'RequestHandler'
            ]
        }
        
        for framework, patterns in frameworks.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='backend',
                    name=framework,
                    path=file_path
                )
        
        # Check for ORMs
        orms = {
            'SQLAlchemy': [
                'import sqlalchemy', 'from sqlalchemy import', 'Base.metadata',
                'Column(', 'relationship('
            ],
            'Django ORM': [
                'from django.db import models', 'models.Model', 'models.CharField',
                'models.ForeignKey'
            ],
            'Peewee': [
                'import peewee', 'from peewee import', 'peewee.Model',
                'peewee.CharField'
            ]
        }
        
        for orm, patterns in orms.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='backend',
                    name=orm,
                    path=file_path
                )
        
        # Check for task queues
        task_queues = {
            'Celery': [
                'import celery', 'from celery import', '@app.task',
                'celery.task', '@shared_task'
            ],
            'RQ': [
                'import rq', 'from rq import', 'Queue(', 'redis.Redis'
            ]
        }
        
        for queue, patterns in task_queues.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='backend',
                    name=queue,
                    path=file_path
                )
        
        # Check for API-related
        if 'def get(' in content and 'def post(' in content:
            repository.add_technology(
                category='backend',
                name='REST API',
                path=file_path
            )
            
        if 'graphene' in content or 'graphql' in content:
            repository.add_technology(
                category='backend',
                name='GraphQL',
                path=file_path
            )
    
    def _analyze_requirements_txt(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze requirements.txt for Python dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Python detection
        repository.add_technology(
            category='backend',
            name='Python',
            path=file_path,
            confidence=1.0
        )
        
        # Check for key Python packages
        packages = {
            'Django': ['django'],
            'Flask': ['flask'],
            'FastAPI': ['fastapi'],
            'Pyramid': ['pyramid'],
            'SQLAlchemy': ['sqlalchemy'],
            'Celery': ['celery'],
            'Pandas': ['pandas'],
            'NumPy': ['numpy'],
            'TensorFlow': ['tensorflow'],
            'PyTorch': ['torch'],
            'Scrapy': ['scrapy'],
            'pytest': ['pytest'],
            'Requests': ['requests'],
            'Boto3 (AWS SDK)': ['boto3'],
            'Pillow': ['pillow'],
            'GraphQL': ['graphene', 'graphql-core'],
            'Django REST Framework': ['djangorestframework'],
            'Flask-RESTful': ['flask-restful']
        }
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract package name (strip version info)
                package_name = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].strip()
                package_name = package_name.lower()
                
                # Check against known packages
                for tech, patterns in packages.items():
                    if any(pattern == package_name for pattern in patterns):
                        # Try to extract version
                        version = None
                        if '==' in line:
                            version = line.split('==')[1].split('#')[0].strip()
                        elif '>=' in line:
                            version = line.split('>=')[1].split('#')[0].strip()
                        
                        repository.add_technology(
                            category='backend',
                            name=tech,
                            version=version,
                            path=file_path
                        )
    
    def _analyze_python_dependency_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Python dependency files (Pipfile, pyproject.toml).
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Python detection
        repository.add_technology(
            category='backend',
            name='Python',
            path=file_path,
            confidence=1.0
        )
        
        # Check for key Python packages
        packages = {
            'Django': ['django'],
            'Flask': ['flask'],
            'FastAPI': ['fastapi'],
            'Pyramid': ['pyramid'],
            'SQLAlchemy': ['sqlalchemy'],
            'Celery': ['celery'],
            'Pandas': ['pandas'],
            'NumPy': ['numpy'],
            'TensorFlow': ['tensorflow'],
            'PyTorch': ['torch'],
            'Poetry': ['poetry'],
            'pytest': ['pytest'],
            'Requests': ['requests'],
            'Boto3 (AWS SDK)': ['boto3'],
            'Pillow': ['pillow'],
            'GraphQL': ['graphene', 'graphql-core'],
            'Django REST Framework': ['djangorestframework'],
            'Flask-RESTful': ['flask-restful']
        }
        
        # Check for each package
        for tech, patterns in packages.items():
            for pattern in patterns:
                if pattern in content.lower():
                    # Try to extract version
                    version = extract_version_from_string(content, pattern)
                    
                    repository.add_technology(
                        category='backend',
                        name=tech,
                        version=version,
                        path=file_path
                    )
    
    def _analyze_package_json(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze package.json for Node.js dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        try:
            package_data = json.loads(content)
            
            # Detect Node.js
            repository.add_technology(
                category='backend',
                name='Node.js',
                path=file_path,
                confidence=1.0
            )
            
            # Get Node.js version if specified
            if 'engines' in package_data and 'node' in package_data['engines']:
                repository.add_technology(
                    category='backend',
                    name='Node.js',
                    version=package_data['engines']['node'],
                    path=file_path
                )
            
            # Combine dependencies and devDependencies
            all_deps = {}
            if 'dependencies' in package_data:
                all_deps.update(package_data['dependencies'])
            if 'devDependencies' in package_data:
                all_deps.update(package_data['devDependencies'])
            
            # Check for backend frameworks and libraries
            backend_techs = {
                'Express': ['express'],
                'NestJS': ['@nestjs/core', '@nestjs/common'],
                'Hapi': ['@hapi/hapi', 'hapi'],
                'Koa': ['koa'],
                'Fastify': ['fastify'],
                'Meteor': ['meteor-node-stubs'],
                'Socket.IO': ['socket.io'],
                'Mongoose': ['mongoose'],
                'Sequelize': ['sequelize'],
                'TypeORM': ['typeorm'],
                'Prisma': ['prisma', '@prisma/client'],
                'GraphQL': ['graphql', 'apollo-server', 'type-graphql'],
                'TypeScript': ['typescript', 'ts-node'],
                'Jest': ['jest'],
                'Mocha': ['mocha'],
                'AWS SDK': ['aws-sdk'],
                'Passport': ['passport'],
                'JWT': ['jsonwebtoken'],
                'Axios': ['axios'],
                'Nodemon': ['nodemon'],
                'PM2': ['pm2'],
                'Redis': ['redis', 'ioredis'],
                'MongoDB Driver': ['mongodb'],
                'PostgreSQL Driver': ['pg'],
                'MySQL Driver': ['mysql', 'mysql2'],
                'Knex': ['knex'],
                'Bull': ['bull'],
                'Webpack': ['webpack'],
                'Babel': ['@babel/core'],
                'ESLint': ['eslint'],
                'Prettier': ['prettier']
            }
            
            for tech, packages in backend_techs.items():
                for pkg in packages:
                    if pkg in all_deps:
                        repository.add_technology(
                            category='backend',
                            name=tech,
                            version=all_deps[pkg],
                            path=file_path
                        )
            
            # Check for type of application
            is_backend = False
            
            # Check main field or scripts
            if 'main' in package_data:
                main_file = package_data['main']
                if main_file in ['server.js', 'app.js', 'index.js', 'api.js']:
                    is_backend = True
            
            # Check scripts
            if 'scripts' in package_data:
                scripts = package_data['scripts']
                backend_script_patterns = ['server', 'start', 'dev', 'serve', 'api']
                
                for script_name, script_cmd in scripts.items():
                    if any(pattern in script_name.lower() for pattern in backend_script_patterns):
                        is_backend = True
                        break
            
            # Check if we have backend dependencies
            backend_indicator_packages = [
                'express', 'koa', 'fastify', 'hapi', '@nestjs/core', 
                'mongoose', 'sequelize', 'typeorm', 'apollo-server'
            ]
            
            if any(pkg in all_deps for pkg in backend_indicator_packages):
                is_backend = True
            
            if is_backend:
                repository.add_technology(
                    category='backend',
                    name='Node.js Backend',
                    path=file_path
                )
                
        except json.JSONDecodeError:
            # Invalid JSON, skip analysis
            pass
    
    def _analyze_js_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze JavaScript/TypeScript file for backend code.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Only analyze as backend if it looks like server code
        is_backend = False
        
        # Check for backend imports
        backend_imports = [
            'require(\'express\')', 'require("express")',
            'require(\'koa\')', 'require("koa")',
            'require(\'fastify\')', 'require("fastify")',
            'require(\'http\')', 'require("http")',
            'require(\'fs\')', 'require("fs")',
            'import express from', 'import * as express from',
            'import koa from', 'import * as koa from',
            'import fastify from', 'import * as fastify from',
            'import { NestFactory }', 'createConnection(',
            'mongoose.connect', 'new Sequelize(',
            'createServer(', 'listen(', '.listen(',
        ]
        
        if any(pattern in content for pattern in backend_imports):
            is_backend = True
        
        # Check for route definitions
        route_patterns = [
            'app.get(', 'app.post(', 'app.put(', 'app.delete(',
            'router.get(', 'router.post(', 'router.put(', 'router.delete(',
            '@Get(', '@Post(', '@Put(', '@Delete(',
            'server.route(', 'fastify.get(', 'fastify.post(',
            'app.use('
        ]
        
        if any(pattern in content for pattern in route_patterns):
            is_backend = True
            repository.add_technology(
                category='backend',
                name='REST API',
                path=file_path
            )
        
        # If it's backend code, identify frameworks
        if is_backend:
            # Identify if it's TypeScript
            if file_path.endswith('.ts'):
                repository.add_technology(
                    category='backend',
                    name='TypeScript',
                    path=file_path
                )
            else:
                repository.add_technology(
                    category='backend',
                    name='JavaScript',
                    path=file_path
                )
            
            # Identify specific frameworks
            if 'express' in content:
                repository.add_technology(
                    category='backend',
                    name='Express',
                    path=file_path
                )
            
            if 'new Koa()' in content or 'require(\'koa\')' in content:
                repository.add_technology(
                    category='backend',
                    name='Koa',
                    path=file_path
                )
            
            if 'fastify(' in content or 'require(\'fastify\')' in content:
                repository.add_technology(
                    category='backend',
                    name='Fastify',
                    path=file_path
                )
            
            if 'NestFactory' in content or '@Module' in content:
                repository.add_technology(
                    category='backend',
                    name='NestJS',
                    path=file_path
                )
            
            # Database connections
            if 'mongoose.connect' in content or 'mongoose.Schema' in content:
                repository.add_technology(
                    category='backend',
                    name='MongoDB',
                    path=file_path
                )
                
                repository.add_technology(
                    category='backend',
                    name='Mongoose',
                    path=file_path
                )
            
            if 'new Sequelize(' in content or 'sequelize' in content:
                repository.add_technology(
                    category='backend',
                    name='Sequelize',
                    path=file_path
                )
            
            # GraphQL detection
            if 'gql`' in content or 'graphql' in content or 'ApolloServer' in content:
                repository.add_technology(
                    category='backend',
                    name='GraphQL',
                    path=file_path
                )
    
    def _analyze_java_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Java file for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Java
        repository.add_technology(
            category='backend',
            name='Java',
            path=file_path,
            confidence=1.0
        )
        
        # Check for Spring framework
        spring_patterns = [
            '@Controller', '@RestController', '@Service', '@Repository',
            '@Component', '@Autowired', '@RequestMapping', '@GetMapping',
            'org.springframework', 'SpringApplication', '@SpringBootApplication'
        ]
        
        if any(pattern in content for pattern in spring_patterns):
            repository.add_technology(
                category='backend',
                name='Spring Framework',
                path=file_path
            )
            
            if '@SpringBootApplication' in content or 'SpringApplication.run' in content:
                repository.add_technology(
                    category='backend',
                    name='Spring Boot',
                    path=file_path
                )
        
        # Check for Java EE / Jakarta EE
        javaee_patterns = [
            'javax.servlet', 'javax.ejb', '@EJB', '@Stateless',
            '@Stateful', '@Entity', '@PersistenceContext',
            'persistence.xml', 'jakarta.servlet'
        ]
        
        if any(pattern in content for pattern in javaee_patterns):
            repository.add_technology(
                category='backend',
                name='Jakarta EE',
                path=file_path
            )
        
        # Check for Hibernate
        hibernate_patterns = [
            'org.hibernate', '@Entity', '@Table', '@Column', 
            'SessionFactory', '@Id', '@GeneratedValue'
        ]
        
        if any(pattern in content for pattern in hibernate_patterns):
            repository.add_technology(
                category='backend',
                name='Hibernate',
                path=file_path
            )
        
        # Check for other Java frameworks
        if 'quarkus' in content.lower() or 'io.quarkus' in content:
            repository.add_technology(
                category='backend',
                name='Quarkus',
                path=file_path
            )
            
        if 'micronaut' in content.lower():
            repository.add_technology(
                category='backend',
                name='Micronaut',
                path=file_path
            )
            
        if 'play.api' in content or 'play.mvc' in content:
            repository.add_technology(
                category='backend',
                name='Play Framework',
                path=file_path
            )
            
        # Check for REST API
        if '@RestController' in content or '@GetMapping' in content or '@RequestMapping' in content:
            repository.add_technology(
                category='backend',
                name='REST API',
                path=file_path
            )
            
        # GraphQL detection
        if 'graphql' in content.lower() or 'graphqloperation' in content:
            repository.add_technology(
                category='backend',
                name='GraphQL',
                path=file_path
            )
    
    def _analyze_pom_xml(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Maven pom.xml file for Java dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Java
        repository.add_technology(
            category='backend',
            name='Java',
            path=file_path,
            confidence=1.0
        )
        
        # Detect Maven
        repository.add_technology(
            category='backend',
            name='Maven',
            path=file_path
        )
        
        # Extract dependencies
        java_techs = {
            'Spring Boot': ['spring-boot-starter', 'spring-boot-autoconfigure'],
            'Spring Framework': ['springframework', 'spring-core', 'spring-context'],
            'Spring Web MVC': ['spring-webmvc', 'spring-web'],
            'Spring Data': ['spring-data'],
            'Spring Security': ['spring-security'],
            'Spring Cloud': ['spring-cloud'],
            'Hibernate': ['hibernate-core', 'hibernate-entitymanager'],
            'JPA': ['javax.persistence', 'jakarta.persistence', 'spring-data-jpa'],
            'Jakarta EE': ['javax.servlet', 'jakarta.servlet', 'javaee-api', 'jakarta.jakartaee-api'],
            'Quarkus': ['quarkus-core', 'io.quarkus'],
            'Micronaut': ['micronaut-core', 'io.micronaut'],
            'JUnit': ['junit'],
            'Mockito': ['mockito'],
            'Log4j': ['log4j'],
            'SLF4J': ['slf4j'],
            'Logback': ['logback'],
            'Jackson': ['jackson-databind', 'jackson-core'],
            'Gson': ['gson'],
            'MySQL Connector': ['mysql-connector'],
            'PostgreSQL JDBC': ['postgresql'],
            'MongoDB Java Driver': ['mongodb-driver'],
            'Cassandra Driver': ['cassandra-driver'],
            'Thymeleaf': ['thymeleaf'],
            'Lombok': ['lombok'],
            'GraphQL Java': ['graphql-java'],
            'Kafka Client': ['kafka-clients'],
            'RabbitMQ Client': ['amqp-client']
        }
        
        for tech, patterns in java_techs.items():
            if any(f"<artifactId>{pattern}</artifactId>" in content for pattern in patterns):
                # Try to extract version
                version = None
                
                for pattern in patterns:
                    if f"<artifactId>{pattern}</artifactId>" in content:
                        # Try to find version after the artifact ID
                        match = re.search(
                            f"<artifactId>{pattern}</artifactId>\\s*<version>([^<]+)</version>", 
                            content
                        )
                        if match:
                            version = match.group(1)
                            break
                
                repository.add_technology(
                    category='backend',
                    name=tech,
                    version=version,
                    path=file_path
                )
        
        # Java version
        java_version_match = re.search(r'<java.version>([^<]+)</java.version>', content)
        if java_version_match:
            repository.add_technology(
                category='backend',
                name='Java',
                version=java_version_match.group(1),
                path=file_path
            )
    
    def _analyze_gradle_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Gradle build file for Java dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Java
        repository.add_technology(
            category='backend',
            name='Java',
            path=file_path,
            confidence=1.0
        )
        
        # Detect Gradle
        repository.add_technology(
            category='backend',
            name='Gradle',
            path=file_path
        )
        
        # Check for dependencies
        java_techs = {
            'Spring Boot': ['org.springframework.boot', 'spring-boot-starter'],
            'Spring Framework': ['org.springframework', 'spring-core', 'spring-context'],
            'Spring Web MVC': ['spring-webmvc', 'spring-web'],
            'Spring Data': ['spring-data'],
            'Spring Security': ['spring-security'],
            'Spring Cloud': ['spring-cloud'],
            'Hibernate': ['org.hibernate', 'hibernate-core'],
            'JPA': ['javax.persistence', 'jakarta.persistence', 'spring-data-jpa'],
            'Quarkus': ['io.quarkus', 'quarkus-core'],
            'Micronaut': ['io.micronaut', 'micronaut-core'],
            'JUnit': ['junit'],
            'Mockito': ['mockito'],
            'Log4j': ['log4j'],
            'SLF4J': ['slf4j'],
            'Logback': ['logback'],
            'Jackson': ['jackson'],
            'Gson': ['gson'],
            'MySQL Connector': ['mysql-connector'],
            'PostgreSQL JDBC': ['postgresql'],
            'MongoDB Java Driver': ['mongodb-driver'],
            'GraphQL Java': ['graphql-java'],
            'Kafka Client': ['kafka-clients'],
            'RabbitMQ Client': ['amqp-client']
        }
        
        for tech, patterns in java_techs.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='backend',
                    name=tech,
                    path=file_path
                )
    
    def _analyze_ruby_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Ruby file for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Ruby
        repository.add_technology(
            category='backend',
            name='Ruby',
            path=file_path,
            confidence=1.0
        )
        
        # Check for Rails
        rails_patterns = [
            'class ApplicationController < ActionController::Base',
            'Rails.application', 'ActiveRecord::Base',
            'ActiveRecord::Migration', 'has_many', 'belongs_to',
            'ActionController', 'ActionView', 'ActionMailer'
        ]
        
        if any(pattern in content for pattern in rails_patterns):
            repository.add_technology(
                category='backend',
                name='Ruby on Rails',
                path=file_path
            )
        
        # Check for Sinatra
        sinatra_patterns = [
            'require \'sinatra\'', 'require "sinatra"',
            'class MyApp < Sinatra::Base', 'get \'', 'post \''
        ]
        
        if any(pattern in content for pattern in sinatra_patterns):
            repository.add_technology(
                category='backend',
                name='Sinatra',
                path=file_path
            )
        
        # Check for other Ruby frameworks
        if 'Hanami::' in content or 'require \'hanami\'' in content:
            repository.add_technology(
                category='backend',
                name='Hanami',
                path=file_path
            )
            
        if 'require \'grape\'' in content or 'class API < Grape::API' in content:
            repository.add_technology(
                category='backend',
                name='Grape',
                path=file_path
            )
        
        # Check for ORM
        if 'ActiveRecord::' in content or 'has_many' in content or 'belongs_to' in content:
            repository.add_technology(
                category='backend',
                name='ActiveRecord',
                path=file_path
            )
            
        if 'DataMapper.' in content or 'include DataMapper::Resource' in content:
            repository.add_technology(
                category='backend',
                name='DataMapper',
                path=file_path
            )
        
        # Check for REST API
        route_patterns = ['get ', 'post ', 'put ', 'delete ', 'resources :']
        if any(pattern in content for pattern in route_patterns):
            repository.add_technology(
                category='backend',
                name='REST API',
                path=file_path
            )
    
    def _analyze_gemfile(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Ruby Gemfile for dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Ruby
        repository.add_technology(
            category='backend',
            name='Ruby',
            path=file_path,
            confidence=1.0
        )
        
        # Check for key gems
        ruby_techs = {
            'Ruby on Rails': ['rails'],
            'Sinatra': ['sinatra'],
            'Hanami': ['hanami'],
            'Grape': ['grape'],
            'RSpec': ['rspec'],
            'Minitest': ['minitest'],
            'Sidekiq': ['sidekiq'],
            'Redis': ['redis'],
            'PostgreSQL': ['pg'],
            'MySQL': ['mysql2'],
            'MongoDB': ['mongoid'],
            'ActiveRecord': ['activerecord'],
            'DataMapper': ['datamapper'],
            'GraphQL': ['graphql'],
            'Puma': ['puma'],
            'Unicorn': ['unicorn'],
            'Passenger': ['passenger'],
            'Devise': ['devise'],
            'CanCanCan': ['cancancan']
        }
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and 'gem ' in line:
                # Extract gem name and version
                match = re.search(r'gem\s+[\'"]([^\'"]+)[\'"](?:\s*,\s*[\'"]([^\'"]+)[\'"])?', line)
                if match:
                    gem_name = match.group(1)
                    version = match.group(2) if match.group(2) else None
                    
                    # Check against known gems
                    for tech, patterns in ruby_techs.items():
                        if gem_name in patterns:
                            repository.add_technology(
                                category='backend',
                                name=tech,
                                version=version,
                                path=file_path
                            )
    
    def _analyze_php_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze PHP file for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect PHP
        repository.add_technology(
            category='backend',
            name='PHP',
            path=file_path,
            confidence=1.0
        )
        
        # Check for frameworks
        laravel_patterns = [
            'Illuminate\\', 'namespace App\\', 'extends Controller',
            'use Laravel\\', 'artisan', 'Eloquent'
        ]
        
        if any(pattern in content for pattern in laravel_patterns):
            repository.add_technology(
                category='backend',
                name='Laravel',
                path=file_path
            )
        
        symfony_patterns = [
            'Symfony\\', 'namespace Symfony\\', 'extends AbstractController',
            'ContainerInterface', 'SymfonyComponentHttpFoundation'
        ]
        
        if any(pattern in content for pattern in symfony_patterns):
            repository.add_technology(
                category='backend',
                name='Symfony',
                path=file_path
            )
        
        codeigniter_patterns = [
            'defined(\'BASEPATH\')', 'extends CI_Controller',
            'CodeIgniter\\', 'class MY_Controller'
        ]
        
        if any(pattern in content for pattern in codeigniter_patterns):
            repository.add_technology(
                category='backend',
                name='CodeIgniter',
                path=file_path
            )
        
        # Check for WordPress
        wordpress_patterns = [
            'wp_', 'add_action', 'get_template_part', 'add_filter',
            'get_post', 'the_content'
        ]
        
        if any(pattern in content for pattern in wordpress_patterns):
            repository.add_technology(
                category='backend',
                name='WordPress',
                path=file_path
            )
        
        # Check for Drupal
        drupal_patterns = [
            'Drupal\\', 'drupal_', 'hook_', 'module_implements'
        ]
        
        if any(pattern in content for pattern in drupal_patterns):
            repository.add_technology(
                category='backend',
                name='Drupal',
                path=file_path
            )
        
        # Check for database connections
        if 'mysqli_connect' in content or 'new PDO(' in content:
            repository.add_technology(
                category='backend',
                name='MySQL',
                path=file_path
            )
            
        if 'pg_connect' in content or 'pgsql:' in content:
            repository.add_technology(
                category='backend',
                name='PostgreSQL',
                path=file_path
            )
        
        # Check for REST API
        if ('class ApiController' in content or 
            '->json(' in content or 
            'Response::json' in content or
            'api/' in file_path.lower()):
            repository.add_technology(
                category='backend',
                name='REST API',
                path=file_path
            )
    
    def _analyze_composer_json(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze PHP composer.json for dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        try:
            composer_data = json.loads(content)
            
            # Detect PHP
            repository.add_technology(
                category='backend',
                name='PHP',
                path=file_path,
                confidence=1.0
            )
            
            # PHP version if specified
            if 'require' in composer_data and 'php' in composer_data['require']:
                repository.add_technology(
                    category='backend',
                    name='PHP',
                    version=composer_data['require']['php'],
                    path=file_path
                )
            
            # Get all dependencies
            all_deps = {}
            if 'require' in composer_data:
                all_deps.update(composer_data['require'])
            if 'require-dev' in composer_data:
                all_deps.update(composer_data['require-dev'])
            
            # Check for frameworks and libraries
            php_techs = {
                'Laravel': ['laravel/framework', 'laravel/lumen'],
                'Symfony': ['symfony/symfony', 'symfony/framework-bundle'],
                'CodeIgniter': ['codeigniter/framework'],
                'CakePHP': ['cakephp/cakephp'],
                'Yii': ['yiisoft/yii2'],
                'Zend Framework': ['zendframework/zend-framework'],
                'Laminas': ['laminas/laminas-mvc'],
                'Slim': ['slim/slim'],
                'Doctrine ORM': ['doctrine/orm'],
                'Eloquent ORM': ['illuminate/database'],
                'MySQL': ['mysql', 'mysqli'],
                'PostgreSQL': ['pgsql', 'postgres'],
                'MongoDB': ['mongodb/mongodb'],
                'Redis': ['predis/predis'],
                'PHPUnit': ['phpunit/phpunit'],
                'PHPStan': ['phpstan/phpstan'],
                'Composer': ['composer/composer'],
                'Guzzle HTTP': ['guzzlehttp/guzzle'],
                'Twig': ['twig/twig'],
                'Blade': ['illuminate/view'],
                'GraphQL': ['webonyx/graphql-php'],
                'REST API': ['laravel/passport', 'league/oauth2-server'],
                'JWT': ['firebase/php-jwt', 'lcobucci/jwt']
            }
            
            for tech, packages in php_techs.items():
                for pkg in packages:
                    if pkg in all_deps:
                        repository.add_technology(
                            category='backend',
                            name=tech,
                            version=all_deps[pkg],
                            path=file_path
                        )
                            
        except json.JSONDecodeError:
            # Invalid JSON, skip analysis
            pass
    
    def _analyze_go_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Go file for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Go
        repository.add_technology(
            category='backend',
            name='Go',
            path=file_path,
            confidence=1.0
        )
        
        # Check for web frameworks
        go_frameworks = {
            'Gin': ['gin.', 'gin.Context', 'gin.Default()', 'gin.H{'],
            'Echo': ['echo.', 'echo.Context', 'echo.New()', 'e.GET'],
            'Gorilla': ['mux.', 'gorilla/mux', 'gorilla/websocket', 'gorilla/sessions'],
            'Fiber': ['fiber.', 'fiber.New()', 'app.Get(', 'fiber.Ctx'],
            'Beego': ['beego.', 'beego.Controller', 'beego.Run()'],
            'Buffalo': ['buffalo.', 'buffalo.App', 'actions.App()'],
            'Chi Router': ['chi.', 'chi.Router', 'chi.NewRouter()'],
            'gRPC': ['grpc.', 'google.golang.org/grpc', 'pb.'],
            'GraphQL': ['graphql-go', 'graphql.', 'graphql.Schema'],
            'gqlgen': ['gqlgen.', 'github.com/99designs/gqlgen']
        }
        
        for framework, patterns in go_frameworks.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='backend',
                    name=framework,
                    path=file_path
                )
        
        # Check for database drivers
        go_db = {
            'MySQL Driver': ['mysql', 'go-sql-driver/mysql'],
            'PostgreSQL Driver': ['pgx', 'pq', 'lib/pq'],
            'SQLite Driver': ['go-sqlite3', 'sqlite3'],
            'MongoDB Driver': ['mongo-driver', 'mongodb'],
            'Redis Driver': ['go-redis', 'redigo']
        }
        
        for db, patterns in go_db.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='backend',
                    name=db,
                    path=file_path
                )
        
        # Check for ORM
        if 'gorm' in content:
            repository.add_technology(
                category='backend',
                name='GORM',
                path=file_path
            )
        
        # Check for REST API
        if (any(x in content for x in ['http.HandleFunc', 'http.ListenAndServe', 'r.Get', 'r.Post', 
                                      'e.GET', 'e.POST', 'gin.Context']) or
            'api/' in file_path.lower()):
            repository.add_technology(
                category='backend',
                name='REST API',
                path=file_path
            )
    
    def _analyze_go_mod(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze Go module file for dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect Go
        repository.add_technology(
            category='backend',
            name='Go',
            path=file_path,
            confidence=1.0
        )
        
        # Check for module name and go version
        go_version_match = re.search(r'go\s+(\d+\.\d+)', content)
        if go_version_match:
            repository.add_technology(
                category='backend',
                name='Go',
                version=go_version_match.group(1),
                path=file_path
            )
        
        # Check for dependencies
        go_techs = {
            'Gin': ['github.com/gin-gonic/gin'],
            'Echo': ['github.com/labstack/echo'],
            'Gorilla': ['github.com/gorilla/mux', 'github.com/gorilla/websocket'],
            'Fiber': ['github.com/gofiber/fiber'],
            'Chi Router': ['github.com/go-chi/chi'],
            'gRPC': ['google.golang.org/grpc'],
            'GraphQL': ['github.com/graphql-go/graphql'],
            'gqlgen': ['github.com/99designs/gqlgen'],
            'GORM': ['gorm.io/gorm', 'github.com/jinzhu/gorm'],
            'MySQL Driver': ['github.com/go-sql-driver/mysql'],
            'PostgreSQL Driver': ['github.com/lib/pq', 'github.com/jackc/pgx'],
            'SQLite Driver': ['github.com/mattn/go-sqlite3'],
            'MongoDB Driver': ['go.mongodb.org/mongo-driver'],
            'Redis Driver': ['github.com/go-redis/redis', 'github.com/gomodule/redigo'],
            'AWS SDK': ['github.com/aws/aws-sdk-go'],
            'Testify': ['github.com/stretchr/testify'],
            'Cobra': ['github.com/spf13/cobra'],
            'Viper': ['github.com/spf13/viper']
        }
        
        for tech, patterns in go_techs.items():
            if any(pattern in content for pattern in patterns):
                # Try to extract version
                version = None
                for pattern in patterns:
                    if pattern in content:
                        version_match = re.search(rf'{re.escape(pattern)}\s+v([\d\.]+)', content)
                        if version_match:
                            version = version_match.group(1)
                            break
                
                repository.add_technology(
                    category='backend',
                    name=tech,
                    version=version,
                    path=file_path
                )
    
    def _analyze_cs_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze C# file for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect C#
        repository.add_technology(
            category='backend',
            name='C#',
            path=file_path,
            confidence=1.0
        )
        
        # Check for ASP.NET
        aspnet_patterns = [
            'Microsoft.AspNetCore', 'IApplicationBuilder', 'IHostBuilder',
            'AddControllers', 'AddRazorPages', 'MapControllers',
            'app.UseRouting', 'app.UseEndpoints', 'Controller',
            'IActionResult', 'ControllerBase'
        ]
        
        if any(pattern in content for pattern in aspnet_patterns):
            repository.add_technology(
                category='backend',
                name='ASP.NET Core',
                path=file_path
            )
            
        # Check for Entity Framework
        ef_patterns = [
            'DbContext', 'OnModelCreating', 'Microsoft.EntityFrameworkCore',
            'DbSet<', 'Entity Framework', 'EF Core'
        ]
        
        if any(pattern in content for pattern in ef_patterns):
            repository.add_technology(
                category='backend',
                name='Entity Framework',
                path=file_path
            )
        
        # Check for REST API
        if ('[ApiController]' in content or 
            '[Route(' in content or 
            'ControllerBase' in content or
            '[HttpGet]' in content):
            repository.add_technology(
                category='backend',
                name='REST API',
                path=file_path
            )
            
        # Check for GraphQL
        if 'GraphQL' in content:
            repository.add_technology(
                category='backend',
                name='GraphQL',
                path=file_path
            )
        
        # Check for Blazor
        if 'Blazor' in content or '@page' in content:
            repository.add_technology(
                category='backend',
                name='Blazor',
                path=file_path
            )
    
    def _analyze_csproj(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze .NET project file for dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect .NET
        repository.add_technology(
            category='backend',
            name='.NET',
            path=file_path,
            confidence=1.0
        )
        
        # Check for .NET version
        sdk_match = re.search(r'<TargetFramework>([^<]+)</TargetFramework>', content)
        if sdk_match:
            repository.add_technology(
                category='backend',
                name='.NET',
                version=sdk_match.group(1),
                path=file_path
            )
        
        # Check for packages
        dotnet_techs = {
            'ASP.NET Core': ['Microsoft.AspNetCore'],
            'Entity Framework': ['Microsoft.EntityFrameworkCore'],
            'ASP.NET MVC': ['Microsoft.AspNetCore.Mvc'],
            'ASP.NET Razor Pages': ['Microsoft.AspNetCore.Razor'],
            'ASP.NET Blazor': ['Microsoft.AspNetCore.Blazor'],
            'Identity': ['Microsoft.AspNetCore.Identity'],
            'SQL Server': ['Microsoft.Data.SqlClient', 'System.Data.SqlClient'],
            'MySQL': ['MySql.Data', 'Pomelo.EntityFrameworkCore.MySql'],
            'PostgreSQL': ['Npgsql'],
            'SQLite': ['Microsoft.Data.Sqlite'],
            'MongoDB': ['MongoDB.Driver'],
            'Redis': ['StackExchange.Redis'],
            'GraphQL': ['GraphQL', 'HotChocolate'],
            'Newtonsoft.Json': ['Newtonsoft.Json'],
            'AutoMapper': ['AutoMapper'],
            'SignalR': ['Microsoft.AspNetCore.SignalR'],
            'gRPC': ['Grpc.AspNetCore'],
            'Swagger': ['Swashbuckle', 'NSwag'],
            'xUnit': ['xunit'],
            'NUnit': ['nunit'],
            'Moq': ['Moq'],
            'Serilog': ['Serilog'],
            'NLog': ['NLog']
        }
        
        for tech, patterns in dotnet_techs.items():
            if any(f"<PackageReference Include=\"{pattern}" in content for pattern in patterns):
                # Try to extract version
                version = None
                for pattern in patterns:
                    pkg_match = re.search(
                        f'<PackageReference Include="{pattern}[^"]*" Version="([^"]+)"', 
                        content
                    )
                    if pkg_match:
                        version = pkg_match.group(1)
                        break
                
                repository.add_technology(
                    category='backend',
                    name=tech,
                    version=version,
                    path=file_path
                )
    
    def _analyze_yaml_config(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze YAML configuration files for backend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Django settings
        if 'INSTALLED_APPS' in content and 'MIDDLEWARE' in content and 'DATABASES' in content:
            repository.add_technology(
                category='backend',
                name='Django',
                path=file_path
            )
            
        # Spring Boot application.yml
        if 'spring:' in content and ('datasource:' in content or 'jpa:' in content):
            repository.add_technology(
                category='backend',
                name='Spring Boot',
                path=file_path
            )
            
        # Ruby on Rails database.yml
        if 'adapter: postgresql' in content or 'adapter: mysql' in content or 'adapter: sqlite3' in content:
            repository.add_technology(
                category='backend',
                name='Ruby on Rails',
                path=file_path
            )
            
        # Check for database connections
        if 'postgresql' in content.lower():
            repository.add_technology(
                category='backend',
                name='PostgreSQL',
                path=file_path
            )
            
        if 'mysql' in content.lower():
            repository.add_technology(
                category='backend',
                name='MySQL',
                path=file_path
            )
            
        if 'mongodb' in content.lower():
            repository.add_technology(
                category='backend',
                name='MongoDB',
                path=file_path
            )
            
        if 'redis' in content.lower():
            repository.add_technology(
                category='backend',
                name='Redis',
                path=file_path
            )
