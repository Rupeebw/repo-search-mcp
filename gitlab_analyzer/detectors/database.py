"""
Database technology detector for GitLab Repository Analyzer.
Detects database systems, ORMs, and related technologies.
"""

import re
import json
import yaml
from typing import Dict, List, Any, Optional

from .base_detector import BaseDetector
from ..core.repository import Repository


class DatabaseDetector(BaseDetector):
    """Detector for database technologies."""
    
    def __init__(self):
        """Initialize database detector."""
        super().__init__(name="Database", category="database")
        
        # File patterns to match
        self.file_patterns = [
            # Database configuration files
            "*.sql", "schema.rb", "migrations/*.rb", "migrations/*.php", "migrations/*.py",
            "*.hql", "*.hcl", "*.prisma", "*.gql", "*.graphql",
            "database.yml", "database.yaml", "database.json", "database.xml",
            "db/schema.rb", "db/structure.sql", "db/migrations/*",
            "*/databases/*.tf", "*/database/*.tf",
            
            # ORM models and configuration
            "models/*.py", "models/*.rb", "models/*.php", "models/*.js", "models/*.ts",
            "entities/*.java", "entities/*.kt", "entities/*.ts",
            "*Repository.java", "*Repository.kt", "*Dao.java", "*Dao.kt",
            "repositories/*.ts", "repositories/*.js",
            
            # Configuration files that might contain database settings
            "application.properties", "application.yml", "config/database.yml",
            ".env", ".env.*", "config.js", "config.ts", "config.json",
            "knexfile.js", "sequelize.config.js", "*/connection.js",
            "persistence.xml", "hibernate.cfg.xml",
            
            # Docker and container config files (might contain DB references)
            "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
            "kubernetes/*.yaml", "kubernetes/*.yml",
            "helm/*/values.yaml", "helm/*/values.yml"
        ]
        
        # Content patterns for database detection
        self.content_patterns = {
            # SQL databases
            "PostgreSQL": [
                "postgres", "postgresql", "pg_", "pgdata", "psql", 
                "Postgres", "PostgreSQL", "PGHOST", "PGDATABASE",
                "jdbc:postgresql", "pg_hba.conf", "PgAdmin"
            ],
            "MySQL": [
                "mysql", "mariadb", "innodb", "MyISAM", "MySQL", "MariaDB",
                "MYSQL_", "mysqli_", "jdbc:mysql", "my.cnf", "mysqldump"
            ],
            "SQL Server": [
                "sqlserver", "mssql", "SQL Server", "MSSQL", "jdbc:sqlserver",
                "Microsoft SQL Server", ".mdf", ".ldf", "sp_"
            ],
            "Oracle": [
                "oracle", "OracleDriver", "Oracle", "ORACLE_", "jdbc:oracle",
                "oracledb", "TNS_", "SID=", "SERVICE_NAME="
            ],
            "SQLite": [
                "sqlite", "sqlite3", "SQLite", "sqlite_", "jdbc:sqlite", ".sqlite", ".db"
            ],
            "DB2": [
                "db2", "DB2", "ibm_db", "jdbc:db2", "IBM DB2"
            ],
            
            # NoSQL databases
            "MongoDB": [
                "mongodb", "MongoDB", "MONGO_", "mongoose", "mongo.", "mongo ",
                "MongoClient", "findOne(", "aggregate(", "MongoCollection"
            ],
            "Redis": [
                "redis", "Redis", "REDIS_", "redisClient", "createClient", "SETEX", "HSET",
                "JedisPool", "Lettuce", "RedisTemplate"
            ],
            "Elasticsearch": [
                "elasticsearch", "Elasticsearch", "ELASTIC_", "createIndex", 
                "search(", "elasticsearchClient", "Lucene"
            ],
            "Cassandra": [
                "cassandra", "Cassandra", "CassandraClient", "cql", "CQL", "keyspace",
                "DataStax", "cassandra-driver", "column_family"
            ],
            "DynamoDB": [
                "dynamodb", "DynamoDB", "DYNAMODB_", "DocumentClient", "putItem", "getItem",
                "aws-sdk", "dynamoDbClient"
            ],
            "Couchbase": [
                "couchbase", "Couchbase", "Bucket.", "CouchbaseClient", "cluster.OpenBucket"
            ],
            "Firebase": [
                "firebase", "Firebase", "firestore", "Firestore", "collection(", "doc(",
                "initializeApp", "firebase.database()"
            ],
            "Neo4j": [
                "neo4j", "Neo4j", "NEO4J_", "cypher", "Cypher", "createNode(",
                "GraphDatabase", "RelationshipType"
            ],
            
            # Columnular & time-series databases
            "InfluxDB": [
                "influxdb", "InfluxDB", "INFLUX_", "measurement", "influx-client",
                "Point(", "WritePrecision", "InfluxQLQuery"
            ],
            "Timescale": [
                "timescale", "TimescaleDB", "hypertable", "time_bucket"
            ],
            "ClickHouse": [
                "clickhouse", "ClickHouse", "CLICKHOUSE_", "ClickHouseClient", "MergeTree",
                "ReplacingMergeTree"
            ],
            
            # In-memory databases
            "H2": [
                "h2", "H2", "jdbc:h2", "H2 Database", "org.h2"
            ],
            "HSQLDB": [
                "hsqldb", "HSQLDB", "jdbc:hsqldb", "org.hsqldb"
            ],
            
            # Message queues with persistence
            "Kafka": [
                "kafka", "Kafka", "KAFKA_", "KafkaConsumer", "KafkaProducer", 
                "TopicPartition", "kafkajs"
            ],
            "RabbitMQ": [
                "rabbitmq", "RabbitMQ", "RABBITMQ_", "amqp", "AMQP", "createChannel",
                "MessageProperties", "RabbitTemplate"
            ],
            
            # Object/file storage
            "S3": [
                "s3", "S3", "S3Client", "s3_client", "s3.Bucket", "aws-s3",
                "getObject(", "putObject(", "S3_BUCKET"
            ],
            "MinIO": [
                "minio", "MinIO", "MINIO_", "minioClient", "mc ", "s3:minio"
            ],
            
            # ORM frameworks
            "Hibernate": [
                "hibernate", "Hibernate", "HibernateUtil", "@Entity", "@Table", "@Column",
                "SessionFactory", "EntityManager"
            ],
            "JPA": [
                "javax.persistence", "jakarta.persistence", "@Entity", "@Id", "@GeneratedValue",
                "PersistenceContext", "EntityManager", "CrudRepository"
            ],
            "Sequelize": [
                "sequelize", "Sequelize", "Model.init", "sequelize.define", "DataTypes"
            ],
            "TypeORM": [
                "typeorm", "TypeORM", "@Entity", "@Column", "Repository<",
                "createConnection", "getRepository"
            ],
            "Prisma": [
                "prisma", "Prisma", "PrismaClient", "schema.prisma", "datasource db",
                "generator client"
            ],
            "SQLAlchemy": [
                "sqlalchemy", "SQLAlchemy", "Base.metadata", "Column(", "relationship(",
                "create_engine", "Session", "query("
            ],
            "Django ORM": [
                "django.db", "models.Model", "models.CharField", "models.ForeignKey",
                "objects.filter", "objects.get", "makemigrations", "migrate"
            ],
            "Mongoose": [
                "mongoose", "Mongoose", "mongoose.Schema", "mongoose.model", "mongoose.connect",
                "Schema({", "findById"
            ],
            "Active Record": [
                "ActiveRecord::Base", "ActiveRecord::Migration", "has_many", "belongs_to",
                "create_table", "add_column", "change_column"
            ],
            "GORM": [
                "gorm", "GORM", "gorm.Model", "gorm.Open", "AutoMigrate"
            ],
            "Doctrine": [
                "doctrine", "Doctrine", "EntityManager", "createQueryBuilder",
                "@ORM\\", "@ORM\\Entity", "@ORM\\Column"
            ],
            "Eloquent ORM": [
                "Eloquent", "Illuminate\\Database", "Schema::create", "hasMany(",
                "belongsTo(", "Model extends", "table()"
            ],
            
            # Database migration tools
            "Flyway": [
                "flyway", "Flyway", "flywaydb", "flyway:migrate", "FlywayMigration"
            ],
            "Liquibase": [
                "liquibase", "Liquibase", "changeSet", "databaseChangeLog", "rollback"
            ],
            "Alembic": [
                "alembic", "Alembic", "alembic.ini", "alembic revision", "alembic upgrade"
            ],
            "Knex.js": [
                "knex", "Knex", "knex.schema", "table.increments", "table.string",
                "knexfile"
            ],
            "db-migrate": [
                "db-migrate", "migrations/", "createTable", "addColumn", "changeColumn"
            ]
        }
        
        # Regex patterns for connection string detection
        self.regex_patterns = {
            "Database Connection String": [
                # PostgreSQL connection strings
                r'(?:jdbc:)?postgresql:\/\/([^:]+):?(\d+)?\/?([^?]+)',
                r'postgres(?:ql)?:\/\/[^:]+:[^@]+@[^:\/]+:?\d*\/[^?]+',
                # MySQL connection strings
                r'(?:jdbc:)?mysql:\/\/([^:]+):?(\d+)?\/?([^?]+)',
                r'mysql:\/\/[^:]+:[^@]+@[^:\/]+:?\d*\/[^?]+',
                # MongoDB connection strings
                r'mongodb(?:\+srv)?:\/\/[^:]*:[^@]*@[^\/]+\/?[^?]*',
                r'mongodb:\/\/([^:\/]+):?(\d+)?(?:\/([^?]+))?',
                # Redis connection strings
                r'redis:\/\/[^:]*:[^@]*@[^:]+:?\d*(?:\/\d*)?',
                # General JDBC connection strings
                r'jdbc:[a-z]+:\/\/[^:]+:?(\d+)?\/?([^?]+)',
                # Connection string in quotes/environment variables
                r'[\'"](?:(?:DB|DATABASE|MONGO|REDIS|SQL|PG)_URL)[\'"](?:\s*[:=]\s*)[\'"]([^\'"]+)[\'"]',
                r'(?:DB|DATABASE|MONGO|REDIS|SQL|PG)_URL\s*[:=]\s*[\'"]?([^\'"]+)[\'"]?'
            ],
            "Database Credentials": [
                # Username/password patterns in configuration
                r'(?:username|user)[\'":\s]+[\'"]([^\'"]+)[\'"]',
                r'(?:password|passwd)[\'":\s]+[\'"]([^\'"]+)[\'"]',
                r'(?:host|host_name|hostname)[\'":\s]+[\'"]([^\'"]+)[\'"]',
                r'(?:database|db_name|dbname)[\'":\s]+[\'"]([^\'"]+)[\'"]',
                r'(?:port)[\'":\s]+(\d+)',
                # Database credentials in environment variables
                r'(?:DB|DATABASE|MYSQL|POSTGRES|MONGO|REDIS)_(?:USER|USERNAME)[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                r'(?:DB|DATABASE|MYSQL|POSTGRES|MONGO|REDIS)_(?:PASSWORD|PASSWD)[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                r'(?:DB|DATABASE|MYSQL|POSTGRES|MONGO|REDIS)_(?:HOST|HOSTNAME)[=:]\s*[\'"]?([^\'"]+)[\'"]?',
                r'(?:DB|DATABASE|MYSQL|POSTGRES|MONGO|REDIS)_(?:NAME|DBNAME)[=:]\s*[\'"]?([^\'"]+)[\'"]?',
            ]
        }
    
    def _detect_specialized(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Specialized detection for database technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Analyze configuration files
        if self._is_db_config_file(file_path):
            self._analyze_db_config(repository, content, file_path)
        
        # Analyze ORM files
        elif self._is_orm_file(file_path):
            self._analyze_orm_file(repository, content, file_path)
        
        # Analyze database migration files
        elif self._is_migration_file(file_path):
            self._analyze_migration_file(repository, content, file_path)
        
        # Analyze SQL files
        elif file_path.endswith('.sql'):
            self._analyze_sql_file(repository, content, file_path)
        
        # Check for environment variables and connection strings
        if self._has_db_connection_strings(content):
            self._extract_connection_info(repository, content, file_path)
    
    def _is_db_config_file(self, file_path: str) -> bool:
        """
        Check if the file is a database configuration file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if it's a database configuration file
        """
        db_config_patterns = [
            'database.yml', 'database.yaml', 'database.json', 'database.xml',
            'application.properties', 'application.yml', 'config/database',
            'persistence.xml', 'hibernate.cfg.xml', 'knexfile.js', 'sequelize.config',
            'schema.prisma', 'my.cnf', 'pg_hba.conf'
        ]
        
        return any(pattern in file_path.lower() for pattern in db_config_patterns)
    
    def _is_orm_file(self, file_path: str) -> bool:
        """
        Check if the file is related to ORM models.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if it's an ORM-related file
        """
        orm_patterns = [
            '/models/', 'models.py', '/entities/', 'Repository.java', 'Repository.ts',
            'Dao.java', '/entities/', 'Entity.java', 'Entity.kt'
        ]
        
        return any(pattern in file_path for pattern in orm_patterns)
    
    def _is_migration_file(self, file_path: str) -> bool:
        """
        Check if the file is a database migration file.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if it's a migration file
        """
        migration_patterns = [
            '/migrations/', '_migration', 'migrate_', 'schema.rb', 'structure.sql',
            'alembic/versions/', 'liquibase/'
        ]
        
        return any(pattern in file_path for pattern in migration_patterns)
    
    def _has_db_connection_strings(self, content: str) -> bool:
        """
        Check if the content contains database connection strings.
        
        Args:
            content: Content to check
            
        Returns:
            True if database connection strings are found
        """
        connection_patterns = [
            'jdbc:', 'mongodb://', 'postgresql://', 'mysql://', 'database_url',
            'db_url', 'redis://', 'mongodb+srv://', 'sqlserver://', 'oracle://',
            'connection_string', 'connection-string', 'connectionString',
            'DB_HOST', 'DATABASE_URL', 'MONGODB_URI', 'REDIS_URL', 'POSTGRES_URL'
        ]
        
        return any(pattern.lower() in content.lower() for pattern in connection_patterns)
    
    def _analyze_db_config(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze database configuration files.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Try to parse as YAML
        if file_path.endswith(('.yml', '.yaml')):
            try:
                yaml_data = yaml.safe_load(content)
                if yaml_data:
                    self._extract_db_from_config_dict(repository, yaml_data, file_path)
            except yaml.YAMLError:
                pass
        
        # Try to parse as JSON
        elif file_path.endswith('.json'):
            try:
                json_data = json.loads(content)
                if json_data:
                    self._extract_db_from_config_dict(repository, json_data, file_path)
            except json.JSONDecodeError:
                pass
        
        # Properties files
        elif file_path.endswith('.properties'):
            self._extract_db_from_properties(repository, content, file_path)
        
        # XML files
        elif file_path.endswith('.xml'):
            self._extract_db_from_xml(repository, content, file_path)
        
        # Environment files
        elif '.env' in file_path:
            self._extract_db_from_dotenv(repository, content, file_path)
        
        # General scan for database identifiers
        self._scan_for_db_tech(repository, content, file_path)
    
    def _extract_db_from_config_dict(self, repository: Repository, config: Dict[str, Any], file_path: str) -> None:
        """
        Extract database info from configuration dictionary (parsed YAML/JSON).
        
        Args:
            repository: Repository to update
            config: Configuration dictionary
            file_path: Path to the file
        """
        # Check for database section in config
        db_section = None
        
        # Common database config section names
        db_section_names = ['database', 'db', 'databases', 'datasource', 'data-source', 
                           'spring.datasource', 'mongo', 'redis', 'sql', 'mysql', 
                           'postgresql', 'postgres', 'oracle', 'mssql', 'sqlserver']
        
        # Try to find database section
        for section_name in db_section_names:
            # Handle nested paths like spring.datasource
            if '.' in section_name:
                parts = section_name.split('.')
                current = config
                found = True
                
                for part in parts:
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    else:
                        found = False
                        break
                
                if found:
                    db_section = current
                    break
            elif section_name in config:
                db_section = config[section_name]
                break
        
        # Process database section if found
        if db_section:
            # Look for database type/driver
            db_type = None
            
            type_keys = ['type', 'driver', 'dialect', 'adapter', 'client', 'engine', 'platform']
            
            for key in type_keys:
                if isinstance(db_section, dict) and key in db_section:
                    db_type = str(db_section[key]).lower()
                    break
            
            # If no explicit type, try to infer from URL or other fields
            if not db_type:
                url_keys = ['url', 'uri', 'connection-url', 'connection_url', 'connectionUrl', 'jdbc-url', 'jdbc_url']
                
                for key in url_keys:
                    if isinstance(db_section, dict) and key in db_section:
                        url = str(db_section[key])
                        db_type = self._infer_db_type_from_url(url)
                        if db_type:
                            break
            
            # Determine database technology from type
            if db_type:
                db_tech = self._map_db_type_to_tech(db_type)
                
                if db_tech:
                    repository.add_technology(
                        category='database',
                        name=db_tech,
                        path=file_path
                    )
        
        # Also check for ORM configuration
        orm_sections = ['hibernate', 'jpa', 'sequelize', 'mongoose', 'typeorm', 'prisma', 'active_record']
        
        for section_name in orm_sections:
            if section_name in config:
                repository.add_technology(
                    category='database',
                    name=self._capitalize_tech_name(section_name),
                    path=file_path
                )
    
    def _extract_db_from_properties(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Extract database info from properties files.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Parse properties file
        properties = {}
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split('=', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                properties[key] = value
        
        # Look for database connection properties
        db_url_keys = [
            'spring.datasource.url', 'database.url', 'db.url', 'jdbc.url',
            'hibernate.connection.url', 'javax.persistence.jdbc.url',
            'jakarta.persistence.jdbc.url', 'datasource.url'
        ]
        
        for key in db_url_keys:
            if key in properties:
                url = properties[key]
                db_type = self._infer_db_type_from_url(url)
                
                if db_type:
                    db_tech = self._map_db_type_to_tech(db_type)
                    
                    if db_tech:
                        repository.add_technology(
                            category='database',
                            name=db_tech,
                            path=file_path
                        )
        
        # Look for ORM properties
        orm_keys = {
            'hibernate': 'Hibernate',
            'jpa': 'JPA',
            'javax.persistence': 'JPA',
            'jakarta.persistence': 'JPA',
            'eclipselink': 'EclipseLink',
            'openjpa': 'OpenJPA'
        }
        
        for key_prefix, tech_name in orm_keys.items():
            for prop_key in properties:
                if prop_key.startswith(key_prefix):
                    repository.add_technology(
                        category='database',
                        name=tech_name,
                        path=file_path
                    )
                    break
    
    def _extract_db_from_xml(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Extract database info from XML configuration files.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Look for Hibernate configuration
        if '<hibernate-configuration>' in content or '<hibernate-mapping>' in content:
            repository.add_technology(
                category='database',
                name='Hibernate',
                path=file_path
            )
            
            # Check for database dialect
            dialect_match = re.search(r'<property\s+name="hibernate.dialect">([^<]+)</property>', content)
            if dialect_match:
                dialect = dialect_match.group(1)
                
                if 'mysql' in dialect.lower():
                    repository.add_technology(
                        category='database',
                        name='MySQL',
                        path=file_path
                    )
                elif 'postgresql' in dialect.lower() or 'postgres' in dialect.lower():
                    repository.add_technology(
                        category='database',
                        name='PostgreSQL',
                        path=file_path
                    )
                elif 'oracle' in dialect.lower():
                    repository.add_technology(
                        category='database',
                        name='Oracle',
                        path=file_path
                    )
                elif 'sqlserver' in dialect.lower() or 'mssql' in dialect.lower():
                    repository.add_technology(
                        category='database',
                        name='SQL Server',
                        path=file_path
                    )
                elif 'h2' in dialect.lower():
                    repository.add_technology(
                        category='database',
                        name='H2',
                        path=file_path
                    )
                elif 'hsql' in dialect.lower():
                    repository.add_technology(
                        category='database',
                        name='HSQLDB',
                        path=file_path
                    )
            
            # Check for connection URL
            url_match = re.search(r'<property\s+name="hibernate.connection.url">([^<]+)</property>', content)
            if url_match:
                url = url_match.group(1)
                db_type = self._infer_db_type_from_url(url)
                
                if db_type:
                    db_tech = self._map_db_type_to_tech(db_type)
                    
                    if db_tech:
                        repository.add_technology(
                            category='database',
                            name=db_tech,
                            path=file_path
                        )
        
        # Look for JPA persistence.xml
        if '<persistence' in content and '<persistence-unit' in content:
            repository.add_technology(
                category='database',
                name='JPA',
                path=file_path
            )
            
            # Check for provider
            provider_match = re.search(r'<provider>([^<]+)</provider>', content)
            if provider_match:
                provider = provider_match.group(1).lower()
                
                if 'hibernate' in provider:
                    repository.add_technology(
                        category='database',
                        name='Hibernate',
                        path=file_path
                    )
                elif 'eclipse' in provider:
                    repository.add_technology(
                        category='database',
                        name='EclipseLink',
                        path=file_path
                    )
                elif 'openjpa' in provider:
                    repository.add_technology(
                        category='database',
                        name='OpenJPA',
                        path=file_path
                    )
            
            # Check for JDBC URL
            url_match = re.search(r'<property\s+name="(?:javax|jakarta).persistence.jdbc.url"\s+value="([^"]+)"', content)
            if url_match:
                url = url_match.group(1)
                db_type = self._infer_db_type_from_url(url)
                
                if db_type:
                    db_tech = self._map_db_type_to_tech(db_type)
                    
                    if db_tech:
                        repository.add_technology(
                            category='database',
                            name=db_tech,
                            path=file_path
                        )
        
        # Look for MyBatis configuration
        if '<mapper ' in content or '<resultMap ' in content or 'mybatis' in content.lower():
            repository.add_technology(
                category='database',
                name='MyBatis',
                path=file_path
            )
    
    def _extract_db_from_dotenv(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Extract database info from .env files.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Parse .env file
        env_vars = {}
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split('=', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip().strip('\'"')  # Remove quotes
                env_vars[key] = value
        
        # Look for database URLs
        db_url_keys = [
            'DATABASE_URL', 'DB_URL', 'POSTGRES_URL', 'POSTGRESQL_URL', 'MYSQL_URL', 
            'MONGODB_URI', 'MONGO_URL', 'REDIS_URL', 'SQL_SERVER_URL', 'ORACLE_URL',
            'SQLITE_URL', 'DATABASE_CONNECTION', 'DB_CONNECTION_STRING'
        ]
        
        for key in db_url_keys:
            if key in env_vars:
                url = env_vars[key]
                db_type = self._infer_db_type_from_url(url)
                
                if db_type:
                    db_tech = self._map_db_type_to_tech(db_type)
                    
                    if db_tech:
                        repository.add_technology(
                            category='database',
                            name=db_tech,
                            path=file_path
                        )
        
        # Look for database host/name pairs
        db_host_keys = {
            'POSTGRES_HOST': 'PostgreSQL',
            'PG_HOST': 'PostgreSQL',
            'MYSQL_HOST': 'MySQL',
            'MARIADB_HOST': 'MariaDB',
            'MONGO_HOST': 'MongoDB',
            'MONGODB_HOST': 'MongoDB',
            'REDIS_HOST': 'Redis',
            'SQLSERVER_HOST': 'SQL Server',
            'MSSQL_HOST': 'SQL Server',
            'ORACLE_HOST': 'Oracle',
            'DB_HOST': None  # Generic, needs additional info
        }
        
        for key, tech in db_host_keys.items():
            if key in env_vars:
                if tech:
                    repository.add_technology(
                        category='database',
                        name=tech,
                        path=file_path
                    )
                else:
                    # For generic DB_HOST, try to infer from other variables
                    db_tech = self._infer_db_from_env_vars(env_vars)
                    if db_tech:
                        repository.add_technology(
                            category='database',
                            name=db_tech,
                            path=file_path
                        )
    
    def _analyze_orm_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze ORM model files.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Check for Hibernate/JPA annotations
        if '@Entity' in content or '@Table' in content:
            if '@Entity' in content:
                repository.add_technology(
                    category='database',
                    name='JPA',
                    path=file_path
                )
            
            if 'import javax.persistence' in content or 'import jakarta.persistence' in content:
                repository.add_technology(
                    category='database',
                    name='JPA',
                    path=file_path
                )
            
            if 'import org.hibernate' in content:
                repository.add_technology(
                    category='database',
                    name='Hibernate',
                    path=file_path
                )
        
        # Check for Django ORM
        if 'from django.db import models' in content or 'models.Model' in content:
            repository.add_technology(
                category='database',
                name='Django ORM',
                path=file_path
            )
        
        # Check for SQLAlchemy
        if 'import sqlalchemy' in content or 'from sqlalchemy import' in content:
            repository.add_technology(
                category='database',
                name='SQLAlchemy',
                path=file_path
            )
        
        # Check for Sequelize
        if 'import { Model, DataTypes }' in content or 'sequelize.define' in content:
            repository.add_technology(
                category='database',
                name='Sequelize',
                path=file_path
            )
        
        # Check for TypeORM
        if 'import { Entity, Column }' in content or '@Entity()' in content:
            repository.add_technology(
                category='database',
                name='TypeORM',
                path=file_path
            )
        
        # Check for Prisma
        if 'import { PrismaClient }' in content or 'new PrismaClient' in content:
            repository.add_technology(
                category='database',
                name='Prisma',
                path=file_path
            )
        
        # Check for Mongoose
        if 'mongoose.Schema' in content or 'mongoose.model' in content:
            repository.add_technology(
                category='database',
                name='Mongoose',
                path=file_path
            )
            
            repository.add_technology(
                category='database',
                name='MongoDB',
                path=file_path
            )
        
        # Check for Active Record
        if 'class' in content and ('< ActiveRecord::Base' in content or 
                                   'ApplicationRecord' in content or 
                                   'has_many' in content or 
                                   'belongs_to' in content):
            repository.add_technology(
                category='database',
                name='Active Record',
                path=file_path
            )
        
        # Check for GORM
        if 'gorm.Model' in content or 'gorm.Open' in content:
            repository.add_technology(
                category='database',
                name='GORM',
                path=file_path
            )
    
    def _analyze_migration_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze database migration files.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Check for Rails migrations
        if 'class' in content and 'ActiveRecord::Migration' in content:
            repository.add_technology(
                category='database',
                name='Active Record',
                path=file_path
            )
        
        # Check for Alembic migrations
        if 'import alembic' in content or 'from alembic import' in content:
            repository.add_technology(
                category='database',
                name='Alembic',
                path=file_path
            )
            
            repository.add_technology(
                category='database',
                name='SQLAlchemy',
                path=file_path
            )
        
        # Check for Sequelize migrations
        if "'use strict';" in content and 'module.exports' in content and 'queryInterface' in content:
            repository.add_technology(
                category='database',
                name='Sequelize',
                path=file_path
            )
        
        # Check for Knex migrations
        if 'exports.up' in content and 'exports.down' in content:
            repository.add_technology(
                category='database',
                name='Knex.js',
                path=file_path
            )
        
        # Check for Django migrations
        if 'from django.db import migrations' in content or 'class Migration(' in content:
            repository.add_technology(
                category='database',
                name='Django ORM',
                path=file_path
            )
        
        # Check for Flyway migrations
        if file_path.lower().endswith('.sql') and re.search(r'V\d+__[A-Za-z0-9_]+\.sql$', file_path):
            repository.add_technology(
                category='database',
                name='Flyway',
                path=file_path
            )
        
        # Check for Liquibase migrations
        if '<changeSet ' in content or '<databaseChangeLog ' in content:
            repository.add_technology(
                category='database',
                name='Liquibase',
                path=file_path
            )
        
        # Try to determine database from table creation syntax
        if 'CREATE TABLE' in content.upper():
            # PostgreSQL specific syntax
            if 'SERIAL' in content.upper() or 'PRIMARY KEY GENERATED ALWAYS AS IDENTITY' in content.upper():
                repository.add_technology(
                    category='database',
                    name='PostgreSQL',
                    path=file_path
                )
            # MySQL specific syntax
            elif 'ENGINE=' in content or 'AUTO_INCREMENT' in content:
                repository.add_technology(
                    category='database',
                    name='MySQL',
                    path=file_path
                )
            # SQL Server specific syntax
            elif 'IDENTITY(' in content.upper() or 'NVARCHAR' in content.upper():
                repository.add_technology(
                    category='database',
                    name='SQL Server',
                    path=file_path
                )
            # Oracle specific syntax
            elif 'NUMBER(' in content.upper() or 'VARCHAR2' in content.upper():
                repository.add_technology(
                    category='database',
                    name='Oracle',
                    path=file_path
                )
    
    def _analyze_sql_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze SQL files.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        content_upper = content.upper()
        
        # Check for PostgreSQL specific syntax
        if ('CREATE EXTENSION' in content_upper or 
            'SERIAL' in content_upper or 
            'PRIMARY KEY GENERATED ALWAYS AS IDENTITY' in content_upper or
            'CREATE SEQUENCE' in content_upper or
            'RETURNING' in content_upper):
            repository.add_technology(
                category='database',
                name='PostgreSQL',
                path=file_path
            )
        
        # Check for MySQL specific syntax
        elif ('ENGINE=' in content or 
             'AUTO_INCREMENT' in content or
             'SHOW TABLES' in content_upper or
             '`id` INT NOT NULL AUTO_INCREMENT' in content):
            repository.add_technology(
                category='database',
                name='MySQL',
                path=file_path
            )
        
        # Check for SQL Server specific syntax
        elif ('IDENTITY(' in content_upper or 
             'NVARCHAR' in content_upper or
             'EXEC sp_' in content_upper or
             'BEGIN TRANSACTION' in content_upper):
            repository.add_technology(
                category='database',
                name='SQL Server',
                path=file_path
            )
        
        # Check for Oracle specific syntax
        elif ('NUMBER(' in content_upper or 
             'VARCHAR2' in content_upper or
             'CONNECT SYS/' in content_upper or
             'CREATE SEQUENCE' in content_upper and 'NOCACHE' in content_upper):
            repository.add_technology(
                category='database',
                name='Oracle',
                path=file_path
            )
        
        # Check for SQLite specific syntax
        elif ('PRAGMA' in content_upper or 
             'SQLITE_' in content_upper):
            repository.add_technology(
                category='database',
                name='SQLite',
                path=file_path
            )
    
    def _extract_connection_info(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Extract database connection information from content.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Look for connection strings
        for pattern in self.regex_patterns.get('Database Connection String', []):
            matches = re.finditer(pattern, content)
            for match in matches:
                conn_string = match.group(0)
                db_type = self._infer_db_type_from_url(conn_string)
                
                if db_type:
                    db_tech = self._map_db_type_to_tech(db_type)
                    
                    if db_tech:
                        repository.add_technology(
                            category='database',
                            name=db_tech,
                            path=file_path
                        )
    
    def _scan_for_db_tech(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Scan content for various database technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        content_lower = content.lower()
        
        # Check content for known database connections
        db_connection_patterns = {
            'jdbc:postgresql': 'PostgreSQL',
            'jdbc:mysql': 'MySQL',
            'jdbc:mariadb': 'MariaDB',
            'jdbc:sqlserver': 'SQL Server',
            'jdbc:oracle': 'Oracle',
            'jdbc:db2': 'DB2',
            'jdbc:sqlite': 'SQLite',
            'jdbc:h2': 'H2',
            'jdbc:hsqldb': 'HSQLDB',
            'postgres://': 'PostgreSQL',
            'postgresql://': 'PostgreSQL',
            'mysql://': 'MySQL',
            'mariadb://': 'MariaDB',
            'mongodb://': 'MongoDB',
            'mongodb+srv://': 'MongoDB',
            'redis://': 'Redis',
            'elasticsearch://': 'Elasticsearch',
            'cassandra://': 'Cassandra',
            'dynamodb://': 'DynamoDB',
            'neo4j://': 'Neo4j'
        }
        
        for pattern, tech in db_connection_patterns.items():
            if pattern in content_lower:
                repository.add_technology(
                    category='database',
                    name=tech,
                    path=file_path
                )
        
        # Check for ORM imports and usage
        orm_patterns = {
            'import javax.persistence': 'JPA',
            'import jakarta.persistence': 'JPA',
            'import org.hibernate': 'Hibernate',
            'import jakarta.jpa': 'JPA',
            'import javax.jpa': 'JPA',
            'import jakarta.persistence.Entity': 'JPA',
            'import javax.persistence.Entity': 'JPA',
            'import org.sequelize': 'Sequelize',
            'import { Sequelize,': 'Sequelize',
            'import sequelize': 'Sequelize',
            'import type { Prisma } from': 'Prisma',
            'import { PrismaClient }': 'Prisma',
            'import { Entity, Column,': 'TypeORM',
            'import typeorm': 'TypeORM',
            'import { mongoose }': 'Mongoose',
            'import mongoose': 'Mongoose',
            'import sqlalchemy': 'SQLAlchemy',
            'from sqlalchemy import': 'SQLAlchemy',
            'import gorm': 'GORM',
            '_gorm "gorm.io/gorm"': 'GORM',
            'from django.db import models': 'Django ORM',
            'import models': 'Django ORM',
            'ActiveRecord::Base': 'Active Record',
            'use Doctrine\\ORM': 'Doctrine'
        }
        
        for pattern, tech in orm_patterns.items():
            if pattern in content:
                repository.add_technology(
                    category='database',
                    name=tech,
                    path=file_path
                )
    
    def _infer_db_type_from_url(self, url: str) -> Optional[str]:
        """
        Infer database type from connection URL.
        
        Args:
            url: Database connection URL
            
        Returns:
            Database type or None if not recognized
        """
        url_lower = url.lower()
        
        if 'postgres' in url_lower or 'postgresql' in url_lower:
            return 'postgresql'
        elif 'mysql' in url_lower:
            return 'mysql'
        elif 'mariadb' in url_lower:
            return 'mariadb'
        elif 'mongodb' in url_lower or 'mongo://' in url_lower:
            return 'mongodb'
        elif 'redis' in url_lower:
            return 'redis'
        elif 'sqlserver' in url_lower or 'mssql' in url_lower:
            return 'sqlserver'
        elif 'oracle' in url_lower:
            return 'oracle'
        elif 'sqlite' in url_lower:
            return 'sqlite'
        elif 'db2' in url_lower:
            return 'db2'
        elif 'h2' in url_lower:
            return 'h2'
        elif 'hsql' in url_lower:
            return 'hsqldb'
        elif 'elasticsearch' in url_lower:
            return 'elasticsearch'
        elif 'cassandra' in url_lower:
            return 'cassandra'
        elif 'dynamodb' in url_lower:
            return 'dynamodb'
        elif 'neo4j' in url_lower:
            return 'neo4j'
        
        return None
    
    def _map_db_type_to_tech(self, db_type: str) -> Optional[str]:
        """
        Map database type to technology name.
        
        Args:
            db_type: Database type string
            
        Returns:
            Technology name or None if not recognized
        """
        db_type_lower = db_type.lower()
        
        # Define mapping of database types to technology names
        mapping = {
            'postgresql': 'PostgreSQL',
            'postgres': 'PostgreSQL',
            'mysql': 'MySQL',
            'mariadb': 'MariaDB',
            'mongodb': 'MongoDB',
            'mongo': 'MongoDB',
            'redis': 'Redis',
            'sqlserver': 'SQL Server',
            'mssql': 'SQL Server',
            'oracle': 'Oracle',
            'sqlite': 'SQLite',
            'db2': 'DB2',
            'h2': 'H2',
            'hsqldb': 'HSQLDB',
            'hsql': 'HSQLDB',
            'elasticsearch': 'Elasticsearch',
            'cassandra': 'Cassandra',
            'dynamodb': 'DynamoDB',
            'neo4j': 'Neo4j'
        }
        
        return mapping.get(db_type_lower)
    
    def _infer_db_from_env_vars(self, env_vars: Dict[str, str]) -> Optional[str]:
        """
        Infer database type from environment variables.
        
        Args:
            env_vars: Dictionary of environment variables
            
        Returns:
            Database technology name or None if not inferred
        """
        # Check for database type-specific variables
        db_type_keys = {
            'DB_TYPE': None,  # Direct value
            'DB_DIALECT': None,  # Direct value
            'DB_DRIVER': None,  # Direct value
            'POSTGRES': 'PostgreSQL',
            'PG': 'PostgreSQL',
            'MYSQL': 'MySQL',
            'MARIADB': 'MariaDB',
            'MONGO': 'MongoDB',
            'REDIS': 'Redis',
            'SQLSERVER': 'SQL Server',
            'MSSQL': 'SQL Server',
            'ORACLE': 'Oracle',
            'SQLITE': 'SQLite'
        }
        
        # First try direct DB_TYPE variables
        for key, tech in db_type_keys.items():
            if key in env_vars:
                if tech:
                    return tech
                else:
                    # For DB_TYPE variables, use the value itself
                    db_type = env_vars[key].lower()
                    return self._map_db_type_to_tech(db_type)
        
        # Then check for database-specific prefixes in any variable
        prefixes = {
            'POSTGRES_': 'PostgreSQL',
            'PG_': 'PostgreSQL',
            'MYSQL_': 'MySQL',
            'MARIADB_': 'MariaDB',
            'MONGO_': 'MongoDB',
            'MONGODB_': 'MongoDB',
            'REDIS_': 'Redis',
            'SQLSERVER_': 'SQL Server',
            'MSSQL_': 'SQL Server',
            'ORACLE_': 'Oracle',
            'SQLITE_': 'SQLite'
        }
        
        for key in env_vars.keys():
            for prefix, tech in prefixes.items():
                if key.startswith(prefix):
                    return tech
        
        return None
    
    def _capitalize_tech_name(self, name: str) -> str:
        """
        Capitalize technology name properly.
        
        Args:
            name: Technology name
            
        Returns:
            Properly capitalized name
        """
        # Convert snake_case to space-separated words and capitalize
        words = name.replace('_', ' ').split()
        capitalized = ' '.join(word.capitalize() for word in words)
        
        # Handle special cases
        special_cases = {
            'Postgresql': 'PostgreSQL',
            'Mysql': 'MySQL',
            'Mariadb': 'MariaDB',
            'Mongodb': 'MongoDB',
            'Sqlserver': 'SQL Server',
            'Dynamodb': 'DynamoDB',
            'Neo4j': 'Neo4j',
            'Elasticsearch': 'Elasticsearch',
            'Hsqldb': 'HSQLDB',
            'Jpa': 'JPA',
            'Orm': 'ORM',
            'Gorm': 'GORM',
            'Active Record': 'Active Record',
            'Typeorm': 'TypeORM'
        }
        
        return special_cases.get(capitalized, capitalized)
