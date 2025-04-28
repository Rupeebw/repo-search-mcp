# GitLab Repository Analyzer

A comprehensive tool for analyzing GitLab repositories, providing insights into code structure, dependencies, CI/CD configurations, and security practices.

## Features

- **Code Analysis**: Analyze code structure, complexity, and quality metrics
- **Dependency Analysis**: Identify dependencies within repositories and between repositories
- **CI/CD Detection**: Detect and analyze CI/CD configurations and pipelines
- **Security Analysis**: Identify security vulnerabilities and risks
- **Repository Metrics**: Generate metrics on code size, commits, branches, and more
- **Report Generation**: Export analysis results in various formats (JSON, CSV, HTML)

## Installation

### Prerequisites

- Python 3.8 or higher
- Git command-line tools
- Access to GitLab repositories (local or remote)

### Setup

1. Clone the repository:
   ```

## Project Structure

```
gitlab-repo-analyzer/
├── gitlab_repo_analyzer/
│   ├── __init__.py
│   ├── repo_analyzer.py
│   ├── code_analyzer.py
│   ├── dependency_analyzer.py
│   ├── ci_cd_detector.py
│   ├── security_analyzer.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── file_utils.py
│   │   └── git_utils.py
│   └── exporters/
│       ├── __init__.py
│       ├── json_exporter.py
│       ├── csv_exporter.py
│       ├── html_exporter.py
│       └── report_generator.py
├── bin/
│   └── gitlab-analyzer
├── tests/
│   ├── __init__.py
│   ├── test_repo_analyzer.py
│   ├── test_code_analyzer.py
│   └── ...
├── examples/
│   ├── basic_analysis.py
│   ├── dependency_graph.py
│   └── security_report.py
├── docs/
│   ├── conf.py
│   ├── index.rst
│   └── ...
├── .gitlab-ci.yml
├── setup.py
├── requirements.txt
├── README.md
└── LICENSE
```

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make your changes
4. Run tests: `pytest`
5. Commit your changes: `git commit -m 'Add new feature'`
6. Push to the branch: `git push origin feature/new-feature`
7. Submit a pull request

Please make sure your code follows our coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to all contributors who have helped with this project
- Inspired by various code analysis tools and the GitLab API

## Contact

For questions, feedback, or contributions, please open an issue on GitHub or contact the maintainers at example@example.com.

## Advanced Usage

### Analyzing Multiple Repositories

Create a file `repos.txt` with repository paths or URLs:

```
/path/to/local/repo1
https://gitlab.com/username/repo2.git
/path/to/local/repo3
```

Then run:

```bash
gitlab-analyzer analyze-bulk --file repos.txt --output reports/
```

### Integration with CI/CD Pipelines

You can integrate GitLab Repository Analyzer into your CI/CD pipelines to automatically analyze code changes:

```yaml
# .gitlab-ci.yml example
code_analysis:
  stage: test
  script:
    - pip install gitlab-repo-analyzer
    - gitlab-analyzer analyze --path . --output results.json
    - python -c "import json; data=json.load(open('results.json')); exit(1 if data['security']['critical_issues'] > 0 else 0)"
  artifacts:
    paths:
      - results.json
```

### Custom Plugins

You can extend the analyzer with custom plugins:

```python
from gitlab_repo_analyzer.plugins import AnalyzerPlugin

class CustomAnalyzer(AnalyzerPlugin):
    """Custom analyzer plugin."""
    
    def analyze(self, repo_path):
        # Custom analysis logic
        return {
            'custom_metric': 42,
            'custom_findings': ['finding1', 'finding2']
        }

# Register the plugin
from gitlab_repo_analyzer import RepoAnalyzer
analyzer = RepoAnalyzer(repo_path="/path/to/repo")
analyzer.register_plugin(CustomAnalyzer())
results = analyzer.analyze()  # Will include custom analysis results
```

### Dependency Analysis

```bash
gitlab-analyzer analyze-deps --path /path/to/repo --cross-repo
```

This will analyze dependencies within the repository and identify potential dependencies between different repositories in your organization.

### CI/CD Pipeline Analysis

```bash
gitlab-analyzer analyze-cicd --path /path/to/repo
```

Sample output:

```
CI/CD Configuration Analysis:
- CI System: GitLab CI
- Configuration Files: 1 (.gitlab-ci.yml)
- Pipeline Stages: build, test, deploy
- Total Jobs: 7
- Deployment Environments: staging, production
- Testing Coverage: Yes (pytest with coverage)
- Security Scanning: Yes (SAST, dependency scanning)
- Complexity Score: 24 (Medium)
```

### Security Scan

```bash
gitlab-analyzer security --path /path/to/repo --full-scan
```

Sample output:

```
Security Analysis Results:
- Total Issues: 8
- Critical: 1
- High: 2
- Medium: 3
- Low: 2

Critical Issues:
- Hardcoded credentials in config/settings.py (line 45)

High Issues:
- Outdated dependency: django 2.2.4 (CVE-2019-14232)
- SQL Injection vulnerability in app/views.py (line 126)

Recommended Actions:
1. Remove hardcoded credentials and use environment variables
2. Update django to version 3.2.18 or higher
3. Use parameterized queries in app/views.py
```bash
   git clone https://github.com/yourusername/gitlab-repo-analyzer.git
   cd gitlab-repo-analyzer
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the package and dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

## Usage

### Command Line Interface

The GitLab Repository Analyzer provides a command-line interface for easy integration into your workflow:

```bash
# Analyze a local repository
gitlab-analyzer analyze --path /path/to/local/repo

# Analyze a remote GitLab repository
gitlab-analyzer analyze --url https://gitlab.com/username/repo.git

# Analyze multiple repositories
gitlab-analyzer analyze-bulk --file repos.txt

# Generate a comprehensive report
gitlab-analyzer report --path /path/to/local/repo --output report.html

# Check security vulnerabilities
gitlab-analyzer security --path /path/to/local/repo
```

### Configuration

Create a configuration file `.gitlab-analyzer.yml` in your home directory or project directory:

```yaml
gitlab:
  url: https://gitlab.com
  token: your_gitlab_token  # Optional, for accessing private repositories

analysis:
  include:
    - "*.py"
    - "*.js"
    - "*.java"
  exclude:
    - "*/vendor/*"
    - "*/node_modules/*"
    - "*/tests/*"
  
security:
  enable_all: true
  skip:
    - secret_scanning
    - dependency_check
```

### Python API

You can also use the GitLab Repository Analyzer as a Python library:

```python
from gitlab_repo_analyzer import RepoAnalyzer

# Initialize the analyzer
analyzer = RepoAnalyzer(repo_path="/path/to/repo")

# Run a full analysis
results = analyzer.analyze()

# Access specific analysis results
code_metrics = results['code_metrics']
dependencies = results['dependencies']
ci_cd_config = results['ci_cd']
security_issues = results['security']

# Generate a report
analyzer.generate_report(output_path="report.html")
```

## Examples

### Basic Repository Analysis

```bash
gitlab-analyzer analyze --path /path/to/repo --output json
```

Sample output:

```json
{
  "repository": {
    "name": "example-repo",
    "url": "https://gitlab.com/username/example-repo.git",
    "size": "24.5 MB",
    "branches": ["main", "develop", "feature/new-auth"],
    "last_commit": "2023-04-15T12:34:56Z"
  },
  "code_metrics": {
    "total_files": 156,
    "total_lines": 28450,
    "language_breakdown": {
      "Python": "45%",
      "JavaScript": "30%",
      "HTML/CSS": "15%",
      "Other": "10%"
    },
    "complexity": {
      "average_cyclomatic_complexity": 12.3,
      "average_maintainability_index": 68.5
    }
  },
  "dependencies": {
    "total_dependencies": 87,
    "direct_dependencies": 45,
    "transitive_dependencies": 42,
    "vulnerability_count": 3
  },
  "ci_cd": {
    "has_ci_cd": true,
    "ci_type": "GitLab CI",
    "stages": ["build", "test", "deploy"],
    "complexity_score": 24
  }
}