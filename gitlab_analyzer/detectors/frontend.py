"""
Frontend technology detector for GitLab Repository Analyzer.
Detects frontend frameworks, libraries, and tools.
"""

import json
import re
from typing import Dict, List, Any, Optional

from .base_detector import BaseDetector
from ..core.repository import Repository
from ..core.utils import extract_version_from_string


class FrontendDetector(BaseDetector):
    """Detector for frontend technologies."""
    
    def __init__(self):
        """Initialize frontend detector."""
        super().__init__(name="Frontend", category="frontend")
        
        # File patterns to match
        self.file_patterns = [
            "*.js", "*.jsx", "*.ts", "*.tsx", "*.vue", "*.html", "*.css", "*.scss", "*.sass",
            "package.json", "webpack.config.js", "vite.config.js", "angular.json", "next.config.js",
            ".babelrc", ".eslintrc", "tsconfig.json", "nuxt.config.js", "tailwind.config.js",
            "postcss.config.js", ".storybook/*", "*.svelte"
        ]
        
        # Simple content patterns for quick detection
        self.content_patterns = {
            "React": ["import React", "from 'react'", "from \"react\"", "React.Component"],
            "Vue.js": ["import Vue", "from 'vue'", "new Vue(", "createApp"],
            "Angular": ["@angular/core", "NgModule", "Component({", "Injectable({"],
            "Svelte": ["<script>", "<style>", "export let", "svelte:"],
            "jQuery": ["$(", "jQuery(", "$.ajax"],
            "Bootstrap": ["navbar-", "btn-", "col-md-", "text-center", "container-fluid"],
            "Tailwind CSS": ["flex", "mx-auto", "px-4", "text-center", "bg-white", "dark:"],
            "SASS/SCSS": ["@mixin", "@include", "$variable", "@extend", "@import"],
            "TypeScript": ["interface ", "type ", "enum ", "as ", "implements "],
            "Next.js": ["import { useRouter }", "next/", "getStaticProps", "getServerSideProps"],
            "Gatsby": ["gatsby-", "graphql`"],
            "Webpack": ["webpack", "module.exports", "entry:", "output:"],
            "Babel": ["@babel/", "babel-", "preset-"],
            "ESLint": ["eslint", "rules:", "extends:"],
            "Jest": ["describe(", "test(", "it(", "expect("],
            "Storybook": ["storiesOf", "Meta>", "Story>"],
            "Redux": ["createStore", "useSelector", "useDispatch", "combineReducers"],
            "MobX": ["observable", "action", "computed", "observer"],
            "GraphQL": ["gql`", "useQuery", "useMutation", "Apollo"],
            "PWA": ["serviceWorker", "manifest.json", "navigator.serviceWorker"],
            "Web Components": ["customElements.define", "attachShadow", "HTMLElement"],
            "D3.js": ["d3.select", "d3.scaleLinear", "d3.axisBottom"],
            "Three.js": ["THREE.", "WebGLRenderer", "PerspectiveCamera"],
            "Material UI": ["@material-ui", "@mui/", "makeStyles", "createTheme"],
            "Chakra UI": ["@chakra-ui", "ChakraProvider", "useDisclosure"]
        }
        
        # Regex patterns for more complex matching
        self.regex_patterns = {
            "React Version": [r'["\']react["\']:\s*["\']([~^>\d\\.]+)["\']'],
            "Vue Version": [r'["\']vue["\']:\s*["\']([~^>\d\\.]+)["\']'],
            "Angular Version": [r'["\']@angular\/core["\']:\s*["\']([~^>\d\\.]+)["\']'],
            "TypeScript Version": [r'["\']typescript["\']:\s*["\']([~^>\d\\.]+)["\']'],
            "Webpack Version": [r'["\']webpack["\']:\s*["\']([~^>\d\\.]+)["\']']
        }
    
    def _detect_specialized(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Specialized detection for frontend technologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Package.json analysis
        if file_path.endswith('package.json'):
            self._analyze_package_json(repository, content, file_path)
        
        # HTML analysis for frameworks that might not be in package.json
        elif file_path.endswith('.html'):
            self._analyze_html(repository, content, file_path)
        
        # CSS/SCSS analysis
        elif any(file_path.endswith(ext) for ext in ['.css', '.scss', '.sass']):
            self._analyze_css(repository, content, file_path)
        
        # Config file analysis
        elif any(config in file_path for config in ['webpack', 'vite', 'babel', 'tailwind']):
            self._analyze_config_file(repository, content, file_path)
    
    def _analyze_package_json(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze package.json for frontend dependencies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        try:
            package_data = json.loads(content)
            
            # Combine dependencies and devDependencies
            all_deps = {}
            if 'dependencies' in package_data:
                all_deps.update(package_data['dependencies'])
            if 'devDependencies' in package_data:
                all_deps.update(package_data['devDependencies'])
            
            # Frontend framework detection
            framework_detected = False
            
            # React detection
            if 'react' in all_deps:
                repository.add_technology(
                    category='frontend',
                    name='React',
                    version=all_deps['react'],
                    path=file_path,
                    confidence=1.0
                )
                framework_detected = True
                
                # Related React technologies
                self._detect_related_tech(repository, all_deps, {
                    'react-router': 'React Router',
                    'react-redux': 'Redux',
                    'redux': 'Redux',
                    'redux-saga': 'Redux Saga',
                    'redux-thunk': 'Redux Thunk',
                    'recoil': 'Recoil',
                    'styled-components': 'Styled Components',
                    'emotion': 'Emotion',
                    'framer-motion': 'Framer Motion'
                }, file_path)
                
                # React frameworks
                if 'next' in all_deps:
                    repository.add_technology(
                        category='frontend',
                        name='Next.js',
                        version=all_deps['next'],
                        path=file_path
                    )
                
                if 'gatsby' in all_deps:
                    repository.add_technology(
                        category='frontend',
                        name='Gatsby',
                        version=all_deps['gatsby'],
                        path=file_path
                    )
            
            # Vue detection
            if 'vue' in all_deps:
                repository.add_technology(
                    category='frontend',
                    name='Vue.js',
                    version=all_deps['vue'],
                    path=file_path,
                    confidence=1.0
                )
                framework_detected = True
                
                # Vue related
                self._detect_related_tech(repository, all_deps, {
                    'vuex': 'Vuex',
                    'vue-router': 'Vue Router',
                    'nuxt': 'Nuxt.js',
                    'quasar': 'Quasar',
                    'vuetify': 'Vuetify'
                }, file_path)
            
            # Angular detection
            if '@angular/core' in all_deps:
                repository.add_technology(
                    category='frontend',
                    name='Angular',
                    version=all_deps['@angular/core'],
                    path=file_path,
                    confidence=1.0
                )
                framework_detected = True
                
                # Angular related
                self._detect_related_tech(repository, all_deps, {
                    '@angular/router': 'Angular Router',
                    '@angular/material': 'Angular Material',
                    'ngrx/store': 'NgRx',
                    '@ngrx/effects': 'NgRx Effects'
                }, file_path)
            
            # Other major frameworks
            if 'svelte' in all_deps:
                repository.add_technology(
                    category='frontend',
                    name='Svelte',
                    version=all_deps['svelte'],
                    path=file_path,
                    confidence=1.0
                )
                framework_detected = True
                
                if 'sveltekit' in all_deps or '@sveltejs/kit' in all_deps:
                    repository.add_technology(
                        category='frontend',
                        name='SvelteKit',
                        version=all_deps.get('sveltekit') or all_deps.get('@sveltejs/kit'),
                        path=file_path
                    )
            
            # UI libraries
            ui_libs = {
                '@mui/material': 'Material UI',
                '@material-ui/core': 'Material UI',
                'antd': 'Ant Design',
                '@chakra-ui/react': 'Chakra UI',
                'bootstrap': 'Bootstrap',
                'tailwindcss': 'Tailwind CSS',
                'bulma': 'Bulma',
                '@mantine/core': 'Mantine',
                'semantic-ui-react': 'Semantic UI',
                '@headlessui/react': 'Headless UI'
            }
            self._detect_related_tech(repository, all_deps, ui_libs, file_path)
            
            # Build tools
            build_tools = {
                'webpack': 'Webpack',
                'vite': 'Vite',
                'parcel': 'Parcel',
                'esbuild': 'esbuild',
                'rollup': 'Rollup',
                'gulp': 'Gulp',
                'grunt': 'Grunt'
            }
            self._detect_related_tech(repository, all_deps, build_tools, file_path)
            
            # Testing frameworks
            test_tools = {
                'jest': 'Jest',
                '@testing-library/react': 'React Testing Library',
                'cypress': 'Cypress',
                'puppeteer': 'Puppeteer',
                'playwright': 'Playwright',
                'karma': 'Karma',
                'jasmine': 'Jasmine',
                'mocha': 'Mocha',
                'chai': 'Chai',
                'enzyme': 'Enzyme',
                'vitest': 'Vitest'
            }
            self._detect_related_tech(repository, all_deps, test_tools, file_path)
            
            # Misc frontend tech
            misc_tech = {
                'typescript': 'TypeScript',
                'graphql': 'GraphQL',
                'apollo-client': 'Apollo Client',
                'urql': 'URQL',
                'swr': 'SWR',
                'react-query': 'React Query',
                'axios': 'Axios',
                'd3': 'D3.js',
                'three': 'Three.js',
                'chart.js': 'Chart.js',
                'lodash': 'Lodash',
                'date-fns': 'date-fns',
                'moment': 'Moment.js',
                'i18next': 'i18next',
                'storybook': 'Storybook',
                '@storybook/react': 'Storybook'
            }
            self._detect_related_tech(repository, all_deps, misc_tech, file_path)
            
        except json.JSONDecodeError:
            # Invalid JSON, skip analysis
            pass
    
    def _detect_related_tech(self, repository: Repository, deps: Dict[str, str], 
                           tech_mapping: Dict[str, str], file_path: str) -> None:
        """
        Detect related technologies from dependencies.
        
        Args:
            repository: Repository to update
            deps: Dependencies dictionary
            tech_mapping: Mapping of package names to technology names
            file_path: Path to the file
        """
        for package, tech_name in tech_mapping.items():
            if any(package in dep for dep in deps):
                # Find the exact package name (for packages with partial matches)
                for dep in deps:
                    if package in dep:
                        repository.add_technology(
                            category='frontend',
                            name=tech_name,
                            version=deps[dep],
                            path=file_path
                        )
                        break
    
    def _analyze_html(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze HTML files for frontend frameworks.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Check for framework-specific HTML markers
        markers = {
            'Angular': ['ng-app', 'ng-controller', 'ng-model', 'ng-repeat', '[(ngModel)]', '*ngIf', '*ngFor'],
            'React': ['data-reactroot', 'react-app', 'reactjs'],
            'Vue.js': ['v-app', 'v-if', 'v-for', 'v-model', 'v-on', 'v-bind', '@click'],
            'jQuery': ['jquery', 'data-toggle', 'data-target'],
            'Bootstrap': ['navbar', 'container-fluid', 'row', 'col-md-', 'btn-primary'],
            'Tailwind CSS': ['class="flex', 'class="grid', 'class="px-', 'class="py-', 'class="mx-', 'class="my-']
        }
        
        for tech, patterns in markers.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='frontend',
                    name=tech,
                    path=file_path,
                    confidence=0.8  # Lower confidence for HTML detection
                )
    
    def _analyze_css(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze CSS/SCSS files for frameworks and methodologies.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # CSS frameworks and methodologies
        if file_path.endswith(('.scss', '.sass')):
            repository.add_technology(
                category='frontend',
                name='SASS/SCSS',
                path=file_path
            )
        
        # BEM methodology
        if re.search(r'[a-z]+-[a-z]+__[a-z]+', content) or re.search(r'[a-z]+__[a-z]+--[a-z]+', content):
            repository.add_technology(
                category='frontend',
                name='BEM Methodology',
                path=file_path
            )
        
        # CSS framework detection
        framework_patterns = {
            'Bootstrap': ['navbar-', 'container-fluid', '.row', '.col-', '.btn-'],
            'Tailwind CSS': ['@tailwind', '@apply', 'space-x-', 'space-y-'],
            'Bulma': ['.is-primary', '.is-info', '.is-success', '.is-warning', '.is-danger'],
            'Foundation': ['.button.primary', '.callout', '.top-bar']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in content for pattern in patterns):
                repository.add_technology(
                    category='frontend',
                    name=framework,
                    path=file_path
                )
    
    def _analyze_config_file(self, repository: Repository, content: str, file_path: str) -> None:
        """
        Analyze configuration files to detect build tools.
        
        Args:
            repository: Repository to update
            content: File content
            file_path: Path to the file
        """
        # Detect build tools from config files
        if 'webpack' in file_path:
            repository.add_technology(
                category='frontend',
                name='Webpack',
                path=file_path
            )
            
            # Look for webpack plugins
            plugins = [
                ('babel-loader', 'Babel'),
                ('css-loader', 'Webpack CSS Loader'),
                ('sass-loader', 'Webpack SASS Loader'),
                ('ts-loader', 'TypeScript'),
                ('file-loader', 'Webpack File Loader'),
                ('html-webpack-plugin', 'HTML Webpack Plugin')
            ]
            
            for plugin, tech in plugins:
                if plugin in content:
                    repository.add_technology(
                        category='frontend',
                        name=tech,
                        path=file_path
                    )
        
        elif 'vite.config' in file_path:
            repository.add_technology(
                category='frontend',
                name='Vite',
                path=file_path
            )
            
        elif 'babel' in file_path:
            repository.add_technology(
                category='frontend',
                name='Babel',
                path=file_path
            )
            
            # Detect babel presets
            presets = [
                ('@babel/preset-react', 'React'),
                ('@babel/preset-typescript', 'TypeScript'),
                ('@babel/preset-env', 'Babel preset-env')
            ]
            
            for preset, tech in presets:
                if preset in content:
                    repository.add_technology(
                        category='frontend',
                        name=tech,
                        path=file_path
                    )
                    
        elif 'tailwind.config' in file_path:
            repository.add_technology(
                category='frontend',
                name='Tailwind CSS',
                path=file_path
            )
