"""
Code parsing utilities for different programming languages
Extracts functions, classes, and important code structures
"""

import ast
import re
from typing import Dict, List, Optional, Tuple

class CodebaseParser:
    """Main parser for analyzing code structure"""

    def parse_python_file(self, content: str, filename: str) -> Dict:
        """Parse Python file and extract structure"""
        try:
            tree = ast.parse(content)

            functions = []
            classes = []
            imports = []

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append({
                        'name': node.name,
                        'line_start': node.lineno,
                        'line_end': node.end_lineno or node.lineno,
                        'is_async': isinstance(node, ast.AsyncFunctionDef),
                        'args': [arg.arg for arg in node.args.args]
                    })

                elif isinstance(node, ast.ClassDef):
                    classes.append({
                        'name': node.name,
                        'line_start': node.lineno,
                        'line_end': node.end_lineno or node.lineno,
                        'bases': [ast.unparse(base) for base in node.bases]
                    })

                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.append({
                                'module': alias.name,
                                'alias': alias.asname,
                                'type': 'import'
                            })
                    else:
                        for alias in node.names:
                            imports.append({
                                'module': node.module,
                                'name': alias.name,
                                'alias': alias.asname,
                                'type': 'from_import'
                            })

            return {
                'language': 'python',
                'functions': functions,
                'classes': classes,
                'imports': imports,
                'complexity_score': self._calculate_complexity(content)
            }

        except SyntaxError as e:
            return {
                'language': 'python',
                'error': f'Syntax error: {str(e)}',
                'functions': [],
                'classes': [],
                'imports': [],
                'complexity_score': 0
            }

    def parse_javascript_file(self, content: str, filename: str) -> Dict:
        """Parse JavaScript file and extract basic structure"""
        # Simple regex-based parsing for JavaScript (good enough for MVP)

        # Find functions
        function_pattern = r'(?:function\s+(\w+)|(\w+)\s*=\s*function|(\w+)\s*=\s*\([^)]*\)\s*=>)'
        functions = []
        for match in re.finditer(function_pattern, content):
            func_name = match.group(1) or match.group(2) or match.group(3)
            if func_name:
                line_no = content[:match.start()].count('\n') + 1
                functions.append({
                    'name': func_name,
                    'line_start': line_no,
                    'type': 'function'
                })

        # Find classes
        class_pattern = r'class\s+(\w+)'
        classes = []
        for match in re.finditer(class_pattern, content):
            class_name = match.group(1)
            line_no = content[:match.start()].count('\n') + 1
            classes.append({
                'name': class_name,
                'line_start': line_no
            })

        # Find imports/requires
        import_pattern = r'(?:import\s+.*?from\s+[\'"]([^\'"]+)[\'"]|require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\))'
        imports = []
        for match in re.finditer(import_pattern, content):
            module = match.group(1) or match.group(2)
            imports.append({
                'module': module,
                'type': 'import' if match.group(1) else 'require'
            })

        return {
            'language': 'javascript',
            'functions': functions,
            'classes': classes,
            'imports': imports,
            'complexity_score': self._calculate_complexity(content)
        }

    def parse_file(self, content: str, filename: str) -> Dict:
        """Parse file based on extension"""
        _, ext = filename.lower().split('.')[-1:] if '.' in filename else ['']

        if ext == 'py':
            return self.parse_python_file(content, filename)
        elif ext in ['js', 'jsx']:
            return self.parse_javascript_file(content, filename)
        else:
            # Basic parsing for other languages
            return {
                'language': ext,
                'functions': [],
                'classes': [],
                'imports': [],
                'complexity_score': self._calculate_complexity(content)
            }

    def _calculate_complexity(self, content: str) -> int:
        """Calculate basic code complexity score"""
        # Simple complexity metrics
        lines = content.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]

        # Count complexity indicators
        complexity_keywords = ['if', 'else', 'elif', 'for', 'while', 'try', 'catch', 'switch', 'case']
        complexity_score = 0

        for line in non_empty_lines:
            line_lower = line.lower()
            for keyword in complexity_keywords:
                complexity_score += line_lower.count(keyword)

        # Normalize by code length
        if len(non_empty_lines) > 0:
            return min(complexity_score * 10 // len(non_empty_lines), 100)

        return 0
