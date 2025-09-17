"""
File handling utilities for code analysis
Handles ZIP extraction, file validation, and parsing
"""
import os
import zipfile
import tempfile
from typing import List, Dict, Optional
import magic
import shutil

class FileHandler:
    """Handles file operations for code analysis"""

    # Supported file extensions and their languages
    SUPPORTED_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.go': 'go',
        '.php': 'php',
        '.rb': 'ruby',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.sql': 'sql'
    }

    # Files to ignore during analysis
    IGNORE_PATTERNS = {
        '.git/', '__pycache__/', 'node_modules/', '.vscode/', '.idea/',
        'venv/', 'env/', 'build/', 'dist/', 'target/', '.pytest_cache/',
        '.mypy_cache/', '.coverage', '*.pyc', '*.pyo', '*.class',
        '*.jar', '*.war', '*.min.js', '*.bundle.js'
    }

    def extract_and_validate_zip(self, zip_path: str, extract_dir: str) -> List[str]:
        """
        Extract ZIP file and return list of supported code files
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Check ZIP file integrity
                if zip_ref.testzip():
                    raise ValueError("ZIP file is corrupted")

                # Extract all files
                zip_ref.extractall(extract_dir)

            # Find supported code files
            code_files = self._find_code_files(extract_dir)

            # Validate file count
            if len(code_files) > 100:
                raise ValueError("Too many files to analyze. Maximum: 100 files")

            return code_files

        except zipfile.BadZipFile:
            raise ValueError("Invalid ZIP file")
        except Exception as e:
            raise ValueError(f"Failed to extract ZIP: {str(e)}")

    def _find_code_files(self, directory: str) -> List[str]:
        """Recursively find all supported code files"""
        code_files = []

        for root, dirs, files in os.walk(directory):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not self._should_ignore(d + '/')]

            for file in files:
                if self._should_ignore(file):
                    continue

                file_path = os.path.join(root, file)

                # Check if file extension is supported
                _, ext = os.path.splitext(file.lower())
                if ext in self.SUPPORTED_EXTENSIONS:
                    # Validate file size (max 1MB per file)
                    if os.path.getsize(file_path) > 1024 * 1024:
                        continue

                    # Validate it's a text file
                    if self._is_text_file(file_path):
                        code_files.append(file_path)

        return sorted(code_files)

    def _should_ignore(self, path: str) -> bool:
        """Check if file/directory should be ignored"""
        path_lower = path.lower()

        for pattern in self.IGNORE_PATTERNS:
            if pattern.endswith('/'):
                # Directory pattern
                if pattern.rstrip('/') in path_lower:
                    return True
            elif pattern.startswith('*.'):
                # File extension pattern
                if path_lower.endswith(pattern[1:]):
                    return True
            else:
                # Exact match pattern
                if pattern in path_lower:
                    return True

        return False

    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is a text file (not binary)"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Try to read first 1024 bytes
                sample = f.read(1024)
                # If we can read it as UTF-8, it's probably text
                return True
        except (UnicodeDecodeError, IOError):
            return False

    def get_file_language(self, filename: str) -> Optional[str]:
        """Determine programming language from filename"""
        _, ext = os.path.splitext(filename.lower())
        return self.SUPPORTED_EXTENSIONS.get(ext)

    def get_file_stats(self, file_path: str) -> Dict:
        """Get basic statistics about a code file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            lines = content.split('\n')

            return {
                'size_bytes': len(content),
                'line_count': len(lines),
                'non_empty_lines': len([line for line in lines if line.strip()]),
                'language': self.get_file_language(file_path),
                'has_content': len(content.strip()) > 0
            }
        except Exception:
            return {
                'size_bytes': 0,
                'line_count': 0,
                'non_empty_lines': 0,
                'language': None,
                'has_content': False
            }
