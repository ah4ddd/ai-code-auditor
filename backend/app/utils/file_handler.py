# backend/app/utils/file_handler.py
import os
import zipfile
from typing import List, Dict, Optional

class FileHandler:
    """Enhanced file handler supporting multiple programming languages"""

    # Comprehensive language support with file extensions
    SUPPORTED_EXTENSIONS = {
        # Python
        '.py': 'python',
        '.pyx': 'python',
        '.pyw': 'python',

        # JavaScript/TypeScript
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',

        # Java
        '.java': 'java',
        '.class': 'java',
        '.jar': 'java',

        # C/C++
        '.c': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.c++': 'cpp',
        '.h': 'c',
        '.hpp': 'cpp',
        '.hh': 'cpp',
        '.hxx': 'cpp',

        # C#
        '.cs': 'csharp',
        '.csx': 'csharp',

        # Go
        '.go': 'go',

        # Rust
        '.rs': 'rust',

        # PHP
        '.php': 'php',
        '.php3': 'php',
        '.php4': 'php',
        '.php5': 'php',
        '.phtml': 'php',

        # Ruby
        '.rb': 'ruby',
        '.rbw': 'ruby',
        '.rake': 'ruby',
        '.gemspec': 'ruby',

        # Swift
        '.swift': 'swift',

        # Kotlin
        '.kt': 'kotlin',
        '.kts': 'kotlin',

        # Scala
        '.scala': 'scala',
        '.sc': 'scala',

        # Perl
        '.pl': 'perl',
        '.pm': 'perl',
        '.perl': 'perl',

        # Shell scripts
        '.sh': 'bash',
        '.bash': 'bash',
        '.zsh': 'zsh',
        '.fish': 'fish',
        '.ps1': 'powershell',

        # SQL
        '.sql': 'sql',
        '.psql': 'postgresql',
        '.mysql': 'mysql',

        # Web languages
        '.html': 'html',
        '.htm': 'html',
        '.xml': 'xml',
        '.jsp': 'jsp',
        '.asp': 'asp',
        '.aspx': 'aspx',

        # Other languages
        '.r': 'r',
        '.R': 'r',
        '.m': 'matlab',
        '.lua': 'lua',
        '.dart': 'dart',
        '.vb': 'vbnet',
        '.vbs': 'vbscript',
        '.f': 'fortran',
        '.f90': 'fortran',
        '.pas': 'pascal',
        '.ada': 'ada',
        '.asm': 'assembly',
        '.s': 'assembly',
        '.clj': 'clojure',
        '.ex': 'elixir',
        '.exs': 'elixir',
        '.erl': 'erlang',
        '.hrl': 'erlang',
        '.fs': 'fsharp',
        '.fsx': 'fsharp',
        '.hs': 'haskell',
        '.ml': 'ocaml',
        '.nim': 'nim',
        '.jl': 'julia',
        '.cr': 'crystal'
    }

    # Language-specific vulnerability patterns
    LANGUAGE_VULNERABILITIES = {
        'python': [
            'SQL_INJECTION', 'XSS', 'HARDCODED_SECRETS', 'WEAK_CRYPTO',
            'INSECURE_DESERIALIZATION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL',
            'WEAK_RANDOM', 'INSECURE_AUTH', 'INSUFFICIENT_LOGGING'
        ],
        'javascript': [
            'XSS', 'SQL_INJECTION', 'HARDCODED_SECRETS', 'PROTOTYPE_POLLUTION',
            'UNSAFE_EVAL', 'INSECURE_RANDOMNESS', 'WEAK_CRYPTO', 'DOM_XSS',
            'COMMAND_INJECTION', 'PATH_TRAVERSAL'
        ],
        'java': [
            'SQL_INJECTION', 'XSS', 'INSECURE_DESERIALIZATION', 'XXE',
            'HARDCODED_SECRETS', 'WEAK_CRYPTO', 'PATH_TRAVERSAL',
            'LDAP_INJECTION', 'COMMAND_INJECTION', 'INSECURE_RANDOM'
        ],
        'c': [
            'BUFFER_OVERFLOW', 'FORMAT_STRING', 'USE_AFTER_FREE', 'DOUBLE_FREE',
            'NULL_POINTER_DEREFERENCE', 'INTEGER_OVERFLOW', 'RACE_CONDITION',
            'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'HARDCODED_SECRETS'
        ],
        'cpp': [
            'BUFFER_OVERFLOW', 'USE_AFTER_FREE', 'MEMORY_LEAK', 'DOUBLE_FREE',
            'INTEGER_OVERFLOW', 'RACE_CONDITION', 'WEAK_CRYPTO',
            'HARDCODED_SECRETS', 'COMMAND_INJECTION', 'PATH_TRAVERSAL'
        ],
        'csharp': [
            'SQL_INJECTION', 'XSS', 'INSECURE_DESERIALIZATION', 'XXE',
            'HARDCODED_SECRETS', 'WEAK_CRYPTO', 'PATH_TRAVERSAL',
            'LDAP_INJECTION', 'COMMAND_INJECTION', 'INSECURE_RANDOM'
        ],
        'go': [
            'SQL_INJECTION', 'XSS', 'HARDCODED_SECRETS', 'WEAK_CRYPTO',
            'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'RACE_CONDITION',
            'INSECURE_RANDOM', 'BUFFER_OVERFLOW', 'FORMAT_STRING'
        ],
        'php': [
            'SQL_INJECTION', 'XSS', 'LFI', 'RFI', 'COMMAND_INJECTION',
            'HARDCODED_SECRETS', 'WEAK_CRYPTO', 'INSECURE_DESERIALIZATION',
            'PATH_TRAVERSAL', 'WEAK_SESSION_MANAGEMENT'
        ],
        'ruby': [
            'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'YAML_DESERIALIZATION',
            'HARDCODED_SECRETS', 'WEAK_CRYPTO', 'PATH_TRAVERSAL',
            'MASS_ASSIGNMENT', 'INSECURE_RANDOM', 'OPEN_REDIRECT'
        ],
        'rust': [
            'UNSAFE_CODE', 'INTEGER_OVERFLOW', 'HARDCODED_SECRETS',
            'WEAK_CRYPTO', 'COMMAND_INJECTION', 'PATH_TRAVERSAL',
            'INSECURE_RANDOM', 'BUFFER_OVERFLOW', 'RACE_CONDITION'
        ],
        'swift': [
            'SQL_INJECTION', 'XSS', 'HARDCODED_SECRETS', 'WEAK_CRYPTO',
            'INSECURE_RANDOM', 'PATH_TRAVERSAL', 'MEMORY_CORRUPTION',
            'INSECURE_NETWORKING', 'KEYCHAIN_MISUSE', 'BIOMETRIC_BYPASS'
        ]
    }

    # Files and directories to ignore during analysis
    IGNORE_PATTERNS = {
        '.git/', '__pycache__/', 'node_modules/', '.vscode/', '.idea/',
        'venv/', 'env/', 'build/', 'dist/', 'target/', '.pytest_cache/',
        '.mypy_cache/', '.coverage', '*.pyc', '*.pyo', '*.class',
        '*.jar', '*.war', '*.min.js', '*.bundle.js', 'vendor/',
        'third_party/', 'external/', '.nuget/', 'packages/',
        'bower_components/', 'jspm_packages/', '.cargo/', 'Pods/'
    }

    def extract_and_validate_zip(self, zip_path: str, extract_dir: str) -> List[str]:
        """
        Extract ZIP file and return list of supported code files
        Enhanced with better language detection and filtering
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

            # Validate file count (increased limit for enterprise use)
            if len(code_files) > 500:
                raise ValueError("Too many files to analyze. Maximum: 500 files")

            return code_files

        except zipfile.BadZipFile:
            raise ValueError("Invalid ZIP file")
        except Exception as e:
            raise ValueError(f"Failed to extract ZIP: {str(e)}")

    def _find_code_files(self, directory: str) -> List[str]:
        """Recursively find all supported code files with enhanced filtering"""
        code_files = []
        total_size = 0
        max_total_size = 100 * 1024 * 1024  # 100MB total limit

        for root, dirs, files in os.walk(directory):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not self._should_ignore(d + '/')]

            for file in files:
                if self._should_ignore(file):
                    continue

                file_path = os.path.join(root, file)

                # Check if file extension is supported
                language = self.get_file_language(file)
                if not language:
                    continue

                # Check file size (max 5MB per file for large enterprise files)
                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > 5 * 1024 * 1024:  # 5MB limit per file
                        continue

                    total_size += file_size
                    if total_size > max_total_size:
                        break  # Stop if total size exceeds limit

                except OSError:
                    continue

                # Validate it's a text file
                if self._is_text_file(file_path):
                    code_files.append(file_path)

        return sorted(code_files)

    def _should_ignore(self, path: str) -> bool:
        """Enhanced ignore patterns for better filtering"""
        path_lower = path.lower()

        # Check ignore patterns
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
                # Exact match or substring pattern
                if pattern in path_lower:
                    return True

        # Ignore hidden files and temporary files
        filename = os.path.basename(path_lower)
        if filename.startswith('.') and filename not in ['.htaccess', '.env']:
            return True

        # Ignore backup and temporary files
        if any(filename.endswith(suffix) for suffix in ['.bak', '.tmp', '.temp', '.swp', '~']):
            return True

        # Ignore very large files by name patterns
        if any(pattern in filename for pattern in ['minified', 'compressed', 'bundled']):
            return True

        return False

    def _is_text_file(self, file_path: str) -> bool:
        """Enhanced text file detection with better encoding support"""
        try:
            # Try multiple encodings
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']

            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        # Read first 1KB to check if it's text
                        sample = f.read(1024)

                        # Check for binary indicators
                        if '\x00' in sample:  # Null bytes indicate binary
                            return False

                        # Check if mostly printable characters
                        printable_chars = sum(1 for c in sample if c.isprintable() or c.isspace())
                        if len(sample) > 0 and printable_chars / len(sample) > 0.95:
                            return True

                except UnicodeDecodeError:
                    continue

            return False

        except (IOError, OSError):
            return False

    def get_file_language(self, filename: str) -> Optional[str]:
        """Enhanced language detection with fallback mechanisms"""
        # Primary detection by extension
        _, ext = os.path.splitext(filename.lower())
        language = self.SUPPORTED_EXTENSIONS.get(ext)

        if language:
            return language

        # Fallback detection by filename patterns
        filename_lower = filename.lower()

        # Special files without extensions
        special_files = {
            'dockerfile': 'dockerfile',
            'makefile': 'makefile',
            'rakefile': 'ruby',
            'gemfile': 'ruby',
            'podfile': 'ruby',
            'vagrantfile': 'ruby',
            'gruntfile': 'javascript',
            'gulpfile': 'javascript'
        }

        if filename_lower in special_files:
            return special_files[filename_lower]

        # Check for shebang in shell scripts
        if filename_lower.startswith('run') or filename_lower.startswith('install'):
            return 'bash'

        return None

    def get_language_vulnerabilities(self, language: str) -> List[str]:
        """Get vulnerability types specific to a programming language"""
        return self.LANGUAGE_VULNERABILITIES.get(language, [
            'HARDCODED_SECRETS', 'WEAK_CRYPTO', 'COMMAND_INJECTION',
            'PATH_TRAVERSAL', 'INSECURE_RANDOM'
        ])

    def get_file_stats(self, file_path: str) -> Dict:
        """Enhanced file statistics with language-specific metrics"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            lines = content.split('\n')
            language = self.get_file_language(os.path.basename(file_path))

            stats = {
                'size_bytes': len(content),
                'line_count': len(lines),
                'non_empty_lines': len([line for line in lines if line.strip()]),
                'language': language,
                'has_content': len(content.strip()) > 0,
                'comment_lines': self._count_comment_lines(content, language),
                'vulnerability_types': self.get_language_vulnerabilities(language) if language else []
            }

            return stats

        except Exception:
            return {
                'size_bytes': 0,
                'line_count': 0,
                'non_empty_lines': 0,
                'language': None,
                'has_content': False,
                'comment_lines': 0,
                'vulnerability_types': []
            }

    def _count_comment_lines(self, content: str, language: str) -> int:
        """Count comment lines based on language syntax"""
        if not language:
            return 0

        lines = content.split('\n')
        comment_count = 0

        # Language-specific comment patterns
        single_line_comments = {
            'python': ['#'],
            'javascript': ['//'],
            'typescript': ['//'],
            'java': ['//'],
            'c': ['//'],
            'cpp': ['//'],
            'csharp': ['//'],
            'go': ['//'],
            'rust': ['//'],
            'swift': ['//'],
            'kotlin': ['//'],
            'scala': ['//'],
            'php': ['//', '#'],
            'ruby': ['#'],
            'perl': ['#'],
            'bash': ['#'],
            'r': ['#'],
            'sql': ['--']
        }

        comment_chars = single_line_comments.get(language, [])

        for line in lines:
            stripped = line.strip()
            if any(stripped.startswith(char) for char in comment_chars):
                comment_count += 1

        return comment_count
