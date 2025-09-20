# backend/app/utils/file_handler.py
import os
import zipfile
from typing import List, Dict, Optional

class FileHandler:
    """Universal file handler - analyzes ANY text-based file"""

    # Files and directories to ignore during analysis
    IGNORE_PATTERNS = {
        '.git/', '__pycache__/', 'node_modules/', '.vscode/', '.idea/',
        'venv/', 'env/', 'build/', 'dist/', 'target/', '.pytest_cache/',
        '.mypy_cache/', '.coverage', '*.pyc', '*.pyo', '*.class',
        '*.jar', '*.war', '*.min.js', '*.bundle.js', 'vendor/',
        'third_party/', 'external/', '.nuget/', 'packages/',
        'bower_components/', 'jspm_packages/', '.cargo/', 'Pods/',
        '*.exe', '*.dll', '*.so', '*.dylib', '*.bin', '*.obj'
    }

    # Binary file extensions to definitely skip
    BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico', '.svg',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'  # Archives handled separately
    }

    def extract_and_validate_zip(self, zip_path: str, extract_dir: str) -> List[str]:
        """
        Extract ZIP file and return list of ALL text files (no restrictions)
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Check ZIP file integrity
                if zip_ref.testzip():
                    raise ValueError("ZIP file is corrupted")

                # Extract all files
                zip_ref.extractall(extract_dir)

            # Find ALL text files (no language restrictions)
            text_files = self._find_text_files(extract_dir)

            # Only limit by file count for performance
            if len(text_files) > 1000:
                raise ValueError("Too many files to analyze. Maximum: 1000 files")

            return text_files

        except zipfile.BadZipFile:
            raise ValueError("Invalid ZIP file")
        except Exception as e:
            raise ValueError(f"Failed to extract ZIP: {str(e)}")

    def _find_text_files(self, directory: str) -> List[str]:
        """Find ALL text files with NO language restrictions"""
        text_files = []
        total_size = 0
        max_total_size = 200 * 1024 * 1024  # 200MB total limit

        for root, dirs, files in os.walk(directory):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]

            for file in files:
                if self._should_ignore_file(file):
                    continue

                file_path = os.path.join(root, file)

                # Check file size (max 20MB per file)
                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > 20 * 1024 * 1024:  # 20MB limit per file
                        continue

                    if file_size == 0:  # Skip empty files
                        continue

                    total_size += file_size
                    if total_size > max_total_size:
                        break  # Stop if total size exceeds limit

                except OSError:
                    continue

                # Check if it's a text file (this is the key - no language restrictions)
                if self._is_text_file(file_path):
                    text_files.append(file_path)

        return sorted(text_files)

    def _should_ignore_directory(self, dirname: str) -> bool:
        """Check if directory should be ignored"""
        dirname_lower = dirname.lower()

        ignore_dirs = [
            '.git', '__pycache__', 'node_modules', '.vscode', '.idea',
            'venv', 'env', 'build', 'dist', 'target', '.pytest_cache',
            '.mypy_cache', 'vendor', 'third_party', 'external', 'packages',
            'bower_components', 'jspm_packages', '.cargo', 'pods'
        ]

        return dirname_lower in ignore_dirs

    def _should_ignore_file(self, filename: str) -> bool:
        """Check if file should be ignored (only ignores truly binary/useless files)"""
        filename_lower = filename.lower()

        # Skip hidden files (except some useful ones)
        if filename_lower.startswith('.') and filename_lower not in ['.env', '.htaccess', '.gitignore', '.dockerignore']:
            return True

        # Skip backup and temporary files
        if any(filename_lower.endswith(suffix) for suffix in ['.bak', '.tmp', '.temp', '.swp', '~', '.log']):
            return True

        # Skip compiled/binary files by extension
        _, ext = os.path.splitext(filename_lower)
        if ext in self.BINARY_EXTENSIONS:
            return True

        # Skip very specific patterns that are definitely not code
        skip_patterns = ['package-lock.json', 'yarn.lock', '.min.', '.bundle.']
        if any(pattern in filename_lower for pattern in skip_patterns):
            return True

        return False

    def _is_text_file(self, file_path: str) -> bool:
        """
        Universal text file detection - accepts ANYTHING that's readable as text
        No language restrictions whatsoever
        """
        try:
            # Try multiple encodings to read the file
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252', 'ascii']

            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        # Read first 4KB to check if it's text
                        sample = f.read(4096)

                        # If we can read it and it has some content, consider it text
                        if len(sample.strip()) > 0:
                            # Very liberal check - if it's mostly printable, it's text
                            printable_chars = sum(1 for c in sample if c.isprintable() or c.isspace())

                            # Accept if more than 70% printable (very permissive)
                            if len(sample) > 0 and printable_chars / len(sample) > 0.7:
                                return True

                except (UnicodeDecodeError, UnicodeError):
                    continue

            return False

        except (IOError, OSError, PermissionError):
            return False

    def get_file_language(self, filename: str) -> str:
        """
        Universal language detection - returns a language or 'unknown'
        NEVER returns None, always allows analysis
        """
        if not filename:
            return 'text'

        # Get extension
        _, ext = os.path.splitext(filename.lower())
        filename_lower = filename.lower()

        # Comprehensive language mapping
        language_map = {
            # Popular languages
            '.py': 'python', '.pyx': 'python', '.pyw': 'python', '.pyi': 'python',
            '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.java': 'java', '.jsp': 'java', '.jspx': 'java',
            '.kt': 'kotlin', '.kts': 'kotlin',
            '.scala': 'scala', '.sc': 'scala',
            '.clj': 'clojure', '.cljs': 'clojure',
            '.groovy': 'groovy', '.gradle': 'groovy',

            # C/C++
            '.c': 'c', '.h': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.c++': 'cpp',
            '.hpp': 'cpp', '.hh': 'cpp', '.hxx': 'cpp', '.h++': 'cpp',

            # .NET
            '.cs': 'csharp', '.csx': 'csharp',
            '.vb': 'vbnet', '.vbs': 'vbscript',
            '.fs': 'fsharp', '.fsx': 'fsharp',

            # Systems languages
            '.go': 'go',
            '.rs': 'rust',
            '.zig': 'zig',
            '.nim': 'nim',
            '.d': 'd',
            '.carbon': 'carbon',

            # Mobile
            '.swift': 'swift',
            '.dart': 'dart',
            '.m': 'objectivec', '.mm': 'objectivec',

            # Web languages
            '.php': 'php', '.phtml': 'php', '.php3': 'php', '.php4': 'php', '.php5': 'php', '.php7': 'php', '.php8': 'php',
            '.rb': 'ruby', '.rbw': 'ruby', '.rake': 'ruby', '.gemspec': 'ruby', '.erb': 'ruby',
            '.pl': 'perl', '.pm': 'perl', '.perl': 'perl',
            '.py3': 'python', '.pyw3': 'python',

            # Functional languages
            '.hs': 'haskell', '.lhs': 'haskell',
            '.ml': 'ocaml', '.mli': 'ocaml',
            '.elm': 'elm',
            '.ex': 'elixir', '.exs': 'elixir',
            '.erl': 'erlang', '.hrl': 'erlang',
            '.lisp': 'lisp', '.lsp': 'lisp',
            '.scheme': 'scheme', '.scm': 'scheme',
            '.clj': 'clojure', '.cljs': 'clojure',

            # Scripting
            '.r': 'r', '.R': 'r', '.rmd': 'r', '.Rmd': 'r',
            '.lua': 'lua',
            '.tcl': 'tcl',
            '.jl': 'julia',
            '.cr': 'crystal',
            '.odin': 'odin',

            # Shell scripts
            '.sh': 'bash', '.bash': 'bash',
            '.zsh': 'zsh', '.fish': 'fish',
            '.csh': 'csh', '.tcsh': 'tcsh', '.ksh': 'ksh',
            '.ps1': 'powershell', '.psm1': 'powershell', '.psd1': 'powershell',
            '.bat': 'batch', '.cmd': 'batch',

            # Database
            '.sql': 'sql', '.psql': 'postgresql', '.mysql': 'mysql',
            '.sqlite': 'sqlite', '.pgsql': 'postgresql', '.plsql': 'plsql',

            # Web markup/styling
            '.html': 'html', '.htm': 'html', '.xhtml': 'html',
            '.xml': 'xml', '.xsl': 'xml', '.xslt': 'xml',
            '.css': 'css', '.scss': 'scss', '.sass': 'sass', '.less': 'less',
            '.vue': 'vue', '.svelte': 'svelte', '.astro': 'astro',

            # Assembly
            '.asm': 'assembly', '.s': 'assembly', '.S': 'assembly',
            '.nasm': 'assembly', '.masm': 'assembly',

            # Scientific/Engineering
            '.f': 'fortran', '.f77': 'fortran', '.f90': 'fortran', '.f95': 'fortran',
            '.f03': 'fortran', '.f08': 'fortran', '.for': 'fortran',
            '.pas': 'pascal', '.pp': 'pascal', '.inc': 'pascal',
            '.ada': 'ada', '.adb': 'ada', '.ads': 'ada',
            '.cob': 'cobol', '.cbl': 'cobol',
            '.pro': 'prolog', '.pl': 'prolog',  # Note: .pl could be Perl or Prolog

            # Modern/Emerging languages
            '.sol': 'solidity',
            '.move': 'move',
            '.cairo': 'cairo',
            '.yul': 'yul',
            '.vyper': 'vyper',
            '.fe': 'fe',
            '.pony': 'pony',
            '.red': 'red',
            '.factor': 'factor',

            # DevOps/Config
            '.tf': 'terraform', '.tfvars': 'terraform',
            '.hcl': 'hcl',
            '.yaml': 'yaml', '.yml': 'yaml',
            '.toml': 'toml',
            '.ini': 'ini', '.cfg': 'ini', '.conf': 'ini',
            '.json': 'json', '.jsonc': 'json',
            '.proto': 'protobuf',
            '.thrift': 'thrift',
            '.avro': 'avro',

            # Other text formats that could contain code
            '.md': 'markdown', '.markdown': 'markdown',
            '.rst': 'restructuredtext',
            '.tex': 'latex', '.cls': 'latex', '.sty': 'latex',
            '.bib': 'bibtex',
            '.org': 'org-mode',

            # Jupyter/Data Science
            '.ipynb': 'jupyter',
            '.rmd': 'rmarkdown',
            '.qmd': 'quarto',

            # Game Development
            '.gd': 'gdscript',
            '.cs': 'unity-csharp',  # Could be regular C# too
            '.hlsl': 'hlsl', '.glsl': 'glsl',
            '.shader': 'shader',

            # Query languages
            '.sparql': 'sparql',
            '.cypher': 'cypher',
            '.gql': 'graphql', '.graphql': 'graphql'
        }

        # Check extension first
        if ext in language_map:
            return language_map[ext]

        # Special filename detection (no extension files)
        special_files = {
            'dockerfile': 'dockerfile', 'containerfile': 'dockerfile',
            'makefile': 'makefile', 'gnumakefile': 'makefile',
            'cmakelists.txt': 'cmake', 'cmake': 'cmake',
            'rakefile': 'ruby', 'gemfile': 'ruby', 'podfile': 'ruby',
            'vagrantfile': 'ruby', 'guardfile': 'ruby',
            'gruntfile.js': 'javascript', 'gulpfile.js': 'javascript',
            'webpack.config.js': 'javascript', 'rollup.config.js': 'javascript',
            'package.json': 'json', 'composer.json': 'json',
            'requirements.txt': 'text', 'pipfile': 'toml',
            'cargo.toml': 'toml', 'pyproject.toml': 'toml',
            '.gitignore': 'gitignore', '.dockerignore': 'dockerignore',
            '.env': 'env', '.env.local': 'env', '.env.example': 'env',
            'readme': 'markdown', 'readme.md': 'markdown',
            'license': 'text', 'changelog': 'text', 'authors': 'text',
            'procfile': 'procfile', 'buildfile': 'text'
        }

        if filename_lower in special_files:
            return special_files[filename_lower]

        # If no extension, try to detect from filename patterns
        if not ext:
            if any(keyword in filename_lower for keyword in ['config', 'conf', 'settings']):
                return 'config'
            if any(keyword in filename_lower for keyword in ['script', 'run', 'start', 'install']):
                return 'script'
            if 'test' in filename_lower:
                return 'test'

        # Default fallback - NEVER return None, always allow analysis
        return 'text'

    def get_file_stats(self, file_path: str) -> Dict:
        """Get comprehensive file statistics"""
        try:
            # Try multiple encodings
            content = None
            encoding_used = None

            for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    encoding_used = encoding
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue

            if content is None:
                return {
                    'size_bytes': 0, 'line_count': 0, 'non_empty_lines': 0,
                    'language': 'binary', 'has_content': False, 'encoding': 'unknown'
                }

            lines = content.split('\n')
            language = self.get_file_language(os.path.basename(file_path))

            return {
                'size_bytes': len(content),
                'line_count': len(lines),
                'non_empty_lines': len([line for line in lines if line.strip()]),
                'language': language,
                'has_content': len(content.strip()) > 0,
                'encoding': encoding_used,
                'char_count': len(content),
                'word_count': len(content.split()) if content else 0
            }

        except Exception:
            return {
                'size_bytes': 0, 'line_count': 0, 'non_empty_lines': 0,
                'language': 'error', 'has_content': False, 'encoding': 'error'
            }

    def _is_text_file_by_name(self, filename: str) -> bool:
        """
        Quick check if file is likely text-based by extension
        Very permissive - only blocks obviously binary files
        """
        if not filename:
            return True

        _, ext = os.path.splitext(filename.lower())

        # Only block clearly binary extensions
        definitely_binary = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }

        # If it's not definitely binary, assume it's text
        return ext not in definitely_binary

    def _is_text_file_by_name(self, filename: str) -> bool:
        """
        Quick check if file is likely text-based by extension
        Very permissive - only blocks obviously binary files
        """
        if not filename:
            return True

        _, ext = os.path.splitext(filename.lower())

        # Only block clearly binary extensions
        definitely_binary = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav', '.ogg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }

        # If it's not definitely binary, assume it's text
        return ext not in definitely_binary

