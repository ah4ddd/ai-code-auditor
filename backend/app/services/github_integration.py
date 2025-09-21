"""
GitHub Integration Service
Handles repository cloning, file discovery, and branch management
"""
import os
import tempfile
import shutil
from typing import List, Dict, Optional, Tuple
from github import Github
from github.Repository import Repository
from github.Branch import Branch
import git
from datetime import datetime
import asyncio
import aiofiles

class GitHubIntegration:
    """GitHub repository integration for security analysis"""

    def __init__(self, github_token: str = None):
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.github_client = Github(self.github_token) if self.github_token else None

    async def clone_repository(self, repo_url: str, branch: str = "main") -> Tuple[str, str]:
        """
        Clone repository and return (temp_dir, repo_name)
        """
        try:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp(prefix="repo_scan_")

            # Parse repository URL
            repo_name = self._extract_repo_name(repo_url)

            print(f"📥 Cloning repository: {repo_name} (branch: {branch})")

            # Clone repository
            repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch)

            print(f"✅ Repository cloned successfully: {temp_dir}")

            return temp_dir, repo_name

        except Exception as e:
            print(f"❌ Failed to clone repository: {str(e)}")
            if 'temp_dir' in locals():
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"Repository cloning failed: {str(e)}")

    async def get_repository_info(self, repo_url: str) -> Dict:
        """
        Get repository information without cloning
        """
        try:
            if not self.github_client:
                # For public repositories, we can still get basic info
                if 'github.com' in repo_url:
                    # Parse repository info from URL
                    parts = repo_url.replace('https://github.com/', '').replace('.git', '').split('/')
                    if len(parts) >= 2:
                        owner, repo_name = parts[0], parts[1]
                        return {
                            "name": repo_name,
                            "full_name": f"{owner}/{repo_name}",
                            "description": "Public repository - detailed info requires GitHub token",
                            "language": "Unknown",
                            "languages": [],
                            "stars": 0,
                            "forks": 0,
                            "size": 0,
                            "branches": ["main", "master"],
                            "default_branch": "main",
                            "recent_commits": [],
                            "clone_url": repo_url,
                            "html_url": repo_url,
                            "created_at": "Unknown",
                            "updated_at": "Unknown"
                        }
                raise Exception("GitHub token not configured for private repositories")

            # Parse repository owner and name
            owner, repo_name = self._parse_repo_url(repo_url)

            # Get repository
            repo = self.github_client.get_repo(f"{owner}/{repo_name}")

            # Get branches
            branches = [branch.name for branch in repo.get_branches()]

            # Get languages
            languages = list(repo.get_languages().keys())

            # Get recent commits
            commits = []
            try:
                default_branch = repo.default_branch or "main"
                all_commits = repo.get_commits(sha=default_branch)
                commit_count = 0
                for commit in all_commits:
                    if commit_count >= 5:
                        break
                    commits.append({
                        "sha": commit.sha[:8],
                        "message": commit.commit.message.split('\n')[0],
                        "author": commit.commit.author.name,
                        "date": commit.commit.author.date.isoformat()
                    })
                    commit_count += 1
            except Exception as commit_error:
                print(f"Warning: Could not get commits: {commit_error}")
                commits = []

            return {
                "name": repo.name,
                "full_name": repo.full_name,
                "description": repo.description,
                "language": repo.language,
                "languages": languages,
                "stars": repo.stargazers_count,
                "forks": repo.forks_count,
                "size": repo.size,
                "branches": branches,
                "default_branch": repo.default_branch,
                "recent_commits": commits,
                "clone_url": repo.clone_url,
                "html_url": repo.html_url,
                "created_at": repo.created_at.isoformat(),
                "updated_at": repo.updated_at.isoformat()
            }

        except Exception as e:
            print(f"❌ Failed to get repository info: {str(e)}")
            raise Exception(f"Repository info retrieval failed: {str(e)}")

    async def discover_files(self, repo_path: str, languages: List[str] = None) -> List[Dict]:
        """
        Discover all analyzable files in the repository
        """
        try:
            files = []
            total_size = 0
            max_total_size = 500 * 1024 * 1024  # 500MB limit

            print(f"🔍 Discovering files in: {repo_path}")

            for root, dirs, filenames in os.walk(repo_path):
                # Skip ignored directories
                dirs[:] = [d for d in dirs if not self._should_ignore_directory(d)]

                for filename in filenames:
                    if self._should_ignore_file(filename):
                        continue

                    file_path = os.path.join(root, filename)

                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > 20 * 1024 * 1024:  # 20MB per file
                            continue

                        if file_size == 0:
                            continue

                        total_size += file_size
                        if total_size > max_total_size:
                            print(f"⚠️ Repository size limit reached ({max_total_size // (1024*1024)}MB)")
                            break

                        # Check if it's a text file
                        if self._is_text_file(file_path):
                            relative_path = os.path.relpath(file_path, repo_path)
                            language = self._detect_language(filename)

                            files.append({
                                "path": relative_path,
                                "full_path": file_path,
                                "filename": filename,
                                "size": file_size,
                                "language": language,
                                "extension": os.path.splitext(filename)[1].lower()
                            })

                    except (OSError, PermissionError):
                        continue

                if total_size > max_total_size:
                    break

            print(f"✅ Found {len(files)} analyzable files")
            return files

        except Exception as e:
            print(f"❌ File discovery failed: {str(e)}")
            raise Exception(f"File discovery failed: {str(e)}")

    async def get_file_content(self, file_path: str) -> str:
        """
        Read file content with proper encoding handling
        """
        try:
            # Try multiple encodings
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252', 'ascii']

            for encoding in encodings:
                try:
                    async with aiofiles.open(file_path, 'r', encoding=encoding) as f:
                        content = await f.read()
                        return content
                except (UnicodeDecodeError, UnicodeError):
                    continue

            raise Exception("Could not decode file with any supported encoding")

        except Exception as e:
            print(f"❌ Failed to read file {file_path}: {str(e)}")
            raise Exception(f"File reading failed: {str(e)}")

    def _extract_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL"""
        if repo_url.endswith('.git'):
            repo_url = repo_url[:-4]

        if 'github.com' in repo_url:
            return repo_url.split('/')[-1]
        elif 'gitlab.com' in repo_url:
            return repo_url.split('/')[-1]
        elif 'bitbucket.org' in repo_url:
            return repo_url.split('/')[-1]
        else:
            return os.path.basename(repo_url)

    def _parse_repo_url(self, repo_url: str) -> Tuple[str, str]:
        """Parse repository URL to get owner and name"""
        if repo_url.endswith('.git'):
            repo_url = repo_url[:-4]

        if 'github.com' in repo_url:
            parts = repo_url.split('/')
            return parts[-2], parts[-1]
        elif 'gitlab.com' in repo_url:
            parts = repo_url.split('/')
            return parts[-2], parts[-1]
        elif 'bitbucket.org' in repo_url:
            parts = repo_url.split('/')
            return parts[-2], parts[-1]
        else:
            raise Exception("Unsupported repository URL format")

    def _should_ignore_directory(self, dirname: str) -> bool:
        """Check if directory should be ignored"""
        ignore_dirs = {
            '.git', '__pycache__', 'node_modules', '.vscode', '.idea',
            'venv', 'env', 'build', 'dist', 'target', '.pytest_cache',
            '.mypy_cache', 'vendor', 'third_party', 'external', 'packages',
            'bower_components', 'jspm_packages', '.cargo', 'pods',
            '.next', '.nuget', 'coverage', '.nyc_output', 'logs'
        }
        return dirname.lower() in ignore_dirs

    def _should_ignore_file(self, filename: str) -> bool:
        """Enhanced file filtering - Skip ALL non-security relevant files"""
        filename_lower = filename.lower()

        # Skip ALL Zone.Identifier files (Windows metadata)
        if ':zone.identifier' in filename_lower or filename_lower.endswith('.identifier'):
            return True

        # Skip all image files and their metadata
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff', '.ico', '.svg', '.webp'}
        if any(filename_lower.endswith(ext) for ext in image_extensions):
            return True

        # Skip favicon and icon files by name
        if any(word in filename_lower for word in ['favicon', 'android-chrome', 'apple-touch-icon']):
            return True

        # Skip hidden files (except some useful ones)
        if filename_lower.startswith('.') and filename_lower not in {
            '.env', '.htaccess', '.gitignore', '.dockerignore', '.eslintrc',
            '.prettierrc', '.babelrc', '.editorconfig', '.env.example'
        }:
            return True

        # Skip backup and temporary files
        if any(filename_lower.endswith(suffix) for suffix in {
            '.bak', '.tmp', '.temp', '.swp', '~', '.log', '.lock'
        }):
            return True

        # Skip media files
        media_extensions = {'.mp3', '.wav', '.ogg', '.mp4', '.avi', '.mov', '.wmv', '.flv'}
        if any(filename_lower.endswith(ext) for ext in media_extensions):
            return True

        # Skip fonts
        font_extensions = {'.ttf', '.otf', '.woff', '.woff2', '.eot'}
        if any(filename_lower.endswith(ext) for ext in font_extensions):
            return True

        # Skip binary files
        binary_extensions = {
            '.exe', '.dll', '.so', '.dylib', '.bin', '.obj', '.o', '.a', '.lib',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'
        }

        _, ext = os.path.splitext(filename_lower)
        if ext in binary_extensions:
            return True

        # Skip very large files and minified files
        skip_patterns = ['package-lock.json', 'yarn.lock', '.min.', '.bundle.']
        if any(pattern in filename_lower for pattern in skip_patterns):
            return True

        return False

    def _is_text_file(self, file_path: str) -> bool:
        """Check if file is text-based"""
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(4096)

                # Check if file is mostly printable
                printable_chars = sum(1 for c in sample if c >= 32 and c <= 126 or c in {9, 10, 13})

                if len(sample) > 0 and printable_chars / len(sample) > 0.7:
                    return True

                return False

        except (IOError, OSError):
            return False

    def _detect_language(self, filename: str) -> str:
        """Detect programming language from filename"""
        _, ext = os.path.splitext(filename.lower())

        language_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
            '.jsx': 'javascript', '.tsx': 'typescript', '.java': 'java',
            '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
            '.cs': 'csharp', '.php': 'php', '.rb': 'ruby', '.go': 'go',
            '.rs': 'rust', '.swift': 'swift', '.kt': 'kotlin', '.scala': 'scala',
            '.html': 'html', '.css': 'css', '.scss': 'scss', '.sass': 'sass',
            '.xml': 'xml', '.json': 'json', '.yaml': 'yaml', '.yml': 'yaml',
            '.sql': 'sql', '.sh': 'bash', '.ps1': 'powershell', '.bat': 'batch',
            '.dockerfile': 'dockerfile', '.tf': 'terraform', '.hcl': 'hcl',
            '.md': 'markdown', '.rst': 'restructuredtext', '.txt': 'text'
        }

        return language_map.get(ext, 'unknown')

    async def cleanup_repository(self, temp_dir: str):
        """Clean up temporary repository directory"""
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                print(f"🧹 Cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            print(f"⚠️ Failed to cleanup directory {temp_dir}: {str(e)}")
