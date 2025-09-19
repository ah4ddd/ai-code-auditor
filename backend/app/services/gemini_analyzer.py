# backend/app/services/gemini_analyzer.py
"""
Enhanced AI Code Security Analyzer supporting multiple programming languages
FIXED VERSION - Language-specific vulnerability detection with specialized prompts
"""

import json
import requests
import time
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityType(Enum):
    # Web vulnerabilities
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    CSRF = "CSRF"

    # Authentication/Authorization
    HARDCODED_SECRETS = "HARDCODED_SECRETS"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    INSECURE_AUTH = "INSECURE_AUTH"

    # Code injection
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_INJECTION = "CODE_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"

    # Deserialization
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    YAML_DESERIALIZATION = "YAML_DESERIALIZATION"

    # Memory issues (C/C++)
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    USE_AFTER_FREE = "USE_AFTER_FREE"
    DOUBLE_FREE = "DOUBLE_FREE"
    MEMORY_LEAK = "MEMORY_LEAK"
    NULL_POINTER_DEREFERENCE = "NULL_POINTER_DEREFERENCE"

    # Other security issues
    WEAK_RANDOM = "WEAK_RANDOM"
    RACE_CONDITION = "RACE_CONDITION"
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"
    FORMAT_STRING = "FORMAT_STRING"
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"

@dataclass
class Vulnerability:
    line_number: int
    vulnerability_type: VulnerabilityType
    severity: Severity
    description: str
    code_snippet: str
    fix_suggestion: str
    confidence: float

class GeminiSecurityAnalyzer:
    """Enhanced security analyzer with multi-language support - FIXED VERSION"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

        # Language-specific security prompts
        self.language_prompts = self._initialize_language_prompts()

    def _initialize_language_prompts(self) -> Dict[str, str]:
        """Initialize language-specific security analysis prompts"""

        base_instruction = """You are a world-class security expert and code auditor. Analyze the following {language} code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{{
  "vulnerabilities": [
    {{
      "line_number": 42,
      "vulnerability_type": "SQL_INJECTION",
      "severity": "HIGH",
      "description": "Direct string concatenation in SQL query allows injection attacks",
      "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
      "fix_suggestion": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
      "confidence": 0.95
    }}
  ],
  "summary": {{
    "total_vulnerabilities": 1,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 0,
    "low_count": 0,
    "info_count": 0
  }}
}}

Severity levels:
- CRITICAL: Immediate exploitation possible, data breach likely
- HIGH: Easy to exploit, significant impact
- MEDIUM: Requires some skill to exploit, moderate impact
- LOW: Difficult to exploit or minor impact
- INFO: Security best practice violations

Be precise with line numbers. Only flag REAL vulnerabilities with high confidence (>0.7), not theoretical ones."""

        return {
            'python': base_instruction.format(language='Python') + """

Look specifically for these Python vulnerabilities:
- SQL_INJECTION: String concatenation/formatting in SQL queries
- XSS: Unescaped output in Flask/Django templates
- HARDCODED_SECRETS: API keys, passwords, tokens in source
- WEAK_CRYPTO: MD5, SHA1, DES usage for security
- INSECURE_AUTH: Poor password handling, weak sessions
- PATH_TRAVERSAL: Unchecked file paths in open(), os.path.join()
- COMMAND_INJECTION: subprocess, os.system with user input
- INSECURE_DESERIALIZATION: pickle.loads(), eval(), exec()
- WEAK_RANDOM: random module for crypto purposes
- INSUFFICIENT_LOGGING: Missing security event logs

Focus on high-confidence, exploitable vulnerabilities only.""",

            'javascript': base_instruction.format(language='JavaScript') + """

Look specifically for these JavaScript vulnerabilities:
- XSS: innerHTML usage, document.write() with user data
- SQL_INJECTION: Unsanitized database queries
- HARDCODED_SECRETS: API keys in client-side code
- PROTOTYPE_POLLUTION: Unsafe Object.assign usage
- UNSAFE_EVAL: eval(), Function() with user input
- INSECURE_RANDOMNESS: Math.random() for security
- DOM_XSS: Unsafe DOM manipulation
- COMMAND_INJECTION: child_process.exec() with user input

Focus on client-side security issues and Node.js vulnerabilities.""",

            'java': base_instruction.format(language='Java') + """

Look specifically for these Java vulnerabilities:
- SQL_INJECTION: Statement vs PreparedStatement usage
- XSS: Unescaped JSP/servlet output
- INSECURE_DESERIALIZATION: ObjectInputStream.readObject()
- XXE: XML parser vulnerabilities
- HARDCODED_SECRETS: Credentials in source code
- WEAK_CRYPTO: DES, MD5, SHA1 usage
- COMMAND_INJECTION: Runtime.exec() with user input
- LDAP_INJECTION: Unsanitized LDAP queries

Focus on enterprise Java security patterns.""",

            'c': base_instruction.format(language='C') + """

Look specifically for these C vulnerabilities:
- BUFFER_OVERFLOW: strcpy, strcat, gets, sprintf without bounds
- FORMAT_STRING: printf with user-controlled format strings
- USE_AFTER_FREE: Accessing freed memory
- DOUBLE_FREE: Multiple free() calls
- NULL_POINTER_DEREFERENCE: Dereferencing NULL pointers
- INTEGER_OVERFLOW: Arithmetic without overflow checks
- COMMAND_INJECTION: system() with user input

Focus on memory safety and injection vulnerabilities.""",

            'cpp': base_instruction.format(language='C++') + """

Look specifically for these C++ vulnerabilities:
- BUFFER_OVERFLOW: Unsafe string operations
- USE_AFTER_FREE: Smart pointer misuse
- MEMORY_LEAK: Missing delete, RAII violations
- DOUBLE_FREE: Multiple delete calls
- INTEGER_OVERFLOW: Arithmetic overflow issues
- RACE_CONDITION: Thread safety problems
- WEAK_CRYPTO: Deprecated crypto algorithms

Focus on modern C++ security patterns.""",

            'csharp': base_instruction.format(language='C#') + """

Look specifically for these C# vulnerabilities:
- SQL_INJECTION: String concatenation in SQL
- XSS: Unencoded web output
- INSECURE_DESERIALIZATION: BinaryFormatter usage
- XXE: XmlDocument without secure settings
- HARDCODED_SECRETS: Connection strings in code
- WEAK_CRYPTO: DES, MD5, SHA1 usage
- COMMAND_INJECTION: Process.Start() with user input

Focus on .NET security best practices.""",

            'go': base_instruction.format(language='Go') + """

Look specifically for these Go vulnerabilities:
- SQL_INJECTION: String formatting in queries
- XSS: Unescaped template output
- HARDCODED_SECRETS: API keys in source
- WEAK_CRYPTO: MD5, SHA1, DES usage
- COMMAND_INJECTION: exec.Command() with user input
- PATH_TRAVERSAL: File operations without cleaning
- RACE_CONDITION: Goroutine sync issues

Focus on Go-specific security patterns.""",

            'php': base_instruction.format(language='PHP') + """

Look specifically for these PHP vulnerabilities:
- SQL_INJECTION: String concatenation vs PDO
- XSS: Unescaped echo output
- LFI: include/require with user input
- RFI: Remote file inclusion
- COMMAND_INJECTION: shell_exec(), system() with user data
- HARDCODED_SECRETS: Database credentials
- INSECURE_DESERIALIZATION: unserialize() with user input

Focus on common PHP web vulnerabilities.""",

            'ruby': base_instruction.format(language='Ruby') + """

Look specifically for these Ruby vulnerabilities:
- SQL_INJECTION: String interpolation in ActiveRecord
- XSS: Raw output in ERB templates
- COMMAND_INJECTION: system(), backticks with user input
- YAML_DESERIALIZATION: YAML.load() vs YAML.safe_load()
- HARDCODED_SECRETS: API keys, passwords
- MASS_ASSIGNMENT: Unfiltered params

Focus on Rails security patterns.""",

            'rust': base_instruction.format(language='Rust') + """

Look specifically for these Rust vulnerabilities:
- UNSAFE_CODE: Unsafe blocks without proper validation
- INTEGER_OVERFLOW: Arithmetic without overflow checks
- HARDCODED_SECRETS: API keys in source
- WEAK_CRYPTO: Weak algorithms
- COMMAND_INJECTION: Command::new() with user input
- RACE_CONDITION: Arc/Mutex misuse

Focus on unsafe Rust patterns.""",

            'swift': base_instruction.format(language='Swift') + """

Look specifically for these Swift vulnerabilities:
- SQL_INJECTION: String interpolation in SQL
- HARDCODED_SECRETS: API keys in source
- WEAK_CRYPTO: Deprecated algorithms
- INSECURE_NETWORKING: HTTP vs HTTPS issues
- KEYCHAIN_MISUSE: Improper keychain usage

Focus on iOS security patterns.""",

            'kotlin': base_instruction.format(language='Kotlin') + """

Look specifically for these Kotlin vulnerabilities:
- SQL_INJECTION: String templates in SQL
- HARDCODED_SECRETS: API keys in source
- INSECURE_DESERIALIZATION: Unsafe deserialization
- COMMAND_INJECTION: ProcessBuilder with user input
- NULL_SAFETY_BYPASS: Unsafe null assertions

Focus on Android/JVM security.""",

            'typescript': base_instruction.format(language='TypeScript') + """

Look specifically for these TypeScript vulnerabilities:
- XSS: Unescaped output, innerHTML usage
- HARDCODED_SECRETS: API keys in client code
- PROTOTYPE_POLLUTION: Unsafe object operations
- UNSAFE_EVAL: eval(), Function() usage
- INSECURE_RANDOMNESS: Math.random() for security

Focus on TypeScript-specific patterns.""",

            'default': base_instruction.format(language='') + """

Look for these common vulnerabilities:
- HARDCODED_SECRETS: API keys, passwords in source
- WEAK_CRYPTO: MD5, SHA1, weak encryption
- COMMAND_INJECTION: System calls with user input
- PATH_TRAVERSAL: File operations with user paths
- INSECURE_RANDOM: Weak random generation
- SQL_INJECTION: Unsanitized database queries
- XSS: Unescaped output in web contexts

Focus on high-confidence vulnerabilities only."""
        }

    def analyze_code(self, code_content: str, filename: str, language: str = None) -> Dict:
        """
        Enhanced code analysis with language-specific prompts - FIXED VERSION
        """
        print(f"🔍 Analyzing {filename} ({len(code_content.split())} words of {language or 'detecting'} code)")

        # Detect language if not provided - FIXED VERSION
        if not language:
            language = self._detect_language(filename, code_content)

        # Get appropriate prompt for language
        prompt = self._get_language_prompt(language)

        # Add line numbers to code for reference
        numbered_code = self._add_line_numbers(code_content)

        # Truncate very long files to avoid token limits
        if len(numbered_code) > 15000:  # About 3000 tokens
            lines = numbered_code.split('\n')
            numbered_code = '\n'.join(lines[:200]) + '\n... [File truncated for analysis] ...'
            print(f"   📄 File truncated to first 200 lines for analysis")

        # Build the analysis prompt
        full_prompt = f"{prompt}\n\nCODE TO ANALYZE:\n```{language}\n{numbered_code}\n```\n\nReturn only the JSON response:"

        payload = {
            "contents": [
                {
                    "parts": [{"text": full_prompt}],
                    "role": "user"
                }
            ],
            "generationConfig": {
                "temperature": 0.1,  # Low temperature for consistent analysis
                "maxOutputTokens": 2000,
                "topP": 0.8,
                "topK": 40
            }
        }

        try:
            print(f"🤖 Sending {language} code to Gemini for analysis...")

            response = requests.post(
                self.base_url,
                headers={
                    'Content-Type': 'application/json',
                    'X-goog-api-key': self.api_key
                },
                json=payload,
                timeout=45  # Increased timeout
            )

            response.raise_for_status()
            result = response.json()

            if 'candidates' in result and result['candidates']:
                gemini_response = result['candidates'][0]['content']['parts'][0]['text']

                # Enhanced JSON extraction
                json_match = re.search(r'\{.*\}', gemini_response, re.DOTALL)
                if json_match:
                    try:
                        analysis_result = json.loads(json_match.group())

                        # Validate required fields
                        if 'vulnerabilities' not in analysis_result:
                            analysis_result['vulnerabilities'] = []
                        if 'summary' not in analysis_result:
                            analysis_result['summary'] = {
                                'total_vulnerabilities': len(analysis_result['vulnerabilities']),
                                'critical_count': 0,
                                'high_count': 0,
                                'medium_count': 0,
                                'low_count': 0,
                                'info_count': 0
                            }

                        # Add metadata
                        analysis_result['metadata'] = {
                            'filename': filename,
                            'language': language,
                            'analyzed_at': time.time(),
                            'code_length': len(code_content),
                            'gemini_tokens_used': result.get('usageMetadata', {}).get('totalTokenCount', 0),
                            'analysis_version': '2.0'
                        }

                        vuln_count = len(analysis_result.get('vulnerabilities', []))
                        print(f"✅ Analysis complete! Found {vuln_count} potential issues")
                        return analysis_result

                    except json.JSONDecodeError as e:
                        print(f"❌ JSON parsing error: {str(e)}")
                        return self._create_error_response("Invalid JSON response from Gemini", gemini_response[:500])
                else:
                    print("❌ No JSON found in Gemini response")
                    return self._create_error_response("No JSON found in response", gemini_response[:500])
            else:
                print("❌ No candidates in Gemini response")
                return self._create_error_response("No response candidates from Gemini API", str(result))

        except requests.exceptions.Timeout:
            print("❌ Gemini API timeout")
            return self._create_error_response("Analysis timeout - file may be too large")
        except requests.exceptions.RequestException as e:
            print(f"❌ API request failed: {str(e)}")
            return self._create_error_response(f"API request failed: {str(e)}")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return self._create_error_response(f"Unexpected error: {str(e)}")

    def _detect_language(self, filename: str, code_content: str) -> str:
        """Detect programming language from filename and content - FIXED VERSION"""

        # FIXED: Proper string splitting for extension detection
        if '.' in filename:
            ext = '.' + filename.lower().split('.')[-1]
        else:
            ext = ''

        # Extension-based detection
        ext_map = {
            '.py': 'python', '.pyx': 'python', '.pyw': 'python',
            '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript',
            '.ts': 'typescript', '.tsx': 'typescript',
            '.java': 'java', '.kt': 'kotlin', '.scala': 'scala',
            '.c': 'c', '.h': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
            '.cs': 'csharp', '.go': 'go', '.rs': 'rust', '.swift': 'swift',
            '.php': 'php', '.rb': 'ruby', '.pl': 'perl', '.r': 'r',
            '.sh': 'bash', '.bash': 'bash', '.ps1': 'powershell',
            '.sql': 'sql', '.html': 'html', '.xml': 'xml'
        }

        if ext in ext_map:
            return ext_map[ext]

        # Special filename detection
        filename_lower = filename.lower()
        if filename_lower in ['dockerfile', 'makefile', 'rakefile', 'gemfile']:
            return filename_lower

        # Content-based detection fallback
        content_lower = code_content[:1000].lower()  # Check first 1000 chars

        content_patterns = [
            ('import java.', 'java'),
            ('public class', 'java'),
            ('def ', 'python'),
            ('import ', 'python'),
            ('function ', 'javascript'),
            ('const ', 'javascript'),
            ('#include', 'c'),
            ('using System', 'csharp'),
            ('package main', 'go'),
            ('<?php', 'php'),
            ('class ', 'ruby')  # Could be multiple languages
        ]

        for pattern, lang in content_patterns:
            if pattern in content_lower:
                return lang

        return 'unknown'

    def _get_language_prompt(self, language: str) -> str:
        """Get appropriate security analysis prompt for language"""
        return self.language_prompts.get(language, self.language_prompts['default'])

    def _add_line_numbers(self, code: str) -> str:
        """Add line numbers to code for easier reference"""
        lines = code.split('\n')
        numbered_lines = []
        for i, line in enumerate(lines, 1):
            numbered_lines.append(f"{i:3d}: {line}")
        return '\n'.join(numbered_lines)

    def _create_error_response(self, error_message: str, raw_response: str = "") -> Dict:
        """Create standardized error response"""
        return {
            'error': True,
            'message': error_message,
            'raw_response': raw_response,
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0
            }
        }

    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a file with automatic language detection"""
        try:
            # Try multiple encodings
            code_content = None
            for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        code_content = f.read()
                    break
                except UnicodeDecodeError:
                    continue

            if code_content is None:
                return self._create_error_response("Could not decode file as text")

            filename = os.path.basename(file_path)
            language = self._detect_language(filename, code_content)

            return self.analyze_code(code_content, filename, language)

        except FileNotFoundError:
            return self._create_error_response(f"File not found: {file_path}")
        except Exception as e:
            return self._create_error_response(f"Error reading file: {str(e)}")
