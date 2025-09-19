import json
import requests
import time
import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
from dotenv import load_dotenv
import os

# Load env vars
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../../.env"))
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise SystemExit("❌ No GEMINI_API_KEY found in .env")

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityType(Enum):
    # Injection Attacks
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    LDAP_INJECTION = "LDAP_INJECTION"
    XPATH_INJECTION = "XPATH_INJECTION"

    # Authentication & Authorization
    INSECURE_AUTH = "INSECURE_AUTH"
    WEAK_SESSION_MANAGEMENT = "WEAK_SESSION_MANAGEMENT"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"

    # Cryptographic Issues
    WEAK_CRYPTO = "WEAK_CRYPTO"
    HARDCODED_SECRETS = "HARDCODED_SECRETS"
    WEAK_RANDOM = "WEAK_RANDOM"

    # Memory Issues (C/C++/Rust)
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    USE_AFTER_FREE = "USE_AFTER_FREE"
    MEMORY_LEAK = "MEMORY_LEAK"
    DOUBLE_FREE = "DOUBLE_FREE"
    NULL_POINTER_DEREFERENCE = "NULL_POINTER_DEREFERENCE"
    INTEGER_OVERFLOW = "INTEGER_OVERFLOW"

    # Serialization Issues
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    YAML_DESERIALIZATION = "YAML_DESERIALIZATION"

    # File System Issues
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    LFI = "LFI"  # Local File Inclusion
    RFI = "RFI"  # Remote File Inclusion

    # Web-Specific
    DOM_XSS = "DOM_XSS"
    PROTOTYPE_POLLUTION = "PROTOTYPE_POLLUTION"

    # Language-Specific
    UNSAFE_EVAL = "UNSAFE_EVAL"
    UNSAFE_CODE = "UNSAFE_CODE"  # Rust unsafe blocks
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"  # Ruby/Rails

    # General Security
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"
    RACE_CONDITION = "RACE_CONDITION"
    FORMAT_STRING = "FORMAT_STRING"
    XXE = "XXE"  # XML External Entity
    OPEN_REDIRECT = "OPEN_REDIRECT"

@dataclass
class Vulnerability:
    line_number: int
    vulnerability_type: VulnerabilityType
    severity: Severity
    description: str
    code_snippet: str
    fix_suggestion: str
    confidence: float  # 0.0 to 1.0

class EnhancedGeminiSecurityAnalyzer:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

        # Language-specific security analysis prompts
        self.language_prompts = self._build_language_prompts()

    def _build_language_prompts(self) -> Dict[str, str]:
        """Build language-specific security analysis prompts"""

        base_json_format = """{
  "vulnerabilities": [
    {
      "line_number": 42,
      "vulnerability_type": "SQL_INJECTION",
      "severity": "HIGH",
      "description": "Direct string concatenation in SQL query allows injection attacks",
      "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
      "fix_suggestion": "Use parameterized queries or prepared statements",
      "confidence": 0.95
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 0,
    "low_count": 0
  }
}"""

        return {
            'python': f"""You are a Python security expert. Analyze this Python code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

Python-specific vulnerabilities to look for:
- SQL_INJECTION: Unsanitized input in SQL queries, string concatenation in queries
- XSS: Unescaped output in web frameworks (Flask, Django)
- HARDCODED_SECRETS: API keys, passwords, database credentials in code
- WEAK_CRYPTO: MD5, SHA1, weak encryption algorithms
- INSECURE_DESERIALIZATION: Unsafe pickle.loads(), eval(), exec() usage
- COMMAND_INJECTION: os.system(), subprocess with shell=True and user input
- PATH_TRAVERSAL: File operations with unsanitized paths
- WEAK_RANDOM: random module for security purposes (use secrets instead)
- INSECURE_AUTH: Weak password hashing, plaintext passwords
- INSUFFICIENT_LOGGING: Missing security event logging

Severity levels:
- CRITICAL: Immediate exploitation possible, data breach likely
- HIGH: Easy to exploit, significant impact
- MEDIUM: Requires some skill to exploit, moderate impact
- LOW: Difficult to exploit or minor impact

Be precise with line numbers. Only flag REAL vulnerabilities.""",

            'javascript': f"""You are a JavaScript security expert. Analyze this JavaScript/Node.js code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

JavaScript-specific vulnerabilities to look for:
- XSS: Unescaped user input in DOM manipulation, innerHTML usage
- DOM_XSS: Client-side XSS in DOM manipulation
- SQL_INJECTION: Unsanitized input in database queries (especially NoSQL)
- PROTOTYPE_POLLUTION: Unsafe object merging, __proto__ manipulation
- UNSAFE_EVAL: eval(), Function(), setTimeout/setInterval with strings
- HARDCODED_SECRETS: API keys, tokens, passwords in client-side code
- WEAK_CRYPTO: Weak random number generation, Math.random() for security
- COMMAND_INJECTION: child_process.exec() with user input
- PATH_TRAVERSAL: File operations with unsanitized paths
- INSECURE_RANDOMNESS: Math.random() for security tokens

Focus on both client-side and server-side (Node.js) security issues.""",

            'java': f"""You are a Java security expert. Analyze this Java code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

Java-specific vulnerabilities to look for:
- SQL_INJECTION: JDBC queries with string concatenation
- XSS: Unescaped output in JSP, servlets
- INSECURE_DESERIALIZATION: ObjectInputStream.readObject() on untrusted data
- XXE: XML parsing without disabling external entities
- HARDCODED_SECRETS: API keys, passwords, database credentials
- WEAK_CRYPTO: MD5, SHA1, DES, weak key sizes
- PATH_TRAVERSAL: File operations with unsanitized paths
- LDAP_INJECTION: Unsanitized input in LDAP queries
- COMMAND_INJECTION: Runtime.exec(), ProcessBuilder with user input
- INSECURE_RANDOM: java.util.Random for security purposes (use SecureRandom)

Pay attention to Spring framework, Struts, and other common Java frameworks.""",

            'c': f"""You are a C security expert. Analyze this C code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

C-specific vulnerabilities to look for:
- BUFFER_OVERFLOW: strcpy, strcat, sprintf, gets usage without bounds checking
- FORMAT_STRING: printf family functions with user-controlled format strings
- USE_AFTER_FREE: Using freed memory pointers
- DOUBLE_FREE: Calling free() twice on same pointer
- NULL_POINTER_DEREFERENCE: Using NULL pointers without checking
- INTEGER_OVERFLOW: Arithmetic operations without overflow checks
- RACE_CONDITION: Shared memory access without proper synchronization
- COMMAND_INJECTION: system(), popen() with user input
- PATH_TRAVERSAL: File operations with unsanitized paths
- HARDCODED_SECRETS: Passwords, keys embedded in code

Focus on memory safety and bounds checking issues.""",

            'cpp': f"""You are a C++ security expert. Analyze this C++ code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

C++-specific vulnerabilities to look for:
- BUFFER_OVERFLOW: Unsafe string operations, array bounds violations
- USE_AFTER_FREE: Using deleted objects or freed memory
- MEMORY_LEAK: Missing delete/delete[] calls, RAII violations
- DOUBLE_FREE: Multiple delete calls on same object
- INTEGER_OVERFLOW: Arithmetic operations without overflow checks
- RACE_CONDITION: Shared resource access without proper synchronization
- WEAK_CRYPTO: Weak cryptographic implementations
- HARDCODED_SECRETS: Embedded credentials or keys
- COMMAND_INJECTION: system() calls with user input
- PATH_TRAVERSAL: File operations with unsanitized paths

Consider modern C++ best practices and smart pointer usage.""",

            'csharp': f"""You are a C# security expert. Analyze this C# code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

C#-specific vulnerabilities to look for:
- SQL_INJECTION: String concatenation in SQL queries
- XSS: Unescaped output in ASP.NET applications
- INSECURE_DESERIALIZATION: BinaryFormatter, unsafe JSON deserialization
- XXE: XmlDocument, XmlReader without secure settings
- HARDCODED_SECRETS: Connection strings, API keys in code
- WEAK_CRYPTO: MD5, SHA1, DES usage
- PATH_TRAVERSAL: File operations with unsanitized paths
- LDAP_INJECTION: DirectorySearcher with user input
- COMMAND_INJECTION: Process.Start with user input
- INSECURE_RANDOM: System.Random for security purposes

Focus on .NET Framework and ASP.NET-specific issues.""",

            'go': f"""You are a Go security expert. Analyze this Go code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

Go-specific vulnerabilities to look for:
- SQL_INJECTION: String concatenation in database queries
- XSS: Unescaped template output, unsafe HTML generation
- HARDCODED_SECRETS: API keys, passwords in source code
- WEAK_CRYPTO: MD5, SHA1, weak ciphers usage
- COMMAND_INJECTION: exec.Command with user input
- PATH_TRAVERSAL: File operations with unsanitized paths
- RACE_CONDITION: Shared memory access without proper goroutine synchronization
- INSECURE_RANDOM: math/rand for security purposes (use crypto/rand)
- BUFFER_OVERFLOW: unsafe package usage
- FORMAT_STRING: fmt.Printf with user-controlled format strings

Consider Go-specific concurrency issues with goroutines.""",

            'php': f"""You are a PHP security expert. Analyze this PHP code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

PHP-specific vulnerabilities to look for:
- SQL_INJECTION: String concatenation in MySQL queries, no prepared statements
- XSS: Unescaped echo/print output, missing htmlspecialchars
- LFI: include/require with user input, file_get_contents with user paths
- RFI: Remote file inclusion in include/require statements
- COMMAND_INJECTION: shell_exec, system, exec with user input
- HARDCODED_SECRETS: Database passwords, API keys in code
- WEAK_CRYPTO: MD5, SHA1 for password hashing
- INSECURE_DESERIALIZATION: unserialize() on user data
- PATH_TRAVERSAL: File operations with unsanitized $_GET/$_POST data
- WEAK_SESSION_MANAGEMENT: session_start() without proper configuration

Focus on common PHP web application vulnerabilities.""",

            'ruby': f"""You are a Ruby security expert. Analyze this Ruby code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

Ruby-specific vulnerabilities to look for:
- SQL_INJECTION: String interpolation in ActiveRecord queries
- XSS: Unescaped output in ERB templates, raw HTML output
- COMMAND_INJECTION: system, backticks, %x with user input
- YAML_DESERIALIZATION: YAML.load on untrusted data (use YAML.safe_load)
- HARDCODED_SECRETS: API keys, database credentials in code
- WEAK_CRYPTO: MD5, SHA1 usage for security purposes
- PATH_TRAVERSAL: File.open, File.read with user input
- MASS_ASSIGNMENT: params without strong parameters in Rails
- INSECURE_RANDOM: Random.rand for security tokens (use SecureRandom)
- OPEN_REDIRECT: redirect_to with user input

Pay attention to Rails framework-specific issues.""",

            'rust': f"""You are a Rust security expert. Analyze this Rust code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

Rust-specific vulnerabilities to look for:
- UNSAFE_CODE: unsafe blocks that could introduce memory safety issues
- INTEGER_OVERFLOW: Arithmetic operations that could overflow
- HARDCODED_SECRETS: API keys, passwords embedded in code
- WEAK_CRYPTO: Weak cryptographic algorithms or implementations
- COMMAND_INJECTION: std::process::Command with user input
- PATH_TRAVERSAL: File operations with unsanitized paths
- INSECURE_RANDOM: Non-cryptographic random number generation
- BUFFER_OVERFLOW: Unsafe array/slice access in unsafe blocks
- RACE_CONDITION: Shared state without proper synchronization

Focus on unsafe code blocks and external interface security.""",

            'swift': f"""You are a Swift security expert. Analyze this Swift code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{base_json_format}

Swift-specific vulnerabilities to look for:
- SQL_INJECTION: String concatenation in database queries
- XSS: Unescaped output in web views
- HARDCODED_SECRETS: API keys, passwords in code
- WEAK_CRYPTO: Weak cryptographic algorithms
- INSECURE_RANDOM: arc4random() for security-critical purposes
- PATH_TRAVERSAL: File operations with unsanitized paths
- MEMORY_CORRUPTION: Unsafe pointers, force unwrapping
- INSECURE_NETWORKING: Unencrypted HTTP, certificate bypass
- KEYCHAIN_MISUSE: Improper keychain access, weak access control
- BIOMETRIC_BYPASS: Weak biometric authentication implementation

Consider iOS/macOS-specific security features and frameworks."""
        }

    def analyze_code(self, code: str, language: str, filename: str = "unknown") -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities using language-specific prompts
        """
        print(f"🔍 Analyzing {filename} ({language}) - {len(code.split())} words of code")

        # Get language-specific prompt
        prompt = self.language_prompts.get(language.lower())
        if not prompt:
            # Fallback to generic analysis
            prompt = self._get_generic_prompt()

        # Add line numbers to code for reference
        numbered_code = self._add_line_numbers(code)

        # Build the full analysis prompt
        full_prompt = f"{prompt}\n\nCODE TO ANALYZE ({language}):\n```{language}\n{numbered_code}\n```\n\nReturn only the JSON response:"

        payload = {
            "contents": [
                {
                    "parts": [{"text": full_prompt}],
                    "role": "user"
                }
            ],
            "generationConfig": {
                "temperature": 0.1,  # Low temperature for consistent analysis
                "maxOutputTokens": 3000,  # Increased for complex analysis
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
                timeout=45  # Increased timeout for complex analysis
            )

            response.raise_for_status()
            result = response.json()

            if 'candidates' in result and result['candidates']:
                gemini_response = result['candidates'][0]['content']['parts'][0]['text']

                # Extract JSON from response
                json_match = re.search(r'\{.*\}', gemini_response, re.DOTALL)
                if json_match:
                    analysis_result = json.loads(json_match.group())

                    # Add metadata
                    analysis_result['metadata'] = {
                        'filename': filename,
                        'language': language,
                        'analyzed_at': time.time(),
                        'code_length': len(code),
                        'line_count': len(code.split('\n')),
                        'gemini_tokens_used': result.get('usageMetadata', {}).get('totalTokenCount', 0)
                    }

                    vulnerabilities_count = len(analysis_result.get('vulnerabilities', []))
                    print(f"✅ Analysis complete! Found {vulnerabilities_count} potential issues in {language} code")

                    return analysis_result
                else:
                    return self._create_error_response("Failed to parse Gemini JSON response", gemini_response)
            else:
                return self._create_error_response("No response from Gemini API", str(result))

        except requests.exceptions.RequestException as e:
            return self._create_error_response(f"API request failed: {str(e)}")
        except json.JSONDecodeError as e:
            return self._create_error_response(f"JSON parsing failed: {str(e)}")
        except Exception as e:
            return self._create_error_response(f"Unexpected error: {str(e)}")

    def _get_generic_prompt(self) -> str:
        """Fallback prompt for unsupported languages"""
        return """You are a security expert. Analyze this code for common security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{
  "vulnerabilities": [
    {
      "line_number": 42,
      "vulnerability_type": "HARDCODED_SECRETS",
      "severity": "HIGH",
      "description": "API key or password found in source code",
      "code_snippet": "api_key = 'secret123'",
      "fix_suggestion": "Store secrets in environment variables or secure configuration",
      "confidence": 0.90
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 0,
    "low_count": 0
  }
}

Look for common vulnerabilities:
- HARDCODED_SECRETS: API keys, passwords, tokens in code
- COMMAND_INJECTION: User input in system commands
- PATH_TRAVERSAL: Unsafe file path operations
- WEAK_CRYPTO: Weak cryptographic algorithms
- INSECURE_RANDOM: Weak random number generation

Be precise with line numbers and only flag real vulnerabilities."""

    def _add_line_numbers(self, code: str) -> str:
        """Add line numbers to code for easier reference"""
        lines = code.split('\n')
        numbered_lines = []
        for i, line in enumerate(lines, 1):
            numbered_lines.append(f"{i:3d}: {line}")
        return '\n'.join(numbered_lines)

    def _create_error_response(self, error_message: str, raw_response: str = "") -> Dict[str, Any]:
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
                'low_count': 0
            }
        }

    def analyze_file(self, file_path: str, language: str = None) -> Dict[str, Any]:
        """Analyze a file for security vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            # Auto-detect language if not provided
            if not language:
                from .file_handler import FileHandler
                handler = FileHandler()
                language = handler.get_file_language(os.path.basename(file_path)) or 'unknown'

            return self.analyze_code(code, language, file_path)
        except FileNotFoundError:
            return self._create_error_response(f"File not found: {file_path}")
        except Exception as e:
            return self._create_error_response(f"Error reading file: {str(e)}")

    def get_supported_languages(self) -> List[str]:
        """Get list of languages with specialized analysis prompts"""
        return list(self.language_prompts.keys())

def test_multi_language_analysis():
    """Test the analyzer with different programming languages"""

    analyzer = EnhancedGeminiSecurityAnalyzer(API_KEY)

    # Test cases for different languages
    test_cases = {
        "java": '''
public class UserService {
    public User getUser(String userId) {
        String query = "SELECT * FROM users WHERE id = " + userId;
        return database.executeQuery(query);
    }

    private static final String API_KEY = "sk-abc123def456";
}''',

        "go": '''
package main

import (
    "fmt"
    "os/exec"
)

const APIKey = "secret-key-123"

func processFile(filename string) {
    cmd := exec.Command("convert", filename, "output.jpg")
    cmd.Run()
}''',

        "php": '''
<?php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
$result = mysql_query($query);

echo "<div>" . $_POST['content'] . "</div>";

$password = "admin123";
?>''',

        "csharp": '''
using System;
using System.Data.SqlClient;

public class UserController {
    private string connectionString = "Server=localhost;Database=app;User=admin;Password=secret123;";

    public User GetUser(string userId) {
        string query = "SELECT * FROM Users WHERE Id = " + userId;
        using (var connection = new SqlConnection(connectionString)) {
            var command = new SqlCommand(query, connection);
            // Execute query
        }
    }
}'''
    }

    print("🧪 TESTING MULTI-LANGUAGE SECURITY ANALYSIS")
    print("=" * 60)

    for language, code in test_cases.items():
        print(f"\n🎯 Testing {language.upper()} analysis:")
        print("-" * 40)

        result = analyzer.analyze_code(code, language, f"test.{language}")

        if result.get('error'):
            print(f"❌ Error: {result['message']}")
        else:
            vulns = result.get('vulnerabilities', [])
            summary = result.get('summary', {})

            print(f"📊 Found {len(vulns)} vulnerabilities:")
            for vuln in vulns:
                print(f"   🚨 Line {vuln['line_number']}: {vuln['vulnerability_type']} ({vuln['severity']})")
                print(f"      {vuln['description'][:60]}...")

        time.sleep(2)  # Rate limiting

    print(f"\n✅ Multi-language testing complete!")
    return True

if __name__ == "__main__":
    # Test multi-language capabilities
    test_multi_language_analysis()

GeminiSecurityAnalyzer = EnhancedGeminiSecurityAnalyzer
