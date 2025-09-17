import json
import requests
import time
import re
from typing import List, Dict, Optional
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
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    HARDCODED_SECRETS = "HARDCODED_SECRETS"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    INSECURE_AUTH = "INSECURE_AUTH"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    WEAK_RANDOM = "WEAK_RANDOM"
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"

@dataclass
class Vulnerability:
    line_number: int
    vulnerability_type: VulnerabilityType
    severity: Severity
    description: str
    code_snippet: str
    fix_suggestion: str
    confidence: float  # 0.0 to 1.0

class GeminiSecurityAnalyzer:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

        # Security analysis prompt
        self.security_prompt = """You are a world-class security expert and code auditor. Analyze the following Python code for security vulnerabilities.

CRITICAL: Return ONLY valid JSON in this exact format:
{
  "vulnerabilities": [
    {
      "line_number": 42,
      "vulnerability_type": "SQL_INJECTION",
      "severity": "HIGH",
      "description": "Direct string concatenation in SQL query allows injection attacks",
      "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
      "fix_suggestion": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
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
}

Look for these vulnerability types:
- SQL_INJECTION: Unsanitized input in SQL queries
- XSS: Unescaped output in web responses
- HARDCODED_SECRETS: API keys, passwords, tokens in code
- WEAK_CRYPTO: MD5, SHA1, weak encryption
- INSECURE_AUTH: Poor password handling, weak session management
- PATH_TRAVERSAL: Unchecked file paths
- COMMAND_INJECTION: Unsanitized input in system commands
- INSECURE_DESERIALIZATION: Unsafe pickle, eval usage
- WEAK_RANDOM: Predictable random number generation
- INSUFFICIENT_LOGGING: Missing security event logging

Severity levels:
- CRITICAL: Immediate exploitation possible, data breach likely
- HIGH: Easy to exploit, significant impact
- MEDIUM: Requires some skill to exploit, moderate impact
- LOW: Difficult to exploit or minor impact
- INFO: Security best practice violations

Be precise with line numbers. Only flag REAL vulnerabilities, not theoretical ones.
"""

    def analyze_code(self, python_code: str, filename: str = "unknown.py") -> Dict:
        """
        Analyze Python code for security vulnerabilities using Gemini
        Returns structured vulnerability data or error info
        """
        print(f"🔍 Analyzing {filename} ({len(python_code.split())} words of code)")

        # Add line numbers to code for reference
        numbered_code = self._add_line_numbers(python_code)

        # Build the analysis prompt
        full_prompt = f"{self.security_prompt}\n\nCODE TO ANALYZE:\n```python\n{numbered_code}\n```\n\nReturn only the JSON response:"

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
            print("🤖 Sending code to Gemini for analysis...")

            response = requests.post(
                self.base_url,
                headers={
                    'Content-Type': 'application/json',
                    'X-goog-api-key': self.api_key
                },
                json=payload,
                timeout=30
            )

            response.raise_for_status()
            result = response.json()

            if 'candidates' in result and result['candidates']:
                gemini_response = result['candidates'][0]['content']['parts'][0]['text']

                # Extract JSON from response (Gemini sometimes adds extra text)
                json_match = re.search(r'\{.*\}', gemini_response, re.DOTALL)
                if json_match:
                    analysis_result = json.loads(json_match.group())

                    # Add metadata
                    analysis_result['metadata'] = {
                        'filename': filename,
                        'analyzed_at': time.time(),
                        'code_length': len(python_code),
                        'gemini_tokens_used': result.get('usageMetadata', {}).get('totalTokenCount', 0)
                    }

                    print(f"✅ Analysis complete! Found {len(analysis_result.get('vulnerabilities', []))} potential issues")
                    return analysis_result
                else:
                    return self._create_error_response("Failed to parse Gemini JSON response", gemini_response)
            else:
                return self._create_error_response("No response from Gemini API", str(result))

        except requests.exceptions.RequestException as e:
            return self._create_error_response(f"API request failed: {str(e)}")
        except json.JSONDecodeError as e:
            return self._create_error_response(f"JSON parsing failed: {str(e)}", gemini_response)
        except Exception as e:
            return self._create_error_response(f"Unexpected error: {str(e)}")

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
                'low_count': 0
            }
        }

    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a Python file for security vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            return self.analyze_code(code, file_path)
        except FileNotFoundError:
            return self._create_error_response(f"File not found: {file_path}")
        except Exception as e:
            return self._create_error_response(f"Error reading file: {str(e)}")

def test_vulnerable_code_samples():
    """
    Test the analyzer with known vulnerable code samples
    This proves whether Gemini can actually catch real security issues
    """

     #Gemini API key

    analyzer = GeminiSecurityAnalyzer(API_KEY)

    # Test cases with known vulnerabilities
    test_cases = {
        "sql_injection": '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result
''',

        "hardcoded_secrets": '''
import requests

# VULNERABLE: Hardcoded API key
API_KEY = "sk-abc123def456ghi789jkl012mno345"
DATABASE_PASSWORD = "admin123"

def make_api_call():
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    response = requests.get('https://api.example.com/data', headers=headers)
    return response.json()
''',

        "command_injection": '''
import os
import subprocess

def process_file(filename):
    # VULNERABLE: Unsanitized input in shell command
    command = f"convert {filename} output.jpg"
    os.system(command)

    # Also vulnerable
    subprocess.call(f"rm -rf /tmp/{filename}", shell=True)
''',

        "weak_crypto": '''
import hashlib
import random

def hash_password(password):
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # VULNERABLE: Weak random number generation
    token = ""
    for i in range(32):
        token += str(random.randint(0, 9))
    return token
''',

        "insecure_deserialization": '''
import pickle
import json

def load_user_data(data):
    # VULNERABLE: Unpickling untrusted data
    user_obj = pickle.loads(data)
    return user_obj

def process_config(config_str):
    # VULNERABLE: eval() on user input
    config = eval(config_str)
    return config['settings']
'''
    }

    print("🧪 TESTING GEMINI'S SECURITY ANALYSIS CAPABILITIES")
    print("=" * 60)

    results = {}

    for test_name, vulnerable_code in test_cases.items():
        print(f"\n🎯 Testing: {test_name.replace('_', ' ').title()}")
        print("-" * 40)

        result = analyzer.analyze_code(vulnerable_code, f"{test_name}.py")
        results[test_name] = result

        if result.get('error'):
            print(f"❌ Error: {result['message']}")
        else:
            vulns = result.get('vulnerabilities', [])
            summary = result.get('summary', {})

            print(f"📊 Found {len(vulns)} vulnerabilities:")
            print(f"   Critical: {summary.get('critical_count', 0)}")
            print(f"   High: {summary.get('high_count', 0)}")
            print(f"   Medium: {summary.get('medium_count', 0)}")
            print(f"   Low: {summary.get('low_count', 0)}")

            for vuln in vulns:
                print(f"   🚨 Line {vuln['line_number']}: {vuln['vulnerability_type']} ({vuln['severity']})")
                print(f"      {vuln['description'][:80]}...")

        time.sleep(2)  # Be nice to the API

    print("\n" + "=" * 60)
    print("🎯 ANALYSIS COMPLETE!")

    # Calculate success metrics
    total_tests = len(test_cases)
    successful_analyses = sum(1 for r in results.values() if not r.get('error'))
    vulnerabilities_found = sum(len(r.get('vulnerabilities', [])) for r in results.values())

    print(f"📈 Results Summary:")
    print(f"   Tests run: {total_tests}")
    print(f"   Successful analyses: {successful_analyses}/{total_tests}")
    print(f"   Total vulnerabilities detected: {vulnerabilities_found}")
    print(f"   Success rate: {(successful_analyses/total_tests)*100:.1f}%")

    if vulnerabilities_found > 0:
        print("\n✅ GEMINI CAN DETECT SECURITY VULNERABILITIES!")
        print("   This proves our core concept works. Time to build the full system!")
    else:
        print("\n❌ GEMINI FAILED TO DETECT VULNERABILITIES")
        print("   We need to either improve our prompts or add static analysis backup")

    return results

if __name__ == "__main__":
    # Run the core test to see if our business idea actually works
    test_results = test_vulnerable_code_samples()

    # Save results for analysis
    with open('gemini_analysis_test_results.json', 'w') as f:
        json.dump(test_results, f, indent=2)

    print(f"\n💾 Results saved to 'gemini_analysis_test_results.json'")
    print("\n🚀 If this worked, we're ready to build the full product!")
