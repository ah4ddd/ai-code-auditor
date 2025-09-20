"""
Static Analysis Pre-filter
Fast pattern-based vulnerability detection before AI analysis
"""
import re
import os
from typing import Dict, List, Tuple
import hashlib
import base64

class StaticAnalyzer:
    """Static analysis for common vulnerability patterns"""
    
    def __init__(self):
        # Common API key patterns
        self.api_key_patterns = [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'sk-[a-zA-Z0-9]{20,}',
            r'pk_[a-zA-Z0-9]{20,}',
            r'[a-zA-Z0-9]{32,}',
        ]
        
        # Password patterns
        self.password_patterns = [
            r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?pwd["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?pass["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        # Database connection patterns
        self.db_patterns = [
            r'["\']?database["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?db[_-]?host["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?db[_-]?user["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?db[_-]?pass["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        # Dangerous function calls
        self.dangerous_functions = {
            'python': [
                'os.system', 'subprocess.call', 'subprocess.run', 'exec', 'eval',
                'pickle.loads', 'pickle.load', 'yaml.load', 'yaml.safe_load'
            ],
            'javascript': [
                'eval', 'Function', 'setTimeout', 'setInterval', 'innerHTML',
                'document.write', 'document.writeln'
            ],
            'java': [
                'Runtime.exec', 'ProcessBuilder', 'Class.forName', 'Method.invoke'
            ],
            'php': [
                'eval', 'exec', 'system', 'shell_exec', 'passthru', 'popen'
            ],
            'c': ['system', 'exec', 'popen'],
            'cpp': ['system', 'exec', 'popen'],
        }
        
        # SQL injection patterns
        self.sql_patterns = [
            r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+.*',
            r'INSERT\s+INTO\s+.*\s+VALUES\s+.*\+.*',
            r'UPDATE\s+.*\s+SET\s+.*\+.*',
            r'DELETE\s+FROM\s+.*\s+WHERE\s+.*\+.*',
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r'innerHTML\s*=\s*[^;]+',
            r'document\.write\s*\([^)]+\)',
            r'\.html\s*\([^)]+\)',
        ]
    
    def analyze_file(self, content: str, filename: str, language: str) -> Dict:
        """
        Analyze file for common vulnerability patterns
        """
        vulnerabilities = []
        lines = content.split('\n')
        
        # Check for hardcoded secrets
        vulnerabilities.extend(self._check_hardcoded_secrets(content, lines))
        
        # Check for dangerous function calls
        vulnerabilities.extend(self._check_dangerous_functions(content, lines, language))
        
        # Check for SQL injection patterns
        vulnerabilities.extend(self._check_sql_injection(content, lines))
        
        # Check for XSS patterns
        vulnerabilities.extend(self._check_xss_patterns(content, lines))
        
        # Check for weak cryptography
        vulnerabilities.extend(self._check_weak_crypto(content, lines))
        
        # Check for insecure deserialization
        vulnerabilities.extend(self._check_insecure_deserialization(content, lines, language))
        
        # Check for path traversal
        vulnerabilities.extend(self._check_path_traversal(content, lines))
        
        # Check for command injection
        vulnerabilities.extend(self._check_command_injection(content, lines, language))
        
        # Calculate summary
        total_vulns = len(vulnerabilities)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "vulnerabilities": vulnerabilities,
            "critical_issues": severity_counts["critical"] > 0,
            "summary": {
                "total_vulnerabilities": total_vulns,
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"]
            }
        }
    
    def _check_hardcoded_secrets(self, content: str, lines: List[str]) -> List[Dict]:
        """Check for hardcoded API keys, passwords, and secrets"""
        vulnerabilities = []
        
        for pattern in self.api_key_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "HARDCODED_SECRETS",
                    "severity": "HIGH",
                    "description": "Hardcoded API key or secret detected",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": "Store API keys in environment variables or secure configuration management system",
                    "confidence": 0.95,
                    "detection_method": "static_pattern"
                })
        
        for pattern in self.password_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "HARDCODED_CREDENTIALS",
                    "severity": "HIGH",
                    "description": "Hardcoded password detected",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": "Use environment variables or secure password management",
                    "confidence": 0.90,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
    
    def _check_dangerous_functions(self, content: str, lines: List[str], language: str) -> List[Dict]:
        """Check for dangerous function calls"""
        vulnerabilities = []
        
        dangerous_funcs = self.dangerous_functions.get(language.lower(), [])
        
        for func in dangerous_funcs:
            pattern = rf'\b{re.escape(func)}\s*\('
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                severity = "CRITICAL" if func in ['eval', 'exec', 'system'] else "HIGH"
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "DANGEROUS_FUNCTION",
                    "severity": severity,
                    "description": f"Dangerous function '{func}' detected",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": f"Replace {func} with safer alternatives or validate input thoroughly",
                    "confidence": 0.85,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
    
    def _check_sql_injection(self, content: str, lines: List[str]) -> List[Dict]:
        """Check for SQL injection patterns"""
        vulnerabilities = []
        
        for pattern in self.sql_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "description": "Potential SQL injection vulnerability",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": "Use parameterized queries or prepared statements",
                    "confidence": 0.80,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
    
    def _check_xss_patterns(self, content: str, lines: List[str]) -> List[Dict]:
        """Check for XSS patterns"""
        vulnerabilities = []
        
        for pattern in self.xss_patterns:
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "XSS",
                    "severity": "MEDIUM",
                    "description": "Potential XSS vulnerability",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": "Sanitize user input and use safe DOM manipulation methods",
                    "confidence": 0.75,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
    
    def _check_weak_crypto(self, content: str, lines: List[str]) -> List[Dict]:
        """Check for weak cryptographic practices"""
        vulnerabilities = []
        
        weak_crypto_patterns = [
            (r'MD5\s*\(', "MD5", "CRITICAL"),
            (r'SHA1\s*\(', "SHA1", "HIGH"),
            (r'DES\s*\(', "DES", "HIGH"),
            (r'RC4\s*\(', "RC4", "HIGH"),
            (r'random\s*\(', "Weak random", "MEDIUM"),
        ]
        
        for pattern, algo, severity in weak_crypto_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "WEAK_CRYPTO",
                    "severity": severity,
                    "description": f"Weak cryptographic algorithm '{algo}' detected",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": f"Use stronger cryptographic algorithms like SHA-256, AES-256, or secure random generators",
                    "confidence": 0.90,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
    
    def _check_insecure_deserialization(self, content: str, lines: List[str], language: str) -> List[Dict]:
        """Check for insecure deserialization"""
        vulnerabilities = []
        
        deserialization_patterns = {
            'python': [r'pickle\.loads?\s*\(', r'yaml\.load\s*\('],
            'java': [r'ObjectInputStream', r'readObject\s*\('],
            'php': [r'unserialize\s*\(', r'json_decode\s*\('],
            'javascript': [r'JSON\.parse\s*\(', r'eval\s*\('],
        }
        
        patterns = deserialization_patterns.get(language.lower(), [])
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "INSECURE_DESERIALIZATION",
                    "severity": "HIGH",
                    "description": "Insecure deserialization detected",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": "Validate and sanitize deserialized data, use safe deserialization methods",
                    "confidence": 0.85,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
    
    def _check_path_traversal(self, content: str, lines: List[str]) -> List[Dict]:
        """Check for path traversal vulnerabilities"""
        vulnerabilities = []
        
        path_patterns = [
            r'\.\./',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
        ]
        
        for pattern in path_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "description": "Potential path traversal vulnerability",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": "Validate and sanitize file paths, use whitelist of allowed directories",
                    "confidence": 0.80,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
    
    def _check_command_injection(self, content: str, lines: List[str], language: str) -> List[Dict]:
        """Check for command injection vulnerabilities"""
        vulnerabilities = []
        
        command_patterns = {
            'python': [r'os\.system\s*\(', r'subprocess\.call\s*\(', r'subprocess\.run\s*\('],
            'php': [r'system\s*\(', r'exec\s*\(', r'shell_exec\s*\('],
            'javascript': [r'eval\s*\(', r'Function\s*\('],
            'java': [r'Runtime\.getRuntime\(\)\.exec\s*\('],
        }
        
        patterns = command_patterns.get(language.lower(), [])
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                vulnerabilities.append({
                    "line_number": line_num,
                    "vulnerability_type": "COMMAND_INJECTION",
                    "severity": "CRITICAL",
                    "description": "Potential command injection vulnerability",
                    "code_snippet": line_content.strip(),
                    "fix_suggestion": "Avoid executing user input as commands, use parameterized commands or input validation",
                    "confidence": 0.90,
                    "detection_method": "static_pattern"
                })
        
        return vulnerabilities
