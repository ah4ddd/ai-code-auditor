"""
Data models for analysis results and status tracking
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime

class AnalysisStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    line_number: int
    vulnerability_type: str
    severity: VulnerabilitySeverity
    description: str
    code_snippet: str
    fix_suggestion: str
    confidence: float

@dataclass
class FileAnalysis:
    filename: str
    language: str
    vulnerabilities: List[Vulnerability]
    code_stats: Dict
    analysis_time: float

@dataclass
class AnalysisResult:
    analysis_id: str
    status: AnalysisStatus
    created_at: datetime
    completed_at: Optional[datetime]
    files: List[FileAnalysis]
    summary: Dict
    error_message: Optional[str] = None
