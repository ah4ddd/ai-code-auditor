"""
Risk Scorer Service
Computes numeric scores per file and repository based on vulnerability severities.
"""
from typing import Dict, List


class RiskScorer:
    def __init__(self):
        # Explicit mapping per spec
        self.weights = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1,
        }

    def score_file(self, file_analysis: Dict) -> int:
        score = 0
        for vuln in file_analysis.get("vulnerabilities", []) or []:
            sev = (vuln.get("severity") or "LOW").upper()
            score += self.weights.get(sev, 1)
        return score

    def score_repository(self, files: List[Dict], dependency_risk: int = 0) -> int:
        total = dependency_risk
        for file_result in files:
            analysis = file_result.get("analysis", {})
            total += self.score_file(analysis)
        return total


