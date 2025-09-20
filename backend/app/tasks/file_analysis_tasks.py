"""
File Analysis Tasks
Handles individual file analysis with pre-filtering
"""
from celery import current_task
from app.celery_app import celery_app
from app.services.gemini_analyzer import GeminiSecurityAnalyzer
from app.utils.static_analyzer import StaticAnalyzer
import os
import re
from typing import Dict, List

@celery_app.task(bind=True, name="analyze_file_with_prefilter")
def analyze_file_with_prefilter_task(self, file_path: str, filename: str, language: str, content: str):
    """
    Analyze file with static pre-filtering before AI analysis
    """
    try:
        # Step 1: Static analysis pre-filtering
        static_analyzer = StaticAnalyzer()
        static_results = static_analyzer.analyze_file(content, filename, language)
        
        # If static analysis found critical issues, return immediately
        if static_results.get("critical_issues"):
            return {
                "vulnerabilities": static_results["vulnerabilities"],
                "summary": {
                    "total_vulnerabilities": len(static_results["vulnerabilities"]),
                    "critical_count": len([v for v in static_results["vulnerabilities"] if v["severity"] == "CRITICAL"]),
                    "high_count": len([v for v in static_results["vulnerabilities"] if v["severity"] == "HIGH"]),
                    "medium_count": len([v for v in static_results["vulnerabilities"] if v["severity"] == "MEDIUM"]),
                    "low_count": len([v for v in static_results["vulnerabilities"] if v["severity"] == "LOW"]),
                    "info_count": len([v for v in static_results["vulnerabilities"] if v["severity"] == "INFO"])
                },
                "metadata": {
                    "filename": filename,
                    "language": language,
                    "analysis_method": "static_only",
                    "code_length": len(content)
                }
            }
        
        # Step 2: AI analysis for complex patterns
        gemini_analyzer = GeminiSecurityAnalyzer(os.getenv("GEMINI_API_KEY"))
        ai_result = gemini_analyzer.analyze_code(content, filename, language)
        
        # Step 3: Combine static and AI results
        if ai_result.get("error"):
            return static_results
        
        # Merge vulnerabilities (avoid duplicates)
        all_vulnerabilities = static_results["vulnerabilities"].copy()
        ai_vulnerabilities = ai_result.get("vulnerabilities", [])
        
        for ai_vuln in ai_vulnerabilities:
            # Check for duplicates based on line number and type
            is_duplicate = any(
                v["line_number"] == ai_vuln["line_number"] and 
                v["vulnerability_type"] == ai_vuln["vulnerability_type"]
                for v in all_vulnerabilities
            )
            
            if not is_duplicate:
                all_vulnerabilities.append(ai_vuln)
        
        # Update summary
        total_vulns = len(all_vulnerabilities)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in all_vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            "vulnerabilities": all_vulnerabilities,
            "summary": {
                "total_vulnerabilities": total_vulns,
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"]
            },
            "metadata": {
                "filename": filename,
                "language": language,
                "analysis_method": "static_plus_ai",
                "code_length": len(content),
                "static_issues": len(static_results["vulnerabilities"]),
                "ai_issues": len(ai_vulnerabilities)
            }
        }
        
    except Exception as e:
        return {"error": str(e), "filename": filename}

@celery_app.task(bind=True, name="batch_analyze_files")
def batch_analyze_files_task(self, files_data: List[Dict]):
    """
    Analyze multiple files in batch for efficiency
    """
    try:
        results = []
        total_files = len(files_data)
        
        for i, file_data in enumerate(files_data):
            # Update progress
            progress = int((i / total_files) * 100)
            self.update_state(
                state="PROGRESS",
                meta={
                    "status": "Processing",
                    "progress": progress,
                    "message": f"Analyzing {file_data['filename']} ({i+1}/{total_files})"
                }
            )
            
            # Analyze file
            result = analyze_file_with_prefilter_task.delay(
                file_data["file_path"],
                file_data["filename"],
                file_data["language"],
                file_data["content"]
            ).get()
            
            results.append({
                "filename": file_data["filename"],
                "path": file_data["path"],
                "analysis": result
            })
        
        return {
            "status": "completed",
            "results": results,
            "total_files": total_files
        }
        
    except Exception as e:
        self.update_state(
            state="FAILURE",
            meta={"status": "Failed", "message": str(e)}
        )
        raise e
