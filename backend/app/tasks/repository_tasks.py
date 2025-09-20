"""
Repository Analysis Tasks
Handles repository cloning, file discovery, and orchestration
"""
from celery import current_task
from app.celery_app import celery_app
from app.services.github_integration import GitHubIntegration
from app.services.gemini_analyzer import GeminiSecurityAnalyzer
from app.utils.file_handler import FileHandler
import os
import json
import asyncio
from typing import Dict, List
from datetime import datetime

@celery_app.task(bind=True, name="scan_repository")
def scan_repository_task(self, repo_url: str, branch: str = "main", github_token: str = None):
    """
    Main repository scanning task
    """
    try:
        # Update task state
        self.update_state(
            state="PROGRESS",
            meta={"status": "Initializing", "progress": 0, "message": "Starting repository scan"}
        )
        
        # Initialize services
        github_integration = GitHubIntegration(github_token)
        gemini_analyzer = GeminiSecurityAnalyzer(os.getenv("GEMINI_API_KEY"))
        file_handler = FileHandler()
        
        temp_dir = None
        
        try:
            # Step 1: Clone repository
            self.update_state(
                state="PROGRESS",
                meta={"status": "Cloning", "progress": 10, "message": f"Cloning repository from {repo_url}"}
            )
            
            temp_dir, repo_name = asyncio.run(github_integration.clone_repository(repo_url, branch))
            
            # Step 2: Discover files
            self.update_state(
                state="PROGRESS",
                meta={"status": "Discovering", "progress": 20, "message": "Discovering analyzable files"}
            )
            
            files = asyncio.run(github_integration.discover_files(temp_dir))
            
            if not files:
                return {
                    "status": "completed",
                    "message": "No analyzable files found",
                    "results": {
                        "files": [],
                        "overall_summary": {
                            "total_vulnerabilities": 0,
                            "critical_count": 0,
                            "high_count": 0,
                            "medium_count": 0,
                            "low_count": 0,
                            "info_count": 0,
                            "total_files_analyzed": 0,
                            "languages_detected": []
                        }
                    }
                }
            
            # Step 3: Analyze files in parallel
            self.update_state(
                state="PROGRESS",
                meta={"status": "Analyzing", "progress": 30, "message": f"Analyzing {len(files)} files"}
            )
            
            # Create file analysis tasks
            file_tasks = []
            for i, file_info in enumerate(files):
                task = analyze_file_task.delay(
                    file_info["full_path"],
                    file_info["filename"],
                    file_info["language"],
                    file_info["path"]
                )
                file_tasks.append((task, file_info))
            
            # Wait for all file analyses to complete
            results = []
            total_files = len(file_tasks)
            
            for i, (task, file_info) in enumerate(file_tasks):
                try:
                    # Update progress
                    progress = 30 + int((i / total_files) * 60)  # 30-90%
                    self.update_state(
                        state="PROGRESS",
                        meta={
                            "status": "Analyzing",
                            "progress": progress,
                            "message": f"Analyzing {file_info['filename']} ({i+1}/{total_files})"
                        }
                    )
                    
                    # Get result
                    result = task.get(timeout=300)  # 5 minute timeout per file
                    
                    if result and not result.get("error"):
                        results.append({
                            "filename": file_info["path"],
                            "analysis": result
                        })
                    
                except Exception as e:
                    print(f"❌ Failed to analyze {file_info['filename']}: {str(e)}")
                    continue
            
            # Step 4: Aggregate results
            self.update_state(
                state="PROGRESS",
                meta={"status": "Aggregating", "progress": 90, "message": "Aggregating results"}
            )
            
            aggregated_results = aggregate_repository_results(results, files)
            
            # Step 5: Cleanup
            asyncio.run(github_integration.cleanup_repository(temp_dir))
            
            # Final result
            self.update_state(
                state="SUCCESS",
                meta={
                    "status": "Completed",
                    "progress": 100,
                    "message": f"Repository scan completed. Found {aggregated_results['overall_summary']['total_vulnerabilities']} vulnerabilities"
                }
            )
            
            return {
                "status": "completed",
                "repository": repo_name,
                "branch": branch,
                "total_files": len(files),
                "analyzed_files": len(results),
                "results": aggregated_results,
                "metadata": {
                    "scanned_at": datetime.now().isoformat(),
                    "repo_url": repo_url,
                    "branch": branch
                }
            }
            
        except Exception as e:
            # Cleanup on error
            if temp_dir:
                asyncio.run(github_integration.cleanup_repository(temp_dir))
            
            self.update_state(
                state="FAILURE",
                meta={"status": "Failed", "message": str(e)}
            )
            raise e
            
    except Exception as e:
        self.update_state(
            state="FAILURE",
            meta={"status": "Failed", "message": str(e)}
        )
        raise e

@celery_app.task(bind=True, name="analyze_file")
def analyze_file_task(self, file_path: str, filename: str, language: str, relative_path: str):
    """
    Analyze a single file for security vulnerabilities
    """
    try:
        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Analyze with Gemini
        gemini_analyzer = GeminiSecurityAnalyzer(os.getenv("GEMINI_API_KEY"))
        result = gemini_analyzer.analyze_code(content, filename, language)
        
        return result
        
    except Exception as e:
        return {"error": str(e), "filename": filename}

def aggregate_repository_results(file_results: List[Dict], all_files: List[Dict]) -> Dict:
    """
    Aggregate results from multiple file analyses
    """
    total_vulnerabilities = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    languages_found = set()
    vulnerability_types = {}
    
    for file_result in file_results:
        analysis = file_result.get("analysis", {})
        vulnerabilities = analysis.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
                total_vulnerabilities += 1
            
            # Track vulnerability types
            vuln_type = vuln.get("vulnerability_type", "UNKNOWN")
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        # Track languages
        metadata = analysis.get("metadata", {})
        if metadata.get("language"):
            languages_found.add(metadata["language"])
    
    # Calculate risk level
    risk_level = calculate_repository_risk_level(severity_counts)
    
    return {
        "files": file_results,
        "overall_summary": {
            "total_vulnerabilities": total_vulnerabilities,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "info_count": severity_counts["info"],
            "total_files_analyzed": len(file_results),
            "total_files_discovered": len(all_files),
            "languages_detected": list(languages_found),
            "vulnerability_types": vulnerability_types,
            "risk_level": risk_level
        }
    }

def calculate_repository_risk_level(severity_counts: Dict) -> str:
    """
    Calculate overall risk level for repository
    """
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    medium = severity_counts.get("medium", 0)
    low = severity_counts.get("low", 0)
    
    if critical > 0:
        return "CRITICAL"
    elif critical == 0 and high >= 5:
        return "HIGH"
    elif critical == 0 and high >= 2:
        return "MEDIUM"
    elif critical == 0 and high == 1 and medium >= 5:
        return "MEDIUM"
    elif critical == 0 and high == 1:
        return "LOW"
    elif critical == 0 and high == 0 and medium >= 10:
        return "LOW"
    else:
        return "MINIMAL"
