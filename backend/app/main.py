"""
AI Code Security Auditor - FastAPI Backend
Handles file uploads, analysis orchestration, and results management
"""
from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import zipfile
import tempfile
import os
import json
import uuid
from typing import List, Optional, Dict
import asyncio
from datetime import datetime
import shutil

from app.services.gemini_analyzer import GeminiSecurityAnalyzer
from app.services.report_generator import ReportGenerator
from app.parsers.code_parser import CodebaseParser
from app.models.analysis import AnalysisResult, AnalysisStatus
from app.utils.file_handler import FileHandler

app = FastAPI(
    title="AI Security Auditor",
    description="Professional code security analysis powered by AI",
    version="1.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security for API
security = HTTPBearer()

# Global instances
analyzer = GeminiSecurityAnalyzer("AIzaSyA9iKMWOTIEKPegzKuRUqhKj0h7yWQzY4U")
report_gen = ReportGenerator()
parser = CodebaseParser()
file_handler = FileHandler()

# In-memory storage for demo (use Redis/DB in production)
analysis_storage = {}
analysis_queue = {}

@app.get("/")
async def root():
    return {"message": "AI Security Auditor API", "status": "operational", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# ============================================================================
# FILE UPLOAD & ANALYSIS ENDPOINTS
# ============================================================================

@app.post("/api/analyze/file")
async def analyze_single_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Analyze a single code file for security vulnerabilities"""

    # Validate file
    if not file.filename.endswith(('.py', '.js', '.java', '.go', '.php')):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Supported: .py, .js, .java, .go, .php"
        )

    if file.size > 1024 * 1024:  # 1MB limit
        raise HTTPException(status_code=400, detail="File too large. Max size: 1MB")

    # Create analysis job
    analysis_id = str(uuid.uuid4())

    try:
        # Read file content
        content = await file.read()
        code_content = content.decode('utf-8')

        # Initialize analysis record
        analysis_storage[analysis_id] = {
            'id': analysis_id,
            'filename': file.filename,
            'status': AnalysisStatus.PROCESSING,
            'created_at': datetime.now().isoformat(),
            'file_count': 1,
            'results': None,
            'error': None
        }

        # Start background analysis
        background_tasks.add_task(
            analyze_single_file_background,
            analysis_id,
            code_content,
            file.filename
        )

        return JSONResponse({
            'analysis_id': analysis_id,
            'status': 'processing',
            'message': f'Analysis started for {file.filename}',
            'estimated_time': '30-60 seconds'
        })

    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not valid UTF-8 text")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze/codebase")
async def analyze_codebase(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Analyze an entire codebase (ZIP file) for security vulnerabilities"""

    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only ZIP files are supported")

    if file.size > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=400, detail="ZIP file too large. Max size: 50MB")

    analysis_id = str(uuid.uuid4())

    try:
        # Save uploaded ZIP temporarily
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, f"{analysis_id}.zip")

        with open(zip_path, 'wb') as f:
            content = await file.read()
            f.write(content)

        # Extract and validate ZIP
        extracted_files = file_handler.extract_and_validate_zip(zip_path, temp_dir)

        if not extracted_files:
            shutil.rmtree(temp_dir)
            raise HTTPException(status_code=400, detail="No supported code files found in ZIP")

        # Initialize analysis record
        analysis_storage[analysis_id] = {
            'id': analysis_id,
            'filename': file.filename,
            'status': AnalysisStatus.PROCESSING,
            'created_at': datetime.now().isoformat(),
            'file_count': len(extracted_files),
            'results': None,
            'error': None,
            'temp_dir': temp_dir
        }

        # Start background analysis
        background_tasks.add_task(
            analyze_codebase_background,
            analysis_id,
            extracted_files,
            temp_dir
        )

        return JSONResponse({
            'analysis_id': analysis_id,
            'status': 'processing',
            'message': f'Codebase analysis started for {file.filename}',
            'files_found': len(extracted_files),
            'estimated_time': f'{len(extracted_files) * 30} seconds'
        })

    except Exception as e:
        if 'temp_dir' in locals():
            shutil.rmtree(temp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/analyze/{analysis_id}/status")
async def get_analysis_status(analysis_id: str):
    """Get the current status of an analysis job"""

    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analysis_storage[analysis_id]
    return {
        'analysis_id': analysis_id,
        'status': analysis['status'],
        'filename': analysis['filename'],
        'file_count': analysis['file_count'],
        'created_at': analysis['created_at'],
        'progress': calculate_progress(analysis)
    }

@app.get("/api/analyze/{analysis_id}/results")
async def get_analysis_results(analysis_id: str):
    """Get the detailed results of a completed analysis"""

    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analysis_storage[analysis_id]

    if analysis['status'] == AnalysisStatus.PROCESSING:
        raise HTTPException(status_code=202, detail="Analysis still in progress")

    if analysis['status'] == AnalysisStatus.FAILED:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {analysis['error']}")

    return {
        'analysis_id': analysis_id,
        'status': analysis['status'],
        'results': analysis['results'],
        'summary': generate_summary(analysis['results'])
    }

@app.get("/api/analyze/{analysis_id}/report")
async def download_report(analysis_id: str, format: str = "pdf"):
    """Download analysis report in PDF or HTML format"""

    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analysis_storage[analysis_id]

    if analysis['status'] != AnalysisStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Analysis not completed")

    try:
        if format.lower() == "pdf":
            report_path = report_gen.generate_pdf_report(analysis['results'], analysis_id)
            return FileResponse(
                report_path,
                filename=f"security_analysis_{analysis_id}.pdf",
                media_type="application/pdf"
            )
        elif format.lower() == "html":
            report_path = report_gen.generate_html_report(analysis['results'], analysis_id)
            return FileResponse(
                report_path,
                filename=f"security_analysis_{analysis_id}.html",
                media_type="text/html"
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use 'pdf' or 'html'")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

# ============================================================================
# BACKGROUND ANALYSIS TASKS
# ============================================================================

async def analyze_single_file_background(analysis_id: str, code_content: str, filename: str):
    """Background task to analyze a single file"""

    try:
        print(f"🔍 Starting analysis for {filename} (ID: {analysis_id})")

        # Run Gemini analysis
        result = analyzer.analyze_code(code_content, filename)

        if result.get('error'):
            analysis_storage[analysis_id]['status'] = AnalysisStatus.FAILED
            analysis_storage[analysis_id]['error'] = result['message']
        else:
            analysis_storage[analysis_id]['status'] = AnalysisStatus.COMPLETED
            analysis_storage[analysis_id]['results'] = {
                'files': [{
                    'filename': filename,
                    'analysis': result
                }],
                'overall_summary': result['summary']
            }

        print(f"✅ Analysis completed for {filename}")

    except Exception as e:
        print(f"❌ Analysis failed for {filename}: {str(e)}")
        analysis_storage[analysis_id]['status'] = AnalysisStatus.FAILED
        analysis_storage[analysis_id]['error'] = str(e)

async def analyze_codebase_background(analysis_id: str, file_paths: List[str], temp_dir: str):
    """Background task to analyze an entire codebase"""

    try:
        print(f"🔍 Starting codebase analysis (ID: {analysis_id}) - {len(file_paths)} files")

        results = []
        total_vulns = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for i, file_path in enumerate(file_paths):
            try:
                print(f"   Analyzing {os.path.basename(file_path)} ({i+1}/{len(file_paths)})")

                with open(file_path, 'r', encoding='utf-8') as f:
                    code_content = f.read()

                # Skip empty files
                if len(code_content.strip()) < 10:
                    continue

                # Analyze with Gemini
                result = analyzer.analyze_code(code_content, os.path.basename(file_path))

                if not result.get('error'):
                    results.append({
                        'filename': os.path.relpath(file_path, temp_dir),
                        'analysis': result
                    })

                    # Aggregate statistics
                    vulns = result.get('vulnerabilities', [])
                    total_vulns += len(vulns)

                    for vuln in vulns:
                        sev = vuln['severity'].lower()
                        if sev in severity_counts:
                            severity_counts[sev] += 1

                # Rate limiting - be nice to the API
                await asyncio.sleep(1)

            except Exception as file_error:
                print(f"   ⚠️ Failed to analyze {file_path}: {str(file_error)}")
                continue

        # Compile final results
        final_results = {
            'files': results,
            'overall_summary': {
                'total_files_analyzed': len(results),
                'total_vulnerabilities': total_vulns,
                'critical_count': severity_counts['critical'],
                'high_count': severity_counts['high'],
                'medium_count': severity_counts['medium'],
                'low_count': severity_counts['low']
            }
        }

        analysis_storage[analysis_id]['status'] = AnalysisStatus.COMPLETED
        analysis_storage[analysis_id]['results'] = final_results

        print(f"✅ Codebase analysis completed - Found {total_vulns} vulnerabilities")

    except Exception as e:
        print(f"❌ Codebase analysis failed: {str(e)}")
        analysis_storage[analysis_id]['status'] = AnalysisStatus.FAILED
        analysis_storage[analysis_id]['error'] = str(e)

    finally:
        # Cleanup temp directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def calculate_progress(analysis: Dict) -> int:
    """Calculate analysis progress percentage"""
    if analysis['status'] == AnalysisStatus.COMPLETED:
        return 100
    elif analysis['status'] == AnalysisStatus.FAILED:
        return 0
    else:
        # Simple time-based estimation for demo
        created_time = datetime.fromisoformat(analysis['created_at'])
        elapsed = (datetime.now() - created_time).total_seconds()
        estimated_total = analysis['file_count'] * 30  # 30 seconds per file
        progress = min(int((elapsed / estimated_total) * 100), 90)
        return progress

def generate_summary(results: Dict) -> Dict:
    """Generate executive summary of analysis results"""
    if not results:
        return {}

    summary = results.get('overall_summary', {})

    risk_level = "LOW"
    if summary.get('critical_count', 0) > 0:
        risk_level = "CRITICAL"
    elif summary.get('high_count', 0) > 2:
        risk_level = "HIGH"
    elif summary.get('high_count', 0) > 0 or summary.get('medium_count', 0) > 5:
        risk_level = "MEDIUM"

    return {
        'risk_level': risk_level,
        'total_issues': summary.get('total_vulnerabilities', 0),
        'files_with_issues': len([f for f in results.get('files', [])
                                 if len(f['analysis'].get('vulnerabilities', [])) > 0]),
        'most_common_issues': get_most_common_vulnerabilities(results),
        'recommendations': generate_recommendations(summary)
    }

def get_most_common_vulnerabilities(results: Dict) -> List[str]:
    """Identify most common vulnerability types"""
    vuln_counts = {}

    for file_result in results.get('files', []):
        for vuln in file_result['analysis'].get('vulnerabilities', []):
            vuln_type = vuln['vulnerability_type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

    # Return top 3 most common
    sorted_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)
    return [vuln_type for vuln_type, count in sorted_vulns[:3]]

def generate_recommendations(summary: Dict) -> List[str]:
    """Generate actionable recommendations based on findings"""
    recommendations = []

    if summary.get('critical_count', 0) > 0:
        recommendations.append("Address CRITICAL vulnerabilities immediately - they pose immediate security risk")

    if summary.get('high_count', 0) > 0:
        recommendations.append("Fix HIGH severity issues within 48 hours")

    if summary.get('medium_count', 0) > 3:
        recommendations.append("Plan remediation for MEDIUM severity issues within next sprint")

    recommendations.append("Implement automated security scanning in CI/CD pipeline")
    recommendations.append("Conduct security code review training for development team")

    return recommendations

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
