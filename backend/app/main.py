"""
AI Code Security Auditor - FastAPI Backend
Fixed version with proper file handling and multi-language support
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
from dotenv import load_dotenv
import os

from app.services.gemini_analyzer import GeminiSecurityAnalyzer
from app.utils.file_handler import FileHandler

# Load environment variables
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("❌ GEMINI_API_KEY not found in environment variables!")
    exit(1)

app = FastAPI(
    title="AI Security Auditor",
    description="Professional code security analysis powered by AI - Now supports 40+ languages",
    version="2.0.0"
)

# Enhanced CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security for API
security = HTTPBearer()

# Global instances
analyzer = GeminiSecurityAnalyzer(GEMINI_API_KEY)
file_handler = FileHandler()

# In-memory storage for demo (use Redis/DB in production)
analysis_storage = {}

# Analysis status enum
class AnalysisStatus:
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

@app.get("/")
async def root():
    return {
        "message": "AI Security Auditor API",
        "status": "operational",
        "version": "2.0.0",
        "supported_languages": "40+ programming languages"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "gemini_api": "connected" if GEMINI_API_KEY else "missing"
    }

@app.get("/api/languages")
async def supported_languages():
    """Get list of all supported programming languages"""
    return {
        "languages": list(file_handler.SUPPORTED_EXTENSIONS.keys()),
        "count": len(file_handler.SUPPORTED_EXTENSIONS),
        "categories": {
            "backend": ["python", "java", "go", "rust", "csharp", "php", "ruby"],
            "frontend": ["javascript", "typescript", "html", "css"],
            "systems": ["c", "cpp", "rust", "assembly"],
            "mobile": ["swift", "kotlin", "dart"],
            "database": ["sql", "postgresql", "mysql"],
            "devops": ["bash", "powershell", "dockerfile", "yaml"]
        }
    }

# ============================================================================
# ENHANCED FILE UPLOAD & ANALYSIS ENDPOINTS
# ============================================================================

@app.post("/api/analyze/file")
async def analyze_single_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Analyze a single code file - supports 40+ programming languages"""

    print(f"📤 Received file: {file.filename} ({file.size} bytes)")

    # Enhanced file validation - ACCEPTS ALL TEXT FILES
    language = file_handler.get_file_language(file.filename)
    # Note: get_file_language now NEVER returns None/False, always returns a string

    # Only check if it's actually a text file (not binary)
    if not file_handler._is_text_file_by_name(file.filename):
        raise HTTPException(
            status_code=400,
            detail=f"File appears to be binary. We analyze text-based files including source code, scripts, config files, and any readable text format."
        )

    # File size validation - increased for enterprise files
    max_size = 10 * 1024 * 1024  # 10MB limit
    if file.size > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size: {max_size // (1024*1024)}MB"
        )

    # Create analysis job
    analysis_id = str(uuid.uuid4())

    try:
        # Read file content with proper encoding handling
        content = await file.read()

        # Try multiple encodings
        code_content = None
        for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
            try:
                code_content = content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if code_content is None:
            raise HTTPException(status_code=400, detail="Could not decode file as text")

        # Initialize analysis record
        analysis_storage[analysis_id] = {
            'id': analysis_id,
            'filename': file.filename,
            'language': language,
            'status': AnalysisStatus.PROCESSING,
            'created_at': datetime.now().isoformat(),
            'file_count': 1,
            'results': None,
            'error': None,
            'progress': 0
        }

        # Start background analysis
        background_tasks.add_task(
            analyze_single_file_background,
            analysis_id,
            code_content,
            file.filename,
            language
        )

        print(f"✅ Analysis job created: {analysis_id}")

        return JSONResponse({
            'analysis_id': analysis_id,
            'status': 'processing',
            'message': f'Analysis started for {file.filename}',
            'language': language,
            'estimated_time': '30-90 seconds'
        })

    except Exception as e:
        print(f"❌ File processing error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/analyze/codebase")
async def analyze_codebase(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Analyze entire codebase from ZIP file - supports mixed language projects"""

    if not file.filename.endswith(('.zip', '.tar', '.tar.gz')):
        raise HTTPException(
            status_code=400,
            detail="Only ZIP and TAR archives are supported"
        )

    # Increased size limit for enterprise codebases
    max_size = 100 * 1024 * 1024  # 100MB limit
    if file.size > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"Archive too large. Maximum size: {max_size // (1024*1024)}MB"
        )

    analysis_id = str(uuid.uuid4())

    try:
        # Save uploaded archive temporarily
        temp_dir = tempfile.mkdtemp()
        archive_path = os.path.join(temp_dir, f"{analysis_id}.zip")

        with open(archive_path, 'wb') as f:
            content = await file.read()
            f.write(content)

        print(f"📦 Extracting archive: {file.filename}")

        # Extract and validate archive
        extracted_files = file_handler.extract_and_validate_zip(archive_path, temp_dir)

        if not extracted_files:
            shutil.rmtree(temp_dir)
            raise HTTPException(
                status_code=400,
                detail="No supported code files found in archive"
            )

        print(f"📁 Found {len(extracted_files)} code files to analyze")

        # Initialize analysis record
        analysis_storage[analysis_id] = {
            'id': analysis_id,
            'filename': file.filename,
            'status': AnalysisStatus.PROCESSING,
            'created_at': datetime.now().isoformat(),
            'file_count': len(extracted_files),
            'results': None,
            'error': None,
            'temp_dir': temp_dir,
            'progress': 0
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
            'estimated_time': f'{len(extracted_files) * 45} seconds'
        })

    except Exception as e:
        if 'temp_dir' in locals():
            shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"❌ Codebase analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/analyze/{analysis_id}/status")
async def get_analysis_status(analysis_id: str):
    """Get current analysis status with enhanced progress tracking"""

    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analysis_storage[analysis_id]

    return {
        'analysis_id': analysis_id,
        'status': analysis['status'],
        'filename': analysis['filename'],
        'file_count': analysis['file_count'],
        'created_at': analysis['created_at'],
        'progress': calculate_progress(analysis),
        'language': analysis.get('language', 'mixed')
    }

@app.get("/api/analyze/{analysis_id}/results")
async def get_analysis_results(analysis_id: str):
    """Get detailed analysis results with enhanced summary"""

    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analysis_storage[analysis_id]

    if analysis['status'] == AnalysisStatus.PROCESSING:
        raise HTTPException(status_code=202, detail="Analysis still in progress")

    if analysis['status'] == AnalysisStatus.FAILED:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {analysis.get('error', 'Unknown error')}"
        )

    return {
        'analysis_id': analysis_id,
        'status': analysis['status'],
        'results': analysis['results'],
        'summary': generate_summary(analysis['results']),
        'metadata': {
            'analyzed_at': analysis['created_at'],
            'file_count': analysis['file_count'],
            'total_time': calculate_total_time(analysis)
        }
    }

# ============================================================================
# ENHANCED BACKGROUND ANALYSIS TASKS
# ============================================================================

async def analyze_single_file_background(
    analysis_id: str,
    code_content: str,
    filename: str,
    language: str
):
    """Enhanced single file analysis with better error handling"""

    try:
        print(f"🔍 Starting analysis for {filename} (Language: {language})")

        # Update progress
        analysis_storage[analysis_id]['progress'] = 25

        # Run Gemini analysis with language context
        result = analyzer.analyze_code(code_content, filename, language)

        if result.get('error'):
            print(f"❌ Analysis failed: {result['message']}")
            analysis_storage[analysis_id]['status'] = AnalysisStatus.FAILED
            analysis_storage[analysis_id]['error'] = result['message']
        else:
            print(f"✅ Analysis completed: Found {len(result.get('vulnerabilities', []))} issues")

            analysis_storage[analysis_id]['status'] = AnalysisStatus.COMPLETED
            analysis_storage[analysis_id]['results'] = {
                'files': [{
                    'filename': filename,
                    'analysis': result
                }],
                'overall_summary': result.get('summary', {})
            }
            analysis_storage[analysis_id]['progress'] = 100

    except Exception as e:
        print(f"❌ Unexpected error analyzing {filename}: {str(e)}")
        analysis_storage[analysis_id]['status'] = AnalysisStatus.FAILED
        analysis_storage[analysis_id]['error'] = str(e)

async def analyze_codebase_background(
    analysis_id: str,
    file_paths: List[str],
    temp_dir: str
):
    """Enhanced codebase analysis with progress tracking and language detection"""

    try:
        print(f"🔍 Starting codebase analysis - {len(file_paths)} files")

        results = []
        total_vulns = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        languages_found = set()

        for i, file_path in enumerate(file_paths):
            try:
                # Update progress
                progress = int((i / len(file_paths)) * 80) + 10  # 10-90% range
                analysis_storage[analysis_id]['progress'] = progress

                print(f"   📄 Analyzing {os.path.basename(file_path)} ({i+1}/{len(file_paths)})")

                # Read file with encoding handling
                code_content = None
                for encoding in ['utf-8', 'utf-16', 'latin-1', 'cp1252']:
                    try:
                        with open(file_path, 'r', encoding=encoding) as f:
                            code_content = f.read()
                        break
                    except UnicodeDecodeError:
                        continue

                if not code_content or len(code_content.strip()) < 10:
                    continue

                # Detect language for this file
                filename = os.path.basename(file_path)
                language = file_handler.get_file_language(filename)
                if language:
                    languages_found.add(language)

                # Analyze with Gemini
                result = analyzer.analyze_code(code_content, filename, language)

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

                # Rate limiting for API
                await asyncio.sleep(2)

            except Exception as file_error:
                print(f"   ⚠️ Failed to analyze {file_path}: {str(file_error)}")
                continue

        # Update final progress
        analysis_storage[analysis_id]['progress'] = 95

        # Compile final results
        final_results = {
            'files': results,
            'overall_summary': {
                'total_files_analyzed': len(results),
                'total_vulnerabilities': total_vulns,
                'critical_count': severity_counts['critical'],
                'high_count': severity_counts['high'],
                'medium_count': severity_counts['medium'],
                'low_count': severity_counts['low'],
                'info_count': severity_counts['info'],
                'languages_detected': list(languages_found)
            }
        }

        analysis_storage[analysis_id]['status'] = AnalysisStatus.COMPLETED
        analysis_storage[analysis_id]['results'] = final_results
        analysis_storage[analysis_id]['progress'] = 100

        print(f"✅ Codebase analysis completed - {total_vulns} vulnerabilities across {len(languages_found)} languages")

    except Exception as e:
        print(f"❌ Codebase analysis failed: {str(e)}")
        analysis_storage[analysis_id]['status'] = AnalysisStatus.FAILED
        analysis_storage[analysis_id]['error'] = str(e)

    finally:
        # Cleanup temp directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

# ============================================================================
# ENHANCED UTILITY FUNCTIONS
# ============================================================================

def calculate_progress(analysis: Dict) -> int:
    """Calculate analysis progress with better estimation"""
    if analysis['status'] == AnalysisStatus.COMPLETED:
        return 100
    elif analysis['status'] == AnalysisStatus.FAILED:
        return 0
    else:
        # Return stored progress or calculate time-based
        if 'progress' in analysis and analysis['progress'] > 0:
            return analysis['progress']

        created_time = datetime.fromisoformat(analysis['created_at'])
        elapsed = (datetime.now() - created_time).total_seconds()
        estimated_total = analysis['file_count'] * 45  # 45 seconds per file
        progress = min(int((elapsed / estimated_total) * 100), 85)
        return progress

def calculate_total_time(analysis: Dict) -> str:
    """Calculate total analysis time"""
    try:
        created_time = datetime.fromisoformat(analysis['created_at'])
        elapsed = (datetime.now() - created_time).total_seconds()

        if elapsed < 60:
            return f"{elapsed:.1f} seconds"
        else:
            return f"{elapsed/60:.1f} minutes"
    except:
        return "Unknown"

def generate_summary(results: Dict) -> Dict:
    """Generate enhanced executive summary"""
    if not results:
        return {}

    summary = results.get('overall_summary', {})
    files = results.get('files', [])

    # Calculate risk level
    critical = summary.get('critical_count', 0)
    high = summary.get('high_count', 0)
    medium = summary.get('medium_count', 0)

    if critical > 0:
        risk_level = "CRITICAL"
    elif high > 3:
        risk_level = "HIGH"
    elif high > 0 or medium > 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Get most common vulnerabilities
    vuln_counts = {}
    for file_result in files:
        for vuln in file_result.get('analysis', {}).get('vulnerabilities', []):
            vuln_type = vuln['vulnerability_type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

    most_common = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        'risk_level': risk_level,
        'total_issues': summary.get('total_vulnerabilities', 0),
        'files_analyzed': summary.get('total_files_analyzed', 0),
        'files_with_issues': len([f for f in files
                                 if len(f.get('analysis', {}).get('vulnerabilities', [])) > 0]),
        'languages_detected': summary.get('languages_detected', []),
        'most_common_issues': [vuln_type for vuln_type, count in most_common],
        'severity_breakdown': {
            'critical': summary.get('critical_count', 0),
            'high': summary.get('high_count', 0),
            'medium': summary.get('medium_count', 0),
            'low': summary.get('low_count', 0),
            'info': summary.get('info_count', 0)
        },
        'recommendations': generate_recommendations(summary)
    }

def generate_recommendations(summary: Dict) -> List[str]:
    """Generate actionable security recommendations"""
    recommendations = []

    critical = summary.get('critical_count', 0)
    high = summary.get('high_count', 0)
    medium = summary.get('medium_count', 0)

    if critical > 0:
        recommendations.append("🚨 URGENT: Address CRITICAL vulnerabilities immediately - they pose immediate security risk")

    if high > 0:
        recommendations.append("⚡ Fix HIGH severity issues within 24-48 hours")

    if medium > 3:
        recommendations.append("📋 Plan remediation for MEDIUM severity issues in next development cycle")

    if critical + high + medium > 0:
        recommendations.append("🔄 Implement automated security scanning in CI/CD pipeline")
        recommendations.append("📚 Conduct security code review training for development team")

    if len(recommendations) == 0:
        recommendations.append("✅ Good security posture! Continue regular security reviews")

    recommendations.append("🛡️ Consider implementing static analysis tools like SonarQube or Checkmarx")

    return recommendations

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting AI Security Auditor API...")
    print(f"📊 Supporting {len(file_handler.SUPPORTED_EXTENSIONS)} programming languages")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
