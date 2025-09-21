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
from pydantic import BaseModel
import requests  # <-- MISSING IMPORT ADDED
import time     # <-- MISSING IMPORT ADDED

from app.services.gemini_analyzer import GeminiSecurityAnalyzer
from app.utils.file_handler import FileHandler
from app.services.github_integration import GitHubIntegration
from app.tasks.repository_tasks import scan_repository_task

class RepositoryRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    github_token: str = None

# Load environment variables
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("❌ GEMINI_API_KEY not found in environment variables!")
    exit(1)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
github_integration = GitHubIntegration(GITHUB_TOKEN)

if not GITHUB_TOKEN:
    print("⚠️ GITHUB_TOKEN not found. Public repositories only.")
    exit(1)

app = FastAPI(
    title="AI Security Auditor",
    description="Universal code security analysis powered by AI - Supports ALL programming languages",
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
github_integration = GitHubIntegration()

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
        "supported_languages": "Universal - ALL programming languages and text files"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "gemini_api": "connected" if GEMINI_API_KEY else "missing"
    }

# ============================================================================
# UNIVERSAL FILE UPLOAD & ANALYSIS ENDPOINTS
# ============================================================================

@app.post("/api/analyze/file")
async def analyze_single_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """Analyze ANY text-based file - supports ALL programming languages and text formats"""

    print(f"📤 Received file: {file.filename} ({file.size} bytes)")

    # Universal file validation - accepts ALL text files
    language = file_handler.get_file_language(file.filename)

    # Only reject if it's truly a binary file
    if not file_handler._is_text_file_by_name(file.filename):
        raise HTTPException(
            status_code=400,
            detail="File appears to be binary. We analyze any text-based file including source code, scripts, configs, and readable text formats."
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
                detail="No text files found in archive"
            )

        print(f"📁 Found {len(extracted_files)} files to analyze")

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

async def analyze_repository_background(
    analysis_id: str,
    repo_url: str,
    branch: str,
    github_token: str = None
):
    """Enhanced repository analysis with intelligent rate limiting and retry logic"""

    temp_dir = None

    # Rate limiting configuration
    REQUESTS_PER_MINUTE = 12  # Conservative for free tier (actual limit ~15)
    REQUESTS_PER_DAY = 1200   # Conservative for free tier (actual limit ~1500)
    MIN_DELAY_SECONDS = 5     # Minimum delay between requests
    MAX_RETRIES = 3           # Retry failed requests
    BACKOFF_MULTIPLIER = 2    # Exponential backoff

    # Track API usage (in production, use Redis/database)
    request_timestamps = []
    daily_request_count = 0

    def can_make_request():
        """Check if we can make an API request based on rate limits"""
        nonlocal request_timestamps, daily_request_count

        current_time = time.time()

        # Clean old timestamps (older than 1 minute)
        request_timestamps = [ts for ts in request_timestamps if current_time - ts < 60]

        # Check per-minute limit
        if len(request_timestamps) >= REQUESTS_PER_MINUTE:
            return False, f"Rate limit: {len(request_timestamps)}/{REQUESTS_PER_MINUTE} requests in last minute"

        # Check daily limit (simplified - in production, use proper day tracking)
        if daily_request_count >= REQUESTS_PER_DAY:
            return False, f"Daily limit reached: {daily_request_count}/{REQUESTS_PER_DAY} requests today"

        return True, "OK"

    def record_request():
        """Record that we made an API request"""
        nonlocal request_timestamps, daily_request_count
        request_timestamps.append(time.time())
        daily_request_count += 1

    async def smart_api_call(analyzer, code_content, filename, language, file_index, total_files):
        """Make API call with intelligent rate limiting and retries"""

        for attempt in range(MAX_RETRIES):
            try:
                # Check if we can make the request
                can_request, reason = can_make_request()
                if not can_request:
                    print(f"   ⏳ Waiting due to rate limit: {reason}")
                    # Calculate smart delay
                    if "per minute" in reason:
                        delay = 65  # Wait for minute window to reset
                    else:
                        delay = 3600  # Wait for hour if daily limit (simplified)

                    await asyncio.sleep(delay)
                    continue

                # Calculate smart delay before request
                if request_timestamps:
                    time_since_last = time.time() - request_timestamps[-1]
                    if time_since_last < MIN_DELAY_SECONDS:
                        delay_needed = MIN_DELAY_SECONDS - time_since_last
                        print(f"   ⏱️  Smart delay: {delay_needed:.1f}s before analyzing {filename}")
                        await asyncio.sleep(delay_needed)

                print(f"   📄 Analyzing {filename} ({file_index}/{total_files}) - Attempt {attempt + 1}")

                # Make the API call
                result = analyzer.analyze_code(code_content, filename, language)
                record_request()

                if result.get('error'):
                    print(f"   ❌ Analysis failed: {result['message']}")
                    return None
                else:
                    print(f"   ✅ Analysis complete: Found {len(result.get('vulnerabilities', []))} issues")
                    return result

            except requests.exceptions.HTTPError as e:
                if "429" in str(e):  # Rate limit error
                    backoff_delay = MIN_DELAY_SECONDS * (BACKOFF_MULTIPLIER ** attempt)
                    print(f"   ⚠️ Rate limited - backing off {backoff_delay}s (attempt {attempt + 1}/{MAX_RETRIES})")
                    await asyncio.sleep(backoff_delay)
                    continue
                else:
                    print(f"   ❌ HTTP error: {str(e)}")
                    return None
            except Exception as e:
                print(f"   ❌ Unexpected error: {str(e)}")
                if attempt == MAX_RETRIES - 1:
                    return None
                await asyncio.sleep(2)  # Brief delay before retry

        print(f"   ❌ Failed to analyze {filename} after {MAX_RETRIES} attempts")
        return None

    try:
        print(f"🔍 Starting repository analysis: {repo_url}")
        analysis_storage[analysis_id]['progress'] = 5

        # Clone repository
        temp_dir, repo_name = await github_integration.clone_repository(repo_url, branch)
        analysis_storage[analysis_id]['progress'] = 15

        # Discover files
        files = await github_integration.discover_files(temp_dir)

        if not files:
            analysis_storage[analysis_id]['status'] = AnalysisStatus.COMPLETED
            analysis_storage[analysis_id]['results'] = {
                'files': [],
                'overall_summary': {
                    'total_vulnerabilities': 0, 'critical_count': 0, 'high_count': 0,
                    'medium_count': 0, 'low_count': 0, 'info_count': 0,
                    'total_files_analyzed': 0, 'languages_detected': []
                }
            }
            analysis_storage[analysis_id]['progress'] = 100
            return

        print(f"📁 Found {len(files)} files to analyze with smart rate limiting")
        analysis_storage[analysis_id]['progress'] = 25

        # Analyze files with intelligent rate limiting
        results = []
        total_vulns = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        languages_found = set()

        successful_analyses = 0

        for i, file_info in enumerate(files):
            try:
                # Update progress
                progress = 25 + int((i / len(files)) * 65)  # 25-90%
                analysis_storage[analysis_id]['progress'] = progress

                # Read file content
                content = await github_integration.get_file_content(file_info['full_path'])
                if len(content.strip()) < 10:
                    continue

                # Make smart API call with rate limiting
                result = await smart_api_call(
                    analyzer, content, file_info['filename'],
                    file_info['language'], i + 1, len(files)
                )

                if result:
                    successful_analyses += 1
                    results.append({
                        'filename': file_info['path'],
                        'analysis': result
                    })

                    # Aggregate statistics
                    vulns = result.get('vulnerabilities', [])
                    total_vulns += len(vulns)

                    for vuln in vulns:
                        sev = vuln['severity'].lower()
                        if sev in severity_counts:
                            severity_counts[sev] += 1

                    # Track languages
                    if file_info['language']:
                        languages_found.add(file_info['language'])

            except Exception as file_error:
                print(f"   ⚠️ Failed to analyze {file_info['filename']}: {str(file_error)}")
                continue

        # Final progress update
        analysis_storage[analysis_id]['progress'] = 95

        # Compile final results
        final_results = {
            'files': results,
            'overall_summary': {
                'total_files_analyzed': successful_analyses,
                'total_files_discovered': len(files),
                'total_vulnerabilities': total_vulns,
                'critical_count': severity_counts['critical'],
                'high_count': severity_counts['high'],
                'medium_count': severity_counts['medium'],
                'low_count': severity_counts['low'],
                'info_count': severity_counts['info'],
                'languages_detected': list(languages_found),
                'api_requests_used': daily_request_count,
                'success_rate': f"{(successful_analyses/len(files)*100):.1f}%" if files else "0%"
            }
        }

        analysis_storage[analysis_id]['status'] = AnalysisStatus.COMPLETED
        analysis_storage[analysis_id]['results'] = final_results
        analysis_storage[analysis_id]['progress'] = 100

        print(f"✅ Repository analysis completed: {total_vulns} vulnerabilities found")
        print(f"📊 Success rate: {successful_analyses}/{len(files)} files analyzed")
        print(f"🔄 API requests used: {daily_request_count}")

    except Exception as e:
        print(f"❌ Repository analysis failed: {str(e)}")
        analysis_storage[analysis_id]['status'] = AnalysisStatus.FAILED
        analysis_storage[analysis_id]['error'] = str(e)

    finally:
        # Cleanup
        if temp_dir:
            await github_integration.cleanup_repository(temp_dir)

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

    # Calculate risk level based on actual vulnerability counts
    critical = summary.get('critical_count', 0)
    high = summary.get('high_count', 0)
    medium = summary.get('medium_count', 0)
    low = summary.get('low_count', 0)
    info = summary.get('info_count', 0)

    # More accurate risk assessment based on severity and count
    if critical > 0:
        risk_level = "CRITICAL"
    elif critical == 0 and high >= 2:  # 2+ high severity issues = HIGH risk
        risk_level = "HIGH"
    elif critical == 0 and high == 1 and medium >= 3:  # 1 high + 3+ medium = HIGH risk
        risk_level = "HIGH"
    elif critical == 0 and high == 1:  # 1 high severity = MEDIUM risk
        risk_level = "MEDIUM"
    elif critical == 0 and high == 0 and medium >= 5:  # 5+ medium = MEDIUM risk
        risk_level = "MEDIUM"
    elif critical == 0 and high == 0 and medium >= 2:  # 2-4 medium = LOW risk
        risk_level = "LOW"
    elif critical == 0 and high == 0 and medium == 1 and low >= 3:  # 1 medium + 3+ low = LOW risk
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

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
        recommendations.append("🔥 Implement automated security scanning in CI/CD pipeline")
        recommendations.append("📚 Conduct security code review training for development team")

    if len(recommendations) == 0:
        recommendations.append("✅ Good security posture! Continue regular security reviews")

    recommendations.append("🛡️ Consider implementing static analysis tools like SonarQube or Checkmarx")

    return recommendations

# ============================================================================
# REPOSITORY SCANNING ENDPOINTS
# ============================================================================
@app.post("/api/analyze/repository")
async def analyze_repository(
    background_tasks: BackgroundTasks,
    request: RepositoryRequest  # <-- Changed from individual parameters to single request object
):
    """Analyze entire repository for security vulnerabilities"""

    try:
        # Validate repository URL
        if not request.repo_url or not any(domain in request.repo_url for domain in ['github.com', 'gitlab.com', 'bitbucket.org']):
            raise HTTPException(
                status_code=400,
                detail="Invalid repository URL. Supported: GitHub, GitLab, Bitbucket"
            )

        # Get repository information
        try:
            repo_info = await github_integration.get_repository_info(request.repo_url)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to access repository: {str(e)}"
            )

        # Create analysis job
        analysis_id = str(uuid.uuid4())

        # Store analysis record
        analysis_storage[analysis_id] = {
            'id': analysis_id,
            'type': 'repository',
            'repo_url': request.repo_url,
            'branch': request.branch,
            'repo_info': repo_info,
            'status': AnalysisStatus.PROCESSING,
            'created_at': datetime.now().isoformat(),
            'task_id': None,
            'results': None,
            'error': None,
            'progress': 0
        }

        # Start background repository analysis
        background_tasks.add_task(
            analyze_repository_background,
            analysis_id,
            request.repo_url,
            request.branch,
            request.github_token
        )

        print(f"🚀 Repository analysis started: {repo_info['name']} (ID: {analysis_id})")

        return JSONResponse({
            'analysis_id': analysis_id,
            'status': 'processing',
            'message': f'Repository analysis started for {repo_info["name"]}',
            'repository': repo_info['name'],
            'branch': request.branch,
            'languages': repo_info['languages'],
            'estimated_time': f'{repo_info["size"] // 1000} seconds'
        })

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Repository analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Repository analysis failed: {str(e)}")

@app.get("/api/analyze/repository/{analysis_id}/status")
async def get_repository_analysis_status(analysis_id: str):
    """Get repository analysis status"""

    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analysis_storage[analysis_id]

    if analysis['type'] != 'repository':
        raise HTTPException(status_code=400, detail="Not a repository analysis")

    # Check analysis status (without Celery for now)
    if analysis['status'] == AnalysisStatus.PROCESSING:
        status = 'processing'
        progress = analysis.get('progress', 0)
        message = 'Repository analysis in progress...'
    elif analysis['status'] == AnalysisStatus.COMPLETED:
        status = 'completed'
        progress = 100
        message = 'Analysis completed'
    elif analysis['status'] == AnalysisStatus.FAILED:
        status = 'failed'
        progress = 0
        message = analysis.get('error', 'Analysis failed')
    else:
        status = 'processing'
        progress = 0
        message = 'Processing...'

    return {
        'analysis_id': analysis_id,
        'status': status,
        'progress': progress,
        'message': message,
        'repository': analysis['repo_info']['name'],
        'branch': analysis['branch']
    }

@app.get("/api/analyze/repository/{analysis_id}/results")
async def get_repository_analysis_results(analysis_id: str):
    """Get repository analysis results"""

    if analysis_id not in analysis_storage:
        raise HTTPException(status_code=404, detail="Analysis not found")

    analysis = analysis_storage[analysis_id]

    if analysis['type'] != 'repository':
        raise HTTPException(status_code=400, detail="Not a repository analysis")

    if analysis['status'] == AnalysisStatus.PROCESSING:
        raise HTTPException(status_code=202, detail="Analysis still in progress")

    if analysis['status'] == AnalysisStatus.FAILED:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {analysis.get('error', 'Unknown error')}"
        )

    if not analysis['results']:
        raise HTTPException(status_code=404, detail="Results not available")

    # Generate summary
    results = analysis['results']
    summary = generate_repository_summary(results)

    return {
        'analysis_id': analysis_id,
        'status': analysis['status'],
        'repository': analysis['repo_info'],
        'results': results,
        'summary': summary,
        'metadata': {
            'analyzed_at': analysis['created_at'],
            'branch': analysis['branch'],
            'total_time': calculate_total_time(analysis)
        }
    }

def generate_repository_summary(results: Dict) -> Dict:
    """Generate repository analysis summary"""
    if not results:
        return {}

    overall_summary = results.get('overall_summary', {})
    files = results.get('files', [])

    # Calculate risk level
    critical = overall_summary.get('critical_count', 0)
    high = overall_summary.get('high_count', 0)
    medium = overall_summary.get('medium_count', 0)
    low = overall_summary.get('low_count', 0)
    info = overall_summary.get('info_count', 0)

    if critical > 0:
        risk_level = "CRITICAL"
    elif critical == 0 and high >= 5:
        risk_level = "HIGH"
    elif critical == 0 and high >= 2:
        risk_level = "MEDIUM"
    elif critical == 0 and high == 1 and medium >= 5:
        risk_level = "MEDIUM"
    elif critical == 0 and high == 1:
        risk_level = "LOW"
    elif critical == 0 and high == 0 and medium >= 10:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    # Get most common vulnerabilities
    vuln_counts = {}
    for file_result in files:
        for vuln in file_result.get('analysis', {}).get('vulnerabilities', []):
            vuln_type = vuln['vulnerability_type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

    most_common = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        'risk_level': risk_level,
        'total_issues': overall_summary.get('total_vulnerabilities', 0),
        'files_analyzed': overall_summary.get('total_files_analyzed', 0),
        'files_discovered': overall_summary.get('total_files_discovered', 0),
        'languages_detected': overall_summary.get('languages_detected', []),
        'most_common_issues': [vuln_type for vuln_type, count in most_common],
        'severity_breakdown': {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'info': info
        },
        'vulnerability_types': overall_summary.get('vulnerability_types', {}),
        'recommendations': generate_repository_recommendations(overall_summary)
    }

def generate_repository_recommendations(summary: Dict) -> List[str]:
    """Generate repository-level recommendations"""
    recommendations = []

    critical = summary.get('critical_count', 0)
    high = summary.get('high_count', 0)
    medium = summary.get('medium_count', 0)
    total_files = summary.get('total_files_analyzed', 0)

    if critical > 0:
        recommendations.append("🚨 URGENT: Address CRITICAL vulnerabilities immediately - they pose immediate security risk")

    if high > 0:
        recommendations.append("⚡ Fix HIGH severity issues within 24-48 hours")

    if medium > 10:
        recommendations.append("📋 Plan remediation for MEDIUM severity issues in next development cycle")

    if critical + high + medium > 0:
        recommendations.append("🔥 Implement automated security scanning in CI/CD pipeline")
        recommendations.append("📚 Conduct security code review training for development team")
        recommendations.append("🛡️ Consider implementing static analysis tools like SonarQube or Checkmarx")

    if total_files > 100:
        recommendations.append("📊 Consider implementing incremental scanning for large repositories")

    if len(recommendations) == 0:
        recommendations.append("✅ Good security posture! Continue regular security reviews")

    return recommendations

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Universal AI Security Auditor API...")
    print("📊 Supporting ALL programming languages and text formats")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
