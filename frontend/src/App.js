import React, { useState, useCallback } from 'react';
import { Upload, Shield, AlertTriangle, CheckCircle, FileText, Download, Code2, Bug, Zap, Menu, Sun, Moon, BarChart3, Settings, Book, TrendingUp } from 'lucide-react';
import { useTheme } from './contexts/ThemeContext';
import SeverityPie from './components/SeverityPie';
import TopFilesBar from './components/TopFilesBar';
import FileHeatmap from './components/FileHeatmap';
import './App.css';

const API_BASE_URL = 'http://localhost:8000';

function App() {
    const { isDark, toggleTheme } = useTheme();
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

    const [analysisState, setAnalysisState] = useState({
        isAnalyzing: false,
        currentAnalysis: null,
        results: null,
        error: null,
        progress: 0
    });

    const [history, setHistory] = useState(() => {
        try {
            const raw = localStorage.getItem('audit_history');
            return raw ? JSON.parse(raw) : [];
        } catch {
            return [];
        }
    });

    const [selectedFiles, setSelectedFiles] = useState([]);
    const [scanMode, setScanMode] = useState('files');
    const [repoUrl, setRepoUrl] = useState('');
    const [repoBranch, setRepoBranch] = useState('main');
    const [dragActive, setDragActive] = useState(false);

    const isBinaryFile = (filename) => {
        const ext = '.' + filename.split('.').pop().toLowerCase();
        const binaryExtensions = {
            '.exe': true, '.dll': true, '.so': true, '.dylib': true, '.bin': true, '.obj': true, '.o': true, '.a': true, '.lib': true,
            '.jpg': true, '.jpeg': true, '.png': true, '.gif': true, '.bmp': true, '.tiff': true, '.ico': true, '.svg': true,
            '.mp3': true, '.mp4': true, '.avi': true, '.mov': true, '.wmv': true, '.flv': true, '.wav': true, '.ogg': true,
            '.pdf': true, '.doc': true, '.docx': true, '.xls': true, '.xlsx': true, '.ppt': true, '.pptx': true,
            '.zip': true, '.rar': true, '.7z': true, '.tar': true, '.gz': true, '.bz2': true
        };
        return binaryExtensions[ext] || false;
    };

    const getLanguageInfo = (filename) => {
        const name = filename.toLowerCase();
        const ext = '.' + name.split('.').pop();

        const languageMap = {
            '.py': { name: 'Python', color: '#3776ab', category: 'Backend' },
            '.pyx': { name: 'Cython', color: '#3776ab', category: 'Backend' },
            '.js': { name: 'JavaScript', color: '#f7df1e', category: 'Frontend' },
            '.jsx': { name: 'React', color: '#61dafb', category: 'Frontend' },
            '.ts': { name: 'TypeScript', color: '#007acc', category: 'Frontend' },
            '.tsx': { name: 'TypeScript React', color: '#007acc', category: 'Frontend' },
            '.mjs': { name: 'JavaScript Module', color: '#f7df1e', category: 'Frontend' },
            '.java': { name: 'Java', color: '#ed8b00', category: 'Backend' },
            '.kt': { name: 'Kotlin', color: '#7f52ff', category: 'Backend' },
            '.scala': { name: 'Scala', color: '#dc322f', category: 'Backend' },
            '.clj': { name: 'Clojure', color: '#5881d8', category: 'Functional' },
            '.groovy': { name: 'Groovy', color: '#e69f56', category: 'Backend' },
            '.c': { name: 'C', color: '#a8b9cc', category: 'Systems' },
            '.cpp': { name: 'C++', color: '#00599c', category: 'Systems' },
            '.cc': { name: 'C++', color: '#00599c', category: 'Systems' },
            '.cxx': { name: 'C++', color: '#00599c', category: 'Systems' },
            '.go': { name: 'Go', color: '#00add8', category: 'Backend' },
            '.rs': { name: 'Rust', color: '#dea584', category: 'Systems' },
            '.zig': { name: 'Zig', color: '#ec915c', category: 'Systems' },
            '.nim': { name: 'Nim', color: '#ffe953', category: 'Systems' },
            '.d': { name: 'D', color: '#ba595e', category: 'Systems' },
            '.cs': { name: 'C#', color: '#239120', category: 'Backend' },
            '.vb': { name: 'Visual Basic', color: '#945db7', category: 'Backend' },
            '.fs': { name: 'F#', color: '#378bba', category: 'Functional' },
            '.php': { name: 'PHP', color: '#777bb4', category: 'Backend' },
            '.rb': { name: 'Ruby', color: '#cc342d', category: 'Backend' },
            '.rake': { name: 'Ruby Rake', color: '#cc342d', category: 'Backend' },
            '.erb': { name: 'ERB Template', color: '#cc342d', category: 'Template' },
            '.swift': { name: 'Swift', color: '#fa7343', category: 'Mobile' },
            '.dart': { name: 'Dart', color: '#0175c2', category: 'Mobile' },
            '.hs': { name: 'Haskell', color: '#5e5086', category: 'Functional' },
            '.ml': { name: 'OCaml', color: '#3be133', category: 'Functional' },
            '.elm': { name: 'Elm', color: '#60b5cc', category: 'Frontend' },
            '.ex': { name: 'Elixir', color: '#6e4a7e', category: 'Backend' },
            '.erl': { name: 'Erlang', color: '#b83998', category: 'Backend' },
            '.sol': { name: 'Solidity', color: '#363636', category: 'Blockchain' }
        };

        if (name === 'dockerfile' || name === 'containerfile') {
            return { name: 'Dockerfile', color: '#384d54', category: 'DevOps' };
        }
        if (name === 'makefile') {
            return { name: 'Makefile', color: '#427819', category: 'Build' };
        }

        return languageMap[ext] || { name: 'Code', color: '#6c757d', category: 'Other' };
    };

    const getSeverityColor = (severity) => {
        const colors = {
            'CRITICAL': '#FF3B30',
            'HIGH': '#FF9500',
            'MEDIUM': '#FFD60A',
            'LOW': '#5AC8FA',
            'INFO': '#8E8E93'
        };
        return colors[severity] || '#6c757d';
    };

    const getVulnIcon = (vulnType) => {
        const iconMap = {
            'SQL_INJECTION': '💉',
            'XSS': '🕷️',
            'CSRF': '🔄',
            'HARDCODED_SECRETS': '🔑',
            'WEAK_CRYPTO': '🔐',
            'COMMAND_INJECTION': '⚡',
            'BUFFER_OVERFLOW': '💥',
            'RACE_CONDITION': '🏃‍♂️',
            'PATH_TRAVERSAL': '📁',
            'INSECURE_DESERIALIZATION': '📦',
            'USE_AFTER_FREE': '🧠',
            'NULL_POINTER_DEREFERENCE': '📍',
            'MEMORY_LEAK': '🕳️',
            'INTEGER_OVERFLOW': '🔢',
            'FORMAT_STRING': '📝'
        };
        return iconMap[vulnType] || '⚠️';
    };

    // FIXED: Only select files, don't start analysis
    const handleFileSelection = useCallback((files) => {
        if (!files || files.length === 0) return;

        const fileList = Array.from(files);
        const validFiles = [];
        const errors = [];

        for (const file of fileList) {
            if (isBinaryFile(file.name)) {
                errors.push(`${file.name}: Binary files are not supported`);
                continue;
            }

            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            const maxSize = fileExtension.includes('zip') || fileExtension.includes('tar') ?
                100 * 1024 * 1024 : 10 * 1024 * 1024;

            if (file.size > maxSize) {
                errors.push(`${file.name}: File too large`);
                continue;
            }

            validFiles.push(file);
        }

        if (validFiles.length === 0) {
            setAnalysisState(prev => ({
                ...prev,
                error: errors.length > 0 ? errors.join('; ') : 'No valid files selected'
            }));
            return;
        }

        if (errors.length > 0) {
            console.warn('Some files were skipped:', errors);
        }

        // Just set selected files, don't start analysis
        setSelectedFiles(validFiles);
        setAnalysisState(prev => ({ ...prev, error: null }));
    }, []);

    // NEW: Separate function to start analysis
    const startFileAnalysis = useCallback(async () => {
        if (selectedFiles.length === 0) return;

        setAnalysisState({
            isAnalyzing: true,
            currentAnalysis: null,
            results: null,
            error: null,
            progress: 0
        });

        try {
            const hasArchives = selectedFiles.some(file => {
                const ext = '.' + file.name.split('.').pop().toLowerCase();
                return ext.includes('zip') || ext.includes('tar');
            });

            if (hasArchives && selectedFiles.length > 1) {
                setAnalysisState(prev => ({
                    ...prev,
                    isAnalyzing: false,
                    error: 'Cannot mix archive files with individual files'
                }));
                return;
            }

            if (hasArchives) {
                const file = selectedFiles[0];
                const formData = new FormData();
                formData.append('file', file);

                const response = await fetch(`${API_BASE_URL}/api/analyze/codebase`, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    throw new Error(`Upload failed: ${response.statusText}`);
                }

                const uploadResult = await response.json();

                setAnalysisState(prev => ({
                    ...prev,
                    currentAnalysis: uploadResult.analysis_id,
                    progress: 15
                }));

                pollAnalysisStatus(uploadResult.analysis_id);
            } else {
                await analyzeMultipleFiles(selectedFiles);
            }

        } catch (error) {
            console.error('Upload error:', error);
            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                error: error.message
            }));
        }
    }, [selectedFiles]);

    const analyzeMultipleFiles = useCallback(async (files) => {
        try {
            const allResults = {
                files: [],
                overall_summary: {
                    total_vulnerabilities: 0,
                    critical_count: 0,
                    high_count: 0,
                    medium_count: 0,
                    low_count: 0,
                    info_count: 0,
                    total_files_analyzed: files.length,
                    languages_detected: []
                }
            };

            const languagesFound = new Set();

            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                const progress = Math.round((i / files.length) * 80) + 10;
                setAnalysisState(prev => ({ ...prev, progress }));

                const formData = new FormData();
                formData.append('file', file);

                const response = await fetch(`${API_BASE_URL}/api/analyze/file`, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    console.error(`Failed to analyze ${file.name}`);
                    continue;
                }

                const uploadResult = await response.json();
                const analysisResult = await waitForAnalysis(uploadResult.analysis_id);

                if (analysisResult && analysisResult.results) {
                    const fileResult = analysisResult.results.files[0];
                    if (fileResult) {
                        allResults.files.push(fileResult);

                        const vulns = fileResult.analysis.vulnerabilities || [];
                        allResults.overall_summary.total_vulnerabilities += vulns.length;

                        vulns.forEach(vuln => {
                            const severity = vuln.severity.toLowerCase();
                            if (severity in allResults.overall_summary) {
                                allResults.overall_summary[severity + '_count']++;
                            }
                        });

                        const language = fileResult.analysis.metadata?.language;
                        if (language) {
                            languagesFound.add(language);
                        }
                    }
                }

                await new Promise(resolve => setTimeout(resolve, 1000));
            }

            allResults.overall_summary.languages_detected = Array.from(languagesFound);
            const summary = generateSummary(allResults);

            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                results: {
                    analysis_id: `multi-${Date.now()}`,
                    status: 'completed',
                    results: allResults,
                    summary: summary,
                    metadata: {
                        analyzed_at: new Date().toISOString(),
                        file_count: files.length
                    }
                },
                progress: 100
            }));

        } catch (error) {
            console.error('Multi-file analysis error:', error);
            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                error: error.message
            }));
        }
    }, []);

    const waitForAnalysis = useCallback(async (analysisId) => {
        const maxAttempts = 60;
        let attempts = 0;

        while (attempts < maxAttempts) {
            try {
                const statusResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/status`);
                if (!statusResponse.ok) {
                    throw new Error('Failed to get analysis status');
                }

                const status = await statusResponse.json();

                if (status.status === 'completed') {
                    const resultsResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/results`);
                    if (resultsResponse.ok) {
                        return await resultsResponse.json();
                    }
                } else if (status.status === 'failed') {
                    throw new Error('Analysis failed');
                }

                attempts++;
                await new Promise(resolve => setTimeout(resolve, 2000));
            } catch (error) {
                console.error('Error waiting for analysis:', error);
                throw error;
            }
        }

        throw new Error('Analysis timeout');
    }, []);

    const generateSummary = useCallback((results) => {
        const summary = results.overall_summary;
        const critical = summary.critical_count || 0;
        const high = summary.high_count || 0;
        const medium = summary.medium_count || 0;

        let riskLevel;
        if (critical > 0) {
            riskLevel = 'CRITICAL';
        } else if (high >= 2) {
            riskLevel = 'HIGH';
        } else if (high === 1 && medium >= 3) {
            riskLevel = 'HIGH';
        } else if (high === 1) {
            riskLevel = 'MEDIUM';
        } else if (medium >= 5) {
            riskLevel = 'MEDIUM';
        } else if (medium >= 2) {
            riskLevel = 'LOW';
        } else {
            riskLevel = 'MINIMAL';
        }

        return {
            risk_level: riskLevel,
            total_issues: summary.total_vulnerabilities,
            files_analyzed: summary.total_files_analyzed,
            files_with_issues: results.files.filter(f => f.analysis.vulnerabilities?.length > 0).length,
            languages_detected: summary.languages_detected,
            severity_breakdown: {
                critical,
                high,
                medium,
                low: summary.low_count || 0,
                info: summary.info_count || 0
            }
        };
    }, []);

    const handleRepositoryScan = useCallback(async () => {
        if (!repoUrl.trim()) {
            setAnalysisState(prev => ({
                ...prev,
                error: 'Please enter a repository URL'
            }));
            return;
        }

        // FIXED: Clear error and START analyzing immediately
        setAnalysisState({
            isAnalyzing: true,
            currentAnalysis: null,
            results: null,
            error: null,
            progress: 5
        });

        try {
            const response = await fetch(`${API_BASE_URL}/api/analyze/repository`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    repo_url: repoUrl,
                    branch: repoBranch
                })
            });

            if (!response.ok) throw new Error('Repository scan failed');

            const result = await response.json();
            setAnalysisState(prev => ({
                ...prev,
                currentAnalysis: result.analysis_id,
                progress: 15
            }));

            pollRepositoryAnalysisStatus(result.analysis_id);

        } catch (error) {
            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                error: error.message
            }));
        }
    }, [repoUrl, repoBranch]);

    const pollRepositoryAnalysisStatus = useCallback(async (analysisId) => {
        const maxAttempts = 300;
        let attempts = 0;

        const poll = async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/analyze/repository/${analysisId}/status`);
                if (!response.ok) throw new Error('Failed to get analysis status');

                const status = await response.json();
                setAnalysisState(prev => ({ ...prev, progress: status.progress || 0 }));

                if (status.status === 'completed') {
                    const resultsResponse = await fetch(`${API_BASE_URL}/api/analyze/repository/${analysisId}/results`);
                    if (resultsResponse.ok) {
                        const newResults = await resultsResponse.json();
                        setAnalysisState(prev => ({
                            ...prev,
                            isAnalyzing: false,
                            results: newResults,
                            progress: 100
                        }));

                        const sum = newResults?.results?.overall_summary || {};
                        const entry = {
                            timestamp: Date.now(),
                            repoScore: sum.repo_score || 0,
                            critical: sum.critical_count || 0,
                            high: sum.high_count || 0
                        };
                        const next = [...history, entry].slice(-20);
                        setHistory(next);
                        localStorage.setItem('audit_history', JSON.stringify(next));
                    }
                } else if (status.status === 'failed') {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: status.message || 'Analysis failed'
                    }));
                } else if (attempts < maxAttempts) {
                    attempts++;
                    setTimeout(poll, 2000);
                } else {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: 'Timeout'
                    }));
                }
            } catch (error) {
                setAnalysisState(prev => ({
                    ...prev,
                    isAnalyzing: false,
                    error: error.message
                }));
            }
        };

        poll();
    }, [history]);

    const pollAnalysisStatus = useCallback(async (analysisId) => {
        const maxAttempts = 120;
        let attempts = 0;

        const poll = async () => {
            try {
                attempts++;

                const statusResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/status`);
                if (!statusResponse.ok) throw new Error('Failed to get status');

                const status = await statusResponse.json();
                const progressIncrement = Math.max(2, Math.floor(70 / maxAttempts));
                const newProgress = Math.min(status.progress || (15 + attempts * progressIncrement), 85);

                setAnalysisState(prev => ({ ...prev, progress: newProgress }));

                if (status.status === 'completed') {
                    const resultsResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/results`);
                    if (resultsResponse.ok) {
                        const results = await resultsResponse.json();
                        setAnalysisState(prev => ({
                            ...prev,
                            isAnalyzing: false,
                            results,
                            progress: 100
                        }));

                        const sum = results?.results?.overall_summary || {};
                        const entry = {
                            timestamp: Date.now(),
                            repoScore: sum.repo_score || 0,
                            critical: sum.critical_count || 0,
                            high: sum.high_count || 0
                        };
                        const next = [...history, entry].slice(-20);
                        setHistory(next);
                        localStorage.setItem('audit_history', JSON.stringify(next));
                    }
                } else if (status.status === 'failed') {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: status.error || 'Analysis failed'
                    }));
                } else if (attempts < maxAttempts) {
                    setTimeout(poll, attempts < 20 ? 2000 : attempts < 60 ? 3000 : 5000);
                } else {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: 'Timeout'
                    }));
                }
            } catch (error) {
                setAnalysisState(prev => ({
                    ...prev,
                    isAnalyzing: false,
                    error: error.message
                }));
            }
        };

        poll();
    }, [history]);

    const handleDrag = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === "dragenter" || e.type === "dragover") {
            setDragActive(true);
        } else if (e.type === "dragleave") {
            setDragActive(false);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileSelection(e.dataTransfer.files);
        }
    };

    const exportResults = () => {
        if (!analysisState.results) return;

        const dataStr = JSON.stringify(analysisState.results, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);

        const link = document.createElement('a');
        link.href = url;
        link.download = 'security-analysis-results.json';
        link.click();

        URL.revokeObjectURL(url);
    };

    const calculateRiskLevel = () => {
        const files = analysisState.results?.results?.files || [];
        const critical = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0), 0);
        const high = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'HIGH').length || 0), 0);
        const medium = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'MEDIUM').length || 0), 0);

        if (critical >= 1) return 'CRITICAL';
        if (high >= 5) return 'HIGH';
        if (high >= 2) return 'HIGH';
        if (high === 1 && medium >= 3) return 'HIGH';
        if (medium >= 5) return 'MEDIUM';
        if (medium >= 2) return 'LOW';
        return 'MINIMAL';
    };

    return (
        <div className="app-wrapper">
            <aside className={`modern-sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
                <div className="sidebar-header">
                    <div className="sidebar-logo">
                        <Shield size={28} />
                        {!sidebarCollapsed && <span>SecAudit</span>}
                    </div>
                    <button onClick={() => setSidebarCollapsed(!sidebarCollapsed)} className="sidebar-toggle">
                        <Menu size={20} />
                    </button>
                </div>
                <nav className="sidebar-nav">
                    <button className="nav-item active">
                        <BarChart3 size={20} />
                        {!sidebarCollapsed && <span>Dashboard</span>}
                    </button>
                    <button className="nav-item">
                        <FileText size={20} />
                        {!sidebarCollapsed && <span>Scans</span>}
                    </button>
                    <button className="nav-item">
                        <Settings size={20} />
                        {!sidebarCollapsed && <span>Settings</span>}
                    </button>
                    <button className="nav-item">
                        <Book size={20} />
                        {!sidebarCollapsed && <span>Docs</span>}
                    </button>
                </nav>
            </aside>

            <div className="main-wrapper">
                <header className="modern-header">
                    <div className="header-left">
                        <h1>AI Security Auditor</h1>
                        {analysisState.results && (
                            <span className="header-subtitle">
                                {analysisState.results.results?.files?.length || 1} files analyzed
                            </span>
                        )}
                    </div>
                    <button onClick={toggleTheme} className="theme-toggle-btn">
                        {isDark ? <Sun size={20} /> : <Moon size={20} />}
                    </button>
                </header>

                <main className="modern-content">
                    {!analysisState.results && !analysisState.isAnalyzing && (
                        <div className="upload-section-modern">
                            <div className="mode-selector-modern">
                                <button
                                    className={`mode-btn-modern ${scanMode === 'files' ? 'active' : ''}`}
                                    onClick={() => setScanMode('files')}
                                >
                                    <FileText size={20} />
                                    Upload Files
                                </button>
                                <button
                                    className={`mode-btn-modern ${scanMode === 'repository' ? 'active' : ''}`}
                                    onClick={() => setScanMode('repository')}
                                >
                                    <Code2 size={20} />
                                    Scan Repository
                                </button>
                            </div>

                            {scanMode === 'files' ? (
                                <>
                                    <div
                                        className={`upload-zone-modern ${dragActive ? 'drag-active' : ''}`}
                                        onDragEnter={handleDrag}
                                        onDragLeave={handleDrag}
                                        onDragOver={handleDrag}
                                        onDrop={handleDrop}
                                    >
                                        <Upload size={48} className="upload-icon" />
                                        <h2>Upload Code for Security Analysis</h2>
                                        <p>Drag & drop files or click to browse</p>

                                        <input
                                            type="file"
                                            id="file-upload"
                                            multiple
                                            className="file-input-hidden"
                                            onChange={(e) => handleFileSelection(e.target.files)}
                                        />

                                        <label htmlFor="file-upload" className="upload-btn-modern">
                                            <Code2 size={20} />
                                            Choose Files
                                        </label>

                                        <div className="supported-formats-modern">
                                            <span>Python</span>
                                            <span>JavaScript</span>
                                            <span>Java</span>
                                            <span>C/C++</span>
                                            <span>Go</span>
                                            <span>Rust</span>
                                            <span>PHP</span>
                                            <span>Ruby</span>
                                            <span>+50 more</span>
                                        </div>
                                    </div>

                                    {/* ADDED: Selected Files Preview */}
                                    {selectedFiles.length > 0 && (
                                        <div className="selected-files-preview">
                                            <h3>Selected Files ({selectedFiles.length})</h3>
                                            <div className="files-list-preview">
                                                {selectedFiles.map((file, idx) => {
                                                    const langInfo = getLanguageInfo(file.name);
                                                    return (
                                                        <div key={idx} className="file-preview-item">
                                                            <FileText size={16} />
                                                            <span className="file-name">{file.name}</span>
                                                            <span className="lang-badge-small"
                                                                style={{ background: langInfo.color }}
                                                            >
                                                                {langInfo.name}
                                                            </span>
                                                            <span className="file-size-small">
                                                                {(file.size / 1024).toFixed(1)}KB
                                                            </span>
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                            <div className="file-actions-preview">
                                                <button
                                                    onClick={() => setSelectedFiles([])}
                                                    className="btn-secondary-modern"
                                                >
                                                    Clear
                                                </button>
                                                <button
                                                    onClick={startFileAnalysis}
                                                    className="btn-primary-modern"
                                                >
                                                    <Shield size={20} />
                                                    Analyze {selectedFiles.length} File{selectedFiles.length > 1 ? 's' : ''}
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </>
                            ) : (
                                <div className="repo-scan-modern">
                                    <div className="upload-zone-modern">
                                        <Code2 size={48} className="upload-icon" />
                                        <h2>Scan Repository</h2>
                                        <p>Analyze entire repositories from GitHub, GitLab, or Bitbucket</p>

                                        <div className="repo-inputs">
                                            <input
                                                type="url"
                                                placeholder="https://github.com/username/repository"
                                                value={repoUrl}
                                                onChange={(e) => setRepoUrl(e.target.value)}
                                                className="repo-input-modern"
                                            />
                                            <input
                                                type="text"
                                                placeholder="Branch (default: main)"
                                                value={repoBranch}
                                                onChange={(e) => setRepoBranch(e.target.value)}
                                                className="repo-input-modern"
                                            />
                                            <button
                                                onClick={handleRepositoryScan}
                                                className="upload-btn-modern"
                                                disabled={!repoUrl.trim()}
                                            >
                                                <Shield size={20} />
                                                Scan Repository
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {analysisState.error && (
                                <div className="error-alert-modern">
                                    <AlertTriangle size={20} />
                                    <span>{analysisState.error}</span>
                                </div>
                            )}
                        </div>
                    )}

                    {analysisState.isAnalyzing && (
                        <div className="analyzing-modern">
                            <div className="spinner-modern"></div>
                            <h2>Analyzing {scanMode === 'repository' ? 'Repository' : 'Your Code'}</h2>
                            <p>AI is scanning for security vulnerabilities...</p>

                            {selectedFiles.length > 0 && (
                                <div style={{ marginTop: '1rem', color: 'var(--text-secondary)' }}>
                                    Scanning {selectedFiles.length} file{selectedFiles.length > 1 ? 's' : ''}...
                                </div>
                            )}

                            {scanMode === 'repository' && repoUrl && (
                                <div style={{ marginTop: '1rem', color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                                    Repository: {repoUrl}
                                </div>
                            )}

                            <div className="progress-bar-modern">
                                <div className="progress-fill-modern" style={{ width: `${analysisState.progress}%` }} />
                            </div>
                            <div className="progress-text-modern">{analysisState.progress}% complete</div>

                            <div style={{ marginTop: '2rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', alignItems: 'center' }}>
                                {analysisState.progress >= 15 && <div style={{ color: '#34C759', fontSize: '0.9rem' }}>✓ Files uploaded</div>}
                                {analysisState.progress >= 30 && <div style={{ color: '#34C759', fontSize: '0.9rem' }}>✓ Analyzing code structure</div>}
                                {analysisState.progress >= 50 && <div style={{ color: '#34C759', fontSize: '0.9rem' }}>✓ AI security analysis running</div>}
                                {analysisState.progress >= 70 && <div style={{ color: '#34C759', fontSize: '0.9rem' }}>✓ Generating vulnerability report</div>}
                                {analysisState.progress >= 90 && <div style={{ color: '#34C759', fontSize: '0.9rem' }}>✓ Finalizing results</div>}
                            </div>
                        </div>
                    )}

                    {analysisState.results && (
                        <div className="results-modern">
                            <div className="results-header-modern">
                                <h2>Security Analysis Results</h2>
                                <div className="results-actions-modern">
                                    <button onClick={exportResults} className="btn-secondary-modern">
                                        <Download size={16} />
                                        Export
                                    </button>
                                    <button
                                        onClick={() => {
                                            setAnalysisState({ isAnalyzing: false, results: null, error: null, progress: 0 });
                                            setSelectedFiles([]);
                                            setRepoUrl('');
                                        }}
                                        className="btn-primary-modern"
                                    >
                                        New Scan
                                    </button>
                                </div>
                            </div>

                            <div className="dashboard-grid-modern">
                                <div className="card-modern risk-meter-card">
                                    <h3>Overall Risk Score</h3>
                                    <div className="risk-meter-visual">
                                        {(() => {
                                            const files = analysisState.results.results?.files || [];
                                            const critical = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0), 0);
                                            const high = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'HIGH').length || 0), 0);
                                            const medium = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'MEDIUM').length || 0), 0);
                                            const low = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'LOW').length || 0), 0);
                                            const totalIssues = critical + high + medium + low;

                                            let riskScore = 0;
                                            if (totalIssues > 0) {
                                                const rawScore = (critical * 40) + (high * 20) + (medium * 8) + (low * 2);
                                                riskScore = Math.round(rawScore);
                                                const displayScore = riskScore;
                                                const circleProgress = Math.min(100, riskScore);

                                                window._actualRiskScore = displayScore;
                                                window._circleProgress = circleProgress;
                                            }

                                            const riskLevel = calculateRiskLevel();

                                            return (
                                                <>
                                                    <svg className="risk-circle" viewBox="0 0 200 200">
                                                        <circle cx="100" cy="100" r="90" fill="none" stroke="var(--border)" strokeWidth="12" />
                                                        <circle
                                                            cx="100"
                                                            cy="100"
                                                            r="90"
                                                            fill="none"
                                                            stroke={getSeverityColor(riskLevel)}
                                                            strokeWidth="12"
                                                            strokeDasharray={`${((window._circleProgress || 0) / 100) * 565} 565`}
                                                            strokeLinecap="round"
                                                            transform="rotate(-90 100 100)"
                                                        />
                                                    </svg>
                                                    <div className="risk-score-text">
                                                        <div className="score-number">{window._actualRiskScore || riskScore}</div>
                                                        <div className="score-label">risk score</div>
                                                    </div>
                                                </>
                                            );
                                        })()}
                                    </div>
                                    <div className="risk-level-badge" style={{ background: getSeverityColor(calculateRiskLevel()) }}>
                                        {calculateRiskLevel()}
                                    </div>
                                </div>

                                <div className="stats-grid-modern">
                                    <div className="stat-card-modern">
                                        <div className="stat-icon" style={{ background: 'rgba(99, 102, 241, 0.1)' }}>
                                            <FileText size={24} style={{ color: '#6366f1' }} />
                                        </div>
                                        <div className="stat-value">
                                            {analysisState.results.results?.files?.length || analysisState.results.results?.total_files_analyzed || 1}
                                        </div>
                                        <div className="stat-label">Files Analyzed</div>
                                    </div>
                                    <div className="stat-card-modern">
                                        <div className="stat-icon" style={{ background: 'rgba(255, 149, 0, 0.1)' }}>
                                            <Bug size={24} style={{ color: '#FF9500' }} />
                                        </div>
                                        <div className="stat-value">
                                            {(() => {
                                                const summary = analysisState.results.results?.overall_summary || analysisState.results.summary || {};
                                                return summary.total_vulnerabilities ||
                                                    (analysisState.results.results?.files || []).reduce((sum, f) =>
                                                        sum + (f.analysis?.vulnerabilities?.length || 0), 0) || 0;
                                            })()}
                                        </div>
                                        <div className="stat-label">Total Issues</div>
                                    </div>
                                    <div className="stat-card-modern">
                                        <div className="stat-icon" style={{ background: 'rgba(255, 59, 48, 0.1)' }}>
                                            <AlertTriangle size={24} style={{ color: '#FF3B30' }} />
                                        </div>
                                        <div className="stat-value">
                                            {(() => {
                                                const summary = analysisState.results.results?.overall_summary || analysisState.results.summary || {};
                                                return summary.critical_count ||
                                                    (analysisState.results.results?.files || []).reduce((sum, f) =>
                                                        sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0), 0) || 0;
                                            })()}
                                        </div>
                                        <div className="stat-label">Critical</div>
                                    </div>
                                    <div className="stat-card-modern">
                                        <div className="stat-icon" style={{ background: 'rgba(52, 199, 89, 0.1)' }}>
                                            <TrendingUp size={24} style={{ color: '#34C759' }} />
                                        </div>
                                        <div className="stat-value">
                                            {new Set((analysisState.results.results?.files || []).map(f => getLanguageInfo(f.filename).name)).size}
                                        </div>
                                        <div className="stat-label">Languages</div>
                                    </div>
                                </div>

                                <div className="card-modern">
                                    <h3>Severity Distribution</h3>
                                    <div className="severity-grid-modern">
                                        {(() => {
                                            const files = analysisState.results.results?.files || [];
                                            const critical = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0), 0);
                                            const high = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'HIGH').length || 0), 0);
                                            const medium = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'MEDIUM').length || 0), 0);
                                            const low = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'LOW').length || 0), 0);
                                            const info = files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'INFO').length || 0), 0);

                                            return (
                                                <>
                                                    <div className="severity-item-modern critical">
                                                        <div className="sev-count">{critical}</div>
                                                        <div className="sev-label">Critical</div>
                                                    </div>
                                                    <div className="severity-item-modern high">
                                                        <div className="sev-count">{high}</div>
                                                        <div className="sev-label">High</div>
                                                    </div>
                                                    <div className="severity-item-modern medium">
                                                        <div className="sev-count">{medium}</div>
                                                        <div className="sev-label">Medium</div>
                                                    </div>
                                                    <div className="severity-item-modern low">
                                                        <div className="sev-count">{low}</div>
                                                        <div className="sev-label">Low</div>
                                                    </div>
                                                    <div className="severity-item-modern info">
                                                        <div className="sev-count">{info}</div>
                                                        <div className="sev-label">Info</div>
                                                    </div>
                                                </>
                                            );
                                        })()}
                                    </div>
                                </div>

                                <div className="card-modern">
                                    <h3>Top Vulnerable Files</h3>
                                    <div style={{ height: 300 }}>
                                        <TopFilesBar files={analysisState.results.results?.files} />
                                    </div>
                                </div>

                                <div className="card-modern">
                                    <h3>Severity Distribution Chart</h3>
                                    <div style={{ height: 300 }}>
                                        {(() => {
                                            const files = analysisState.results.results?.files || [];
                                            const summary = {
                                                critical_count: files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0), 0),
                                                high_count: files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'HIGH').length || 0), 0),
                                                medium_count: files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'MEDIUM').length || 0), 0),
                                                low_count: files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'LOW').length || 0), 0),
                                                info_count: files.reduce((sum, f) => sum + (f.analysis?.vulnerabilities?.filter(v => v.severity === 'INFO').length || 0), 0)
                                            };
                                            return <SeverityPie summary={summary} />;
                                        })()}
                                    </div>
                                </div>

                                <div className="card-modern full-width">
                                    <h3>File Risk Heatmap</h3>
                                    <FileHeatmap files={analysisState.results.results?.files} />
                                </div>
                            </div>

                            <div className="detailed-findings-modern">
                                <h2>Detailed Findings by File</h2>
                                {(analysisState.results.results?.files || []).map((file, fileIdx) => {
                                    const langInfo = getLanguageInfo(file.filename);
                                    const vulns = file.analysis?.vulnerabilities || [];

                                    return (
                                        <div key={fileIdx} className="file-card-modern">
                                            <div className="file-header-modern">
                                                <div className="file-info-modern">
                                                    <FileText size={20} />
                                                    <span className="file-name-modern">{file.filename}</span>
                                                    <span className="lang-badge-modern" style={{ background: langInfo.color }}>
                                                        {langInfo.name}
                                                    </span>
                                                </div>
                                                <span className="issue-count-modern">{vulns.length} issues</span>
                                            </div>

                                            {vulns.length > 0 ? (
                                                <div className="vulns-list-modern">
                                                    {vulns.sort((a, b) => {
                                                        const order = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
                                                        return order[b.severity] - order[a.severity];
                                                    }).map((vuln, vIdx) => (
                                                        <div key={vIdx} className="vuln-card-modern">
                                                            <div className="vuln-header-modern">
                                                                <span className="vuln-icon-modern">{getVulnIcon(vuln.vulnerability_type)}</span>
                                                                <span className="vuln-badge-modern" style={{ background: getSeverityColor(vuln.severity) }}>
                                                                    {vuln.severity}
                                                                </span>
                                                                <span className="vuln-type-modern">
                                                                    {vuln.vulnerability_type.replace(/_/g, ' ')}
                                                                </span>
                                                                <span className="vuln-line-modern">Line {vuln.line_number}</span>
                                                            </div>

                                                            <div className="vuln-body-modern">
                                                                <p className="vuln-desc-modern">{vuln.description}</p>

                                                                {vuln.code_snippet && (
                                                                    <div className="code-block-modern">
                                                                        <div className="code-header-modern">Vulnerable Code</div>
                                                                        <pre className="code-pre-modern">
                                                                            <code>{vuln.code_snippet}</code>
                                                                        </pre>
                                                                    </div>
                                                                )}

                                                                <div className="fix-box-modern">
                                                                    <div className="fix-header-modern">
                                                                        <Zap size={16} />
                                                                        Recommended Fix
                                                                    </div>
                                                                    <p>{vuln.fix_suggestion}</p>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="no-issues-modern">
                                                    <CheckCircle size={20} />
                                                    <span>No security issues detected</span>
                                                </div>
                                            )}
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}
                </main>
            </div>
        </div>
    );
}

export default App;
