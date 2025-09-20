import React, { useState, useCallback } from 'react';
import { Upload, Shield, AlertTriangle, CheckCircle, FileText, Download, Code2, Bug, Zap } from 'lucide-react';
import './App.css';

const API_BASE_URL = 'http://localhost:8000';

function App() {
    const [analysisState, setAnalysisState] = useState({
        isAnalyzing: false,
        currentAnalysis: null,
        results: null,
        error: null,
        progress: 0
    });

    const [dragActive, setDragActive] = useState(false);

    // Universal file support - accepts ANY text-based file
    // Only blocks truly binary files like images, videos, executables
    const isBinaryFile = (filename) => {
        const ext = '.' + filename.split('.').pop().toLowerCase();
        const binaryExtensions = {
            '.exe': true, '.dll': true, '.so': true, '.dylib': true, '.bin': true, '.obj': true, '.o': true, '.a': true, '.lib': true,
            '.jpg': true, '.jpeg': true, '.png': true, '.gif': true, '.bmp': true, '.tiff': true, '.ico': true, '.svg': true,
            '.mp3': true, '.mp4': true, '.avi': true, '.mov': true, '.wmv': true, '.flv': true, '.wav': true, '.ogg': true,
            '.pdf': true, '.doc': true, '.docx': true, '.xls': true, '.xlsx': true, '.ppt': true, '.pptx': true,
            '.zip': true, '.rar': true, '.7z': true, '.tar': true, '.gz': true, '.bz2': true // Archives handled separately
        };
        return binaryExtensions[ext] || false;
    };

    // Language detection and metadata
    const getLanguageInfo = (filename) => {
        const name = filename.toLowerCase();
        const ext = '.' + name.split('.').pop();

        const languageMap = {
            // Mainstream languages
            '.py': { name: 'Python', color: '#3776ab', category: 'Backend' },
            '.pyx': { name: 'Cython', color: '#3776ab', category: 'Backend' },
            '.js': { name: 'JavaScript', color: '#f7df1e', category: 'Frontend' },
            '.jsx': { name: 'React', color: '#61dafb', category: 'Frontend' },
            '.ts': { name: 'TypeScript', color: '#007acc', category: 'Frontend' },
            '.tsx': { name: 'TypeScript React', color: '#007acc', category: 'Frontend' },
            '.mjs': { name: 'JavaScript Module', color: '#f7df1e', category: 'Frontend' },

            // JVM ecosystem
            '.java': { name: 'Java', color: '#ed8b00', category: 'Backend' },
            '.kt': { name: 'Kotlin', color: '#7f52ff', category: 'Backend' },
            '.scala': { name: 'Scala', color: '#dc322f', category: 'Backend' },
            '.clj': { name: 'Clojure', color: '#5881d8', category: 'Functional' },
            '.groovy': { name: 'Groovy', color: '#e69f56', category: 'Backend' },

            // Systems programming
            '.c': { name: 'C', color: '#a8b9cc', category: 'Systems' },
            '.cpp': { name: 'C++', color: '#00599c', category: 'Systems' },
            '.cc': { name: 'C++', color: '#00599c', category: 'Systems' },
            '.cxx': { name: 'C++', color: '#00599c', category: 'Systems' },
            '.go': { name: 'Go', color: '#00add8', category: 'Backend' },
            '.rs': { name: 'Rust', color: '#dea584', category: 'Systems' },
            '.zig': { name: 'Zig', color: '#ec915c', category: 'Systems' },
            '.nim': { name: 'Nim', color: '#ffe953', category: 'Systems' },
            '.d': { name: 'D', color: '#ba595e', category: 'Systems' },

            // .NET ecosystem
            '.cs': { name: 'C#', color: '#239120', category: 'Backend' },
            '.vb': { name: 'Visual Basic', color: '#945db7', category: 'Backend' },
            '.fs': { name: 'F#', color: '#378bba', category: 'Functional' },

            // Web backend
            '.php': { name: 'PHP', color: '#777bb4', category: 'Backend' },
            '.rb': { name: 'Ruby', color: '#cc342d', category: 'Backend' },
            '.rake': { name: 'Ruby Rake', color: '#cc342d', category: 'Backend' },
            '.erb': { name: 'ERB Template', color: '#cc342d', category: 'Template' },

            // Mobile
            '.swift': { name: 'Swift', color: '#fa7343', category: 'Mobile' },
            '.dart': { name: 'Dart', color: '#0175c2', category: 'Mobile' },

            // Functional languages
            '.hs': { name: 'Haskell', color: '#5e5086', category: 'Functional' },
            '.ml': { name: 'OCaml', color: '#3be133', category: 'Functional' },
            '.elm': { name: 'Elm', color: '#60b5cc', category: 'Frontend' },
            '.ex': { name: 'Elixir', color: '#6e4a7e', category: 'Backend' },
            '.erl': { name: 'Erlang', color: '#b83998', category: 'Backend' },
            '.lisp': { name: 'Lisp', color: '#3fb68b', category: 'Functional' },
            '.scheme': { name: 'Scheme', color: '#1e4aec', category: 'Functional' },

            // Scripting
            '.pl': { name: 'Perl', color: '#0073a1', category: 'Scripting' },
            '.r': { name: 'R', color: '#276dc3', category: 'Data Science' },
            '.R': { name: 'R', color: '#276dc3', category: 'Data Science' },
            '.lua': { name: 'Lua', color: '#000080', category: 'Scripting' },
            '.m': { name: 'MATLAB', color: '#e16737', category: 'Data Science' },
            '.jl': { name: 'Julia', color: '#9558b2', category: 'Data Science' },
            '.cr': { name: 'Crystal', color: '#000100', category: 'Backend' },

            // Shell scripts
            '.sh': { name: 'Shell', color: '#4eaa25', category: 'DevOps' },
            '.bash': { name: 'Bash', color: '#4eaa25', category: 'DevOps' },
            '.zsh': { name: 'Zsh', color: '#4eaa25', category: 'DevOps' },
            '.fish': { name: 'Fish Shell', color: '#4eaa25', category: 'DevOps' },
            '.ps1': { name: 'PowerShell', color: '#012456', category: 'DevOps' },

            // Database
            '.sql': { name: 'SQL', color: '#336791', category: 'Database' },
            '.psql': { name: 'PostgreSQL', color: '#336791', category: 'Database' },
            '.mysql': { name: 'MySQL', color: '#00758f', category: 'Database' },
            '.sqlite': { name: 'SQLite', color: '#003b57', category: 'Database' },
            '.plsql': { name: 'PL/SQL', color: '#f80000', category: 'Database' },

            // Web templates
            '.html': { name: 'HTML', color: '#e34c26', category: 'Frontend' },
            '.xml': { name: 'XML', color: '#0060ac', category: 'Data' },
            '.jsp': { name: 'JSP', color: '#ed8b00', category: 'Backend' },
            '.asp': { name: 'ASP', color: '#239120', category: 'Backend' },
            '.aspx': { name: 'ASP.NET', color: '#239120', category: 'Backend' },
            '.vue': { name: 'Vue.js', color: '#4fc08d', category: 'Frontend' },
            '.svelte': { name: 'Svelte', color: '#ff3e00', category: 'Frontend' },

            // Assembly
            '.asm': { name: 'Assembly', color: '#6e4c13', category: 'Assembly' },
            '.s': { name: 'Assembly', color: '#6e4c13', category: 'Assembly' },
            '.nasm': { name: 'NASM', color: '#6e4c13', category: 'Assembly' },

            // Scientific/Engineering
            '.f': { name: 'Fortran', color: '#734f96', category: 'Scientific' },
            '.f90': { name: 'Fortran 90', color: '#734f96', category: 'Scientific' },
            '.pas': { name: 'Pascal', color: '#e3f171', category: 'Legacy' },
            '.ada': { name: 'Ada', color: '#02f88c', category: 'Systems' },

            // Blockchain
            '.sol': { name: 'Solidity', color: '#363636', category: 'Blockchain' },
            '.move': { name: 'Move', color: '#4285f4', category: 'Blockchain' },
            '.cairo': { name: 'Cairo', color: '#ff6b35', category: 'Blockchain' },

            // Infrastructure
            '.tf': { name: 'Terraform', color: '#623ce4', category: 'DevOps' },
            '.dockerfile': { name: 'Dockerfile', color: '#384d54', category: 'DevOps' },
            '.yaml': { name: 'YAML', color: '#cb171e', category: 'Config' },
            '.yml': { name: 'YAML', color: '#cb171e', category: 'Config' },
            '.toml': { name: 'TOML', color: '#9c4221', category: 'Config' },
            '.proto': { name: 'Protocol Buffer', color: '#4285f4', category: 'API' },

            // Archives
            '.zip': { name: 'ZIP Archive', color: '#6c757d', category: 'Archive' },
            '.tar': { name: 'TAR Archive', color: '#6c757d', category: 'Archive' },
            '.gz': { name: 'Archive', color: '#6c757d', category: 'Archive' }
        };

        // Special filename detection
        if (name === 'dockerfile' || name === 'containerfile') {
            return { name: 'Dockerfile', color: '#384d54', category: 'DevOps' };
        }
        if (name === 'makefile' || name === 'makefile.am' || name === 'makefile.in') {
            return { name: 'Makefile', color: '#427819', category: 'Build' };
        }
        if (name === 'cmakelists.txt') {
            return { name: 'CMake', color: '#064f8c', category: 'Build' };
        }
        if (name.endsWith('.cmake')) {
            return { name: 'CMake', color: '#064f8c', category: 'Build' };
        }

        return languageMap[ext] || { name: 'Code', color: '#6c757d', category: 'Other' };
    };

    // Get severity color scheme
    const getSeverityColor = (severity) => {
        const colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
            'INFO': '#17a2b8'
        };
        return colors[severity] || '#6c757d';
    };

    // Get vulnerability type icon
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

    const handleFileUpload = useCallback(async (files) => {
        const file = files[0];
        if (!file) return;

        // Enhanced file validation - now accepts ANY text-based file
        const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
        const fileName = file.name.toLowerCase();

        // Check if it's a binary file (only block truly binary files)
        if (isBinaryFile(fileName)) {
            setAnalysisState(prev => ({
                ...prev,
                error: `Binary files are not supported. Please upload text-based files like code, configuration, documentation, or data files.`
            }));
            return;
        }

        // File size validation (increased limits for different file types)
        const maxSize = fileExtension.includes('zip') || fileExtension.includes('tar') ?
            100 * 1024 * 1024 : // 100MB for archives
            10 * 1024 * 1024;   // 10MB for source files

        if (file.size > maxSize) {
            setAnalysisState(prev => ({
                ...prev,
                error: `File too large. Maximum size: ${fileExtension.includes('zip') || fileExtension.includes('tar') ? '100MB' : '10MB'}`
            }));
            return;
        }

        // Start analysis
        setAnalysisState({
            isAnalyzing: true,
            currentAnalysis: null,
            results: null,
            error: null,
            progress: 0
        });

        try {
            const formData = new FormData();
            formData.append('file', file);

            // Choose endpoint based on file type
            const isArchive = fileExtension.includes('zip') || fileExtension.includes('tar');
            const endpoint = isArchive ? '/api/analyze/codebase' : '/api/analyze/file';

            console.log(`🚀 Uploading ${file.name} (${(file.size / 1024).toFixed(1)}KB) for analysis`);

            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
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

            // Poll for results with enhanced progress tracking
            pollAnalysisStatus(uploadResult.analysis_id);

        } catch (error) {
            console.error('Upload error:', error);
            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                error: error.message
            }));
        }
    }, []);

    const pollAnalysisStatus = useCallback(async (analysisId) => {
        const maxAttempts = 120; // Increased for large codebases
        let attempts = 0;

        const poll = async () => {
            try {
                attempts++;

                const statusResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/status`);
                if (!statusResponse.ok) {
                    throw new Error('Failed to get analysis status');
                }

                const status = await statusResponse.json();

                // Enhanced progress calculation
                const progressIncrement = Math.max(2, Math.floor(70 / maxAttempts));
                const newProgress = Math.min(status.progress || (15 + attempts * progressIncrement), 85);

                setAnalysisState(prev => ({
                    ...prev,
                    progress: newProgress
                }));

                if (status.status === 'completed') {
                    const resultsResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/results`);
                    if (resultsResponse.ok) {
                        const results = await resultsResponse.json();
                        console.log('📊 Analysis completed:', results);

                        setAnalysisState(prev => ({
                            ...prev,
                            isAnalyzing: false,
                            results: results,
                            progress: 100
                        }));
                    }
                } else if (status.status === 'failed') {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: status.error || 'Analysis failed. Please try again.'
                    }));
                } else if (attempts < maxAttempts) {
                    // Adaptive polling interval
                    const pollInterval = attempts < 20 ? 2000 : attempts < 60 ? 3000 : 5000;
                    setTimeout(poll, pollInterval);
                } else {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: 'Analysis timeout. Please try again with a smaller file.'
                    }));
                }
            } catch (error) {
                console.error('Polling error:', error);
                setAnalysisState(prev => ({
                    ...prev,
                    isAnalyzing: false,
                    error: error.message
                }));
            }
        };

        poll();
    }, []);

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
            handleFileUpload(e.dataTransfer.files);
        }
    };

    // Export results as PDF/JSON
    const exportResults = (format) => {
        if (!analysisState.results) return;

        if (format === 'json') {
            const dataStr = JSON.stringify(analysisState.results, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            const url = URL.createObjectURL(dataBlob);

            const link = document.createElement('a');
            link.href = url;
            link.download = 'security-analysis-results.json';
            link.click();

            URL.revokeObjectURL(url);
        }
        // PDF export would require backend implementation
    };

    return (
        <div className="app">
            <header className="header">
                <div className="header-content">
                    <div className="logo">
                        <Shield size={32} />
                        <h1>AI Security Auditor</h1>
                    </div>
                    <p className="tagline">Universal security analysis for ANY text-based file powered by AI</p>
                </div>
            </header>

            <main className="main">
                <div className="container">
                    {!analysisState.results && !analysisState.isAnalyzing && (
                        <div className="upload-section">
                            <div
                                className={`upload-area ${dragActive ? 'drag-active' : ''}`}
                                onDragEnter={handleDrag}
                                onDragLeave={handleDrag}
                                onDragOver={handleDrag}
                                onDrop={handleDrop}
                            >
                                <Upload size={48} />
                                <h2>Upload Code for Security Analysis</h2>
                                <p>Supports ANY text-based file including code, configuration, documentation, data files, and more</p>

                                <input
                                    type="file"
                                    id="file-upload"
                                    className="file-input"
                                    onChange={(e) => handleFileUpload(e.target.files)}
                                />

                                <label htmlFor="file-upload" className="upload-button">
                                    <Code2 size={20} />
                                    Choose Files or ZIP Archives
                                </label>

                                <div className="supported-formats">
                                    <p><strong>File Types We Support:</strong></p>
                                    <div className="format-tags">
                                        <span style={{ backgroundColor: '#3776ab', color: 'white' }}>Code Files</span>
                                        <span style={{ backgroundColor: '#f7df1e', color: 'black' }}>JSON/Config</span>
                                        <span style={{ backgroundColor: '#007acc', color: 'white' }}>Documentation</span>
                                        <span style={{ backgroundColor: '#ed8b00', color: 'white' }}>Data Files</span>
                                        <span style={{ backgroundColor: '#00599c', color: 'white' }}>Scripts</span>
                                        <span style={{ backgroundColor: '#00add8', color: 'white' }}>Logs</span>
                                        <span style={{ backgroundColor: '#dea584', color: 'black' }}>Markdown</span>
                                        <span style={{ backgroundColor: '#777bb4', color: 'white' }}>XML/YAML</span>
                                        <span style={{ backgroundColor: '#cc342d', color: 'white' }}>CSV/TSV</span>
                                        <span style={{ backgroundColor: '#fa7343', color: 'white' }}>Text Files</span>
                                        <span style={{ backgroundColor: '#239120', color: 'white' }}>Archives</span>
                                        <span style={{ backgroundColor: '#7f52ff', color: 'white' }}>Any Text</span>
                                    </div>

                                    <div className="categories">
                                        <div className="category-group">
                                            <strong>Programming:</strong> Python, JavaScript, Java, C/C++, Go, Rust, PHP, Ruby, Swift, Kotlin, and 50+ more
                                        </div>
                                        <div className="category-group">
                                            <strong>Configuration:</strong> JSON, YAML, TOML, INI, XML, ENV files
                                        </div>
                                        <div className="category-group">
                                            <strong>Documentation:</strong> Markdown, RST, TXT, README files
                                        </div>
                                        <div className="category-group">
                                            <strong>Data:</strong> CSV, TSV, LOG, SQL, SPARQL, GraphQL
                                        </div>
                                        <div className="category-group">
                                            <strong>Archives:</strong> ZIP, TAR, GZ files for codebase analysis
                                        </div>
                                        <div className="category-group">
                                            <strong>Universal:</strong> ANY text-based file that contains readable content
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {analysisState.error && (
                                <div className="error-message">
                                    <AlertTriangle size={20} />
                                    <p>{analysisState.error}</p>
                                </div>
                            )}
                        </div>
                    )}

                    {analysisState.isAnalyzing && (
                        <div className="analysis-progress">
                            <div className="progress-content">
                                <div className="spinner"></div>
                                <h2>Analyzing Your Code</h2>
                                <p>AI is scanning for security vulnerabilities across all file types and content...</p>

                                <div className="progress-bar">
                                    <div
                                        className="progress-fill"
                                        style={{ width: `${analysisState.progress}%` }}
                                    ></div>
                                </div>

                                <p className="progress-text">{analysisState.progress}% complete</p>

                                <div className="progress-steps">
                                    {analysisState.progress >= 15 && <span className="step completed">📤 File uploaded</span>}
                                    {analysisState.progress >= 30 && <span className="step completed">🔍 Language detected</span>}
                                    {analysisState.progress >= 50 && <span className="step completed">🤖 AI analysis running</span>}
                                    {analysisState.progress >= 70 && <span className="step completed">📊 Generating report</span>}
                                    {analysisState.progress >= 100 && <span className="step completed">✅ Analysis complete</span>}
                                </div>
                            </div>
                        </div>
                    )}

                    {analysisState.results && (
                        <div className="results-section">
                            <div className="results-header">
                                <h2>Security Analysis Results</h2>
                                <div className="results-actions">
                                    <button
                                        onClick={() => exportResults('json')}
                                        className="export-button"
                                    >
                                        <Download size={16} />
                                        Export JSON
                                    </button>
                                    <button
                                        onClick={() => setAnalysisState({
                                            isAnalyzing: false,
                                            currentAnalysis: null,
                                            results: null,
                                            error: null,
                                            progress: 0
                                        })}
                                        className="new-analysis-button"
                                    >
                                        New Analysis
                                    </button>
                                </div>
                            </div>

                            {/* Enhanced summary cards */}
                            <div className="summary-cards">
                                <div className="summary-card">
                                    <h3>Vulnerabilities Found</h3>
                                    <div className="severity-breakdown">
                                        <div className="severity-item critical">
                                            <span className="count">{
                                                analysisState.results.summary?.critical_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0), 0) || 0
                                            }</span>
                                            <span className="label">Critical</span>
                                        </div>
                                        <div className="severity-item high">
                                            <span className="count">{
                                                analysisState.results.summary?.high_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'HIGH').length || 0), 0) || 0
                                            }</span>
                                            <span className="label">High</span>
                                        </div>
                                        <div className="severity-item medium">
                                            <span className="count">{
                                                analysisState.results.summary?.medium_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'MEDIUM').length || 0), 0) || 0
                                            }</span>
                                            <span className="label">Medium</span>
                                        </div>
                                        <div className="severity-item low">
                                            <span className="count">{
                                                analysisState.results.summary?.low_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'LOW').length || 0), 0) || 0
                                            }</span>
                                            <span className="label">Low</span>
                                        </div>
                                        <div className="severity-item info">
                                            <span className="count">{
                                                analysisState.results.summary?.info_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'INFO').length || 0), 0) || 0
                                            }</span>
                                            <span className="label">Info</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="summary-card">
                                    <h3>Analysis Overview</h3>
                                    <div className="analysis-stats">
                                        <div className="stat-item">
                                            <span className="stat-value">
                                                {analysisState.results.results?.files?.length || 1}
                                            </span>
                                            <span className="stat-label">Files Analyzed</span>
                                        </div>
                                        <div className="stat-item">
                                            <span className="stat-value">
                                                {analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.length || 0), 0) ||
                                                    analysisState.results.vulnerabilities?.length || 0}
                                            </span>
                                            <span className="stat-label">Total Issues</span>
                                        </div>
                                        <div className="stat-item">
                                            <span className="stat-value">
                                                {analysisState.results.results?.files ?
                                                    [...new Set(analysisState.results.results.files.map(f =>
                                                        getLanguageInfo(f.filename).name))].length : 1}
                                            </span>
                                            <span className="stat-label">Languages</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="summary-card">
                                    <h3>Risk Assessment</h3>
                                    <div className="risk-meter">
                                        {(() => {
                                            const critical = analysisState.results.summary?.critical_count || 0;
                                            const high = analysisState.results.summary?.high_count || 0;
                                            const medium = analysisState.results.summary?.medium_count || 0;

                                            const riskScore = (critical * 10) + (high * 5) + (medium * 2);
                                            const riskLevel = riskScore > 50 ? 'HIGH' : riskScore > 20 ? 'MEDIUM' : riskScore > 5 ? 'LOW' : 'MINIMAL';
                                            const riskColor = riskLevel === 'HIGH' ? '#dc3545' :
                                                riskLevel === 'MEDIUM' ? '#fd7e14' :
                                                    riskLevel === 'LOW' ? '#ffc107' : '#28a745';

                                            return (
                                                <>
                                                    <div className="risk-level" style={{ backgroundColor: riskColor }}>
                                                        {riskLevel}
                                                    </div>
                                                    <div className="risk-description">
                                                        {riskLevel === 'HIGH' && 'Immediate attention required'}
                                                        {riskLevel === 'MEDIUM' && 'Several issues need fixing'}
                                                        {riskLevel === 'LOW' && 'Minor improvements suggested'}
                                                        {riskLevel === 'MINIMAL' && 'Good security posture'}
                                                    </div>
                                                </>
                                            );
                                        })()}
                                    </div>
                                </div>
                            </div>

                            {/* File results display */}
                            {analysisState.results.results?.files?.length > 0 ? (
                                <div className="detailed-results">
                                    <h3>Detailed Findings by File</h3>

                                    {analysisState.results.results.files.map((file, fileIndex) => {
                                        const languageInfo = getLanguageInfo(file.filename);
                                        const vulnerabilities = file.analysis.vulnerabilities || [];

                                        return (
                                            <div key={fileIndex} className="file-result">
                                                <div className="file-header">
                                                    <div className="file-info">
                                                        <h4>{file.filename}</h4>
                                                        <span
                                                            className="language-badge"
                                                            style={{ backgroundColor: languageInfo.color }}
                                                        >
                                                            {languageInfo.name}
                                                        </span>
                                                        <span className="category-badge">
                                                            {languageInfo.category}
                                                        </span>
                                                    </div>
                                                    <div className="file-stats">
                                                        <span className="issue-count">
                                                            {vulnerabilities.length} issues
                                                        </span>
                                                        {file.analysis.metadata && (
                                                            <span className="code-length">
                                                                {Math.round(file.analysis.metadata.code_length / 1024 * 10) / 10}KB
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>

                                                {vulnerabilities.length > 0 && (
                                                    <div className="vulnerabilities-list">
                                                        {vulnerabilities
                                                            .sort((a, b) => {
                                                                const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
                                                                return severityOrder[b.severity] - severityOrder[a.severity];
                                                            })
                                                            .map((vuln, vulnIndex) => (
                                                                <div key={vulnIndex} className="vulnerability-item">
                                                                    <div className="vuln-header">
                                                                        <span className="vuln-icon">
                                                                            {getVulnIcon(vuln.vulnerability_type)}
                                                                        </span>
                                                                        <span
                                                                            className="severity-badge"
                                                                            style={{ backgroundColor: getSeverityColor(vuln.severity) }}
                                                                        >
                                                                            {vuln.severity}
                                                                        </span>
                                                                        <span className="vuln-type">
                                                                            {vuln.vulnerability_type.replace(/_/g, ' ')}
                                                                        </span>
                                                                        <span className="line-number">
                                                                            Line {vuln.line_number}
                                                                        </span>
                                                                        {vuln.confidence && (
                                                                            <span className="confidence">
                                                                                {Math.round(vuln.confidence * 100)}% confidence
                                                                            </span>
                                                                        )}
                                                                    </div>

                                                                    <div className="vuln-content">
                                                                        <p className="description">{vuln.description}</p>

                                                                        {vuln.code_snippet && (
                                                                            <div className="code-snippet">
                                                                                <h5>Vulnerable Code:</h5>
                                                                                <pre><code>{vuln.code_snippet}</code></pre>
                                                                            </div>
                                                                        )}

                                                                        <div className="fix-suggestion">
                                                                            <h5>
                                                                                <Zap size={16} />
                                                                                Recommended Fix:
                                                                            </h5>
                                                                            <p>{vuln.fix_suggestion}</p>
                                                                        </div>
                                                                    </div>
                                                                </div>
                                                            ))}
                                                    </div>
                                                )}

                                                {vulnerabilities.length === 0 && (
                                                    <div className="no-issues">
                                                        <CheckCircle size={20} color="#28a745" />
                                                        <span>No security issues detected in this file</span>
                                                    </div>
                                                )}
                                            </div>
                                        );
                                    })}
                                </div>
                            ) : analysisState.results.vulnerabilities?.length > 0 ? (
                                // Single file analysis results
                                <div className="detailed-results">
                                    <h3>Detailed Findings</h3>

                                    <div className="file-result">
                                        <div className="file-header">
                                            <div className="file-info">
                                                <h4>{analysisState.results.metadata?.filename || 'Analyzed File'}</h4>
                                                {analysisState.results.metadata?.language && (
                                                    <span
                                                        className="language-badge"
                                                        style={{
                                                            backgroundColor: getLanguageInfo(
                                                                analysisState.results.metadata.filename || 'file.txt'
                                                            ).color
                                                        }}
                                                    >
                                                        {analysisState.results.metadata.language}
                                                    </span>
                                                )}
                                            </div>
                                            <span className="issue-count">
                                                {analysisState.results.vulnerabilities.length} issues found
                                            </span>
                                        </div>

                                        <div className="vulnerabilities-list">
                                            {analysisState.results.vulnerabilities
                                                .sort((a, b) => {
                                                    const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
                                                    return severityOrder[b.severity] - severityOrder[a.severity];
                                                })
                                                .map((vuln, vulnIndex) => (
                                                    <div key={vulnIndex} className="vulnerability-item">
                                                        <div className="vuln-header">
                                                            <span className="vuln-icon">
                                                                {getVulnIcon(vuln.vulnerability_type)}
                                                            </span>
                                                            <span
                                                                className="severity-badge"
                                                                style={{ backgroundColor: getSeverityColor(vuln.severity) }}
                                                            >
                                                                {vuln.severity}
                                                            </span>
                                                            <span className="vuln-type">
                                                                {vuln.vulnerability_type.replace(/_/g, ' ')}
                                                            </span>
                                                            <span className="line-number">
                                                                Line {vuln.line_number}
                                                            </span>
                                                            {vuln.confidence && (
                                                                <span className="confidence">
                                                                    {Math.round(vuln.confidence * 100)}% confidence
                                                                </span>
                                                            )}
                                                        </div>

                                                        <div className="vuln-content">
                                                            <p className="description">{vuln.description}</p>

                                                            {vuln.code_snippet && (
                                                                <div className="code-snippet">
                                                                    <h5>Vulnerable Code:</h5>
                                                                    <pre><code>{vuln.code_snippet}</code></pre>
                                                                </div>
                                                            )}

                                                            <div className="fix-suggestion">
                                                                <h5>
                                                                    <Zap size={16} />
                                                                    Recommended Fix:
                                                                </h5>
                                                                <p>{vuln.fix_suggestion}</p>
                                                            </div>
                                                        </div>
                                                    </div>
                                                ))}
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                // No vulnerabilities found
                                <div className="no-results">
                                    <CheckCircle size={48} color="#28a745" />
                                    <h3>No Security Issues Detected</h3>
                                    <p>Your code passed our security analysis. Great job!</p>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </main>
        </div>
    );
}

export default App;
