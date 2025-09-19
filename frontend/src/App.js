import React, { useState, useCallback } from 'react';
import { Upload, Shield, AlertTriangle, CheckCircle, FileText, Download } from 'lucide-react';
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

    const handleFileUpload = useCallback(async (files) => {
        const file = files[0];
        if (!file) return;

        // Validate file type - now supporting 40+ programming languages
        const validExtensions = [
            // Python
            '.py', '.pyx', '.pyw',
            // JavaScript/TypeScript
            '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
            // Java
            '.java',
            // C/C++
            '.c', '.cpp', '.cc', '.cxx', '.c++', '.h', '.hpp', '.hh', '.hxx',
            // C#
            '.cs', '.csx',
            // Go
            '.go',
            // Rust
            '.rs',
            // PHP
            '.php', '.php3', '.php4', '.php5', '.phtml',
            // Ruby
            '.rb', '.rbw', '.rake', '.gemspec',
            // Swift
            '.swift',
            // Kotlin
            '.kt', '.kts',
            // Scala
            '.scala', '.sc',
            // Perl
            '.pl', '.pm', '.perl',
            // Shell scripts
            '.sh', '.bash', '.zsh', '.fish', '.ps1',
            // SQL
            '.sql', '.psql', '.mysql',
            // Web languages
            '.html', '.htm', '.xml', '.jsp', '.asp', '.aspx',
            // Other languages
            '.r', '.R', '.m', '.lua', '.dart', '.vb', '.vbs',
            '.f', '.f90', '.pas', '.ada', '.asm', '.s',
            '.clj', '.ex', '.exs', '.erl', '.hrl', '.fs', '.fsx',
            '.hs', '.ml', '.nim', '.jl', '.cr',
            // Archives
            '.zip'
        ];
        const fileExtension = '.' + file.name.split('.').pop().toLowerCase();

        if (!validExtensions.includes(fileExtension)) {
            setAnalysisState(prev => ({
                ...prev,
                error: `Unsupported file type. Supported formats: ${validExtensions.join(', ')}`
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

            const endpoint = fileExtension === '.zip' ? '/api/analyze/codebase' : '/api/analyze/file';
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
                progress: 10
            }));

            // Poll for results
            pollAnalysisStatus(uploadResult.analysis_id);

        } catch (error) {
            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                error: error.message
            }));
        }
    }, []);

    const pollAnalysisStatus = useCallback(async (analysisId) => {
        const maxAttempts = 60;
        let attempts = 0;

        const poll = async () => {
            try {
                attempts++;

                const statusResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/status`);
                if (!statusResponse.ok) {
                    throw new Error('Failed to get analysis status');
                }

                const status = await statusResponse.json();

                setAnalysisState(prev => ({
                    ...prev,
                    progress: Math.min(status.progress || prev.progress + 5, 90)
                }));

                if (status.status === 'completed') {
                    const resultsResponse = await fetch(`${API_BASE_URL}/api/analyze/${analysisId}/results`);
                    if (resultsResponse.ok) {
                        const results = await resultsResponse.json();
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
                        error: 'Analysis failed. Please try again.'
                    }));
                } else if (attempts < maxAttempts) {
                    setTimeout(poll, 3000);
                } else {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: 'Analysis timeout. Please try again.'
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

    return (
        <div className="app">
            <header className="header">
                <div className="header-content">
                    <div className="logo">
                        <Shield size={32} />
                        <h1>AI Security Auditor</h1>
                    </div>
                    <p className="tagline">Professional code security analysis powered by AI</p>
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
                                <p>Drag and drop your code files or click to browse</p>

                                <input
                                    type="file"
                                    id="file-upload"
                                    className="file-input"
                                    accept=".py,.pyx,.pyw,.js,.jsx,.ts,.tsx,.mjs,.cjs,.java,.c,.cpp,.cc,.cxx,.c++,.h,.hpp,.hh,.hxx,.cs,.csx,.go,.rs,.php,.php3,.php4,.php5,.phtml,.rb,.rbw,.rake,.gemspec,.swift,.kt,.kts,.scala,.sc,.pl,.pm,.perl,.sh,.bash,.zsh,.fish,.ps1,.sql,.psql,.mysql,.html,.htm,.xml,.jsp,.asp,.aspx,.r,.R,.m,.lua,.dart,.vb,.vbs,.f,.f90,.pas,.ada,.asm,.s,.clj,.ex,.exs,.erl,.hrl,.fs,.fsx,.hs,.ml,.nim,.jl,.cr,.zip"
                                    onChange={(e) => handleFileUpload(e.target.files)}
                                />

                                <label htmlFor="file-upload" className="upload-button">
                                    Choose Files
                                </label>
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
                                <p>AI is scanning for security vulnerabilities...</p>

                                <div className="progress-bar">
                                    <div
                                        className="progress-fill"
                                        style={{ width: `${analysisState.progress}%` }}
                                    ></div>
                                </div>

                                <p className="progress-text">{analysisState.progress}% complete</p>
                            </div>
                        </div>
                    )}

                    {analysisState.results && (
                        <div className="results-section">
                            <div className="results-header">
                                <h2>Security Analysis Results</h2>
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
                                    </div>
                                </div>
                            </div>

                            {analysisState.results.results?.files?.length > 0 && (
                                <div className="detailed-results">
                                    <h3>Detailed Findings</h3>

                                    {analysisState.results.results.files.map((file, fileIndex) => (
                                        <div key={fileIndex} className="file-result">
                                            <div className="file-header">
                                                <h4>{file.filename}</h4>
                                                <span className="issue-count">
                                                    {file.analysis.vulnerabilities?.length || 0} issues found
                                                </span>
                                            </div>

                                            {file.analysis.vulnerabilities?.length > 0 && (
                                                <div className="vulnerabilities-list">
                                                    {file.analysis.vulnerabilities.map((vuln, vulnIndex) => (
                                                        <div key={vulnIndex} className="vulnerability-item">
                                                            <div className="vuln-header">
                                                                <span className="severity-badge" style={{
                                                                    backgroundColor: vuln.severity === 'CRITICAL' ? '#dc3545' :
                                                                        vuln.severity === 'HIGH' ? '#fd7e14' :
                                                                            vuln.severity === 'MEDIUM' ? '#ffc107' : '#28a745'
                                                                }}>
                                                                    {vuln.severity}
                                                                </span>
                                                                <span className="vuln-type">{vuln.vulnerability_type.replace('_', ' ')}</span>
                                                                <span className="line-number">Line {vuln.line_number}</span>
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
                                                                    <h5>Recommended Fix:</h5>
                                                                    <p>{vuln.fix_suggestion}</p>
                                                                </div>

                                                                <div className="confidence-score">
                                                                    Confidence: {Math.round(vuln.confidence * 100)}%
                                                                </div>
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                        </div>
                                    ))}
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
