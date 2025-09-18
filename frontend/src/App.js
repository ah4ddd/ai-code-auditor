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

        // Validate file type
        const validExtensions = ['.py', '.js', '.jsx', '.java', '.go', '.php', '.zip'];
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
                                    accept=".py,.js,.jsx,.java,.go,.php,.zip"
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
                </div>
            </main>
        </div>
    );
}

export default App;
