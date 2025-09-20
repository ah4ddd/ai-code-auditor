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

    const [selectedFiles, setSelectedFiles] = useState([]);
    const [scanMode, setScanMode] = useState('files'); // 'files' or 'repository'
    const [repoUrl, setRepoUrl] = useState('');
    const [repoBranch, setRepoBranch] = useState('main');

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
        if (!files || files.length === 0) return;

        // Handle multiple files
        const fileList = Array.from(files);

        // Validate all files
        const validFiles = [];
        const errors = [];

        for (const file of fileList) {
            // Check if it's a binary file (only block truly binary files)
            if (isBinaryFile(file.name)) {
                errors.push(`${file.name}: Binary files are not supported`);
                continue;
            }

            // File size validation
            const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
            const maxSize = fileExtension.includes('zip') || fileExtension.includes('tar') ?
                100 * 1024 * 1024 : // 100MB for archives
                10 * 1024 * 1024;   // 10MB for source files

            if (file.size > maxSize) {
                errors.push(`${file.name}: File too large (max ${fileExtension.includes('zip') || fileExtension.includes('tar') ? '100MB' : '10MB'})`);
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

        // Store selected files for display
        setSelectedFiles(validFiles);

        // Start analysis
        setAnalysisState({
            isAnalyzing: true,
            currentAnalysis: null,
            results: null,
            error: null,
            progress: 0
        });

        try {
            // Check if any files are archives
            const hasArchives = validFiles.some(file => {
                const ext = '.' + file.name.split('.').pop().toLowerCase();
                return ext.includes('zip') || ext.includes('tar');
            });

            if (hasArchives && validFiles.length > 1) {
                setAnalysisState(prev => ({
                    ...prev,
                    isAnalyzing: false,
                    error: 'Cannot mix archive files with individual files. Please upload either archives OR individual files.'
                }));
                return;
            }

            if (hasArchives) {
                // Handle single archive file
                const file = validFiles[0];
                const formData = new FormData();
                formData.append('file', file);

                console.log(`🚀 Uploading archive ${file.name} (${(file.size / 1024).toFixed(1)}KB) for analysis`);

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
                // Handle multiple individual files
                await analyzeMultipleFiles(validFiles);
            }

        } catch (error) {
            console.error('Upload error:', error);
            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                error: error.message
            }));
        }
    }, []);

    const analyzeMultipleFiles = useCallback(async (files) => {
        try {
            console.log(`🚀 Analyzing ${files.length} files...`);

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

                // Update progress
                const progress = Math.round((i / files.length) * 80) + 10; // 10-90%
                setAnalysisState(prev => ({
                    ...prev,
                    progress: progress
                }));

                console.log(`📄 Analyzing ${file.name} (${i + 1}/${files.length})`);

                const formData = new FormData();
                formData.append('file', file);

                const response = await fetch(`${API_BASE_URL}/api/analyze/file`, {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    console.error(`Failed to analyze ${file.name}: ${response.statusText}`);
                    continue;
                }

                const uploadResult = await response.json();

                // Wait for analysis to complete
                const analysisResult = await waitForAnalysis(uploadResult.analysis_id);

                if (analysisResult && analysisResult.results) {
                    const fileResult = analysisResult.results.files[0];
                    if (fileResult) {
                        allResults.files.push(fileResult);

                        // Aggregate statistics
                        const vulns = fileResult.analysis.vulnerabilities || [];
                        allResults.overall_summary.total_vulnerabilities += vulns.length;

                        vulns.forEach(vuln => {
                            const severity = vuln.severity.toLowerCase();
                            if (severity in allResults.overall_summary) {
                                allResults.overall_summary[severity + '_count']++;
                            }
                        });

                        // Track languages
                        const language = fileResult.analysis.metadata?.language;
                        if (language) {
                            languagesFound.add(language);
                        }
                    }
                }

                // Small delay between files to avoid overwhelming the API
                await new Promise(resolve => setTimeout(resolve, 1000));
            }

            allResults.overall_summary.languages_detected = Array.from(languagesFound);

            // Generate summary
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
                        file_count: files.length,
                        total_time: `${files.length * 2} seconds`
                    }
                },
                progress: 100
            }));

            console.log(`✅ Multi-file analysis completed: ${allResults.overall_summary.total_vulnerabilities} vulnerabilities found`);

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
        const low = summary.low_count || 0;

        // Use the same risk assessment logic
        let riskLevel;
        if (critical > 0) {
            riskLevel = 'CRITICAL';
        } else if (critical === 0 && high >= 2) {
            riskLevel = 'HIGH';
        } else if (critical === 0 && high === 1 && medium >= 3) {
            riskLevel = 'HIGH';
        } else if (critical === 0 && high === 1) {
            riskLevel = 'MEDIUM';
        } else if (critical === 0 && high === 0 && medium >= 5) {
            riskLevel = 'MEDIUM';
        } else if (critical === 0 && high === 0 && medium >= 2) {
            riskLevel = 'LOW';
        } else if (critical === 0 && high === 0 && medium === 1 && low >= 3) {
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
                critical: critical,
                high: high,
                medium: medium,
                low: low,
                info: summary.info_count || 0
            },
            recommendations: generateRecommendations(summary)
        };
    }, []);

    const generateRecommendations = useCallback((summary) => {
        const recommendations = [];
        const critical = summary.critical_count || 0;
        const high = summary.high_count || 0;
        const medium = summary.medium_count || 0;

        if (critical > 0) {
            recommendations.push("🚨 URGENT: Address CRITICAL vulnerabilities immediately - they pose immediate security risk");
        }
        if (high > 0) {
            recommendations.push("⚡ Fix HIGH severity issues within 24-48 hours");
        }
        if (medium > 3) {
            recommendations.push("📋 Plan remediation for MEDIUM severity issues in next development cycle");
        }
        if (critical + high + medium > 0) {
            recommendations.push("🔄 Implement automated security scanning in CI/CD pipeline");
            recommendations.push("📚 Conduct security code review training for development team");
        }
        if (recommendations.length === 0) {
            recommendations.push("✅ Good security posture! Continue regular security reviews");
        }
        recommendations.push("🛡️ Consider implementing static analysis tools like SonarQube or Checkmarx");

        return recommendations;
    }, []);

    const handleRepositoryScan = useCallback(async () => {
        if (!repoUrl.trim()) {
            setAnalysisState(prev => ({
                ...prev,
                error: 'Please enter a repository URL'
            }));
            return;
        }

        // Validate repository URL
        const supportedDomains = ['github.com', 'gitlab.com', 'bitbucket.org'];
        if (!supportedDomains.some(domain => repoUrl.includes(domain))) {
            setAnalysisState(prev => ({
                ...prev,
                error: 'Unsupported repository. Please use GitHub, GitLab, or Bitbucket.'
            }));
            return;
        }

        setAnalysisState({
            isAnalyzing: true,
            currentAnalysis: null,
            results: null,
            error: null,
            progress: 0
        });

        try {
            console.log(`🚀 Starting repository scan: ${repoUrl} (branch: ${repoBranch})`);

            const response = await fetch(`${API_BASE_URL}/api/analyze/repository`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    repo_url: repoUrl,
                    branch: repoBranch
                })
            });

            if (!response.ok) {
                throw new Error(`Repository scan failed: ${response.statusText}`);
            }

            const result = await response.json();

            setAnalysisState(prev => ({
                ...prev,
                currentAnalysis: result.analysis_id,
                progress: 10
            }));

            // Poll for results
            pollRepositoryAnalysisStatus(result.analysis_id);

        } catch (error) {
            console.error('Repository scan error:', error);
            setAnalysisState(prev => ({
                ...prev,
                isAnalyzing: false,
                error: error.message
            }));
        }
    }, [repoUrl, repoBranch]);

    const pollRepositoryAnalysisStatus = useCallback(async (analysisId) => {
        const maxAttempts = 300; // 5 minutes for repository scanning
        let attempts = 0;

        const poll = async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/analyze/repository/${analysisId}/status`);
                if (!response.ok) {
                    throw new Error('Failed to get analysis status');
                }

                const status = await response.json();

                setAnalysisState(prev => ({
                    ...prev,
                    progress: status.progress || 0
                }));

                if (status.status === 'completed') {
                    // Get results
                    const resultsResponse = await fetch(`${API_BASE_URL}/api/analyze/repository/${analysisId}/results`);
                    if (resultsResponse.ok) {
                        const results = await resultsResponse.json();
                        setAnalysisState(prev => ({
                            ...prev,
                            isAnalyzing: false,
                            results: results,
                            progress: 100
                        }));
                        console.log(`✅ Repository analysis completed: ${results.summary.total_issues} vulnerabilities found`);
                    }
                } else if (status.status === 'failed') {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: status.message || 'Repository analysis failed'
                    }));
                } else if (attempts < maxAttempts) {
                    attempts++;
                    setTimeout(poll, 2000); // Poll every 2 seconds
                } else {
                    setAnalysisState(prev => ({
                        ...prev,
                        isAnalyzing: false,
                        error: 'Repository analysis timeout'
                    }));
                }
            } catch (error) {
                console.error('Error polling repository analysis status:', error);
                setAnalysisState(prev => ({
                    ...prev,
                    isAnalyzing: false,
                    error: error.message
                }));
            }
        };

        poll();
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
                            {/* Mode Selector */}
                            <div className="mode-selector">
                                <button
                                    className={`mode-btn ${scanMode === 'files' ? 'active' : ''}`}
                                    onClick={() => setScanMode('files')}
                                >
                                    <FileText size={20} />
                                    Upload Files
                                </button>
                                <button
                                    className={`mode-btn ${scanMode === 'repository' ? 'active' : ''}`}
                                    onClick={() => setScanMode('repository')}
                                >
                                    <Code2 size={20} />
                                    Scan Repository
                                </button>
                            </div>

                            {scanMode === 'files' ? (
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
                                        multiple
                                        onChange={(e) => handleFileUpload(e.target.files)}
                                    />

                                    <label htmlFor="file-upload" className="upload-button">
                                        <Code2 size={20} />
                                        Choose Multiple Files or ZIP Archives
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
                            ) : (
                                /* Repository Scanning Form */
                                <div className="repository-scan-form">
                                    <div className="upload-area">
                                        <Code2 size={48} />
                                        <h2>Scan Repository for Security Vulnerabilities</h2>
                                        <p>Analyze entire repositories from GitHub, GitLab, or Bitbucket</p>

                                        <div className="repo-input-group">
                                            <div className="input-field">
                                                <label htmlFor="repo-url">Repository URL</label>
                                                <input
                                                    type="url"
                                                    id="repo-url"
                                                    placeholder="https://github.com/username/repository"
                                                    value={repoUrl}
                                                    onChange={(e) => setRepoUrl(e.target.value)}
                                                    className="repo-input"
                                                />
                                            </div>
                                            <div className="input-field">
                                                <label htmlFor="repo-branch">Branch (optional)</label>
                                                <input
                                                    type="text"
                                                    id="repo-branch"
                                                    placeholder="main"
                                                    value={repoBranch}
                                                    onChange={(e) => setRepoBranch(e.target.value)}
                                                    className="repo-input"
                                                />
                                            </div>
                                            <button
                                                onClick={handleRepositoryScan}
                                                className="scan-repo-btn"
                                                disabled={!repoUrl.trim()}
                                            >
                                                <Shield size={20} />
                                                Scan Repository
                                            </button>
                                        </div>

                                        <div className="supported-repos">
                                            <p><strong>Supported Platforms:</strong></p>
                                            <div className="repo-platforms">
                                                <span className="platform-badge github">GitHub</span>
                                                <span className="platform-badge gitlab">GitLab</span>
                                                <span className="platform-badge bitbucket">Bitbucket</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Selected Files Preview */}
                            {selectedFiles.length > 0 && !analysisState.isAnalyzing && (
                                <div className="selected-files">
                                    <h3>Selected Files ({selectedFiles.length})</h3>
                                    <div className="files-list">
                                        {selectedFiles.map((file, index) => {
                                            const languageInfo = getLanguageInfo(file.name);
                                            return (
                                                <div key={index} className="file-preview">
                                                    <div className="file-info">
                                                        <span className="file-name">{file.name}</span>
                                                        <span
                                                            className="language-badge"
                                                            style={{ backgroundColor: languageInfo.color }}
                                                        >
                                                            {languageInfo.name}
                                                        </span>
                                                        <span className="file-size">
                                                            {(file.size / 1024).toFixed(1)}KB
                                                        </span>
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                    <div className="file-actions">
                                        <button
                                            onClick={() => setSelectedFiles([])}
                                            className="clear-files-btn"
                                        >
                                            Clear All
                                        </button>
                                        <button
                                            onClick={() => handleFileUpload(selectedFiles)}
                                            className="analyze-files-btn"
                                        >
                                            <Shield size={16} />
                                            Analyze {selectedFiles.length} Files
                                        </button>
                                    </div>
                                </div>
                            )}

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
                                <h2>Analyzing {scanMode === 'repository' ? 'Repository' : 'Your Files'}</h2>
                                <p>AI is scanning {scanMode === 'repository' ? 'the repository' : selectedFiles.length > 0 ? `${selectedFiles.length} files` : 'your files'} for security vulnerabilities across all file types and content...</p>

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
                                            // Get actual vulnerability counts from results
                                            const critical = analysisState.results.summary?.critical_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'CRITICAL').length || 0), 0) || 0;
                                            const high = analysisState.results.summary?.high_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'HIGH').length || 0), 0) || 0;
                                            const medium = analysisState.results.summary?.medium_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'MEDIUM').length || 0), 0) || 0;
                                            const low = analysisState.results.summary?.low_count ||
                                                analysisState.results.results?.files?.reduce((count, file) =>
                                                    count + (file.analysis.vulnerabilities?.filter(v => v.severity === 'LOW').length || 0), 0) || 0;

                                            // Use the same logic as backend for consistency
                                            let riskLevel;
                                            if (critical > 0) {
                                                riskLevel = 'CRITICAL';
                                            } else if (critical === 0 && high >= 2) {
                                                riskLevel = 'HIGH';
                                            } else if (critical === 0 && high === 1 && medium >= 3) {
                                                riskLevel = 'HIGH';
                                            } else if (critical === 0 && high === 1) {
                                                riskLevel = 'MEDIUM';
                                            } else if (critical === 0 && high === 0 && medium >= 5) {
                                                riskLevel = 'MEDIUM';
                                            } else if (critical === 0 && high === 0 && medium >= 2) {
                                                riskLevel = 'LOW';
                                            } else if (critical === 0 && high === 0 && medium === 1 && low >= 3) {
                                                riskLevel = 'LOW';
                                            } else {
                                                riskLevel = 'MINIMAL';
                                            }

                                            const riskColor = riskLevel === 'CRITICAL' ? '#dc2626' :
                                                riskLevel === 'HIGH' ? '#dc3545' :
                                                    riskLevel === 'MEDIUM' ? '#fd7e14' :
                                                        riskLevel === 'LOW' ? '#ffc107' : '#28a745';

                                            return (
                                                <>
                                                    <div className="risk-level" style={{ backgroundColor: riskColor }}>
                                                        {riskLevel}
                                                    </div>
                                                    <div className="risk-description">
                                                        {riskLevel === 'CRITICAL' && '🚨 URGENT: Critical vulnerabilities require immediate action'}
                                                        {riskLevel === 'HIGH' && '⚡ HIGH: Immediate attention required - fix within 24-48 hours'}
                                                        {riskLevel === 'MEDIUM' && '⚠️ MEDIUM: Several issues need fixing - plan remediation'}
                                                        {riskLevel === 'LOW' && '📋 LOW: Minor improvements suggested'}
                                                        {riskLevel === 'MINIMAL' && '✅ MINIMAL: Good security posture'}
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
