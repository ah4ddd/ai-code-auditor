# backend/app/services/report_generator.py
"""
Professional report generation for security analysis results
Generates PDF and HTML reports for stakeholders
"""

import os
import tempfile
from datetime import datetime
from typing import Dict, List
from jinja2 import Template
import pdfkit
import json

class ReportGenerator:
    """Generates professional security analysis reports"""

    def __init__(self):
        self.report_template = self._get_html_template()
        self.css_styles = self._get_css_styles()

    def generate_html_report(self, analysis_results: Dict, analysis_id: str) -> str:
        """Generate HTML report file"""

        # Prepare report data
        report_data = self._prepare_report_data(analysis_results, analysis_id)

        # Render template
        template = Template(self.report_template)
        html_content = template.render(**report_data)

        # Save to temporary file
        temp_dir = tempfile.gettempdir()
        html_path = os.path.join(temp_dir, f"security_report_{analysis_id}.html")

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return html_path

    def generate_pdf_report(self, analysis_results: Dict, analysis_id: str) -> str:
        """Generate PDF report file"""

        # First generate HTML
        html_path = self.generate_html_report(analysis_results, analysis_id)

        # Convert to PDF
        temp_dir = tempfile.gettempdir()
        pdf_path = os.path.join(temp_dir, f"security_report_{analysis_id}.pdf")

        options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None,
            'enable-local-file-access': None
        }

        try:
            pdfkit.from_file(html_path, pdf_path, options=options)
        except Exception as e:
            # Fallback: just return HTML if PDF generation fails
            print(f"PDF generation failed: {e}")
            return html_path

        return pdf_path

    def _prepare_report_data(self, analysis_results: Dict, analysis_id: str) -> Dict:
        """Prepare data for report template"""

        files = analysis_results.get('files', [])
        summary = analysis_results.get('overall_summary', {})

        # Calculate risk score
        risk_score = self._calculate_risk_score(summary)
        risk_level = self._get_risk_level(risk_score)

        # Group vulnerabilities by severity
        vulnerability_breakdown = self._group_vulnerabilities_by_severity(files)

        # Get top files with most issues
        problematic_files = self._get_most_problematic_files(files)

        # Generate recommendations
        recommendations = self._generate_recommendations(summary, vulnerability_breakdown)

        return {
            'analysis_id': analysis_id,
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': summary,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'files_analyzed': len(files),
            'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
            'severity_breakdown': {
                'critical': summary.get('critical_count', 0),
                'high': summary.get('high_count', 0),
                'medium': summary.get('medium_count', 0),
                'low': summary.get('low_count', 0)
            },
            'vulnerability_breakdown': vulnerability_breakdown,
            'problematic_files': problematic_files,
            'recommendations': recommendations,
            'detailed_findings': self._prepare_detailed_findings(files),
            'css_styles': self.css_styles
        }

    def _calculate_risk_score(self, summary: Dict) -> int:
        """Calculate overall risk score (0-100)"""
        critical = summary.get('critical_count', 0)
        high = summary.get('high_count', 0)
        medium = summary.get('medium_count', 0)
        low = summary.get('low_count', 0)

        # Weighted scoring
        score = (critical * 25) + (high * 15) + (medium * 8) + (low * 3)
        return min(score, 100)

    def _get_risk_level(self, score: int) -> Dict:
        """Get risk level based on score"""
        if score >= 80:
            return {'level': 'CRITICAL', 'color': '#dc3545', 'description': 'Immediate action required'}
        elif score >= 60:
            return {'level': 'HIGH', 'color': '#fd7e14', 'description': 'High priority remediation needed'}
        elif score >= 30:
            return {'level': 'MEDIUM', 'color': '#ffc107', 'description': 'Moderate security concerns'}
        elif score >= 10:
            return {'level': 'LOW', 'color': '#28a745', 'description': 'Minor security issues'}
        else:
            return {'level': 'MINIMAL', 'color': '#6c757d', 'description': 'Good security posture'}

    def _group_vulnerabilities_by_severity(self, files: List[Dict]) -> Dict:
        """Group vulnerabilities by severity level"""
        breakdown = {}

        for file_data in files:
            vulnerabilities = file_data['analysis'].get('vulnerabilities', [])

            for vuln in vulnerabilities:
                severity = vuln['severity']
                vuln_type = vuln['vulnerability_type']

                if severity not in breakdown:
                    breakdown[severity] = {}

                if vuln_type not in breakdown[severity]:
                    breakdown[severity][vuln_type] = []

                breakdown[severity][vuln_type].append({
                    'file': file_data['filename'],
                    'line': vuln['line_number'],
                    'description': vuln['description']
                })

        return breakdown

    def _get_most_problematic_files(self, files: List[Dict], limit: int = 5) -> List[Dict]:
        """Get files with most security issues"""
        file_scores = []

        for file_data in files:
            vulnerabilities = file_data['analysis'].get('vulnerabilities', [])

            score = 0
            critical = high = medium = low = 0

            for vuln in vulnerabilities:
                if vuln['severity'] == 'CRITICAL':
                    score += 25
                    critical += 1
                elif vuln['severity'] == 'HIGH':
                    score += 15
                    high += 1
                elif vuln['severity'] == 'MEDIUM':
                    score += 8
                    medium += 1
                else:
                    score += 3
                    low += 1

            if score > 0:
                file_scores.append({
                    'filename': file_data['filename'],
                    'score': score,
                    'total_issues': len(vulnerabilities),
                    'critical': critical,
                    'high': high,
                    'medium': medium,
                    'low': low
                })

        return sorted(file_scores, key=lambda x: x['score'], reverse=True)[:limit]

    def _generate_recommendations(self, summary: Dict, vulnerability_breakdown: Dict) -> List[Dict]:
        """Generate actionable security recommendations"""
        recommendations = []

        critical_count = summary.get('critical_count', 0)
        high_count = summary.get('high_count', 0)

        if critical_count > 0:
            recommendations.append({
                'priority': 'URGENT',
                'title': 'Address Critical Vulnerabilities Immediately',
                'description': f'Found {critical_count} critical vulnerabilities that pose immediate risk to your application.',
                'action': 'Fix all critical issues within 24 hours. These vulnerabilities can be exploited with minimal effort.',
                'impact': 'Prevents potential data breaches and system compromise'
            })

        if high_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Remediate High Severity Issues',
                'description': f'Found {high_count} high severity vulnerabilities that should be addressed quickly.',
                'action': 'Plan fixes for high severity issues within next sprint (1-2 weeks).',
                'impact': 'Reduces attack surface and improves security posture'
            })

        # Check for common vulnerability patterns
        if 'CRITICAL' in vulnerability_breakdown:
            if 'SQL_INJECTION' in vulnerability_breakdown['CRITICAL']:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'title': 'Implement Parameterized Queries',
                    'description': 'SQL injection vulnerabilities found in database queries.',
                    'action': 'Replace all string concatenation in SQL with parameterized queries or prepared statements.',
                    'impact': 'Prevents unauthorized database access and data theft'
                })

            if 'HARDCODED_SECRETS' in vulnerability_breakdown['CRITICAL']:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'title': 'Remove Hardcoded Secrets',
                    'description': 'API keys, passwords, or tokens found hardcoded in source code.',
                    'action': 'Move all secrets to environment variables or secure key management system.',
                    'impact': 'Prevents unauthorized access to external services and systems'
                })

        # General security recommendations
        recommendations.extend([
            {
                'priority': 'MEDIUM',
                'title': 'Implement Automated Security Scanning',
                'description': 'Set up continuous security scanning in your CI/CD pipeline.',
                'action': 'Integrate security scanning tools to catch vulnerabilities before production deployment.',
                'impact': 'Prevents future security issues from reaching production'
            },
            {
                'priority': 'MEDIUM',
                'title': 'Security Training for Development Team',
                'description': 'Improve security awareness among developers.',
                'action': 'Conduct secure coding training focusing on common vulnerability patterns found in analysis.',
                'impact': 'Reduces likelihood of introducing new security issues'
            }
        ])

        return recommendations

    def _prepare_detailed_findings(self, files: List[Dict]) -> List[Dict]:
        """Prepare detailed findings for each file"""
        detailed_findings = []

        for file_data in files:
            vulnerabilities = file_data['analysis'].get('vulnerabilities', [])

            if vulnerabilities:
                # Sort by severity and line number
                sorted_vulns = sorted(vulnerabilities,
                                    key=lambda x: (self._severity_weight(x['severity']), x['line_number']))

                detailed_findings.append({
                    'filename': file_data['filename'],
                    'vulnerability_count': len(vulnerabilities),
                    'vulnerabilities': sorted_vulns
                })

        return detailed_findings

    def _severity_weight(self, severity: str) -> int:
        """Get numeric weight for severity sorting"""
        weights = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        return weights.get(severity, 5)

    def _get_html_template(self) -> str:
        """HTML template for reports"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {{ analysis_id }}</title>
    <style>{{ css_styles }}</style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Security Analysis Report</h1>
            <div class="report-meta">
                <p><strong>Analysis ID:</strong> {{ analysis_id }}</p>
                <p><strong>Generated:</strong> {{ generated_at }}</p>
                <p><strong>Files Analyzed:</strong> {{ files_analyzed }}</p>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="risk-overview">
                <div class="risk-score" style="border-left: 4px solid {{ risk_level.color }};">
                    <h3>Risk Level: {{ risk_level.level }}</h3>
                    <p>{{ risk_level.description }}</p>
                    <div class="score">Risk Score: {{ risk_score }}/100</div>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card critical">
                    <h4>{{ severity_breakdown.critical }}</h4>
                    <p>Critical Issues</p>
                </div>
                <div class="stat-card high">
                    <h4>{{ severity_breakdown.high }}</h4>
                    <p>High Issues</p>
                </div>
                <div class="stat-card medium">
                    <h4>{{ severity_breakdown.medium }}</h4>
                    <p>Medium Issues</p>
                </div>
                <div class="stat-card low">
                    <h4>{{ severity_breakdown.low }}</h4>
                    <p>Low Issues</p>
                </div>
            </div>
        </div>

        <!-- Recommendations -->
        <div class="section">
            <h2>Priority Recommendations</h2>
            {% for rec in recommendations[:5] %}
            <div class="recommendation {{ rec.priority.lower() }}">
                <div class="rec-header">
                    <span class="priority">{{ rec.priority }}</span>
                    <h3>{{ rec.title }}</h3>
                </div>
                <p class="description">{{ rec.description }}</p>
                <p class="action"><strong>Action:</strong> {{ rec.action }}</p>
                <p class="impact"><strong>Impact:</strong> {{ rec.impact }}</p>
            </div>
            {% endfor %}
        </div>

        <!-- Most Problematic Files -->
        {% if problematic_files %}
        <div class="section">
            <h2>Files Requiring Immediate Attention</h2>
            <table class="files-table">
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Risk Score</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Total Issues</th>
                    </tr>
                </thead>
                <tbody>
                    {% for file in problematic_files %}
                    <tr>
                        <td class="filename">{{ file.filename }}</td>
                        <td class="risk-score">{{ file.score }}</td>
                        <td class="critical">{{ file.critical }}</td>
                        <td class="high">{{ file.high }}</td>
                        <td class="medium">{{ file.medium }}</td>
                        <td class="low">{{ file.low }}</td>
                        <td class="total">{{ file.total_issues }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Detailed Findings -->
        <div class="section">
            <h2>Detailed Security Findings</h2>
            {% for file in detailed_findings %}
            <div class="file-findings">
                <h3>{{ file.filename }} <span class="vuln-count">({{ file.vulnerability_count }} issues)</span></h3>

                {% for vuln in file.vulnerabilities %}
                <div class="vulnerability {{ vuln.severity.lower() }}">
                    <div class="vuln-header">
                        <span class="severity">{{ vuln.severity }}</span>
                        <span class="type">{{ vuln.vulnerability_type }}</span>
                        <span class="line">Line {{ vuln.line_number }}</span>
                    </div>

                    <div class="vuln-content">
                        <p class="description">{{ vuln.description }}</p>

                        {% if vuln.code_snippet %}
                        <div class="code-snippet">
                            <h5>Vulnerable Code:</h5>
                            <pre><code>{{ vuln.code_snippet }}</code></pre>
                        </div>
                        {% endif %}

                        <div class="fix-suggestion">
                            <h5>Recommended Fix:</h5>
                            <p>{{ vuln.fix_suggestion }}</p>
                        </div>

                        <div class="confidence">
                            Confidence: {{ (vuln.confidence * 100)|round }}%
                        </div>
                    </div>
                </div>
                {% endfor %}
            </div>
            {% endfor %}
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>This report was generated by AI Security Auditor. For questions or support, contact your security team.</p>
            <p class="disclaimer">This analysis should be reviewed by security professionals before taking action on critical findings.</p>
        </div>
    </div>
</body>
</html>
        '''

    def _get_css_styles(self) -> str:
        """CSS styles for professional report appearance"""
        return '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #fff;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px;
        }

        .header {
            text-align: center;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 30px;
            margin-bottom: 40px;
        }

        .header h1 {
            font-size: 2.5rem;
            color: #212529;
            margin-bottom: 20px;
        }

        .report-meta {
            display: flex;
            justify-content: center;
            gap: 40px;
            font-size: 0.9rem;
            color: #6c757d;
        }

        .section {
            margin-bottom: 50px;
        }

        .section h2 {
            font-size: 1.8rem;
            color: #212529;
            margin-bottom: 25px;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 10px;
        }

        .risk-overview {
            margin-bottom: 30px;
        }

        .risk-score {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
        }

        .risk-score h3 {
            font-size: 1.5rem;
            margin-bottom: 10px;
        }

        .score {
            font-size: 2rem;
            font-weight: bold;
            margin-top: 15px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-top: 30px;
        }

        .stat-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            color: white;
        }

        .stat-card.critical { background: #dc3545; }
        .stat-card.high { background: #fd7e14; }
        .stat-card.medium { background: #ffc107; color: #000; }
        .stat-card.low { background: #28a745; }

        .stat-card h4 {
            font-size: 2rem;
            margin-bottom: 5px;
        }

        .recommendation {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .recommendation.urgent { border-left: 4px solid #dc3545; }
        .recommendation.critical { border-left: 4px solid #dc3545; }
        .recommendation.high { border-left: 4px solid #fd7e14; }
        .recommendation.medium { border-left: 4px solid #ffc107; }

        .rec-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }

        .priority {
            background: #e9ecef;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }

        .files-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        .files-table th,
        .files-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }

        .files-table th {
            background: #f8f9fa;
            font-weight: 600;
        }

        .filename {
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9rem;
        }

        .file-findings {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }

        .file-findings h3 {
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 1.2rem;
            margin-bottom: 20px;
        }

        .vuln-count {
            color: #6c757d;
            font-weight: normal;
        }

        .vulnerability {
            border: 1px solid #dee2e6;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .vulnerability.critical { border-left: 4px solid #dc3545; }
        .vulnerability.high { border-left: 4px solid #fd7e14; }
        .vulnerability.medium { border-left: 4px solid #ffc107; }
        .vulnerability.low { border-left: 4px solid #28a745; }

        .vuln-header {
            background: #f8f9fa;
            padding: 12px 20px;
            display: flex;
            gap: 15px;
            align-items: center;
        }

        .severity,
        .type,
        .line {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }

        .severity { background: #e9ecef; }
        .type { background: #d1ecf1; color: #0c5460; }
        .line { background: #d4edda; color: #155724; }

        .vuln-content {
            padding: 20px;
        }

        .description {
            margin-bottom: 20px;
            font-size: 1rem;
        }

        .code-snippet {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }

        .code-snippet h5 {
            margin-bottom: 10px;
            color: #495057;
        }

        .code-snippet pre {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9rem;
        }

        .fix-suggestion {
            background: #d1f2eb;
            border: 1px solid #a7f3d0;
            border-radius: 4px;
            padding: 15px;
            margin: 15px 0;
        }

        .fix-suggestion h5 {
            color: #047857;
            margin-bottom: 10px;
        }

        .confidence {
            text-align: right;
            font-size: 0.9rem;
            color: #6c757d;
            margin-top: 15px;
        }

        .footer {
            margin-top: 60px;
            padding-top: 30px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
        }

        .disclaimer {
            font-style: italic;
            font-size: 0.9rem;
            margin-top: 10px;
        }

        @media print {
            .container { padding: 20px; }
            .section { page-break-inside: avoid; }
        }
        '''
