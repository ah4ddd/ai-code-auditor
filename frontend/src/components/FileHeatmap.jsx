import React, { useMemo } from 'react';

function scoreToColor(score) {
    // REVERSED: High score = RED (dangerous), Low score = GREEN (safe)
    if (score >= 3) return '#FF3B30';  // Critical - Red
    if (score === 2) return '#FF9500';  // High - Orange
    if (score === 1) return '#FFD60A';  // Medium - Yellow
    return '#34C759';  // Safe - Green
}

export default function FileHeatmap({ files }) {
    const items = useMemo(() => {
        const list = (files || []).map(f => ({
            file: f.filename,
            vulns: f.file_score || (f.analysis?.vulnerabilities || []).length,
        }))
            .sort((a, b) => b.vulns - a.vulns)
            .slice(0, 25);
        return list;
    }, [files]);

    if (!items || items.length === 0) {
        return (
            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '200px',
                color: 'var(--text-secondary)',
                fontSize: '0.9rem'
            }}>
                No file data available
            </div>
        );
    }

    return (
        <div className="file-heatmap" style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
            gap: 12,
            maxHeight: '320px',
            overflowY: 'auto',
            padding: '1rem'
        }}>
            {items.map((it, idx) => (
                <div
                    key={idx}
                    className="heatmap-cell"
                    style={{
                        background: scoreToColor(it.vulns),
                        color: '#ffffff',
                        borderRadius: 8,
                        padding: 12,
                        minHeight: 80,
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'center',
                        border: '1px solid rgba(255, 255, 255, 0.2)',
                        cursor: 'pointer',
                        transition: 'transform 0.2s ease',
                        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                    }}
                    title={`${it.file} — ${it.vulns} vulnerabilities`}
                    onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.05)'}
                    onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
                >
                    <div style={{
                        fontSize: 11,
                        fontWeight: 600,
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        marginBottom: 6,
                        textShadow: '0 1px 2px rgba(0,0,0,0.3)'
                    }}>
                        {it.file}
                    </div>
                    <div style={{
                        fontSize: 13,
                        fontWeight: 700,
                        textShadow: '0 1px 2px rgba(0,0,0,0.3)'
                    }}>
                        {it.vulns} {it.vulns === 1 ? 'issue' : 'issues'}
                    </div>
                </div>
            ))}
        </div>
    );
}
