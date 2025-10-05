import React, { useMemo, useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    BarElement,
    Title,
    Tooltip,
    Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

export default function TopFilesBar({ files }) {
    const [colors, setColors] = useState({
        text: '#1a1a1a',
        secondary: '#6c757d',
        grid: '#e5e7eb'
    });

    useEffect(() => {
        const updateColors = () => {
            const root = document.documentElement;
            setColors({
                text: getComputedStyle(root).getPropertyValue('--text-primary').trim() || '#1a1a1a',
                secondary: getComputedStyle(root).getPropertyValue('--text-secondary').trim() || '#6c757d',
                grid: getComputedStyle(root).getPropertyValue('--border').trim() || '#e5e7eb'
            });
        };

        updateColors();
        // Listen for theme changes
        const observer = new MutationObserver(updateColors);
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

        return () => observer.disconnect();
    }, []);

    const { labels, totals, fullNames } = useMemo(() => {
        const byScore = (files || []).map(f => ({
            file: f.filename,
            score: f.file_score || (f.analysis?.vulnerabilities || []).length,
        }))
            .filter(f => f.score > 0)
            .sort((a, b) => b.score - a.score)
            .slice(0, 15);

        return {
            labels: byScore.map(x => {
                const name = x.file;
                return name.length > 15 ? name.substring(0, 12) + '...' : name;
            }),
            totals: byScore.map(x => x.score),
            fullNames: byScore.map(x => x.file)
        };
    }, [files]);

    if (!labels || labels.length === 0) {
        return (
            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: 'var(--text-secondary)',
                fontSize: '0.9rem'
            }}>
                No file risk data available
            </div>
        );
    }

    const data = {
        labels,
        datasets: [
            {
                label: 'Risk Score',
                data: totals,
                backgroundColor: '#6366f1',
                borderRadius: 4,
                maxBarThickness: 50,
            },
        ],
    };

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: {
            legend: { display: false },
            tooltip: {
                callbacks: {
                    title: function (context) {
                        return fullNames[context[0].dataIndex] || context[0].label;
                    }
                }
            }
        },
        scales: {
            x: {
                beginAtZero: true,
                ticks: {
                    font: { size: 11 },
                    color: colors.secondary
                },
                grid: { color: colors.grid }
            },
            y: {
                ticks: {
                    font: { size: 10 },
                    color: colors.text
                },
                grid: { display: false }
            }
        },
        layout: {
            padding: { top: 10, bottom: 10, left: 10, right: 10 }
        }
    };

    return (
        <div style={{ height: '100%', width: '100%', position: 'relative', minHeight: '260px' }}>
            <Bar data={data} options={options} key={colors.text} />
        </div>
    );
}
