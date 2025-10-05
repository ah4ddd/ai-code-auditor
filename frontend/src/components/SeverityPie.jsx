import React, { useEffect, useState } from 'react';
import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

export default function SeverityPie({ summary }) {
    const [colors, setColors] = useState({
        text: '#1a1a1a',
        bg: '#ffffff'
    });

    useEffect(() => {
        const updateColors = () => {
            const root = document.documentElement;
            setColors({
                text: getComputedStyle(root).getPropertyValue('--text-primary').trim() || '#1a1a1a',
                bg: getComputedStyle(root).getPropertyValue('--bg-primary').trim() || '#ffffff'
            });
        };

        updateColors();
        // Listen for theme changes
        const observer = new MutationObserver(updateColors);
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

        return () => observer.disconnect();
    }, []);

    const critical = summary?.critical_count || 0;
    const high = summary?.high_count || 0;
    const medium = summary?.medium_count || 0;
    const low = summary?.low_count || 0;
    const info = summary?.info_count || 0;

    const total = critical + high + medium + low + info;

    if (total === 0) {
        return (
            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: 'var(--text-secondary)',
                fontSize: '0.9rem',
                textAlign: 'center',
                padding: '2rem'
            }}>
                No vulnerabilities detected
            </div>
        );
    }

    const data = {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [
            {
                label: 'Findings',
                data: [critical, high, medium, low, info],
                backgroundColor: ['#FF3B30', '#FF9500', '#FFD60A', '#34C759', '#8E8E93'],
                borderWidth: 2,
                borderColor: colors.bg,
            },
        ],
    };

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    padding: 10,
                    font: {
                        size: 11
                    },
                    boxWidth: 12,
                    color: colors.text
                }
            },
            tooltip: {
                callbacks: {
                    label: function (context) {
                        const label = context.label || '';
                        const value = context.parsed || 0;
                        const percentage = ((value / total) * 100).toFixed(1);
                        return `${label}: ${value} (${percentage}%)`;
                    }
                }
            }
        },
        layout: {
            padding: 10
        }
    };

    return (
        <div style={{ height: '100%', width: '100%', position: 'relative', minHeight: '260px' }}>
            <Pie data={data} options={options} key={colors.text} />
        </div>
    );
}
