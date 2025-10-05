import React from 'react';
import { Line } from 'react-chartjs-2';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

export default function TrendsLine({ history }) {
    if (!history || history.length === 0) {
        return (
            <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: '#94a3b8',
                fontSize: '0.9rem',
                textAlign: 'center',
                padding: '2rem'
            }}>
                <div style={{ marginBottom: '0.5rem' }}>No historical data yet</div>
                <div style={{ fontSize: '0.8rem' }}>Run more analyses to see trends</div>
            </div>
        );
    }

    const labels = history.map(h => {
        const date = new Date(h.timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });

    const repoScores = history.map(h => h.repoScore || 0);
    const criticals = history.map(h => h.critical || 0);

    const data = {
        labels,
        datasets: [
            {
                label: 'Repo Score',
                data: repoScores,
                borderColor: '#6366f1',
                backgroundColor: 'rgba(99, 102, 241, 0.1)',
                yAxisID: 'y',
                tension: 0.3,
                borderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 5,
            },
            {
                label: 'Critical Issues',
                data: criticals,
                borderColor: '#dc2626',
                backgroundColor: 'rgba(220, 38, 38, 0.1)',
                yAxisID: 'y1',
                tension: 0.3,
                borderWidth: 2,
                pointRadius: 3,
                pointHoverRadius: 5,
            },
        ],
    };

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
            mode: 'index',
            intersect: false
        },
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    padding: 10,
                    font: {
                        size: 11
                    },
                    boxWidth: 12,
                    usePointStyle: true
                }
            },
            tooltip: {
                backgroundColor: 'rgba(0, 0, 0, 0.8)',
                padding: 10,
                titleFont: {
                    size: 12
                },
                bodyFont: {
                    size: 11
                }
            }
        },
        scales: {
            x: {
                ticks: {
                    maxRotation: 45,
                    minRotation: 45,
                    font: {
                        size: 9
                    }
                },
                grid: {
                    display: false
                }
            },
            y: {
                type: 'linear',
                display: true,
                position: 'left',
                title: {
                    display: true,
                    text: 'Repo Score',
                    font: {
                        size: 10
                    }
                },
                ticks: {
                    font: {
                        size: 10
                    }
                }
            },
            y1: {
                type: 'linear',
                display: true,
                position: 'right',
                title: {
                    display: true,
                    text: 'Critical',
                    font: {
                        size: 10
                    }
                },
                grid: {
                    drawOnChartArea: false
                },
                ticks: {
                    font: {
                        size: 10
                    }
                }
            },
        },
        layout: {
            padding: {
                top: 10,
                bottom: 10,
                left: 10,
                right: 10
            }
        }
    };

    return (
        <div style={{ height: '100%', width: '100%', position: 'relative', minHeight: '260px' }}>
            <Line data={data} options={options} />
        </div>
    );
}
