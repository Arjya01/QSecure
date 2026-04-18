import { useState, useEffect } from 'react';
import { Loader2, MapPin, Download, AlertTriangle, ShieldCheck, ArrowRight, CheckCircle2 } from 'lucide-react';
import client from '../api/client';
import styles from './CommonPage.module.css';

export default function Roadmap() {
  const [roadmap, setRoadmap] = useState(null);
  const [loading, setLoading] = useState(true);
  const [errorStr, setErrorStr] = useState(null);

  useEffect(() => {
    async function fetchRoadmap() {
      try {
        const res = await client.get('/dashboard/ai-roadmap');
        if (res.success) {
          if (res.data?.error) {
              setErrorStr(res.data.executive_summary);
          } else {
              setRoadmap(res.data);
          }
        }
      } catch (err) {
        console.error(err);
        setErrorStr("Failed to load roadmap data from server.");
      } finally {
        setLoading(false);
      }
    }
    fetchRoadmap();
  }, []);

  const handleExportJSON = () => {
    if (!roadmap) return;
    const blob = new Blob([JSON.stringify(roadmap, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'PQC_Migration_Roadmap.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const getSeverityColor = (sev) => {
      switch(sev?.toUpperCase()) {
          case 'CRITICAL': return 'var(--risk-critical)';
          case 'HIGH': return 'var(--risk-high)';
          case 'MEDIUM': return 'var(--risk-medium)';
          case 'LOW': return 'var(--risk-low)';
          default: return 'var(--text-secondary)';
      }
  };

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <MapPin size={24} color="var(--color-primary)" />
            AI Enterprise Roadmap
          </h2>
          <p className={styles.subtitle}>Enoki AI generated structured action plan based on deep cryptographic telemetry.</p>
        </div>
        <div className={styles.actions}>
          <button className={styles.secondaryBadge} onClick={handleExportJSON} disabled={loading || !roadmap}>
            <Download size={16} /> Export JSON Data
          </button>
        </div>
      </div>

      {loading ? (
        <div className={styles.card} style={{ minHeight: '60vh', padding: '32px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
          <Loader2 size={48} className="spin" style={{ marginBottom: '16px', color: 'var(--color-primary)' }} />
          <p>Enoki AI is analyzing raw CBOM configurations, extracting anomalies, and synthesizing a PQC Roadmap...</p>
          <p style={{ fontSize: '12px', marginTop: '8px', opacity: 0.7 }}>This advanced analysis takes about ~20 seconds.</p>
        </div>
      ) : errorStr ? (
         <div className={styles.card} style={{ minHeight: '60vh', padding: '32px' }}>
            <h3 style={{ color: 'var(--risk-critical)' }}>⚠️ AI Service Error</h3>
            <p style={{ marginTop: '16px' }}>{errorStr}</p>
         </div>
      ) : roadmap && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
            {/* Executive Summary */}
            <div className={styles.card} style={{ padding: '24px', borderLeft: '4px solid var(--color-primary)' }}>
                <h3 style={{ fontSize: '18px', color: 'var(--text-primary)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldCheck size={20} color="var(--color-primary)" /> Executive Target Posture
                </h3>
                <p style={{ color: 'var(--text-secondary)', lineHeight: '1.6', fontSize: '15px' }}>
                    {roadmap.executive_summary || "No executive summary available."}
                </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '24px' }}>
                {/* Anomalies Card */}
                <div className={styles.card} style={{ padding: '24px' }}>
                    <h3 style={{ fontSize: '18px', color: 'var(--text-primary)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                       <AlertTriangle size={20} color="var(--risk-high)" /> Detected Anomalies
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {(roadmap.anomalies || []).length === 0 ? (
                            <p style={{ color: 'var(--text-muted)' }}>No severe anomalies detected in the parsed scan scope.</p>
                        ) : roadmap.anomalies.map((an, i) => (
                            <div key={i} style={{ display: 'flex', gap: '12px', padding: '12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px', border: `1px solid ${getSeverityColor(an.severity)}40` }}>
                                <div style={{ color: getSeverityColor(an.severity), fontSize: '12px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', backgroundColor: `${getSeverityColor(an.severity)}15`, height: 'fit-content' }}>
                                    {an.severity}
                                </div>
                                <div style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                                    {an.finding}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Crypto Upgrades Card */}
                <div className={styles.card} style={{ padding: '24px', overflowX: 'auto' }}>
                    <h3 style={{ fontSize: '18px', color: 'var(--text-primary)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                       <ArrowRight size={20} color="var(--risk-safe)" /> Required Upgrades
                    </h3>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
                        <thead>
                            <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)', textAlign: 'left' }}>
                                <th style={{ padding: '8px 0' }}>Current Algorithm</th>
                                <th style={{ padding: '8px 0' }}>PQC Alternative</th>
                                <th style={{ padding: '8px 0' }}>Impact</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(roadmap.cryptographic_upgrades || []).map((upg, i) => (
                                <tr key={i} style={{ borderBottom: '1px solid var(--bg-main)' }}>
                                    <td style={{ padding: '12px 16px 12px 0', color: 'var(--risk-critical)', fontFamily: 'monospace' }}>{upg.current_algorithm}</td>
                                    <td style={{ padding: '12px 16px 12px 0', color: 'var(--risk-safe)', fontFamily: 'monospace', fontWeight: 600 }}>{upg.recommended_pqc_alternative}</td>
                                    <td style={{ padding: '12px 0', color: 'var(--text-secondary)', fontSize: '13px' }}>{upg.impact}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Phased Roadmap Timeline */}
            <div className={styles.card} style={{ padding: '24px' }}>
                <h3 style={{ fontSize: '18px', color: 'var(--text-primary)', marginBottom: '24px' }}>
                    Deployment Roadmap Steps
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '32px', position: 'relative' }}>
                    {/* Vertical line indicator */}
                    <div style={{ position: 'absolute', left: '16px', top: '16px', bottom: '16px', width: '2px', backgroundColor: 'var(--border-color)', zIndex: 0 }} />
                    
                    {(roadmap.roadmap_phases || []).map((phase, i) => (
                        <div key={i} style={{ display: 'flex', gap: '24px', zIndex: 1 }}>
                            <div style={{ width: '32px', height: '32px', borderRadius: '50%', backgroundColor: 'var(--color-primary)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 'bold' }}>
                                {i + 1}
                            </div>
                            <div style={{ flex: 1 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '8px' }}>
                                    <h4 style={{ fontSize: '16px', color: 'var(--text-primary)', margin: 0 }}>{phase.phase}</h4>
                                    <span style={{ fontSize: '13px', color: 'var(--text-muted)', backgroundColor: 'var(--bg-main)', padding: '2px 8px', borderRadius: '4px' }}>
                                        {phase.timeframe}
                                    </span>
                                </div>
                                <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                    {(phase.steps || []).map((step, j) => (
                                        <li key={j} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '14px', color: 'var(--text-secondary)' }}>
                                            <CheckCircle2 size={16} color="var(--risk-safe)" style={{ flexShrink: 0, marginTop: '2px' }} />
                                            <span style={{ lineHeight: '1.5' }}>{step}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

        </div>
      )}
    </div>
  );
}
