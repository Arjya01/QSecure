/**
 * Q-Secure | AnomalyAlert.jsx
 * Phase 5 — Shows anomaly/regression banner and modal
 */

import { useState } from 'react';
import { AlertTriangle, TrendingDown, TrendingUp, X, ChevronDown, ChevronUp } from 'lucide-react';

const SEV_COLOR = {
  CRITICAL: 'var(--color-critical, #ff2244)',
  HIGH:     'var(--color-high, #ff7a00)',
  MEDIUM:   'var(--color-medium, #f5c842)',
  LOW:      'var(--color-low, #60a5fa)',
};

const SEV_BG = {
  CRITICAL: 'rgba(255,34,68,0.1)',
  HIGH:     'rgba(255,122,0,0.1)',
  MEDIUM:   'rgba(245,200,66,0.1)',
  LOW:      'rgba(96,165,250,0.1)',
};

function AnomalyRow({ anomaly }) {
  const [open, setOpen] = useState(false);
  const color = SEV_COLOR[anomaly.severity] || 'var(--text-muted)';

  return (
    <div style={{
      border: `1px solid ${color}22`,
      borderRadius: 8,
      marginBottom: 8,
      overflow: 'hidden',
      background: SEV_BG[anomaly.severity] || 'transparent',
    }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 14px', cursor: 'pointer',
        }}
      >
        <span style={{ color, fontWeight: 700, fontSize: 11, minWidth: 70 }}>
          {anomaly.severity}
        </span>
        <span style={{ flex: 1, fontWeight: 600, fontSize: 13 }}>
          {anomaly.anomaly_type.replace(/_/g, ' ')}
        </span>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', marginRight: 8 }}>
          {anomaly.previous_value} → {anomaly.current_value}
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </div>
      {open && (
        <div style={{ padding: '0 14px 12px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: '10px 0 6px' }}>
            {anomaly.description}
          </p>
          {anomaly.possible_causes?.length > 0 && (
            <>
              <p style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                Possible Causes
              </p>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: 'var(--text-secondary)' }}>
                {anomaly.possible_causes.map((c, i) => <li key={i}>{c}</li>)}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default function AnomalyAlert({ anomalyData, assetHostname }) {
  const [modalOpen, setModalOpen] = useState(false);

  if (!anomalyData || !anomalyData.degradation_detected) return null;

  const critical = anomalyData.anomalies_detected?.filter(a =>
    a.severity === 'CRITICAL' || a.severity === 'HIGH'
  ) || [];

  return (
    <>
      {/* Banner */}
      <div
        onClick={() => setModalOpen(true)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 16px',
          background: 'rgba(255,34,68,0.12)',
          border: '1px solid rgba(255,34,68,0.3)',
          borderRadius: 8,
          cursor: 'pointer',
          marginBottom: 12,
        }}
      >
        <AlertTriangle size={16} color="#ff2244" />
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: '#ff5577' }}>
          Cryptographic regression detected on {assetHostname}
          {critical.length > 0 && ` — ${critical.length} critical issue${critical.length > 1 ? 's' : ''}`}
        </span>
        <TrendingDown size={14} color="#ff2244" />
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Δ {anomalyData.score_delta > 0 ? '+' : ''}{anomalyData.score_delta?.toFixed(1)} pts
        </span>
      </div>

      {/* Modal */}
      {modalOpen && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: 20,
        }}>
          <div style={{
            background: 'var(--bg-surface, #0e1525)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 14,
            width: '100%', maxWidth: 680,
            maxHeight: '80vh', overflowY: 'auto',
            padding: 24,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <div>
                <h3 style={{ margin: 0, fontWeight: 800, fontSize: 16 }}>
                  Anomaly Report — {assetHostname}
                </h3>
                <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--text-muted)' }}>
                  Compared to scan from {anomalyData.scan_date_compared?.slice(0, 10) || 'previous scan'}
                </p>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{
              display: 'flex', gap: 12, marginBottom: 20,
              padding: '12px 16px',
              background: 'rgba(255,255,255,0.04)',
              borderRadius: 8,
            }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Score Delta</div>
                <div style={{
                  fontSize: 20, fontWeight: 800,
                  color: anomalyData.score_delta < 0 ? '#ff2244' : '#22c55e',
                }}>
                  {anomalyData.score_delta > 0 ? '+' : ''}{anomalyData.score_delta?.toFixed(1)}
                </div>
              </div>
              <div style={{ width: 1, background: 'var(--border-color)', margin: '0 4px' }} />
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Anomalies</div>
                <div style={{ fontSize: 20, fontWeight: 800 }}>
                  {anomalyData.anomalies_detected?.length || 0}
                </div>
              </div>
              <div style={{ width: 1, background: 'var(--border-color)', margin: '0 4px' }} />
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Degradation</div>
                <div style={{ fontSize: 20, fontWeight: 800, color: anomalyData.degradation_detected ? '#ff2244' : '#22c55e' }}>
                  {anomalyData.degradation_detected ? 'Yes' : 'No'}
                </div>
              </div>
            </div>

            {(anomalyData.anomalies_detected || []).map((a, i) => (
              <AnomalyRow key={i} anomaly={a} />
            ))}
          </div>
        </div>
      )}
    </>
  );
}
