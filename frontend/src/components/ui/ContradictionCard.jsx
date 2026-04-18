/**
 * Q-Secure | ContradictionCard.jsx
 * Phase 5 — Displays a single cross-layer contradiction
 */

import { AlertOctagon, Layers } from 'lucide-react';

const SEV_STYLES = {
  CRITICAL: {
    border: 'rgba(255,34,68,0.35)',
    bg: 'rgba(255,34,68,0.08)',
    badge: 'rgba(255,34,68,0.2)',
    color: '#ff2244',
  },
  HIGH: {
    border: 'rgba(255,122,0,0.3)',
    bg: 'rgba(255,122,0,0.07)',
    badge: 'rgba(255,122,0,0.2)',
    color: '#ff7a00',
  },
  MEDIUM: {
    border: 'rgba(245,200,66,0.3)',
    bg: 'rgba(245,200,66,0.06)',
    badge: 'rgba(245,200,66,0.18)',
    color: '#f5c842',
  },
};

export default function ContradictionCard({ contradiction }) {
  const sev = SEV_STYLES[contradiction.severity] || SEV_STYLES.MEDIUM;

  return (
    <div style={{
      border: `1px solid ${sev.border}`,
      background: sev.bg,
      borderRadius: 12,
      padding: '16px 18px',
      display: 'flex',
      flexDirection: 'column',
      gap: 10,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <AlertOctagon size={18} color={sev.color} style={{ flexShrink: 0, marginTop: 1 }} />
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
            <span style={{ fontWeight: 800, fontSize: 14 }}>{contradiction.title}</span>
            <span style={{
              background: sev.badge, color: sev.color,
              fontSize: 10, fontWeight: 700,
              padding: '2px 8px', borderRadius: 99,
              letterSpacing: '0.08em', textTransform: 'uppercase',
            }}>
              {contradiction.severity}
            </span>
          </div>
          {/* Layer tags */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {(contradiction.layers_involved || []).map(layer => (
              <span key={layer} style={{
                display: 'flex', alignItems: 'center', gap: 4,
                background: 'rgba(255,255,255,0.07)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 6, padding: '2px 8px',
                fontSize: 11, color: 'var(--text-muted)',
              }}>
                <Layers size={10} />
                {layer}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Description */}
      <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary, #9aa5bf)', lineHeight: 1.5 }}>
        {contradiction.description}
      </p>

      {/* False Assurance Risk */}
      {contradiction.false_assurance_risk && (
        <div style={{
          padding: '8px 12px',
          background: 'rgba(245,200,66,0.07)',
          border: '1px solid rgba(245,200,66,0.2)',
          borderRadius: 6,
        }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: '#f5c842', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            False Assurance Risk
          </span>
          <p style={{ margin: '4px 0 0', fontSize: 12, color: '#f5c842bb' }}>
            {contradiction.false_assurance_risk}
          </p>
        </div>
      )}

      {/* Resolution */}
      {contradiction.resolution && (
        <div style={{
          padding: '8px 12px',
          background: 'rgba(34,197,94,0.07)',
          border: '1px solid rgba(34,197,94,0.2)',
          borderRadius: 6,
        }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: '#22c55e', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Resolution
          </span>
          <p style={{ margin: '4px 0 0', fontSize: 12, color: '#22c55ebb' }}>
            {contradiction.resolution}
          </p>
        </div>
      )}
    </div>
  );
}
