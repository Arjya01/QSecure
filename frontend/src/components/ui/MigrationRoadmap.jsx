/**
 * Q-Secure | MigrationRoadmap.jsx
 * Phase 5 — Horizontal phase timeline with expandable actions
 */

import { useState } from 'react';
import { ChevronDown, ChevronUp, CheckCircle2, Circle, Zap, Clock } from 'lucide-react';

const PRIORITY_COLOR = {
  IMMEDIATE: '#ff2244',
  HIGH:      '#ff7a00',
  MEDIUM:    '#f5c842',
  LOW:       '#60a5fa',
  NONE:      '#22c55e',
};

const EFFORT_COLOR = {
  'Very High': '#ff2244',
  'High':      '#ff7a00',
  'Medium':    '#f5c842',
  'Low':       '#22c55e',
  'Minimal':   '#60a5fa',
};

function ActionItem({ action, index }) {
  const [open, setOpen] = useState(false);
  const [done, setDone]  = useState(false);

  return (
    <div style={{
      border: `1px solid ${done ? 'rgba(34,197,94,0.3)' : 'rgba(255,255,255,0.08)'}`,
      borderRadius: 8,
      marginBottom: 8,
      overflow: 'hidden',
      background: done ? 'rgba(34,197,94,0.05)' : 'rgba(255,255,255,0.02)',
      transition: 'all 0.2s',
    }}>
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 14px', cursor: 'pointer',
        }}
        onClick={() => setOpen(o => !o)}
      >
        <button
          onClick={e => { e.stopPropagation(); setDone(d => !d); }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: done ? '#22c55e' : 'var(--text-muted)' }}
        >
          {done ? <CheckCircle2 size={16} /> : <Circle size={16} />}
        </button>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, textDecoration: done ? 'line-through' : 'none', color: done ? 'var(--text-muted)' : 'inherit' }}>
          {action.title}
        </span>
        <span style={{ fontSize: 11, color: EFFORT_COLOR[action.effort] || 'var(--text-muted)', marginRight: 4 }}>
          {action.effort}
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', marginRight: 4, fontFamily: 'monospace' }}>
          {action.nist_standard}
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </div>

      {open && (
        <div style={{ padding: '0 14px 14px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, margin: '12px 0 10px' }}>
            <div style={{ background: 'rgba(255,34,68,0.06)', border: '1px solid rgba(255,34,68,0.15)', borderRadius: 6, padding: '8px 12px' }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 3 }}>Current State</div>
              <div style={{ fontSize: 12 }}>{action.current_state}</div>
            </div>
            <div style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.15)', borderRadius: 6, padding: '8px 12px' }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 3 }}>Target State</div>
              <div style={{ fontSize: 12 }}>{action.target_state}</div>
            </div>
          </div>

          {action.technical_steps?.length > 0 && (
            <>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
                Technical Steps
              </div>
              <ol style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: 'var(--text-secondary, #9aa5bf)' }}>
                {action.technical_steps.map((step, i) => (
                  <li key={i} style={{ marginBottom: 4, lineHeight: 1.5 }}>{step}</li>
                ))}
              </ol>
            </>
          )}

          {action.verification_method && (
            <div style={{
              marginTop: 10, padding: '8px 12px',
              background: 'rgba(96,165,250,0.07)',
              border: '1px solid rgba(96,165,250,0.2)',
              borderRadius: 6,
            }}>
              <span style={{ fontSize: 10, color: '#60a5fa', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 700 }}>
                Verification
              </span>
              <p style={{ margin: '3px 0 0', fontSize: 12, color: '#60a5fabb' }}>
                {action.verification_method}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function PhasePanel({ phase, isActive, onClick }) {
  const color = PRIORITY_COLOR[phase.priority] || '#60a5fa';
  return (
    <div style={{ flex: 1, minWidth: 140 }}>
      {/* Phase header button */}
      <div
        onClick={onClick}
        style={{
          padding: '12px 14px',
          background: isActive ? `${color}18` : 'rgba(255,255,255,0.03)',
          border: `2px solid ${isActive ? color : 'rgba(255,255,255,0.08)'}`,
          borderRadius: 10,
          cursor: 'pointer',
          transition: 'all 0.2s',
          textAlign: 'center',
        }}
      >
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 2 }}>Phase {phase.phase_number}</div>
        <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 6, lineHeight: 1.3 }}>{phase.phase_name}</div>
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 4 }}>
          <Zap size={10} color={color} />
          <span style={{ fontSize: 10, color, fontWeight: 700 }}>{phase.priority}</span>
        </div>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 3 }}>
          <Clock size={9} />
          {phase.timeframe}
        </div>
        <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-muted)' }}>
          {phase.actions?.length || 0} action{(phase.actions?.length || 0) !== 1 ? 's' : ''}
        </div>
      </div>
    </div>
  );
}

export default function MigrationRoadmap({ roadmap }) {
  const [activePhase, setActivePhase] = useState(0);

  if (!roadmap || !roadmap.phases?.length) {
    return (
      <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>
        No migration roadmap available. Run a scan first.
      </div>
    );
  }

  const phase = roadmap.phases[activePhase];

  return (
    <div>
      {/* Meta info */}
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 16 }}>
        <div style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: '8px 14px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Current Label</div>
          <div style={{ fontWeight: 700, fontSize: 14, marginTop: 2 }}>{roadmap.current_label?.replace(/_/g, ' ')}</div>
        </div>
        <div style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: '8px 14px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Total Effort</div>
          <div style={{ fontWeight: 700, fontSize: 14, marginTop: 2, color: EFFORT_COLOR[roadmap.estimated_total_effort] || 'inherit' }}>
            {roadmap.estimated_total_effort}
          </div>
        </div>
        {roadmap.ai_enhanced && (
          <div style={{ background: 'rgba(200,146,42,0.1)', border: '1px solid rgba(200,146,42,0.3)', borderRadius: 8, padding: '8px 14px' }}>
            <div style={{ fontSize: 10, color: '#c8922a', textTransform: 'uppercase', letterSpacing: '0.06em' }}>AI Enhanced</div>
            <div style={{ fontWeight: 700, fontSize: 13, color: '#f5c842', marginTop: 2 }}>⚡ Groq LLM</div>
          </div>
        )}
      </div>

      {/* Phase timeline */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, position: 'relative', flexWrap: 'wrap' }}>
        {roadmap.phases.map((p, i) => (
          <PhasePanel
            key={i}
            phase={p}
            isActive={activePhase === i}
            onClick={() => setActivePhase(i)}
          />
        ))}
      </div>

      {/* Active phase content */}
      {phase && (
        <div style={{
          background: 'rgba(255,255,255,0.02)',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 12,
          padding: 20,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 8 }}>
            <h4 style={{ margin: 0, fontWeight: 800 }}>
              Phase {phase.phase_number}: {phase.phase_name}
            </h4>
            {phase.dependencies?.length > 0 && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Requires: {phase.dependencies.join(', ')}
              </span>
            )}
          </div>

          {phase.actions?.map((action, i) => (
            <ActionItem key={action.action_id || i} action={action} index={i} />
          ))}

          {phase.risk_if_delayed && (
            <div style={{
              marginTop: 14, padding: '10px 14px',
              background: 'rgba(255,122,0,0.08)',
              border: '1px solid rgba(255,122,0,0.25)',
              borderRadius: 8,
            }}>
              <div style={{ fontSize: 10, color: '#ff7a00', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                Risk If Delayed
              </div>
              <p style={{ margin: 0, fontSize: 13, color: '#ff7a00bb', whiteSpace: 'pre-line' }}>
                {phase.risk_if_delayed}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
