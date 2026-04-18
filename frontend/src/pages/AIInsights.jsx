import { Fragment, useEffect, useMemo, useState } from 'react';
import {
  Brain, ShieldAlert, AlertTriangle, CheckCircle2, XCircle,
  RefreshCw, Cpu, TrendingDown, TrendingUp, ChevronDown, ChevronUp,
  Clock, Zap, Target, Shield, Lock, Activity, Eye, Layers,
  AlertCircle, ArrowRight, Wifi,
} from 'lucide-react';
import client from '../api/client';
import RiskBadge from '../components/ui/RiskBadge';
import useDomainStore from '../store/domainStore';
import { getScopeLabel, getScopeQuery } from '../utils/scope';

// ─── color helpers ────────────────────────────────────────────────────────────

function riskColor(level) {
  return {
    CRITICAL: '#ff2244', HIGH: '#ff7a00', MEDIUM: '#f5c842',
    LOW: '#60a5fa', NONE: '#22c55e', SAFE: '#22c55e',
  }[String(level).toUpperCase()] || 'var(--text-muted)';
}

function tierColor(tier) {
  return { CRITICAL: '#ff2244', HIGH: '#ff7a00', MEDIUM: '#f5c842', LOW: '#60a5fa' }[tier] || '#60a5fa';
}

function labelColor(label) {
  if (!label) return 'var(--text-muted)';
  if (label === 'QUANTUM_SAFE') return '#22c55e';
  if (label === 'PQC_READY') return '#60a5fa';
  return '#ff2244';
}

// ─── shared section wrapper ───────────────────────────────────────────────────

function Section({ icon: Icon, title, badge, badgeColor, children, defaultOpen = true, accent }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{
      background: 'var(--bg-surface, #0e1525)',
      border: `1px solid ${accent ? accent + '44' : 'rgba(255,255,255,0.08)'}`,
      borderRadius: 14,
      marginBottom: 20,
      overflow: 'hidden',
    }}>
      <div
        onClick={() => setOpen(v => !v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 12, padding: '16px 20px',
          background: accent ? `${accent}0a` : 'rgba(255,255,255,0.02)',
          borderBottom: open ? '1px solid rgba(255,255,255,0.06)' : 'none',
          cursor: 'pointer',
        }}
      >
        <Icon size={18} color={accent || 'var(--color-primary, #c41230)'} />
        <span style={{ fontWeight: 800, fontSize: 15, flex: 1, color: 'var(--text-primary)' }}>{title}</span>
        {badge != null && (
          <span style={{
            background: (badgeColor || '#c41230') + '22',
            border: `1px solid ${badgeColor || '#c41230'}44`,
            color: badgeColor || '#ff5577',
            fontSize: 11, fontWeight: 700, padding: '2px 10px', borderRadius: 99,
          }}>
            {badge}
          </span>
        )}
        {open ? <ChevronUp size={16} color="var(--text-muted)" /> : <ChevronDown size={16} color="var(--text-muted)" />}
      </div>
      {open && <div style={{ padding: 20 }}>{children}</div>}
    </div>
  );
}

// ─── posture stat card ────────────────────────────────────────────────────────

function PostureCard({ icon: Icon, label, value, sub, color }) {
  return (
    <div style={{
      flex: 1, background: 'var(--bg-surface)', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 12, padding: '18px 20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <Icon size={15} color={color || 'var(--text-muted)'} />
        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' }}>
          {label}
        </span>
      </div>
      <div style={{ fontSize: 32, fontWeight: 800, color: color || 'var(--text-primary)', lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

// ─── HNDL row ─────────────────────────────────────────────────────────────────

function HNDLRow({ item, rank }) {
  const [expanded, setExpanded] = useState(false);
  const color = tierColor(item.hndl_risk_tier);
  const windowOpen = item.harvest_window_open;

  return (
    <Fragment>
      <tr
        onClick={() => setExpanded(v => !v)}
        style={{
          cursor: 'pointer',
          background: expanded ? 'rgba(255,255,255,0.04)' : 'transparent',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
        }}
      >
        <td style={{ padding: '12px 14px', fontWeight: 700, color: 'var(--text-muted)' }}>#{rank}</td>
        <td style={{ padding: '12px 14px', fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-primary)' }}>
          {item.asset_hostname}
        </td>
        <td style={{ padding: '12px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
            <span style={{ fontSize: 20, fontWeight: 800, color }}>{item.hndl_risk_score?.toFixed(0)}</span>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/100</span>
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
            {item.hndl_risk_score < 20 ? 'Low adversary interest' : item.hndl_risk_score < 45 ? 'Moderate exposure' : 'Priority target'}
          </div>
        </td>
        <td style={{ padding: '12px 14px' }}>
          <span style={{ padding: '4px 10px', borderRadius: 99, background: `${color}22`, color, fontWeight: 700, fontSize: 12 }}>
            {item.hndl_risk_tier}
          </span>
        </td>
        <td style={{ padding: '12px 14px', color: 'var(--text-muted)', fontSize: 12, maxWidth: 240 }}>
          {(item.data_sensitivity_signals || []).slice(0, 2).join(' · ')}
          {(item.data_sensitivity_signals || []).length > 2 && (
            <span style={{ color: 'var(--text-muted)', opacity: 0.6 }}> +{item.data_sensitivity_signals.length - 2} more</span>
          )}
        </td>
        <td style={{ padding: '12px 14px' }}>
          <span style={{ fontWeight: 700, fontSize: 13, color: windowOpen ? '#ff2244' : '#22c55e' }}>
            {windowOpen ? '⚠ OPEN' : '✓ Closed'}
          </span>
        </td>
        <td style={{ padding: '12px 14px', color: 'var(--text-muted)', fontSize: 12 }}>{item.time_to_quantum_threat}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} style={{ padding: '0 14px 14px' }}>
            <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 8, padding: '12px 16px', marginTop: 4 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 8, fontWeight: 700 }}>
                HNDL Reasoning
              </div>
              <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{item.reasoning}</p>
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  );
}

// ─── rule finding card ────────────────────────────────────────────────────────

function RuleFinding({ finding }) {
  const [expanded, setExpanded] = useState(false);
  const color = riskColor(finding.severity);
  return (
    <div style={{
      borderRadius: 8, border: `1px solid ${color}33`,
      background: `${color}08`, overflow: 'hidden', marginBottom: 8,
    }}>
      <div
        onClick={() => setExpanded(v => !v)}
        style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', cursor: 'pointer' }}
      >
        <span style={{ fontSize: 11, fontFamily: 'monospace', padding: '2px 6px', background: `${color}22`, color, borderRadius: 4, fontWeight: 700 }}>
          {finding.rule_id}
        </span>
        <span style={{ fontWeight: 700, fontSize: 13, flex: 1, color: 'var(--text-primary)' }}>{finding.title}</span>
        {finding.asset_hostname && (
          <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{finding.asset_hostname}</span>
        )}
        <span style={{ fontWeight: 700, fontSize: 12, color, background: `${color}22`, padding: '2px 8px', borderRadius: 4 }}>
          {finding.score_impact > 0 ? '+' : ''}{finding.score_impact?.toFixed(0)} pts
        </span>
        <span style={{ padding: '3px 10px', borderRadius: 99, background: `${color}22`, color, fontWeight: 700, fontSize: 11 }}>
          {finding.severity}
        </span>
        {expanded ? <ChevronUp size={14} color="var(--text-muted)" /> : <ChevronDown size={14} color="var(--text-muted)" />}
      </div>
      {expanded && (
        <div style={{ padding: '0 16px 14px', borderTop: `1px solid ${color}22` }}>
          <p style={{ margin: '10px 0 8px', fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{finding.description}</p>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {(finding.affected_layers || []).map(l => (
              <span key={l} style={{ padding: '2px 8px', background: 'rgba(255,255,255,0.06)', borderRadius: 4, fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>
                {l}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── action plan ─────────────────────────────────────────────────────────────

function ActionPlan({ plan }) {
  if (!plan) return <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No action plan available.</p>;
  const cols = [
    { key: 'immediate', label: 'Immediate', color: '#ff2244', icon: Zap },
    { key: 'short_term', label: 'Short-Term (30–90d)', color: '#f59e0b', icon: Clock },
    { key: 'long_term', label: 'Long-Term (90d+)', color: '#60a5fa', icon: Target },
  ];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
      {cols.map(({ key, label, color, icon: Ic }) => (
        <div key={key} style={{ background: 'rgba(255,255,255,0.03)', border: `1px solid ${color}22`, borderRadius: 10, padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Ic size={14} color={color} />
            <span style={{ fontWeight: 800, fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.07em', color }}>{label}</span>
          </div>
          {(plan[key] || []).length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: 12, margin: 0 }}>No actions required.</p>
          ) : (plan[key] || []).map((action, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'flex-start' }}>
              <ArrowRight size={13} color={color} style={{ flexShrink: 0, marginTop: 2 }} />
              <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{action}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

// ─── contradiction card ───────────────────────────────────────────────────────

function ContradictionCard({ c }) {
  const color = riskColor(c.severity);
  return (
    <div style={{ background: `${color}08`, border: `1px solid ${color}33`, borderRadius: 10, padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <AlertTriangle size={16} color={color} />
        <span style={{ fontWeight: 700, fontSize: 14, flex: 1, color: 'var(--text-primary)' }}>{c.title}</span>
        <span style={{ padding: '3px 10px', borderRadius: 99, background: `${color}22`, color, fontWeight: 700, fontSize: 11 }}>{c.severity}</span>
      </div>
      {c.layers_involved?.length > 0 && (
        <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
          {c.layers_involved.map(l => (
            <span key={l} style={{ padding: '2px 8px', background: 'rgba(255,255,255,0.06)', borderRadius: 4, fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>{l}</span>
          ))}
        </div>
      )}
      <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{c.description}</p>
      {c.false_assurance_risk && (
        <div style={{ padding: '8px 12px', background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 6, marginBottom: 8, fontSize: 12, color: '#f59e0b' }}>
          <strong>False Assurance Risk:</strong> {c.false_assurance_risk}
        </div>
      )}
      {c.resolution && (
        <div style={{ padding: '8px 12px', background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.15)', borderRadius: 6, fontSize: 12, color: '#22c55e' }}>
          <strong>Resolution:</strong> {c.resolution}
        </div>
      )}
    </div>
  );
}

// ─── anomaly alert ────────────────────────────────────────────────────────────

function AnomalyAlert({ analysis }) {
  const anomaly = analysis.anomaly;
  if (!anomaly) return null;
  const degraded = anomaly.degradation_detected;
  const improved = anomaly.improvement_detected;
  const color = degraded ? '#ff2244' : improved ? '#22c55e' : 'var(--text-muted)';
  const Icon = degraded ? TrendingDown : improved ? TrendingUp : Activity;
  return (
    <div style={{ padding: '12px 16px', background: `${color}0a`, border: `1px solid ${color}33`, borderRadius: 8, marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: degraded && anomaly.anomalies_detected?.length ? 10 : 0 }}>
        <Icon size={15} color={color} />
        <span style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-primary)', fontSize: 13 }}>{analysis.hostname}</span>
        <span style={{ marginLeft: 'auto', fontWeight: 700, color, fontSize: 12 }}>
          {degraded ? `REGRESSION  Δ ${anomaly.score_delta?.toFixed(1)}` : improved ? `IMPROVED  +${anomaly.score_delta?.toFixed(1)}` : 'STABLE'}
        </span>
      </div>
      {degraded && (anomaly.anomalies_detected || []).map((a, i) => (
        <div key={i} style={{ fontSize: 12, color: 'var(--text-secondary)', paddingLeft: 24, lineHeight: 1.5 }}>
          · <strong style={{ color: riskColor(a.severity) }}>[{a.type}]</strong> {a.description}
        </div>
      ))}
    </div>
  );
}

// ─── loading skeleton ─────────────────────────────────────────────────────────

function SkeletonLine({ width = '100%', height = 14 }) {
  return (
    <div style={{ width, height, background: 'rgba(255,255,255,0.06)', borderRadius: 4, marginBottom: 8, animation: 'pulse 1.5s ease-in-out infinite' }} />
  );
}

// ─── main page ────────────────────────────────────────────────────────────────

export default function AIInsights() {
  const { activeScope } = useDomainStore();
  const scopeLabel = getScopeLabel(activeScope);
  const scopeQuery = useMemo(() => getScopeQuery(activeScope), [activeScope]);

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);       // enterprise analysis
  const [actionPlan, setActionPlan] = useState(null); // dashboard action plan
  const [error, setError] = useState(null);

  async function loadAll() {
    setLoading(true);
    setError(null);
    try {
      const [entRes, planRes] = await Promise.all([
        client.post(`/ai/analyze/enterprise${scopeQuery}`),
        client.get(`/dashboard/ai-roadmap${scopeQuery}`),
      ]);
      if (entRes.success) setData(entRes.data);
      else setError(entRes.error || 'Analysis failed');
      if (planRes.success) setActionPlan(planRes.data);
    } catch (err) {
      setError(err.message || 'Failed to connect');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAll(); }, [scopeQuery]);

  // ── derived data ────────────────────────────────────────────────────────────
  const hndlProfiles   = data?.hndl_profiles || [];
  const contradictions = data?.contradictions || [];
  const narrative      = data?.enterprise_narrative || null;
  const ruleFindings   = data?.rule_findings || [];
  const assetAnalyses  = data?.asset_analyses || [];
  const groqAvailable  = data?.groq_available || false;
  const effectiveAvg   = data?.effective_score_avg || 0;
  const harvestOpen    = data?.harvest_windows_open || 0;
  const degradations   = data?.degradations_detected || 0;
  const totalAssets    = data?.total_assets || 0;

  const effectiveColor = effectiveAvg >= 70 ? '#22c55e' : effectiveAvg >= 40 ? '#f59e0b' : '#ff2244';

  const hasAnomalyData = assetAnalyses.some(a => a.anomaly !== null);

  // ── severity filter for rules ───────────────────────────────────────────────
  const [ruleFilter, setRuleFilter] = useState('ALL');
  const filteredRules = ruleFindings.filter(f => ruleFilter === 'ALL' || f.severity === ruleFilter);

  // ── contradiction severity filter ───────────────────────────────────────────
  const [contFilter, setContFilter] = useState('ALL');
  const filteredCont = contradictions.filter(c => contFilter === 'ALL' || c.severity === contFilter);

  // ────────────────────────────────────────────────────────────────────────────

  return (
    <div style={{ maxWidth: 1160, margin: '0 auto', padding: '24px 16px' }}>

      {/* ── Page Header ──────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24, flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 44, height: 44, borderRadius: 12, background: 'rgba(196,18,48,0.12)', border: '1px solid rgba(196,18,48,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Brain size={22} color="var(--color-primary, #c41230)" />
          </div>
          <div>
            <h1 style={{ margin: 0, fontWeight: 800, fontSize: 20, color: 'var(--text-primary)' }}>Quantum Intelligence</h1>
            <p style={{ margin: '3px 0 0', fontSize: 13, color: 'var(--text-muted)' }}>
              AI-powered posture analysis · Scope: <strong style={{ color: 'var(--color-primary)' }}>{scopeLabel}</strong>
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {groqAvailable && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', background: 'rgba(200,146,42,0.12)', border: '1px solid rgba(200,146,42,0.3)', borderRadius: 99, fontSize: 11, fontWeight: 700, color: '#f5c842' }}>
              <Cpu size={12} />
              Groq LLM Active
            </div>
          )}
          <button
            onClick={loadAll}
            disabled={loading}
            style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '8px 18px', background: 'var(--bg-surface)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 8, color: 'var(--text-primary)', fontWeight: 700, fontSize: 13, cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.6 : 1 }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            {loading ? 'Analyzing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* ── Error State ──────────────────────────────────────────────── */}
      {error && (
        <div style={{ padding: 20, background: 'rgba(255,34,68,0.08)', border: '1px solid rgba(255,34,68,0.25)', borderRadius: 10, marginBottom: 20, color: '#ff5577', fontSize: 14 }}>
          <strong>Analysis Error:</strong> {error}
        </div>
      )}

      {/* ── Posture Overview Strip ────────────────────────────────────── */}
      {loading ? (
        <div style={{ display: 'flex', gap: 16, marginBottom: 20 }}>
          {[1,2,3,4].map(i => (
            <div key={i} style={{ flex: 1, background: 'var(--bg-surface)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 12, padding: '18px 20px' }}>
              <SkeletonLine width="60%" height={12} />
              <SkeletonLine width="40%" height={32} />
            </div>
          ))}
        </div>
      ) : data && (
        <div style={{ display: 'flex', gap: 16, marginBottom: 24, flexWrap: 'wrap' }}>
          <PostureCard
            icon={Shield}
            label="Effective Security Score"
            value={`${effectiveAvg}/100`}
            sub="Avg across scope after cross-layer adjustments"
            color={effectiveColor}
          />
          <PostureCard
            icon={Eye}
            label="HNDL Harvest Windows"
            value={`${harvestOpen} of ${totalAssets}`}
            sub={harvestOpen === 0 ? 'No open windows · good posture' : 'assets with open harvest risk'}
            color={harvestOpen > 0 ? '#ff2244' : '#22c55e'}
          />
          <PostureCard
            icon={Zap}
            label="Rule Engine Alerts"
            value={ruleFindings.length}
            sub={ruleFindings.length === 0 ? 'No cross-layer risks detected' : `${ruleFindings.length} risk amplifiers firing`}
            color={ruleFindings.length > 0 ? '#f59e0b' : '#22c55e'}
          />
          <PostureCard
            icon={Layers}
            label="Layer Contradictions"
            value={contradictions.length}
            sub={contradictions.length === 0 ? 'Architecture is internally consistent' : 'cross-layer conflicts found'}
            color={contradictions.length > 0 ? '#ff2244' : '#22c55e'}
          />
        </div>
      )}

      {/* ── Enterprise Intelligence Summary ──────────────────────────── */}
      {loading ? (
        <div style={{ background: 'var(--bg-surface)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 14, padding: 20, marginBottom: 20 }}>
          <SkeletonLine width="30%" height={14} />
          <SkeletonLine width="100%" height={13} />
          <SkeletonLine width="85%" height={13} />
          <SkeletonLine width="70%" height={13} />
        </div>
      ) : narrative && (
        <Section icon={Brain} title="Enterprise Intelligence Summary" badge={narrative.generated_by === 'GROQ_LLM' ? 'AI-Generated' : 'Rule-Based'} badgeColor={narrative.generated_by === 'GROQ_LLM' ? '#f5c842' : '#60a5fa'} accent="var(--color-primary)">
          <p style={{ margin: '0 0 16px', fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
            {narrative.enterprise_summary}
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 16 }}>
            {narrative.critical_patterns?.length > 0 && (
              <div style={{ padding: 14, background: 'rgba(255,34,68,0.05)', border: '1px solid rgba(255,34,68,0.15)', borderRadius: 8 }}>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#ff5577', marginBottom: 10 }}>
                  Critical Patterns Detected
                </div>
                {narrative.critical_patterns.map((p, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6, fontSize: 13, color: 'var(--text-secondary)' }}>
                    <AlertCircle size={13} color="#ff5577" style={{ flexShrink: 0, marginTop: 2 }} />
                    {p}
                  </div>
                ))}
              </div>
            )}

            {narrative.enterprise_migration_priority?.length > 0 && (
              <div style={{ padding: 14, background: 'rgba(96,165,250,0.05)', border: '1px solid rgba(96,165,250,0.15)', borderRadius: 8 }}>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#60a5fa', marginBottom: 10 }}>
                  Migration Priority Order
                </div>
                {narrative.enterprise_migration_priority.map((h, i) => (
                  <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 6, fontSize: 13, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                    <span style={{ color: '#60a5fa', fontWeight: 700 }}>{i + 1}.</span>
                    {h}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-muted)', textAlign: 'right' }}>
            Generated {new Date(narrative.generated_at || Date.now()).toLocaleString()}
          </div>
        </Section>
      )}

      {/* ── HNDL Threat Matrix ───────────────────────────────────────── */}
      <Section
        icon={ShieldAlert}
        title="HNDL Threat Matrix"
        badge={hndlProfiles.length > 0 ? `${hndlProfiles.length} assets` : null}
        badgeColor="#ff7a00"
        accent="#ff7a00"
      >
        <div style={{ padding: '10px 14px', background: 'rgba(255,122,0,0.06)', border: '1px solid rgba(255,122,0,0.15)', borderRadius: 8, marginBottom: 16, fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          <strong style={{ color: '#ff7a00' }}>What is HNDL?</strong> "Harvest Now, Decrypt Later" — adversaries record encrypted traffic today and will decrypt it once a cryptographically-relevant quantum computer (CRQC) is available, estimated 5–10 years. <strong>Higher score = higher priority target for quantum adversaries. Open harvest window = RSA/classical KEX actively in use.</strong>
        </div>

        {loading ? (
          <><SkeletonLine /><SkeletonLine width="85%" /><SkeletonLine width="70%" /></>
        ) : hndlProfiles.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', fontSize: 13, textAlign: 'center', padding: '20px 0' }}>No HNDL data available. Run scans first.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr>
                  {['Rank', 'Hostname', 'HNDL Score', 'Risk Tier', 'Sensitivity Signals', 'Harvest Window', 'Time to Threat'].map(h => (
                    <th key={h} style={{ padding: '8px 14px', textAlign: 'left', background: 'rgba(255,255,255,0.04)', borderBottom: '1px solid rgba(255,255,255,0.08)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {hndlProfiles.map((item, idx) => (
                  <HNDLRow key={item.asset_hostname || idx} item={item} rank={idx + 1} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      {/* ── Rule Engine Analysis ──────────────────────────────────────── */}
      <Section
        icon={Cpu}
        title="Cross-Layer Rule Engine Analysis"
        badge={ruleFindings.length > 0 ? `${ruleFindings.length} alerts` : 'All Clear'}
        badgeColor={ruleFindings.length > 0 ? '#f59e0b' : '#22c55e'}
        accent={ruleFindings.length > 0 ? '#f59e0b' : '#22c55e'}
      >
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.5 }}>
          8 deterministic cross-layer rules are evaluated against each asset's scan data. These rules detect patterns that individual surface scores miss — such as a strong TLS score masking a missing DNSSEC chain, or incomplete PQC migration that leaves the application layer exposed.
        </p>

        {loading ? (
          <><SkeletonLine /><SkeletonLine width="90%" /><SkeletonLine width="75%" /></>
        ) : ruleFindings.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 16, background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.18)', borderRadius: 8 }}>
            <CheckCircle2 size={22} color="#22c55e" />
            <div>
              <div style={{ fontWeight: 700, fontSize: 14, color: '#22c55e' }}>All 8 rules passed</div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 3 }}>No cross-layer risk amplifiers detected across your scoped assets. Individual surface scores represent the true posture.</div>
            </div>
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(lvl => (
                <button key={lvl} onClick={() => setRuleFilter(lvl)} style={{ padding: '5px 14px', background: ruleFilter === lvl ? `${riskColor(lvl)}22` : 'rgba(255,255,255,0.04)', border: `1px solid ${ruleFilter === lvl ? riskColor(lvl) + '44' : 'rgba(255,255,255,0.1)'}`, borderRadius: 99, color: ruleFilter === lvl ? riskColor(lvl) : 'var(--text-muted)', fontSize: 12, fontWeight: 700, cursor: 'pointer', letterSpacing: '0.04em' }}>
                  {lvl}
                </button>
              ))}
            </div>
            {filteredRules.map((f, i) => <RuleFinding key={i} finding={f} />)}
          </>
        )}

        {!loading && assetAnalyses.length > 0 && (
          <div style={{ marginTop: 16, padding: '10px 14px', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', marginBottom: 10 }}>Effective vs Base Scores</div>
            {assetAnalyses.map(a => {
              const base = a.rule_result?.base_score || 0;
              const eff = a.rule_result?.effective_security_score || 0;
              const diff = eff - base;
              return (
                <div key={a.asset_id} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8, fontSize: 13 }}>
                  <span style={{ fontFamily: 'monospace', minWidth: 200, color: 'var(--text-secondary)' }}>{a.hostname}</span>
                  <span style={{ color: 'var(--text-muted)' }}>Base: <strong style={{ color: 'var(--text-primary)' }}>{base.toFixed(1)}</strong></span>
                  <span style={{ color: 'var(--text-muted)' }}>→</span>
                  <span style={{ color: 'var(--text-muted)' }}>Effective: <strong style={{ color: eff >= 70 ? '#22c55e' : eff >= 40 ? '#f59e0b' : '#ff2244' }}>{eff.toFixed(1)}</strong></span>
                  {diff < 0 && <span style={{ fontSize: 11, fontWeight: 700, color: '#ff2244', background: 'rgba(255,34,68,0.1)', padding: '2px 6px', borderRadius: 4 }}>{diff.toFixed(0)} pts adjusted</span>}
                </div>
              );
            })}
          </div>
        )}
      </Section>

      {/* ── Cross-Layer Contradictions ────────────────────────────────── */}
      <Section
        icon={AlertTriangle}
        title="Cross-Layer Contradictions"
        badge={contradictions.length > 0 ? `${contradictions.length} found` : 'None Detected'}
        badgeColor={contradictions.length > 0 ? '#ff2244' : '#22c55e'}
        accent={contradictions.length > 0 ? '#ff2244' : undefined}
      >
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.5 }}>
          Contradictions occur when individual layer scores suggest safety but the <em>combination</em> of configurations creates a hidden risk — e.g., a high TLS score alongside missing DNSSEC gives a false sense of security. These are often missed by single-surface scanners.
        </p>

        {loading ? (
          <><SkeletonLine /><SkeletonLine width="80%" /></>
        ) : contradictions.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 16, background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.18)', borderRadius: 8 }}>
            <CheckCircle2 size={22} color="#22c55e" />
            <div>
              <div style={{ fontWeight: 700, fontSize: 14, color: '#22c55e' }}>No contradictions detected</div>
              <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 3 }}>Your infrastructure's security layers are internally consistent. All 7 contradiction detectors returned clean for this scope.</div>
            </div>
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(lvl => (
                <button key={lvl} onClick={() => setContFilter(lvl)} style={{ padding: '5px 14px', background: contFilter === lvl ? `${riskColor(lvl)}22` : 'rgba(255,255,255,0.04)', border: `1px solid ${contFilter === lvl ? riskColor(lvl) + '44' : 'rgba(255,255,255,0.1)'}`, borderRadius: 99, color: contFilter === lvl ? riskColor(lvl) : 'var(--text-muted)', fontSize: 12, fontWeight: 700, cursor: 'pointer' }}>
                  {lvl}
                </button>
              ))}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(440px, 1fr))', gap: 12 }}>
              {filteredCont.map((c, i) => <ContradictionCard key={c.contradiction_id || i} c={c} />)}
            </div>
          </>
        )}
      </Section>

      {/* ── Priority Action Plan ──────────────────────────────────────── */}
      <Section
        icon={Zap}
        title="PQC Migration Action Plan"
        badge={actionPlan?.generated_by === 'GROQ_LLM' ? 'AI-Generated' : actionPlan ? 'Rule-Based' : null}
        badgeColor={actionPlan?.generated_by === 'GROQ_LLM' ? '#f5c842' : '#60a5fa'}
      >
        {loading ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
            {[1,2,3].map(i => <div key={i} style={{ height: 120, background: 'rgba(255,255,255,0.04)', borderRadius: 10 }} />)}
          </div>
        ) : (
          <ActionPlan plan={actionPlan} />
        )}
      </Section>

      {/* ── Scan-Over-Scan Anomaly Detection ─────────────────────────── */}
      <Section
        icon={Activity}
        title="Scan-Over-Scan Regression Detection"
        badge={degradations > 0 ? `${degradations} regressions` : hasAnomalyData ? 'No regressions' : null}
        badgeColor={degradations > 0 ? '#ff2244' : '#22c55e'}
        accent={degradations > 0 ? '#ff2244' : undefined}
        defaultOpen={degradations > 0}
      >
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.5 }}>
          Automatically detects when a new scan shows security regression compared to the previous scan — catching sudden protocol downgrades, new vulnerabilities, DNSSEC failures, or HSTS disappearing.
        </p>

        {loading ? (
          <><SkeletonLine /><SkeletonLine width="80%" /></>
        ) : !hasAnomalyData ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 16, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8 }}>
            <Clock size={20} color="var(--text-muted)" />
            <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              Run a second scan on each asset to enable regression detection. Anomaly analysis requires at least 2 scan results per asset.
            </div>
          </div>
        ) : degradations === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 16, background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.18)', borderRadius: 8, marginBottom: 12 }}>
            <CheckCircle2 size={22} color="#22c55e" />
            <div style={{ fontWeight: 700, fontSize: 14, color: '#22c55e' }}>No regressions detected — posture is stable or improving.</div>
          </div>
        ) : null}

        {assetAnalyses.filter(a => a.anomaly).map(a => (
          <AnomalyAlert key={a.asset_id} analysis={a} />
        ))}
      </Section>

      {/* ── Footer ───────────────────────────────────────────────────── */}
      <div style={{ textAlign: 'center', padding: '14px 0', fontSize: 11, color: 'var(--text-muted)', borderTop: '1px solid rgba(255,255,255,0.06)', marginTop: 8 }}>
        {groqAvailable
          ? 'AI analysis powered by Groq LLM (llama-3.3-70b-versatile) · deterministic rule engine always active'
          : 'Running in rule-based mode — set GROQ_API_KEY for LLM-enhanced analysis · start.bat YOUR_GROQ_API_KEY'}
      </div>

    </div>
  );
}
