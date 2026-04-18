import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Loader2, ArrowLeft, Shield, Lock, Globe, FileKey, Activity,
  Server, AlertTriangle, CheckCircle2, XCircle, Clock, Cpu,
  FileText, Wifi, Key, ShieldAlert, Fingerprint, List,
} from 'lucide-react';
import client from '../api/client';
import RiskBadge from '../components/ui/RiskBadge';
import LabelBadge from '../components/ui/LabelBadge';
import styles from './CommonPage.module.css';

// ─── helpers ────────────────────────────────────────────────────────────────

function riskColor(level) {
  const map = {
    CRITICAL: 'var(--risk-critical)',
    HIGH:     'var(--risk-high)',
    MEDIUM:   '#f59e0b',
    LOW:      'var(--risk-low)',
    NONE:     'var(--risk-safe)',
    SAFE:     'var(--risk-safe)',
  };
  return map[level?.toUpperCase()] || 'var(--text-muted)';
}

function SectionCard({ icon: Icon, title, children, accent }) {
  return (
    <section
      className={styles.card}
      style={{ padding: '24px', borderLeft: accent ? `3px solid ${accent}` : undefined }}
    >
      <h3 style={{ fontSize: '16px', color: 'var(--text-primary)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Icon size={18} color="var(--color-primary)" />
        {title}
      </h3>
      {children}
    </section>
  );
}

function Row({ label, value, valueColor, mono }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--border-color)' }}>
      <span style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>{label}</span>
      <span style={{ color: valueColor || 'var(--text-primary)', fontSize: '13px', fontFamily: mono ? 'monospace' : undefined, fontWeight: 500 }}>
        {value ?? '—'}
      </span>
    </div>
  );
}

function ModuleChip({ label, status }) {
  // status: 'ok' | 'warn' | 'skip'
  const cfg = {
    ok:   { color: 'var(--risk-safe)',     bg: 'rgba(34,197,94,0.08)',  icon: CheckCircle2 },
    warn: { color: 'var(--risk-critical)', bg: 'rgba(239,68,68,0.08)', icon: AlertTriangle },
    skip: { color: 'var(--text-muted)',    bg: 'var(--bg-main)',        icon: XCircle },
  }[status] || { color: 'var(--text-muted)', bg: 'var(--bg-main)', icon: XCircle };
  const Ic = cfg.icon;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px', backgroundColor: cfg.bg, border: `1px solid ${cfg.color}22`, borderRadius: '20px', fontSize: '12px', fontWeight: 600, color: cfg.color }}>
      <Ic size={13} />
      {label}
    </div>
  );
}

function ScoreSubBar({ label, score, weight }) {
  const pct = Math.min(100, Math.max(0, score || 0));
  const color = pct >= 70 ? 'var(--risk-safe)' : pct >= 40 ? '#f59e0b' : 'var(--risk-critical)';
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
        <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
        <span style={{ color, fontWeight: 700 }}>{pct.toFixed(0)}<span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>/100</span></span>
      </div>
      <div style={{ height: '5px', backgroundColor: 'var(--bg-main)', borderRadius: '3px', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, backgroundColor: color, transition: 'width 0.4s ease' }} />
      </div>
      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', textAlign: 'right' }}>weight {weight}</div>
    </div>
  );
}

// ─── main component ──────────────────────────────────────────────────────────

export default function ScanDetails() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const res = await client.get(`/scanner/results/${id}`);
        if (res.success) {
          const inner = res.data.scan_data || {};
          setScan({ ...res.data, ...inner });
        }
      } catch (err) {
        console.error('Failed to load scan details', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [id]);

  if (loading) {
    return (
      <div className={styles.page} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Loader2 size={48} className="spin" color="var(--color-primary)" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className={styles.page}>
        <div className={styles.card} style={{ padding: '32px', textAlign: 'center' }}>
          <h2>Scan not found</h2>
          <button onClick={() => navigate(-1)} className={styles.secondaryBadge} style={{ marginTop: '16px' }}>Go Back</button>
        </div>
      </div>
    );
  }

  const {
    target, quantum_score, vulnerabilities, ciphers, tls_versions, cbom,
    ssh_result, dnssec_result, headers_result, ct_log_result, jwt_result, quic_result,
    subdomains, attack_surface_rating, label, certificate, key_exchange,
    scan_status, scan_duration_seconds, is_mock, negotiated_tls_version,
  } = scan;

  // Module coverage status
  const modules = [
    { label: 'TLS',         status: tls_versions?.length ? 'ok' : 'skip' },
    { label: 'Certificate', status: certificate ? (certificate.is_expired ? 'warn' : 'ok') : 'skip' },
    { label: 'Ciphers',     status: ciphers?.length ? (ciphers.some(c => c.quantum_risk === 'CRITICAL' || c.quantum_risk === 'HIGH') ? 'warn' : 'ok') : 'skip' },
    { label: 'SSH',         status: ssh_result ? (ssh_result.error ? 'skip' : (ssh_result.overall_risk === 'CRITICAL' ? 'warn' : 'ok')) : 'skip' },
    { label: 'DNSSEC',      status: dnssec_result ? (dnssec_result.enabled ? 'ok' : 'warn') : 'skip' },
    { label: 'Sec Headers', status: headers_result ? (headers_result.security_score >= 60 ? 'ok' : 'warn') : 'skip' },
    { label: 'Subdomains',  status: subdomains?.length ? 'ok' : 'skip' },
    { label: 'CT Logs',     status: ct_log_result ? (ct_log_result.flagged ? 'warn' : 'ok') : 'skip' },
    { label: 'JWT',         status: jwt_result ? (jwt_result.overall_risk === 'CRITICAL' ? 'warn' : 'ok') : 'skip' },
    { label: 'QUIC/HTTP3',  status: quic_result ? (quic_result.flagged ? 'warn' : 'ok') : 'skip' },
  ];

  const overallScore = quantum_score?.overall_score ?? 0;
  const scoreColor = overallScore >= 70 ? 'var(--risk-safe)' : overallScore >= 40 ? '#f59e0b' : 'var(--risk-critical)';

  return (
    <div className={styles.page}>

      {/* ── Header ────────────────────────────────────────────────────── */}
      <div className={styles.pageHeader}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button
            onClick={() => navigate(-1)}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '8px' }}
          >
            <ArrowLeft size={22} />
          </button>
          <div>
            <h2 className={styles.title} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <Server size={22} color="var(--color-primary)" />
              {target?.hostname}
              <span style={{ color: 'var(--text-muted)', fontSize: '16px', fontWeight: 400 }}>:{target?.port}</span>
              {is_mock && (
                <span style={{ fontSize: '11px', padding: '2px 8px', background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: '12px', color: '#f59e0b', fontWeight: 700 }}>
                  MOCK
                </span>
              )}
            </h2>
            <p className={styles.subtitle} style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Clock size={12} /> {new Date(scan.scan_timestamp || scan.started_at).toLocaleString()}
              </span>
              {scan_duration_seconds > 0 && (
                <span style={{ color: 'var(--text-muted)' }}>· {scan_duration_seconds.toFixed(1)}s scan</span>
              )}
              <span style={{
                padding: '2px 8px', borderRadius: '10px', fontSize: '11px', fontWeight: 700,
                background: scan_status === 'SUCCESS' ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                color: scan_status === 'SUCCESS' ? 'var(--risk-safe)' : 'var(--risk-critical)',
              }}>
                {scan_status}
              </span>
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Quantum Score</span>
            <span style={{ fontSize: '28px', fontWeight: 800, color: scoreColor, lineHeight: 1.1 }}>
              {overallScore.toFixed(1)}
            </span>
            {quantum_score?.grade && (
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Grade {quantum_score.grade}</span>
            )}
          </div>
          <RiskBadge level={attack_surface_rating} />
          <LabelBadge label={label || scan.scan_status} />
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

        {/* ── Module Coverage ────────────────────────────────────────── */}
        <div className={styles.card} style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '13px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: '14px', fontWeight: 700 }}>
            Scan Coverage — {modules.filter(m => m.status !== 'skip').length} of {modules.length} modules executed
          </h3>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {modules.map(m => <ModuleChip key={m.label} label={m.label} status={m.status} />)}
          </div>
        </div>

        {/* ── Quantum Score Breakdown ────────────────────────────────── */}
        {quantum_score && (
          <SectionCard icon={Cpu} title="Quantum Safety Score Breakdown">
            <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0 40px', alignItems: 'start' }}>
              {/* Big score circle */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', paddingRight: '24px', borderRight: '1px solid var(--border-color)' }}>
                <div style={{
                  width: 100, height: 100, borderRadius: '50%',
                  background: `conic-gradient(${scoreColor} ${overallScore * 3.6}deg, var(--bg-main) 0deg)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <div style={{ width: 78, height: 78, borderRadius: '50%', background: 'var(--bg-surface)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: '22px', fontWeight: 800, color: scoreColor, lineHeight: 1 }}>{overallScore.toFixed(0)}</span>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>/100</span>
                  </div>
                </div>
                <span style={{ fontSize: '11px', fontWeight: 700, color: scoreColor }}>{quantum_score.tier?.replace('_', ' ')}</span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Cyber Rating: <strong style={{ color: 'var(--text-primary)' }}>{quantum_score.cyber_rating?.toFixed(0)}</strong>/1000</span>
              </div>

              {/* Sub-scores */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', paddingLeft: '8px' }}>
                <ScoreSubBar label="TLS Version Quality" score={quantum_score.tls_version_score} weight="20%" />
                <ScoreSubBar label="Cipher Suite Strength" score={quantum_score.cipher_quality_score} weight="25%" />
                <ScoreSubBar label="Certificate Strength" score={quantum_score.certificate_strength_score} weight="25%" />
                <ScoreSubBar label="Key Exchange Security" score={quantum_score.key_exchange_score} weight="30%" />
                {quantum_score.summary && (
                  <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5', borderTop: '1px solid var(--border-color)', paddingTop: '10px' }}>
                    {quantum_score.summary}
                  </p>
                )}
              </div>
            </div>
          </SectionCard>
        )}

        {/* ── TLS Versions & Cipher Suites ──────────────────────────── */}
        <SectionCard icon={Lock} title="TLS Versions & Cipher Suites">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '24px' }}>
            {/* TLS Versions */}
            <div>
              <h4 style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '10px', fontWeight: 700 }}>Supported Versions</h4>
              {negotiated_tls_version && (
                <div style={{ marginBottom: '10px', padding: '8px 12px', background: 'rgba(34,197,94,0.08)', borderRadius: '6px', fontSize: '12px', color: 'var(--risk-safe)' }}>
                  Negotiated: <strong>{negotiated_tls_version}</strong>
                </div>
              )}
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {(tls_versions || []).map(v => (
                  <li key={v.version} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px' }}>
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>{v.version}</span>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: v.supported ? (v.is_insecure ? 'var(--risk-critical)' : 'var(--risk-safe)') : 'var(--text-muted)' }}>
                      {v.supported ? (v.is_insecure ? 'Insecure' : 'Supported') : 'Disabled'}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Ciphers */}
            <div>
              <h4 style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '10px', fontWeight: 700 }}>Negotiated Cipher Suites</h4>
              {(ciphers || []).length === 0 ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No cipher data collected.</p>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                    <thead>
                      <tr style={{ color: 'var(--text-muted)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                        <th style={{ padding: '6px 8px', fontWeight: 700 }}>Cipher Suite</th>
                        <th style={{ padding: '6px 8px', fontWeight: 700 }}>Key Ex.</th>
                        <th style={{ padding: '6px 8px', fontWeight: 700 }}>Auth</th>
                        <th style={{ padding: '6px 8px', fontWeight: 700 }}>FS</th>
                        <th style={{ padding: '6px 8px', fontWeight: 700 }}>Q-Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(ciphers || []).map((c, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--bg-main)' }}>
                          <td style={{ padding: '8px', color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: '11px' }}>{c.iana_name}</td>
                          <td style={{ padding: '8px', color: 'var(--text-secondary)' }}>{c.key_exchange}</td>
                          <td style={{ padding: '8px', color: 'var(--text-secondary)' }}>{c.authentication || '—'}</td>
                          <td style={{ padding: '8px', color: c.is_forward_secret ? 'var(--risk-safe)' : 'var(--text-muted)', fontSize: '11px', fontWeight: 600 }}>
                            {c.is_forward_secret ? 'Yes' : 'No'}
                          </td>
                          <td style={{ padding: '8px' }}><RiskBadge level={c.quantum_risk} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </SectionCard>

        {/* ── Certificate Details ────────────────────────────────────── */}
        {certificate ? (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            <SectionCard icon={Fingerprint} title="TLS Certificate" accent={certificate.is_expired ? 'var(--risk-critical)' : undefined}>
              <Row label="Subject (CN)" value={certificate.subject_cn} mono />
              <Row label="Issuer" value={certificate.issuer_cn} />
              <Row label="Signature Algorithm" value={certificate.signature_algorithm} mono />
              <Row label="Public Key" value={certificate.public_key_algorithm ? `${certificate.public_key_algorithm} ${certificate.public_key_size}‑bit` : undefined} mono />
              <Row label="Not Before" value={certificate.not_before ? new Date(certificate.not_before).toLocaleDateString() : '—'} />
              <Row
                label="Expires"
                value={certificate.not_after ? new Date(certificate.not_after).toLocaleDateString() : '—'}
                valueColor={certificate.is_expired ? 'var(--risk-critical)' : undefined}
              />
              <Row label="Status" value={certificate.is_expired ? 'EXPIRED' : 'Valid'} valueColor={certificate.is_expired ? 'var(--risk-critical)' : 'var(--risk-safe)'} />
              <Row label="Self-Signed" value={certificate.is_self_signed ? 'Yes' : 'No'} valueColor={certificate.is_self_signed ? 'var(--risk-critical)' : undefined} />
              <Row label="Chain Valid" value={certificate.chain_valid ? 'Yes' : 'No'} valueColor={certificate.chain_valid ? 'var(--risk-safe)' : 'var(--risk-critical)'} />
              <Row label="Quantum Safe Cert" value={certificate.is_quantum_safe_cert ? 'Yes' : 'No'} valueColor={certificate.is_quantum_safe_cert ? 'var(--risk-safe)' : 'var(--text-muted)'} />
              {certificate.san_entries?.length > 0 && (
                <div style={{ marginTop: '10px' }}>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>SANs ({certificate.san_entries.length})</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {certificate.san_entries.slice(0, 8).map((s, i) => (
                      <span key={i} style={{ padding: '2px 8px', background: 'var(--bg-main)', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace' }}>{s}</span>
                    ))}
                    {certificate.san_entries.length > 8 && (
                      <span style={{ padding: '2px 8px', color: 'var(--text-muted)', fontSize: '11px' }}>+{certificate.san_entries.length - 8} more</span>
                    )}
                  </div>
                </div>
              )}
            </SectionCard>

            {/* Key Exchange */}
            <SectionCard icon={Key} title="Key Exchange Assessment">
              {key_exchange ? (
                <>
                  <Row label="Algorithm" value={key_exchange.algorithm} mono />
                  <Row label="Key Size" value={key_exchange.key_size ? `${key_exchange.key_size}-bit` : '—'} />
                  <Row label="Post-Quantum" value={key_exchange.is_post_quantum ? 'Yes' : 'No'} valueColor={key_exchange.is_post_quantum ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                  <Row label="Quantum Risk" value={key_exchange.quantum_risk} valueColor={riskColor(key_exchange.quantum_risk)} />
                  {key_exchange.nist_standard && <Row label="NIST Standard" value={key_exchange.nist_standard} mono />}
                  {key_exchange.notes && (
                    <p style={{ marginTop: '10px', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5', padding: '10px', background: 'var(--bg-main)', borderRadius: '6px' }}>
                      {key_exchange.notes}
                    </p>
                  )}
                </>
              ) : (
                <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Key exchange data not collected.</p>
              )}
            </SectionCard>
          </div>
        ) : null}

        {/* ── Vulnerabilities ────────────────────────────────────────── */}
        {(vulnerabilities || []).length > 0 && (
          <SectionCard icon={AlertTriangle} title={`Vulnerabilities Detected (${vulnerabilities.length})`} accent="var(--risk-critical)">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {vulnerabilities.map((v, i) => (
                <div key={i} style={{ padding: '14px', backgroundColor: 'var(--bg-main)', borderRadius: '8px', borderLeft: `3px solid ${riskColor(v.severity)}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-muted)', background: 'var(--bg-surface)', padding: '2px 6px', borderRadius: '4px' }}>{v.id}</span>
                      <span style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)' }}>{v.title}</span>
                    </div>
                    <RiskBadge level={v.severity} />
                  </div>
                  <p style={{ margin: '0 0 6px', fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>{v.description}</p>
                  {v.affected_component && (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                      Affected: <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{v.affected_component}</span>
                    </div>
                  )}
                  {v.recommendation && (
                    <div style={{ marginTop: '8px', fontSize: '12px', padding: '8px', background: 'rgba(34,197,94,0.06)', borderRadius: '4px', color: 'var(--risk-safe)' }}>
                      Recommendation: {v.recommendation}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </SectionCard>
        )}

        {/* ── CBOM ───────────────────────────────────────────────────── */}
        {(cbom || []).length > 0 && (
          <SectionCard icon={List} title={`Cryptographic Bill of Materials (${cbom.length} entries)`}>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                <thead>
                  <tr style={{ color: 'var(--text-muted)', textAlign: 'left', borderBottom: '1px solid var(--border-color)' }}>
                    {['ID', 'Type', 'Algorithm', 'Key Size', 'Q-Risk', 'Priority', 'Replacement', 'NIST'].map(h => (
                      <th key={h} style={{ padding: '6px 10px', fontWeight: 700, fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {cbom.map((e, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--bg-main)' }}>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: '11px' }}>{e.entry_id}</td>
                      <td style={{ padding: '8px 10px', color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '11px' }}>{e.component_type}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: 'var(--text-primary)', fontWeight: 600 }}>{e.name}</td>
                      <td style={{ padding: '8px 10px', color: 'var(--text-secondary)' }}>{e.key_size ? `${e.key_size}-bit` : '—'}</td>
                      <td style={{ padding: '8px 10px' }}><RiskBadge level={e.quantum_risk} /></td>
                      <td style={{ padding: '8px 10px', fontWeight: 600, fontSize: '11px', color: riskColor(e.migration_priority === 'IMMEDIATE' ? 'CRITICAL' : e.migration_priority === 'HIGH' ? 'HIGH' : 'MEDIUM') }}>{e.migration_priority}</td>
                      <td style={{ padding: '8px 10px', color: 'var(--risk-safe)', fontSize: '11px' }}>{e.recommended_replacement || '—'}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontSize: '11px', color: 'var(--text-muted)' }}>{e.nist_fips_standard || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SectionCard>
        )}

        {/* ── Security Surfaces Grid ─────────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: '20px' }}>

          {/* Security Headers */}
          <SectionCard icon={Shield} title="Security Headers">
            {headers_result ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
                <Row label="HSTS Enabled" value={headers_result.hsts_enabled ? 'Yes' : 'No'} valueColor={headers_result.hsts_enabled ? 'var(--risk-safe)' : 'var(--risk-critical)'} />
                {headers_result.hsts_max_age > 0 && (
                  <Row label="HSTS Max-Age" value={`${headers_result.hsts_max_age}s`} />
                )}
                <Row label="CSP Present" value={headers_result.csp_present ? 'Yes' : 'No'} valueColor={headers_result.csp_present ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                <Row label="Security Score" value={`${headers_result.security_score}/100`} valueColor={headers_result.security_score >= 60 ? 'var(--risk-safe)' : 'var(--risk-critical)'} />
                <div style={{ marginTop: '12px' }}>
                  {headers_result.headers_checked?.map((h, i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', margin: '4px 0', backgroundColor: h.present ? 'var(--bg-main)' : 'rgba(239,68,68,0.05)', borderRadius: '6px', borderLeft: `2px solid ${h.present ? 'transparent' : 'var(--risk-critical)'}` }}>
                      <span style={{ color: 'var(--text-primary)', fontSize: '13px' }}>{h.header_name}</span>
                      <span style={{ color: h.present ? 'var(--risk-safe)' : 'var(--text-muted)', fontSize: '12px', fontWeight: 600 }}>{h.present ? 'Present' : 'Missing'}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Header scan skipped or failed.</p>
            )}
          </SectionCard>

          {/* DNSSEC */}
          <SectionCard icon={Activity} title="DNS & DNSSEC">
            {dnssec_result ? (
              <>
                <Row label="DNSSEC Enabled" value={dnssec_result.enabled ? 'Yes' : 'No'} valueColor={dnssec_result.enabled ? 'var(--risk-safe)' : 'var(--risk-high)'} />
                <Row label="Chain Valid" value={dnssec_result.chain_valid ? 'Yes' : 'No'} valueColor={dnssec_result.chain_valid ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                <Row label="DS Record Found" value={dnssec_result.ds_record_found ? 'Yes' : 'No'} valueColor={dnssec_result.ds_record_found ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                <Row label="RRSIG Found" value={dnssec_result.rrsig_found ? 'Yes' : 'No'} valueColor={dnssec_result.rrsig_found ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                {dnssec_result.dnskey_algorithm && (
                  <Row label="DNSKEY Algorithm" value={dnssec_result.dnskey_algorithm} mono />
                )}
                <Row label="Algorithm Safe" value={dnssec_result.dnskey_algorithm_safe ? 'Yes' : 'No'} valueColor={dnssec_result.dnskey_algorithm_safe ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                <Row label="Quantum Risk" value={dnssec_result.quantum_risk} valueColor={riskColor(dnssec_result.quantum_risk)} />
                {dnssec_result.notes && (
                  <p style={{ marginTop: '10px', fontSize: '12px', color: 'var(--text-secondary)', padding: '8px', background: 'var(--bg-main)', borderRadius: '6px' }}>{dnssec_result.notes}</p>
                )}
              </>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>DNSSEC analysis unavailable.</p>
            )}
          </SectionCard>

          {/* SSH */}
          <SectionCard icon={FileKey} title="SSH Risk Analysis">
            {ssh_result ? (
              ssh_result.error ? (
                <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>{ssh_result.error}</p>
              ) : (
                <>
                  {ssh_result.server_banner && <Row label="Server Banner" value={ssh_result.server_banner} mono />}
                  <Row label="Overall Risk" value={ssh_result.overall_risk} valueColor={riskColor(ssh_result.overall_risk)} />
                  {ssh_result.kex_algorithms?.length > 0 && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        KEX Algorithms ({ssh_result.kex_algorithms.length})
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {ssh_result.kex_algorithms.map((k, i) => (
                          <span key={i} style={{ padding: '4px 8px', backgroundColor: 'var(--bg-main)', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace', borderLeft: `2px solid ${k.quantum_risk === 'CRITICAL' || k.quantum_risk === 'HIGH' ? 'var(--risk-critical)' : 'transparent'}` }}>
                            {k.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {ssh_result.host_key_algorithms?.length > 0 && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        Host Key Algorithms
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                        {ssh_result.host_key_algorithms.map((k, i) => (
                          <span key={i} style={{ padding: '4px 8px', backgroundColor: 'var(--bg-main)', borderRadius: '4px', fontSize: '11px', fontFamily: 'monospace' }}>
                            {k.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No SSH service detected on this host.</p>
            )}
          </SectionCard>

          {/* CT Logs */}
          <SectionCard icon={FileText} title="Certificate Transparency Logs">
            {ct_log_result ? (
              <>
                <Row label="Certs Found in CT" value={ct_log_result.total_certs_found} />
                <Row label="Recent Issuances (30d)" value={ct_log_result.recent_certs_count} valueColor={ct_log_result.recent_certs_count > 3 ? '#f59e0b' : undefined} />
                <Row label="Unexpected CAs" value={ct_log_result.unexpected_cas?.length || 0} valueColor={ct_log_result.unexpected_cas?.length ? 'var(--risk-critical)' : 'var(--risk-safe)'} />
                <Row label="Flagged" value={ct_log_result.flagged ? 'Yes' : 'No'} valueColor={ct_log_result.flagged ? 'var(--risk-critical)' : 'var(--risk-safe)'} />
                {ct_log_result.flag_reason && (
                  <div style={{ marginTop: '10px', padding: '10px', background: 'rgba(239,68,68,0.06)', borderRadius: '6px', fontSize: '12px', color: 'var(--risk-critical)' }}>
                    {ct_log_result.flag_reason}
                  </div>
                )}
                {ct_log_result.cert_history?.length > 0 && (
                  <div style={{ marginTop: '12px' }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Recent Issuances</div>
                    {ct_log_result.cert_history.slice(0, 4).map((c, i) => (
                      <div key={i} style={{ padding: '8px', background: 'var(--bg-main)', borderRadius: '5px', marginBottom: '4px', fontSize: '12px' }}>
                        <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{c.issuer_cn}</span>
                        <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>{c.not_before?.slice(0, 10)} → {c.not_after?.slice(0, 10)}</span>
                        {c.is_unexpected_ca && <span style={{ marginLeft: '8px', color: 'var(--risk-critical)', fontSize: '11px', fontWeight: 700 }}>UNEXPECTED CA</span>}
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>CT log check not performed.</p>
            )}
          </SectionCard>

          {/* JWT */}
          <SectionCard icon={ShieldAlert} title="JWT & Auth Token Detection">
            {jwt_result ? (
              <>
                <Row label="Overall Risk" value={jwt_result.overall_risk} valueColor={riskColor(jwt_result.overall_risk)} />
                <Row label="JWTs Found" value={jwt_result.jwts_found?.length || 0} />
                {jwt_result.jwts_found?.length > 0 && (
                  <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {jwt_result.jwts_found.map((j, i) => (
                      <div key={i} style={{ padding: '10px', background: 'var(--bg-main)', borderRadius: '6px', borderLeft: `2px solid ${riskColor(j.quantum_risk)}` }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontFamily: 'monospace', fontSize: '12px', color: 'var(--text-primary)', fontWeight: 700 }}>{j.algorithm}</span>
                          <RiskBadge level={j.quantum_risk} />
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Source: {j.source}</div>
                        {j.notes && <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>{j.notes}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No JWT tokens detected.</p>
            )}
          </SectionCard>

          {/* QUIC */}
          <SectionCard icon={Wifi} title="QUIC / HTTP3 Detection">
            {quic_result ? (
              <>
                <Row label="HTTP/3 Advertised" value={quic_result.h3_advertised ? 'Yes' : 'No'} valueColor={quic_result.h3_advertised ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                <Row label="QUIC UDP Detected" value={quic_result.quic_detected_udp ? 'Yes' : 'No'} valueColor={quic_result.quic_detected_udp ? 'var(--risk-safe)' : 'var(--text-muted)'} />
                <Row label="Flagged (missed surface)" value={quic_result.flagged ? 'Yes' : 'No'} valueColor={quic_result.flagged ? 'var(--risk-critical)' : 'var(--risk-safe)'} />
                {quic_result.alt_svc_value && <Row label="Alt-Svc" value={quic_result.alt_svc_value} mono />}
                {quic_result.versions_advertised?.length > 0 && (
                  <div style={{ marginTop: '10px' }}>
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '6px' }}>Versions Advertised</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {quic_result.versions_advertised.map((v, i) => (
                        <span key={i} style={{ padding: '3px 8px', background: 'var(--bg-main)', borderRadius: '4px', fontFamily: 'monospace', fontSize: '11px' }}>{v}</span>
                      ))}
                    </div>
                  </div>
                )}
                {quic_result.notes && <p style={{ marginTop: '8px', fontSize: '12px', color: 'var(--text-secondary)', padding: '8px', background: 'var(--bg-main)', borderRadius: '6px' }}>{quic_result.notes}</p>}
              </>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>QUIC/HTTP3 probe not performed.</p>
            )}
          </SectionCard>

        </div>

        {/* ── Subdomains ──────────────────────────────────────────────── */}
        <SectionCard icon={Globe} title={`Subdomain Discovery${subdomains?.length ? ` (${subdomains.length} found)` : ''}`}>
          {(subdomains || []).length === 0 ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No subdomains discovered.</p>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '8px', maxHeight: '320px', overflowY: 'auto' }}>
              {subdomains.map((s, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 12px', backgroundColor: 'var(--bg-main)', borderRadius: '6px' }}>
                  <div>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>{s.subdomain}</span>
                    {s.ip_address && <span style={{ marginLeft: '8px', color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'monospace' }}>{s.ip_address}</span>}
                    {s.source && <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>via {s.source}</div>}
                  </div>
                  <div style={{ display: 'flex', gap: '4px' }}>
                    {s.is_live && <span style={{ color: 'var(--risk-safe)', fontSize: '11px', padding: '2px 6px', background: 'rgba(34,197,94,0.1)', borderRadius: '4px', fontWeight: 700 }}>LIVE</span>}
                    {s.tls_weak && <span style={{ color: 'var(--risk-critical)', fontSize: '11px', padding: '2px 6px', background: 'rgba(239,68,68,0.1)', borderRadius: '4px', fontWeight: 700 }}>WEAK TLS</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </SectionCard>

      </div>
    </div>
  );
}
