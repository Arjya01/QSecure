import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Server, Database, AlertCircle, ShieldEllipsis, Loader2, Play, Search } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line,
} from 'recharts';
import client from '../api/client';
import StatCard from '../components/ui/StatCard';
import LabelBadge from '../components/ui/LabelBadge';
import RiskBadge from '../components/ui/RiskBadge';
import ExplanationPopover from '../components/ui/ExplanationPopover';
import useDomainStore from '../store/domainStore';
import { getScopeLabel, getScopeQuery } from '../utils/scope';
import styles from './Dashboard.module.css';

const SCAN_STEPS = [
  'Initializing quantum assessment engine...',
  'Negotiating TLS handshakes (v1.0 - v1.3)...',
  'Extracting Cryptographic Bill of Materials (CBOM)...',
  'Checking SSH host keys & KEX algorithms...',
  'Enumerating Subdomains & Passive OSINT...',
  'Analyzing DNSSEC signatures...',
  'Detecting JWTs & verifying signature algorithms...',
  'Probing HTTP/3 QUIC support...',
  'Evaluating HTTP Security Headers & HSTS...',
  'Analyzing Certificate Transparency (CT) Logs...',
  'Computing Enoki Quantum Vulnerability Score...',
  'Finalizing assessment...',
];

function ScanProgressTracker({ target }) {
  const [stepIndex, setStepIndex] = useState(0);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress(current => current >= 99 ? 99 : current + 1);
    }, 150);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const stepInterval = setInterval(() => {
      setStepIndex(index => index >= SCAN_STEPS.length - 1 ? index : index + 1);
    }, 1200);
    return () => clearInterval(stepInterval);
  }, []);

  return (
    <div style={{ padding: 16, backgroundColor: 'var(--bg-surface-elevated)', borderRadius: 8, border: '1px solid var(--border-color)', width: '100%', marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 13 }}>
        <span style={{ color: 'var(--color-primary)', fontWeight: 600 }}>Scanning: {target}</span>
        <span style={{ color: 'var(--text-primary)' }}>{progress}%</span>
      </div>
      <div style={{ width: '100%', height: 6, backgroundColor: 'var(--bg-main)', borderRadius: 3, overflow: 'hidden', marginBottom: 12 }}>
        <div style={{ height: '100%', width: `${progress}%`, backgroundColor: 'var(--color-primary)', transition: 'width 0.15s linear' }} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text-secondary)' }}>
        <Loader2 size={14} className="spin" color="var(--color-primary)" />
        <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{SCAN_STEPS[stepIndex]}</span>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const { activeScope } = useDomainStore();
  const scopeQuery = useMemo(() => getScopeQuery(activeScope), [activeScope]);
  const scopeLabel = getScopeLabel(activeScope);

  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState(null);
  const [ratingData, setRatingData] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [scanHost, setScanHost] = useState('');
  const [aiInsight, setAiInsight] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [groqAvailable, setGroqAvailable] = useState(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [sumRes, ratRes, scanRes] = await Promise.all([
          client.get(`/dashboard/summary${scopeQuery}`),
          client.get(`/dashboard/cyber-rating${scopeQuery}`),
          client.get(`/dashboard/recent-scans${scopeQuery}`),
        ]);

        if (sumRes.success) setSummary(sumRes.data);
        if (ratRes.success) setRatingData(ratRes.data);
        if (scanRes.success) setRecentScans(scanRes.data);

        client.get(`/dashboard/ai-insight${scopeQuery}`)
          .then(res => {
            if (res.success) {
              setAiInsight(res.data);
              setGroqAvailable(res.data?.generated_by === 'GROQ_LLM');
            }
          })
          .catch(err => console.error(err));
      } catch (err) {
        console.error('Failed to load dashboard data', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [scopeQuery]);

  const handleQuickScan = async (e) => {
    e.preventDefault();
    if (!scanHost) return;
    setScanning(true);
    try {
      const res = await client.post('/scanner/quick-scan', { hostname: scanHost });
      if (res.success && typeof res.data?.id === 'number') {
        navigate(`/scan/${res.data.id}`);
        return;
      }
      setScanHost('');
    } catch (err) {
      const msg = err.code === 'ECONNABORTED'
        ? 'Scan timed out. The backend may be unreachable or the scan is taking too long.'
        : err.response?.data?.error || err.message || 'Network error - is the backend running?';
      alert(`Scan failed: ${msg}`);
    } finally {
      setScanning(false);
    }
  };

  if (loading) {
    return <div className={styles.loader}><Loader2 size={32} className="spin" /></div>;
  }

  const isEmpty = summary?.total_assets === 0;
  if (isEmpty) {
    return (
      <div className={styles.dashboard} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
        <div className={styles.card} style={{ textAlign: 'center', padding: 64, maxWidth: 600, width: '100%' }}>
          <ShieldEllipsis size={64} color="var(--text-muted)" style={{ margin: '0 auto 24px' }} />
          <h2 style={{ fontSize: 24, color: 'var(--text-primary)', marginBottom: 16 }}>Welcome to Q-Secure</h2>
          <p style={{ color: 'var(--text-secondary)', marginBottom: 32, lineHeight: '1.6' }}>
            Your Quantum Security Posture dashboard is currently empty. Enter a hostname below to run your first depth scan and start building your quantum readiness picture.
          </p>

          {scanning ? (
            <div style={{ maxWidth: 400, margin: '0 auto' }}>
              <ScanProgressTracker target={scanHost} />
            </div>
          ) : (
            <form onSubmit={handleQuickScan} className={styles.quickScanForm} style={{ justifyContent: 'center', marginBottom: 32 }}>
              <input
                type="text"
                placeholder="hostname or IP (e.g. google.com)"
                value={scanHost}
                onChange={e => setScanHost(e.target.value)}
                className={styles.quickScanInput}
                style={{ maxWidth: 300 }}
              />
              <button type="submit" disabled={!scanHost} className={styles.quickScanBtn} style={{ padding: '0 24px', fontSize: '15px' }}>
                <Search size={18} />
                Run Depth Scan
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  const riskChartData = summary ? [
    { name: 'CRITICAL', count: summary.risk_distribution.CRITICAL || 0, fill: 'var(--risk-critical)' },
    { name: 'LARGE', count: summary.risk_distribution.LARGE || 0, fill: 'var(--risk-high)' },
    { name: 'MODERATE', count: summary.risk_distribution.MODERATE || 0, fill: 'var(--risk-medium)' },
    { name: 'MINIMAL', count: summary.risk_distribution.MINIMAL || 0, fill: 'var(--risk-safe)' },
  ] : [];

  return (
    <div className={styles.dashboard}>
      <div className="tour-explanations">
        <h2 style={{ margin: 0, color: 'var(--text-primary)', display: 'inline-flex', alignItems: 'center' }}>
          Dashboard
          <ExplanationPopover 
            title="Dashboard Overview"
            what="A high-level summary of your organization's cryptographic posture."
            why="Provides immediate visibility into vulnerabilities and overall readiness for Post-Quantum Cryptography."
            relevance="Aggregates data across all scanned domains to compute enterprise-wide metrics."
            articles={[ { title: 'NIST PQC Migration Guidelines', url: 'https://csrc.nist.gov/projects/post-quantum-cryptography' } ]}
          />
        </h2>
        <p style={{ margin: '8px 0 0', color: 'var(--text-secondary)' }}>
          Active scope: <strong style={{ color: 'var(--color-primary)' }}>{scopeLabel}</strong>
        </p>
      </div>

      <div style={{ padding: '16px 20px', background: 'rgba(139, 92, 246, 0.05)', border: '1px solid rgba(139, 92, 246, 0.2)', borderRadius: '8px', color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: '1.5' }}>
        <strong style={{ color: 'var(--color-primary)', display: 'block', marginBottom: '4px', fontSize: '1rem' }}>The Quantum Threat</strong>
        Quantum computers possess the computational power to break modern public-key cryptography (like RSA and ECC) using Shor's Algorithm. QSecure prepares your infrastructure for the NIST Post-Quantum Cryptography transition by deeply scanning your digital attack surface. We identify vulnerable algorithms, certificates, and TLS configurations that need migration to quantum-safe alternatives.
      </div>

      <div className={styles.statsGrid}>
        <div className="tour-pqc-readiness"><StatCard title="Assets In Scope" value={summary?.total_assets || 0} icon={Server} /></div>
        <StatCard title="Assets Scanned" value={summary?.assets_scanned || 0} icon={Database} />
        <StatCard title="Critical Risk Assets" value={summary?.critical_risk_assets || 0} icon={AlertCircle} />
        <div className="tour-cyber-rating">
          <StatCard
            title="Cyber Rating"
            value={summary?.enterprise_cyber_rating?.score || 0}
            subtitle={`Tier: ${summary?.enterprise_cyber_rating?.tier || 'UNKNOWN'}`}
            icon={ShieldEllipsis}
          />
        </div>
      </div>

      <div className={styles.mainGrid}>
        <div className={styles.leftCol}>
          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle} style={{ display: 'inline-flex', alignItems: 'center' }}>
                Risk Distribution
                <ExplanationPopover 
                  title="Risk Surface Distribution"
                  what="Categorizes identified cryptographic risks across your scanned assets by severity."
                  why="Helps prioritize remediation efforts by highlighting CRITICAL and LARGE vulnerabilities."
                  relevance="Essential for tactical triage of TLS, SSH, and certificate misconfigurations."
                />
              </h2>
            </div>
            <div className={styles.chartWrapper}>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={riskChartData} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal vertical={false} stroke="var(--border-color)" />
                  <XAxis type="number" stroke="var(--text-muted)" fontSize={12} />
                  <YAxis dataKey="name" type="category" stroke="var(--text-muted)" fontSize={12} width={80} />
                  <Tooltip
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                    contentStyle={{ backgroundColor: 'var(--bg-surface-elevated)', borderColor: 'var(--border-color)', borderRadius: 8 }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={32} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Cyber Rating Trend</h2>
            </div>
            <div className={styles.chartWrapper}>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={ratingData?.trend || []} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-color)" />
                  <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={12} tickFormatter={value => value.split('-').slice(1).join('/')} />
                  <YAxis domain={['auto', 'auto']} stroke="var(--text-muted)" fontSize={12} />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--bg-surface-elevated)', borderColor: 'var(--border-color)', borderRadius: 8 }} />
                  <Line type="monotone" dataKey="score" stroke="var(--color-primary)" strokeWidth={2} dot={false} activeDot={{ r: 6 }} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className={styles.rightCol}>
          <div className={styles.card} style={{ border: `1px solid ${groqAvailable ? 'var(--color-primary)' : 'var(--border-color)'}` }}>
            <div className={styles.cardHeader} style={{ borderBottom: '1px solid rgba(37, 99, 235, 0.12)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <h2 className={styles.cardTitle} style={{ color: groqAvailable ? 'var(--color-primary)' : 'var(--text-primary)' }}>Enoki AI Insight</h2>
              {groqAvailable === false && aiInsight !== null && (
                <span style={{ fontSize: 11, padding: '2px 8px', background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: 999, color: '#fbbf24', fontWeight: 600 }}>
                  RULE-BASED
                </span>
              )}
              {groqAvailable === true && (
                <span style={{ fontSize: 11, padding: '2px 8px', background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: 999, color: '#4ade80', fontWeight: 600 }}>
                  AI ACTIVE
                </span>
              )}
            </div>
            <div style={{ padding: 20, fontSize: 14, lineHeight: '1.6', color: 'var(--text-secondary)' }}>
              {aiInsight === null ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Loader2 size={16} className="spin" color="var(--color-primary)" /> Analyzing telemetry...
                </div>
              ) : (
                <>
                  <p style={{ margin: '0 0 12px', whiteSpace: 'pre-wrap' }}>
                    {typeof aiInsight === 'string' ? aiInsight : aiInsight?.insight || '-'}
                  </p>
                  {groqAvailable === false && (
                    <div style={{ padding: '10px 12px', background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 6, fontSize: 12, color: '#fcd34d' }}>
                      💡 <strong>AI not configured.</strong> Go to{' '}
                      <a href="/admin" style={{ color: '#60a5fa' }}>Admin → API Settings</a>
                      {' '}to add a free Groq key for full AI-powered insights.
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          <div className={styles.card}>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Run Depth Scan</h2>
            </div>
            {scanning ? (
              <ScanProgressTracker target={scanHost} />
            ) : (
              <form onSubmit={handleQuickScan} className={styles.quickScanForm}>
                <input
                  type="text"
                  placeholder="hostname or IP"
                  value={scanHost}
                  onChange={e => setScanHost(e.target.value)}
                  className={styles.quickScanInput}
                />
                <button type="submit" disabled={!scanHost} className={styles.quickScanBtn} style={{ padding: '0 20px', fontSize: '14px' }}>
                  <Search size={16} />
                  Depth Scan
                </button>
              </form>
            )}
          </div>

          <div className={`${styles.card} ${styles.scansCard}`}>
            <div className={styles.cardHeader}>
              <h2 className={styles.cardTitle}>Recent Scan Activity</h2>
            </div>
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Score</th>
                    <th>Risk Surface</th>
                    <th>Label</th>
                  </tr>
                </thead>
                <tbody>
                  {(recentScans || []).slice(0, 10).map((row) => (
                    <tr
                      key={row.id}
                      onClick={() => typeof row.id === 'number' && navigate(`/scan/${row.id}`)}
                      style={{ cursor: typeof row.id === 'number' ? 'pointer' : 'default' }}
                      className={styles.scanRow}
                    >
                      <td className="mono">{row.hostname}</td>
                      <td className="mono">{row.quantum_score?.toFixed(1) || '0.0'}</td>
                      <td><RiskBadge level={row.attack_surface_rating} /></td>
                      <td><LabelBadge label={row.label} /></td>
                    </tr>
                  ))}
                  {(!recentScans || recentScans.length === 0) && (
                    <tr>
                      <td colSpan="4" className={styles.emptyState}>No recent scans</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
