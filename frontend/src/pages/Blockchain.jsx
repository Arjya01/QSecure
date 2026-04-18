import { useEffect, useState } from 'react';
import { Loader2, Box, Link2, Shield, CheckCircle, XCircle, Pickaxe, AlertTriangle, Search } from 'lucide-react';
import { getBlockchainStats, getBlocks, validateChain, getTransactions, mineBlock, listBCCertificates, verifyBCCertificate, getSmartContracts, getThreatIntel, shareThreatIntel } from '../api/client';
import StatCard from '../components/ui/StatCard';
import DataTable from '../components/ui/DataTable';
import styles from './CommonPage.module.css';

const TABS = ['Overview','Blocks','Transactions','Certificates','Smart Contracts','Threat Intel'];

export default function Blockchain() {
  const [tab, setTab] = useState(0);
  const [stats, setStats] = useState(null);
  const [blocks, setBlocks] = useState([]);
  const [txs, setTxs] = useState([]);
  const [certs, setCerts] = useState([]);
  const [contracts, setContracts] = useState([]);
  const [threats, setThreats] = useState([]);
  const [validation, setValidation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verifyHash, setVerifyHash] = useState('');
  const [verifyResult, setVerifyResult] = useState(null);

  useEffect(() => {
    Promise.all([getBlockchainStats(), getBlocks({ limit: 20 })])
      .then(([s, b]) => {
        if (s.success) setStats(s.data);
        if (b.success) setBlocks(b.data.blocks || []);
      })
      .finally(() => setLoading(false));
  }, []);

  const loadTab = (t) => {
    setTab(t);
    if (t === 2 && !txs.length) getTransactions({ limit: 50 }).then(r => r.success && setTxs(r.data.transactions || []));
    if (t === 3 && !certs.length) listBCCertificates().then(r => r.success && setCerts(r.data.certificates || []));
    if (t === 4 && !contracts.length) getSmartContracts().then(r => r.success && setContracts(r.data.contracts || []));
    if (t === 5 && !threats.length) getThreatIntel().then(r => r.success && setThreats(r.data.feed || []));
  };

  const handleMine = async () => {
    try { const r = await mineBlock(); if (r.success) { getBlockchainStats().then(s => s.success && setStats(s.data)); getBlocks({ limit: 20 }).then(b => b.success && setBlocks(b.data.blocks || [])); } } catch {}
  };

  const handleValidate = async () => {
    try { const r = await validateChain(); if (r.success) setValidation(r.data); } catch {}
  };

  const handleVerify = async () => {
    if (!verifyHash.trim()) return;
    try { const r = await verifyBCCertificate(verifyHash.trim()); if (r.success) setVerifyResult(r.data); } catch {}
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 80 }}><Loader2 className="spin" size={32} /></div>;

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div><h1 className={styles.title}>Blockchain Explorer</h1><p className={styles.subtitle}>Immutable audit ledger, PQC certificates, smart contracts & threat intelligence</p></div>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, background: 'var(--surface)', borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--border)' }}>
        {TABS.map((t, i) => (
          <button key={i} onClick={() => loadTab(i)} style={{ flex: 1, padding: '10px 8px', border: 'none', background: tab === i ? 'var(--accent)' : 'transparent', color: tab === i ? '#000' : 'var(--text-secondary)', fontWeight: tab === i ? 600 : 400, cursor: 'pointer', fontSize: 13, fontFamily: 'inherit' }}>{t}</button>
        ))}
      </div>

      {/* ━━━ Overview ━━━ */}
      {tab === 0 && <>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
          <StatCard label="Chain Length" value={stats?.chain_length || 0} icon={Link2} />
          <StatCard label="Transactions" value={stats?.total_transactions || 0} icon={Box} />
          <StatCard label="Pending" value={stats?.pending_transactions || 0} />
          <StatCard label="Valid" value={stats?.chain_valid ? '✓ Yes' : '✗ No'} icon={Shield} />
          <StatCard label="Difficulty" value={stats?.difficulty || 0} />
          <StatCard label="Revoked Certs" value={stats?.revoked_certificates || 0} />
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button className={styles.primaryBadge} style={{ background: 'var(--accent)', color: '#000', cursor: 'pointer', border: 'none' }} onClick={handleMine}><Pickaxe size={14} /> Mine Block</button>
          <button className={styles.secondaryBadge} style={{ cursor: 'pointer', border: '1px solid var(--border)', background: 'var(--surface)' }} onClick={handleValidate}><CheckCircle size={14} /> Validate Chain</button>
        </div>

        {validation && (
          <div style={{ padding: 16, borderRadius: 'var(--radius-md)', background: validation.valid ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${validation.valid ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}` }}>
            <strong style={{ color: validation.valid ? 'var(--success)' : 'var(--danger)' }}>{validation.valid ? '✓ Chain is valid and tamper-proof' : '✗ Chain integrity compromised!'}</strong>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{validation.blocks_checked} blocks verified</p>
          </div>
        )}

        <div style={{ background: 'var(--surface)', borderRadius: 'var(--radius-md)', padding: 16, border: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 12 }}>Transaction Types</h3>
          {stats?.transaction_types && Object.entries(stats.transaction_types).map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: 13 }}>
              <span style={{ textTransform: 'capitalize' }}>{k.replace(/_/g, ' ')}</span>
              <strong>{v}</strong>
            </div>
          ))}
        </div>

        <div style={{ background: 'var(--surface)', borderRadius: 'var(--radius-md)', padding: 16, border: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Smart Contracts</h3>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {stats?.smart_contracts?.map(c => <span key={c} style={{ padding: '4px 10px', borderRadius: 12, background: 'var(--accent-muted)', fontSize: 12, fontWeight: 500 }}>{c.replace(/_/g, ' ')}</span>)}
          </div>
        </div>

        <div style={{ background: 'var(--surface)', borderRadius: 'var(--radius-md)', padding: 16, border: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Latest Block Hash</h3>
          <code style={{ fontSize: 12, wordBreak: 'break-all', color: 'var(--accent)' }}>{stats?.latest_block_hash}</code>
        </div>
      </>}

      {/* ━━━ Blocks ━━━ */}
      {tab === 1 && (
        <DataTable
          columns={[
            { key: 'index', title: '#', render: v => <strong style={{ color: 'var(--accent)' }}>{v}</strong> },
            { key: 'hash', title: 'Hash', render: v => <span className="mono" style={{ fontSize: 11 }}>{v?.slice(0, 20)}…</span> },
            { key: 'previous_hash', title: 'Prev Hash', render: v => <span className="mono" style={{ fontSize: 11 }}>{v?.slice(0, 20)}…</span> },
            { key: 'merkle_root', title: 'Merkle Root', render: v => <span className="mono" style={{ fontSize: 11 }}>{v?.slice(0, 16)}…</span> },
            { key: 'transaction_count', title: 'TXs' },
            { key: 'nonce', title: 'Nonce' },
            { key: 'timestamp', title: 'Time', render: v => v ? new Date(v).toLocaleString() : '—' },
          ]}
          data={blocks}
          emptyMessage="No blocks yet — run a scan to generate blockchain events"
        />
      )}

      {/* ━━━ Transactions ━━━ */}
      {tab === 2 && (
        <DataTable
          columns={[
            { key: 'type', title: 'Type', render: v => <span style={{ padding: '2px 8px', borderRadius: 8, background: 'var(--accent-muted)', fontSize: 11, fontWeight: 600 }}>{v?.replace(/_/g, ' ')}</span> },
            { key: 'asset_name', title: 'Subject', render: (_, row) => row.asset_name || row.details || row.hostname || row.threat_type || '—' },
            { key: 'block_index', title: 'Block', render: v => <strong>#{v}</strong> },
            { key: 'tx_hash', title: 'TX Hash', render: v => <span className="mono" style={{ fontSize: 11 }}>{v?.slice(0, 16)}…</span> },
            { key: 'timestamp', title: 'Time', render: v => v ? new Date(v).toLocaleString() : '—' },
          ]}
          data={txs}
          emptyMessage="No transactions yet"
        />
      )}

      {/* ━━━ Certificates ━━━ */}
      {tab === 3 && <>
        <div style={{ display: 'flex', gap: 8 }}>
          <input value={verifyHash} onChange={e => setVerifyHash(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleVerify()} placeholder="Enter certificate hash to verify…" style={{ flex: 1, padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit' }} />
          <button className={styles.primaryBadge} style={{ background: 'var(--accent)', color: '#000', cursor: 'pointer', border: 'none' }} onClick={handleVerify}><Search size={14} /> Verify</button>
        </div>
        {verifyResult && (
          <div style={{ padding: 14, borderRadius: 'var(--radius-md)', background: verifyResult.valid ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${verifyResult.valid ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}` }}>
            <strong style={{ color: verifyResult.valid ? 'var(--success)' : 'var(--danger)' }}>
              {verifyResult.valid ? '✓ Certificate Valid' : '✗ Invalid'} — {verifyResult.status}
            </strong>
            {verifyResult.certificate && <p style={{ fontSize: 12, marginTop: 4, color: 'var(--text-secondary)' }}>Asset: {verifyResult.certificate.asset_name} | Score: {verifyResult.certificate.score}</p>}
          </div>
        )}
        <DataTable
          columns={[
            { key: 'asset_name', title: 'Asset' },
            { key: 'label_type', title: 'Label', render: v => <span style={{ padding: '2px 10px', borderRadius: 12, fontSize: 11, fontWeight: 700, background: v === 'fully_quantum_safe' ? 'rgba(59,130,246,0.15)' : v === 'pqc_ready' ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)', color: v === 'fully_quantum_safe' ? '#60a5fa' : v === 'pqc_ready' ? '#22c55e' : '#ef4444' }}>{v?.replace(/_/g, ' ')}</span> },
            { key: 'score', title: 'Score', render: v => <strong>{v}</strong> },
            { key: 'certificate_hash', title: 'Hash', render: v => <span className="mono" style={{ fontSize: 11 }}>{v?.slice(0, 20)}…</span> },
            { key: 'block_index', title: 'Block', render: v => `#${v}` },
            { key: 'revoked', title: 'Status', render: v => v ? <span style={{ color: 'var(--danger)' }}>Revoked</span> : <span style={{ color: 'var(--success)' }}>Active</span> },
          ]}
          data={certs}
          emptyMessage="No certificates issued yet — run scans to auto-issue"
        />
      </>}

      {/* ━━━ Smart Contracts ━━━ */}
      {tab === 4 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 16 }}>
          {contracts.map(c => (
            <div key={c.id} style={{ background: 'var(--surface)', borderRadius: 'var(--radius-md)', padding: 20, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <h4 style={{ fontSize: 14, fontWeight: 600 }}>{c.name}</h4>
                <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 8, background: 'var(--accent-muted)' }}>v{c.version}</span>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 10 }}>{c.description}</p>
              <code style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{c.id}</code>
              {c.conditions && <div style={{ marginTop: 8 }}>{Object.entries(c.conditions).map(([k, v]) => (
                <div key={k} style={{ fontSize: 11, padding: '3px 6px', background: 'rgba(255,255,255,0.04)', borderRadius: 4, marginBottom: 3 }}>
                  <strong>{k.replace(/_/g, ' ')}</strong>: min_score={v.min_score}
                </div>
              ))}</div>}
              {c.frameworks && <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>{c.frameworks.map(f => <span key={f} style={{ padding: '2px 6px', borderRadius: 6, background: 'var(--accent-muted)', fontSize: 10, fontWeight: 600 }}>{f.toUpperCase()}</span>)}</div>}
            </div>
          ))}
        </div>
      )}

      {/* ━━━ Threat Intel ━━━ */}
      {tab === 5 && <>
        <button className={styles.primaryBadge} style={{ background: 'var(--accent)', color: '#000', cursor: 'pointer', border: 'none', width: 'fit-content' }}
          onClick={() => shareThreatIntel({ threat_type: 'weak_cipher', details: 'Weak TLS 1.0 cipher on banking portal', severity: 'high' }).then(() => getThreatIntel().then(r => r.success && setThreats(r.data.feed || [])))}>
          <AlertTriangle size={14} /> Share Sample Threat Intel
        </button>
        <DataTable
          columns={[
            { key: 'threat_type', title: 'Type', render: v => <span style={{ padding: '2px 8px', borderRadius: 8, background: 'rgba(245,158,11,0.15)', fontSize: 11, fontWeight: 600 }}>{v?.replace(/_/g, ' ')}</span> },
            { key: 'details', title: 'Details' },
            { key: 'severity', title: 'Severity', render: v => <span style={{ color: v === 'critical' ? 'var(--danger)' : 'var(--warning)', fontWeight: 600 }}>{v}</span> },
            { key: 'reported_by', title: 'Reporter', render: v => <span className="mono" style={{ fontSize: 11 }}>{v?.slice(0, 8)}…</span> },
            { key: 'shared_at', title: 'Time', render: v => v ? new Date(v).toLocaleString() : '—' },
          ]}
          data={threats}
          emptyMessage="No threat intel shared yet"
        />
      </>}
    </div>
  );
}
