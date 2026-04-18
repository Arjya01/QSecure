import { useEffect, useState } from 'react';
import { Shield, CheckCircle, XCircle, Loader2 } from 'lucide-react';
import { getComplianceFrameworks, checkCompliance } from '../api/client';
import client from '../api/client';
import DataTable from '../components/ui/DataTable';
import styles from './CommonPage.module.css';

export default function Compliance() {
  const [frameworks, setFrameworks] = useState([]);
  const [assets, setAssets] = useState([]);
  const [sf, setSf] = useState(null);
  const [sa, setSa] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    Promise.all([
      getComplianceFrameworks(),
      client.get('/assets?per_page=200'),
    ]).then(([f, a]) => {
      if (f.success) setFrameworks(f.data.frameworks || []);
      if (a.success) setAssets(a.data.items || a.data.assets || []);
    }).finally(() => setLoading(false));
  }, []);

  const handleCheck = async () => {
    if (!sa || !sf) return;
    setChecking(true); setResult(null);
    try { const r = await checkCompliance({ asset_id: sa, framework_id: sf }); if (r.success) setResult(r.data.compliance); }
    catch {}
    setChecking(false);
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 80 }}><Loader2 className="spin" size={32} /></div>;

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div><h1 className={styles.title}>Compliance Assessment</h1>
          <p className={styles.subtitle}>PCI DSS · RBI · SWIFT CSP · GDPR · SOX · Basel III · PSD2 · NIST PQC · FFIEC · FATF · OWASP API</p></div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
        {frameworks.map(f => (
          <div key={f.id} onClick={() => setSf(f.id)} style={{ background: 'var(--surface)', borderRadius: 'var(--radius-md)', padding: '14px 16px', border: sf === f.id ? '2px solid var(--accent)' : '1px solid var(--border)', cursor: 'pointer' }}>
            <h4 style={{ fontSize: 14, fontWeight: 600, color: 'var(--accent)' }}>{f.name}</h4>
            <p style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{f.full_name}</p>
            <div style={{ marginTop: 6 }}><span style={{ padding: '2px 8px', borderRadius: 8, background: 'var(--accent-muted)', fontSize: 10 }}>{f.jurisdiction}</span></div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
        <div style={{ flex: 1 }}>
          <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Asset to check</label>
          <select value={sa} onChange={e => setSa(e.target.value)} style={{ width: '100%', padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit' }}>
            <option value="">Select asset…</option>
            {assets.map(a => <option key={a.id} value={a.id}>{a.hostname || a.name}</option>)}
          </select>
        </div>
        <button onClick={handleCheck} disabled={checking} style={{ padding: '10px 20px', borderRadius: 'var(--radius-md)', border: 'none', background: 'var(--accent)', color: '#000', cursor: 'pointer', fontWeight: 600, fontFamily: 'inherit', whiteSpace: 'nowrap' }}>
          {checking ? <Loader2 className="spin" size={14} /> : <Shield size={14} />} Check Compliance
        </button>
      </div>

      {result && (
        <div>
          <div style={{ padding: 16, borderRadius: 'var(--radius-md)', background: result.compliant ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)', border: `1px solid ${result.compliant ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`, marginBottom: 16 }}>
            <strong style={{ color: result.compliant ? 'var(--success)' : 'var(--danger)', fontSize: 16 }}>
              {result.compliance_pct}% — {result.compliant ? 'Compliant' : 'Non-Compliant'}
            </strong>
            <span style={{ marginLeft: 12, fontSize: 13, color: 'var(--text-secondary)' }}>{result.framework_name}</span>
          </div>
          <DataTable
            columns={[
              { key: 'check', title: 'Check' },
              { key: 'required', title: 'Required', render: v => v || '—' },
              { key: 'actual', title: 'Actual', render: (v, row) => String(v || row.violations?.join(', ') || '—') },
              { key: 'status', title: 'Status', render: v => v === 'pass' ? <span style={{ color: 'var(--success)' }}><CheckCircle size={14} /> Pass</span> : <span style={{ color: 'var(--danger)' }}><XCircle size={14} /> Fail</span> },
            ]}
            data={result.results || []}
          />
        </div>
      )}
    </div>
  );
}
