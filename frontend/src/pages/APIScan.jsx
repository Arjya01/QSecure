import { useState } from 'react';
import { Globe, Loader2 } from 'lucide-react';
import { scanAPISecurity } from '../api/client';
import StatCard from '../components/ui/StatCard';
import DataTable from '../components/ui/DataTable';
import styles from './CommonPage.module.css';

export default function APIScan() {
  const [hostname, setHostname] = useState('');
  const [basePath, setBasePath] = useState('/api');
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const scan = async () => {
    if (!hostname.trim()) return;
    setScanning(true); setResult(null);
    try { const r = await scanAPISecurity({ hostname: hostname.trim(), base_path: basePath }); if (r.success) setResult(r.data.api_scan); } catch {}
    setScanning(false);
  };

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div><h1 className={styles.title}>API Security Assessment</h1>
          <p className={styles.subtitle}>OWASP API Top 10 · CORS · Rate Limiting · Auth · Method Restriction — Open Banking, UPI, SWIFT, Payment APIs</p></div>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <input value={hostname} onChange={e => setHostname(e.target.value)} placeholder="api.bank.com"
          style={{ flex: 1, padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit' }} />
        <input value={basePath} onChange={e => setBasePath(e.target.value)} placeholder="/api"
          style={{ width: 120, padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit' }} />
        <button onClick={scan} disabled={scanning} style={{ padding: '10px 20px', borderRadius: 'var(--radius-md)', border: 'none', background: 'var(--accent)', color: '#000', cursor: 'pointer', fontWeight: 600, fontFamily: 'inherit' }}>
          {scanning ? <Loader2 className="spin" size={14} /> : <Globe size={14} />} Test API
        </button>
      </div>
      {result && <>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          <StatCard label="Grade" value={result.grade} />
          <StatCard label="Score" value={`${result.score}/100`} />
          <StatCard label="Passed" value={`${result.checks?.filter(c => c.status === 'pass').length}/${result.checks?.length}`} />
        </div>
        <DataTable columns={[
          { key: 'name', title: 'Check' },
          { key: 'status', title: 'Status', render: v => <span style={{ color: v === 'pass' ? 'var(--success)' : v === 'warning' ? 'var(--warning)' : 'var(--danger)', fontWeight: 600 }}>{v}</span> },
          { key: 'detail', title: 'Detail', render: v => v || '—' },
          { key: 'severity', title: 'Severity', render: v => <span style={{ fontWeight: 600 }}>{v}</span> },
        ]} data={result.checks || []} />
      </>}
    </div>
  );
}
