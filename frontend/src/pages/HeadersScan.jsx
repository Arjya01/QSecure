import { useState } from 'react';
import { Globe, Loader2 } from 'lucide-react';
import { scanHTTPHeaders } from '../api/client';
import StatCard from '../components/ui/StatCard';
import DataTable from '../components/ui/DataTable';
import styles from './CommonPage.module.css';

export default function HeadersScan() {
  const [hostname, setHostname] = useState('');
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const scan = async () => {
    if (!hostname.trim()) return;
    setScanning(true); setResult(null);
    try { const r = await scanHTTPHeaders({ hostname: hostname.trim() }); if (r.success) setResult(r.data.headers_scan); }
    catch {} setScanning(false);
  };

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div><h1 className={styles.title}>HTTP Security Headers</h1>
          <p className={styles.subtitle}>HSTS · CSP · X-Frame-Options · Cache-Control · CORS · COOP/COEP · Cookie Flags — 15+ headers critical for banking</p></div>
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <input value={hostname} onChange={e => setHostname(e.target.value)} onKeyDown={e => e.key === 'Enter' && scan()} placeholder="e.g. onlinesbi.sbi"
          style={{ flex: 1, padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit' }} />
        <button onClick={scan} disabled={scanning} style={{ padding: '10px 20px', borderRadius: 'var(--radius-md)', border: 'none', background: 'var(--accent)', color: '#000', cursor: 'pointer', fontWeight: 600, fontFamily: 'inherit' }}>
          {scanning ? <Loader2 className="spin" size={14} /> : <Globe size={14} />} Scan
        </button>
      </div>

      {result && !result.error && <>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
          <StatCard label="Grade" value={result.grade} />
          <StatCard label="Score" value={`${result.score}/100`} />
          <StatCard label="Present" value={result.present_headers?.length || 0} />
          <StatCard label="Missing" value={result.missing_headers?.length || 0} />
          <StatCard label="Info Leaks" value={result.info_disclosure?.length || 0} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div>
            <h3 style={{ fontSize: 14, marginBottom: 8, color: 'var(--success)' }}>✓ Present ({result.present_headers?.length})</h3>
            <DataTable columns={[
              { key: 'label', title: 'Header' },
              { key: 'value', title: 'Value', render: v => <span className="mono" style={{ fontSize: 10, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', display: 'block' }}>{v}</span> },
              { key: 'quality', title: 'Quality', render: v => <span style={{ color: v === 'good' ? 'var(--success)' : 'var(--warning)', fontWeight: 600 }}>{v}</span> },
            ]} data={result.present_headers || []} />
          </div>
          <div>
            <h3 style={{ fontSize: 14, marginBottom: 8, color: 'var(--danger)' }}>✗ Missing ({result.missing_headers?.length})</h3>
            <DataTable columns={[
              { key: 'label', title: 'Header' },
              { key: 'severity', title: 'Severity', render: v => <span style={{ color: v === 'critical' ? 'var(--danger)' : 'var(--warning)', fontWeight: 600 }}>{v}</span> },
              { key: 'recommendation', title: 'Fix', render: v => <span style={{ fontSize: 11 }}>{v}</span> },
            ]} data={result.missing_headers || []} />
          </div>
        </div>
      </>}
    </div>
  );
}
