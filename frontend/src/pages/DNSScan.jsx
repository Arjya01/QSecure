import { useState } from 'react';
import { Globe, Loader2, CheckCircle, XCircle } from 'lucide-react';
import { scanDNSSecurity } from '../api/client';
import StatCard from '../components/ui/StatCard';
import DataTable from '../components/ui/DataTable';
import styles from './CommonPage.module.css';

export default function DNSScan() {
  const [hostname, setHostname] = useState('');
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const scan = async () => {
    if (!hostname.trim()) return;
    setScanning(true); setResult(null);
    try { const r = await scanDNSSecurity({ hostname: hostname.trim() }); if (r.success) setResult(r.data.dns_scan); } catch {}
    setScanning(false);
  };

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div><h1 className={styles.title}>DNS Security Analysis</h1>
          <p className={styles.subtitle}>DNSSEC · CAA · SPF · DKIM · DMARC — critical for preventing DNS poisoning & email spoofing</p></div>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <input value={hostname} onChange={e => setHostname(e.target.value)} onKeyDown={e => e.key === 'Enter' && scan()} placeholder="e.g. pnb.bank.in"
          style={{ flex: 1, padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit' }} />
        <button onClick={scan} disabled={scanning} style={{ padding: '10px 20px', borderRadius: 'var(--radius-md)', border: 'none', background: 'var(--accent)', color: '#000', cursor: 'pointer', fontWeight: 600, fontFamily: 'inherit' }}>
          {scanning ? <Loader2 className="spin" size={14} /> : <Globe size={14} />} Scan DNS
        </button>
      </div>
      {result && <>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
          <StatCard label="Grade" value={result.grade} />
          <StatCard label="Score" value={`${result.score}/100`} />
          <StatCard label="Passed" value={`${result.checks?.filter(c => c.status === 'pass' || c.status === 'present').length}/${result.checks?.length}`} />
        </div>
        <DataTable columns={[
          { key: 'check', title: 'Check' },
          { key: 'status', title: 'Status', render: v => (v === 'pass' || v === 'present') ? <span style={{ color: 'var(--success)' }}><CheckCircle size={14} /> OK</span> : <span style={{ color: 'var(--danger)' }}><XCircle size={14} /> {v}</span> },
          { key: 'values', title: 'Details', render: (v, row) => (v?.join?.(', ')) || row.recommendation || '—' },
          { key: 'banking_relevance', title: 'Banking Relevance', render: v => <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{v || '—'}</span> },
        ]} data={result.checks || []} />
      </>}
    </div>
  );
}
