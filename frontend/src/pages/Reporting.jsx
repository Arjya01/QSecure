import { useState, useEffect } from 'react';
import { Loader2, Download, FileText } from 'lucide-react';
import client from '../api/client';
import DataTable from '../components/ui/DataTable';
import useAuthStore from '../store/authStore';
import useDomainStore from '../store/domainStore';
import styles from './CommonPage.module.css';

export default function Reporting() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [meta, setMeta] = useState({ total: 0, pages: 1 });
  const [generating, setGenerating] = useState(false);
  const user = useAuthStore(s => s.user);
  const { activeScope } = useDomainStore();

  useEffect(() => {
    loadReports(page);
  }, [page]);

  const loadReports = async (p) => {
    setLoading(true);
    try {
      const res = await client.get(`/reports?page=${p}&per_page=15`);
      if (res.success) {
        setData(res.data.items);
        setMeta(res.data.meta);
      }
    } catch(err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async (type, format) => {
    setGenerating(true);
    try {
      const scopeKey = activeScope?.scope_key || 'all';
      const scopeLabel = activeScope?.label || 'All Assets';
      await client.post('/reports/generate', { 
        type, format, scope: scopeKey, title: `${scopeLabel} — ${type.toUpperCase()} Report` 
      });
      loadReports(1);
    } catch(err) {
      alert("Generation failed");
    } finally {
      setGenerating(false);
    }
  };

  const handDownload = (id) => {
    // Append the JWT token as a query parameter so the browser can natively view/download 
    // the file via a standard GET request without relying on fetch blobs.
    const token = useAuthStore.getState().accessToken;
    const url = `http://localhost:5000/api/reports/${id}/download?jwt=${token}`;
    window.open(url, '_blank');
  };

  const columns = [
    { key: 'title', title: 'Report Title', render: v => <span style={{fontWeight: 500, color: 'var(--text-primary)'}}><FileText size={14} style={{marginRight: '6px', verticalAlign: 'text-bottom'}}/>{v}</span> },
    { key: 'type', title: 'Type', render: v => v.charAt(0).toUpperCase() + v.slice(1) },
    { key: 'format', title: 'Format', render: v => <span className="mono" style={{textTransform: 'uppercase'}}>{v}</span> },
    { key: 'created_at', title: 'Generated On', render: v => new Date(v).toLocaleString() },
    { key: 'file_size', title: 'Size', render: v => `${(v/1024).toFixed(1)} KB` },
    { key: 'id', title: 'Action', render: (v) => (
      <button 
        onClick={(e) => { e.stopPropagation(); handDownload(v); }}
        style={{ color: 'var(--color-primary)', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px', fontWeight: 600 }}
      >
        <Download size={14} /> Download
      </button>
    ) }
  ];

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title}>Auditing & Reporting</h2>
          <p className={styles.subtitle}>Generate compliance documents and board-ready deliverables.</p>
        </div>
        <div className={styles.actions}>
          <button className={styles.secondaryBadge} onClick={() => handleGenerate('cbom', 'json')} disabled={generating}>
            Detailed JSON
          </button>
          <button className={styles.primaryBadge} onClick={() => handleGenerate('executive', 'pdf')} disabled={generating}>
            {generating ? <Loader2 size={16} className="spin" /> : <FileText size={16} />} 
            Executive PDF
          </button>
        </div>
      </div>

      {loading && data.length === 0 ? (
        <div className={styles.loader}><Loader2 size={32} className="spin" /></div>
      ) : (
        <DataTable 
          columns={columns} 
          data={data} 
          pagination={{ ...meta, page, onPageChange: setPage }} 
        />
      )}
    </div>
  );
}
