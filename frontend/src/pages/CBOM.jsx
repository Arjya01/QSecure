import { useEffect, useMemo, useState } from 'react';
import { Loader2, Download } from 'lucide-react';
import client from '../api/client';
import DataTable from '../components/ui/DataTable';
import RiskBadge from '../components/ui/RiskBadge';
import ExplanationPopover from '../components/ui/ExplanationPopover';
import useDomainStore from '../store/domainStore';
import { getScopeLabel, getScopeQuery } from '../utils/scope';
import styles from './CommonPage.module.css';

export default function CBOM() {
  const { activeScope } = useDomainStore();
  const scopeQuery = useMemo(() => getScopeQuery(activeScope), [activeScope]);
  const scopeLabel = getScopeLabel(activeScope);

  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [meta, setMeta] = useState({ total: 0, pages: 1 });

  useEffect(() => {
    setPage(1);
  }, [scopeQuery]);

  useEffect(() => {
    loadCBOM(page);
  }, [page, scopeQuery]);

  async function loadCBOM(nextPage) {
    setLoading(true);
    try {
      const joiner = scopeQuery ? '&' : '?';
      const res = await client.get(`/cbom${scopeQuery}${joiner}page=${nextPage}&per_page=15`);
      if (res.success) {
        setData(res.data.items);
        setMeta(res.data.meta);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  const handleExport = () => {
    window.location.href = `http://localhost:5000/api/cbom/export${scopeQuery}`;
  };

  const columns = [
    { key: 'entry_id', title: 'Entry ID', render: value => <span className="mono">{value}</span> },
    { key: 'component_type', title: 'Type', render: value => value?.toUpperCase() },
    { key: 'algorithm', title: 'Algorithm', render: value => <span className="mono">{value}</span> },
    { key: 'key_size', title: 'Key Size', render: value => <span className="mono">{value || '-'}</span> },
    { key: 'quantum_risk', title: 'Risk', render: value => <RiskBadge level={value} /> },
    { key: 'replacement', title: 'PQC Replacement', render: value => <span className="mono" style={{ color: 'var(--risk-safe)' }}>{value || '-'}</span> },
    { key: 'nist_standard', title: 'NIST Standard', render: value => value || '-' },
  ];

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title} style={{ display: 'inline-flex', alignItems: 'center' }}>
            CBOM - <span style={{ color: 'var(--color-primary)', fontFamily: 'var(--font-mono)', fontSize: 20, marginLeft: 8 }}>{scopeLabel}</span>
            <ExplanationPopover 
              title="Cryptographic Bill of Materials (CBOM)"
              what="A comprehensive inventory of all cryptographic algorithms, keys, and certificates detected in your infrastructure."
              why="Provides the foundational visibility required to plan a migration to quantum-safe algorithms."
              relevance="Identifies specifically which components (e.g. RSA-2048, SHA-1) are deprecated or vulnerable to Shor's algorithm."
              articles={[{title: 'CISA: Preparing for PQC', url: 'https://www.cisa.gov/news-events/news/preparing-post-quantum-cryptography'}]}
            />
          </h2>
          <p className={styles.subtitle}>Cryptographic inventory for the currently selected scope.</p>
        </div>
        <div className={styles.actions}>
          <button className={styles.secondaryBadge} onClick={handleExport}>
            <Download size={16} /> Export CSV
          </button>
        </div>
      </div>

      {loading && data.length === 0 ? (
        <div className={styles.loader}><Loader2 size={32} className="spin" /></div>
      ) : data.length === 0 ? (
        <div className={styles.emptyState} style={{ padding: 48, textAlign: 'center', color: 'var(--text-muted)' }}>
          No CBOM entries found for {scopeLabel}. Run a scan first.
        </div>
      ) : (
        <div className="tour-cbom">
          <DataTable
            columns={columns}
            data={data}
            pagination={{ ...meta, page, onPageChange: setPage }}
          />
        </div>
      )}
    </div>
  );
}
