import { useEffect, useMemo, useState } from 'react';
import { Loader2, Globe, Shield, Router } from 'lucide-react';
import client from '../api/client';
import DataTable from '../components/ui/DataTable';
import RiskBadge from '../components/ui/RiskBadge';
import ExplanationPopover from '../components/ui/ExplanationPopover';
import useDomainStore from '../store/domainStore';
import { getScopeLabel, getScopeQuery } from '../utils/scope';
import styles from './CommonPage.module.css';

export default function AssetDiscovery() {
  const { activeScope } = useDomainStore();
  const scopeQuery = useMemo(() => getScopeQuery(activeScope), [activeScope]);
  const scopeLabel = getScopeLabel(activeScope);

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('domains');

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const res = await client.get(`/dashboard/asset-discovery${scopeQuery}`);
        if (res.success) setData(res.data);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [scopeQuery]);

  if (loading) return <div className={styles.loader}><Loader2 size={32} className="spin" /></div>;

  const domainCols = [
    { key: 'root_domain', title: 'Root Domain', render: value => <span className="mono">{value}</span> },
    { key: 'subdomain', title: 'Discovered Subdomain', render: value => <span className="mono" style={{ color: 'var(--color-primary)' }}>{value}</span> },
    { key: 'ip_address', title: 'Resolved IP', render: value => <span className="mono">{value || 'Unresolved'}</span> },
    { key: 'record_type', title: 'Record Type' },
    { key: 'is_live', title: 'Status', render: value => <span style={{ color: value ? 'var(--risk-safe)' : 'var(--text-muted)' }}>{value ? 'Live' : 'Offline'}</span> },
  ];

  const certCols = [
    { key: 'common_name', title: 'Common Name', render: value => <span className="mono">{value}</span> },
    { key: 'issuer', title: 'Issuer' },
    { key: 'not_after', title: 'Expires', render: value => value ? new Date(value).toLocaleDateString() : '-' },
    { key: 'is_expired', title: 'Validity', render: value => <span style={{ color: value ? 'var(--risk-critical)' : 'var(--risk-safe)' }}>{value ? 'Expired' : 'Valid'}</span> },
    { key: 'quantum_risk', title: 'Quantum Risk', render: value => <RiskBadge level={value} /> },
  ];

  const ipCols = [
    { key: 'address', title: 'IP Address', render: value => <span className="mono">{value}</span> },
    { key: 'subdomain', title: 'Domain Mapping', render: value => <span className="mono">{value}</span> },
    { key: 'is_live', title: 'Accessibility', render: value => <span style={{ color: value ? 'var(--risk-safe)' : 'var(--text-muted)' }}>{value ? 'Reachable' : 'Unreachable'}</span> },
  ];

  return (
    <div className={`tour-asset-discovery ${styles.page}`}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title} style={{ display: 'inline-flex', alignItems: 'center' }}>
            Asset Discovery & Attack Surface
            <ExplanationPopover 
              title="Asset Discovery"
              what="Automatically maps out all externally facing subdomains, IPs, and certificates linked to your primary domain."
              why="Shadow IT and forgotten infrastructure often run outdated, vulnerable cryptography."
              relevance="Ensures your PQC migration covers your complete attack surface, not just known assets."
            />
          </h2>
          <p className={styles.subtitle}>Viewing discovery results for <strong style={{ color: 'var(--color-primary)' }}>{scopeLabel}</strong>.</p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12, borderBottom: '1px solid var(--border-color)' }}>
        <button
          onClick={() => setActiveTab('domains')}
          style={{
            padding: '12px 24px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'domains' ? '2px solid var(--color-primary)' : '2px solid transparent',
            color: activeTab === 'domains' ? 'var(--text-primary)' : 'var(--text-secondary)',
            cursor: 'pointer',
            display: 'flex',
            gap: 8,
            alignItems: 'center',
          }}
        >
          <Globe size={16} /> Subdomains
        </button>
        <button
          onClick={() => setActiveTab('certs')}
          style={{
            padding: '12px 24px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'certs' ? '2px solid var(--color-primary)' : '2px solid transparent',
            color: activeTab === 'certs' ? 'var(--text-primary)' : 'var(--text-secondary)',
            cursor: 'pointer',
            display: 'flex',
            gap: 8,
            alignItems: 'center',
          }}
        >
          <Shield size={16} /> Certificates
        </button>
        <button
          onClick={() => setActiveTab('ips')}
          style={{
            padding: '12px 24px',
            background: 'none',
            border: 'none',
            borderBottom: activeTab === 'ips' ? '2px solid var(--color-primary)' : '2px solid transparent',
            color: activeTab === 'ips' ? 'var(--text-primary)' : 'var(--text-secondary)',
            cursor: 'pointer',
            display: 'flex',
            gap: 8,
            alignItems: 'center',
          }}
        >
          <Router size={16} /> Live IPs
        </button>
      </div>

      {activeTab === 'domains' && <DataTable columns={domainCols} data={data?.domains || []} keyField="subdomain" />}
      {activeTab === 'certs' && <DataTable columns={certCols} data={data?.certificates || []} keyField="common_name" />}
      {activeTab === 'ips' && <DataTable columns={ipCols} data={data?.ips || []} keyField="address" />}
    </div>
  );
}
