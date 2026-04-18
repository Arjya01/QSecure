import { useEffect, useMemo, useState } from 'react';
import { Loader2, Layers3, Plus, Trash2, Target } from 'lucide-react';
import client from '../api/client';
import DataTable from '../components/ui/DataTable';
import RiskBadge from '../components/ui/RiskBadge';
import LabelBadge from '../components/ui/LabelBadge';
import useDomainStore from '../store/domainStore';
import { defaultScope, getScopeLabel, getScopeQuery, scopeContainsDomain } from '../utils/scope';
import styles from './CommonPage.module.css';

export default function AssetInventory() {
  const { activeScope, setActiveScope } = useDomainStore();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [meta, setMeta] = useState({ total: 0, pages: 1 });
  const [catalog, setCatalog] = useState({ all: defaultScope, domains: [], groups: [] });
  const [selectedDomains, setSelectedDomains] = useState([]);
  const [groupName, setGroupName] = useState('');
  const [savingGroup, setSavingGroup] = useState(false);

  const scopeQuery = useMemo(() => getScopeQuery(activeScope), [activeScope]);

  useEffect(() => {
    loadCatalog();
  }, []);

  useEffect(() => {
    setPage(1);
  }, [scopeQuery]);

  useEffect(() => {
    loadAssets(page);
  }, [page, scopeQuery]);

  async function loadCatalog() {
    try {
      const res = await client.get('/groups/scopes');
      if (res.success) {
        setCatalog(res.data);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async function loadAssets(nextPage) {
    setLoading(true);
    try {
      const joiner = scopeQuery ? '&' : '?';
      const res = await client.get(`/assets${scopeQuery}${joiner}page=${nextPage}&per_page=15`);
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

  function toggleDomain(domain) {
    setSelectedDomains(current =>
      current.includes(domain)
        ? current.filter(item => item !== domain)
        : [...current, domain]
    );
  }

  async function handleCreateGroup() {
    if (!groupName.trim() || selectedDomains.length < 2) {
      return;
    }

    setSavingGroup(true);
    try {
      const res = await client.post('/groups', {
        name: groupName.trim(),
        domains: selectedDomains,
      });
      if (res.success) {
        setGroupName('');
        setSelectedDomains([]);
        await loadCatalog();
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to create group');
    } finally {
      setSavingGroup(false);
    }
  }

  async function handleDeleteGroup(groupId) {
    try {
      await client.delete(`/groups/${groupId}`);
      if (activeScope?.scope_type === 'group' && activeScope.id === groupId) {
        setActiveScope(catalog.all || defaultScope);
      }
      await loadCatalog();
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to delete group');
    }
  }

  const columns = [
    {
      key: 'root_domain',
      title: 'Root Domain',
      render: (value) => (
        <span
          className="mono"
          style={{ color: scopeContainsDomain(activeScope, value) ? 'var(--color-primary)' : undefined }}
        >
          {value}
        </span>
      ),
    },
    { key: 'hostname', title: 'Hostname', render: value => <span className="mono">{value}</span> },
    { key: 'type', title: 'Type', render: value => value.toUpperCase().replace('_', ' ') },
    { key: 'environment', title: 'Environment', render: value => value?.charAt(0).toUpperCase() + value?.slice(1) },
    {
      key: 'criticality',
      title: 'Criticality',
      render: value => <RiskBadge level={value === 'critical' ? 'CRITICAL' : value === 'high' ? 'HIGH' : 'MEDIUM'} />,
    },
    {
      key: 'last_scan',
      title: 'PQC Label',
      render: value => value ? <LabelBadge label={value.label} /> : <span style={{ color: 'var(--text-muted)' }}>No Scan</span>,
    },
    {
      key: 'last_scan',
      title: 'Q-Score',
      render: value => value ? <span className="mono">{value.quantum_score?.toFixed(1)}</span> : '-',
    },
    {
      key: 'root_domain',
      title: '',
      render: (value) => {
        const scope = (catalog.domains || []).find(item => item.domain === value);
        return (
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (scope) {
                setActiveScope(scope);
              }
            }}
            style={{
              padding: '4px 10px',
              fontSize: 11,
              fontWeight: 700,
              background: scopeContainsDomain(activeScope, value) ? 'rgba(37,99,235,0.15)' : 'var(--bg-main)',
              border: `1px solid ${scopeContainsDomain(activeScope, value) ? 'var(--color-primary)' : 'var(--border-color)'}`,
              borderRadius: 6,
              color: scopeContainsDomain(activeScope, value) ? 'var(--color-primary)' : 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
          >
            <Target size={11} />
            Focus
          </button>
        );
      },
    },
  ];

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title}>Asset Inventory</h2>
          <p className={styles.subtitle}>
            Viewing scope: <strong style={{ color: 'var(--color-primary)' }}>{getScopeLabel(activeScope)}</strong>
          </p>
        </div>
      </div>

      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-color)',
          borderRadius: 'var(--radius-lg)',
          padding: 20,
          marginBottom: 24,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <Layers3 size={18} color="var(--color-primary)" />
          <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-primary)' }}>Manual Domain Groups</h3>
        </div>
        <p style={{ color: 'var(--text-secondary)', marginTop: 0, marginBottom: 16, fontSize: 13 }}>
          Domains stay separate by default. Select two or more root domains here when you want their dashboard, CBOM,
          discovery, posture, and AI data aggregated together.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20 }}>
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
              {(catalog.domains || []).map(domain => (
                <label
                  key={domain.scope_key}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    padding: '10px 12px',
                    borderRadius: 10,
                    border: `1px solid ${selectedDomains.includes(domain.domain) ? 'var(--color-primary)' : 'var(--border-color)'}`,
                    background: selectedDomains.includes(domain.domain) ? 'rgba(37,99,235,0.08)' : 'var(--bg-main)',
                    cursor: 'pointer',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selectedDomains.includes(domain.domain)}
                    onChange={() => toggleDomain(domain.domain)}
                  />
                  <div>
                    <div className="mono" style={{ fontSize: 13 }}>{domain.domain}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{domain.asset_count} assets</div>
                  </div>
                </label>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
              <input
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
                placeholder="Group name, e.g. SBI Banking Cluster"
                style={{
                  flex: 1,
                  background: 'var(--bg-main)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 10,
                  color: 'var(--text-primary)',
                  padding: '10px 12px',
                  fontSize: 13,
                }}
              />
              <button
                onClick={handleCreateGroup}
                disabled={savingGroup || selectedDomains.length < 2 || !groupName.trim()}
                className={styles.primaryBadge}
              >
                {savingGroup ? <Loader2 size={16} className="spin" /> : <Plus size={16} />}
                Save Group
              </button>
            </div>
          </div>

          <div>
            <h4 style={{ marginTop: 0, marginBottom: 12, fontSize: 14, color: 'var(--text-primary)' }}>Saved Groups</h4>
            {(catalog.groups || []).length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>No manual groups yet.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {(catalog.groups || []).map(group => (
                  <div
                    key={group.scope_key}
                    style={{
                      padding: 12,
                      borderRadius: 10,
                      border: `1px solid ${activeScope?.scope_key === group.scope_key ? 'var(--color-primary)' : 'var(--border-color)'}`,
                      background: activeScope?.scope_key === group.scope_key ? 'rgba(37,99,235,0.08)' : 'var(--bg-main)',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <button
                        onClick={() => setActiveScope(group)}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-primary)',
                          fontWeight: 700,
                          padding: 0,
                          cursor: 'pointer',
                          textAlign: 'left',
                        }}
                      >
                        {group.name}
                      </button>
                      <button
                        onClick={() => handleDeleteGroup(group.id)}
                        style={{ background: 'none', border: 'none', color: 'var(--risk-critical)', cursor: 'pointer' }}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                      {(group.domains || []).join(', ')}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
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
