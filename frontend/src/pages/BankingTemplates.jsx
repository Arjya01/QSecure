import { useEffect, useState } from 'react';
import { Loader2, Building, Shield, CreditCard, TrendingUp, Database, Smartphone, Umbrella, Server, Zap, User, Search, Plus } from 'lucide-react';
import { getBankingTemplates, createAssetFromTemplate } from '../api/client';
import styles from './CommonPage.module.css';

const ICONS = { user: User, building: Building, 'credit-card': CreditCard, 'trending-up': TrendingUp, shield: Shield, database: Database, smartphone: Smartphone, umbrella: Umbrella, server: Server, zap: Zap };

export default function BankingTemplates() {
  const [templates, setTemplates] = useState([]);
  const [categories, setCategories] = useState({});
  const [activeCat, setActiveCat] = useState('all');
  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState(null);
  const [hostname, setHostname] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getBankingTemplates().then(r => {
      if (r.success) { setTemplates(r.data.templates || []); setCategories(r.data.categories || {}); }
    }).finally(() => setLoading(false));
  }, []);

  const filtered = templates.filter(t => {
    if (activeCat !== 'all' && t.category !== activeCat) return false;
    if (search && !t.name.toLowerCase().includes(search.toLowerCase()) && !t.description?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const grouped = {};
  filtered.forEach(t => { if (!grouped[t.category]) grouped[t.category] = []; grouped[t.category].push(t); });

  const handleCreate = async () => {
    if (!hostname.trim() || !creating) return;
    try {
      await createAssetFromTemplate(creating.id, { hostname: hostname.trim() });
      setCreating(null); setHostname('');
    } catch {}
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 80 }}><Loader2 className="spin" size={32} /></div>;

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div><h1 className={styles.title}>Banking Application Templates</h1>
          <p className={styles.subtitle}>{templates.length} pre-configured templates for global banking systems</p></div>
        <div style={{ position: 'relative' }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: 11, color: 'var(--text-secondary)' }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search templates…"
            style={{ paddingLeft: 32, padding: '9px 14px 9px 32px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, width: 240, fontFamily: 'inherit' }} />
        </div>
      </div>

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        <button onClick={() => setActiveCat('all')} style={{ padding: '6px 14px', borderRadius: 'var(--radius-md)', border: activeCat === 'all' ? '2px solid var(--accent)' : '1px solid var(--border)', background: activeCat === 'all' ? 'var(--accent-muted)' : 'var(--surface)', color: 'var(--text-primary)', fontSize: 12, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit' }}>All ({templates.length})</button>
        {Object.entries(categories).map(([k, v]) => (
          <button key={k} onClick={() => setActiveCat(k)} style={{ padding: '6px 14px', borderRadius: 'var(--radius-md)', border: activeCat === k ? '2px solid var(--accent)' : '1px solid var(--border)', background: activeCat === k ? 'var(--accent-muted)' : 'var(--surface)', color: 'var(--text-primary)', fontSize: 12, fontWeight: 500, cursor: 'pointer', fontFamily: 'inherit' }}>
            {v.label} ({templates.filter(t => t.category === k).length})
          </button>
        ))}
      </div>

      {Object.entries(grouped).map(([cat, items]) => {
        const ci = categories[cat] || {};
        const Icon = ICONS[ci.icon] || Shield;
        return (
          <div key={cat}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <Icon size={16} style={{ color: 'var(--accent)' }} />
              <h3 style={{ fontSize: 15, fontWeight: 600 }}>{ci.label || cat}</h3>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>({items.length})</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12 }}>
              {items.map(t => (
                <div key={t.id} onClick={() => { setCreating(t); setHostname(''); }} style={{ background: 'var(--surface)', borderRadius: 'var(--radius-md)', padding: '14px 18px', border: '1px solid var(--border)', cursor: 'pointer', transition: 'border-color 0.15s' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <h4 style={{ fontSize: 13, fontWeight: 600 }}>{t.name}</h4>
                    <span style={{ padding: '2px 8px', borderRadius: 10, fontSize: 10, fontWeight: 700, background: t.criticality === 'critical' ? 'rgba(239,68,68,0.12)' : 'rgba(245,158,11,0.12)', color: t.criticality === 'critical' ? '#ef4444' : '#f59e0b' }}>{t.criticality}</span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>{t.description}</p>
                  <div style={{ display: 'flex', gap: 4, marginTop: 8, flexWrap: 'wrap' }}>
                    <span style={{ padding: '2px 6px', borderRadius: 6, background: 'var(--accent-muted)', fontSize: 10 }}>{t.asset_type?.replace('_', ' ')}</span>
                    {(t.compliance || []).slice(0, 3).map(c => <span key={c} style={{ padding: '2px 6px', borderRadius: 6, background: 'rgba(218,165,32,0.15)', fontSize: 10, fontWeight: 600 }}>{c.toUpperCase().replace('_', ' ')}</span>)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {creating && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={() => setCreating(null)}>
          <div style={{ background: 'var(--bg)', borderRadius: 'var(--radius-lg)', padding: 24, width: 420, border: '1px solid var(--border)' }} onClick={e => e.stopPropagation()}>
            <h3 style={{ marginBottom: 12 }}>{creating.name}</h3>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>{creating.description}</p>
            <input value={hostname} onChange={e => setHostname(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleCreate()} placeholder="Enter hostname (e.g. banking.example.com)"
              style={{ width: '100%', padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', fontSize: 13, fontFamily: 'inherit', marginBottom: 16, boxSizing: 'border-box' }} />
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button onClick={() => setCreating(null)} style={{ padding: '8px 16px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', background: 'var(--surface)', color: 'var(--text-primary)', cursor: 'pointer', fontFamily: 'inherit' }}>Cancel</button>
              <button onClick={handleCreate} style={{ padding: '8px 16px', borderRadius: 'var(--radius-md)', border: 'none', background: 'var(--accent)', color: '#000', cursor: 'pointer', fontWeight: 600, fontFamily: 'inherit' }}><Plus size={14} style={{ verticalAlign: 'middle' }} /> Create Asset</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
