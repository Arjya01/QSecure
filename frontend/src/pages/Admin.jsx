import { useState, useEffect } from 'react';
import { Loader2, KeyRound, CheckCircle2, Trash2, Eye, EyeOff, ExternalLink, Bot, Users, FileText, HelpCircle, RotateCcw } from 'lucide-react';
import client from '../api/client';
import DataTable from '../components/ui/DataTable';
import styles from './CommonPage.module.css';

// ─── API Key Panel ───────────────────────────────────────────────────────────

function ApiKeyPanel() {
  const [status, setStatus] = useState(null);
  const [inputKey, setInputKey] = useState('');
  const [showInput, setShowInput] = useState(false);
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [msg, setMsg] = useState(null);

  const loadStatus = async () => {
    try {
      const res = await client.get('/admin/groq-key');
      if (res.success) setStatus(res.data);
    } catch { /* ignore */ }
  };

  useEffect(() => { loadStatus(); }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    if (!inputKey.startsWith('gsk_')) {
      setMsg({ type: 'error', text: 'Invalid key format. Groq keys start with gsk_' });
      return;
    }
    setSaving(true);
    setMsg(null);
    try {
      const res = await client.post('/admin/groq-key', { api_key: inputKey });
      if (res.success) {
        setMsg({ type: 'success', text: 'API key saved! AI features are now active.' });
        setInputKey('');
        setShowInput(false);
        await loadStatus();
      } else {
        setMsg({ type: 'error', text: res.error || 'Failed to save key' });
      }
    } catch (err) {
      setMsg({ type: 'error', text: err.message || 'Network error' });
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    if (!window.confirm('Remove the Groq API key? AI features will fall back to rule-based mode.')) return;
    setRemoving(true);
    try {
      const res = await client.delete('/admin/groq-key');
      if (res.success) {
        setMsg({ type: 'info', text: 'Key removed. Running in rule-based fallback mode.' });
        await loadStatus();
      }
    } finally {
      setRemoving(false);
    }
  };

  const isLive = status?.groq_available;

  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Bot size={20} color="#8b5cf6" />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: 'var(--text-primary)' }}>Groq AI API Key</h3>
            <p style={{ margin: 0, fontSize: 13, color: 'var(--text-secondary)' }}>Powers the Enoki AI analysis engine — free at console.groq.com</p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: isLive ? '#22c55e' : '#f59e0b', display: 'inline-block' }} />
          <span style={{ fontSize: 13, color: isLive ? '#22c55e' : '#f59e0b', fontWeight: 600 }}>
            {isLive ? 'AI Active' : status?.configured ? 'Key Configured (initializing…)' : 'Rule-Based Mode'}
          </span>
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Current status */}
        {status?.configured && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <CheckCircle2 size={16} color="#22c55e" />
              <div>
                <span style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>Key: </span>
                <code style={{ fontSize: 13, color: '#94a3b8' }}>{status.masked_key}</code>
                <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 8 }}>({status.source})</span>
              </div>
            </div>
            <button
              onClick={handleRemove}
              disabled={removing}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 6, color: '#fca5a5', cursor: 'pointer', fontSize: 13 }}
            >
              {removing ? <Loader2 size={14} className="spin" /> : <Trash2 size={14} />}
              Remove
            </button>
          </div>
        )}

        {!status?.configured && (
          <div style={{ padding: '12px 16px', background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 8, fontSize: 13, color: '#fcd34d', lineHeight: 1.6 }}>
            <strong>No API key configured.</strong> AI-powered insights, narratives, and roadmaps are running in <strong>rule-based fallback mode</strong>. Add a key to enable the full Enoki AI engine.
          </div>
        )}

        {/* Add key form */}
        <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <label style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-secondary)' }}>
            {status?.configured ? 'Update API Key' : 'Add Groq API Key'}
          </label>
          <div style={{ display: 'flex', gap: 10 }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <input
                type={showInput ? 'text' : 'password'}
                value={inputKey}
                onChange={e => setInputKey(e.target.value)}
                placeholder="gsk_••••••••••••••••••••••••••••••••"
                style={{ width: '100%', padding: '10px 40px 10px 14px', background: 'var(--bg-main)', border: '1px solid var(--border-color)', borderRadius: 8, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 13, outline: 'none', boxSizing: 'border-box' }}
              />
              <button
                type="button"
                onClick={() => setShowInput(!showInput)}
                style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0 }}
              >
                {showInput ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <button
              type="submit"
              disabled={saving || !inputKey}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 20px', background: 'var(--color-primary)', border: 'none', borderRadius: 8, color: '#fff', fontWeight: 600, fontSize: 14, cursor: saving || !inputKey ? 'not-allowed' : 'pointer', opacity: saving || !inputKey ? 0.6 : 1, whiteSpace: 'nowrap' }}
            >
              {saving ? <Loader2 size={16} className="spin" /> : <KeyRound size={16} />}
              {saving ? 'Saving…' : 'Save Key'}
            </button>
          </div>
          {msg && (
            <p style={{ margin: 0, fontSize: 13, color: msg.type === 'success' ? '#4ade80' : msg.type === 'error' ? '#fca5a5' : '#94a3b8' }}>
              {msg.text}
            </p>
          )}
        </form>

        {/* Help */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text-muted)' }}>
          <ExternalLink size={14} />
          <span>Get a free API key at </span>
          <a href="https://console.groq.com/keys" target="_blank" rel="noopener noreferrer" style={{ color: '#60a5fa' }}>console.groq.com/keys</a>
          <span> — includes generous free tier (supports llama-3.3-70b)</span>
        </div>
      </div>
    </div>
  );
}

// ─── Main Admin Page ─────────────────────────────────────────────────────────

export default function Admin() {
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tourResetStatus, setTourResetStatus] = useState(null);

  const resetTour = () => {
    localStorage.removeItem('qsecure_tour_v2_completed');
    setTourResetStatus('Tour has been reset. It will automatically start the next time you visit the Dashboard!');
    setTimeout(() => setTourResetStatus(null), 5000);
  };

  useEffect(() => {
    async function load() {
      try {
        const [uRes, lRes] = await Promise.all([
          client.get('/admin/users'),
          client.get('/admin/audit-log?per_page=10')
        ]);
        if (uRes.success) setUsers(uRes.data.items);
        if (lRes.success) setLogs(lRes.data.items);
      } catch(err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <div className={styles.loader}><Loader2 size={32} className="spin" /></div>;

  const uCols = [
    { key: 'email', title: 'User Email' },
    { key: 'is_active', title: 'Status', render: v => <span style={{color: v ? 'var(--risk-safe)' : 'var(--text-muted)'}}>{v ? 'Active' : 'Inactive'}</span> },
    { key: 'locked', title: 'Locked', render: v => <span style={{color: v ? 'var(--risk-critical)' : 'transparent'}}>{v ? 'LOCKED' : ''}</span> },
    { key: 'last_login', title: 'Last Login', render: v => v ? new Date(v).toLocaleString() : 'Never' },
  ];

  const lCols = [
    { key: 'timestamp', title: 'Time', render: v => new Date(v).toLocaleString() },
    { key: 'user_email', title: 'User', render: v => v || 'System' },
    { key: 'action', title: 'Action', render: v => <span className="mono">{v}</span> },
    { key: 'resource', title: 'Resource' },
    { key: 'outcome', title: 'Outcome', render: v => <span style={{color: v==='success'?'var(--risk-safe)':'var(--risk-critical)'}}>{v}</span> }
  ];

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title}>Administration</h2>
          <p className={styles.subtitle}>Manage users, AI settings, and audit trails</p>
        </div>
      </div>

      <div style={{display: 'flex', flexDirection: 'column', gap: '32px'}}>

        {/* API Key Section */}
        <div>
          <h3 style={{ marginBottom: '16px', fontSize: '18px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Bot size={20} color="#8b5cf6" /> API Settings
          </h3>
          <ApiKeyPanel />
        </div>

        {/* User Accounts */}
        <div>
          <h3 style={{ marginBottom: '16px', fontSize: '18px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Users size={20} color="#8b5cf6" /> User Accounts
          </h3>
          <DataTable columns={uCols} data={users} />
        </div>
        
        {/* Audit Logs */}
        <div>
          <h3 style={{ marginBottom: '16px', fontSize: '18px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <FileText size={20} color="#8b5cf6" /> Recent System Audit Logs
          </h3>
          <DataTable columns={lCols} data={logs} />
        </div>

        {/* Demo Support */}
        <div style={{ marginTop: '32px', padding: '24px', background: 'rgba(139,92,246,0.04)', border: '1px dashed rgba(139,92,246,0.3)', borderRadius: 'var(--radius-lg)' }}>
          <h3 style={{ margin: '0 0 12px 0', fontSize: '18px', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <HelpCircle size={20} color="#8b5cf6" /> Demo and Support
          </h3>
          <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '20px' }}>
            Preparing for a presentation? You can reset the onboarding tour to show it to new stakeholders.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <button 
              onClick={resetTour}
              style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px', background: 'rgba(139,92,246,0.1)', border: '1px solid rgba(139,92,246,0.3)', borderRadius: 8, color: '#c4b5fd', fontSize: '14px', fontWeight: 600, cursor: 'pointer' }}
            >
              <RotateCcw size={16} /> Restart Onboarding Tour
            </button>
            {tourResetStatus && (
              <span style={{ fontSize: '13px', color: '#4ade80', fontWeight: 500 }}>{tourResetStatus}</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
