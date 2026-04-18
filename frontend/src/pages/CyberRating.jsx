import { useEffect, useMemo, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import client from '../api/client';
import useDomainStore from '../store/domainStore';
import { getScopeLabel, getScopeQuery } from '../utils/scope';
import styles from './CommonPage.module.css';

function RatingDial({ score, maxScore = 1000, subtitle }) {
  const pct = Math.min(100, (score / maxScore) * 100);
  const color = pct >= 70 ? 'var(--risk-safe)' : pct >= 40 ? '#f59e0b' : 'var(--risk-critical)';
  return (
    <div style={{ width: 260, height: 260, borderRadius: '50%', background: `conic-gradient(${color} ${pct * 3.6}deg, var(--bg-surface-elevated) 0deg)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ width: 220, height: 220, borderRadius: '50%', background: 'var(--bg-main)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <div className="mono" style={{ fontSize: 58, fontWeight: 700, color, lineHeight: 1 }}>
          {Math.round(score)}
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 6 }}>/ {maxScore} pts</div>
        {subtitle && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{subtitle}</div>}
      </div>
    </div>
  );
}

export default function CyberRating() {
  const { activeScope } = useDomainStore();
  const scopeQuery = useMemo(() => getScopeQuery(activeScope), [activeScope]);
  const scopeLabel = getScopeLabel(activeScope);

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    client.get(`/dashboard/cyber-rating${scopeQuery}`)
      .then(res => { if (res.success) setData(res.data); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scopeQuery]);

  if (loading) return <div className={styles.loader}><Loader2 size={32} className="spin" /></div>;

  const current = data?.current || { score: 0, tier: 'UNKNOWN', assets_evaluated: 0 };

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title}>Cyber Rating</h2>
          <p className={styles.subtitle}>Aggregated rating for <strong style={{ color: 'var(--color-primary)' }}>{scopeLabel}</strong>.</p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 48, alignItems: 'center', justifyContent: 'center', margin: '40px 0', flexWrap: 'wrap' }}>
        <RatingDial score={current.score} maxScore={1000} subtitle="CYBER RATING" />

        <div>
          <div style={{ fontSize: 16, color: 'var(--text-secondary)', marginBottom: 8 }}>Assigned Tier</div>
          <div style={{ fontSize: 48, fontWeight: 800, color: 'var(--color-primary)', letterSpacing: '-0.02em', marginBottom: 16 }}>
            {current.tier?.replace('_', ' ')}
          </div>
          <p style={{ color: 'var(--text-muted)', maxWidth: 400, lineHeight: '1.6' }}>
            This view averages the latest posture across {current.assets_evaluated || 0} assets inside the active scope.
          </p>
        </div>
      </div>

      {data?.trend?.length > 0 && (
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-lg)', padding: 24 }}>
          <h3 style={{ fontSize: 15, marginBottom: 16, color: 'var(--text-primary)' }}>30-Day Rating Trend</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={data.trend} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--border-color)" />
              <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={11} tickFormatter={value => value.slice(5)} />
              <YAxis domain={['auto', 'auto']} stroke="var(--text-muted)" fontSize={11} />
              <Tooltip contentStyle={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-color)' }} />
              <Line type="monotone" dataKey="score" stroke="var(--color-primary)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
