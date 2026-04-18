import { useEffect, useMemo, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  PieChart, Pie, Cell, Tooltip as RechartsTooltip, ResponsiveContainer, Legend,
} from 'recharts';
import client from '../api/client';
import DataTable from '../components/ui/DataTable';
import LabelBadge from '../components/ui/LabelBadge';
import RiskBadge from '../components/ui/RiskBadge';
import ExplanationPopover from '../components/ui/ExplanationPopover';
import useDomainStore from '../store/domainStore';
import { getScopeLabel, getScopeQuery } from '../utils/scope';
import styles from './CommonPage.module.css';

export default function PQCPosture() {
  const { activeScope } = useDomainStore();
  const scopeQuery = useMemo(() => getScopeQuery(activeScope), [activeScope]);
  const scopeLabel = getScopeLabel(activeScope);

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    client.get(`/dashboard/pqc-posture${scopeQuery}`)
      .then(res => { if (res.success) setData(res.data); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [scopeQuery]);

  if (loading) return <div className={styles.loader}><Loader2 size={32} className="spin" /></div>;

  const labels = data?.label_distribution || {};
  const tiers = data?.tier_distribution || {};

  const pieDataLabels = [
    { name: 'QUANTUM_SAFE', value: labels.QUANTUM_SAFE || 0, color: 'var(--risk-safe)' },
    { name: 'PQC_READY', value: labels.PQC_READY || 0, color: 'var(--risk-medium)' },
    { name: 'NOT_QUANTUM_SAFE', value: labels.NOT_QUANTUM_SAFE || 0, color: 'var(--risk-critical)' },
  ];

  const pieDataTiers = [
    { name: 'ELITE_PQC', value: tiers.ELITE_PQC || 0, color: 'var(--risk-safe)' },
    { name: 'STANDARD', value: tiers.STANDARD || 0, color: 'var(--risk-low)' },
    { name: 'LEGACY', value: tiers.LEGACY || 0, color: 'var(--risk-medium)' },
    { name: 'CRITICAL', value: tiers.CRITICAL || 0, color: 'var(--risk-critical)' },
  ];

  const columns = [
    { key: 'root_domain', title: 'Root Domain', render: value => <span className="mono">{value}</span> },
    { key: 'hostname', title: 'Asset', render: value => <span className="mono">{value}</span> },
    { key: 'type', title: 'Type', render: value => value?.toUpperCase() },
    { key: 'quantum_score', title: 'Score', render: value => <span className="mono">{value?.toFixed(1)}</span> },
    { key: 'tier', title: 'Tier' },
    { key: 'label', title: 'PQC Badge', render: value => <LabelBadge label={value} /> },
    { key: 'attack_surface', title: 'Attack Surface', render: value => <RiskBadge level={value} /> },
  ];

  return (
    <div className={styles.page}>
      <div className={styles.pageHeader}>
        <div>
          <h2 className={styles.title} style={{ display: 'inline-flex', alignItems: 'center' }}>
            Post-Quantum Cryptography Posture
            <ExplanationPopover 
              title="PQC Readiness Posture"
              what="Measures how prepared your infrastructure is against Quantum Computing threats."
              why="Organizations must transition to quantum-resistant cryptography before Shor's algorithm becomes a practical reality."
              relevance="Scores algorithms based on CNSA 2.0 and NIST PQC finalized standards (FIPS 203, 204)."
            />
          </h2>
          <p className={styles.subtitle}>Aggregated posture for <strong style={{ color: 'var(--color-primary)' }}>{scopeLabel}</strong>.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        <div style={{ background: 'var(--bg-surface)', padding: 24, borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-color)' }}>
          <h3 style={{ marginBottom: 20, fontSize: 16, color: 'var(--text-primary)' }}>PQC Label Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={pieDataLabels} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                {pieDataLabels.map((entry, index) => <Cell key={index} fill={entry.color} />)}
              </Pie>
              <RechartsTooltip contentStyle={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-color)' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: 'var(--bg-surface)', padding: 24, borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-color)' }}>
          <h3 style={{ marginBottom: 20, fontSize: 16, color: 'var(--text-primary)' }}>PQC Tier Classification</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={pieDataTiers} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                {pieDataTiers.map((entry, index) => <Cell key={index} fill={entry.color} />)}
              </Pie>
              <RechartsTooltip contentStyle={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border-color)' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={{ marginTop: 24 }}>
        <h3 style={{ marginBottom: 16, fontSize: 16, color: 'var(--text-primary)' }}>Assets In Scope</h3>
        <DataTable columns={columns} data={data?.assets || []} />
      </div>
    </div>
  );
}
