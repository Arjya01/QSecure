import { useLocation } from 'react-router-dom';
import { LogOut, User as UserIcon } from 'lucide-react';
import useAuthStore from '../../store/authStore';
import styles from './TopBar.module.css';

const PAGE_META = {
  '/':             { title: 'Dashboard',                       sub: 'Enterprise quantum posture at a glance' },
  '/assets':       { title: 'Asset Inventory',                 sub: 'All monitored hosts and endpoints' },
  '/discovery':    { title: 'Asset Discovery',                 sub: 'Attack surface mapping & subdomain recon' },
  '/cbom':         { title: 'Cryptographic Bill of Materials', sub: 'Full cryptographic inventory per asset' },
  '/posture':      { title: 'PQC Posture',                     sub: 'NIST PQC compliance & readiness scoring' },
  '/cyber-rating': { title: 'Enterprise Cyber Rating',         sub: 'Aggregate security score across your estate' },
  '/reporting':    { title: 'Reporting',                       sub: 'Compliance documents & board deliverables' },
  '/ai-insights':  { title: 'AI Insights',                     sub: 'Enoki AI — HNDL ranking, roadmap & contradictions' },
  '/admin':        { title: 'Administration',                  sub: 'Users, API settings, and audit trails' },
};

const ROLE_COLORS = {
  admin:   { bg: 'rgba(139,92,246,0.12)', color: '#a78bfa', label: 'Admin' },
  analyst: { bg: 'rgba(59,130,246,0.12)', color: '#60a5fa', label: 'Analyst' },
  viewer:  { bg: 'rgba(34,197,94,0.1)',   color: '#4ade80', label: 'Viewer' },
  auditor: { bg: 'rgba(245,158,11,0.1)',  color: '#fbbf24', label: 'Auditor' },
};

export default function TopBar() {
  const { user, logout } = useAuthStore();
  const location = useLocation();

  const meta = PAGE_META[location.pathname] || { title: 'Q-Secure', sub: 'Quantum Readiness Platform' };
  const roleStyle = ROLE_COLORS[user?.role] || ROLE_COLORS.viewer;

  return (
    <header className={styles.topbar}>
      <div className={styles.titleContainer}>
        <div className={styles.titleBlock}>
          <h1 className={styles.pageTitle}>{meta.title}</h1>
          <p className={styles.pageSub}>{meta.sub}</p>
        </div>
      </div>

      <div className={styles.actions}>
        {/* User + role */}
        <div className={styles.userInfo}>
          <div className={styles.avatar}>
            <UserIcon size={16} />
          </div>
          <div className={styles.userDetails}>
            <span className={styles.email}>{user?.email}</span>
            <span
              className={styles.roleBadge}
              style={{ background: roleStyle.bg, color: roleStyle.color }}
            >
              {roleStyle.label}
            </span>
          </div>
        </div>

        <button className={styles.logoutBtn} onClick={logout} title="Sign Out">
          <LogOut size={18} />
        </button>
      </div>
    </header>
  );
}
