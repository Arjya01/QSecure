import { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Database, Search,
  FileKey, Shield, Activity, FileText, Settings, Brain, ChevronDown, Globe,
  Link2, Building, CheckSquare, Wifi, Code, ScanLine
} from 'lucide-react';
import useDomainStore from '../../store/domainStore';
import client from '../../api/client';
import { defaultScope } from '../../utils/scope';
import QSecureLogo from './Logo';
import styles from './Sidebar.module.css';

const navItems = [
  { name: 'Dashboard',       path: '/',             icon: LayoutDashboard },
  { name: 'Asset Inventory', path: '/assets',        icon: Database },
  { name: 'Asset Discovery', path: '/discovery',     icon: Search },
  { name: 'CBOM',            path: '/cbom',          icon: FileKey },
  { name: 'PQC Posture',     path: '/posture',       icon: Shield },
  { name: 'Cyber Rating',    path: '/cyber-rating',  icon: Activity },
  { name: 'Reporting',       path: '/reporting',     icon: FileText },
  { divider: true, label: 'Advanced Scanning' },
  { name: 'AI Insights',     path: '/ai-insights',   icon: Brain },
  { name: 'HTTP Headers',    path: '/headers-scan',  icon: Globe },
  { name: 'DNS Security',    path: '/dns-scan',      icon: Wifi },
  { name: 'API Security',    path: '/api-scan',      icon: Code },
  { divider: true, label: 'Banking & Blockchain' },
  { name: 'Banking Templates', path: '/banking-templates', icon: Building },
  { name: 'Compliance',      path: '/compliance',    icon: CheckSquare },
  { name: 'Blockchain',      path: '/blockchain',    icon: Link2 },
  { divider: true, label: 'Admin' },
  { name: 'Admin',           path: '/admin',         icon: Settings },
];

export default function Sidebar() {
  const { activeScope, setActiveScope } = useDomainStore();
  const [catalog, setCatalog] = useState({ all: defaultScope, domains: [], groups: [] });

  useEffect(() => {
    client.get('/groups/scopes')
      .then(res => { if (res.success) setCatalog(res.data); })
      .catch(() => {});
  }, []);

  const allScopes = [catalog.all, ...(catalog.groups || []), ...(catalog.domains || [])];

  useEffect(() => {
    const match = allScopes.find(scope => scope?.scope_key === activeScope?.scope_key);
    if (match && JSON.stringify(match) !== JSON.stringify(activeScope)) {
      setActiveScope(match);
    } else if (!match && catalog?.all) {
      setActiveScope(catalog.all);
    }
  }, [catalog, activeScope]);

  const handleScopeChange = (e) => {
    const found = allScopes.find(scope => scope?.scope_key === e.target.value);
    setActiveScope(found || catalog.all || defaultScope);
  };

  return (
    <aside className={`${styles.sidebar} tour-sidebar`}>
      <div className={styles.logoContainer}>
        <QSecureLogo size={34} />
        <div>
          <span className={styles.logoText}>Q-Secure</span>
          <div className={styles.logoSub}>Quantum Posture Platform</div>
        </div>
      </div>

      <nav className={styles.nav}>
        {navItems.map((item, idx) => {
          if (item.divider) {
            return <div key={idx} className={styles.sectionLabel}>{item.label}</div>;
          }
          const Icon = item.icon;
          const tourClass = `tour-${item.name.toLowerCase().replace(/\s+/g, '-')}`;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `${styles.navItem} ${isActive ? styles.active : ''} ${tourClass}`
              }
            >
              <Icon size={20} />
              <span>{item.name}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Scope Picker */}
      <div className={styles.domainPicker}>
        <div className={styles.domainPickerLabel}>
          <Globe size={11} />
          Active Scope
        </div>
        <div className={styles.domainSelectWrap}>
          <select
            className={styles.domainSelect}
            value={activeScope?.scope_key ?? 'all'}
            onChange={handleScopeChange}
          >
            <option value="all">All Domains</option>
            {(catalog.groups || []).length > 0 && (
              <optgroup label="Manual Groups">
                {(catalog.groups || []).map(group => (
                  <option key={group.scope_key} value={group.scope_key}>
                    {group.label} ({group.asset_count})
                  </option>
                ))}
              </optgroup>
            )}
            {(catalog.domains || []).length > 0 && (
              <optgroup label="Domains">
                {(catalog.domains || []).map(domain => (
                  <option key={domain.scope_key} value={domain.scope_key}>
                    {domain.label} ({domain.asset_count})
                  </option>
                ))}
              </optgroup>
            )}
          </select>
          <ChevronDown size={12} className={styles.domainCaret} />
        </div>
        {activeScope && (
          <div className={styles.domainActive}>
            <span className={styles.domainDot} />
            {activeScope.latest_scan?.label || 'NO SCAN'}
          </div>
        )}
        <div className={styles.scopeMeta}>
          {(activeScope?.asset_count || 0)} assets in view
        </div>
      </div>

      <div className={styles.footer}>
      </div>
    </aside>
  );
}
