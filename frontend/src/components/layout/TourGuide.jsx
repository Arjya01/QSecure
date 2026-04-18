import { useState, useEffect } from 'react';
import { Joyride, STATUS, ACTIONS } from 'react-joyride';
import { useLocation } from 'react-router-dom';
import useAuthStore from '../../store/authStore';

const TOUR_KEY = 'qsecure_tour_v2_completed';

const TourGuide = () => {
  const { isAuthenticated } = useAuthStore();
  const location = useLocation();
  const [run, setRun] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) return;
    if (location.pathname !== '/') return;
    const done = localStorage.getItem(TOUR_KEY);
    if (!done) {
      localStorage.setItem(TOUR_KEY, 'started');
      setTimeout(() => setRun(true), 1200);
    }
  }, [isAuthenticated, location.pathname]);

  const handleCallback = (data) => {
    const { status, action } = data;

    // Escape key or manual close
    if (action === ACTIONS.CLOSE) {
      setRun(false);
      localStorage.setItem(TOUR_KEY, 'completed');
      return;
    }

    if ([STATUS.FINISHED, STATUS.SKIPPED].includes(status)) {
      setRun(false);
      localStorage.setItem(TOUR_KEY, 'completed');
    }
  };

  const steps = [
    {
      target: 'body',
      placement: 'center',
      disableBeacon: true,
      content: (
        <div>
          <h3 style={{ color: '#c4b5fd', marginBottom: 8, fontSize: 18 }}>Welcome to Q‑Secure</h3>
          <p style={{ lineHeight: 1.6, marginBottom: 10 }}>
            Q‑Secure is an <strong>Enterprise Quantum Readiness Platform</strong> that scans your
            entire digital infrastructure for cryptographic vulnerabilities before quantum computers
            can exploit them.
          </p>
          <p style={{ lineHeight: 1.6, color: '#94a3b8', fontSize: 13 }}>
            This short tour (~2 min) walks you through every module. You can skip anytime.
          </p>
        </div>
      ),
    },
    {
      target: '.tour-dashboard',
      placement: 'right',
      disableBeacon: true,
      disableScrolling: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>Navigation Sidebar</h4>
          <p style={{ lineHeight: 1.6, marginBottom: 10 }}>
            Use the sidebar to switch between modules. We'll briefly walk through the core features!
          </p>
          <p style={{ fontSize: 12, color: '#8b5cf6', marginTop: 8 }}>
            The <strong>Active Scope</strong> dropdown at the bottom lets you filter everything to a specific domain or group.
          </p>
        </div>
      ),
    },
    {
      target: '.tour-asset-inventory',
      placement: 'right',
      disableBeacon: true,
      disableScrolling: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>Assets In Scope</h4>
          <p style={{ lineHeight: 1.6 }}>
            View all monitored assets in the currently selected scope. Each asset is a distinct
            hostname, API endpoint, or service endpoint that has been scanned.
          </p>
        </div>
      ),
    },
    {
      target: '.tour-asset-discovery',
      placement: 'right',
      disableBeacon: true,
      disableScrolling: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>Asset Discovery and Attack Surface</h4>
          <p style={{ lineHeight: 1.6, marginBottom: 8 }}>
            Automatically maps your <strong>full external attack surface</strong>:
          </p>
          <ul style={{ paddingLeft: 18, lineHeight: 2, fontSize: 13, color: '#cbd5e1' }}>
            <li><strong>Subdomains</strong> via passive DNS enumeration</li>
            <li><strong>TLS Certificates</strong> from Certificate Transparency logs</li>
            <li><strong>Live IPs</strong> resolved from DNS records</li>
          </ul>
        </div>
      ),
    },
    {
      target: '.tour-cbom',
      placement: 'right',
      disableBeacon: true,
      disableScrolling: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>Cryptographic Bill of Materials</h4>
          <p style={{ lineHeight: 1.6, marginBottom: 8 }}>
            The CBOM is a <strong>structured inventory</strong> of every cryptographic primitive
            detected across your infrastructure — similar to a software SBOM but for crypto.
          </p>
          <ul style={{ paddingLeft: 18, lineHeight: 2, fontSize: 13, color: '#cbd5e1' }}>
            <li>Algorithm (e.g. <code>RSA-2048</code>, <code>AES-256-GCM</code>)</li>
            <li>Quantum risk level</li>
            <li>Recommended NIST PQC replacement (e.g. <code>ML-KEM-768</code>)</li>
          </ul>
        </div>
      ),
    },
    {
      target: '.tour-cyber-rating',
      placement: 'right',
      disableBeacon: true,
      disableScrolling: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>Enterprise Cyber Rating</h4>
          <p style={{ lineHeight: 1.6, marginBottom: 8 }}>
            A composite <strong>0 – 1000 score</strong> modelled on industry-standard security
            ratings (like BitSight). It reflects your organisation's overall quantum-readiness:
          </p>
          <ul style={{ paddingLeft: 18, lineHeight: 2, fontSize: 13, color: '#cbd5e1' }}>
            <li><strong>ELITE_PQC</strong> — 850+ (quantum-safe)</li>
            <li><strong>STANDARD</strong> — 650–849 (partially safe)</li>
            <li><strong>LEGACY</strong> — 400–649 (vulnerable)</li>
            <li><strong>CRITICAL</strong> — &lt;400 (immediate action needed)</li>
          </ul>
        </div>
      ),
    },
    {
      target: '.tour-ai-insights',
      placement: 'right',
      disableBeacon: true,
      disableScrolling: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>Enoki AI - Powered by Groq</h4>
          <p style={{ lineHeight: 1.6, marginBottom: 8 }}>
            The <strong>AI Insights</strong> module uses the Enoki AI engine to generate:
          </p>
          <ul style={{ paddingLeft: 18, lineHeight: 2, fontSize: 13, color: '#cbd5e1' }}>
            <li>HNDL (Harvest‑Now‑Decrypt‑Later) risk profiles</li>
            <li>Cross‑asset contradiction detection</li>
            <li>Prioritised remediation roadmaps</li>
            <li>Executive narrative reports</li>
          </ul>
        </div>
      ),
    },
    {
      target: '.tour-admin',
      placement: 'right',
      disableBeacon: true,
      disableScrolling: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>API Settings and Inline Help</h4>
          <p style={{ lineHeight: 1.6, marginBottom: 8 }}>
            To enable full AI, go here and paste your free <strong>Groq API key</strong>.
          </p>
          <p style={{ lineHeight: 1.6 }}>
            Also, look for the purple information icons next to section titles across the platform for deep dives into specific metrics.
          </p>
        </div>
      ),
    },
    {
      target: 'body',
      placement: 'center',
      disableBeacon: true,
      content: (
        <div>
          <h4 style={{ color: '#c4b5fd', marginBottom: 8 }}>You are all set</h4>
          <p style={{ lineHeight: 1.6, marginBottom: 10 }}>
            Here's how to get started in 3 steps:
          </p>
          <ol style={{ paddingLeft: 18, lineHeight: 2.2, fontSize: 13, color: '#cbd5e1' }}>
            <li>Go to <strong>Admin → API Settings</strong> and add your Groq key to enable AI</li>
            <li>Run a <strong>Depth Scan</strong> from the Dashboard on your target domain</li>
            <li>Explore <strong>AI Insights</strong> for your automated remediation roadmap</li>
          </ol>
          <p style={{ fontSize: 12, color: '#64748b', marginTop: 12 }}>
            Demo credentials: <strong style={{ color: '#94a3b8' }}>admin@qsecure.local</strong> / <strong style={{ color: '#94a3b8' }}>QSecure@2026</strong>
          </p>
        </div>
      ),
    },
  ];

  if (!isAuthenticated) return null;

  return (
    <Joyride
      callback={handleCallback}
      continuous
      disableOverlayClose
      run={run}
      scrollToFirstStep
      showProgress
      showSkipButton
      steps={steps}
      styles={{
        options: {
          arrowColor: '#0f172a',
          overlayColor: 'rgba(0, 0, 0, 0.8)',
          primaryColor: '#8b5cf6',
          zIndex: 10000,
        },
        tooltip: {
          backgroundColor: '#0f172a',
          borderRadius: 14,
          border: '1px solid rgba(139,92,246,0.3)',
          color: '#f1f5f9',
          fontSize: 14,
          padding: '20px 24px',
          width: 460,
          boxShadow: '0 25px 50px rgba(0,0,0,0.6)',
        },
        tooltipTitle: {
          color: '#c4b5fd',
          fontSize: 16,
          fontWeight: 700,
          marginBottom: 8,
        },
        tooltipContent: {
          color: '#cbd5e1',
          lineHeight: 1.65,
          padding: '4px 0',
        },
        tooltipContainer: {
          textAlign: 'left',
        },
        tooltipFooter: {
          borderTop: '1px solid rgba(255,255,255,0.08)',
          marginTop: 16,
          paddingTop: 12,
        },
        buttonNext: {
          backgroundColor: '#7c3aed',
          borderRadius: 8,
          color: '#fff',
          fontWeight: 600,
          outline: 'none',
          padding: '8px 18px',
        },
        buttonBack: {
          color: '#94a3b8',
          marginRight: 10,
          fontWeight: 500,
        },
        buttonSkip: {
          color: '#475569',
          fontWeight: 500,
        },
        buttonClose: {
          color: '#475569',
        },
        progressBar: {
          backgroundColor: '#7c3aed',
          height: 3,
        },
        spotlight: {
          borderRadius: 8,
        },
      }}
    />
  );
};

export default TourGuide;
