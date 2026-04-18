import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import useAuthStore from '../store/authStore';
import client from '../api/client';
import QSecureLogo from '../components/layout/Logo';
import styles from './Login.module.css';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const setAuth = useAuthStore(s => s.setAuth);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    
    try {
      const res = await client.post('/auth/login', { email, password });
      if (res.success) {
        setAuth(res.data.user, res.data.access_token, res.data.refresh_token);
        navigate('/');
      } else {
        setError(res.error || 'Login failed');
      }
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Connection error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.heroBackground}></div>
      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.logo}>
            <QSecureLogo size={48} />
            <h1>Q-Secure</h1>
          </div>
          <p className={styles.subtitle}>Enterprise Quantum Readiness Platform</p>
        </div>
        
        {error && <div className={styles.error}>{error}</div>}
        
        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.inputGroup}>
            <label>Email Address</label>
            <input 
              type="email" 
              value={email} 
              onChange={e => setEmail(e.target.value)} 
              placeholder="admin@qsecure.local"
              required 
              autoFocus
            />
          </div>
          
          <div className={styles.inputGroup}>
            <label>Password</label>
            <input 
              type="password" 
              value={password} 
              onChange={e => setPassword(e.target.value)} 
              placeholder="••••••••"
              required 
            />
          </div>
          
          <button type="submit" disabled={loading} className={styles.button}>
            {loading ? <Loader2 size={20} className={styles.spin} /> : 'Sign In to Dashboard'}
          </button>
        </form>

        {/* Demo Credentials */}
        <div className={styles.demoBox}>
          <div className={styles.demoLabel}>🔑 Demo Credentials</div>
          <div className={styles.demoRow}>
            <span className={styles.demoKey}>Email</span>
            <button
              className={styles.demoValue}
              onClick={() => setEmail('admin@qsecure.local')}
              title="Click to auto-fill"
            >admin@qsecure.local</button>
          </div>
          <div className={styles.demoRow}>
            <span className={styles.demoKey}>Password</span>
            <button
              className={styles.demoValue}
              onClick={() => setPassword('QSecure@2026')}
              title="Click to auto-fill"
            >QSecure@2026</button>
          </div>
          <p className={styles.demoHint}>Click any value to auto-fill the form</p>
        </div>

        <div className={styles.footer}>
          Authorized personnel only. All access is logged and monitored.
        </div>
      </div>
    </div>
  );
}
