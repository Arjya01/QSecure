import styles from './LabelBadge.module.css';

export default function LabelBadge({ label }) {
  if (!label) return null;
  const normalizedLabel = label.toUpperCase();
  
  const getBadgeClass = () => {
    switch (normalizedLabel) {
      case 'QUANTUM_SAFE': return styles.safe;
      case 'PQC_READY': return styles.ready;
      case 'NOT_QUANTUM_SAFE': return styles.notsafe;
      default: return styles.default;
    }
  };

  return (
    <span className={`${styles.badge} ${getBadgeClass()}`}>
      {normalizedLabel.replace(/_/g, ' ')}
    </span>
  );
}
