import styles from './RiskBadge.module.css';

export default function RiskBadge({ level }) {
  if (!level) return null;
  const normalizedLevel = level.toUpperCase();
  
  const getBadgeClass = () => {
    switch (normalizedLevel) {
      case 'CRITICAL': return styles.critical;
      case 'HIGH': return styles.high;
      case 'MEDIUM': return styles.medium;
      case 'LOW': return styles.low;
      case 'SAFE': 
      case 'NONE': return styles.safe;
      default: return styles.default;
    }
  };

  return (
    <span className={`${styles.badge} ${getBadgeClass()}`}>
      {normalizedLevel}
    </span>
  );
}
