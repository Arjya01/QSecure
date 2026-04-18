import Sidebar from './Sidebar';
import TopBar from './TopBar';
import styles from './PageWrapper.module.css';

export default function PageWrapper({ children }) {
  return (
    <div className={styles.layout}>
      <Sidebar />
      <div className={styles.main}>
        <TopBar />
        <div className={styles.content}>
          <div className={styles.container}>
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
