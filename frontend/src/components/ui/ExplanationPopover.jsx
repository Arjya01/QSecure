import React, { useState, useRef, useEffect } from 'react';
import { Info, X, BookOpen, ShieldAlert, CheckCircle2 } from 'lucide-react';
import styles from './ExplanationPopover.module.css';

const ExplanationPopover = ({ title, what, why, relevance, articles }) => {
  const [isOpen, setIsOpen] = useState(false);
  const popoverRef = useRef(null);

  // Close popover when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (popoverRef.current && !popoverRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const togglePopover = (e) => {
    e.stopPropagation();
    setIsOpen(!isOpen);
  };

  return (
    <div className={styles.container} ref={popoverRef}>
      <button 
        className={styles.infoButton} 
        onClick={togglePopover}
        aria-label="More information"
        title="What is this?"
      >
        <Info size={16} />
      </button>

      {isOpen && (
        <div className={styles.popover}>
          <div className={styles.header}>
            <h4>{title}</h4>
            <button className={styles.closeButton} onClick={togglePopover}>
              <X size={16} />
            </button>
          </div>
          
          <div className={styles.content}>
            {what && (
              <div className={styles.section}>
                <h5><CheckCircle2 size={14} className={styles.icon} /> What is this?</h5>
                <p>{what}</p>
              </div>
            )}
            
            {why && (
              <div className={styles.section}>
                <h5><Info size={14} className={styles.icon} /> Why it matters</h5>
                <p>{why}</p>
              </div>
            )}
            
            {relevance && (
              <div className={styles.section}>
                <h5><ShieldAlert size={14} className={styles.icon} /> Relevance to QSecure</h5>
                <p>{relevance}</p>
              </div>
            )}
            
            {articles && articles.length > 0 && (
              <div className={styles.section}>
                <h5><BookOpen size={14} className={styles.icon} /> Related Guidelines & Articles</h5>
                <ul className={styles.articleList}>
                  {articles.map((article, index) => (
                    <li key={index}>
                      <a href={article.url} target="_blank" rel="noopener noreferrer">
                        {article.title}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ExplanationPopover;
