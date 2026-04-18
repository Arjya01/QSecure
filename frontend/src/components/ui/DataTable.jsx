import React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import styles from './DataTable.module.css';

export default function DataTable({ 
  columns, 
  data, 
  keyField = 'id',
  onRowClick,
  pagination = null 
}) {
  return (
    <div className={styles.container}>
      <div className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            <tr>
              {columns.map((col, i) => (
                <th key={col.key || i} style={{ width: col.width }}>
                  {col.title}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {!data || data.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className={styles.emptyState}>
                  No data available.
                </td>
              </tr>
            ) : (
              data.map((row) => (
                <tr 
                  key={row[keyField] || Math.random()} 
                  onClick={() => onRowClick && onRowClick(row)}
                  className={onRowClick ? styles.clickableRow : ''}
                >
                  {columns.map((col, i) => (
                    <td key={col.key || i}>
                      {col.render ? col.render(row[col.key], row) : row[col.key]}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      
      {pagination && (
        <div className={styles.pagination}>
          <div className={styles.pageInfo}>
            Showing page {pagination.page} of {pagination.pages || 1} ({pagination.total} total)
          </div>
          <div className={styles.pageControls}>
            <button 
              disabled={pagination.page <= 1} 
              onClick={() => pagination.onPageChange(pagination.page - 1)}
            >
              <ChevronLeft size={16} />
            </button>
            <button 
              disabled={pagination.page >= (pagination.pages || 1)} 
              onClick={() => pagination.onPageChange(pagination.page + 1)}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
