import styles from './Logo.module.css';

/**
 * Q-Secure custom logo — hexagonal shield with QS monogram and pulsing ring.
 */
export default function QSecureLogo({ size = 36 }) {
  const r = size / 2;
  return (
    <div className={styles.logoWrap} style={{ width: size, height: size }}>
      <svg
        viewBox="0 0 40 40"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        width={size}
        height={size}
        aria-label="Q-Secure"
      >
        <defs>
          <linearGradient id="qsGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#8b5cf6" />
          </linearGradient>
        </defs>
        {/* Hexagon shield path */}
        <path
          d="M20 2 L36 10 L36 24 C36 32 20 38 20 38 C20 38 4 32 4 24 L4 10 Z"
          fill="url(#qsGrad)"
          opacity="0.15"
          stroke="url(#qsGrad)"
          strokeWidth="1.5"
        />
        {/* Inner glow ring */}
        <path
          d="M20 6 L33 13 L33 24 C33 30.5 20 35.5 20 35.5 C20 35.5 7 30.5 7 24 L7 13 Z"
          fill="url(#qsGrad)"
          opacity="0.08"
        />
        {/* QS monogram */}
        <text
          x="20"
          y="26"
          textAnchor="middle"
          fill="url(#qsGrad)"
          fontFamily="Inter, system-ui, sans-serif"
          fontWeight="800"
          fontSize="14"
          letterSpacing="-0.5"
        >
          QS
        </text>
      </svg>
    </div>
  );
}
