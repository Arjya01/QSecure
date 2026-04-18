# Q-Secure Enterprise

Q-Secure is an Enterprise Quantum Readiness Platform designed to scan, analyze, and secure your digital infrastructure against emerging quantum computing threats. Operating under the principles of Post-Quantum Cryptography (PQC), Q-Secure helps organizations mitigate Harvest-Now-Decrypt-Later (HNDL) data-exfiltration strategies and ensures compliance with the latest NIST standards (FIPS-203, FIPS-204) and OMB memorandums.

## Key Features

*   **Asset Discovery and Attack Surface Mapping**: Automatically identifies external attack surfaces, mapping subdomains via passive DNS enumeration, extracting TLS certificates from Certificate Transparency (CT) logs, and resolving live IPs.
*   **Cryptographic Bill of Materials (CBOM)**: A structured, comprehensive inventory of all cryptographic primitives (e.g., RSA-2048, AES-256-GCM) detected across your ecosystem, mapped directly to their quantum risk profiles and NIST PQC recommended replacements.
*   **Enterprise Cyber Rating**: A unified risk scoring framework (0 - 1000) that categorizes organizational infrastructure into distinct quantum-readiness tiers: CRITICAL, LEGACY, STANDARD, and ELITE_PQC.
*   **Enoki AI Strategic Insights**: Powered by the Groq API, the Enoki AI engine generates highly synthesized executive narratives, detects deep infrastructural contradictions, and drafts dynamic, prioritize remediation roadmaps.
*   **High-Fidelity Reporting**: Generates board-ready Executive PDF reports (rendered in a professional dark-slate aesthetic), as well as JSON and CSV exports for integration with external IT workflows.

## Architecture

The platform is split into a streamlined, high-performance architecture:

*   **Backend / Scanner Engine**: Written in Python. It handles deep telemetry extraction, TLS handshakes, certificate parsing, SSH algorithms, and DNSSEC validation. The API is robustly secured and powers the Enoki LLM pipeline.
*   **Frontend Interface**: Built with modern React and Vite. It provides an intuitive, high-performance executive dashboard with interactive charting (Recharts), reactive state management, and a comprehensive onboarding tour.
*   **Concurrent Startup**: A unified startup script leverages `concurrently` to spin up both the front and backends cleanly in a single terminal pane.

## Getting Started

### Prerequisites

*   Python 3.8+
*   Node.js 18+ and npm
*   A valid Groq API Key (Optional, but required for Enoki AI Insights)

### Quick Start

1.  Clone the repository:
    ```bash
    git clone https://github.com/aarshx05/QSecure.git
    cd QSecure
    ```

2.  Launch the platform using the unified startup script. This single command boots the entire platform concurrently:
    ```bash
    ./start.bat
    ```

The script will automatically spin up the Python backend server alongside the Vite frontend developer server in a single terminal. 
*   **Web Dashboard**: Access via `http://localhost:5173`
*   **API Server**: Running on `http://localhost:5000`

### Initial Configuration

1.  Navigate to the **Admin** dashboard.
2.  Input your **Groq API Key** to unlock the Enoki AI analysis engine. 
3.  If performing presentations, utilize the "Demo and Support" section to replay the guided onboarding tour.

## Core Modules

*   **Dashboard**: A high-level aggregate perspective on total assets, cyber ratings, and real-time risk distribution.
*   **Asset Inventory**: The ground-truth listing of all tracked endpoints.
*   **CBOM Viewer**: Exportable cryptographic material breakdowns.
*   **PQC Posture**: Specific NIST compliance adherence metrics.
*   **Reporting Engine**: The central hub for defining scopes and generating executive deliverables.

## Security and Compliance

The Q-Secure engine does not perform intrusive, damaging active exploits. It utilizes passive intelligence gathering and authorized handshake verifications to establish cryptographic baselines. Ensure you maintain authorization to scan targeted domains and IP ranges.
