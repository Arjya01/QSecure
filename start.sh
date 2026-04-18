#!/bin/bash
echo "═══════════════════════════════════════════════════"
echo "  Q-Secure v3.0 — Quantum-Ready Cybersecurity"
echo "  PNB Cybersecurity Hackathon 2026"
echo "═══════════════════════════════════════════════════"
echo ""

# Backend
cd backend
pip install -r requirements.txt --quiet 2>/dev/null
python seed.py 2>/dev/null
echo "[+] Starting backend on http://localhost:5000"
python app.py &
BACKEND_PID=$!
cd ..

# Frontend
cd frontend
npm install --silent 2>/dev/null
echo "[+] Starting frontend on http://localhost:5173"
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "  Backend:  http://localhost:5000"
echo "  Frontend: http://localhost:5173"
echo "  Login:    admin@qsecure.local / QSecure@2026"
echo ""
echo "  Press Ctrl+C to stop"
wait
