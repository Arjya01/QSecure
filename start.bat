@echo off
title Q-Secure Platform Launcher
chcp 65001 >nul 2>&1

set "ROOT=%~dp0"

echo.
echo  ============================================================
echo   Q-SECURE  ^|  Quantum Posture Management Platform  v5.0
echo   Phase 5  ^|  AI Intelligence Layer
echo  ============================================================
echo.

:: -----------------------------------------------------------------------
:: Groq API Key setup
:: -----------------------------------------------------------------------
if defined GROQ_API_KEY (
    echo  [AI]  GROQ_API_KEY found in environment.
    echo        Primary model: llama-3.3-70b-versatile
) else (
    echo  [AI]  No GROQ_API_KEY set.
    echo.
    echo        To enable full AI features (free, ~30 seconds):
    echo          1. Visit https://console.groq.com  -  create a free account
    echo          2. Generate an API key
    echo          3. In the app: Admin -^> API Settings -^> paste your key
    echo.
    echo        Rule-based analysis is active until a key is configured.
)

echo.
echo  Starting services...
echo.

echo.
echo  Starting services in a single terminal...
echo.

:: -----------------------------------------------------------------------
:: Run both using concurrently for a single terminal experience
:: -----------------------------------------------------------------------
npx -y concurrently -n "API,WEB" -c "blue.bold,magenta.bold" "cd backend && py app.py" "cd frontend && npm run dev"

echo.
echo  ============================================================
echo   Services have stopped.
echo  ============================================================
pause
