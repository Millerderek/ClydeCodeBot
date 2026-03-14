#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# ClydeCodeBot Deploy Script
# Usage: ./deploy.sh
#
# Run after SCP'ing new files to ~/clydecodebot/
# Installs deps, kills old bot process, starts fresh, shows logs.
# ═══════════════════════════════════════════════════════════════

set -e
cd ~/clydecodebot

echo "═══ ClydeCodeBot Deploy ═══"

# Install/update deps
echo "📦 Installing dependencies..."
pip install -q --break-system-packages -r requirements.txt 2>/dev/null || \
pip install -q -r requirements.txt

# Kill old bot process (targeted — does NOT kill vault, uvicorn, etc.)
echo "🔪 Stopping old bot process..."
pkill -f 'python3 clydecodebot.py' 2>/dev/null && sleep 3 || true
screen -S claw -X quit 2>/dev/null || true
screen -wipe 2>/dev/null || true

# Clear old log
rm -f /tmp/claw.log

# Start fresh
echo "🚀 Starting ClydeCodeBot..."
screen -dmS claw bash -c 'exec env -u CLAUDECODE python3 clydecodebot.py 2>&1 | tee /tmp/claw.log'

# Wait and show startup
sleep 8
echo ""
echo "═══ Startup Log ═══"
head -20 /tmp/claw.log
echo ""
echo "═══ Status ═══"
if pgrep -f "python3 clydecodebot.py" > /dev/null; then
    echo "✅ ClydeCodeBot running (PID: $(pgrep -f 'python3 clydecodebot.py'))"
else
    echo "❌ Failed to start. Full log:"
    cat /tmp/claw.log
fi
