#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# ClaudeClaw Deploy Script
# Usage: ./deploy.sh
#
# Run after SCP'ing new files to ~/claudeclaw/
# Installs deps, kills old process, starts fresh, shows logs.
# ═══════════════════════════════════════════════════════════════

set -e
cd ~/claudeclaw

echo "═══ ClaudeClaw Deploy ═══"

# Install/update deps
echo "📦 Installing dependencies..."
pip install -q --break-system-packages -r requirements.txt 2>/dev/null || \
pip install -q -r requirements.txt

# Kill old process
echo "🔪 Stopping old process..."
killall -9 python3 2>/dev/null && sleep 3 || true
screen -wipe 2>/dev/null || true

# Clear old log
rm -f /tmp/claw.log

# Start fresh
echo "🚀 Starting ClaudeClaw..."
screen -dmS claw bash -c 'exec env -u CLAUDECODE python3 clydecodebot.py 2>&1 | tee /tmp/claw.log'

# Wait and show startup
sleep 8
echo ""
echo "═══ Startup Log ═══"
head -20 /tmp/claw.log
echo ""
echo "═══ Status ═══"
if pgrep -f "python3 claudeclaw.py" > /dev/null; then
    echo "✅ ClaudeClaw running (PID: $(pgrep -f 'python3 claudeclaw.py'))"
else
    echo "❌ Failed to start. Full log:"
    cat /tmp/claw.log
fi
