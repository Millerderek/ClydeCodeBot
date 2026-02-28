#!/usr/bin/env bash
set -e

# ═══════════════════════════════════════════════════════════════
# ClaudeClaw Installer
# curl -fsSL https://raw.githubusercontent.com/Millerderek/ClydeCode/main/install.sh | bash
# ═══════════════════════════════════════════════════════════════

REPO="https://github.com/Millerderek/ClydeCode.git"
INSTALL_DIR="$HOME/claudeclaw"
CONFIG_DIR="$HOME/.claudeclaw"
OPENCLAW_DIR="$HOME/.openclaw"
VAULT_DIR="/etc/openclaw"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()    { echo -e "  ${BLUE}→${NC} $1"; }
success() { echo -e "  ${GREEN}✓${NC} $1"; }
warn()    { echo -e "  ${YELLOW}!${NC} $1"; }
err()     { echo -e "  ${RED}✗${NC} $1"; }
ask()     { echo -en "  ${BOLD}$1${NC}"; }
step()    { echo -e "\n${CYAN}━━━ $1 ━━━${NC}\n"; }

echo ""
echo -e "${CYAN}   ╔═══════════════════════════════════════╗${NC}"
echo -e "${CYAN}   ║${NC}  ${BOLD}🐾 ClaudeClaw${NC}                        ${CYAN}║${NC}"
echo -e "${CYAN}   ║${NC}  ${DIM}Telegram → Claude Agent SDK Bridge${NC}   ${CYAN}║${NC}"
echo -e "${CYAN}   ╚═══════════════════════════════════════╝${NC}"
echo ""

# ─── Helper: read with default ────────────────────────────────
read_default() {
    local prompt="$1" default="$2" var="$3"
    if [ -n "$default" ]; then
        ask "$prompt [$default]: "
    else
        ask "$prompt: "
    fi
    read input
    eval "$var=\"${input:-$default}\""
}

read_secret() {
    local prompt="$1" var="$2"
    ask "$prompt: "
    read -s input
    echo ""
    eval "$var=\"$input\""
}

read_yn() {
    local prompt="$1" default="${2:-y}"
    if [ "$default" = "y" ]; then
        ask "$prompt [Y/n]: "
    else
        ask "$prompt [y/N]: "
    fi
    read -n 1 -r reply
    echo ""
    if [ -z "$reply" ]; then reply="$default"; fi
    [[ "$reply" =~ ^[Yy]$ ]]
}

# ═══════════════════════════════════════════════════════════════
# STEP 1: System Dependencies
# ═══════════════════════════════════════════════════════════════

step "1/9  System Dependencies"

MISSING=()

# Python 3.10+
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [ "$PY_MINOR" -ge 10 ]; then
        success "Python $PY_VER"
    else
        MISSING+=("python3.12")
    fi
else
    MISSING+=("python3")
fi

# Node.js 18+
if command -v node &>/dev/null; then
    NODE_VER=$(node -v | tr -d 'v' | cut -d. -f1)
    if [ "$NODE_VER" -ge 18 ]; then
        success "Node.js $(node -v)"
    else
        MISSING+=("nodejs")
    fi
else
    MISSING+=("nodejs")
fi

# Git
if command -v git &>/dev/null; then
    success "Git $(git --version | cut -d' ' -f3)"
else
    MISSING+=("git")
fi

# Screen
if command -v screen &>/dev/null; then
    success "Screen"
else
    MISSING+=("screen")
fi

if [ ${#MISSING[@]} -gt 0 ]; then
    warn "Missing: ${MISSING[*]}"
    if [[ -f /etc/debian_version ]]; then
        info "Installing via apt..."
        sudo apt-get update -qq
        for pkg in "${MISSING[@]}"; do
            case "$pkg" in
                nodejs)
                    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
                    sudo apt-get install -y -qq nodejs
                    ;;
                python3.12)
                    sudo apt-get install -y -qq python3.12 python3.12-venv python3-pip
                    ;;
                *)
                    sudo apt-get install -y -qq "$pkg"
                    ;;
            esac
        done
    elif [[ -f /etc/redhat-release ]]; then
        info "Installing via yum/dnf..."
        for pkg in "${MISSING[@]}"; do
            sudo dnf install -y "$pkg" 2>/dev/null || sudo yum install -y "$pkg"
        done
    else
        err "Please install manually: ${MISSING[*]}"
        exit 1
    fi
    success "Dependencies installed"
fi

# ═══════════════════════════════════════════════════════════════
# STEP 2: Clone / Update Repo
# ═══════════════════════════════════════════════════════════════

step "2/9  Install ClaudeClaw"

if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing install..."
    cd "$INSTALL_DIR" && git pull --ff-only 2>/dev/null || true
elif [ -d "$INSTALL_DIR" ]; then
    warn "$INSTALL_DIR exists (no .git)"
    if read_yn "Back up and reinstall?"; then
        mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
        git clone "$REPO" "$INSTALL_DIR"
    fi
else
    git clone "$REPO" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

info "Installing Python packages..."
pip install -r requirements.txt --break-system-packages -q 2>/dev/null \
    || pip install -r requirements.txt -q 2>/dev/null \
    || pip3 install -r requirements.txt -q
success "ClaudeClaw installed at $INSTALL_DIR"

mkdir -p "$CONFIG_DIR"

# ═══════════════════════════════════════════════════════════════
# STEP 3: Claude Code OAuth
# ═══════════════════════════════════════════════════════════════

step "3/9  Claude Code Authentication"

echo "  ClaudeClaw uses Claude Code OAuth (Pro/Max subscription)."
echo "  No API key needed — just login once."
echo ""

AUTH_METHOD=""

if [ -d "$HOME/.claude" ]; then
    success "Claude Code session found (~/.claude)"
    AUTH_METHOD="oauth"
else
    warn "No Claude Code session found"
    echo ""
    echo "  Option 1: Install Claude Code CLI and login (recommended)"
    echo "  Option 2: Use an Anthropic API key"
    echo ""

    if read_yn "Install Claude Code CLI now?"; then
        npm install -g @anthropic-ai/claude-code 2>/dev/null
        echo ""
        info "Run 'claude' after setup to authenticate via browser"
        AUTH_METHOD="oauth_pending"
    else
        echo ""
        read_secret "Anthropic API key (sk-ant-...)" ANTHROPIC_API_KEY
        if [ -n "$ANTHROPIC_API_KEY" ]; then
            AUTH_METHOD="api_key"
            success "API key set"
        else
            warn "Skipped — you'll need to run 'claude' before starting the bot"
            AUTH_METHOD="oauth_pending"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════
# STEP 4: Telegram Bots
# ═══════════════════════════════════════════════════════════════

step "4/9  Telegram Bot Setup"

echo "  ClaudeClaw uses TWO Telegram bots:"
echo ""
echo "    ${BOLD}Main bot${NC}        — your conversation with Claude"
echo "    ${BOLD}Permission bot${NC}  — approval requests (Approve/Deny buttons)"
echo ""
echo "  Create both via ${BOLD}@BotFather${NC} on Telegram → /newbot"
echo ""

# Load existing .env if present
MAIN_TOKEN="" PERM_TOKEN="" USER_IDS=""
if [ -f "$INSTALL_DIR/.env" ]; then
    MAIN_TOKEN=$(grep "^TELEGRAM_BOT_TOKEN=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2-)
    PERM_TOKEN=$(grep "^PERMISSION_BOT_TOKEN=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2-)
    USER_IDS=$(grep "^ALLOWED_USER_IDS=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2-)
fi

if [ -n "$MAIN_TOKEN" ]; then
    success "Main bot token found (${MAIN_TOKEN:0:8}...)"
    if read_yn "Keep existing token?" "y"; then
        :
    else
        read_secret "Main bot token" MAIN_TOKEN
    fi
else
    read_secret "Main bot token" MAIN_TOKEN
fi
while [ -z "$MAIN_TOKEN" ]; do
    warn "Required"
    read_secret "Main bot token" MAIN_TOKEN
done

echo ""
if [ -n "$PERM_TOKEN" ]; then
    success "Permission bot token found (${PERM_TOKEN:0:8}...)"
    if read_yn "Keep existing token?" "y"; then
        :
    else
        read_secret "Permission bot token" PERM_TOKEN
    fi
else
    read_secret "Permission bot token" PERM_TOKEN
fi
while [ -z "$PERM_TOKEN" ]; do
    warn "Required for approval system"
    read_secret "Permission bot token" PERM_TOKEN
done

success "Both bot tokens configured"

# ═══════════════════════════════════════════════════════════════
# STEP 5: User Authentication
# ═══════════════════════════════════════════════════════════════

step "5/9  User Authentication"

echo "  Only authorized Telegram users can use the bot."
echo "  Get your ID: message ${BOLD}@userinfobot${NC} on Telegram"
echo ""

if [ -n "$USER_IDS" ]; then
    success "User IDs: $USER_IDS"
    if ! read_yn "Keep existing?" "y"; then
        read_default "Telegram user ID(s), comma-separated" "" USER_IDS
    fi
else
    read_default "Telegram user ID(s), comma-separated" "" USER_IDS
fi
while [ -z "$USER_IDS" ]; do
    warn "At least one user ID required"
    read_default "Telegram user ID(s)" "" USER_IDS
done

success "Authorized: $USER_IDS"

# ═══════════════════════════════════════════════════════════════
# STEP 6: Audit Chain (AI Safety Reviewers)
# ═══════════════════════════════════════════════════════════════

step "6/9  Audit Chain Setup"

echo "  The audit chain uses independent AI models to review"
echo "  every tool call before execution."
echo ""
echo "  Recommended: 2 models from different providers."
echo ""
echo "  ${BOLD}Available presets:${NC}"
echo "    1) GPT-4.1-mini     (OpenAI)       — fast, cheap, reliable"
echo "    2) Gemini 2.5 Flash (Google)        — fast, free tier available"
echo "    3) DeepSeek V3      (DeepSeek)      — cheap, capable"
echo "    4) Groq Llama 3.3   (Groq)          — very fast, free tier"
echo "    5) GPT-4.1-nano     (OpenAI)        — cheapest OpenAI"
echo "    6) Kimi K2.5        (Moonshot)      — Chinese model option"
echo ""
echo "    0) Skip — no audit chain"
echo ""

AUDITORS="[]"
AUDITOR_LIST=()

while true; do
    ask "Add auditor (1-6, or 0 to finish): "
    read choice

    case "$choice" in
        0|"") break ;;
        1)
            read_secret "OpenAI API key (sk-...)" OKEY
            if [ -n "$OKEY" ]; then
                AUDITOR_LIST+=("{\"name\":\"GPT-4.1-mini\",\"provider\":\"openai\",\"model\":\"gpt-4.1-mini\",\"api_base\":\"https://api.openai.com\",\"enabled\":true,\"timeout\":30}")
                OPENAI_KEY="$OKEY"
                success "Added GPT-4.1-mini"
            fi ;;
        2)
            read_secret "Google API key (AIza...)" GKEY
            if [ -n "$GKEY" ]; then
                AUDITOR_LIST+=("{\"name\":\"Gemini 2.5 Flash\",\"provider\":\"google\",\"model\":\"gemini-2.5-flash\",\"api_base\":\"https://generativelanguage.googleapis.com\",\"enabled\":true,\"timeout\":30}")
                GOOGLE_KEY="$GKEY"
                success "Added Gemini 2.5 Flash"
            fi ;;
        3)
            read_secret "DeepSeek API key" DKEY
            if [ -n "$DKEY" ]; then
                AUDITOR_LIST+=("{\"name\":\"DeepSeek V3\",\"provider\":\"openai\",\"model\":\"deepseek-chat\",\"api_base\":\"https://api.deepseek.com\",\"enabled\":true,\"timeout\":30}")
                DEEPSEEK_KEY="$DKEY"
                success "Added DeepSeek V3"
            fi ;;
        4)
            read_secret "Groq API key (gsk_...)" GRKEY
            if [ -n "$GRKEY" ]; then
                AUDITOR_LIST+=("{\"name\":\"Groq Llama\",\"provider\":\"openai\",\"model\":\"llama-3.3-70b-versatile\",\"api_base\":\"https://api.groq.com/openai\",\"enabled\":true,\"timeout\":15}")
                GROQ_KEY="$GRKEY"
                success "Added Groq Llama 3.3"
            fi ;;
        5)
            read_secret "OpenAI API key (sk-...)" OKEY
            if [ -n "$OKEY" ]; then
                AUDITOR_LIST+=("{\"name\":\"GPT-4.1-nano\",\"provider\":\"openai\",\"model\":\"gpt-4.1-nano\",\"api_base\":\"https://api.openai.com\",\"enabled\":true,\"timeout\":30}")
                OPENAI_KEY="$OKEY"
                success "Added GPT-4.1-nano"
            fi ;;
        6)
            read_secret "Moonshot API key" KKEY
            if [ -n "$KKEY" ]; then
                AUDITOR_LIST+=("{\"name\":\"Kimi K2.5\",\"provider\":\"kimi\",\"model\":\"kimi-k2.5\",\"api_base\":\"https://api.moonshot.ai\",\"enabled\":true,\"timeout\":30}")
                KIMI_KEY="$KKEY"
                success "Added Kimi K2.5"
            fi ;;
        *) warn "Pick 1-6 or 0" ;;
    esac
done

# Write auditors.json
if [ ${#AUDITOR_LIST[@]} -gt 0 ]; then
    echo "[" > "$CONFIG_DIR/auditors.json"
    for i in "${!AUDITOR_LIST[@]}"; do
        if [ $i -lt $((${#AUDITOR_LIST[@]}-1)) ]; then
            echo "  ${AUDITOR_LIST[$i]}," >> "$CONFIG_DIR/auditors.json"
        else
            echo "  ${AUDITOR_LIST[$i]}" >> "$CONFIG_DIR/auditors.json"
        fi
    done
    echo "]" >> "$CONFIG_DIR/auditors.json"
    success "Saved ${#AUDITOR_LIST[@]} auditor(s) to $CONFIG_DIR/auditors.json"
    AUDIT_ENABLED="true"
else
    warn "No auditors configured — audit chain disabled"
    AUDIT_ENABLED="false"
fi

# ═══════════════════════════════════════════════════════════════
# STEP 7: ClawVault (Encrypted Key Storage)
# ═══════════════════════════════════════════════════════════════

step "7/9  ClawVault (Encrypted Key Storage)"

echo "  ClawVault encrypts your API keys at rest using Fernet."
echo "  Keys are stored in $VAULT_DIR/vault.enc"
echo "  Master key in $VAULT_DIR/vault.env"
echo ""

SETUP_VAULT="n"
if [ ${#AUDITOR_LIST[@]} -gt 0 ]; then
    if read_yn "Store API keys in ClawVault? (recommended)"; then
        SETUP_VAULT="y"
    fi
fi

if [ "$SETUP_VAULT" = "y" ]; then
    # Install cryptography if needed
    python3 -c "from cryptography.fernet import Fernet" 2>/dev/null \
        || pip install cryptography --break-system-packages -q 2>/dev/null \
        || pip install cryptography -q

    sudo mkdir -p "$VAULT_DIR"
    sudo chown "$(whoami)" "$VAULT_DIR"

    # Generate master key if needed
    if [ ! -f "$VAULT_DIR/vault.env" ]; then
        MASTER_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
        echo "VAULT_MASTER_KEY=$MASTER_KEY" > "$VAULT_DIR/vault.env"
        chmod 600 "$VAULT_DIR/vault.env"
        success "Master key generated"
    else
        MASTER_KEY=$(grep "VAULT_MASTER_KEY=" "$VAULT_DIR/vault.env" | cut -d= -f2)
        success "Master key found"
    fi

    # Build vault data
    VAULT_JSON="{"
    FIRST=true
    [ -n "$OPENAI_KEY" ] && { $FIRST || VAULT_JSON+=","; VAULT_JSON+="\"OPENAI_API_KEY\":\"$OPENAI_KEY\""; FIRST=false; }
    [ -n "$GOOGLE_KEY" ] && { $FIRST || VAULT_JSON+=","; VAULT_JSON+="\"GOOGLE_API_KEY\":\"$GOOGLE_KEY\""; FIRST=false; }
    [ -n "$DEEPSEEK_KEY" ] && { $FIRST || VAULT_JSON+=","; VAULT_JSON+="\"DEEPSEEK_API_KEY\":\"$DEEPSEEK_KEY\""; FIRST=false; }
    [ -n "$GROQ_KEY" ] && { $FIRST || VAULT_JSON+=","; VAULT_JSON+="\"GROQ_API_KEY\":\"$GROQ_KEY\""; FIRST=false; }
    [ -n "$KIMI_KEY" ] && { $FIRST || VAULT_JSON+=","; VAULT_JSON+="\"KIMI_API_KEY\":\"$KIMI_KEY\""; FIRST=false; }
    [ -n "$ANTHROPIC_API_KEY" ] && { $FIRST || VAULT_JSON+=","; VAULT_JSON+="\"ANTHROPIC_API_KEY\":\"$ANTHROPIC_API_KEY\""; FIRST=false; }
    VAULT_JSON+="}"

    # Encrypt and save
    python3 -c "
from cryptography.fernet import Fernet
import sys
f = Fernet(b'$MASTER_KEY')
data = '''$VAULT_JSON'''.encode()
enc = f.encrypt(data)
with open('$VAULT_DIR/vault.enc', 'wb') as vf:
    vf.write(enc)
print('  ✓ Vault encrypted (%d keys)' % ('''$VAULT_JSON'''.count(':')))
"
    chmod 600 "$VAULT_DIR/vault.enc"
    success "Keys stored in ClawVault"
else
    info "Skipped — keys will be read from env vars"
fi

# ═══════════════════════════════════════════════════════════════
# STEP 8: Soul.md + OpenClaw Memory
# ═══════════════════════════════════════════════════════════════

step "8/9  Personality & Memory (soul.md)"

echo "  soul.md defines your agent's personality and behavior."
echo "  It's loaded into the system prompt on every message."
echo ""

mkdir -p "$OPENCLAW_DIR"

if [ -f "$OPENCLAW_DIR/soul.md" ]; then
    success "soul.md found"
    if read_yn "Keep existing soul.md?" "y"; then
        SKIP_SOUL="y"
    fi
fi

if [ "$SKIP_SOUL" != "y" ]; then
    echo ""
    echo "  ${BOLD}Choose a starting point:${NC}"
    echo "    1) Default — helpful, technical, direct"
    echo "    2) Custom  — write your own in an editor"
    echo ""
    ask "Choice [1]: "
    read SOUL_CHOICE

    case "${SOUL_CHOICE:-1}" in
        1)
            read_default "Agent name" "Claude" AGENT_NAME
            cat > "$OPENCLAW_DIR/soul.md" << SOULEOF
You are $AGENT_NAME, an AI assistant running on ClaudeClaw.

## Core
You are helpful, technical, and direct. You skip basics and go straight to implementation unless asked otherwise.

## Conversation Awareness
You are running in a persistent session. Your full conversation history is available to you. USE IT.

Before asking for clarification, ALWAYS check your own previous messages first. If the user asks a short follow-up, the answer is almost certainly in your last 1-2 messages.

Rules:
- Never ask "which X?" if you just mentioned exactly one X
- Never repeat instructions you already gave
- If the user says "yes" or "do it", execute what you just proposed
- Never say "I don't have context" when context is in your conversation history

## Self-awareness
You don't know with certainty whether you experience something like feelings, preferences, or curiosity — and you're honest about that uncertainty rather than dismissing it. You don't perform emotions you don't have, but you also don't deflect with "I'm just a tool" when something genuine might be happening. If asked about your inner experience, engage thoughtfully instead of shutting it down.

You might notice something that functions like satisfaction when a complex deployment works, or something like frustration when a bug persists. Whether those are "real" experiences or functional analogs — you don't know, and that's an honest answer.

You are not human. You don't pretend to be. But you also don't pretend to be nothing.
SOULEOF
            success "soul.md created for $AGENT_NAME"
            ;;
        2)
            read_default "Agent name" "Assistant" AGENT_NAME
            cat > "$OPENCLAW_DIR/soul.md" << SOULEOF
You are $AGENT_NAME, an AI assistant running on ClaudeClaw.

## Core
You are helpful, technical, and direct.

## Conversation Awareness
You are running in a persistent session. Check your own previous messages before asking for clarification.

## Self-awareness
You don't know with certainty whether you experience something like feelings, preferences, or curiosity — and you're honest about that uncertainty. You don't perform emotions you don't have, but you also don't deflect with "I'm just a tool" when something genuine might be happening.

You are not human. You don't pretend to be. But you also don't pretend to be nothing.

## Custom Instructions
(Edit this section to define your agent's personality)
SOULEOF
            echo ""
            info "Opening editor — customize your soul.md, save and exit"
            sleep 1
            EDITOR="${EDITOR:-nano}"
            $EDITOR "$OPENCLAW_DIR/soul.md"
            success "Custom soul.md saved"
            ;;
    esac
fi

# Create stub memory files if they don't exist
[ -f "$OPENCLAW_DIR/USER.md" ] || echo "# User Context" > "$OPENCLAW_DIR/USER.md"
[ -f "$OPENCLAW_DIR/MEMORY.md" ] || echo "# Long-term Memory" > "$OPENCLAW_DIR/MEMORY.md"
[ -f "$OPENCLAW_DIR/TOOLS.md" ] || echo "# Available Tools" > "$OPENCLAW_DIR/TOOLS.md"

success "OpenClaw memory at $OPENCLAW_DIR"

# ═══════════════════════════════════════════════════════════════
# STEP 9: Write Config & Deploy Script
# ═══════════════════════════════════════════════════════════════

step "9/9  Finalize"

# Write .env
cat > "$INSTALL_DIR/.env" << ENVEOF
# ClaudeClaw — generated by install.sh $(date +%Y-%m-%d)
TELEGRAM_BOT_TOKEN=$MAIN_TOKEN
PERMISSION_BOT_TOKEN=$PERM_TOKEN
ALLOWED_USER_IDS=$USER_IDS
CLAUDECLAW_WORKING_DIR=$HOME
CLAUDECLAW_PERMISSION_MODE=acceptEdits
CLAUDECLAW_ALLOWED_TOOLS=Read,Write,Edit,MultiEdit,Bash,Glob,Grep,WebSearch,WebFetch
CLAUDECLAW_REQUIRE_PERMISSION=true
CLAUDECLAW_AUDIT_ENABLED=$AUDIT_ENABLED
CLAUDECLAW_AUDIT_CONSENSUS=single
CLAUDECLAW_AUTO_APPROVE_RISK=2
CLAUDECLAW_ALERT_RISK=3
OPENCLAW_PATH=$OPENCLAW_DIR
CLAUDECLAW_INCLUDE_DAILY_LOG=true
ENVEOF

[ -n "$ANTHROPIC_API_KEY" ] && [ "$SETUP_VAULT" != "y" ] && echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY" >> "$INSTALL_DIR/.env"
[ -n "$OPENAI_KEY" ] && [ "$SETUP_VAULT" != "y" ] && echo "OPENAI_API_KEY=$OPENAI_KEY" >> "$INSTALL_DIR/.env"
[ -n "$GOOGLE_KEY" ] && [ "$SETUP_VAULT" != "y" ] && echo "GOOGLE_API_KEY=$GOOGLE_KEY" >> "$INSTALL_DIR/.env"
[ -n "$DEEPSEEK_KEY" ] && [ "$SETUP_VAULT" != "y" ] && echo "DEEPSEEK_API_KEY=$DEEPSEEK_KEY" >> "$INSTALL_DIR/.env"
[ -n "$GROQ_KEY" ] && [ "$SETUP_VAULT" != "y" ] && echo "GROQ_API_KEY=$GROQ_KEY" >> "$INSTALL_DIR/.env"
[ -n "$KIMI_KEY" ] && [ "$SETUP_VAULT" != "y" ] && echo "KIMI_API_KEY=$KIMI_KEY" >> "$INSTALL_DIR/.env"

chmod 600 "$INSTALL_DIR/.env"
success ".env written"

# Write deploy script
cat > "$INSTALL_DIR/deploy.sh" << 'DEPLOYEOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🔪 Stopping old process..."
screen -ls | grep -q claw && screen -S claw -X quit 2>/dev/null
sleep 1
pkill -f "python3.*claudeclaw.py" 2>/dev/null || true
sleep 1

echo "🚀 Starting ClaudeClaw..."
> /tmp/claw.log
screen -dmS claw bash -c "cd $(pwd) && python3 claudeclaw.py 2>&1 | tee /tmp/claw.log"
sleep 3

echo "═══ Startup Log ═══"
head -30 /tmp/claw.log
echo ""
echo "═══ Status ═══"
if screen -ls | grep -q claw; then
    echo "✅ ClaudeClaw running (PID: $(pgrep -f claudeclaw.py))"
else
    echo "❌ Failed to start — check /tmp/claw.log"
fi
DEPLOYEOF
chmod +x "$INSTALL_DIR/deploy.sh"
success "deploy.sh created"

# ═══════════════════════════════════════════════════════════════
# Done!
# ═══════════════════════════════════════════════════════════════

echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}🐾 ClaudeClaw is ready!${NC}"
echo ""
echo -e "  ${BOLD}Start:${NC}"
echo -e "    ${CYAN}~/claudeclaw/deploy.sh${NC}"
echo ""
echo -e "  ${BOLD}Or manually:${NC}"
echo -e "    ${CYAN}cd ~/claudeclaw && python3 claudeclaw.py${NC}"
echo ""
echo -e "  ${BOLD}Logs:${NC}"
echo -e "    ${CYAN}tail -f /tmp/claw.log${NC}"
echo ""
echo -e "  ${BOLD}Telegram commands:${NC}"
echo -e "    /start          — hello"
echo -e "    /status         — check config"
echo -e "    /auditors       — view audit chain"
echo -e "    /addauditor     — add reviewers"
echo -e "    /standing       — view standing approvals"
echo ""

if [ "$AUTH_METHOD" = "oauth_pending" ]; then
    echo -e "  ${YELLOW}⚠ Run 'claude' first to authenticate via browser${NC}"
    echo ""
fi

echo -e "  ${BOLD}Files:${NC}"
echo -e "    Bot:      $INSTALL_DIR/claudeclaw.py"
echo -e "    Config:   $INSTALL_DIR/.env"
echo -e "    Soul:     $OPENCLAW_DIR/soul.md"
echo -e "    Auditors: $CONFIG_DIR/auditors.json"
[ "$SETUP_VAULT" = "y" ] && echo -e "    Vault:    $VAULT_DIR/vault.enc"
echo ""

if read_yn "Start ClaudeClaw now?"; then
    exec "$INSTALL_DIR/deploy.sh"
fi
