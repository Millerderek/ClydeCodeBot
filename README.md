# ClaudeClaw

**Telegram → Claude Agent SDK Bridge**

A single-file bot (~1800 LOC) that turns Telegram messages into Claude Code CLI work. Instead of building a new agent platform, ClaudeClaw gives you **mobile remote-control for your existing Claude Code workspace** — same CLAUDE.md, same skills, same MCP servers, same local files.

Uses **Claude Code OAuth** (Pro/Max subscription) by default. No API key required.

Each user gets a **persistent `ClaudeSDKClient` session** — Claude remembers the full conversation across messages, just like chatting in a terminal.

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│  Telegram    │     │   ClaudeClaw     │     │  Your Workstation       │
│  (mobile)    │────▶│   Bridge Bot     │────▶│                         │
│              │◀────│                  │◀────│  ├── CLAUDE.md          │
└─────────────┘     │  SessionManager  │     │  ├── Skills              │
                    │  per-user clients │     │  ├── MCP Servers         │
                    │  with full        │     │  ├── Local Files         │
                    │  conversation     │     │  └── Permissions/Hooks   │
                    │  history          │     └─────────────────────────┘
                    └──────────────────┘
```

## Why?

If you already live inside Claude Code, you're duplicating effort by building:
- A skills engine → **Claude Code already has one**
- A memory system → **CLAUDE.md already does this**
- Integrations → **MCP servers already handle this**
- Orchestration → **The Agent SDK loop already does this**

ClaudeClaw just bridges mobile access to that environment. Improvements apply everywhere.

## Quick Start

### 1. Prerequisites

- Python 3.10+
- Node.js 18+ (for Claude Code CLI)
- A Telegram account

### 2. Create Your Telegram Bot

1. Message [@BotFather](https://t.me/BotFather) → `/newbot`
2. Copy the bot token

### 3. Get Your Telegram User ID

Message [@userinfobot](https://t.me/userinfobot) — it replies with your numeric ID.

### 4. Authenticate Claude Code

```bash
npm install -g @anthropic-ai/claude-code
claude
# Follow the prompts to authenticate via browser
```

This creates an OAuth session that the SDK uses automatically. **No API key needed.**

### 5. Install & Run

```bash
git clone https://github.com/yourusername/claudeclaw.git
cd claudeclaw
pip install -r requirements.txt

cp .env.example .env
# Edit .env: set TELEGRAM_BOT_TOKEN and ALLOWED_USER_IDS

python3 claudeclaw.py
```

### 6. Message Your Bot

Open Telegram, find your bot, send any message.

## Authentication

| Method | Setup | Cost Model |
|--------|-------|------------|
| **Claude Code OAuth** (recommended) | Run `claude` and login once | Uses your Pro/Max subscription |
| API Key | Set `ANTHROPIC_API_KEY` in `.env` | Pay-per-token via API |

## Configuration

All config via environment variables (or `.env` file):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | ✅ | — | Main bot token from @BotFather |
| `ALLOWED_USER_IDS` | ✅ | — | Comma-separated Telegram user IDs |
| `ANTHROPIC_API_KEY` | — | — | Fallback if no OAuth session |
| `PERMISSION_BOT_TOKEN` | — | — | Permission bot (setup wizard on first run) |
| `CLAUDECLAW_WORKING_DIR` | — | `~` | Workspace path |
| `CLAUDECLAW_MODEL` | — | SDK default | Model override |
| `CLAUDECLAW_PERMISSION_MODE` | — | `default` | `default` or `acceptEdits` |
| `CLAUDECLAW_ALLOWED_TOOLS` | — | SDK defaults | Comma-separated tool names |
| `CLAUDECLAW_MAX_TURNS` | — | `0` (unlimited) | Max agent loop turns |
| `CLAUDECLAW_REQUIRE_PERMISSION` | — | `true` | Per-task approval gate |
| `CLAUDECLAW_AUDIT_ENABLED` | — | `true` | Enable audit chain |
| `CLAUDECLAW_AUDIT_CONSENSUS` | — | `single` | `single`, `majority`, `unanimous` |
| `CLAUDECLAW_AUTO_APPROVE_RISK` | — | `2` | Max risk for silent auto-approve |
| `CLAUDECLAW_ALERT_RISK` | — | `3` | Max risk for auto-approve with alert |
| `CLAUDECLAW_AUDITORS` | — | `~/.claudeclaw/auditors.json` | Path to auditors config |
| `OPENCLAW_PATH` | — | — | OpenClaw memory directory |
| `CRASHCART_PATH` | — | — | ClawCrashCart backup directory |

## Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message |
| `/status` | Bot status, auth, memory |
| `/new` | Reset conversation |
| `/memory` | Inspect loaded memory files |
| `/workspace` | List workspace files |
| `/whoami` | Your Telegram ID and auth status |
| `/standing` | List standing approvals |
| `/approve` | Add a standing approval |
| `/revoke` | Remove a standing approval |
| `/auditors` | View audit chain config |

## Security

### Audit Chain

Every tool call is reviewed by independent AI auditors before execution. Multiple models run in parallel to evaluate safety, intent match, and risk.

```
User message → Claude proposes tool → Audit Chain reviews → Decision
                                          │
                                    ┌─────┴─────┐
                                    │ GPT-4.1   │
                                    │ Gemini    │
                                    │ (any model)│
                                    └─────┬─────┘
                                          │
                              ┌───────────┴───────────┐
                              │  Consensus Engine     │
                              │  single / majority /  │
                              │  unanimous            │
                              └───────────┬───────────┘
                                          │
                              ┌───────────┴───────────┐
                              │  Risk Thresholds      │
                              │  ≤2: silent execute   │
                              │  ≤3: execute + alert  │
                              │   4: ask human        │
                              │   5: always block     │
                              └───────────────────────┘
```

Each auditor evaluates: safety, relevance, scope, and prompt injection risk.

Risk scale: 1 (safe read-only) → 5 (critical system changes).

### Model-Agnostic Auditors

Add auditors interactively via Telegram — no config files needed:

```
/addauditor                              → show available presets
/addauditor gpt-4.1-mini sk-proj-xxx     → add from preset + key
/addauditor gemini-2.5-flash AIzaXxx     → add Gemini
/addauditor deepseek-chat sk-xxx         → add DeepSeek
/addauditor groq-llama gsk_xxx           → add Groq

/addauditor custom MyModel openai gpt-4o https://api.openai.com sk-xxx

/toggleauditor GPT-4.1-mini              → enable/disable
/removeauditor GPT-4.1-mini              → remove
/auditors                                → view chain status
```

Available presets: `gpt-4.1-mini`, `gpt-4.1-nano`, `gemini-2.5-flash`, `deepseek-chat`, `groq-llama`, `kimi-k2.5`

Supported providers:
- `openai` — Any OpenAI-compatible API (OpenAI, DeepSeek, Groq, Together, Ollama, etc.)
- `google` — Gemini API
- `kimi` — Moonshot API

Config is auto-saved to `~/.claudeclaw/auditors.json` and persists across restarts.

### API Key Resolution

Keys are resolved in order:
1. **ClawVault** — Encrypted vault at `/etc/openclaw/` (recommended)
2. **Environment variables** — `OPENAI_API_KEY`, `GOOGLE_API_KEY`, etc.
3. **Manual paste** — Interactive prompt at startup

Custom providers auto-try `<PROVIDER_UPPER>_API_KEY` (e.g., `DEEPSEEK_API_KEY`).

### Risk Thresholds (Two-Layer Autonomy)

**Layer 1 — Global threshold:**
- Risk ≤2 + both auditors approve → silent auto-execute
- Risk ≤3 + both approve → auto-execute with notification
- Risk 4 → ask human
- Risk 5 → always block

**Layer 2 — Standing approvals** (override for specific patterns):
```
/approve gmail-sorter skill gmail-sorter 3
/approve nginx bash_prefix systemctl restart nginx 4
```

Format: `/approve <name> <type> <pattern> [max_risk]`

Types: `bash_prefix`, `bash_exact`, `bash_contains`, `tool`, `skill`

Standing approvals persist in `~/.claudeclaw/standing_approvals.json`.

### Dual-Bot Permission System

| Bot | Role |
|-----|------|
| **Main bot** | Your conversation with Claude |
| **Permission bot** | Task approval requests with Approve/Deny buttons |

### Other Protections

- User allowlist via `ALLOWED_USER_IDS`
- Workspace scoping via `CLAUDECLAW_WORKING_DIR`
- Telegram is NOT e2e encrypted — don't send secrets

## OpenClaw Memory Integration

Load [OpenClaw](https://github.com/openclawai/openclaw) memory files as system prompt context:

| File | Role |
|------|------|
| `soul.md` | Personality, constraints, conversation awareness |
| `USER.md` | User context & preferences |
| `MEMORY.md` | Long-term curated facts |
| `TOOLS.md` | Capability map |
| `HEARTBEAT.md` | Autonomous task schedule |
| `memory/YYYY-MM-DD.md` | Today's daily log |

Set `OPENCLAW_PATH` or `CRASHCART_PATH`.

## Docker

```bash
cp .env.example .env
docker compose up -d
```

## Memory Stack (Optional)

Persistent memory via Qdrant vectors, PostgreSQL, and Redis in `memory/`:

```bash
cd memory && bash setup.sh
```

Bundled tools: `openclaw-memo`, `openclaw-custodian`, `clawcrashcart` — all auto-approved.

## How It Works

1. Telegram polling (no inbound ports)
2. Auth check against allowlist
3. Persistent session per user
4. OpenClaw memory loaded into system prompt
5. Audit chain reviews each tool proposal
6. Risk thresholds auto-approve or escalate
7. Agent loop executes tools
8. Response chunked to Telegram

## License

MIT

## VPS Deployment

### Passwordless SSH Setup (PowerShell)

```powershell
# Generate SSH key (skip if you already have one)
ssh-keygen -t rsa -N '""' -f "$env:USERPROFILE\.ssh\id_rsa"

# Copy public key to VPS
type "$env:USERPROFILE\.ssh\id_rsa.pub" | ssh root@YOUR_VPS_IP "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

### Deploy Script

Create `~/claudeclaw/deploy.sh` on your VPS:

```bash
#!/bin/bash
echo "🔪 Stopping old process..."
screen -ls | grep claw && screen -S claw -X quit 2>/dev/null
sleep 1

echo "📦 Installing dependencies..."
cd ~/claudeclaw
pip install -r requirements.txt -q --break-system-packages 2>/dev/null

echo "🚀 Starting ClaudeClaw..."
> /tmp/claw.log
screen -dmS claw bash -c "cd ~/claudeclaw && python3 claudeclaw.py 2>&1 | tee /tmp/claw.log"
sleep 2

echo "═══ Startup Log ═══"
cat /tmp/claw.log
echo ""
echo "═══ Status ═══"
screen -ls | grep claw && echo "✅ ClaudeClaw running (PID: $(pgrep -f claudeclaw.py))" || echo "❌ Failed to start"
```

```bash
chmod +x ~/claudeclaw/deploy.sh
```

### One-Liner Deploy (PowerShell)

```powershell
scp "$env:USERPROFILE\Downloads\claudeclaw.py" root@YOUR_VPS_IP:~/claudeclaw/claudeclaw.py; ssh root@YOUR_VPS_IP "~/claudeclaw/deploy.sh"
```

### Deploy with Auditor Config

```powershell
scp "$env:USERPROFILE\Downloads\claudeclaw.py" root@YOUR_VPS_IP:~/claudeclaw/claudeclaw.py; scp "$env:USERPROFILE\Downloads\auditors.json" root@YOUR_VPS_IP:~/.claudeclaw/auditors.json; ssh root@YOUR_VPS_IP "~/claudeclaw/deploy.sh"
```

### Check Logs

```powershell
ssh root@YOUR_VPS_IP "tail -20 /tmp/claw.log"
ssh root@YOUR_VPS_IP "grep 'Auto-approved\|audit chain' /tmp/claw.log | tail -10"
```
