# ClydeCodeBot

Telegram-to-Claude Agent SDK bridge. Single-file Python bot (~1800 LOC).

## Architecture
- `clydecodebot.py` — entire bot
- Uses `ClaudeSDKClient` for persistent per-user conversation sessions
- Polling-based (no inbound ports needed)
- Auth: Claude Code OAuth (subscription) preferred, API key fallback
- OpenClaw memory files loaded as system prompt context

## Key Components
- `Config.from_env()` — all config from env vars / .env
- `PermissionGate` — per-task OTP approval via Telegram
- `AuditChain` — independent AI model review of tool proposals
- `StandingApprovalStore` — persistent pre-approved patterns
- `SessionManager` — per-user ClaudeSDKClient instances
- `resolve_auditor_keys()` — ClawVault → env → manual key resolution
- `build_default_audit_chain()` — loads from ~/.clydecodebot/auditors.json

## Audit Flow
1. Claude proposes a tool call
2. AuditChain sends to all active auditors in parallel
3. Each auditor returns verdict (approve/deny/warn), risk (1-5), concerns
4. Consensus computed (single/majority/unanimous)
5. Risk thresholds determine: auto-approve, alert, or ask human
6. Standing approvals can override global thresholds

## Testing
- `python3 -c "import ast; ast.parse(open('clydecodebot.py').read()); print('OK')"`
- Send `/start` to your bot on Telegram after launching
- `/auditors` to verify audit chain config
- `/standing` to view standing approvals
