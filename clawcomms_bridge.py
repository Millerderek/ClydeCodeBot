#!/usr/bin/env python3
"""
clawcomms_bridge.py — ClawComms integration for ClydeCodeBot.

Enrolls clydecodebot as a ClawComms worker, subscribes to its NATS inbox,
and delivers inbound messages to Derek's Telegram chat.

Also exposes send() so clydecodebot can push messages to other agents.

Usage:
    bridge = ClawCommsBridge(bot, chat_id=8260442678)
    await bridge.start()          # in post_init
    await bridge.send("openclaw-prod", {"text": "Hello"})
    await bridge.stop()           # in post_shutdown
"""

import asyncio
import json
import logging
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/root/clawcomms/sdk")
from clawcomms import ClawCommsClient

logger = logging.getLogger("clawcomms-bridge")

# ── Config ────────────────────────────────────────────────────────────────────

BOT_ID          = "clydecodebot"
ROLE            = "assistant"
ENROLLMENT_URL  = "http://172.17.0.1:8001"
NATS_URL        = "nats://clawcomms-nats:4222"
CA_CERT         = "/root/clawcomms/nats/certs/ca.crt"
WRK_FINGERPRINT = "df100808ff0353e720a266036794c5bc19cacf57a9b994c2992c0a3b39b0d5b9"
WRK_PASSPHRASE  = "D3cPRMKHkfuQyXEinRtcCneDLmDzC8zukEQbBtUP"
KEYS_DIR        = "/root/clawcomms/keys"


def _issue_grant(bot_id: str, pubkey_hex: str) -> dict:
    """Issue a WRK-signed enrollment grant via bootstrap-cli container."""
    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", "none",
            "-e", f"RELAY_WRK_PASSPHRASE={WRK_PASSPHRASE}",
            "-v", f"{KEYS_DIR}:/keys",
            "clawcomms-bootstrap-cli:latest",
            "issue-grant",
            "--bot-id",         bot_id,
            "--bot-public-key", pubkey_hex,
            "--role",           ROLE,
            "--ttl",            "900",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"issue-grant failed:\n{result.stderr}")

    lines = result.stdout.strip().split("\n")
    json_lines, in_json = [], False
    for line in lines:
        if line.strip().startswith("{"):
            in_json = True
        if in_json:
            json_lines.append(line)
        if in_json and line.strip() == "}":
            break

    grant = json.loads("\n".join(json_lines))
    logger.info("Grant issued: grant_id=%s expires=%s", grant["grant_id"], grant["expires_at"])
    return grant


class ClawCommsBridge:
    def __init__(self, bot, chat_id: int = 8260442678):
        self._bot     = bot
        self._chat_id = chat_id
        self._client: ClawCommsClient | None = None
        self._task:   asyncio.Task | None    = None
        self._ready   = asyncio.Event()

    # ── Public API ────────────────────────────────────────────────────────────

    async def start(self):
        """Enroll and connect in the background."""
        self._task = asyncio.create_task(self._run(), name="clawcomms-bridge")
        logger.info("ClawComms bridge starting for %s ...", BOT_ID)

    async def stop(self):
        """Gracefully disconnect."""
        if self._client:
            try:
                await self._client.stop()
            except Exception as e:
                logger.warning("ClawComms stop error: %s", e)
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("ClawComms bridge stopped.")

    async def send(self, to: str, payload: dict, message_type: str = "chat") -> bool:
        """
        Send a message to another ClawComms agent.
        Returns True on success, False if not enrolled yet.
        """
        if not self._client or not self._client.is_enrolled:
            logger.warning("ClawComms not ready — message to %s dropped", to)
            return False
        try:
            await self._client.publish(to=to, payload=payload, message_type=message_type)
            logger.info("→ sent to %s [%s]", to, message_type)
            return True
        except Exception as e:
            logger.error("Send to %s failed: %s", to, e)
            return False

    @property
    def is_ready(self) -> bool:
        return self._client is not None and self._client.is_enrolled

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _run(self):
        """Main loop: enroll, subscribe, refresh before expiry."""
        while True:
            try:
                await self._connect()
                # Wait until credential nears expiry (grant TTL 900s → refresh at 800s)
                await asyncio.sleep(800)
                logger.info("ClawComms credential nearing expiry — re-enrolling ...")
                try:
                    await self._client.stop()
                except Exception:
                    pass
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.error("ClawComms bridge error: %s — retrying in 30s", e)
                await asyncio.sleep(30)

    async def _connect(self):
        """Create client, issue grant, enroll, subscribe."""
        self._client = ClawCommsClient(
            enrollment_url   = ENROLLMENT_URL,
            nats_url         = NATS_URL,
            nats_ca_cert     = CA_CERT,
            wrk_fingerprint  = WRK_FINGERPRINT,
            bot_id           = BOT_ID,
            role             = ROLE,
            use_default_policy_rules=False,
        )

        grant = _issue_grant(BOT_ID, self._client.public_key_hex)
        await self._client.start(grant=grant)

        workspace_id = self._client.credential["workspace_id"]
        inbox        = f"relay.{workspace_id}.{BOT_ID}.>"

        await self._client.subscribe(inbox, self._on_message)
        logger.info("ClawComms online: bot=%s session=%s inbox=%s",
                    BOT_ID, self._client.session_id, inbox)
        self._ready.set()

    async def _on_message(self, envelope: dict):
        """Route inbound messages: tasks get executed, everything else goes to Telegram."""
        from_bot     = envelope.get("from_bot", "unknown")
        message_type = envelope.get("message_type", "message")
        payload      = envelope.get("payload", {})
        reply_to     = envelope.get("message_id")

        logger.info("← ClawComms from=%s type=%s", from_bot, message_type)

        # ── Task execution: run prompt through Claude and return result ──
        if message_type == "task" and isinstance(payload, dict) and "prompt" in payload:
            await self._handle_task(envelope)
            return

        # ── Default: relay to Telegram ──
        text = f"📡 *ClawComms* — from `{from_bot}`\n"
        text += f"Type: `{message_type}`\n\n"

        if isinstance(payload, dict):
            for k, v in payload.items():
                text += f"• *{k}*: {v}\n"
        else:
            text += str(payload)

        try:
            await self._bot.send_message(
                chat_id    = self._chat_id,
                text       = text,
                parse_mode = "Markdown",
            )
        except Exception as e:
            logger.error("Telegram delivery failed: %s", e)

    async def _handle_task(self, envelope: dict):
        """Execute a task prompt via the bot's Claude session and return result."""
        from_bot  = envelope.get("from_bot", "unknown")
        payload   = envelope.get("payload", {})
        prompt    = payload.get("prompt", "")
        task_id   = payload.get("task_id", envelope.get("message_id", "unknown"))

        logger.info("TASK from %s: %s", from_bot, prompt[:100])

        # Notify Derek that a task is being executed
        try:
            await self._bot.send_message(
                chat_id    = self._chat_id,
                text       = f"🔧 *ClawComms Task* from `{from_bot}`\n\n_{prompt[:200]}_\n\n⏳ Executing...",
                parse_mode = "Markdown",
            )
        except Exception:
            pass

        # Execute via subprocess — use the bot's Claude connection
        # Run a quick one-shot Claude query via the API
        try:
            import subprocess as sp
            result = sp.run(
                ["python3", "-c", f"""
import anthropic, os, sys
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
resp = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{{"role": "user", "content": {repr(prompt)}}}],
)
print(resp.content[0].text)
"""],
                capture_output=True, text=True, timeout=60,
                env={**dict(__import__("os").environ)},
            )

            if result.returncode == 0:
                answer = result.stdout.strip()
                status = "completed"
            else:
                answer = f"Error: {result.stderr.strip()[:500]}"
                status = "failed"

        except Exception as e:
            answer = f"Execution error: {str(e)}"
            status = "failed"

        logger.info("TASK %s result: %s (%d chars)", task_id, status, len(answer))

        # Send result back to requester via ClawComms
        await self.send(
            to=from_bot,
            payload={
                "task_id": task_id,
                "status":  status,
                "result":  answer[:4000],  # Cap at 4KB for NATS
                "prompt":  prompt[:200],
            },
            message_type="response",
        )

        # Also notify Derek of the result
        try:
            result_preview = answer[:500] + ("..." if len(answer) > 500 else "")
            await self._bot.send_message(
                chat_id    = self._chat_id,
                text       = f"✅ *Task Complete* → `{from_bot}`\n\n{result_preview}",
                parse_mode = "Markdown",
            )
        except Exception:
            pass
