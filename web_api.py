"""
ClydeCodeBot Web API
Exposes an SSE streaming HTTP endpoint so the OpenClaw web app can talk
to the same SessionManager (and therefore the same session) as Telegram.

Listens on 127.0.0.1:8765 — proxied by Next.js API routes, never public.

Endpoints:
  GET  /health          → {"status":"ok"}
  POST /chat            → SSE stream of {"type":"token","text":"…"} + {"type":"done"}
  POST /stop            → cancel active stream for owner → {"ok":true}
"""

import asyncio
import json
import logging
import os

from aiohttp import web

logger = logging.getLogger("web_api")

# ─── Active stream registry ──────────────────────────────────────────────────
# Maps owner_id → the asyncio.Task running query_streaming for that user.
# Allows /stop to cancel mid-flight.
_active_tasks: dict[int, asyncio.Task] = {}


# ─── Token ──────────────────────────────────────────────────────────────────

def _get_token() -> str:
    return os.environ.get("WEB_API_TOKEN", "")


def _check_auth(request: web.Request) -> bool:
    token = _get_token()
    if not token:
        return True  # no token set → open (only safe because it's loopback-only)
    auth = request.headers.get("Authorization", "")
    supplied = auth.removeprefix("Bearer ").strip()
    return supplied == token


# ─── Handlers ───────────────────────────────────────────────────────────────

async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok"})


async def handle_stop(request: web.Request) -> web.Response:
    """Cancel the active streaming task for the owner, if any."""
    if not _check_auth(request):
        return web.json_response({"error": "Unauthorized"}, status=401)

    owner_id = request.app["owner_id"]
    task = _active_tasks.get(owner_id)
    if task and not task.done():
        task.cancel()
        logger.info("Web API: stream cancelled for owner %d", owner_id)
        return web.json_response({"ok": True, "cancelled": True})

    return web.json_response({"ok": True, "cancelled": False})


async def handle_chat(request: web.Request) -> web.StreamResponse:
    if not _check_auth(request):
        return web.json_response({"error": "Unauthorized"}, status=401)

    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    message = body.get("message", "").strip()
    if not message:
        return web.json_response({"error": "message required"}, status=400)

    sessions   = request.app["sessions"]
    owner_id   = request.app["owner_id"]

    # SSE response
    resp = web.StreamResponse(headers={
        "Content-Type":  "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })
    await resp.prepare(request)

    client_gone = False

    async def send(chunk: dict):
        nonlocal client_gone
        if client_gone:
            return
        try:
            await resp.write(f"data: {json.dumps(chunk)}\n\n".encode())
        except Exception:
            client_gone = True  # client disconnected — stop writing, don't raise

    # Phase tracking: on_text is called with different content shapes across phases:
    #   thinking  → "⏳ Thinking...\n\n<accumulated thinking>"
    #   tool_use  → "🔧 Tool1, Tool2…"
    #   response  → plain accumulated response text (resets to "" each turn)
    # prev_len tracks the last write position within the CURRENT phase's string.
    prev_len = 0
    prev_phase: str = ''

    async def on_text(accumulated: str):
        nonlocal prev_len, prev_phase

        if accumulated.startswith('⏳ Thinking...'):
            if prev_phase != 'thinking':
                prev_phase = 'thinking'
                prev_len = len('⏳ Thinking...\n\n')  # skip static prefix
            new_text = accumulated[prev_len:]
            if new_text:
                await send({"type": "thinking", "text": new_text})
                prev_len = len(accumulated)

        elif accumulated.startswith('🔧'):
            prev_phase = 'tool'
            prev_len = 0
            await send({"type": "tool_status", "text": accumulated})

        else:
            # Response text — resets each query turn
            if prev_phase != 'response':
                prev_phase = 'response'
                prev_len = 0
            new_text = accumulated[prev_len:]
            if new_text:
                await send({"type": "token", "text": new_text})
                prev_len = len(accumulated)

    # Wrap query_streaming in a Task so /stop can cancel it
    async def run_query():
        await sessions.query_streaming(owner_id, message, on_text=on_text)

    task = asyncio.create_task(run_query())
    _active_tasks[owner_id] = task

    try:
        await task
        await send({"type": "done", "messageId": ""})
    except asyncio.CancelledError:
        logger.info("Web API: stream for owner %d was cancelled", owner_id)
        await send({"type": "stopped"})
    except Exception as e:
        logger.error("Web API stream error: %s", e)
        await send({"type": "error", "error": str(e)})
    finally:
        _active_tasks.pop(owner_id, None)

    await resp.write_eof()
    return resp


# ─── App factory ────────────────────────────────────────────────────────────

def create_app(sessions, owner_id: int) -> web.Application:
    app = web.Application()
    app["sessions"] = sessions
    app["owner_id"] = owner_id
    app.router.add_get("/health", handle_health)
    app.router.add_post("/chat",   handle_chat)
    app.router.add_post("/stop",   handle_stop)
    return app


async def start_web_api(sessions, owner_id: int, port: int = 8765):
    """Start the aiohttp server in the current event loop (non-blocking)."""
    app = create_app(sessions, owner_id)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    logger.info("Web API listening on http://127.0.0.1:%d", port)
    return runner  # caller holds reference to prevent GC
