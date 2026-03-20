#!/usr/bin/env python3
"""
ha_panel.py — Live Home Assistant control panel for ClydeCodeBot.

Provides:
  get_states()       → list of {entity_id, friendly_name, state, domain}
  toggle_entity(id)  → POST toggle service call
  build_keyboard()   → InlineKeyboardMarkup (2 cols + Refresh row)
  build_header()     → short Markdown header string

Auth: HA_URL / HA_TOKEN from environment (set in .env, loaded by load_dotenv()
      inside main() before any handler runs — credentials resolved lazily so
      this module is safe to import before dotenv has been called).
Domains covered: light.*, switch.* (incl. plugs), fan.*
New devices auto-appear on next /ha or Refresh — no code changes needed.
"""
import os
import requests
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

# ── Constants ─────────────────────────────────────────────────────────────────
DOMAINS      = ("light", "switch", "fan")
DOMAIN_EMOJI = {"light": "💡", "switch": "🔌", "fan": "🌀"}

# Entity IDs to always hide from the panel
BLOCKED_ENTITIES = {
    "light.anj_12kp_inverter_bridge_status_led",
    "light.garage_mini_split_backlight",
    "switch.pool_pump_switch_1",
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _ha_creds():
    """Resolve HA credentials lazily (after dotenv has been loaded in main())."""
    url   = os.environ.get("HA_URL", "http://localhost:8123").rstrip("/")
    token = os.environ.get("HA_TOKEN", "")
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type":  "application/json",
    }
    return url, headers


def _service_domain(entity_id: str) -> str:
    """Return the HA service domain for a given entity_id."""
    d = entity_id.split(".")[0]
    return d if d in ("light", "switch", "fan") else "homeassistant"


# ── Public API ────────────────────────────────────────────────────────────────
def get_states() -> list:
    """
    Fetch current state of all lights, switches (plugs), and fans from HA.
    Returns a list sorted by friendly_name, each entry:
      {entity_id, friendly_name, state, domain}
    """
    url, headers = _ha_creds()
    resp = requests.get(url + "/api/states", headers=headers, timeout=10)
    resp.raise_for_status()
    results = []
    for s in sorted(
        resp.json(),
        key=lambda x: x["attributes"].get("friendly_name", x["entity_id"]).lower(),
    ):
        domain = s["entity_id"].split(".")[0]
        if domain not in DOMAINS:
            continue
        if s["entity_id"] in BLOCKED_ENTITIES:
            continue
        # For switches: only include actual plugs/outlets (device_class == "outlet"/"plug")
        # Lights and fans are always included
        if domain == "switch":
            dc = s["attributes"].get("device_class", "")
            if dc not in ("outlet", "plug"):
                continue
        results.append({
            "entity_id":    s["entity_id"],
            "friendly_name": s["attributes"].get("friendly_name", s["entity_id"]),
            "state":        s["state"],
            "domain":       domain,
        })
    return results


def toggle_entity(entity_id: str) -> None:
    """Toggle a device on/off via HA service API."""
    url, headers = _ha_creds()
    domain = _service_domain(entity_id)
    resp = requests.post(
        url + "/api/services/%s/toggle" % domain,
        json={"entity_id": entity_id},
        headers=headers,
        timeout=10,
    )
    resp.raise_for_status()


def build_keyboard(states: list) -> InlineKeyboardMarkup:
    """
    Build a 2-column inline keyboard.
    Each button shows current state; tapping sends ha_toggle:{entity_id}.
    Final row is a single Refresh button.
    """
    buttons = []
    for d in states:
        emoji = DOMAIN_EMOJI.get(d["domain"], "🔘")
        st    = d["state"]
        label = st.upper() if st in ("on", "off") else "N/A"
        name  = d["friendly_name"][:18]
        buttons.append(
            InlineKeyboardButton(
                "%s %s ● %s" % (emoji, name, label),
                callback_data="ha_toggle:" + d["entity_id"],
            )
        )
    rows = [buttons[i : i + 2] for i in range(0, len(buttons), 2)]
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data="ha_refresh")])
    return InlineKeyboardMarkup(rows)


def build_header(states: list) -> str:
    """Return a short Markdown header showing on/total device count."""
    on_count = sum(1 for d in states if d["state"] == "on")
    return "🏠 *Home Assistant*\n_%d of %d devices on\\. Tap to toggle\\._" % (
        on_count, len(states)
    )
