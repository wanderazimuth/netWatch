"""Log every event; push the ones your alert settings ask for to ntfy."""

from __future__ import annotations

import json
import logging
import sqlite3
import urllib.request
from datetime import datetime, time as dtime

from . import db
from . import settings as settings_mod
from .scanner import is_randomized_mac
from .tracker import Event

log = logging.getLogger(__name__)

MESSAGES = {
    "new": "New device joined: {name} ({details})",
    "online": "{name} is back online ({ip})",
    "offline": "{name} left the network",
    "ip_change": "{name} changed IP to {ip}",
    "down": "{name} has been offline for {duration}",
    "up": "{name} is back online after {duration}",
    "port": "{name} ({ip}) has a new open port: {port}",
    "router_mac": "The router ({ip}) answered from a MAC address it doesn't use: {who}, {detail}."
                  " Something on the network may be posing as the router (ARP spoofing).",
    "ip_conflict": "Two devices are answering for {ip}: {detail}",
    "rogue_dhcp": "A second DHCP server is handing out addresses: {ip}, from {who}{offering}."
                  " Devices that take its offer could be sent to the wrong router or DNS.",
}
TITLES = {"new": "New device on the network", "online": "Device arrived", "offline": "Device left",
          "down": "Device down", "up": "Device back up", "port": "New open port",
          "router_mac": "Something may be posing as the router", "ip_conflict": "IP address conflict",
          "rogue_dhcp": "Rogue DHCP server"}
TAGS = {"new": "warning", "online": "house", "offline": "wave", "down": "rotating_light", "up": "white_check_mark",
        "port": "unlock", "router_mac": "shield", "ip_conflict": "shield", "rogue_dhcp": "shield"}
SECURITY = ("router_mac", "ip_conflict", "rogue_dhcp")
MAX_LINES = 10
DIGEST_DAYS = 7  # the digest lists devices still to review that were seen this recently


def format_duration(seconds: int) -> str:
    minutes = max(1, round(seconds / 60))
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    return f"{days} d {hours} h" if hours else f"{days} d"


def format_event(e: Event) -> str:
    details = ", ".join(x for x in (e.ip, e.connection, e.mac) if x)
    duration = format_duration(e.seconds) if e.seconds is not None else ""
    who = f"{e.name} ({e.mac})" if e.name != e.mac else e.mac
    offering = f", offering {e.detail}" if e.detail else ""
    text = MESSAGES[e.kind].format(name=e.name, ip=e.ip, details=details, duration=duration, port=e.port,
                                   who=who, detail=e.detail, offering=offering)
    if e.kind == "new" and is_randomized_mac(e.mac):
        text += " [private MAC -- may be a known phone]"
    return text


def in_quiet_hours(now: datetime, start: str, end: str) -> bool:
    if not start or not end or start == end:
        return False
    s, e, t = dtime.fromisoformat(start), dtime.fromisoformat(end), now.time()
    # A window like 22:00-07:00 wraps past midnight.
    return s <= t < e if s < e else t >= s or t < e


def plan(events: list[Event], settings: dict, watched: set[str], now: datetime) -> tuple[list[Event], str | None]:
    """Choose which events to push and the ntfy priority. Priority None means send nothing."""
    if not settings["enabled"] or now.timestamp() < settings["snooze_until"]:
        return [], None
    chosen = []
    for e in events:
        if e.kind == "new":
            if settings["new_devices"] and (settings["private_macs"] or not is_randomized_mac(e.mac)):
                chosen.append(e)
        elif e.kind in ("online", "offline"):
            if settings["watched"] and e.mac in watched:
                chosen.append(e)
        elif e.kind in ("down", "up"):
            # Only devices with an offline alert set produce these.
            if settings["down_alerts"]:
                chosen.append(e)
        elif e.kind == "port":
            if settings["port_alerts"]:
                chosen.append(e)
        elif e.kind in SECURITY:
            if settings["security_alerts"]:
                chosen.append(e)
    if not chosen:
        return [], None
    if in_quiet_hours(now, settings["quiet_start"], settings["quiet_end"]):
        return (chosen, "min") if settings["quiet_mode"] == "silent" else ([], None)
    return chosen, "high" if any(e.kind == "down" or e.kind in SECURITY for e in chosen) else "default"


def build_message(events: list[Event]) -> tuple[str, str, str]:
    """One notification per scan: (title, body, tags)."""
    if len(events) == 1:
        e = events[0]
        return TITLES[e.kind], format_event(e), TAGS[e.kind]
    lines = [format_event(e) for e in events[:MAX_LINES]]
    if len(events) > MAX_LINES:
        lines.append(f"...and {len(events) - MAX_LINES} more")
    kinds = {e.kind for e in events}
    tags = next((TAGS[k] for k in ("router_mac", "rogue_dhcp", "down", "ip_conflict", "new", "port") if k in kinds),
                TAGS[events[0].kind])
    return f"{len(events)} network changes", "\n".join(lines), tags


def actions(events: list[Event], dashboard_url: str, can_pause: bool = False) -> list[dict]:
    """ntfy buttons for an alert with new devices: review one, call it a guest, or pause it for an hour.
    A security problem gets a button to the security page first (ntfy shows at most three).

    The phone's ntfy app makes the Guest and Pause requests itself, so they need dashboard_url to be
    an address the phone can reach (the tailnet name).
    """
    if not dashboard_url:
        return []
    base = dashboard_url.rstrip("/")
    first = ([{"action": "view", "label": "Security", "url": base + "/#/security", "clear": True}]
             if any(e.kind in SECURITY for e in events) else [])
    return (first + new_device_actions(events, base, can_pause))[:3]


def new_device_actions(events: list[Event], base: str, can_pause: bool) -> list[dict]:
    new = [e for e in events if e.kind == "new"]
    if not new:
        return []
    if len(new) > 1:
        return [{"action": "view", "label": "Review devices", "url": base + "/#/review", "clear": True}]
    mac = new[0].mac
    post = {"action": "http", "method": "POST", "headers": {"Content-Type": "application/json"}, "clear": True}
    buttons = [
        {"action": "view", "label": "Review", "url": f"{base}/#/review/{mac}", "clear": True},
        {**post, "label": "Guest", "url": f"{base}/api/devices/{mac}/review", "body": json.dumps({"status": "guest"})},
    ]
    if can_pause:
        buttons.append({**post, "label": "Pause 1 h", "url": f"{base}/api/devices/{mac}/pause",
                        "body": json.dumps({"minutes": 60})})
    return buttons


def push(ntfy_url: str, title: str, body: str, priority: str = "default", tags: str = "", click: str = "",
         buttons: list[dict] | None = None) -> None:
    req = urllib.request.Request(ntfy_url, data=body.encode(), method="POST")
    # Header values must be latin-1; device names can contain anything.
    req.add_header("Title", title.encode("latin-1", "replace").decode("latin-1"))
    req.add_header("Priority", priority)
    if tags:
        req.add_header("Tags", tags)
    if click:
        req.add_header("Click", click)
    if buttons:
        # ntfy takes the JSON form of actions in the header too; json.dumps keeps it ASCII.
        req.add_header("Actions", json.dumps(buttons))
    urllib.request.urlopen(req, timeout=10).close()


def heartbeat(url: str) -> bool:
    """Ping a dead-man's-switch monitor, which alerts you when the pings stop."""
    try:
        urllib.request.urlopen(url, timeout=10).close()
        return True
    except Exception as e:
        log.debug("heartbeat ping failed: %s", e)
        return False


def send(events: list[Event], conn: sqlite3.Connection, ntfy_url: str = "", click: str = "",
         now: datetime | None = None, can_pause: bool = False) -> None:
    for e in events:
        log.info(format_event(e))
    if not ntfy_url or not events:
        return
    watched = {r["mac"] for r in conn.execute("SELECT mac FROM devices WHERE notify = 1")}
    chosen, priority = plan(events, settings_mod.load(conn), watched, now or datetime.now())
    if not chosen:
        return
    title, body, tags = build_message(chosen)
    try:
        push(ntfy_url, title, body, priority, tags, click, actions(chosen, click, can_pause))
    except Exception:
        log.exception("ntfy notification failed")


def digest(conn: sqlite3.Connection, ntfy_url: str = "", dashboard_url: str = "", now: datetime | None = None) -> None:
    """Once a day at the digest time, push a list of recently seen devices that are still to review."""
    now = now or datetime.now()
    s = settings_mod.load(conn)
    if not ntfy_url or not s["digest"] or not s["enabled"] or now.timestamp() < s["snooze_until"]:
        return
    today = now.date().isoformat()
    # Kept beside the settings but not one of them, so the dashboard can't change it.
    sent = conn.execute("SELECT value FROM settings WHERE key = 'digest_sent'").fetchone()
    if now.time() < dtime.fromisoformat(s["digest"]) or (sent and json.loads(sent["value"]) == today):
        return
    rows = conn.execute("SELECT * FROM devices WHERE status IS NULL AND last_seen >= ? ORDER BY last_seen DESC",
                        (int(now.timestamp()) - DIGEST_DAYS * 86400,)).fetchall()
    # Marked before pushing, so a failing push doesn't retry every scan.
    conn.execute("INSERT INTO settings (key, value) VALUES ('digest_sent', ?)"
                 " ON CONFLICT(key) DO UPDATE SET value = excluded.value", (json.dumps(today),))
    conn.commit()
    if not rows:
        return
    lines = [db.display_name(r) for r in rows[:MAX_LINES]]
    if len(rows) > MAX_LINES:
        lines.append(f"...and {len(rows) - MAX_LINES} more")
    title = f"{len(rows)} device{'s' if len(rows) > 1 else ''} to review"
    buttons = ([{"action": "view", "label": "Review", "url": dashboard_url.rstrip("/") + "/#/review", "clear": True}]
               if dashboard_url else None)
    try:
        push(ntfy_url, title, "Seen this week, not reviewed yet:\n" + "\n".join(lines), "low", "mag",
             dashboard_url, buttons)
    except Exception:
        log.exception("ntfy digest failed")
