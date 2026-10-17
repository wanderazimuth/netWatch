"""Log every event; push the ones your alert settings ask for to ntfy."""

from __future__ import annotations

import logging
import sqlite3
import urllib.request
from datetime import datetime, time as dtime

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
}
TITLES = {"new": "New device on the network", "online": "Device arrived", "offline": "Device left",
          "down": "Device down", "up": "Device back up"}
TAGS = {"new": "warning", "online": "house", "offline": "wave", "down": "rotating_light", "up": "white_check_mark"}
MAX_LINES = 10


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
    text = MESSAGES[e.kind].format(name=e.name, ip=e.ip, details=details, duration=duration)
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
    if not chosen:
        return [], None
    if in_quiet_hours(now, settings["quiet_start"], settings["quiet_end"]):
        return (chosen, "min") if settings["quiet_mode"] == "silent" else ([], None)
    return chosen, "high" if any(e.kind == "down" for e in chosen) else "default"


def build_message(events: list[Event]) -> tuple[str, str, str]:
    """One notification per scan: (title, body, tags)."""
    if len(events) == 1:
        e = events[0]
        return TITLES[e.kind], format_event(e), TAGS[e.kind]
    lines = [format_event(e) for e in events[:MAX_LINES]]
    if len(events) > MAX_LINES:
        lines.append(f"...and {len(events) - MAX_LINES} more")
    kinds = {e.kind for e in events}
    tags = next((TAGS[k] for k in ("down", "new") if k in kinds), TAGS[events[0].kind])
    return f"{len(events)} network changes", "\n".join(lines), tags


def push(ntfy_url: str, title: str, body: str, priority: str = "default", tags: str = "", click: str = "") -> None:
    req = urllib.request.Request(ntfy_url, data=body.encode(), method="POST")
    # Header values must be latin-1; device names can contain anything.
    req.add_header("Title", title.encode("latin-1", "replace").decode("latin-1"))
    req.add_header("Priority", priority)
    if tags:
        req.add_header("Tags", tags)
    if click:
        req.add_header("Click", click)
    urllib.request.urlopen(req, timeout=10).close()


def send(events: list[Event], conn: sqlite3.Connection, ntfy_url: str = "", click: str = "",
         now: datetime | None = None) -> None:
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
        push(ntfy_url, title, body, priority, tags, click)
    except Exception:
        log.exception("ntfy notification failed")
