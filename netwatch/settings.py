"""Alert settings, stored in the database so the dashboard can change them live."""

from __future__ import annotations

import json
import re
import sqlite3

DEFAULTS = {
    "enabled": True,  # master switch for push alerts
    "new_devices": True,  # alert when a never-seen device joins
    "private_macs": True,  # ...including devices using randomized (privacy) MACs
    "watched": True,  # alert when devices you've belled come online / go offline
    "down_alerts": True,  # alert when a device with an offline alert has been unseen too long
    "port_alerts": True,  # alert when the weekly port scan finds a newly opened port
    "quiet_start": "",  # "HH:MM" local time; empty = no quiet hours
    "quiet_end": "",
    "quiet_mode": "silent",  # during quiet hours: "silent" (no sound) or "skip" (don't send)
    "snooze_until": 0,  # unix seconds; no alerts before this
}

TIME = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d")


def load(conn: sqlite3.Connection) -> dict:
    settings = dict(DEFAULTS)
    for row in conn.execute("SELECT key, value FROM settings"):
        if row["key"] in settings:
            settings[row["key"]] = json.loads(row["value"])
    return settings


def validate(updates: dict) -> dict:
    """Return the cleaned updates, or raise ValueError naming the bad field."""
    clean = {}
    for key, value in updates.items():
        if key not in DEFAULTS:
            raise ValueError(f"unknown setting {key!r}")
        default = DEFAULTS[key]
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
        elif key in ("quiet_start", "quiet_end"):
            if value != "" and not (isinstance(value, str) and TIME.fullmatch(value)):
                raise ValueError(f"{key} must be HH:MM or empty")
        elif key == "quiet_mode":
            if value not in ("silent", "skip"):
                raise ValueError("quiet_mode must be 'silent' or 'skip'")
        elif key == "snooze_until":
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("snooze_until must be a unix timestamp")
        clean[key] = value
    return clean


def save(conn: sqlite3.Connection, updates: dict) -> dict:
    clean = validate(updates)
    conn.executemany(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [(k, json.dumps(v)) for k, v in clean.items()],
    )
    conn.commit()
    return load(conn)
