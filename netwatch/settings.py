"""Alert settings and the people list, stored in the database so the dashboard can change them live."""

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
    "security_alerts": True,  # router impersonation, IP conflicts, rogue DHCP servers
    "quiet_start": "",  # "HH:MM" local time; empty = no quiet hours
    "quiet_end": "",
    "quiet_mode": "silent",  # during quiet hours: "silent" (no sound) or "skip" (don't send)
    "snooze_until": 0,  # unix seconds; no alerts before this
    "digest": "",  # "HH:MM": a daily alert listing devices still to review; empty = off
    "speed_tests": True,  # hourly internet speed tests
    "speed_busy_mbps": 1,  # skip a test while any device people use moves more than this
    "speed_plan_mbps": 0,  # the download speed your plan promises, drawn on the graph; 0 = none
    "away_after": 60,  # minutes all of a person's phones must be gone before they count as away
    "people": ["Roy", "Shanna", "Shaleece", "Spencer", "Fenly"],  # who a device can belong to
}
MAX_PEOPLE, MAX_PERSON = 30, 32

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
        elif key in ("quiet_start", "quiet_end", "digest"):
            if value != "" and not (isinstance(value, str) and TIME.fullmatch(value)):
                raise ValueError(f"{key} must be HH:MM or empty")
        elif key == "quiet_mode":
            if value not in ("silent", "skip"):
                raise ValueError("quiet_mode must be 'silent' or 'skip'")
        elif key == "people":
            if not isinstance(value, list) or not all(isinstance(p, str) for p in value):
                raise ValueError("people must be a list of names")
            value = [p.strip()[:MAX_PERSON] for p in value if p.strip()]
            if len(set(value)) != len(value):
                raise ValueError("people has the same name twice")
            if len(value) > MAX_PEOPLE:
                raise ValueError(f"people can have at most {MAX_PEOPLE} names")
        elif key in ("speed_busy_mbps", "speed_plan_mbps"):
            low = 0.1 if key == "speed_busy_mbps" else 0
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not low <= value <= 10000:
                raise ValueError(f"{key} must be a number from {low} to 10000")
        elif key == "away_after":
            if not isinstance(value, int) or isinstance(value, bool) or not 10 <= value <= 720:
                raise ValueError("away_after must be 10 to 720 minutes")
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
