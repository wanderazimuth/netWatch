"""Pause schedules: pause a device, or all of a person's pausable devices, at set times each week.

The scanner applies them every minute (run). A schedule's pause ends when its window does. If someone
resumes a device by hand during a window, sched_skip_until keeps the schedule from pausing it again
until that window is over.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from datetime import datetime, time, timedelta

from . import db
from . import pause as pause_mod

log = logging.getLogger(__name__)

MAX_SCHEDULES = 50
FIELDS = ("mac", "person", "days", "start", "end", "enabled")
TIME = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d")
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def windows(s, now: int, days_ahead: int = 8):
    """Each time s runs, as (start, end) unix times, from the one running at now (or the next one) on.

    A window starts on each of its days at start and ends at the next end: the same day, or the next
    morning when end is earlier than start. Local time, so a window keeps its clock times across DST.
    """
    days = {int(c) for c in s["days"]}
    begin_min = _minutes(s["start"])
    length = timedelta(minutes=(_minutes(s["end"]) - begin_min) % 1440)
    today = datetime.fromtimestamp(now).date()
    for offset in range(-1, days_ahead):
        day = today + timedelta(days=offset)
        if day.weekday() not in days:
            continue
        begin = datetime.combine(day, time(begin_min // 60, begin_min % 60))
        a, b = int(begin.timestamp()), int((begin + length).timestamp())
        if b > now:
            yield a, b


def next_window(s, now: int) -> tuple[int, int] | None:
    """The window running now or the next one, leaving out skipped ones. None if it's switched off."""
    if not s["enabled"]:
        return None
    return next(((a, b) for a, b in windows(s, now) if not (s["skip_until"] and b <= s["skip_until"])), None)


def active_until(s, now: int) -> int | None:
    """When the window running now ends, or None if s isn't running now."""
    w = next_window(s, now)
    return w[1] if w and w[0] <= now else None


def targets(conn: sqlite3.Connection, s) -> list[sqlite3.Row]:
    if s["mac"]:
        return conn.execute("SELECT * FROM devices WHERE mac = ?", (s["mac"],)).fetchall()
    return conn.execute("SELECT * FROM devices WHERE person = ?", (s["person"],)).fetchall()


def for_device(conn: sqlite3.Connection, row) -> list[sqlite3.Row]:
    """The schedules that cover a device: its own, and its person's."""
    return conn.execute("SELECT * FROM schedules WHERE mac = ? OR (mac IS NULL AND person = ?) ORDER BY id",
                        (row["mac"], row["person"])).fetchall()


def running_for(conn: sqlite3.Connection, row, now: int) -> int | None:
    """When the latest of the device's schedules running now ends, or None if none is."""
    ends = [e for e in (active_until(s, now) for s in for_device(conn, row)) if e is not None]
    return max(ends, default=None)


def plan(conn: sqlite3.Connection, now: int, listed: frozenset[str]) -> tuple[dict[str, tuple[int, int]], list[str]]:
    """What the schedules need changed: {mac: (until, schedule id)} to pause, and the MACs to resume.

    A pause by hand that lasts longer than the schedule's is left alone; a shorter one is stretched.
    A scheduled pause whose schedule has stopped (deleted, edited, skipped, switched off) is lifted.
    """
    wanted: dict[str, tuple[int, int]] = {}
    for s in conn.execute("SELECT * FROM schedules WHERE enabled = 1 ORDER BY id").fetchall():
        end = active_until(s, now)
        if end is None:
            continue
        for r in targets(conn, s):
            if pause_mod.allowed(r, listed) and (r["sched_skip_until"] or 0) <= now:
                if r["mac"] not in wanted or wanted[r["mac"]][0] < end:
                    wanted[r["mac"]] = (end, s["id"])
    to_pause, to_resume = {}, []
    for r in conn.execute("SELECT * FROM devices WHERE ip IS NOT NULL OR paused_ip IS NOT NULL").fetchall():
        w = wanted.get(r["mac"])
        if w is None:
            if r["paused_ip"] and r["paused_by"] is not None:
                to_resume.append(r["mac"])
        elif not r["paused_ip"]:
            if r["ip"]:
                to_pause[r["mac"]] = w
        elif r["paused_by"] is not None:
            if (r["paused_until"], r["paused_by"]) != w:
                to_pause[r["mac"]] = w
        elif r["paused_until"] is not None and r["paused_until"] < w[0]:
            to_pause[r["mac"]] = w
    return to_pause, to_resume


def run(conn: sqlite3.Connection, admin_session, now: int, listed: frozenset[str]) -> bool:
    """Start and end scheduled pauses. admin_session() opens a Pi-hole admin session (a context
    manager), and is only called when something needs changing. Returns True if Pi-hole changed."""
    to_pause, to_resume = plan(conn, now, listed)
    if not to_pause and not to_resume:
        return False
    with admin_session() as admin:
        for mac, (until, sid) in to_pause.items():
            pause_mod.pause(conn, admin, mac, until, sid)
        for mac in to_resume:
            pause_mod.resume(conn, admin, mac)
    return True


def clean(body: dict, people: list[str], conn: sqlite3.Connection) -> dict:
    """The columns for a new or edited schedule, or raise ValueError naming the bad field."""
    unknown = set(body) - set(FIELDS)
    if unknown:
        raise ValueError(f"unknown field {sorted(unknown)[0]!r}")
    mac, person = body.get("mac"), body.get("person")
    if (mac is None) == (person is None):
        raise ValueError("a schedule is for a device (mac) or a person, not both")
    if mac is not None:
        if not (isinstance(mac, str) and MAC.fullmatch(mac)):
            raise ValueError("mac must be a MAC address")
        if conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac,)).fetchone() is None:
            raise ValueError("unknown device")
    elif person not in people:
        raise ValueError("person must be someone on the people list")
    days = body.get("days")
    if not (isinstance(days, list) and days and all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6
                                                    for d in days)):
        raise ValueError("days must be a list of weekdays, 0 (Monday) to 6 (Sunday)")
    for key in ("start", "end"):
        if not (isinstance(body.get(key), str) and TIME.fullmatch(body[key])):
            raise ValueError(f"{key} must be HH:MM")
    if body["start"] == body["end"]:
        raise ValueError("start and end must be different times")
    enabled = body.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be true or false")
    return {"mac": mac, "person": person, "days": "".join(str(d) for d in sorted(set(days))),
            "start": body["start"], "end": body["end"], "enabled": int(enabled)}


def to_json(conn: sqlite3.Connection, s, now: int, listed: frozenset[str]) -> dict:
    devices = targets(conn, s)
    w = next_window(s, now)
    return {
        "id": s["id"], "mac": s["mac"], "person": s["person"],
        "name": s["person"] or (db.display_name(devices[0]) if devices else s["mac"]),
        "days": [int(c) for c in s["days"]], "start": s["start"], "end": s["end"],
        "enabled": bool(s["enabled"]), "skip_until": s["skip_until"],
        "running": bool(w and w[0] <= now), "next": list(w) if w else None,
        # What it covers that can actually be paused; the rest it can't touch.
        "devices": [{"mac": r["mac"], "name": db.display_name(r), "pausable": pause_mod.allowed(r, listed)}
                    for r in devices],
    }


def all_json(conn: sqlite3.Connection, now: int, listed: frozenset[str]) -> list[dict]:
    return [to_json(conn, s, now, listed) for s in conn.execute("SELECT * FROM schedules ORDER BY id").fetchall()]


def save(conn: sqlite3.Connection, sid: int | None, cols: dict) -> int:
    if sid is None:
        if conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] >= MAX_SCHEDULES:
            raise ValueError(f"at most {MAX_SCHEDULES} schedules")
        sid = conn.execute("INSERT INTO schedules (mac, person, days, start, end, enabled) VALUES (?, ?, ?, ?, ?, ?)",
                           tuple(cols.values())).lastrowid
    else:
        # Editing starts it afresh, so a skip made for the old times doesn't hang around.
        cur = conn.execute(f"UPDATE schedules SET {', '.join(k + ' = ?' for k in cols)}, skip_until = NULL WHERE id = ?",
                           (*cols.values(), sid))
        if not cur.rowcount:
            raise LookupError("unknown schedule")
    conn.commit()
    return sid


def skip(conn: sqlite3.Connection, sid: int, now: int, skipping: bool) -> None:
    """Skip the window running now or the next one ("Skip tonight"), or undo that."""
    s = conn.execute("SELECT * FROM schedules WHERE id = ?", (sid,)).fetchone()
    if s is None:
        raise LookupError("unknown schedule")
    until = None
    if skipping:
        w = next_window(s, now)
        if w is None:
            raise ValueError("it isn't switched on")
        until = w[1]
    conn.execute("UPDATE schedules SET skip_until = ? WHERE id = ?", (until, sid))
    conn.commit()


def delete(conn: sqlite3.Connection, sid: int) -> None:
    if not conn.execute("DELETE FROM schedules WHERE id = ?", (sid,)).rowcount:
        raise LookupError("unknown schedule")
    conn.commit()
