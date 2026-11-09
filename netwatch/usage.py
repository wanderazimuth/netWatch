"""Each device's internet use over time, from the live speeds the Deco reports at every poll.

A poll is a snapshot of the speed at that moment, every 5 minutes, so data totals are
estimates (speed x time until the next poll): a short burst between polls is missed, and a
burst that happens to be caught counts for the whole 5 minutes. Good for "who uses the most",
not for billing.
"""

from __future__ import annotations

import sqlite3

KEEP_DAYS = 30


def record(conn: sqlite3.Connection, ts: int, speeds: dict[str, tuple[int, int]], secs: int) -> None:
    """Store one poll's speeds (kbit/s); secs is how long each reading stands for."""
    rows = [(ts, mac, down, up, secs) for mac, (down, up) in speeds.items() if down or up]
    conn.executemany("INSERT INTO traffic (ts, mac, down, up, secs) VALUES (?, ?, ?, ?, ?)", rows)
    conn.execute("DELETE FROM traffic WHERE ts < ?", (ts - KEEP_DAYS * 86400,))
    conn.commit()


def megabytes(kbps: float, secs: float) -> float:
    return kbps * secs / 8 / 1000


def series(conn: sqlite3.Connection, mac: str, since: int) -> list[list[int]]:
    """[ts, down, up, secs] for each poll that caught the device using the internet."""
    return [list(r) for r in conn.execute(
        "SELECT ts, down, up, secs FROM traffic WHERE mac = ? AND ts >= ? ORDER BY ts", (mac, since))]


def totals(conn: sqlite3.Connection, since: int, mac: str | None = None) -> dict[str, tuple[float, float]]:
    """Estimated MB (down, up) per device since a time."""
    where, args = ("AND mac = ?", (since, mac)) if mac else ("", (since,))
    return {r[0]: (round(megabytes(r[1], 1), 1), round(megabytes(r[2], 1), 1)) for r in conn.execute(
        f"SELECT mac, SUM(down * secs), SUM(up * secs) FROM traffic WHERE ts >= ? {where} GROUP BY mac", args)}


def latest(conn: sqlite3.Connection) -> tuple[int | None, dict[str, tuple[int, int]]]:
    """The most recent poll's time and speeds, leaving out devices that were idle."""
    row = conn.execute("SELECT MAX(ts) FROM traffic").fetchone()
    if row[0] is None:
        return None, {}
    return row[0], {r[0]: (r[1], r[2]) for r in conn.execute("SELECT mac, down, up FROM traffic WHERE ts = ?", (row[0],))}
