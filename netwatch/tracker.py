"""Turn raw scan results into device state changes.

Kept free of networking so it can be unit-tested on any machine.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .info import DeviceInfo
from .scanner import Sighting


@dataclass(frozen=True)
class Event:
    kind: str  # new | online | offline | ip_change
    mac: str
    ip: str | None
    name: str
    connection: str | None = None


def apply_scan(
    conn: sqlite3.Connection,
    sightings: list[Sighting],
    now: int,
    offline_after: int,
    info: dict[str, DeviceInfo] | None = None,
) -> list[Event]:
    info = info or {}
    events: list[Event] = []
    seen = set()

    for s in sightings:
        seen.add(s.mac)
        extra = info.get(s.mac, DeviceInfo())
        row = conn.execute("SELECT * FROM devices WHERE mac = ?", (s.mac,)).fetchone()

        if row is None:
            conn.execute(
                "INSERT INTO devices (mac, ip, hostname, vendor, connection, first_seen, last_seen, online)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (s.mac, s.ip, extra.hostname, extra.vendor, extra.connection, now, now),
            )
            events.append(Event("new", s.mac, s.ip, extra.hostname or extra.vendor or s.mac, extra.connection))
            continue

        name = row["label"] or extra.hostname or row["hostname"] or extra.vendor or row["vendor"] or s.mac
        if not row["online"]:
            events.append(Event("online", s.mac, s.ip, name))
        elif row["ip"] != s.ip:
            events.append(Event("ip_change", s.mac, s.ip, name))

        # COALESCE keeps previously known details if no source has them this time.
        conn.execute(
            "UPDATE devices SET ip = ?, hostname = COALESCE(?, hostname), vendor = COALESCE(?, vendor),"
            " connection = COALESCE(?, connection), last_seen = ?, online = 1 WHERE mac = ?",
            (s.ip, extra.hostname, extra.vendor, extra.connection, now, s.mac),
        )

    # One missed scan is normal (sleeping phones, dropped packets); only declare
    # a device gone once it has been unseen for offline_after seconds.
    for row in conn.execute("SELECT * FROM devices WHERE online = 1").fetchall():
        if row["mac"] not in seen and now - row["last_seen"] >= offline_after:
            conn.execute("UPDATE devices SET online = 0 WHERE mac = ?", (row["mac"],))
            name = row["label"] or row["hostname"] or row["vendor"] or row["mac"]
            events.append(Event("offline", row["mac"], row["ip"], name))

    conn.executemany(
        "INSERT INTO events (ts, mac, kind, ip) VALUES (?, ?, ?, ?)",
        [(now, e.mac, e.kind, e.ip) for e in events],
    )
    conn.commit()
    return events
