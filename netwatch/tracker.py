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
    kind: str  # new | online | offline | ip_change | down | up | port
    mac: str
    ip: str | None
    name: str
    connection: str | None = None
    seconds: int | None = None  # down/up: how long the device has been / was unseen
    port: str | None = None  # port: the newly opened port, e.g. "23/tcp (telnet)"


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
                "INSERT INTO devices (mac, ip, hostname, vendor, connection, deco, first_seen, last_seen, online)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
                (s.mac, s.ip, extra.hostname, extra.vendor, extra.connection, extra.deco, now, now),
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
            " connection = COALESCE(?, connection), deco = COALESCE(?, deco), last_seen = ?, online = 1 WHERE mac = ?",
            (s.ip, extra.hostname, extra.vendor, extra.connection, extra.deco, now, s.mac),
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


def check_down(conn: sqlite3.Connection, now: int) -> list[Event]:
    """Alerts for devices with an offline alert: "down" once when unseen for
    their down_after minutes, then "up" when they're seen again.

    Run after apply_scan so last_seen is current. These are alerts, not state
    changes, so they aren't written to the events table (offline/online are).
    """
    events: list[Event] = []
    for row in conn.execute("SELECT * FROM devices WHERE down_after IS NOT NULL OR down_since IS NOT NULL").fetchall():
        name = row["label"] or row["hostname"] or row["vendor"] or row["mac"]
        if row["down_since"] is not None and row["last_seen"] > row["down_since"]:
            conn.execute("UPDATE devices SET down_since = NULL WHERE mac = ?", (row["mac"],))
            if row["down_after"] is not None:
                events.append(Event("up", row["mac"], row["ip"], name, seconds=row["last_seen"] - row["down_since"]))
        elif row["down_since"] is None and row["down_after"] is not None and now - row["last_seen"] >= row["down_after"] * 60:
            conn.execute("UPDATE devices SET down_since = last_seen WHERE mac = ?", (row["mac"],))
            events.append(Event("down", row["mac"], row["ip"], name, seconds=now - row["last_seen"]))
    conn.commit()
    return events
