"""Device groups: a named set of devices ("Family devices") to pause together, now or on a schedule.

Any device can be in a group, and in more than one, but only those allowed to be paused ever are:
putting a device in a group doesn't make it pausable. A device keeps its person; groups are separate.
"""

from __future__ import annotations

import sqlite3

from . import db
from . import pause as pause_mod

MAX_GROUPS = 20
MAX_NAME = 40
MAX_MEMBERS = 100


def members(conn: sqlite3.Connection, gid: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT d.* FROM devices d JOIN group_members m ON m.mac = d.mac WHERE m.group_id = ?",
                        (gid,)).fetchall()


def names_for(conn: sqlite3.Connection, mac: str) -> list[str]:
    """The names of the groups a device is in."""
    return [r["name"] for r in conn.execute(
        "SELECT g.name FROM device_groups g JOIN group_members m ON m.group_id = g.id WHERE m.mac = ? ORDER BY g.name",
        (mac,))]


def clean(body: dict, conn: sqlite3.Connection, gid: int | None = None) -> tuple[str, list[str]]:
    """The name and member MACs for a new or edited group, or raise ValueError naming the bad field."""
    unknown = set(body) - {"name", "macs"}
    if unknown:
        raise ValueError(f"unknown field {sorted(unknown)[0]!r}")
    name = body.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be some text")
    name = " ".join(name.split())[:MAX_NAME]
    clash = conn.execute("SELECT id FROM device_groups WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
    if clash is not None and clash["id"] != gid:
        raise ValueError(f"there's already a group called {name}")
    macs = body.get("macs", [])
    if not (isinstance(macs, list) and all(isinstance(m, str) for m in macs)):
        raise ValueError("macs must be a list of MAC addresses")
    macs = sorted(set(macs))
    if len(macs) > MAX_MEMBERS:
        raise ValueError(f"at most {MAX_MEMBERS} devices in a group")
    known = {r["mac"] for r in conn.execute(
        f"SELECT mac FROM devices WHERE mac IN ({', '.join('?' * len(macs))})", macs)} if macs else set()
    if missing := [m for m in macs if m not in known]:
        raise ValueError(f"unknown device {missing[0]}")
    return name, macs


def save(conn: sqlite3.Connection, gid: int | None, name: str, macs: list[str]) -> int:
    if gid is None:
        if conn.execute("SELECT COUNT(*) FROM device_groups").fetchone()[0] >= MAX_GROUPS:
            raise ValueError(f"at most {MAX_GROUPS} groups")
        gid = conn.execute("INSERT INTO device_groups (name) VALUES (?)", (name,)).lastrowid
    elif not conn.execute("UPDATE device_groups SET name = ? WHERE id = ?", (name, gid)).rowcount:
        raise LookupError("unknown group")
    conn.execute("DELETE FROM group_members WHERE group_id = ?", (gid,))
    conn.executemany("INSERT INTO group_members (group_id, mac) VALUES (?, ?)", [(gid, m) for m in macs])
    conn.commit()
    return gid


def delete(conn: sqlite3.Connection, gid: int) -> None:
    """Delete a group and its schedules. Their pauses end at the next schedule run."""
    if not conn.execute("DELETE FROM device_groups WHERE id = ?", (gid,)).rowcount:
        raise LookupError("unknown group")
    conn.execute("DELETE FROM group_members WHERE group_id = ?", (gid,))
    conn.execute("DELETE FROM schedules WHERE group_id = ?", (gid,))
    conn.commit()


def all_json(conn: sqlite3.Connection, listed: frozenset[str]) -> list[dict]:
    out = []
    for g in conn.execute("SELECT * FROM device_groups ORDER BY name COLLATE NOCASE").fetchall():
        rows = sorted(members(conn, g["id"]), key=lambda r: db.display_name(r).lower())
        out.append({"id": g["id"], "name": g["name"], "devices": [
            {"mac": r["mac"], "name": db.display_name(r), "kind": r["kind"], "online": bool(r["online"]),
             "pausable": pause_mod.allowed(r, listed), "paused": r["paused_ip"] is not None}
            for r in rows]})
    return out
