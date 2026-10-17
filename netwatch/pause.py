"""Pause a device's internet by putting it in a Pi-hole group that blocks every lookup.

DNS-only: a device with a hard-coded DNS server, or apps that already have an
address cached, can still get through until they look something up again.

Devices are paused by IP, not MAC: the NAS replica runs Pi-hole in Docker and
can't see MACs, but it does get our client entries through nebula-sync. If a
paused device's IP changes, maintain() moves the pause to the new address.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

from . import db

log = logging.getLogger(__name__)

COMMENT = "NetWatch: internet paused"


def _pause_ip(admin, ip: str) -> str | None:
    """Point ip's Pi-hole client entry at the pause group. Returns what to restore later (JSON) or None."""
    gid = admin.ensure_pause_group()
    existing = admin.get_client(ip)
    restore = None
    if existing is not None and existing.get("comment") != COMMENT:
        restore = json.dumps({"groups": existing["groups"], "comment": existing.get("comment")})
    admin.save_client(ip, [gid], COMMENT)
    return restore


def _unpause_ip(admin, ip: str, restore: str | None) -> None:
    if restore:
        old = json.loads(restore)
        admin.save_client(ip, old["groups"], old["comment"])
    else:
        admin.delete_client(ip)


def touch(trigger: str) -> None:
    """Tell anything watching (e.g. a systemd path unit that runs the NAS sync) that Pi-hole changed."""
    if trigger:
        try:
            Path(trigger).touch()
        except OSError:
            log.warning("could not touch %s", trigger, exc_info=True)


def pause(conn: sqlite3.Connection, admin, mac: str, until: int | None) -> None:
    """Pause until the given unix time, or indefinitely if None. Re-pausing just changes the end time."""
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        raise LookupError("unknown device")
    if not row["ip"]:
        raise ValueError("no known IP address to pause")
    if row["paused_ip"] == row["ip"]:
        restore = row["paused_restore"]
    else:
        if row["paused_ip"]:
            _unpause_ip(admin, row["paused_ip"], row["paused_restore"])
        restore = _pause_ip(admin, row["ip"])
    conn.execute(
        "UPDATE devices SET paused_ip = ?, paused_until = ?, paused_restore = ? WHERE mac = ?",
        (row["ip"], until, restore, mac),
    )
    conn.commit()
    log.info("paused internet for %s (%s)%s", db.display_name(row), row["ip"], "" if until else " until resumed")


def resume(conn: sqlite3.Connection, admin, mac: str) -> None:
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        raise LookupError("unknown device")
    if row["paused_ip"]:
        _unpause_ip(admin, row["paused_ip"], row["paused_restore"])
        log.info("resumed internet for %s (%s)", db.display_name(row), row["paused_ip"])
    conn.execute("UPDATE devices SET paused_ip = NULL, paused_until = NULL, paused_restore = NULL WHERE mac = ?", (mac,))
    conn.commit()


def needs_maintenance(conn: sqlite3.Connection, now: int) -> bool:
    """Cheap check so the scanner only logs in to Pi-hole when a pause has expired or moved IP."""
    return conn.execute(
        "SELECT 1 FROM devices WHERE paused_ip IS NOT NULL"
        " AND ((paused_until IS NOT NULL AND paused_until <= ?) OR (ip IS NOT NULL AND ip != paused_ip)) LIMIT 1",
        (now,),
    ).fetchone() is not None


def maintain(conn: sqlite3.Connection, admin, now: int) -> bool:
    """End expired pauses and follow paused devices to new IPs. Returns True if Pi-hole changed."""
    changed = False
    for row in conn.execute("SELECT * FROM devices WHERE paused_ip IS NOT NULL").fetchall():
        if row["paused_until"] is not None and row["paused_until"] <= now:
            resume(conn, admin, row["mac"])
            changed = True
        elif row["ip"] and row["ip"] != row["paused_ip"]:
            pause(conn, admin, row["mac"], row["paused_until"])
            changed = True
    return changed
