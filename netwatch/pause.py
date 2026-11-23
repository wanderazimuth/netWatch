"""Pause a device's internet by putting it in a Pi-hole group that blocks every lookup.

DNS-only: a device with a hard-coded DNS server, or apps that already have an
address cached, can still get through until they look something up again.

Devices are paused by IP, not MAC: the NAS replica runs Pi-hole in Docker and
can't see MACs, but it does get our client entries through nebula-sync. If a
paused device's IP changes, maintain() moves the pause to the new address.

A paused device that goes quiet can lose its address to another device (a blocked speaker's
DHCP lease ran out overnight and the TV got it, 2026-11-23). Whoever was seen at an address most
recently owns it, so then the Pi-hole block on that address is lifted and pause_ip_taken set; the
Deco block, by MAC, still holds the paused device. The block comes back if it reappears there.
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


# Another device has been seen at an address since the paused device was last seen: it has the
# address now, or it moved there and on (the TV went back and forth between two, 2026-11-23).
_TAKEN = ("EXISTS (SELECT 1 FROM devices o WHERE o.ip = {ip} AND o.mac != {mac} AND o.last_seen > {seen})"
          " OR EXISTS (SELECT 1 FROM events e WHERE e.ip = {ip} AND e.mac != {mac} AND e.ts > {seen}"
          " AND e.kind IN ('new', 'online', 'ip_change'))")
TAKEN = "(" + _TAKEN.format(ip="devices.paused_ip", mac="devices.mac", seen="COALESCE(devices.last_seen, 0)") + ")"


def _holder(conn: sqlite3.Connection, row, ip: str):
    """The device that has taken ip from row's device (see _TAKEN), or None."""
    if not conn.execute("SELECT " + _TAKEN.format(ip=":ip", mac=":mac", seen=":seen"),
                        {"ip": ip, "mac": row["mac"], "seen": row["last_seen"] or 0}).fetchone()[0]:
        return None
    args = {"ip": ip, "mac": row["mac"], "seen": row["last_seen"] or 0}
    return (conn.execute("SELECT * FROM devices WHERE ip = :ip AND mac != :mac AND last_seen > :seen"
                         " ORDER BY last_seen DESC LIMIT 1", args).fetchone()
            or conn.execute("SELECT d.* FROM events e JOIN devices d USING (mac) WHERE e.ip = :ip AND e.mac != :mac"
                            " AND e.ts > :seen ORDER BY e.ts DESC LIMIT 1", args).fetchone()
            or row)


def allowed(row, listed: frozenset[str]) -> bool:
    """Devices you've said may be paused: in config.toml's pausable list, or allowed on the dashboard with the PIN."""
    return row["mac"] in listed or bool(row["pause_allowed"])


def touch(trigger: str) -> None:
    """Tell anything watching (e.g. a systemd path unit that runs the NAS sync) that Pi-hole changed."""
    if trigger:
        try:
            Path(trigger).touch()
        except OSError:
            log.warning("could not touch %s", trigger, exc_info=True)


def pause(conn: sqlite3.Connection, admin, mac: str, until: int | None, by: int | None = None) -> None:
    """Pause until the given unix time, or indefinitely if None. Re-pausing just changes the end time.

    by is the schedule doing it; None for a pause by hand.
    """
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        raise LookupError("unknown device")
    if not row["ip"]:
        raise ValueError("no known IP address to pause")
    ip = row["ip"]
    holder = _holder(conn, row, ip)
    blocking = row["paused_ip"] is not None and not row["pause_ip_taken"]
    if blocking and row["paused_ip"] == ip and holder is None:
        restore = row["paused_restore"]
    else:
        if blocking:
            _unpause_ip(admin, row["paused_ip"], row["paused_restore"])
        restore = None if holder is not None else _pause_ip(admin, ip)
    conn.execute(
        "UPDATE devices SET paused_ip = ?, paused_until = ?, paused_restore = ?, paused_by = ?, pause_ip_taken = ?"
        " WHERE mac = ?",
        (ip, until, restore, by, 1 if holder is not None else None, mac),
    )
    conn.commit()
    if holder is not None:
        log.info("paused %s at the Deco only: %s now has %s", db.display_name(row), db.display_name(holder), ip)
    log.info("paused internet for %s (%s)%s", db.display_name(row), ip, "" if until else " until resumed")


def resume(conn: sqlite3.Connection, admin, mac: str) -> None:
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        raise LookupError("unknown device")
    if row["paused_ip"]:
        if not row["pause_ip_taken"]:
            _unpause_ip(admin, row["paused_ip"], row["paused_restore"])
        log.info("resumed internet for %s (%s)", db.display_name(row), row["paused_ip"])
    conn.execute("UPDATE devices SET paused_ip = NULL, paused_until = NULL, paused_restore = NULL, paused_by = NULL,"
                 " pause_ip_taken = NULL WHERE mac = ?", (mac,))
    conn.commit()


def needs_maintenance(conn: sqlite3.Connection, now: int) -> bool:
    """Cheap check so the scanner only logs in to Pi-hole when a pause has expired, moved IP,
    or lost its IP to another device (or got it back)."""
    return conn.execute(
        "SELECT 1 FROM devices WHERE paused_ip IS NOT NULL"
        " AND ((paused_until IS NOT NULL AND paused_until <= ?) OR (ip IS NOT NULL AND ip != paused_ip)"
        f" OR (pause_ip_taken IS NULL AND {TAKEN}) OR (pause_ip_taken IS NOT NULL AND NOT {TAKEN})) LIMIT 1",
        (now,),
    ).fetchone() is not None


def maintain(conn: sqlite3.Connection, admin, now: int) -> bool:
    """End expired pauses, follow paused devices to new IPs, and stop blocking an IP another
    device has taken (or block it again once it's back). Returns True if Pi-hole changed."""
    changed = False
    for row in conn.execute("SELECT * FROM devices WHERE paused_ip IS NOT NULL").fetchall():
        if row["paused_until"] is not None and row["paused_until"] <= now:
            resume(conn, admin, row["mac"])
            changed = True
        elif row["ip"] and (row["ip"] != row["paused_ip"]
                            or bool(row["pause_ip_taken"]) != (_holder(conn, row, row["ip"]) is not None)):
            pause(conn, admin, row["mac"], row["paused_until"], row["paused_by"])
            changed = True
    return changed


def reconcile(conn: sqlite3.Connection, admin) -> bool:
    """Make Pi-hole's pause entries match the database: drop ones for devices that aren't paused,
    and put back missing or changed ones. Returns True if Pi-hole changed.

    Something else rewriting Pi-hole's database can undo a pause or a resume: a gravity run started
    by the NAS sync did, putting back a resumed device's entry (2026-11-22).
    """
    entries = admin.all_clients()
    paused = {r["paused_ip"]: r for r in conn.execute(
        "SELECT * FROM devices WHERE paused_ip IS NOT NULL AND pause_ip_taken IS NULL")}
    changed = False
    for client, entry in entries.items():
        if entry.get("comment") == COMMENT and client not in paused:
            admin.delete_client(client)
            log.warning("removed a leftover Pi-hole pause for %s: nothing paused there", client)
            changed = True
    gid = None
    for ip, row in paused.items():
        entry = entries.get(ip)
        if entry is None or entry.get("comment") != COMMENT:
            gid = gid if gid is not None else admin.ensure_pause_group()
            admin.save_client(ip, [gid], COMMENT)
            log.warning("put back the Pi-hole pause for %s (%s): it had gone", db.display_name(row), ip)
            changed = True
    return changed


# With a Deco, a paused device is also put in the Deco's block list, which cuts all its internet:
# that catches devices that skip Pi-hole, like Google speakers with their own DNS servers. Pausing
# and resuming only change the database; sync_deco then brings the block list in line, from the
# dashboard straight away and from the scanner every minute (for timed and scheduled pauses, and to
# retry when the Deco couldn't be reached).
DECO_OUT_OF_STEP = ("(paused_ip IS NOT NULL AND deco_blocked IS NULL)"
                    " OR (paused_ip IS NULL AND deco_blocked IS NOT NULL)")


def deco_out_of_step(conn: sqlite3.Connection) -> bool:
    return conn.execute(f"SELECT 1 FROM devices WHERE {DECO_OUT_OF_STEP} LIMIT 1").fetchone() is not None


def sync_deco(conn: sqlite3.Connection, block_list) -> bool:
    """Block paused devices at the Deco and unblock resumed ones. block_list() opens a Deco
    session (a context manager), only when something needs changing. Returns True if it did.

    A device that was already blocked in the Deco app is left blocked when it's resumed.
    """
    rows = conn.execute(f"SELECT * FROM devices WHERE {DECO_OUT_OF_STEP}").fetchall()
    if not rows:
        return False
    with block_list() as deco:
        blocked = deco.blocked()
        for r in rows:
            if r["paused_ip"]:
                state = 2 if r["mac"] in blocked else 1
                if state == 1:
                    deco.block(r["mac"], db.display_name(r))
                    log.info("blocked %s at the Deco", db.display_name(r))
            else:
                if r["deco_blocked"] == 1 and r["mac"] in blocked:
                    deco.unblock(r["mac"])
                    log.info("unblocked %s at the Deco", db.display_name(r))
                state = None
            conn.execute("UPDATE devices SET deco_blocked = ? WHERE mac = ?", (state, r["mac"]))
            conn.commit()
    return True
