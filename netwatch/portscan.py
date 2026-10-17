"""Weekly port scan: nmap every online device and alert when one opens a port
it has never had open before.

A device's first scan only records what's open (its baseline). Ports are
remembered after they close, so one that comes and goes doesn't alert again.
"""

from __future__ import annotations

import logging
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from . import db
from .tracker import Event

log = logging.getLogger(__name__)

# A TCP connect scan (-sT) needs no root or raw sockets. -Pn: the devices are
# known to be up, and phones often ignore pings. The host timeout keeps one
# heavily firewalled device from stalling the whole scan.
NMAP = ["nmap", "-sT", "-Pn", "-T4", "--top-ports", "1000", "--host-timeout", "10m", "-oX", "-"]
TIMEOUT = 3 * 3600


@dataclass(frozen=True)
class OpenPort:
    port: int
    proto: str
    service: str | None  # nmap's usual name for the port, e.g. "ssh"; not probed

    def __str__(self) -> str:
        return f"{self.port}/{self.proto}" + (f" ({self.service})" if self.service else "")


def run_nmap(ips: list[str]) -> str:
    return subprocess.run(NMAP + ips, capture_output=True, text=True, check=True, timeout=TIMEOUT).stdout


def parse(xml_text: str) -> dict[str, list[OpenPort]]:
    """Open ports by IP, for every host nmap finished scanning (timed-out hosts are left out)."""
    results = {}
    for host in ET.fromstring(xml_text).iter("host"):
        if host.get("timedout") == "true":
            continue
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        ports = []
        for p in host.iterfind("ports/port"):
            state = p.find("state")
            if state is not None and state.get("state") == "open":
                service = p.find("service")
                ports.append(OpenPort(int(p.get("portid")), p.get("protocol"),
                                      service.get("name") if service is not None else None))
        results[addr.get("addr")] = ports
    return results


def targets(conn: sqlite3.Connection) -> dict[str, str]:
    """IP -> MAC of the devices online now."""
    return {r["ip"]: r["mac"] for r in conn.execute("SELECT ip, mac FROM devices WHERE online = 1 AND ip IS NOT NULL")}


def record(conn: sqlite3.Connection, scanned: dict[str, str], results: dict[str, list[OpenPort]], now: int) -> list[Event]:
    """Store a scan's results; return a "port" event for each never-before-seen open port.

    scanned is the IP -> MAC map the scan was started with, so a device that
    changed IP mid-scan is still credited correctly.
    """
    events = []
    for ip, ports in results.items():
        mac = scanned.get(ip)
        row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone() if mac else None
        if row is None:
            continue
        baseline = row["ports_scanned"] is None
        for p in ports:
            cur = conn.execute(
                "INSERT INTO ports (mac, port, proto, service, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (mac, port, proto) DO UPDATE SET service = excluded.service, last_seen = excluded.last_seen"
                " RETURNING first_seen",
                (mac, p.port, p.proto, p.service, now, now),
            ).fetchone()
            if cur["first_seen"] == now and not baseline:
                events.append(Event("port", mac, ip, db.display_name(row), port=str(p)))
        conn.execute("UPDATE devices SET ports_scanned = ? WHERE mac = ?", (now, mac))
    conn.commit()
    return events
