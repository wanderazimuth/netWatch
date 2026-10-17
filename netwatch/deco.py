"""TP-Link Deco client list, via the community `tplinkrouterc6u` library.

The Deco's local API is unofficial (reverse-engineered), so this is an
optional enrichment source: if it breaks, ARP scanning carries on.

Failed logins count toward the Deco's admin lockout (9 attempts), so after a
failure we back off exponentially instead of retrying every poll, and retry
straight away only when the password file changes.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass

from .info import DeviceInfo, usable_name
from .scanner import Sighting

log = logging.getLogger(__name__)

MAX_BACKOFF = 6 * 3600
BANDS = {"2G": "2.4 GHz", "5G": "5 GHz", "6G": "6 GHz"}


@dataclass(frozen=True)
class DecoClient:
    mac: str
    ip: str | None
    name: str | None
    connection: str | None


def normalize_mac(mac) -> str:
    return str(mac).lower().replace("-", ":")


def connection_label(kind: str) -> str | None:
    """Map the library's Connection enum name to something readable."""
    if kind == "WIRED":
        return "wired"
    if kind == "UNKNOWN":
        return None
    band = BANDS.get(kind.rsplit("_", 1)[-1])
    if band is None:
        return "Wi-Fi"  # e.g. HOST_MLO: multi-link, no single band
    if kind.startswith("GUEST"):
        return band + " guest"
    if kind.startswith("IOT"):
        return band + " IoT"
    return band


class Deco:
    def __init__(self, url: str, password_file: str, poll_interval: int, clock=time.monotonic):
        self.url = url
        self.password_file = password_file
        self.poll_interval = poll_interval
        self.clock = clock
        self.clients: dict[str, DecoClient] = {}
        self._next_poll = 0.0
        self._failures = 0
        self._failed_pw_mtime: float | None = None

    def _password_mtime(self) -> float | None:
        try:
            return os.stat(self.password_file).st_mtime
        except OSError:
            return None

    def _fetch(self) -> list[DecoClient]:
        from tplinkrouterc6u import TPLinkDecoClient

        with open(self.password_file) as f:
            password = f.read().strip()
        client = TPLinkDecoClient(self.url, password, timeout=15)
        client.authorize()
        try:
            status = client.get_status()
            nodes = client.get_mesh_nodes()
        finally:
            try:
                client.logout()
            except Exception:
                log.debug("Deco logout failed", exc_info=True)

        found = [
            DecoClient(
                mac=normalize_mac(d.macaddr),
                ip=str(d.ipaddr) if d.ipaddr else None,
                name=d.hostname if usable_name(d.hostname) else None,
                connection=connection_label(d.type.name),
            )
            for d in status.devices
            if d.active
        ]
        # The Deco units themselves aren't in the client list.
        found += [
            DecoClient(normalize_mac(n.macaddr), str(n.ipaddr) if n.ipaddr else None, f"Deco {n.name}", None)
            for n in nodes
        ]
        return found

    def refresh(self) -> bool:
        """Poll the Deco if due. Returns True when fresh data was fetched."""
        now = self.clock()
        pw_changed = self._failed_pw_mtime is not None and self._password_mtime() != self._failed_pw_mtime
        if now < self._next_poll and not pw_changed:
            return False
        try:
            clients = self._fetch()
        except Exception as e:
            self._failures += 1
            self._failed_pw_mtime = self._password_mtime()
            delay = min(self.poll_interval * 2 ** self._failures, MAX_BACKOFF)
            self._next_poll = now + delay
            log.warning("Deco poll failed (%s); next try in %d min", e, delay // 60)
            return False
        if self._failures:
            log.info("Deco poll recovered after %d failure(s)", self._failures)
        self._failures = 0
        self._failed_pw_mtime = None
        self._next_poll = now + self.poll_interval
        self.clients = {c.mac: c for c in clients}
        return True

    def device_info(self) -> dict[str, DeviceInfo]:
        return {mac: DeviceInfo(hostname=c.name, connection=c.connection) for mac, c in self.clients.items()}

    def sightings(self, network: str) -> list[Sighting]:
        """Clients the Deco reports as connected, limited to the scanned subnet.

        Lets a phone that sleeps through an ARP sweep still count as present.
        """
        net = ipaddress.ip_network(network)
        return [
            Sighting(c.mac, c.ip)
            for c in self.clients.values()
            if c.ip and ipaddress.ip_address(c.ip) in net
        ]
