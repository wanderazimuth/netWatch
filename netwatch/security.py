"""Security checks: something posing as the router, two devices on one IP, and a second DHCP server.

ARP spoofing (a device telling others "I'm the router" so their traffic goes through it) shows as
the router's IP answering from a MAC address that isn't the router's: in the scan's replies, or in
the Pi's own ARP cache if the Pi itself was fooled. The router's MAC is learned on the first scan.

A rogue DHCP server (a misconfigured extender or Pi-hole, or an attacker) hands out addresses that
can send devices to the wrong router or DNS. Every DHCP_EVERY seconds the Pi asks for an offer,
without taking an address, and checks who answers.

Each problem alerts once, and again only if it went away for a day and came back. Trusting a MAC or
server (from the dashboard) stops its alerts.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import defaultdict

from . import db
from .tracker import Event

log = logging.getLogger(__name__)

STATE_KEY = "security"  # written by the scanner
TRUST_KEY = "security_trust"  # written by the dashboard; kept apart so neither overwrites the other
DHCP_EVERY = 15 * 60
CONFLICT_SCANS = 2  # sweeps in a row an IP must have two answers before it's a conflict
REALERT_AFTER = 86400  # a problem gone this long alerts again if it comes back
HISTORY = 20


def _load(conn: sqlite3.Connection, key: str) -> dict:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else {}


def _save(conn: sqlite3.Connection, key: str, value: dict) -> None:
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, json.dumps(value)))
    conn.commit()


def load_state(conn: sqlite3.Connection) -> dict:
    s = _load(conn, STATE_KEY)
    for k, v in (("router_ip", None), ("router_macs", []), ("router_seen", {}), ("pending", {}), ("alerted", {}),
                 ("dhcp_checked", 0), ("dhcp_offers", []), ("conflicts", {}), ("history", [])):
        s.setdefault(k, v)
    return s


def load_trust(conn: sqlite3.Connection) -> dict:
    t = _load(conn, TRUST_KEY)
    t.setdefault("router", [])
    t.setdefault("dhcp", [])
    return t


def trust(conn: sqlite3.Connection, router: str | None = None, dhcp: str | None = None) -> dict:
    t = load_trust(conn)
    for kind, value in (("router", router), ("dhcp", dhcp)):
        if value and value not in t[kind]:
            t[kind].append(value)
    _save(conn, TRUST_KEY, t)
    return t


def kernel_arp(ip: str, arp_file: str = "/proc/net/arp") -> set[str]:
    """The MACs the Pi itself has cached for ip, on any interface."""
    macs = set()
    try:
        with open(arp_file) as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip and int(parts[2], 16) & 2:  # 2 = complete entry
                    macs.add(parts[3].lower())
    except (OSError, ValueError):
        pass
    return macs


def _name(conn: sqlite3.Connection, mac: str) -> str:
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    return db.display_name(row) if row else mac


class Checker:
    """One round of checks on a loaded state; save() writes it back."""

    def __init__(self, conn: sqlite3.Connection, now: int):
        self.conn, self.now = conn, now
        self.state, self.trusted = load_state(conn), load_trust(conn)
        self.events: list[Event] = []

    def _alert(self, key: str, event: Event) -> None:
        """Alert unless this problem already alerted and hasn't been gone for a day since."""
        last = self.state["alerted"].get(key)
        self.state["alerted"][key] = self.now
        if last is None or self.now - last >= REALERT_AFTER:
            self.events.append(event)
            self.state["history"] = ([{"ts": self.now, "kind": event.kind, "mac": event.mac, "ip": event.ip,
                                       "detail": event.detail}] + self.state["history"])[:HISTORY]

    def arp(self, answers: list[tuple[str, str]], gateway: str | None, cached: set[str]) -> None:
        """answers: every (mac, ip) reply from one ARP sweep. cached: the Pi's own ARP entries for the gateway."""
        by_ip: dict[str, set[str]] = defaultdict(set)
        for mac, ip in answers:
            by_ip[ip].add(mac)

        if gateway:
            seen = by_ip.get(gateway, set()) | cached
            if self.state["router_ip"] != gateway:
                # First run, or the network now has a different router address: learn its MAC,
                # but only from a clean answer.
                if len(seen) == 1:
                    self.state.update(router_ip=gateway, router_macs=sorted(seen), router_seen={})
                    log.info("router %s is %s", gateway, next(iter(seen)))
                elif seen:
                    log.warning("router %s answers from several MACs (%s); not learning it yet", gateway,
                                ", ".join(sorted(seen)))
            if self.state["router_ip"] == gateway:
                known = set(self.state["router_macs"]) | set(self.trusted["router"])
                for mac in sorted(seen):
                    self.state["router_seen"][mac] = self.now
                    if mac in known:
                        continue
                    where = " and ".join(s for s, hit in (("in the scan", mac in by_ip.get(gateway, ())),
                                                          ("in the Pi's own ARP cache", mac in cached)) if hit)
                    self._alert(f"router:{mac}", Event("router_mac", mac, gateway, _name(self.conn, mac), detail=where))
                # Forget MACs not seen for a day, so the status shows what answers now.
                self.state["router_seen"] = {m: t for m, t in self.state["router_seen"].items()
                                             if self.now - t < REALERT_AFTER}

        pending = {}
        for ip, macs in by_ip.items():
            if len(macs) < 2 or ip == gateway:  # the router check covers the router's IP
                continue
            key = ",".join(sorted(macs))
            count = self.state["pending"].get(ip, {}).get(key, 0) + 1
            pending[ip] = {key: count}
            if count >= CONFLICT_SCANS:
                self.state["conflicts"][ip] = {"macs": sorted(macs), "ts": self.now}
                names = ", ".join(f"{_name(self.conn, m)} ({m})" for m in sorted(macs))
                self._alert(f"conflict:{ip}:{key}", Event("ip_conflict", sorted(macs)[-1], ip, names, detail=names))
        self.state["pending"] = pending
        self.state["conflicts"] = {ip: c for ip, c in self.state["conflicts"].items()
                                   if self.now - c["ts"] < REALERT_AFTER}

    def dhcp_due(self) -> bool:
        return self.now - self.state["dhcp_checked"] >= DHCP_EVERY

    def dhcp(self, offers: list[dict], gateway: str | None) -> None:
        """offers: from dhcp_offers(). The router is trusted to hand out addresses; other servers alert."""
        self.state["dhcp_checked"] = self.now
        self.state["dhcp_offers"] = offers
        router_macs = set(self.state["router_macs"]) | set(self.trusted["router"])
        for o in offers:
            server = o["server"]
            if server in self.trusted["dhcp"]:
                continue
            # Something else could claim to be the router's DHCP server, so check who sent it too.
            if server == gateway and (not router_macs or o["mac"] in router_macs):
                continue
            offered = ", ".join(f"{label} {o[k]}" for k, label in (("router", "router"), ("dns", "DNS")) if o.get(k))
            self._alert(f"dhcp:{server}:{o['mac']}", Event("rogue_dhcp", o["mac"], server, _name(self.conn, o["mac"]),
                                                           detail=offered or None))

    def save(self) -> list[Event]:
        # Problems not seen for a day are forgotten, so they alert again if they come back.
        self.state["alerted"] = {k: t for k, t in self.state["alerted"].items() if self.now - t < REALERT_AFTER}
        _save(self.conn, STATE_KEY, self.state)
        return self.events


def dhcp_offers(interface: str, timeout: float = 4.0) -> list[dict]:
    """Broadcast a DHCP discover and collect every offer. Never requests an address, so no lease changes."""
    from scapy.all import BOOTP, DHCP, IP, UDP, Ether, conf, get_if_hwaddr, srp
    import random

    conf.verb = 0
    conf.sniff_promisc = False
    conf.checkIPaddr = False  # offers come from the server's IP, not the broadcast address asked
    mac = get_if_hwaddr(interface)
    pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
           / UDP(sport=68, dport=67)
           / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=random.getrandbits(32), flags=0x8000)
           / DHCP(options=[("message-type", "discover"), "end"]))
    answered, _ = srp(pkt, iface=interface, timeout=timeout, multi=True)
    offers = {}
    for _, r in answered:
        opts = {o[0]: o[1] for o in r[DHCP].options if isinstance(o, tuple)}
        if opts.get("message-type") != 2:  # 2 = offer
            continue
        server = opts.get("server_id") or r[IP].src
        dns = opts.get("name_server")
        offers[(server, r[Ether].src.lower())] = {
            "server": server, "mac": r[Ether].src.lower(), "offered": r[BOOTP].yiaddr,
            "router": opts.get("router"), "dns": dns if isinstance(dns, str) else None,
        }
    return list(offers.values())
