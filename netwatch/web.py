"""Read-mostly web dashboard over the NetWatch database.

Stdlib only, so the Pi needs nothing extra installed. Intended for the home
LAN: there is no login, and anyone who can reach the port can relabel devices.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import threading
import time
from collections import Counter
from typing import TYPE_CHECKING
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import db, inventory, notify, tracker
from . import pause as pause_mod
from . import presence
from . import schedule as schedule_mod
from . import security as security_mod
from . import settings as settings_mod
from . import speed as speed_mod
from . import usage as usage_mod
from .pihole import PiholeClient
from .scanner import default_gateway, is_randomized_mac

if TYPE_CHECKING:
    from .config import PiholeConfig  # config imports tomllib, which the dashboard doesn't otherwise need

log = logging.getLogger(__name__)

MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
IPV4 = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)")
DEVICE_PATH = re.compile(
    r"/api/devices/([0-9a-f]{2}(?::[0-9a-f]{2}){5})/(label|notify|down_after|pause|resume|review|merge|pausable)")
SCHEDULE_PATH = re.compile(r"/api/schedules(?:/(\d+)(?:/(skip|delete))?)?")
MAX_PAUSE = 7 * 86400
# Wrong PINs in a row before the PIN stops working for a while, so it can't be guessed.
PIN_TRIES, PIN_LOCKOUT = 5, 15 * 60
PIN_HEADER = "X-NetWatch-PIN"
TOP_USERS = 15
DEVICE_INFO_PATH = re.compile(r"/api/devices/([0-9a-f]{2}(?::[0-9a-f]{2}){5})(/dns)?")
MAX_HISTORY = 31 * 86400
DNS_LIMIT = 10000  # newest queries to tally; a chatty device can make more in a day
TOP_DOMAINS = 25
# Pi-hole v6 query statuses that mean the lookup was blocked.
BLOCKED = {
    "GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "SPECIAL_DOMAIN",
    "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "EXTERNAL_BLOCKED_EDE15",
}
# Offline-alert thresholds, in minutes. Scans run every minute, so anything
# shorter than a couple of minutes would fire on a single missed reply.
DOWN_AFTER_MIN, DOWN_AFTER_MAX = 2, 7 * 24 * 60


def device_json(r, pausable: frozenset[str] = frozenset(), gateway: str | None = None) -> dict:
    return {
        "mac": r["mac"],
        "ip": r["ip"],
        "hostname": r["hostname"],
        "vendor": r["vendor"],
        "connection": r["connection"],
        "deco": r["deco"],
        "label": r["label"],
        "name": db.display_name(r),
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
        "online": bool(r["online"]),
        "notify": bool(r["notify"]),
        "down_after": r["down_after"],
        "down": r["down_since"] is not None,
        "paused": r["paused_ip"] is not None,
        "paused_until": r["paused_until"],
        "paused_by": r["paused_by"],
        "pausable": can_pause(r, pausable, gateway),
        "pause_allowed": bool(r["pause_allowed"]),
        "pause_listed": r["mac"] in pausable,
        "router": gateway is not None and r["ip"] == gateway,
        "randomized": is_randomized_mac(r["mac"]),
        "status": r["status"] or "review",
        "reviewed": r["reviewed"],
        "kind": r["kind"],
        "floor": r["floor"],
        "room": r["room"],
        "person": r["person"],
        "notes": r["notes"],
    }


def can_pause(r, pausable: frozenset[str], gateway: str | None = None) -> bool:
    """Devices listed in config or allowed with the PIN, and ones still to review: they aren't known
    to be yours yet, and pausing one is a way to find out what it is. Never the router, though."""
    return pause_mod.allowed(r, pausable) or (r["status"] is None and r["ip"] != gateway)


def devices_json(conn, pausable: frozenset[str] = frozenset(), gateway: str | None = None) -> list[dict]:
    return [device_json(r, pausable, gateway) for r in conn.execute("SELECT * FROM devices")]


def events_json(conn, limit: int, mac: str | None = None) -> list[dict]:
    rows = conn.execute(
        "SELECT e.ts, e.kind, e.ip AS event_ip, d.* FROM events e JOIN devices d USING (mac)"
        + (" WHERE e.mac = ?" if mac else "")
        + " ORDER BY e.ts DESC, e.id DESC LIMIT ?",
        (mac, limit) if mac else (limit,),
    ).fetchall()
    return [{"ts": r["ts"], "kind": r["kind"], "ip": r["event_ip"], "mac": r["mac"], "name": db.display_name(r)} for r in rows]


def ports_json(conn, mac: str, scanned: int | None) -> list[dict]:
    rows = conn.execute("SELECT * FROM ports WHERE mac = ? ORDER BY port, proto", (mac,))
    return [{"port": r["port"], "proto": r["proto"], "service": r["service"], "first_seen": r["first_seen"],
             "last_seen": r["last_seen"], "open": r["last_seen"] == scanned} for r in rows]


def online_spans(conn, mac: str, start: int, end: int, offline_after: int) -> dict:
    """When a device was online between start and end, as [from, to] pairs.

    Rebuilt from its join/leave events. An offline event is only recorded
    offline_after seconds after the device was last seen, so each span ends
    that much before its offline event.
    """
    row = conn.execute("SELECT first_seen FROM devices WHERE mac = ?", (mac,)).fetchone()
    known_from = min(max(start, row["first_seen"]), end)
    before = conn.execute(
        "SELECT kind FROM events WHERE mac = ? AND ts < ? ORDER BY ts DESC, id DESC LIMIT 1", (mac, start)
    ).fetchone()
    online_since = known_from if before and before["kind"] != "offline" else None
    spans = []
    for e in conn.execute(
        "SELECT ts, kind FROM events WHERE mac = ? AND ts >= ? AND ts <= ? ORDER BY ts, id", (mac, start, end)
    ):
        if e["kind"] == "offline":
            if online_since is not None:
                spans.append([online_since, max(online_since, e["ts"] - offline_after)])
            online_since = None
        elif online_since is None:  # new / online; ip_change while online changes nothing
            online_since = e["ts"]
    if online_since is not None:
        spans.append([online_since, end])
    return {
        "start": start,
        "end": end,
        "known_from": known_from,
        "spans": spans,
        "uptime": sum(b - a for a, b in spans) / (end - known_from) if end > known_from else None,
    }


def dns_summary(result: dict) -> dict:
    """Tally a Pi-hole /api/queries response (newest first) into top domains."""
    queries = result.get("queries", [])
    counts = Counter(q["domain"] for q in queries)
    blocked = Counter(q["domain"] for q in queries if q.get("status") in BLOCKED)
    complete = result.get("recordsFiltered", len(queries)) <= len(queries)
    return {
        "total": len(queries),
        "blocked": sum(blocked.values()),
        "domains": len(counts),
        # Pi-hole keeps about 24 h in memory; past the limit, the tally starts at the oldest query we got.
        "since": result.get("earliest_timestamp") if complete or not queries else int(queries[-1]["time"]),
        "complete": complete,
        "top": [{"domain": d, "count": n, "blocked": blocked[d]} for d, n in counts.most_common(TOP_DOMAINS)],
    }


def make_handler(db_path: str, ntfy_url: str = "", dashboard_url: str = "",
                 pihole: PiholeConfig | None = None, offline_after: int = 600):
    static = resources.files("netwatch").joinpath("static")
    index_html = static.joinpath("index.html").read_bytes()
    pausable = frozenset(pihole.pausable) if pihole is not None else frozenset()
    pin = pihole.pin if pihole is not None else ""
    pin_state = {"fails": 0, "locked_until": 0}
    pin_lock = threading.Lock()
    gateway = default_gateway()
    favicon = static.joinpath("favicon.svg").read_bytes()
    # What makes the page an installable app: the manifest, its icons and the offline service worker.
    app_files = {path: (static.joinpath(path[1:]).read_bytes(), kind) for path, kind in (
        ("/manifest.webmanifest", "application/manifest+json"),
        ("/sw.js", "text/javascript; charset=utf-8"),
        ("/icon-192.png", "image/png"),
        ("/icon-512.png", "image/png"),
    )}

    class Handler(BaseHTTPRequestHandler):
        server_version = "NetWatch"

        def _send(self, status: int, body: bytes, content_type: str, cache: str = "no-store") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, status: int = 200) -> None:
            self._send(status, json.dumps(data).encode(), "application/json")

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/":
                return self._send(200, index_html, "text/html; charset=utf-8")
            # Browsers also probe /favicon.ico (e.g. for bookmarks); modern ones accept SVG there.
            if url.path in ("/favicon.svg", "/favicon.ico"):
                return self._send(200, favicon, "image/svg+xml", cache="max-age=86400")
            if url.path in app_files:
                return self._send(200, *app_files[url.path])
            if url.path == "/api/settings":
                conn = db.connect(db_path)
                try:
                    return self._json(self._settings(conn))
                finally:
                    conn.close()
            if url.path in ("/api/devices", "/api/events"):
                conn = db.connect(db_path)
                try:
                    if url.path == "/api/devices":
                        return self._json({"now": int(time.time()), "devices": devices_json(conn, pausable, gateway)})
                    limit = int(parse_qs(url.query).get("limit", ["100"])[0])
                    return self._json({"events": events_json(conn, min(max(limit, 1), 1000))})
                finally:
                    conn.close()
            if url.path == "/api/speed":
                return self._speed(parse_qs(url.query))
            if url.path == "/api/usage":
                return self._usage(parse_qs(url.query))
            if url.path == "/api/people":
                return self._people(parse_qs(url.query))
            if url.path == "/api/security":
                conn = db.connect(db_path)
                try:
                    return self._json(self._security(conn))
                finally:
                    conn.close()
            if url.path == "/api/pausing":
                conn = db.connect(db_path)
                try:
                    return self._json(self._pausing(conn))
                finally:
                    conn.close()
            m = DEVICE_INFO_PATH.fullmatch(url.path)
            if m:
                return self._device(m.group(1), parse_qs(url.query)) if not m.group(2) else self._dns(m.group(1))
            self._json({"error": "not found"}, 404)

        def _device(self, mac: str, query: dict):
            conn = db.connect(db_path)
            try:
                row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
                if row is None:
                    return self._json({"error": "unknown device"}, 404)
                now = int(time.time())
                try:
                    since = int(query.get("since", [now - 7 * 86400])[0])
                except ValueError:
                    return self._json({"error": "since must be a unix timestamp"}, 400)
                since = min(max(since, now - MAX_HISTORY), now)
                return self._json({
                    "now": now,
                    "device": device_json(row, pausable, gateway),
                    "schedules": [schedule_mod.to_json(conn, x, now, pausable)
                                  for x in schedule_mod.for_device(conn, row)],
                    "history": online_spans(conn, mac, since, now, offline_after),
                    "events": events_json(conn, 100, mac),
                    "ports_scanned": row["ports_scanned"],
                    "ports": ports_json(conn, mac, row["ports_scanned"]),
                    "usage": usage_mod.series(conn, mac, since),
                    "usage_totals": {
                        "day": usage_mod.totals(conn, now - 86400, mac).get(mac, (0, 0)),
                        "week": usage_mod.totals(conn, now - 7 * 86400, mac).get(mac, (0, 0)),
                    },
                })
            finally:
                conn.close()

        def _dns(self, mac: str):
            conn = db.connect(db_path)
            try:
                row = conn.execute("SELECT ip FROM devices WHERE mac = ?", (mac,)).fetchone()
            finally:
                conn.close()
            if row is None:
                return self._json({"error": "unknown device"}, 404)
            if pihole is None:
                return self._json({"error": "Pi-hole isn't set up in config.toml"}, 409)
            if not row["ip"]:
                return self._json({"error": "no known IP address"}, 409)
            try:
                result = PiholeClient(pihole.url, pihole.password, timeout=15).queries(row["ip"], DNS_LIMIT)
            except Exception as e:
                log.warning("Pi-hole query lookup failed", exc_info=True)
                return self._json({"error": f"Pi-hole lookup failed: {e}"}, 502)
            return self._json({"ip": row["ip"], **dns_summary(result)})

        def _speed(self, query: dict):
            try:
                days = min(max(int(query.get("days", ["7"])[0]), 1), 90)
            except ValueError:
                return self._json({"error": "days must be a number"}, 400)
            now = int(time.time())
            conn = db.connect(db_path)
            try:
                tests = speed_mod.results(conn, now - days * 86400)
            finally:
                conn.close()
            pending = os.path.exists(os.path.join(os.path.dirname(db_path), speed_mod.REQUEST_FILE))
            return self._json({"now": now, "tests": tests, "pending": pending})

        def _usage(self, query: dict):
            """Who's using the internet: the latest Deco poll, and estimated totals over some days."""
            try:
                days = min(max(int(query.get("days", ["1"])[0]), 1), usage_mod.KEEP_DAYS)
            except ValueError:
                return self._json({"error": "days must be a number"}, 400)
            now = int(time.time())
            conn = db.connect(db_path)
            try:
                rows = {r["mac"]: r for r in conn.execute("SELECT * FROM devices")}
                ts, speeds = usage_mod.latest(conn)
                totals = usage_mod.totals(conn, now - days * 86400)
            finally:
                conn.close()

            def who(mac: str) -> dict:
                r = rows.get(mac)
                return {"mac": mac, "name": db.display_name(r) if r else mac,
                        "kind": r["kind"] if r else None, "person": r["person"] if r else None}

            return self._json({
                "now": now,
                "latest_ts": ts,
                "latest": sorted(({**who(m), "down": d, "up": u} for m, (d, u) in speeds.items()),
                                 key=lambda x: -(x["down"] + x["up"])),
                "top": sorted(({**who(m), "down_mb": d, "up_mb": u} for m, (d, u) in totals.items()),
                              key=lambda x: -(x["down_mb"] + x["up_mb"]))[:TOP_USERS],
            })

        def _people(self, query: dict):
            try:
                days = min(max(int(query.get("days", ["1"])[0]), 1), 30)
            except ValueError:
                return self._json({"error": "days must be a number"}, 400)
            now = int(time.time())
            conn = db.connect(db_path)
            try:
                s = settings_mod.load(conn)
                people = presence.people(conn, s["people"], now - days * 86400, now, offline_after,
                                         s["away_after"] * 60, online_spans)
            finally:
                conn.close()
            return self._json({"now": now, "start": now - days * 86400, "people": people})

        def _security(self, conn) -> dict:
            state, trusted = security_mod.load_state(conn), security_mod.load_trust(conn)
            names = {r["mac"]: db.display_name(r) for r in conn.execute("SELECT * FROM devices")}
            known = set(state["router_macs"]) | set(trusted["router"])
            router = [{"mac": m, "name": names.get(m), "ts": t, "trusted": m in known}
                      for m, t in sorted(state["router_seen"].items(), key=lambda kv: -kv[1])]
            offers = [{**o, "name": names.get(o["mac"]), "trusted": o["server"] in trusted["dhcp"] or (
                o["server"] == state["router_ip"] and o["mac"] in known)} for o in state["dhcp_offers"]]
            conflicts = [{"ip": ip, "ts": c["ts"], "devices": [{"mac": m, "name": names.get(m)} for m in c["macs"]]}
                         for ip, c in state["conflicts"].items()]
            history = [{**h, "name": names.get(h["mac"]), "text": notify.format_event(tracker.Event(
                h["kind"], h["mac"], h["ip"], names.get(h["mac"], h["mac"]), detail=h["detail"]))}
                for h in state["history"]]
            return {"now": int(time.time()), "router_ip": state["router_ip"], "router": router,
                    "dhcp_checked": state["dhcp_checked"], "dhcp": offers, "conflicts": conflicts,
                    "history": history, "trusted": trusted, "enabled": settings_mod.load(conn)["security_alerts"]}

        def _trust(self, conn, body: dict):
            router, dhcp = body.get("router"), body.get("dhcp")
            if router is not None and not (isinstance(router, str) and MAC.fullmatch(router)):
                return self._json({"error": "router must be a MAC address"}, 400)
            if dhcp is not None and not (isinstance(dhcp, str) and IPV4.fullmatch(dhcp)):
                return self._json({"error": "dhcp must be an IPv4 address"}, 400)
            if router is None and dhcp is None:
                return self._json({"error": "send router or dhcp"}, 400)
            security_mod.trust(conn, router, dhcp)
            return self._json({"ok": True, **self._security(conn)})

        def _settings(self, conn) -> dict:
            return {**settings_mod.load(conn), "ntfy_configured": bool(ntfy_url), "pihole_configured": pihole is not None,
                    "floors": inventory.FLOORS, "kinds": inventory.KINDS, "now": int(time.time())}

        def _review(self, conn, mac: str, body: dict):
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row is None:
                return self._json({"error": "unknown device"}, 404)
            try:
                updates = inventory.clean(body, settings_mod.load(conn)["people"], row["person"])
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            # Moving a pausable device to someone else takes it out of its person's schedules.
            if ("person" in updates and updates["person"] != row["person"] and pause_mod.allowed(row, pausable)
                    and not self._pin_ok()):
                return
            if updates:
                # Column names come from inventory.clean, never from the request.
                conn.execute(f"UPDATE devices SET {', '.join(k + ' = ?' for k in updates)} WHERE mac = ?",
                             (*updates.values(), mac))
                conn.commit()
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            return self._json({"ok": True, "device": device_json(row, pausable, gateway)})

        def _merge(self, conn, mac: str, body: dict):
            old = body.get("from")
            if not (isinstance(old, str) and MAC.fullmatch(old)):
                return self._json({"error": "from must be the old device's MAC address"}, 400)
            # Merging a pausable device away would leave it as a new device its schedules don't know.
            old_row = conn.execute("SELECT * FROM devices WHERE mac = ?", (old,)).fetchone()
            if old_row is not None and pause_mod.allowed(old_row, pausable) and not self._pin_ok():
                return
            try:
                inventory.merge(conn, old, mac)
            except LookupError:
                return self._json({"error": "unknown device"}, 404)
            except ValueError as e:
                return self._json({"error": str(e)}, 409)
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            return self._json({"ok": True, "device": device_json(row, pausable, gateway)})

        def _pin_ok(self, setup: bool = False) -> bool:
            """Check the request's PIN. Sends the refusal and returns False if it can't go ahead.

            With no PIN in config.toml, the things it guards are open (setup=False), or off (setup=True:
            they're new, and only make sense with a PIN).
            """
            if not pin:
                if setup:
                    self._json({"error": "set a pin under [pihole] in /etc/netwatch/config.toml first"}, 409)
                    return False
                return True
            now = time.time()
            given = self.headers.get(PIN_HEADER, "")
            locked = False
            with pin_lock:
                if pin_state["locked_until"] > now:
                    self._json({"error": "too many wrong PINs: try again in "
                                f"{int(pin_state['locked_until'] - now) // 60 + 1} min"}, 429)
                    return False
                if given and hmac.compare_digest(given.encode(), pin.encode()):
                    pin_state["fails"] = 0
                    return True
                if given:
                    pin_state["fails"] += 1
                    if pin_state["fails"] >= PIN_TRIES:
                        pin_state.update(fails=0, locked_until=now + PIN_LOCKOUT)
                        locked = True
            if locked:
                log.warning("%d wrong PINs in a row; PIN locked for %d min", PIN_TRIES, PIN_LOCKOUT // 60)
                if ntfy_url:
                    try:
                        notify.push(ntfy_url, "NetWatch: wrong PIN", f"Someone entered a wrong PIN {PIN_TRIES} times "
                                    f"in a row. Pausing changes are locked for {PIN_LOCKOUT // 60} minutes.",
                                    priority="high", tags="lock", click=dashboard_url)
                    except Exception:
                        log.warning("PIN alert failed", exc_info=True)
            self._json({"error": "wrong PIN" if given else "PIN needed", "pin": True}, 401)
            return False

        def _admin(self):
            return PiholeClient(pihole.url, pihole.password, timeout=15).admin()

        def _until(self, body: dict) -> tuple[bool, int | None]:
            """The end time a pause request asks for: (ok, until). Sends the refusal if it's bad."""
            until, now = body.get("until"), int(time.time())
            # An alert's Pause button sends minutes, so it counts from the tap, not from when the alert went out.
            minutes = body.get("minutes")
            if minutes is not None:
                if not (isinstance(minutes, int) and not isinstance(minutes, bool) and 0 < minutes <= MAX_PAUSE // 60):
                    self._json({"error": "minutes must be 1 to 7 days' worth"}, 400)
                    return False, None
                until = now + minutes * 60
            if until is not None and not (
                isinstance(until, int) and not isinstance(until, bool) and now < until <= now + MAX_PAUSE
            ):
                self._json({"error": "until must be a future unix time within 7 days, or null"}, 400)
                return False, None
            return True, until

        def _resume(self, conn, admin, row) -> None:
            """Resume by hand. If one of its schedules is running, it stays unpaused until that window ends."""
            pause_mod.resume(conn, admin, row["mac"])
            end = schedule_mod.running_for(conn, row, int(time.time()))
            if end:
                conn.execute("UPDATE devices SET sched_skip_until = ? WHERE mac = ?", (end, row["mac"]))
                conn.commit()

        def _pause(self, conn, mac: str, action: str, body: dict):
            if pihole is None:
                return self._json({"error": "Pi-hole isn't set up in config.toml"}, 409)
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row is None:
                return self._json({"error": "unknown device"}, 404)
            if action == "pause" and not can_pause(row, pausable, gateway):
                return self._json({"error": "only devices still to review, or allowed to be paused, can be paused"}, 403)
            # Resuming only puts things back, so it's never refused -- but it does take the PIN once
            # there is one, or whoever a pause is meant for could just resume it.
            if action == "resume" and not self._pin_ok():
                return
            until = None
            if action == "pause":
                ok, until = self._until(body)
                if not ok:
                    return
            try:
                with self._admin() as admin:
                    if action == "pause":
                        pause_mod.pause(conn, admin, mac, until)
                    else:
                        self._resume(conn, admin, row)
            except ValueError as e:
                return self._json({"error": str(e)}, 409)
            except Exception as e:
                log.warning("Pi-hole %s failed", action, exc_info=True)
                return self._json({"error": f"Pi-hole {action} failed: {e}"}, 502)
            pause_mod.touch(pihole.sync_trigger)
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            return self._json({"ok": True, "device": device_json(row, pausable, gateway)})

        def _pause_person(self, conn, action: str, body: dict):
            """Pause, or resume, all of a person's devices that can be paused."""
            if pihole is None:
                return self._json({"error": "Pi-hole isn't set up in config.toml"}, 409)
            person = body.get("person")
            if not isinstance(person, str):
                return self._json({"error": "person must be a name"}, 400)
            rows = conn.execute("SELECT * FROM devices WHERE person = ?", (person,)).fetchall()
            until = None
            if action == "pause":
                rows = [r for r in rows if pause_mod.allowed(r, pausable) and r["ip"]]
                if not rows:
                    return self._json({"error": f"none of {person}'s devices can be paused"}, 409)
                ok, until = self._until(body)
                if not ok:
                    return
            else:
                if not self._pin_ok():
                    return
                rows = [r for r in rows if r["paused_ip"]]
            try:
                if rows:
                    with self._admin() as admin:
                        for r in rows:
                            if action == "pause":
                                pause_mod.pause(conn, admin, r["mac"], until)
                            else:
                                self._resume(conn, admin, r)
            except Exception as e:
                log.warning("Pi-hole %s for %s failed", action, person, exc_info=True)
                return self._json({"error": f"Pi-hole {action} failed: {e}"}, 502)
            pause_mod.touch(pihole.sync_trigger)
            return self._json({"ok": True, "count": len(rows)})

        def _apply_schedules(self, conn) -> str | None:
            """Start or end scheduled pauses now, after a change, rather than at the next scan."""
            try:
                if schedule_mod.run(conn, self._admin, int(time.time()), pausable):
                    pause_mod.touch(pihole.sync_trigger)
            except Exception:
                log.warning("applying pause schedules failed", exc_info=True)
                return "Saved, but Pi-hole couldn't be reached: it takes effect within a minute or two."
            return None

        def _set_pausable(self, conn, mac: str, body: dict):
            if pihole is None:
                return self._json({"error": "Pi-hole isn't set up in config.toml"}, 409)
            if not isinstance(body.get("allowed"), bool):
                return self._json({"error": "allowed must be true or false"}, 400)
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            if row is None:
                return self._json({"error": "unknown device"}, 404)
            if body["allowed"] and gateway is not None and row["ip"] == gateway:
                return self._json({"error": "the router can't be paused"}, 403)
            if not self._pin_ok(setup=True):
                return
            conn.execute("UPDATE devices SET pause_allowed = ? WHERE mac = ?", (1 if body["allowed"] else None, mac))
            conn.commit()
            warning = self._apply_schedules(conn)
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            return self._json({"ok": True, "warning": warning, "device": device_json(row, pausable, gateway)})

        def _schedules(self, conn, sid: str | None, action: str | None, body: dict):
            if pihole is None:
                return self._json({"error": "Pi-hole isn't set up in config.toml"}, 409)
            if not self._pin_ok(setup=True):
                return
            try:
                if action == "delete":
                    schedule_mod.delete(conn, int(sid))
                elif action == "skip":
                    if not isinstance(body.get("skip"), bool):
                        return self._json({"error": "skip must be true or false"}, 400)
                    schedule_mod.skip(conn, int(sid), int(time.time()), body["skip"])
                else:
                    cols = schedule_mod.clean(body, settings_mod.load(conn)["people"], conn)
                    schedule_mod.save(conn, int(sid) if sid else None, cols)
            except LookupError as e:
                return self._json({"error": str(e)}, 404)
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            warning = self._apply_schedules(conn)
            return self._json({"ok": True, "warning": warning, **self._pausing(conn)})

        def _pausing(self, conn) -> dict:
            """The Pausing page: the devices that can be paused (or are), and the schedules."""
            now = int(time.time())
            rows = [r for r in conn.execute("SELECT * FROM devices").fetchall()
                    if pause_mod.allowed(r, pausable) or r["paused_ip"]]
            return {"now": now, "pihole_configured": pihole is not None, "pin_set": bool(pin),
                    "people": settings_mod.load(conn)["people"],
                    "devices": [device_json(r, pausable, gateway) for r in rows],
                    "schedules": schedule_mod.all_json(conn, now, pausable)}

        def do_POST(self):
            path = urlparse(self.path).path
            # Requiring JSON forces a CORS preflight for cross-site requests, which we
            # never approve -- so other websites can't change anything via your browser.
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._json({"error": "expected application/json"}, 415)
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json({"error": "bad request"}, 400)

            if path == "/api/test-notification":
                if not ntfy_url:
                    return self._json({"error": "ntfy_url is not set in config.toml"}, 409)
                try:
                    notify.push(ntfy_url, "NetWatch test", "Alerts are working.", tags="white_check_mark",
                                click=dashboard_url)
                except Exception as e:
                    return self._json({"error": f"ntfy push failed: {e}"}, 502)
                return self._json({"ok": True})

            if path == "/api/speed/run":
                # The test runs in its own service (netwatch-speedtest), which a path unit
                # starts when this file appears; the dashboard polls for the result.
                with open(os.path.join(os.path.dirname(db_path), speed_mod.REQUEST_FILE), "w"):
                    pass
                return self._json({"ok": True})

            conn = db.connect(db_path)
            try:
                if path == "/api/settings":
                    try:
                        settings_mod.save(conn, body)
                    except ValueError as e:
                        return self._json({"error": str(e)}, 400)
                    return self._json(self._settings(conn))

                if path == "/api/security/trust":
                    return self._trust(conn, body)

                if path in ("/api/people/pause", "/api/people/resume"):
                    return self._pause_person(conn, path.rsplit("/", 1)[1], body)

                m = SCHEDULE_PATH.fullmatch(path)
                if m:
                    return self._schedules(conn, *m.groups(), body)

                m = DEVICE_PATH.fullmatch(path)
                if not m:
                    return self._json({"error": "not found"}, 404)
                mac, field = m.groups()
                if field in ("pause", "resume"):
                    return self._pause(conn, mac, field, body)
                if field == "review":
                    return self._review(conn, mac, body)
                if field == "merge":
                    return self._merge(conn, mac, body)
                if field == "pausable":
                    return self._set_pausable(conn, mac, body)
                if field == "label":
                    value = (body.get("label") or "").strip()[:64] or None
                    cur = conn.execute("UPDATE devices SET label = ? WHERE mac = ?", (value, mac))
                elif field == "down_after":
                    minutes = body.get("minutes")
                    if minutes is not None and not (
                        isinstance(minutes, int) and not isinstance(minutes, bool)
                        and DOWN_AFTER_MIN <= minutes <= DOWN_AFTER_MAX
                    ):
                        return self._json({"error": f"minutes must be {DOWN_AFTER_MIN}-{DOWN_AFTER_MAX} or null"}, 400)
                    # Changing the threshold re-arms the alert: a device that's still
                    # gone gets a fresh "down" alert on the next scan if it qualifies.
                    cur = conn.execute("UPDATE devices SET down_after = ?, down_since = NULL WHERE mac = ?", (minutes, mac))
                else:
                    if not isinstance(body.get("notify"), bool):
                        return self._json({"error": "notify must be true or false"}, 400)
                    cur = conn.execute("UPDATE devices SET notify = ? WHERE mac = ?", (int(body["notify"]), mac))
                conn.commit()
                if not cur.rowcount:
                    return self._json({"error": "unknown device"}, 404)
                return self._json({"ok": True})
            finally:
                conn.close()

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(db_path: str, host: str, port: int, ntfy_url: str = "", dashboard_url: str = "",
          pihole: PiholeConfig | None = None, offline_after: int = 600) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(db_path, ntfy_url, dashboard_url, pihole, offline_after))
    log.info("dashboard on http://%s:%d", host, port)
    server.serve_forever()
