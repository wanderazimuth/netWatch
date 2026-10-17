"""Read-mostly web dashboard over the NetWatch database.

Stdlib only, so the Pi needs nothing extra installed. Intended for the home
LAN: there is no login, and anyone who can reach the port can relabel devices.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from typing import TYPE_CHECKING
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import db, notify
from . import pause as pause_mod
from . import settings as settings_mod
from .pihole import PiholeClient
from .scanner import is_randomized_mac

if TYPE_CHECKING:
    from .config import PiholeConfig  # config imports tomllib, which the dashboard doesn't otherwise need

log = logging.getLogger(__name__)

DEVICE_PATH = re.compile(r"/api/devices/([0-9a-f]{2}(?::[0-9a-f]{2}){5})/(label|notify|down_after|pause|resume)")
MAX_PAUSE = 7 * 86400
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


def device_json(r) -> dict:
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
        "randomized": is_randomized_mac(r["mac"]),
    }


def devices_json(conn) -> list[dict]:
    return [device_json(r) for r in conn.execute("SELECT * FROM devices")]


def events_json(conn, limit: int, mac: str | None = None) -> list[dict]:
    rows = conn.execute(
        "SELECT e.ts, e.kind, e.ip AS event_ip, d.* FROM events e JOIN devices d USING (mac)"
        + (" WHERE e.mac = ?" if mac else "")
        + " ORDER BY e.ts DESC, e.id DESC LIMIT ?",
        (mac, limit) if mac else (limit,),
    ).fetchall()
    return [{"ts": r["ts"], "kind": r["kind"], "ip": r["event_ip"], "mac": r["mac"], "name": db.display_name(r)} for r in rows]


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
    favicon = static.joinpath("favicon.svg").read_bytes()

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
                        return self._json({"now": int(time.time()), "devices": devices_json(conn)})
                    limit = int(parse_qs(url.query).get("limit", ["100"])[0])
                    return self._json({"events": events_json(conn, min(max(limit, 1), 1000))})
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
                    "device": device_json(row),
                    "history": online_spans(conn, mac, since, now, offline_after),
                    "events": events_json(conn, 100, mac),
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

        def _settings(self, conn) -> dict:
            return {**settings_mod.load(conn), "ntfy_configured": bool(ntfy_url), "pihole_configured": pihole is not None,
                    "now": int(time.time())}

        def _pause(self, conn, mac: str, action: str, body: dict):
            if pihole is None:
                return self._json({"error": "Pi-hole isn't set up in config.toml"}, 409)
            until, now = body.get("until"), int(time.time())
            if action == "pause" and until is not None and not (
                isinstance(until, int) and not isinstance(until, bool) and now < until <= now + MAX_PAUSE
            ):
                return self._json({"error": "until must be a future unix time within 7 days, or null"}, 400)
            try:
                with PiholeClient(pihole.url, pihole.password, timeout=15).admin() as admin:
                    if action == "pause":
                        pause_mod.pause(conn, admin, mac, until)
                    else:
                        pause_mod.resume(conn, admin, mac)
            except LookupError:
                return self._json({"error": "unknown device"}, 404)
            except ValueError as e:
                return self._json({"error": str(e)}, 409)
            except Exception as e:
                log.warning("Pi-hole %s failed", action, exc_info=True)
                return self._json({"error": f"Pi-hole {action} failed: {e}"}, 502)
            pause_mod.touch(pihole.sync_trigger)
            row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
            return self._json({"ok": True, "device": device_json(row)})

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

            conn = db.connect(db_path)
            try:
                if path == "/api/settings":
                    try:
                        settings_mod.save(conn, body)
                    except ValueError as e:
                        return self._json({"error": str(e)}, 400)
                    return self._json(self._settings(conn))

                m = DEVICE_PATH.fullmatch(path)
                if not m:
                    return self._json({"error": "not found"}, 404)
                mac, field = m.groups()
                if field in ("pause", "resume"):
                    return self._pause(conn, mac, field, body)
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
