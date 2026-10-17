"""Read-mostly web dashboard over the NetWatch database.

Stdlib only, so the Pi needs nothing extra installed. Intended for the home
LAN: there is no login, and anyone who can reach the port can relabel devices.
"""

from __future__ import annotations

import json
import logging
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlparse

from . import db
from .scanner import is_randomized_mac

log = logging.getLogger(__name__)

LABEL_PATH = re.compile(r"/api/devices/([0-9a-f]{2}(?::[0-9a-f]{2}){5})/label")


def devices_json(conn) -> list[dict]:
    rows = conn.execute("SELECT * FROM devices").fetchall()
    return [
        {
            "mac": r["mac"],
            "ip": r["ip"],
            "hostname": r["hostname"],
            "vendor": r["vendor"],
            "connection": r["connection"],
            "label": r["label"],
            "name": db.display_name(r),
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "online": bool(r["online"]),
            "randomized": is_randomized_mac(r["mac"]),
        }
        for r in rows
    ]


def events_json(conn, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT e.ts, e.kind, e.ip AS event_ip, d.* FROM events e JOIN devices d USING (mac)"
        " ORDER BY e.ts DESC, e.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [{"ts": r["ts"], "kind": r["kind"], "ip": r["event_ip"], "mac": r["mac"], "name": db.display_name(r)} for r in rows]


def make_handler(db_path: str):
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
            if url.path in ("/api/devices", "/api/events"):
                conn = db.connect(db_path)
                try:
                    if url.path == "/api/devices":
                        return self._json({"now": int(time.time()), "devices": devices_json(conn)})
                    limit = int(parse_qs(url.query).get("limit", ["100"])[0])
                    return self._json({"events": events_json(conn, min(max(limit, 1), 1000))})
                finally:
                    conn.close()
            self._json({"error": "not found"}, 404)

        def do_POST(self):
            m = LABEL_PATH.fullmatch(urlparse(self.path).path)
            if not m:
                return self._json({"error": "not found"}, 404)
            # Requiring JSON forces a CORS preflight for cross-site requests, which we
            # never approve -- so other websites can't relabel devices via your browser.
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._json({"error": "expected application/json"}, 415)
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                label = (body.get("label") or "").strip()[:64] or None
            except (ValueError, AttributeError):
                return self._json({"error": "bad request"}, 400)
            conn = db.connect(db_path)
            try:
                cur = conn.execute("UPDATE devices SET label = ? WHERE mac = ?", (label, m.group(1)))
                conn.commit()
            finally:
                conn.close()
            if not cur.rowcount:
                return self._json({"error": "unknown device"}, 404)
            self._json({"ok": True})

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(db_path: str, host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(db_path))
    log.info("dashboard on http://%s:%d", host, port)
    server.serve_forever()
