"""Minimal Pi-hole v6 API client, used only to enrich devices with names."""

from __future__ import annotations

import json
import logging
import urllib.request
from contextlib import contextmanager
from urllib.parse import quote

from .info import DeviceInfo, usable_name

log = logging.getLogger(__name__)


class PiholeClient:
    def __init__(self, url: str, password: str, timeout: float = 5.0):
        self.url = url.rstrip("/")
        self.password = password
        self.timeout = timeout

    def _request(self, method: str, path: str, sid: str | None = None, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if sid:
            req.add_header("X-FTL-SID", sid)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = resp.read()
        return json.loads(payload) if payload else {}

    @contextmanager
    def _session(self):
        sid = None
        if self.password:
            auth = self._request("POST", "/api/auth", body={"password": self.password})
            sid = auth["session"]["sid"]
        try:
            yield sid
        finally:
            # Pi-hole caps concurrent sessions, so release ours every time.
            if sid:
                try:
                    self._request("DELETE", "/api/auth", sid=sid)
                except Exception:
                    log.debug("Pi-hole logout failed", exc_info=True)

    def device_info(self) -> dict[str, DeviceInfo]:
        """Map lowercase MAC -> hostname/vendor from Pi-hole's network table."""
        with self._session() as sid:
            devices = self._request("GET", "/api/network/devices", sid=sid).get("devices", [])

        info = {}
        for dev in devices:
            mac = (dev.get("hwaddr") or "").lower()
            if not mac or mac.startswith("ip-"):  # Pi-hole uses "ip-<addr>" for clients with no known MAC
                continue
            name = next((ip["name"] for ip in dev.get("ips", []) if usable_name(ip.get("name"))), None)
            info[mac] = DeviceInfo(hostname=name, vendor=dev.get("macVendor") or None)
        return info

    def queries(self, client_ip: str, limit: int) -> dict:
        """The most recent DNS queries from one client (newest first), from Pi-hole's
        in-memory log, which covers about the last 24 hours."""
        with self._session() as sid:
            return self._request("GET", f"/api/queries?client_ip={quote(client_ip)}&length={limit}", sid=sid)
