"""Minimal Pi-hole v6 API client, used only to enrich devices with names."""

from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeviceInfo:
    hostname: str | None
    vendor: str | None


def usable_name(name: str | None) -> bool:
    # Pi-hole's network table can carry its own PTR name ("pi.hole") against
    # unrelated clients, so it says nothing about the device.
    return bool(name) and name.lower().rstrip(".") != "pi.hole"


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

    def device_info(self) -> dict[str, DeviceInfo]:
        """Map lowercase MAC -> hostname/vendor from Pi-hole's network table."""
        sid = None
        if self.password:
            auth = self._request("POST", "/api/auth", body={"password": self.password})
            sid = auth["session"]["sid"]
        try:
            devices = self._request("GET", "/api/network/devices", sid=sid).get("devices", [])
        finally:
            # Pi-hole caps concurrent sessions, so release ours every time.
            if sid:
                try:
                    self._request("DELETE", "/api/auth", sid=sid)
                except Exception:
                    log.debug("Pi-hole logout failed", exc_info=True)

        info = {}
        for dev in devices:
            mac = (dev.get("hwaddr") or "").lower()
            if not mac or mac.startswith("ip-"):  # Pi-hole uses "ip-<addr>" for clients with no known MAC
                continue
            name = next((ip["name"] for ip in dev.get("ips", []) if usable_name(ip.get("name"))), None)
            info[mac] = DeviceInfo(hostname=name, vendor=dev.get("macVendor") or None)
        return info
