"""Minimal Pi-hole v6 API client: device names, per-device lookups, and pausing devices."""

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

    @contextmanager
    def admin(self):
        """One login session for changing groups, rules and clients."""
        with self._session() as sid:
            yield PiholeAdmin(self, sid)


PAUSE_GROUP = "NetWatch paused"
BLOCK_ALL = ".*"


class PiholeAdmin:
    """The few gravity-database changes NetWatch makes to pause devices."""

    def __init__(self, client: PiholeClient, sid: str | None):
        self.client = client
        self.sid = sid

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        return self.client._request(method, path, self.sid, body)

    def _group_id(self, name: str) -> int | None:
        return next((g["id"] for g in self._call("GET", "/api/groups")["groups"] if g["name"] == name), None)

    def ensure_pause_group(self) -> int:
        """Create (or repair) the group whose members get every lookup blocked; return its id."""
        gid = self._group_id(PAUSE_GROUP)
        if gid is None:
            self._call("POST", "/api/groups", {
                "name": PAUSE_GROUP, "enabled": True,
                "comment": "Managed by NetWatch: devices here have their internet paused",
            })
            gid = self._group_id(PAUSE_GROUP)
        rule = next((d for d in self._call("GET", "/api/domains/deny/regex")["domains"] if d["domain"] == BLOCK_ALL), None)
        body = {"comment": "Managed by NetWatch: blocks everything for paused devices", "enabled": True}
        if rule is None:
            self._call("POST", "/api/domains/deny/regex", {"domain": BLOCK_ALL, "groups": [gid], **body})
        elif gid not in rule["groups"] or not rule["enabled"]:
            self._call("PUT", f"/api/domains/deny/regex/{quote(BLOCK_ALL, safe='')}",
                       {"groups": sorted(set(rule["groups"]) | {gid}), **body})
        return gid

    def get_client(self, client: str) -> dict | None:
        found = self._call("GET", f"/api/clients/{quote(client, safe='')}").get("clients", [])
        return found[0] if found else None

    def save_client(self, client: str, groups: list[int], comment: str | None) -> None:
        body = {"groups": groups, "comment": comment}
        if self.get_client(client) is None:
            self._call("POST", "/api/clients", {"client": client, **body})
        else:
            self._call("PUT", f"/api/clients/{quote(client, safe='')}", body)

    def delete_client(self, client: str) -> None:
        self._call("DELETE", f"/api/clients/{quote(client, safe='')}")
