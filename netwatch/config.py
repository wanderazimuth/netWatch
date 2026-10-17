from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class PiholeConfig:
    url: str = "http://127.0.0.1"
    password: str = ""
    # Touched whenever NetWatch changes Pi-hole (pausing a device), so a systemd
    # path unit can copy the change to a replica Pi-hole right away.
    sync_trigger: str = ""


@dataclass
class DecoConfig:
    url: str = "http://192.168.0.1"
    password_file: str = "/etc/netwatch/deco_password"
    # Fetching the client list takes several seconds and each login may bump
    # the Deco app's session, so poll much less often than the ARP scan.
    poll_interval: int = 300


@dataclass
class Config:
    interface: str = "eth0"
    network: str = "192.168.0.0/24"
    scan_interval: int = 60
    offline_after: int = 600
    db_path: str = "/var/lib/netwatch/netwatch.db"
    ntfy_url: str = ""
    dashboard_url: str = ""  # tapping an alert opens this
    pihole: PiholeConfig | None = None
    deco: DecoConfig | None = None


def load(path: str | Path) -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    pihole = raw.pop("pihole", None)
    deco = raw.pop("deco", None)
    config = Config(**raw)
    if pihole is not None:
        config.pihole = PiholeConfig(**pihole)
    if deco is not None:
        config.deco = DecoConfig(**deco)
    if config.offline_after <= config.scan_interval:
        raise ValueError("offline_after must be greater than scan_interval")
    return config
