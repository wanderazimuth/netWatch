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


@dataclass
class Config:
    interface: str = "eth0"
    network: str = "192.168.0.0/24"
    scan_interval: int = 60
    offline_after: int = 600
    db_path: str = "/var/lib/netwatch/netwatch.db"
    ntfy_url: str = ""
    pihole: PiholeConfig | None = None


def load(path: str | Path) -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    pihole = raw.pop("pihole", None)
    config = Config(**raw)
    if pihole is not None:
        config.pihole = PiholeConfig(**pihole)
    if config.offline_after <= config.scan_interval:
        raise ValueError("offline_after must be greater than scan_interval")
    return config
