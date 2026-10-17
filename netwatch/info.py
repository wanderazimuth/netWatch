"""Device details from enrichment sources (Pi-hole, Deco), merged by priority."""

from __future__ import annotations

from dataclasses import dataclass, fields

# Names that say nothing about the device: Pi-hole can list its own PTR name
# against unrelated clients, and many small IoT gadgets report their TCP/IP
# stack ("lwip") as their hostname.
PLACEHOLDER_NAMES = {"pi.hole", "lwip", "localhost"}


@dataclass(frozen=True)
class DeviceInfo:
    hostname: str | None = None
    vendor: str | None = None
    connection: str | None = None  # e.g. "wired", "5 GHz", "2.4 GHz guest"
    deco: str | None = None  # which Deco unit it's connected through, e.g. "Basement"


def usable_name(name: str | None) -> bool:
    return bool(name) and name.lower().rstrip(".") not in PLACEHOLDER_NAMES


def merge_info(*sources: dict[str, DeviceInfo]) -> dict[str, DeviceInfo]:
    """Combine per-MAC info; for each field the first source with a value wins."""
    merged: dict[str, DeviceInfo] = {}
    for mac in set().union(*sources):
        values = {}
        for f in fields(DeviceInfo):
            values[f.name] = next(
                (getattr(s[mac], f.name) for s in sources if mac in s and getattr(s[mac], f.name)), None
            )
        merged[mac] = DeviceInfo(**values)
    return merged
