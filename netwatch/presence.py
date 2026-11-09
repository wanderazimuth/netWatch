"""Who's home: a person is home while one of their phones (or watches) is on the network.

Laptops and TVs stay home when people leave, so only these kinds count. Phones also go quiet
on Wi-Fi while they sleep (gaps of 20-60 minutes are common here), so someone only counts as
away once all their phones have been gone for away_after; shorter gaps are bridged.
"""

from __future__ import annotations

import sqlite3

from . import db

KINDS = ("phone", "wearable")


def bridge(spans: list[list[int]], gap: int) -> list[list[int]]:
    """The union of [from, to] spans, joining ones less than gap seconds apart."""
    out: list[list[int]] = []
    for a, b in sorted(spans):
        if out and a - out[-1][1] < gap:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def people(conn: sqlite3.Connection, names: list[str], start: int, end: int, offline_after: int,
           away_after: int, spans_of) -> list[dict]:
    """Each person on the list (and anyone else a phone belongs to): home or away, since when,
    and when they were home between start and end. spans_of(conn, mac, start, end, offline_after)
    gives a device's online spans."""
    rows = conn.execute(f"SELECT * FROM devices WHERE person IS NOT NULL AND kind IN ({', '.join('?' * len(KINDS))})",
                        KINDS).fetchall()
    out = []
    for name in names + sorted({r["person"] for r in rows} - set(names)):
        phones = [r for r in rows if r["person"] == name]
        spans = bridge([s for r in phones for s in spans_of(conn, r["mac"], start, end, offline_after)["spans"]],
                       away_after)
        last_seen = max((r["last_seen"] for r in phones), default=None)
        # Still home while the last sighting is within the grace period.
        home = bool(phones) and last_seen is not None and end - last_seen < away_after
        if home and spans:
            spans[-1][1] = end
        out.append({
            "person": name,
            "devices": [{"mac": r["mac"], "name": db.display_name(r)} for r in phones],
            "home": home if phones else None,
            # Home since they arrived; away since their phone was last seen.
            "since": (spans[-1][0] if spans else None) if home else last_seen,
            "spans": spans,
        })
    return out
