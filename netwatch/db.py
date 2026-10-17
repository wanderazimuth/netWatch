from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT,
    hostname   TEXT,
    vendor     TEXT,
    label      TEXT,              -- your own name for the device, set via `netwatch label`
    first_seen INTEGER NOT NULL,  -- unix seconds
    last_seen  INTEGER NOT NULL,
    online     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    id   INTEGER PRIMARY KEY,
    ts   INTEGER NOT NULL,
    mac  TEXT NOT NULL REFERENCES devices(mac),
    kind TEXT NOT NULL,           -- new | online | offline | ip_change
    ip   TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    # WAL lets the dashboard read while the scanner writes.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def display_name(row: sqlite3.Row) -> str:
    return row["label"] or row["hostname"] or row["vendor"] or row["mac"]
