from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT,
    hostname   TEXT,
    vendor     TEXT,
    connection TEXT,              -- from the Deco: wired / 2.4 GHz / 5 GHz ...
    label      TEXT,              -- your own name for the device, set via `netwatch label`
    notify     INTEGER NOT NULL DEFAULT 0,  -- 1 = push when it comes online / goes offline
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

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL           -- JSON
);
"""

# Columns added after the first release, for upgrading existing databases.
ADDED_COLUMNS = {
    "connection": "TEXT",
    "notify": "INTEGER NOT NULL DEFAULT 0",
}


def connect(path: str | Path) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    # WAL lets the dashboard read while the scanner writes.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}
    for column, decl in ADDED_COLUMNS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {decl}")
    return conn


def display_name(row: sqlite3.Row) -> str:
    return row["label"] or row["hostname"] or row["vendor"] or row["mac"]
