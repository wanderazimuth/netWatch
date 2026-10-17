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
    deco       TEXT,              -- which Deco unit it's connected through
    label      TEXT,              -- your own name for the device, set via `netwatch label`
    notify     INTEGER NOT NULL DEFAULT 0,  -- 1 = push when it comes online / goes offline
    down_after INTEGER,           -- minutes unseen before a "device down" alert; NULL = off
    down_since INTEGER,           -- last_seen when the down alert fired; NULL = not alerted
    paused_ip  TEXT,              -- IP whose lookups Pi-hole is blocking; NULL = not paused
    paused_until INTEGER,         -- when the pause ends; NULL = until resumed
    paused_restore TEXT,          -- JSON: the Pi-hole client entry paused_ip had before, to put back
    ports_scanned INTEGER,        -- last port scan of this device; NULL = never scanned
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

-- Every port a device has had open. A port is open now if last_seen equals
-- the device's ports_scanned.
CREATE TABLE IF NOT EXISTS ports (
    mac        TEXT NOT NULL REFERENCES devices(mac),
    port       INTEGER NOT NULL,
    proto      TEXT NOT NULL,     -- tcp
    service    TEXT,              -- nmap's usual name for the port
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (mac, port, proto)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL           -- JSON
);
"""

# Columns added after the first release, for upgrading existing databases.
ADDED_COLUMNS = {
    "connection": "TEXT",
    "deco": "TEXT",
    "notify": "INTEGER NOT NULL DEFAULT 0",
    "down_after": "INTEGER",
    "down_since": "INTEGER",
    "paused_ip": "TEXT",
    "paused_until": "INTEGER",
    "paused_restore": "TEXT",
    "ports_scanned": "INTEGER",
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
            try:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError as e:
                # Another connection (scanner or a parallel dashboard request) added it first.
                if "duplicate column" not in str(e):
                    raise
    return conn


def display_name(row: sqlite3.Row) -> str:
    return row["label"] or row["hostname"] or row["vendor"] or row["mac"]
