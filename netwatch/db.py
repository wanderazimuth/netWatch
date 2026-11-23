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
    paused_by  INTEGER,           -- the schedule that paused it; NULL = paused by hand
    pause_ip_taken INTEGER,       -- 1 = another device has had paused_ip since, so Pi-hole isn't blocking it
    deco_blocked INTEGER,         -- in the Deco's block list: 1 = NetWatch put it there, 2 = it already was; NULL = not
    pause_allowed INTEGER,        -- 1 = the dashboard may pause it (set with the PIN); NULL = no
    sched_skip_until INTEGER,     -- resumed by hand during a schedule: no scheduled pause before this
    ports_scanned INTEGER,        -- last port scan of this device; NULL = never scanned
    status     TEXT,              -- known / guest; NULL = still to review
    reviewed   INTEGER,           -- when it was last marked known or guest
    kind       TEXT,              -- phone / tv / camera ... (inventory.KINDS)
    floor      TEXT,              -- Upstairs / Main floor / Basement / Outside
    room       TEXT,
    person     TEXT,              -- whose it is, from the people list; NULL = shared
    notes      TEXT,
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
CREATE INDEX IF NOT EXISTS events_ip_ts ON events(ip, ts);

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

-- Each device's live speed at every Deco poll (usage.py); only polls that caught it busy.
CREATE TABLE IF NOT EXISTS traffic (
    ts   INTEGER NOT NULL,
    mac  TEXT NOT NULL,
    down INTEGER NOT NULL,        -- kbit/s
    up   INTEGER NOT NULL,
    secs INTEGER NOT NULL         -- how long the reading stands for: the poll interval
);
CREATE INDEX IF NOT EXISTS traffic_mac_ts ON traffic(mac, ts);
CREATE INDEX IF NOT EXISTS traffic_ts ON traffic(ts);

-- Hourly internet speed tests (speed.py).
CREATE TABLE IF NOT EXISTS speedtests (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    kind   TEXT NOT NULL,         -- full | ping (only a ping check: the internet was busy)
    down   REAL,                  -- Mbps
    up     REAL,
    ping   REAL,                  -- ms
    jitter REAL,
    loss   REAL,                  -- percent of packets lost
    server TEXT,
    url    TEXT,                  -- Ookla's page for the result
    busy   TEXT,                  -- who kept the internet busy
    error  TEXT
);
CREATE INDEX IF NOT EXISTS speedtests_ts ON speedtests(ts);

-- When to pause devices (schedule.py). Each targets one device, or one person's or group's pausable devices.
CREATE TABLE IF NOT EXISTS schedules (
    id         INTEGER PRIMARY KEY,
    mac        TEXT,              -- the device, or NULL when it's for a person or group
    person     TEXT,
    group_id   INTEGER,
    days       TEXT NOT NULL,     -- the weekdays it starts on, as digits: 0 = Monday ... 6 = Sunday
    start      TEXT NOT NULL,     -- "HH:MM" local time
    end        TEXT NOT NULL,     -- "HH:MM"; earlier than start means the next morning
    enabled    INTEGER NOT NULL DEFAULT 1,
    skip_until INTEGER            -- "Skip tonight": not before this unix time
);

-- Named sets of devices to pause together (groups.py). A device can be in several.
CREATE TABLE IF NOT EXISTS device_groups (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL,
    mac      TEXT NOT NULL,
    PRIMARY KEY (group_id, mac)
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
    "paused_by": "INTEGER",
    "deco_blocked": "INTEGER",
    "pause_ip_taken": "INTEGER",
    "pause_allowed": "INTEGER",
    "sched_skip_until": "INTEGER",
    "ports_scanned": "INTEGER",
    "status": "TEXT",
    "reviewed": "INTEGER",
    "kind": "TEXT",
    "floor": "TEXT",
    "room": "TEXT",
    "person": "TEXT",
    "notes": "TEXT",
}
ADDED_SCHEDULE_COLUMNS = {
    "group_id": "INTEGER",
}


def connect(path: str | Path) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    # WAL lets the dashboard read while the scanner writes.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    _add_columns(conn, "devices", ADDED_COLUMNS)
    _add_columns(conn, "schedules", ADDED_SCHEDULE_COLUMNS)
    return conn


def _add_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    for column, decl in columns.items():
        if column not in existing:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError as e:
                # Another connection (scanner or a parallel dashboard request) added it first.
                if "duplicate column" not in str(e):
                    raise


def display_name(row: sqlite3.Row) -> str:
    return row["label"] or row["hostname"] or row["vendor"] or row["mac"]
