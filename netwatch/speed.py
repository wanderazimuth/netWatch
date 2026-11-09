"""Hourly internet speed tests with Ookla's CLI, put off while people are using the internet.

A systemd timer runs `netwatch speedtest` every 10 minutes. Once an hour has a full test, the
rest of that hour's runs do nothing. Before a test, the Deco is asked how much each device is
moving; if someone is streaming or on a call, a ping-only check (next to no data) is recorded
instead, and the next run tries again. The dashboard's "Run test now" skips the busy check.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime

from . import db

log = logging.getLogger(__name__)

SPEEDTEST = ["speedtest", "--format=json", "--accept-license", "--accept-gdpr"]
PING = ["ping", "-c", "20", "-i", "0.2", "-W", "2", "1.1.1.1"]
TIMEOUT = 120  # a test takes about 30 s; up to three tries fit the service's 10 minutes
# Devices that move data all day without anyone using them, so they never make the internet "busy".
BACKGROUND_KINDS = frozenset({"camera", "smart_home", "appliance", "printer", "network", "server"})
# Touched by the dashboard's "Run test now"; a systemd path unit starts the test when it appears.
REQUEST_FILE = "speedtest.request"
MAX_DECO_BACKOFF = 6 * 3600


@dataclass
class Result:
    kind: str  # "full", or "ping" when only a ping check ran because the internet was busy
    down: float | None = None  # Mbps
    up: float | None = None
    ping: float | None = None  # ms
    jitter: float | None = None
    loss: float | None = None  # percent
    server: str | None = None
    url: str | None = None  # Ookla's page for the result
    busy: str | None = None  # who kept the internet busy, for a ping check
    error: str | None = None


def parse_ookla(text: str) -> Result:
    r = json.loads(text)
    server = r.get("server") or {}
    return Result(
        "full",
        down=round(r["download"]["bandwidth"] * 8 / 1e6, 1),
        up=round(r["upload"]["bandwidth"] * 8 / 1e6, 1),
        ping=round(r["ping"]["latency"], 1),
        jitter=round(r["ping"]["jitter"], 1),
        loss=round(r["packetLoss"], 1) if r.get("packetLoss") is not None else None,
        server=", ".join(x for x in (server.get("name"), server.get("location")) if x) or None,
        url=(r.get("result") or {}).get("url"),
    )


def parse_ping(text: str) -> Result:
    sent = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    if not sent:
        raise ValueError("couldn't read ping's output")
    out = Result("ping", loss=round(100 * (1 - int(sent[2]) / int(sent[1])), 1))
    rtt = re.search(r"= [\d.]+/([\d.]+)/[\d.]+/([\d.]+) ms", text)
    if rtt:
        out.ping, out.jitter = round(float(rtt[1]), 1), round(float(rtt[2]), 1)
    return out


def _error(e: Exception) -> str:
    if isinstance(e, subprocess.CalledProcessError):
        # Ookla writes its errors to stderr as JSON log lines.
        for line in reversed((e.stderr or "").strip().splitlines()):
            try:
                return json.loads(line).get("message") or line
            except ValueError:
                return line
    if isinstance(e, FileNotFoundError):
        return f"{e.filename} isn't installed"
    return str(e) or type(e).__name__


def run_full(servers: list[int] = ()) -> Result:
    """Test against the first of servers (Ookla server IDs) that works, then Ookla's own pick.

    Ookla picks the server with the lowest ping, and from a Starlink connection that's often one
    that can't fill the line (75-110 Mbps, against 180+ from others, measured 2026-11-09).
    """
    error = None
    for server in [*servers, None]:
        cmd = SPEEDTEST + ([f"--server-id={server}"] if server else [])
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=TIMEOUT).stdout
            return parse_ookla(out)
        except Exception as e:
            error = _error(e)
            log.warning("speed test %sfailed: %s", f"with server {server} " if server else "", error)
    return Result("full", error=error)


def run_ping(busy: str) -> Result:
    try:
        # ping exits non-zero when replies go missing; the counts are still in its output.
        out = subprocess.run(PING, capture_output=True, text=True, timeout=60).stdout
        result = parse_ping(out)
    except Exception as e:
        result = Result("ping", error=_error(e))
    result.busy = busy
    return result


def busy_devices(conn: sqlite3.Connection, traffic: dict[str, tuple[int, int]], threshold_kbps: float) -> list[str]:
    """Names of the devices people use that are moving more than the threshold, busiest first."""
    kinds = {r["mac"]: r for r in conn.execute("SELECT * FROM devices")}
    busy = []
    for mac, (down, up) in sorted(traffic.items(), key=lambda kv: -max(kv[1])):
        row = kinds.get(mac)
        if max(down, up) > threshold_kbps and not (row is not None and row["kind"] in BACKGROUND_KINDS):
            busy.append(db.display_name(row) if row is not None else mac)
    return busy


def _state(conn: sqlite3.Connection, key: str):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else None


def _set_state(conn: sqlite3.Connection, key: str, value) -> None:
    # Kept beside the settings but not one of them, so the dashboard can't change it.
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, json.dumps(value)))
    conn.commit()


def deco_traffic(conn: sqlite3.Connection, fetch, password_file: str, now: int) -> dict[str, tuple[int, int]] | None:
    """fetch() from the Deco, or None when it fails or is backing off.

    Failed logins count toward the Deco's lockout, and this runs every 10 minutes in its own
    process, so failures back off here as in the scanner: doubling, and reset by a new password.
    """
    try:
        mtime = os.stat(password_file).st_mtime
    except OSError:
        mtime = None
    state = _state(conn, "speed_deco_backoff") or {"failures": 0, "next": 0, "mtime": mtime}
    if state["failures"] and now < state["next"] and state["mtime"] == mtime:
        return None
    try:
        traffic = fetch()
    except Exception as e:
        failures = state["failures"] + 1
        delay = min(600 * 2 ** failures, MAX_DECO_BACKOFF)
        log.warning("Deco traffic check failed (%s); next try in %d min", e, delay // 60)
        _set_state(conn, "speed_deco_backoff", {"failures": failures, "next": now + delay, "mtime": mtime})
        return None
    if state["failures"]:
        _set_state(conn, "speed_deco_backoff", {"failures": 0, "next": 0, "mtime": mtime})
    return traffic


def record(conn: sqlite3.Connection, ts: int, r: Result) -> None:
    row = asdict(r)
    conn.execute(f"INSERT INTO speedtests (ts, {', '.join(row)}) VALUES (?, {', '.join('?' * len(row))})",
                 (ts, *row.values()))
    conn.commit()


def hour_start(now: int) -> int:
    return int(datetime.fromtimestamp(now).replace(minute=0, second=0, microsecond=0).timestamp())


def run(conn: sqlite3.Connection, now: int, traffic, busy_mbps: float, force: bool = False,
        servers: list[int] = ()) -> Result | None:
    """One timer run. traffic() returns each client's (down, up) kbit/s, None when the Deco can't
    say, or is None itself when there's no Deco to ask. Returns what was recorded, if anything."""
    start = hour_start(now)
    if not force:
        done = conn.execute("SELECT 1 FROM speedtests WHERE kind = 'full' AND ts >= ?", (start,)).fetchone()
        if done:
            return None
        clients = traffic() if traffic is not None else {}
        if clients is None:
            busy = "couldn't check the Deco"
        else:
            names = busy_devices(conn, clients, busy_mbps * 1000)
            busy = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "") if names else None
        if busy:
            log.info("internet busy (%s); ping check only", busy)
            # One ping check per busy stretch is plenty; later tries just look again.
            pinged = conn.execute("SELECT 1 FROM speedtests WHERE ts >= ?", (start,)).fetchone()
            if pinged:
                return None
            result = run_ping(busy)
            record(conn, now, result)
            return result
    result = run_full(servers)
    record(conn, now, result)
    return result


def take_request(state_dir: str) -> bool:
    """True if the dashboard asked for a test; the request is used up."""
    try:
        os.remove(os.path.join(state_dir, REQUEST_FILE))
        return True
    except FileNotFoundError:
        return False


def results(conn: sqlite3.Connection, since: int) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM speedtests WHERE ts >= ? ORDER BY ts", (since,))]
