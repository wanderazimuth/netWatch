from __future__ import annotations

import argparse
import ipaddress
import logging
import time
from datetime import datetime

from . import config as config_mod
from . import db, notify, pause, portscan, scanner, tracker
from .deco import Deco
from .info import merge_info
from .pihole import PiholeClient

log = logging.getLogger("netwatch")


def make_deco(cfg: config_mod.Config) -> Deco | None:
    if cfg.deco is None:
        return None
    return Deco(cfg.deco.url, cfg.deco.password_file, cfg.deco.poll_interval)


def scan_once(cfg: config_mod.Config, conn, deco: Deco | None = None) -> list[tracker.Event]:
    sightings = scanner.arp_scan(cfg.network, cfg.interface)
    pihole_info = deco_info = {}
    if cfg.pihole is not None:
        try:
            pihole_info = PiholeClient(cfg.pihole.url, cfg.pihole.password).device_info()
        except Exception:
            # Names are a nice-to-have; keep scanning if Pi-hole is unreachable.
            log.warning("Pi-hole lookup failed; continuing without names", exc_info=True)
    if deco is not None:
        # Only count the Deco's clients as present when the list is fresh;
        # between polls it is up to poll_interval old.
        if deco.refresh():
            arp_macs = {s.mac for s in sightings}
            sightings += [s for s in deco.sightings(cfg.network) if s.mac not in arp_macs]
        deco_info = deco.device_info()
    # Deco names come first: they're what the router (and you, in the Deco app) call the device.
    info = merge_info(deco_info, pihole_info)
    now = int(time.time())
    events = tracker.apply_scan(conn, sightings, now, cfg.offline_after, info)
    events += tracker.check_down(conn, now)
    log.debug("scan found %d devices, %d events", len(sightings), len(events))
    return events


def maintain_pauses(cfg: config_mod.Config, conn) -> None:
    """End expired pauses and follow paused devices to new IPs."""
    if cfg.pihole is None or not pause.needs_maintenance(conn, int(time.time())):
        return
    try:
        with PiholeClient(cfg.pihole.url, cfg.pihole.password, timeout=15).admin() as admin:
            changed = pause.maintain(conn, admin, int(time.time()))
    except Exception:
        log.warning("updating paused devices in Pi-hole failed; will retry", exc_info=True)
        return
    if changed:
        pause.touch(cfg.pihole.sync_trigger)


def cmd_run(cfg, conn, args) -> None:
    log.info("watching %s on %s every %ds", cfg.network, cfg.interface, cfg.scan_interval)
    deco = make_deco(cfg)
    heartbeat_ok = True
    while True:
        started = time.monotonic()
        try:
            notify.send(scan_once(cfg, conn, deco), conn, cfg.ntfy_url, cfg.dashboard_url)
        except Exception:
            log.exception("scan failed")
        else:
            # Only after a good scan: a stuck or failing scanner should look as dead as a dead Pi.
            if cfg.heartbeat_url:
                ok = notify.heartbeat(cfg.heartbeat_url)
                if ok != heartbeat_ok:  # log changes, not a line a minute while the internet is down
                    (log.info if ok else log.warning)("heartbeat ping %s", "working again" if ok else "failing")
                heartbeat_ok = ok
        maintain_pauses(cfg, conn)
        time.sleep(max(0.0, cfg.scan_interval - (time.monotonic() - started)))


def cmd_scan(cfg, conn, args) -> None:
    for e in scan_once(cfg, conn, make_deco(cfg)):
        print(notify.format_event(e))
    cmd_devices(cfg, conn, args)


def cmd_portscan(cfg, conn, args) -> None:
    scanned = portscan.targets(conn)
    if not scanned:
        log.info("no devices online to scan")
        return
    log.info("port scanning %d devices", len(scanned))
    results = portscan.parse(portscan.run_nmap(sorted(scanned)))
    events = portscan.record(conn, scanned, results, int(time.time()))
    names = {r["mac"]: db.display_name(r) for r in conn.execute("SELECT * FROM devices")}
    for ip, ports in sorted(results.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
        if ports and scanned.get(ip) in names:
            print(f"{ip:<16}{names[scanned[ip]][:31]:<32}{', '.join(map(str, ports))}")
    if missed := sorted(set(scanned) - set(results)):
        log.warning("scan timed out for %s", ", ".join(missed))
    notify.send(events, conn, cfg.ntfy_url, cfg.dashboard_url)


def cmd_devices(cfg, conn, args) -> None:
    rows = conn.execute("SELECT * FROM devices").fetchall()
    rows.sort(key=lambda r: (not r["online"], ipaddress.ip_address(r["ip"]) if r["ip"] else ipaddress.ip_address("255.255.255.255")))
    print(f"{'':2}{'IP':<16}{'MAC':<19}{'NAME':<32}LAST SEEN")
    for r in rows:
        mark = "* " if r["online"] else "  "
        seen = datetime.fromtimestamp(r["last_seen"]).strftime("%Y-%m-%d %H:%M")
        print(f"{mark}{r['ip'] or '':<16}{r['mac']:<19}{db.display_name(r)[:31]:<32}{seen}")
    print(f"\n{sum(r['online'] for r in rows)} online / {len(rows)} known  (* = online)")


def cmd_events(cfg, conn, args) -> None:
    rows = conn.execute(
        "SELECT e.ts, e.kind, e.ip, d.* FROM events e JOIN devices d USING (mac)"
        " ORDER BY e.ts DESC, e.id DESC LIMIT ?",
        (args.limit,),
    ).fetchall()
    for r in reversed(rows):
        ts = datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d %H:%M")
        print(f"{ts}  {r['kind']:<10}{r['ip'] or '':<16}{db.display_name(r)}")


def cmd_label(cfg, conn, args) -> None:
    cur = conn.execute("UPDATE devices SET label = ? WHERE mac = ?", (args.name or None, args.mac.lower()))
    conn.commit()
    print("labelled" if cur.rowcount else f"unknown MAC {args.mac}")


def cmd_web(cfg, conn, args) -> None:
    from . import web

    conn.close()  # the server opens a connection per request
    web.serve(cfg.db_path, args.host, args.port, cfg.ntfy_url, cfg.dashboard_url, cfg.pihole, cfg.offline_after)


def main() -> None:
    parser = argparse.ArgumentParser(prog="netwatch", description="Watch devices join and leave the network.")
    parser.add_argument("-c", "--config", default="/etc/netwatch/config.toml")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="scan forever (what the systemd service runs)").set_defaults(func=cmd_run)
    sub.add_parser("scan", help="scan once and print devices").set_defaults(func=cmd_scan)
    sub.add_parser("devices", help="list known devices").set_defaults(func=cmd_devices)
    sub.add_parser("portscan", help="port scan online devices and alert on new open ports (weekly timer)"
                   ).set_defaults(func=cmd_portscan)
    p = sub.add_parser("events", help="show recent join/leave events")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.set_defaults(func=cmd_events)
    p = sub.add_parser("label", help="give a device a friendly name (empty name clears it)")
    p.add_argument("mac")
    p.add_argument("name")
    p.set_defaults(func=cmd_label)
    p = sub.add_parser("web", help="serve the web dashboard")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.set_defaults(func=cmd_web)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",  # journald adds timestamps
    )
    cfg = config_mod.load(args.config)
    conn = db.connect(cfg.db_path)
    args.func(cfg, conn, args)


if __name__ == "__main__":
    main()
