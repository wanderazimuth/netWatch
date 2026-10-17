# netWatch
Fing replacement to watch devices enter and leave my home network.

Runs on the Raspberry Pi alongside Pi-hole: ARP-scans the LAN every minute,
records every device in SQLite, and reports when devices join, leave, or change
IP. Optionally pulls device names and connection type from a TP-Link Deco mesh
and Pi-hole, and pushes new-device alerts via [ntfy](https://ntfy.sh).

## Layout

```
netwatch/
  scanner.py   ARP sweep (scapy)
  pihole.py    Pi-hole v6 API client for hostnames/vendors
  deco.py      TP-Link Deco client list: names + wired/2.4/5 GHz (optional)
  info.py      merges device details from the Deco and Pi-hole
  tracker.py   scan results -> device state + events (pure logic, unit-tested)
  db.py        SQLite schema
  notify.py    log + ntfy alerts (what to push, quiet hours, grouping)
  settings.py  alert settings stored in SQLite, edited from the dashboard
  web.py       dashboard server (stdlib only) + JSON API
  static/      dashboard page
  __main__.py  CLI: run | scan | devices | events | label | web
deploy/
  netwatch.service      scanner (runs as `netwatch` user with only CAP_NET_RAW)
  netwatch-web.service  dashboard on port 8080 (no capabilities)
  install.sh         install/update on the Pi
tests/
config.example.toml
```

## Install on the Pi

```sh
sudo git clone https://github.com/wanderazimuth/netWatch.git /opt/netwatch
sudo bash /opt/netwatch/deploy/install.sh
sudo nano /etc/netwatch/config.toml      # then: sudo systemctl restart netwatch
```

Update later with `cd /opt/netwatch && sudo git pull && sudo bash deploy/install.sh`.

## Dashboard

http://192.168.0.10:8080 -- live device list (search, filter, sort), activity
feed, and click-to-rename. Refreshes every 30 s. Click a device's row for its
detail page: which Deco it's connected through, a 7-day online timeline with
uptime, its join/leave history, and its top DNS lookups from Pi-hole over the
last 24 hours (needs the `[pihole]` config section). There is no login: anyone on
the LAN can view it and rename devices, so don't expose port 8080 to the internet.

## Pause internet

The device page's **Pause internet** button blocks every DNS lookup from that
device through Pi-hole, for 30 min / 1 h / 2 h / until 7:00 / until you resume.
NetWatch creates a Pi-hole group, "NetWatch paused", with a block-everything
regex rule (`.*`), and points a client entry for the device's IP at it. Resume
puts back whatever client entry that IP had before. Timed pauses end on their
own, and if a paused device gets a new IP the pause moves with it.

It's DNS-only: apps that are already connected keep working until they look
something up again, and a device set to use its own DNS server isn't affected.
Pauses are by IP rather than MAC because a Pi-hole in Docker (like the NAS
replica) can't see MACs.

With a replica Pi-hole kept in sync by nebula-sync, set `sync_trigger` in the
`[pihole]` config section and add a path unit, so the replica gets the change
right away instead of on its next scheduled sync:

```ini
# /etc/systemd/system/nebula-sync-now.path
[Path]
PathModified=/var/lib/netwatch/pihole-changed
Unit=nebula-sync.service

[Install]
WantedBy=multi-user.target
```

`sudo systemctl enable --now nebula-sync-now.path`

## Alerts

Push notifications go through [ntfy](https://ntfy.sh): set `ntfy_url` (a long,
random topic -- anyone who knows it can read your alerts) in
`/etc/netwatch/config.toml`, install the ntfy app, and subscribe to that topic.

What gets pushed is controlled from the dashboard's **Alerts** button, no SSH needed:

- **Push alerts** -- master on/off switch (events are still logged either way)
- **New devices**, optionally skipping private-MAC devices (rotating phone MACs)
- **Arrivals & departures** of devices you've marked with the row's bell
- **Offline alerts**: click a row's 🚨 to pick a time (5 min to 24 h). If the device
  isn't seen for that long you get one high-priority alert, then another when it's
  back. Meant for always-on devices like the NAS or cameras; devices that are down
  show a red dot on the dashboard
- **Snooze** for 1 / 8 / 24 hours
- **Quiet hours** -- deliver silently, or don't send at all
- **Send test notification**

Several changes in one scan arrive as one notification, not a burst.

## Command line

```sh
journalctl -u netwatch -f                       # live join/leave log
sudo -u netwatch /opt/netwatch/.venv/bin/netwatch devices
sudo -u netwatch /opt/netwatch/.venv/bin/netwatch events -n 20
sudo -u netwatch /opt/netwatch/.venv/bin/netwatch label aa:bb:cc:dd:ee:ff "Kitchen speaker"
```

## Develop

```sh
python -m unittest discover tests
```

`config.toml` and `*.db` are gitignored -- keep device data and passwords out of the repo.
