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
  inventory.py what each device is: review status, type, floor, room, person, notes
  tracker.py   scan results -> device state + events (pure logic, unit-tested)
  db.py        SQLite schema
  notify.py    log + ntfy alerts (what to push, quiet hours, grouping)
  settings.py  alert settings stored in SQLite, edited from the dashboard
  speed.py     hourly internet speed test (Ookla), put off while someone's streaming
  usage.py     each device's internet use, from the Deco's live speeds
  presence.py  who's home, from each person's phones
  security.py  router impersonation, IP conflicts, rogue DHCP servers
  web.py       dashboard server (stdlib only) + JSON API
  static/      dashboard page
  __main__.py  CLI: run | scan | devices | portscan | speedtest | events | label | web
deploy/
  netwatch.service      scanner (runs as `netwatch` user with only CAP_NET_RAW)
  netwatch-web.service  dashboard on port 8080 (no capabilities)
  netwatch-speedtest.*  speed test: every-10-minute timer, and a path unit for "Run test now"
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

**On the phone.** Away from home it's reached over Tailscale, which the
[piServer](https://github.com/wanderazimuth/piServer) repo sets up, at
`https://raspberrypi.<tailnet>.ts.net:8443` (your signed-in devices only). Open that in Chrome
and choose **Add to Home screen > Install** to get NetWatch as an app. The app keeps the page and
the last device list; when the Pi can't be reached it opens with that copy and the header says when
it was saved. Device details, renaming and pausing need the Pi. Installing needs HTTPS, so use the
tailnet address, not http://netwatch.lan.

## Device inventory

Every device starts out **to review**. The dashboard's **Review N devices** button steps through
them one at a time, online ones first. For each, the device page's "About this device" form records:

- **Status:** to review, known (it belongs here) or guest (a visitor's device).
- **Type:** phone, TV, camera and so on, shown as an icon in the device list.
- **Floor and room:** Upstairs, Main floor, Basement or Outside, then a room. Rooms already used on
  that floor are suggested. A device's floor starts out guessed from its Deco, when the Deco is
  named after a floor.
- **Person:** who it belongs to, from the people list (**Edit list** next to it), or shared.
- **Notes.**

The rest of the page has the clues: the Deco it's connected through, its DNS lookups and open
ports. **Skip** leaves a device for later; the "To review" filter and count show what's left.

**Same device as…** is for a phone or laptop that switched to a new private MAC and so showed up as
a new device. Pick the entry it used to be (likely matches come first: the same hostname or maker,
a private MAC, offline now) and that entry's name, details, alerts and history move to the new MAC.
The old entry is removed; if the old MAC ever comes back, it shows up as a new device again.

## Pause internet

The device page's **Pause internet** button blocks every DNS lookup from that
device through Pi-hole, for 30 min / 1 h / 2 h / until 7:00 / until you resume.

The button only appears on devices listed by MAC in `pausable` in the
`[pihole]` config section, and on devices still to review (except the router):
they aren't known to be yours yet, and pausing one for a while is a way to find
out what it is. The server refuses to pause anything else. Since anyone on the
LAN can use the dashboard, this keeps them from pausing your own devices, the Pi
or the router once you've reviewed them. Resume always works.
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
- **New open ports** found by the weekly port scan (below)
- **Network security** problems (below), at high priority
- **Snooze** for 1 / 8 / 24 hours
- **Quiet hours** -- deliver silently, or don't send at all
- **Daily review reminder** at a time you pick: the devices seen this week that are
  still to review (nothing is sent when there are none)
- **Send test notification**

Several changes in one scan arrive as one notification, not a burst.

A new-device alert has buttons: **Review** opens that device's review page, **Guest** marks it a
guest, and **Pause 1 h** pauses its internet for an hour from when you tap it (only with Pi-hole
set up). With several new devices in one alert, **Review devices** starts the walk-through. The
ntfy app sends Guest and Pause itself, so `dashboard_url` must be an address the phone can reach,
such as the tailnet name.

## Is the Pi itself up?

Alerts are sent by the Pi, so if it loses power, crashes or loses its network,
nothing would tell you. Set `heartbeat_url` to the ping URL of a check on
[healthchecks.io](https://healthchecks.io) (free) and NetWatch pings it after
every successful scan. Give the check a period of 1 minute and a grace time of
10 minutes, and connect it to your ntfy topic or email: when pings stop -- Pi
down, NetWatch stuck, or the house internet out -- it alerts you, and again when
they resume.

## Network security

The **Security** button on the dashboard shows three checks, and each problem found sends an alert:

- **Something posing as the router.** Every scan notes which MAC address answers for the
  router's IP, both in the ARP sweep and in the Pi's own ARP cache. The first scan learns the
  router's MAC; any other MAC answering for it may be a device intercepting traffic (ARP spoofing).
- **IP conflicts:** two devices answering for one IP in two scans in a row.
- **A second DHCP server.** Every 15 minutes the Pi broadcasts a DHCP discover and lists who
  offers an address. It never accepts an offer, so nothing changes on the network. Any server
  besides the router is flagged, and so is one claiming the router's IP from another MAC.

Each problem alerts once, and again only if it went away for a day and came back. If you
replace the router, or set up a second DHCP server on purpose, tap **It's my new router** or
**I set this up** on the Security page and it stops alerting.

## Weekly port scan

Every Sunday around 10:00 a systemd timer runs `netwatch portscan`, which
TCP-scans nmap's 1,000 most common ports on every device that's online. Each
device's page lists its open ports. The first scan of a device just records
what's open; after that you get an alert when a device opens a port it has
never had open before, e.g. an old printer starting to offer telnet. To run one
now: `sudo systemctl start netwatch-portscan`.

## Internet speed

Click the speed figure on the dashboard for the graph: download and upload over 24 hours,
7 days or 30 days, ping below, and your plan's speed as a dashed line (set it on that page).

Once an hour the Pi runs [Ookla's Speedtest CLI](https://www.speedtest.net/apps/cli), but not
while someone is using the internet. A systemd timer runs `netwatch speedtest` every 10
minutes; once the hour has its test, the rest of the hour's runs do nothing. Before testing it
watches the Deco's per-device traffic for about 20 seconds (the Deco reports kbit/s). If a phone,
computer, TV, tablet or console (or a device not reviewed yet) moves more than the busy speed,
1 Mbps by default, it runs only a 4-second ping check, which uses next to no data, and tries
again 10 minutes later. Cameras, smart-home gear, network gear and servers don't count: they
move data all day. An hour that never goes quiet shows as a grey mark on the graph. Failed
tests show red; on Starlink, that's often an outage.

"Run test now" skips the busy check. The dashboard can't run programs, so it leaves a request
file that `netwatch-speedtest.path` sees. Ookla receives every test's result; each row in the
table links to Ookla's page for it. Without a Deco configured, every hourly test runs.

## Internet use per device

Every Deco poll (5 minutes) also records each device's live download and upload speed, which
the Deco reports in kbit/s. Each device's page shows its use over the last 7 days in 2-hour
bars, with rough totals for today and the week, and the speed page shows who's using the
internet right now and who used the most data. A poll is a snapshot, so totals are estimates
(speed × 5 minutes): fine for "who uses the most", not for billing. Kept for 30 days.

## Who's home

The dashboard shows who's home under the stats; tap a name for a 7-day timeline per person.
Someone is home while one of their phones or watches is on the network: a device whose
Person is them and whose Type is Phone or Wearable (laptops and TVs stay home when people
leave). Phones go quiet on Wi-Fi while asleep (gaps of 20-60 minutes are common), so someone
counts as away only once all their phones have been gone for an hour; that's adjustable on
the page. Errands shorter than that don't show.

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
