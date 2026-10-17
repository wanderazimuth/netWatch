# netWatch
Fing replacement to watch devices enter and leave my home network.

Runs on the Raspberry Pi alongside Pi-hole: ARP-scans the LAN every minute,
records every device in SQLite, and reports when devices join, leave, or change
IP. Optionally pulls hostnames from Pi-hole and pushes new-device alerts via
[ntfy](https://ntfy.sh).

## Layout

```
netwatch/
  scanner.py   ARP sweep (scapy)
  pihole.py    Pi-hole v6 API client for hostnames/vendors
  tracker.py   scan results -> device state + events (pure logic, unit-tested)
  db.py        SQLite schema
  notify.py    log + ntfy alerts
  __main__.py  CLI: run | scan | devices | events | label
deploy/
  netwatch.service   systemd unit (runs as `netwatch` user with only CAP_NET_RAW)
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

## Use

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
