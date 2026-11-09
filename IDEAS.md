# NetWatch ideas

Things NetWatch could do beyond listing what's on the network, based on what
people build with similar tools (NetAlertX / Pi.Alert, WatchYourLAN, Fing).

## Next up (best value for the effort)

1. ~~**Offline alerts for chosen devices.**~~ Done: the 🚨 column on the dashboard.
2. ~~**Per-device detail page.**~~ Done: click a device row on the dashboard.
3. ~~**"Pause internet" button.**~~ Done: on each device's page.
4. ~~**Weekly port scan.**~~ Done: open ports on each device's page, alerts for new ones.
5. **New-device triage** (planned 2026-11-08, in three steps):
   1. ~~Inventory: review status (to review / known / guest), type, floor, room, person, notes,
      and a review walk-through.~~ Done.
   2. ~~Alert buttons on a new-device ntfy alert: Review, Guest, Pause 1 h. Optionally a morning
      digest of devices still to review.~~ Done.
   3. ~~"Same device as…": move a device's name and notes to the new MAC a phone rotated to.~~ Done.

## Next

6. ~~**Per-device bandwidth.**~~ Done. The Deco's combined client list has each device's live down/up
   speed in kbit/s (checked 2026-11-08 against a download of known speed; the per-unit lists
   miss the main unit's clients). Record it with every Deco poll, graph it on each device's
   page, and show who's using the internet on the speed page.
7. ~~**Who's home.**~~ Done. A person's phone on Wi-Fi means they're home, using the inventory's people
   and device owners. Needs a grace period: phones sleep their Wi-Fi.

8. ~~**Security checks.**~~ Done. Alerts when something poses as the router (ARP spoofing), two
   devices answer for one IP, or a second DHCP server answers. Baseline on 2026-11-09: one router
   MAC, no conflicts, only the Deco offering addresses.

## More ideas

### What devices are talking to
- Flag chatty or tracker-heavy devices: lookups per hour, and how many hit Pi-hole's
  block lists. (Each device's page already lists its lookups.)
- Home Assistant feed for who's home (MQTT or webhook): lights, thermostat, cameras.

### History
- "What was on the network last Tuesday at 2am?" The data is already in the
  database; it needs a time picker.

### Small utilities
- Wake-on-LAN buttons.

## Done

- Offline alerts, per-device pages, pause internet, weekly port scan (with alerts for
  newly opened ports), DNS lookups per device, uptime timeline, first/last seen.
- New-device triage: inventory and review walk-through, alert buttons and daily
  reminder, "Same device as…" for rotated private MACs.
- Hourly internet speed tests with a graph, skipped while someone's streaming.
- Per-device internet use (from the Deco's live speeds) and who's home (from each person's phones).
- Security checks: router impersonation (ARP spoofing), IP conflicts, rogue DHCP servers.
- Room-by-room Wi-Fi test from a phone: considered 2026-11-08, not wanted.
