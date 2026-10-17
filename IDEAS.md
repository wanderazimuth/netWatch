# NetWatch ideas

Things NetWatch could do beyond listing what's on the network, based on what
people build with similar tools (NetAlertX / Pi.Alert, WatchYourLAN, Fing).

## Next up (best value for the effort)

1. ~~**Offline alerts for chosen devices.**~~ Done: the 🚨 column on the dashboard.
2. **Per-device detail page.** First/last seen, online history, which Deco
   (Upstairs/Basement) it's on, and its top DNS lookups from Pi-hole.
3. **"Pause internet" button.** Move a device into a blocking Pi-hole group.
   DNS-only, so a determined user could bypass it, but it works for most devices.
4. **Weekly port scan.** nmap each device; alert when one starts exposing a new
   service.

## More ideas

### Presence detection ("who's home")
- Phone joins Wi-Fi = person is home. Feed into Home Assistant (MQTT or webhook)
  for lights, thermostat, arming cameras.
- Phones sleep their Wi-Fi radio, so require a grace period (e.g. gone 10+ min)
  before calling someone away.

### Security
- **ARP spoofing detection:** alert if the router's MAC address changes.
- **Rogue DHCP / duplicate IP detection:** a second DHCP server or two devices
  claiming one IP.
- **Unexpected open ports** (see port scan above), e.g. telnet on an old printer.

### What devices are talking to
- Pi-hole logs DNS per client: show lookups per device, flag chatty or
  tracker-heavy IoT devices.

### Inventory and history
- First seen / last seen, uptime timeline, notes ("the dishwasher").
- "What was on the network last Tuesday at 2am?" Most of this data is already
  in the database, just not shown.

### Small utilities
- Wake-on-LAN buttons.
- Internet speed tests logged over time (spot ISP slowdowns).
- Per-device bandwidth, if the Deco API exposes per-client speeds (unverified).
