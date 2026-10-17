from __future__ import annotations

import logging
import urllib.request

from .scanner import is_randomized_mac
from .tracker import Event

log = logging.getLogger(__name__)

MESSAGES = {
    "new": "New device joined: {name} ({ip}, {mac})",
    "online": "{name} is back online ({ip})",
    "offline": "{name} left the network",
    "ip_change": "{name} changed IP to {ip}",
}


def format_event(e: Event) -> str:
    text = MESSAGES[e.kind].format(name=e.name, ip=e.ip, mac=e.mac)
    if e.kind == "new" and is_randomized_mac(e.mac):
        text += " [randomized MAC -- may be a known phone with privacy MAC on]"
    return text


def send(events: list[Event], ntfy_url: str = "") -> None:
    for e in events:
        text = format_event(e)
        log.info(text)
        # Only new devices get pushed; online/offline churn would be noisy.
        if ntfy_url and e.kind == "new":
            try:
                req = urllib.request.Request(ntfy_url, data=text.encode(), method="POST")
                req.add_header("Title", "NetWatch: new device")
                req.add_header("Tags", "warning")
                urllib.request.urlopen(req, timeout=10).close()
            except Exception:
                log.exception("ntfy notification failed")
