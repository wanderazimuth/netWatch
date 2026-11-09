"""ARP sweep of the local subnet.

ARP is used instead of ping because many devices (phones especially) ignore
ICMP but must answer ARP to stay on the network. Sending raw ARP frames needs
CAP_NET_RAW; the systemd unit grants exactly that.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class Sighting:
    mac: str
    ip: str


def arp_sweep(network: str, interface: str, timeout: float = 2.0, retry: int = 2) -> list[tuple[str, str]]:
    """Every (mac, ip) that answered. Usually one per device, but two MACs answering for one IP
    (a conflict, or something posing as the router) show up here too."""
    # Imported lazily: scapy is slow to import and only needed on the Pi.
    from scapy.all import ARP, Ether, conf, srp

    conf.verb = 0
    # Replies are unicast to us, so promiscuous mode (which needs CAP_NET_ADMIN) is unnecessary.
    conf.sniff_promisc = False

    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        iface=interface,
        timeout=timeout,
        retry=retry,
    )
    return sorted({(reply[ARP].hwsrc.lower(), reply[ARP].psrc) for _, reply in answered})


def sightings(answers: list[tuple[str, str]]) -> list[Sighting]:
    # A device can answer more than once across retries; keep one entry per MAC.
    return [Sighting(mac, ip) for mac, ip in sorted(dict(answers).items())]


def arp_scan(network: str, interface: str, timeout: float = 2.0, retry: int = 2) -> list[Sighting]:
    return sightings(arp_sweep(network, interface, timeout, retry))


def default_gateway(route_file: str = "/proc/net/route") -> str | None:
    """The router's IP, from the Pi's routing table."""
    try:
        with open(route_file) as f:
            for line in f.readlines()[1:]:
                _, dest, gateway, flags = line.split()[:4]
                if dest == "00000000" and int(flags, 16) & 2:  # the default route, via a gateway
                    return socket.inet_ntoa(struct.pack("<L", int(gateway, 16)))
    except (OSError, ValueError):
        pass
    return None


def is_randomized_mac(mac: str) -> bool:
    """True for locally administered MACs, which phones use for Wi-Fi privacy.

    These can change per network or over time, so one phone may appear as
    several "new" devices.
    """
    return bool(int(mac.split(":")[0], 16) & 0x02)
