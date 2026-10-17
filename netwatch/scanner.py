"""ARP sweep of the local subnet.

ARP is used instead of ping because many devices (phones especially) ignore
ICMP but must answer ARP to stay on the network. Sending raw ARP frames needs
CAP_NET_RAW; the systemd unit grants exactly that.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sighting:
    mac: str
    ip: str


def arp_scan(network: str, interface: str, timeout: float = 2.0, retry: int = 2) -> list[Sighting]:
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
    # A device can answer more than once across retries; keep one entry per MAC.
    seen = {reply[ARP].hwsrc.lower(): reply[ARP].psrc for _, reply in answered}
    return [Sighting(mac, ip) for mac, ip in sorted(seen.items())]


def is_randomized_mac(mac: str) -> bool:
    """True for locally administered MACs, which phones use for Wi-Fi privacy.

    These can change per network or over time, so one phone may appear as
    several "new" devices.
    """
    return bool(int(mac.split(":")[0], 16) & 0x02)
