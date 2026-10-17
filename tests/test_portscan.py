import unittest

from netwatch import db, portscan
from netwatch.portscan import OpenPort
from netwatch.scanner import Sighting
from netwatch.tracker import apply_scan

TV = "00:11:22:33:44:55"
NAS = "00:11:22:33:44:66"


def host(ip, *ports, timedout=False):
    rows = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="{s}"/><service name="{n}" method="table"/></port>'
        for p, s, n in ports
    )
    attrs = ' timedout="true"' if timedout else ""
    return (f'<host{attrs}><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>{rows}</ports></host>')


def xml(*hosts):
    return f'<?xml version="1.0"?><nmaprun scanner="nmap">{"".join(hosts)}</nmaprun>'


class ParseTest(unittest.TestCase):
    def test_open_ports_only_and_timeouts_skipped(self):
        out = portscan.parse(xml(
            host("192.168.0.20", (22, "open", "ssh"), (80, "filtered", "http"), (8008, "open", "http")),
            host("192.168.0.21"),
            host("192.168.0.22", (23, "open", "telnet"), timedout=True),
        ))
        self.assertEqual(out, {
            "192.168.0.20": [OpenPort(22, "tcp", "ssh"), OpenPort(8008, "tcp", "http")],
            "192.168.0.21": [],
        })
        self.assertEqual(str(OpenPort(23, "tcp", "telnet")), "23/tcp (telnet)")


class RecordTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        apply_scan(self.conn, [Sighting(TV, "192.168.0.20"), Sighting(NAS, "192.168.0.11")], 1000, 600)
        self.scanned = portscan.targets(self.conn)

    def ports(self, mac):
        return [(r["port"], r["last_seen"]) for r in self.conn.execute("SELECT * FROM ports WHERE mac = ? ORDER BY port", (mac,))]

    def test_targets(self):
        self.assertEqual(self.scanned, {"192.168.0.20": TV, "192.168.0.11": NAS})

    def test_first_scan_is_baseline_then_new_ports_alert(self):
        ssh, telnet = OpenPort(22, "tcp", "ssh"), OpenPort(23, "tcp", "telnet")
        self.assertEqual(portscan.record(self.conn, self.scanned, {"192.168.0.20": [ssh], "192.168.0.11": []}, 2000), [])
        events = portscan.record(self.conn, self.scanned, {"192.168.0.20": [ssh, telnet], "192.168.0.11": [ssh]}, 3000)
        self.assertEqual([(e.kind, e.mac, e.port) for e in events],
                         [("port", TV, "23/tcp (telnet)"), ("port", NAS, "22/tcp (ssh)")])
        self.assertEqual(self.ports(TV), [(22, 3000), (23, 3000)])
        # telnet closes, then reopens: remembered, so no second alert.
        self.assertEqual(portscan.record(self.conn, self.scanned, {"192.168.0.20": [ssh]}, 4000), [])
        self.assertEqual(self.ports(TV), [(22, 4000), (23, 3000)])
        self.assertEqual(portscan.record(self.conn, self.scanned, {"192.168.0.20": [ssh, telnet]}, 5000), [])

    def test_unscanned_device_keeps_its_baseline_pending(self):
        portscan.record(self.conn, self.scanned, {"192.168.0.20": []}, 2000)  # the NAS timed out
        row = self.conn.execute("SELECT ports_scanned FROM devices WHERE mac = ?", (NAS,)).fetchone()
        self.assertIsNone(row["ports_scanned"])
        # Its first completed scan is still the baseline.
        self.assertEqual(portscan.record(self.conn, self.scanned, {"192.168.0.11": [OpenPort(22, "tcp", "ssh")]}, 3000), [])

    def test_unknown_ip_ignored(self):
        self.assertEqual(portscan.record(self.conn, self.scanned, {"192.168.0.99": [OpenPort(22, "tcp", "ssh")]}, 2000), [])


if __name__ == "__main__":
    unittest.main()
