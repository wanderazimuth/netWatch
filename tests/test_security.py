import os
import tempfile
import unittest

from netwatch import db, notify, security

ROUTER = "60:a4:b7:ae:7c:a4"
EVIL = "00:11:22:33:44:99"
TV = "00:11:22:33:44:55"
PC = "00:11:22:33:44:66"
GW = "192.168.0.1"
NOW = 1_800_000_000


class SecurityTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        self.conn.execute("INSERT INTO devices (mac, label, first_seen, last_seen) VALUES (?, 'Gaming PC', 0, 0)", (EVIL,))

    def arp(self, answers, now=NOW, cached=(), gateway=GW):
        check = security.Checker(self.conn, now)
        check.arp(answers, gateway, set(cached))
        return check.save()

    def dhcp(self, offers, now=NOW):
        check = security.Checker(self.conn, now)
        check.dhcp(offers, GW)
        return check.save()

    def test_learns_the_router_then_alerts_on_a_new_mac(self):
        self.assertEqual(self.arp([(ROUTER, GW), (TV, "192.168.0.20")]), [])
        self.assertEqual(security.load_state(self.conn)["router_macs"], [ROUTER])
        self.assertEqual(self.arp([(ROUTER, GW)], NOW + 60), [])
        [e] = self.arp([(ROUTER, GW), (EVIL, GW)], NOW + 120)
        self.assertEqual((e.kind, e.mac, e.ip, e.name, e.detail), ("router_mac", EVIL, GW, "Gaming PC", "in the scan"))
        self.assertIn("Gaming PC (00:11:22:33:44:99), in the scan", notify.format_event(e))

    def test_router_alerts_once_until_gone_for_a_day(self):
        self.arp([(ROUTER, GW)])
        self.assertEqual(len(self.arp([(EVIL, GW)], NOW + 60)), 1)
        self.assertEqual(self.arp([(EVIL, GW)], NOW + 120), [])
        self.assertEqual(self.arp([(ROUTER, GW)], NOW + 3600), [])  # gone, but not for a day yet
        self.assertEqual(self.arp([(EVIL, GW)], NOW + 7200), [])
        self.arp([(ROUTER, GW)], NOW + 7200 + security.REALERT_AFTER)  # a day without it
        self.assertEqual(len(self.arp([(EVIL, GW)], NOW + 7300 + security.REALERT_AFTER)), 1)

    def test_the_pis_own_arp_cache_counts(self):
        self.arp([(ROUTER, GW)])
        [e] = self.arp([(ROUTER, GW)], NOW + 60, cached=[EVIL])
        self.assertEqual(e.detail, "in the Pi's own ARP cache")

    def test_doesnt_learn_from_a_muddled_first_look(self):
        with self.assertLogs("netwatch.security", "WARNING"):
            self.assertEqual(self.arp([(ROUTER, GW), (EVIL, GW)]), [])
        self.assertIsNone(security.load_state(self.conn)["router_ip"])
        self.arp([(ROUTER, GW)], NOW + 60)
        self.assertEqual(security.load_state(self.conn)["router_macs"], [ROUTER])

    def test_trusted_router_mac(self):
        self.arp([(ROUTER, GW)])
        security.trust(self.conn, router=EVIL)
        self.assertEqual(self.arp([(EVIL, GW)], NOW + 60), [])

    def test_ip_conflict_needs_two_sweeps(self):
        both = [(ROUTER, GW), (TV, "192.168.0.20"), (PC, "192.168.0.20")]
        self.assertEqual(self.arp(both), [])
        self.assertEqual(self.arp([(ROUTER, GW), (TV, "192.168.0.20")], NOW + 60), [])  # a one-off
        self.assertEqual(self.arp(both, NOW + 120), [])
        [e] = self.arp(both, NOW + 180)
        self.assertEqual((e.kind, e.ip), ("ip_conflict", "192.168.0.20"))
        self.assertIn(TV, e.detail)
        self.assertIn(PC, e.detail)
        self.assertEqual(self.arp(both, NOW + 240), [])
        self.assertEqual(list(security.load_state(self.conn)["conflicts"]), ["192.168.0.20"])

    def test_dhcp(self):
        self.arp([(ROUTER, GW)])
        router = {"server": GW, "mac": ROUTER, "offered": "192.168.0.10", "router": GW, "dns": GW}
        self.assertEqual(self.dhcp([router]), [])
        rogue = {"server": "192.168.0.66", "mac": EVIL, "offered": "192.168.0.200", "router": "192.168.0.66", "dns": "1.2.3.4"}
        [e] = self.dhcp([router, rogue], NOW + 900)
        self.assertEqual((e.kind, e.ip, e.mac), ("rogue_dhcp", "192.168.0.66", EVIL))
        self.assertIn("offering router 192.168.0.66, DNS 1.2.3.4", notify.format_event(e))
        self.assertEqual(self.dhcp([router, rogue], NOW + 1800), [])
        security.trust(self.conn, dhcp="192.168.0.66")
        self.arp([(ROUTER, GW)], NOW + 2000 + security.REALERT_AFTER)
        self.assertEqual(self.dhcp([router, rogue], NOW + 2700 + security.REALERT_AFTER), [])

    def test_dhcp_server_claiming_the_routers_ip(self):
        self.arp([(ROUTER, GW)])
        [e] = self.dhcp([{"server": GW, "mac": EVIL, "offered": "192.168.0.201", "router": GW, "dns": "1.2.3.4"}])
        self.assertEqual(e.mac, EVIL)

    def test_dhcp_due(self):
        check = security.Checker(self.conn, NOW)
        self.assertTrue(check.dhcp_due())
        check.dhcp([], GW)
        check.save()
        self.assertFalse(security.Checker(self.conn, NOW + 60).dhcp_due())
        self.assertTrue(security.Checker(self.conn, NOW + security.DHCP_EVERY).dhcp_due())

    def test_history(self):
        self.arp([(ROUTER, GW)])
        self.arp([(EVIL, GW)], NOW + 60)
        [h] = security.load_state(self.conn)["history"]
        self.assertEqual((h["kind"], h["mac"]), ("router_mac", EVIL))

    def test_kernel_arp(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("IP address       HW type     Flags       HW address            Mask     Device\n"
                    f"192.168.0.1      0x1         0x2         {ROUTER.upper()}     *        eth0\n"
                    f"192.168.0.1      0x1         0x2         {ROUTER}     *        wlan0\n"
                    "192.168.0.7      0x1         0x0         00:00:00:00:00:00     *        eth0\n")
        try:
            self.assertEqual(security.kernel_arp(GW, path), {ROUTER})
            self.assertEqual(security.kernel_arp("192.168.0.7", path), set())  # incomplete
            self.assertEqual(security.kernel_arp(GW, path + ".missing"), set())
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
