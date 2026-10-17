import unittest

from netwatch import db
from netwatch.pihole import DeviceInfo, usable_name
from netwatch.scanner import Sighting, is_randomized_mac
from netwatch.tracker import apply_scan

PHONE = "aa:bb:cc:00:00:01"
TV = "00:11:22:33:44:55"


class TrackerTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")

    def scan(self, now, *sightings, info=None):
        return [(e.kind, e.mac) for e in apply_scan(self.conn, list(sightings), now, 600, info)]

    def test_new_device(self):
        self.assertEqual(self.scan(0, Sighting(TV, "192.168.0.20")), [("new", TV)])
        self.assertEqual(self.scan(60, Sighting(TV, "192.168.0.20")), [])

    def test_offline_only_after_grace_period(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.assertEqual(self.scan(300), [])
        self.assertEqual(self.scan(600), [("offline", TV)])
        self.assertEqual(self.scan(660), [])  # not reported twice

    def test_back_online(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.scan(600)
        self.assertEqual(self.scan(700, Sighting(TV, "192.168.0.20")), [("online", TV)])

    def test_ip_change(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.assertEqual(self.scan(60, Sighting(TV, "192.168.0.21")), [("ip_change", TV)])

    def test_pihole_name_kept_when_later_missing(self):
        self.scan(0, Sighting(TV, "192.168.0.20"), info={TV: DeviceInfo("living-room-tv", "Samsung")})
        self.scan(60, Sighting(TV, "192.168.0.20"))
        row = self.conn.execute("SELECT * FROM devices").fetchone()
        self.assertEqual(db.display_name(row), "living-room-tv")

    def test_events_recorded(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.scan(600)
        kinds = [r["kind"] for r in self.conn.execute("SELECT kind FROM events ORDER BY id")]
        self.assertEqual(kinds, ["new", "offline"])

    def test_randomized_mac(self):
        self.assertTrue(is_randomized_mac("da:a1:19:00:00:01"))
        self.assertFalse(is_randomized_mac(TV))

    def test_pihole_placeholder_name_ignored(self):
        self.assertFalse(usable_name("pi.hole"))
        self.assertFalse(usable_name("PI.HOLE."))
        self.assertFalse(usable_name(None))
        self.assertTrue(usable_name("living-room-tv"))


if __name__ == "__main__":
    unittest.main()
