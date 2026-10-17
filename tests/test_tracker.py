import unittest

from netwatch import db
from netwatch.info import DeviceInfo, usable_name
from netwatch.scanner import Sighting, is_randomized_mac
from netwatch.tracker import apply_scan, check_down

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

    def down(self, now, *sightings):
        apply_scan(self.conn, list(sightings), now, 600)
        return [(e.kind, e.seconds) for e in check_down(self.conn, now)]

    def test_down_and_back_up(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.conn.execute("UPDATE devices SET down_after = 5 WHERE mac = ?", (TV,))
        self.assertEqual(self.down(240), [])
        self.assertEqual(self.down(300), [("down", 300)])
        self.assertEqual(self.down(900), [])  # alerted once, not every scan
        self.assertEqual(self.down(1500, Sighting(TV, "192.168.0.20")), [("up", 1500)])
        self.assertEqual(self.down(1560, Sighting(TV, "192.168.0.20")), [])

    def test_down_before_offline_grace_period(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.conn.execute("UPDATE devices SET down_after = 2 WHERE mac = ?", (TV,))
        self.assertEqual(self.down(120), [("down", 120)])
        self.assertEqual(self.conn.execute("SELECT online FROM devices").fetchone()[0], 1)

    def test_no_down_alert_unless_set(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.assertEqual(self.down(10_000), [])

    def test_no_up_alert_after_turned_off(self):
        self.scan(0, Sighting(TV, "192.168.0.20"))
        self.conn.execute("UPDATE devices SET down_after = 5 WHERE mac = ?", (TV,))
        self.down(300)
        self.conn.execute("UPDATE devices SET down_after = NULL WHERE mac = ?", (TV,))
        self.assertEqual(self.down(400, Sighting(TV, "192.168.0.20")), [])
        self.assertIsNone(self.conn.execute("SELECT down_since FROM devices").fetchone()[0])

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
