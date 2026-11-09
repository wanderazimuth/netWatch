import unittest

from netwatch import db, deco, inventory, usage

ROKU = "00:11:22:33:44:01"
PHONE = "da:a1:19:00:00:02"
T = 1_800_000_000


class UsageTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")

    def test_record_skips_idle_devices_and_prunes(self):
        usage.record(self.conn, T - 31 * 86400, {ROKU: (5000, 50)}, 300)
        usage.record(self.conn, T, {ROKU: (2936, 39), PHONE: (0, 0)}, 300)
        self.assertEqual([tuple(r) for r in self.conn.execute("SELECT mac, ts FROM traffic")], [(ROKU, T)])

    def test_totals_are_speed_times_time(self):
        # 8,000 kbit/s for 300 s is 300 MB.
        usage.record(self.conn, T, {ROKU: (8000, 80), PHONE: (800, 0)}, 300)
        usage.record(self.conn, T + 300, {ROKU: (8000, 0)}, 300)
        self.assertEqual(usage.totals(self.conn, T), {ROKU: (600.0, 3.0), PHONE: (30.0, 0.0)})
        self.assertEqual(usage.totals(self.conn, T + 1), {ROKU: (300.0, 0.0)})
        self.assertEqual(usage.totals(self.conn, T, PHONE), {PHONE: (30.0, 0.0)})

    def test_series_and_latest(self):
        self.assertEqual(usage.latest(self.conn), (None, {}))
        usage.record(self.conn, T, {ROKU: (100, 1)}, 300)
        usage.record(self.conn, T + 300, {PHONE: (5, 7)}, 300)
        self.assertEqual(usage.series(self.conn, ROKU, T), [[T, 100, 1, 300]])
        self.assertEqual(usage.latest(self.conn), (T + 300, {PHONE: (5, 7)}))

    def test_merge_moves_usage(self):
        for mac in (ROKU, PHONE):
            self.conn.execute("INSERT INTO devices (mac, first_seen, last_seen) VALUES (?, 0, 0)", (mac,))
        usage.record(self.conn, T, {PHONE: (100, 1)}, 300)
        new = "da:a1:19:00:00:03"
        self.conn.execute("INSERT INTO devices (mac, first_seen, last_seen) VALUES (?, 0, 0)", (new,))
        inventory.merge(self.conn, PHONE, new)
        self.assertEqual(usage.series(self.conn, new, 0), [[T, 100, 1, 300]])


class DecoSpeedsTest(unittest.TestCase):
    def test_parse_speeds(self):
        items = [{"mac": "AA-BB-CC-00-00-01", "down_speed": 2936, "up_speed": "39"},
                 {"mac": "AA-BB-CC-00-00-02"}, {"name": "no mac"}]
        self.assertEqual(deco.parse_speeds(items), {"aa:bb:cc:00:00:01": (2936, 39), "aa:bb:cc:00:00:02": (0, 0)})

    def test_speeds_are_optional(self):
        class Broken:
            def request(self, path, body):
                raise RuntimeError("timeout")

        self.assertEqual(deco.Deco._speeds(Broken()), {})


if __name__ == "__main__":
    unittest.main()
