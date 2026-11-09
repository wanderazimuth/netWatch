import unittest

from netwatch import db, presence, settings
from netwatch.web import online_spans

ROY_PHONE = "00:11:22:33:44:01"
ROY_LAPTOP = "00:11:22:33:44:02"
SHANNA_PHONE = "00:11:22:33:44:03"
H = 3600
NOW = 1_800_000_000


class BridgeTest(unittest.TestCase):
    def test_bridge(self):
        spans = [[50, 60], [0, 10], [12, 20], [40, 45]]
        self.assertEqual(presence.bridge(spans, 5), [[0, 20], [40, 45], [50, 60]])
        self.assertEqual(presence.bridge(spans, 25), [[0, 60]])
        self.assertEqual(presence.bridge([], 5), [])


class PeopleTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        for mac, person, kind, last_seen in ((ROY_PHONE, "Roy", "phone", NOW - 20 * 60),
                                             (ROY_LAPTOP, "Roy", "computer", NOW),
                                             (SHANNA_PHONE, "Shanna", "phone", NOW - 3 * H)):
            self.conn.execute("INSERT INTO devices (mac, person, kind, first_seen, last_seen) VALUES (?, ?, ?, 0, ?)",
                              (mac, person, kind, last_seen))
        self.spans = {
            ROY_PHONE: [[NOW - 10 * H, NOW - 5 * H], [NOW - 4.5 * H, NOW - 20 * 60]],  # a 30 min sleep, then quiet
            SHANNA_PHONE: [[NOW - 8 * H, NOW - 3 * H]],
        }

    def people(self, names, away_after=H):
        return {p["person"]: p for p in presence.people(
            self.conn, names, NOW - 24 * H, NOW, 600, away_after, lambda c, mac, s, e, o: {"spans": self.spans.get(mac, [])})}

    def test_home_and_away(self):
        p = self.people(["Roy", "Shanna", "Fenly"])
        # Roy's phone went quiet 20 minutes ago: still home, since before its short gap.
        self.assertEqual((p["Roy"]["home"], p["Roy"]["since"], p["Roy"]["spans"]), (True, NOW - 10 * H, [[NOW - 10 * H, NOW]]))
        self.assertEqual([d["mac"] for d in p["Roy"]["devices"]], [ROY_PHONE])  # the laptop doesn't count
        self.assertEqual((p["Shanna"]["home"], p["Shanna"]["since"]), (False, NOW - 3 * H))
        self.assertEqual((p["Fenly"]["home"], p["Fenly"]["devices"]), (None, []))

    def test_short_grace(self):
        p = self.people(["Roy"], away_after=15 * 60)
        self.assertEqual((p["Roy"]["home"], p["Roy"]["since"]), (False, NOW - 20 * 60))
        self.assertEqual(len(p["Roy"]["spans"]), 2)

    def test_phone_owner_not_on_the_list(self):
        self.assertEqual(list(self.people(["Fenly"])), ["Fenly", "Roy", "Shanna"])

    def test_with_real_spans(self):
        self.conn.execute("INSERT INTO events (ts, mac, kind) VALUES (?, ?, 'new')", (NOW - 2 * H, ROY_PHONE))
        p = presence.people(self.conn, ["Roy"], NOW - 24 * H, NOW, 600, H, online_spans)
        self.assertEqual(p[0]["spans"], [[NOW - 2 * H, NOW]])

    def test_setting(self):
        self.assertEqual(settings.validate({"away_after": 45}), {"away_after": 45})
        for bad in (5, 721, "60", True):
            with self.assertRaises(ValueError):
                settings.validate({"away_after": bad})


if __name__ == "__main__":
    unittest.main()
