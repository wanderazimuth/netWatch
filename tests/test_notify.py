import unittest
from datetime import datetime
from unittest import mock

from netwatch import db, notify, settings
from netwatch.tracker import Event

PHONE = "da:a1:19:00:00:01"  # randomized (locally administered) MAC
TV = "00:11:22:33:44:55"
NOON = datetime(2026, 10, 16, 12, 0)


def ev(kind, mac=TV, name="TV"):
    return Event(kind, mac, "192.168.0.20", name)


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.s = dict(settings.DEFAULTS)

    def plan(self, events, watched=(), now=NOON):
        chosen, priority = notify.plan(events, self.s, set(watched), now)
        return [e.kind for e in chosen], priority

    def test_defaults_push_new_devices_only(self):
        self.assertEqual(self.plan([ev("new"), ev("online"), ev("offline"), ev("ip_change")]), (["new"], "default"))

    def test_master_switch(self):
        self.s["enabled"] = False
        self.assertEqual(self.plan([ev("new")]), ([], None))

    def test_snooze(self):
        self.s["snooze_until"] = int(NOON.timestamp()) + 60
        self.assertEqual(self.plan([ev("new")]), ([], None))
        self.assertEqual(self.plan([ev("new")], now=datetime(2026, 10, 16, 12, 2)), (["new"], "default"))

    def test_new_devices_off(self):
        self.s["new_devices"] = False
        self.assertEqual(self.plan([ev("new")]), ([], None))

    def test_private_macs_off(self):
        self.s["private_macs"] = False
        self.assertEqual(self.plan([ev("new", PHONE), ev("new", TV)]), (["new"], "default"))
        self.assertEqual(self.plan([ev("new", PHONE)]), ([], None))

    def test_watched_devices(self):
        self.assertEqual(self.plan([ev("online"), ev("offline", PHONE)], watched=[TV]), (["online"], "default"))
        self.s["watched"] = False
        self.assertEqual(self.plan([ev("online")], watched=[TV]), ([], None))

    def test_down_alerts_are_high_priority(self):
        self.assertEqual(self.plan([ev("down"), ev("new")]), (["down", "new"], "high"))
        self.assertEqual(self.plan([ev("up")]), (["up"], "default"))
        self.s["down_alerts"] = False
        self.assertEqual(self.plan([ev("down"), ev("up")]), ([], None))

    def test_down_alerts_respect_quiet_hours(self):
        self.s.update(quiet_start="22:00", quiet_end="07:00")
        self.assertEqual(self.plan([ev("down")], now=datetime(2026, 10, 16, 23, 30)), (["down"], "min"))

    def test_quiet_hours_silent_and_skip(self):
        self.s.update(quiet_start="22:00", quiet_end="07:00")
        night = datetime(2026, 10, 16, 23, 30)
        early = datetime(2026, 10, 17, 6, 59)
        self.assertEqual(self.plan([ev("new")], now=night), (["new"], "min"))
        self.assertEqual(self.plan([ev("new")], now=early), (["new"], "min"))
        self.assertEqual(self.plan([ev("new")], now=datetime(2026, 10, 17, 7, 0)), (["new"], "default"))
        self.s["quiet_mode"] = "skip"
        self.assertEqual(self.plan([ev("new")], now=night), ([], None))

    def test_quiet_hours_same_day_window(self):
        self.assertTrue(notify.in_quiet_hours(NOON, "09:00", "17:00"))
        self.assertFalse(notify.in_quiet_hours(datetime(2026, 10, 16, 18, 0), "09:00", "17:00"))
        self.assertFalse(notify.in_quiet_hours(NOON, "", ""))


class MessageTest(unittest.TestCase):
    def test_single(self):
        title, body, tags = notify.build_message([Event("new", TV, "192.168.0.20", "LGwebOSTV", "5 GHz")])
        self.assertEqual(title, "New device on the network")
        self.assertEqual(body, "New device joined: LGwebOSTV (192.168.0.20, 5 GHz, 00:11:22:33:44:55)")
        self.assertEqual(tags, "warning")

    def test_down_and_up(self):
        title, body, tags = notify.build_message([Event("down", TV, "192.168.0.11", "NAS", seconds=900)])
        self.assertEqual((title, body, tags), ("Device down", "NAS has been offline for 15 min", "rotating_light"))
        _, body, _ = notify.build_message([Event("up", TV, "192.168.0.11", "NAS", seconds=3 * 3600 + 120)])
        self.assertEqual(body, "NAS is back online after 3 h 2 min")
        _, _, tags = notify.build_message([ev("new"), Event("down", TV, None, "NAS", seconds=60)])
        self.assertEqual(tags, "rotating_light")

    def test_format_duration(self):
        self.assertEqual([notify.format_duration(s) for s in (10, 300, 3600, 90000, 2 * 86400)],
                         ["1 min", "5 min", "1 h", "1 d 1 h", "2 d"])

    def test_grouped_and_truncated(self):
        events = [ev("new", name=f"dev{i}") for i in range(12)]
        title, body, _ = notify.build_message(events)
        self.assertEqual(title, "12 network changes")
        self.assertEqual(len(body.splitlines()), 11)
        self.assertTrue(body.endswith("...and 2 more"))


class SendTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        self.conn.execute("INSERT INTO devices (mac, first_seen, last_seen, notify) VALUES (?, 0, 0, 1)", (TV,))

    def test_pushes_once_per_scan(self):
        with mock.patch.object(notify, "push") as push:
            notify.send([ev("new", PHONE), ev("online")], self.conn, "https://ntfy.example/t", "http://dash", now=NOON)
        push.assert_called_once()
        args = push.call_args.args
        self.assertEqual(args[1], "2 network changes")
        self.assertEqual(args[3], "default")
        self.assertEqual(args[5], "http://dash")

    def test_no_url_no_push(self):
        with mock.patch.object(notify, "push") as push:
            notify.send([ev("new")], self.conn, "", now=NOON)
        push.assert_not_called()

    def test_respects_saved_settings(self):
        settings.save(self.conn, {"enabled": False})
        with mock.patch.object(notify, "push") as push:
            notify.send([ev("new")], self.conn, "https://ntfy.example/t", now=NOON)
        push.assert_not_called()

    def test_push_failure_is_logged_not_raised(self):
        with mock.patch.object(notify, "push", side_effect=OSError("offline")), self.assertLogs("netwatch.notify", "ERROR"):
            notify.send([ev("new")], self.conn, "https://ntfy.example/t", now=NOON)


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")

    def test_defaults_and_save(self):
        self.assertEqual(settings.load(self.conn), settings.DEFAULTS)
        saved = settings.save(self.conn, {"quiet_start": "22:00", "quiet_end": "07:00", "enabled": False})
        self.assertEqual((saved["quiet_start"], saved["enabled"], saved["new_devices"]), ("22:00", False, True))

    def test_validation(self):
        for bad in ({"enabled": "yes"}, {"quiet_start": "25:00"}, {"quiet_mode": "loud"},
                    {"snooze_until": -1}, {"snooze_until": True}, {"bogus": 1}):
            with self.assertRaises(ValueError, msg=bad):
                settings.validate(bad)


if __name__ == "__main__":
    unittest.main()
