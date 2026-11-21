import unittest
from contextlib import contextmanager
from datetime import datetime

from netwatch import db, schedule
from netwatch.scanner import Sighting
from netwatch.tracker import apply_scan

from test_pause import FakeAdmin

TABLET = "00:11:22:33:44:55"
LAPTOP = "00:11:22:33:44:66"
TV = "00:11:22:33:44:77"


def ts(y, mo, d, h, mi=0) -> int:
    return int(datetime(y, mo, d, h, mi).timestamp())


# 2026-11-16 is a Monday (weekday 0).
MON_20 = ts(2026, 11, 16, 20)
MON_22 = ts(2026, 11, 16, 22)
TUE_06 = ts(2026, 11, 17, 6)
TUE_07 = ts(2026, 11, 17, 7)
TUE_21 = ts(2026, 11, 17, 21)


def row(days="0123456", start="21:00", end="07:00", enabled=1, skip_until=None, mac=None, person="Fenly"):
    return {"days": days, "start": start, "end": end, "enabled": enabled, "skip_until": skip_until,
            "mac": mac, "person": person}


class WindowTest(unittest.TestCase):
    def test_overnight_window(self):
        s = row(days="0")  # Mondays 21:00 to Tuesday 07:00
        self.assertIsNone(schedule.active_until(s, MON_20))
        self.assertEqual(schedule.next_window(s, MON_20), (ts(2026, 11, 16, 21), TUE_07))
        self.assertEqual(schedule.active_until(s, MON_22), TUE_07)
        # Still running on Tuesday morning, though Tuesday isn't one of its days.
        self.assertEqual(schedule.active_until(s, TUE_06), TUE_07)
        self.assertIsNone(schedule.active_until(s, TUE_07))
        self.assertIsNone(schedule.active_until(s, TUE_21))
        self.assertEqual(schedule.next_window(s, TUE_21)[0], ts(2026, 11, 23, 21))

    def test_same_day_window(self):
        s = row(days="01234", start="15:00", end="17:30")
        self.assertEqual(schedule.active_until(s, ts(2026, 11, 16, 16)), ts(2026, 11, 16, 17, 30))
        self.assertIsNone(schedule.active_until(s, MON_20))
        self.assertIsNone(schedule.active_until(s, ts(2026, 11, 21, 16)))  # Saturday

    def test_skip_and_off(self):
        s = row(skip_until=TUE_07)
        self.assertIsNone(schedule.active_until(s, MON_22))
        self.assertEqual(schedule.next_window(s, MON_22), (TUE_21, ts(2026, 11, 18, 7)))
        self.assertIsNone(schedule.next_window(row(enabled=0), MON_22))


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        apply_scan(self.conn, [Sighting(TABLET, "192.168.0.20"), Sighting(LAPTOP, "192.168.0.21"),
                               Sighting(TV, "192.168.0.22")], 1000, 600)
        self.conn.execute("UPDATE devices SET person = 'Fenly'")
        self.conn.execute("UPDATE devices SET pause_allowed = 1 WHERE mac = ?", (TABLET,))
        self.conn.commit()
        self.admin = FakeAdmin()
        self.listed = frozenset([LAPTOP])

    @contextmanager
    def session(self):
        yield self.admin

    def add(self, **kw):
        cols = schedule.clean({"person": "Fenly", "days": [0], "start": "21:00", "end": "07:00", **kw},
                              ["Fenly"], self.conn)
        return schedule.save(self.conn, None, cols)

    def dev(self, mac):
        return self.conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()

    def test_person_schedule_pauses_only_pausable_devices(self):
        sid = self.add()
        self.assertEqual(schedule.plan(self.conn, MON_20, self.listed), ({}, []))
        self.assertTrue(schedule.run(self.conn, self.session, MON_22, self.listed))
        self.assertEqual(sorted(self.admin.clients), ["192.168.0.20", "192.168.0.21"])  # not the TV
        self.assertEqual((self.dev(TABLET)["paused_until"], self.dev(TABLET)["paused_by"]), (TUE_07, sid))
        self.assertFalse(schedule.run(self.conn, self.session, MON_22 + 60, self.listed))  # nothing more to do

    def test_window_change_lifts_scheduled_pause(self):
        sid = self.add()
        schedule.run(self.conn, self.session, MON_22, self.listed)
        schedule.skip(self.conn, sid, MON_22, True)
        self.assertEqual(schedule.plan(self.conn, MON_22, self.listed), ({}, [TABLET, LAPTOP]))
        schedule.run(self.conn, self.session, MON_22, self.listed)
        self.assertEqual(self.admin.clients, {})
        schedule.skip(self.conn, sid, MON_22, False)
        schedule.run(self.conn, self.session, MON_22, self.listed)
        schedule.delete(self.conn, sid)
        schedule.run(self.conn, self.session, MON_22, self.listed)
        self.assertEqual(self.admin.clients, {})
        self.assertIsNone(self.dev(TABLET)["paused_ip"])

    def test_manual_pauses(self):
        from netwatch import pause
        self.add()
        pause.pause(self.conn, self.admin, TABLET, None)  # until resumed: longer than the schedule's
        pause.pause(self.conn, self.admin, LAPTOP, MON_22 + 600)  # shorter: stretched to the window's end
        to_pause, to_resume = schedule.plan(self.conn, MON_22, self.listed)
        self.assertEqual((list(to_pause), to_resume), ([LAPTOP], []))
        # Resumed by hand during the window: left alone until it ends.
        self.conn.execute("UPDATE devices SET sched_skip_until = ? WHERE mac = ?", (TUE_07, LAPTOP))
        pause.resume(self.conn, self.admin, LAPTOP)
        self.assertEqual(schedule.plan(self.conn, MON_22, self.listed), ({}, []))

    def test_running_for_and_device_schedules(self):
        self.add()
        self.add(person=None, mac=TV, days=[0], start="20:30", end="23:00")
        self.assertEqual(len(schedule.for_device(self.conn, self.dev(TV))), 2)
        self.assertEqual(len(schedule.for_device(self.conn, self.dev(TABLET))), 1)
        self.assertEqual(schedule.running_for(self.conn, self.dev(TV), MON_22), TUE_07)
        self.assertIsNone(schedule.running_for(self.conn, self.dev(TV), MON_20))

    def test_clean(self):
        people = ["Fenly"]
        ok = {"person": "Fenly", "days": [4, 0, 0], "start": "21:00", "end": "07:00"}
        self.assertEqual(schedule.clean(ok, people, self.conn)["days"], "04")
        for bad in ({**ok, "mac": TV}, {**ok, "person": "Nobody"}, {**ok, "days": []}, {**ok, "days": [7]},
                    {**ok, "days": [True]}, {**ok, "start": "7:00"}, {**ok, "end": "21:00"},
                    {**ok, "enabled": "yes"}, {**ok, "extra": 1},
                    {"mac": "00:00:00:00:00:01", "days": [0], "start": "21:00", "end": "07:00"}):
            with self.assertRaises(ValueError, msg=bad):
                schedule.clean(bad, people, self.conn)


if __name__ == "__main__":
    unittest.main()
