import unittest
from contextlib import contextmanager

from netwatch import db, groups, inventory, schedule
from netwatch.scanner import Sighting
from netwatch.tracker import apply_scan

from test_pause import FakeAdmin
from test_schedule import LAPTOP, MON_20, MON_22, TABLET, TUE_07, TV


class GroupTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        apply_scan(self.conn, [Sighting(TABLET, "192.168.0.20"), Sighting(LAPTOP, "192.168.0.21"),
                               Sighting(TV, "192.168.0.22")], 1000, 600)
        self.conn.execute("UPDATE devices SET person = 'Fenly' WHERE mac = ?", (TABLET,))
        self.conn.execute("UPDATE devices SET pause_allowed = 1 WHERE mac IN (?, ?)", (TABLET, TV))
        self.conn.commit()
        self.admin = FakeAdmin()
        self.listed = frozenset()

    @contextmanager
    def session(self):
        yield self.admin

    def make(self, name="Family devices", macs=(TV, LAPTOP)):
        return groups.save(self.conn, None, *groups.clean({"name": name, "macs": list(macs)}, self.conn))

    def test_clean(self):
        self.assertEqual(groups.clean({"name": "  Family   devices ", "macs": [TV, TV]}, self.conn),
                         ("Family devices", [TV]))
        for body in ({"name": ""}, {"name": 3}, {"name": "x", "macs": "aa"}, {"name": "x", "macs": ["00:00:00:00:00:01"]},
                     {"name": "x", "color": "red"}):
            with self.assertRaises(ValueError):
                groups.clean(body, self.conn)
        gid = self.make()
        with self.assertRaises(ValueError):
            groups.clean({"name": "family DEVICES"}, self.conn)
        self.assertEqual(groups.clean({"name": "Family devices"}, self.conn, gid)[0], "Family devices")  # its own name

    def test_members_and_json(self):
        gid = self.make()
        self.make("TVs", [TV])
        self.assertEqual(sorted(r["mac"] for r in groups.members(self.conn, gid)), sorted([TV, LAPTOP]))
        self.assertEqual(groups.names_for(self.conn, TV), ["Family devices", "TVs"])
        family = groups.all_json(self.conn, self.listed)[0]
        self.assertEqual({d["mac"]: d["pausable"] for d in family["devices"]}, {TV: True, LAPTOP: False})
        groups.save(self.conn, gid, "Family devices", [TABLET])
        self.assertEqual([r["mac"] for r in groups.members(self.conn, gid)], [TABLET])
        with self.assertRaises(LookupError):
            groups.save(self.conn, 999, "Nope", [])

    def test_group_schedule_pauses_only_pausable_members(self):
        gid = self.make()
        sid = schedule.save(self.conn, None, schedule.clean(
            {"group": gid, "days": [0], "start": "21:00", "end": "07:00"}, [], self.conn))
        self.assertEqual(schedule.plan(self.conn, MON_20, self.listed), ({}, []))
        schedule.run(self.conn, self.session, MON_22, self.listed)
        self.assertEqual(list(self.admin.clients), ["192.168.0.22"])  # the TV; the laptop isn't allowed
        tv = self.conn.execute("SELECT * FROM devices WHERE mac = ?", (TV,)).fetchone()
        self.assertEqual((tv["paused_until"], tv["paused_by"]), (TUE_07, sid))
        self.assertEqual([s["id"] for s in schedule.for_device(self.conn, tv)], [sid])
        s = schedule.all_json(self.conn, MON_22, self.listed)[0]
        self.assertEqual((s["group"], s["name"], s["running"]), (gid, "Family devices", True))
        # Taken out of the group, its scheduled pause ends.
        groups.save(self.conn, gid, "Family devices", [LAPTOP])
        schedule.run(self.conn, self.session, MON_22, self.listed)
        self.assertEqual(self.admin.clients, {})

    def test_person_schedule_ignores_groups(self):
        # A group schedule has a NULL person; a person schedule mustn't pick up a group's.
        gid = self.make(macs=[TV])
        schedule.save(self.conn, None, schedule.clean(
            {"group": gid, "days": [0], "start": "21:00", "end": "07:00"}, [], self.conn))
        tablet = self.conn.execute("SELECT * FROM devices WHERE mac = ?", (TABLET,)).fetchone()
        self.assertEqual(schedule.for_device(self.conn, tablet), [])

    def test_schedule_target(self):
        gid = self.make()
        base = {"days": [0], "start": "21:00", "end": "07:00"}
        for target in ({}, {"group": gid, "person": "Fenly"}, {"group": 999}, {"group": str(gid)}, {"group": True}):
            with self.assertRaises(ValueError):
                schedule.clean({**base, **target}, ["Fenly"], self.conn)

    def test_delete_takes_its_schedules(self):
        gid = self.make()
        schedule.save(self.conn, None, schedule.clean(
            {"group": gid, "days": [0], "start": "21:00", "end": "07:00"}, [], self.conn))
        schedule.run(self.conn, self.session, MON_22, self.listed)
        groups.delete(self.conn, gid)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM schedules").fetchone()[0], 0)
        self.assertEqual(groups.names_for(self.conn, TV), [])
        schedule.run(self.conn, self.session, MON_22, self.listed)
        self.assertEqual(self.admin.clients, {})
        with self.assertRaises(LookupError):
            groups.delete(self.conn, gid)

    def test_merge_moves_membership(self):
        gid = self.make(macs=[LAPTOP])
        other = self.make("Both", [LAPTOP, TV])
        inventory.merge(self.conn, LAPTOP, TV)
        self.assertEqual([r["mac"] for r in groups.members(self.conn, gid)], [TV])
        self.assertEqual([r["mac"] for r in groups.members(self.conn, other)], [TV])


if __name__ == "__main__":
    unittest.main()
