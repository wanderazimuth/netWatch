import json
import os
import tempfile
import unittest
from contextlib import contextmanager

from netwatch import db, pause
from netwatch.deco import BlockList
from netwatch.pihole import BLOCK_ALL, PAUSE_GROUP, PiholeAdmin
from netwatch.scanner import Sighting
from netwatch.tracker import apply_scan

TV = "00:11:22:33:44:55"
PAUSE_GID = 7


class FakeAdmin:
    """Pi-hole client entries as a dict: client -> {"groups": [...], "comment": ...}."""

    def __init__(self, clients=None):
        self.clients = clients or {}

    def ensure_pause_group(self):
        return PAUSE_GID

    def get_client(self, client):
        return self.clients.get(client)

    def save_client(self, client, groups, comment):
        self.clients[client] = {"groups": groups, "comment": comment}

    def delete_client(self, client):
        del self.clients[client]


class PauseTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        apply_scan(self.conn, [Sighting(TV, "192.168.0.20")], 1000, 600)

    def row(self):
        return self.conn.execute("SELECT * FROM devices").fetchone()

    def test_pause_and_resume_new_client(self):
        admin = FakeAdmin()
        pause.pause(self.conn, admin, TV, 5000)
        self.assertEqual(admin.clients, {"192.168.0.20": {"groups": [PAUSE_GID], "comment": pause.COMMENT}})
        self.assertEqual((self.row()["paused_ip"], self.row()["paused_until"]), ("192.168.0.20", 5000))
        pause.resume(self.conn, admin, TV)
        self.assertEqual(admin.clients, {})
        self.assertIsNone(self.row()["paused_ip"])

    def test_resume_restores_existing_entry(self):
        admin = FakeAdmin({"192.168.0.20": {"groups": [0, 3], "comment": "Living room"}})
        pause.pause(self.conn, admin, TV, None)
        pause.pause(self.conn, admin, TV, 9000)  # re-pause only changes the end time
        self.assertEqual(admin.clients["192.168.0.20"]["groups"], [PAUSE_GID])
        pause.resume(self.conn, admin, TV)
        self.assertEqual(admin.clients, {"192.168.0.20": {"groups": [0, 3], "comment": "Living room"}})

    def test_needs_ip(self):
        self.conn.execute("UPDATE devices SET ip = NULL")
        with self.assertRaises(ValueError):
            pause.pause(self.conn, FakeAdmin(), TV, None)
        with self.assertRaises(LookupError):
            pause.pause(self.conn, FakeAdmin(), "aa:aa:aa:aa:aa:aa", None)

    def test_maintain_expires(self):
        admin = FakeAdmin()
        pause.pause(self.conn, admin, TV, 5000)
        self.assertFalse(pause.needs_maintenance(self.conn, 4999))
        self.assertTrue(pause.needs_maintenance(self.conn, 5000))
        self.assertTrue(pause.maintain(self.conn, admin, 5000))
        self.assertEqual(admin.clients, {})
        self.assertFalse(pause.needs_maintenance(self.conn, 6000))

    def test_maintain_follows_ip_change(self):
        admin = FakeAdmin()
        pause.pause(self.conn, admin, TV, None)
        apply_scan(self.conn, [Sighting(TV, "192.168.0.21")], 1060, 600)
        self.assertTrue(pause.needs_maintenance(self.conn, 1060))
        self.assertTrue(pause.maintain(self.conn, admin, 1060))
        self.assertEqual(list(admin.clients), ["192.168.0.21"])
        self.assertEqual((self.row()["paused_ip"], self.row()["paused_until"]), ("192.168.0.21", None))

    def test_touch(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        os.utime(path, (0, 0))
        pause.touch(path)
        self.assertGreater(os.path.getmtime(path), 0)
        os.remove(path)
        pause.touch("")  # no trigger configured: nothing happens


class FakePihole:
    """Records PiholeAdmin's API calls and answers from a tiny in-memory state."""

    def __init__(self):
        self.calls = []
        self.groups = [{"id": 0, "name": "Default"}]
        self.regex = []
        self.clients = {}

    def _request(self, method, path, sid=None, body=None):
        self.calls.append((method, path, body))
        if path == "/api/groups":
            if method == "POST":
                self.groups.append({"id": PAUSE_GID, "name": body["name"]})
            return {"groups": self.groups}
        if path.startswith("/api/domains/deny/regex"):
            if method == "POST":
                self.regex.append({"domain": body["domain"], "groups": body["groups"], "enabled": True})
            return {"domains": self.regex}
        if path.startswith("/api/clients/"):
            name = path.rsplit("/", 1)[1].replace("%3A", ":")
            if method == "GET":
                return {"clients": [self.clients[name]] if name in self.clients else []}
            if method == "DELETE":
                self.clients.pop(name, None)
            if method == "PUT":
                self.clients[name] = {"client": name, **body}
            return {}
        if path == "/api/clients" and method == "POST":
            self.clients[body["client"]] = body
            return {}
        raise AssertionError(f"unexpected {method} {path}")


class PiholeAdminTest(unittest.TestCase):
    def test_creates_group_and_rule_once(self):
        fake = FakePihole()
        admin = PiholeAdmin(fake, None)
        self.assertEqual(admin.ensure_pause_group(), PAUSE_GID)
        self.assertEqual(admin.ensure_pause_group(), PAUSE_GID)
        posts = [(p, b) for m, p, b in fake.calls if m == "POST"]
        self.assertEqual([p for p, _ in posts], ["/api/groups", "/api/domains/deny/regex"])
        self.assertEqual(posts[0][1]["name"], PAUSE_GROUP)
        self.assertEqual((posts[1][1]["domain"], posts[1][1]["groups"]), (BLOCK_ALL, [PAUSE_GID]))

    def test_save_and_delete_client(self):
        fake = FakePihole()
        admin = PiholeAdmin(fake, None)
        admin.save_client("192.168.0.20", [PAUSE_GID], "x")
        admin.save_client("192.168.0.20", [0], "y")
        self.assertEqual([m for m, p, _ in fake.calls if m in ("POST", "PUT")], ["POST", "PUT"])
        self.assertEqual(admin.get_client("192.168.0.20")["groups"], [0])
        admin.delete_client("192.168.0.20")
        self.assertIsNone(admin.get_client("192.168.0.20"))


class FakeBlockList:
    def __init__(self, blocked=()):
        self.list = set(blocked)
        self.calls = []

    def blocked(self):
        return set(self.list)

    def block(self, mac, name):
        self.calls.append(("block", mac))
        self.list.add(mac)

    def unblock(self, mac):
        self.calls.append(("unblock", mac))
        self.list.discard(mac)


class DecoSyncTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.connect(":memory:")
        apply_scan(self.conn, [Sighting(TV, "192.168.0.20")], 1000, 600)
        self.admin = FakeAdmin()

    def sync(self, deco):
        @contextmanager
        def session():
            yield deco
        return pause.sync_deco(self.conn, session)

    def test_block_then_unblock(self):
        deco = FakeBlockList()
        self.assertFalse(self.sync(deco))  # nothing paused: no Deco login at all
        pause.pause(self.conn, self.admin, TV, None)
        self.assertTrue(pause.deco_out_of_step(self.conn))
        self.assertTrue(self.sync(deco))
        self.assertEqual(deco.list, {TV})
        self.assertFalse(pause.deco_out_of_step(self.conn))
        pause.resume(self.conn, self.admin, TV)
        self.assertTrue(self.sync(deco))
        self.assertEqual((deco.list, deco.calls), (set(), [("block", TV), ("unblock", TV)]))

    def test_leaves_a_block_made_in_the_deco_app(self):
        deco = FakeBlockList([TV])
        pause.pause(self.conn, self.admin, TV, None)
        self.sync(deco)
        pause.resume(self.conn, self.admin, TV)
        self.sync(deco)
        self.assertEqual((deco.list, deco.calls), ({TV}, []))
        self.assertFalse(pause.deco_out_of_step(self.conn))


class BlockListTest(unittest.TestCase):
    def test_requests(self):
        sent = []

        class Client:
            def request(self, path, data):
                sent.append((path, json.loads(data)))
                return {"client_list": [{"mac": "00-11-22-33-44-55", "name": "VFY="}]}

        deco = BlockList(Client())
        self.assertEqual(deco.blocked(), {TV})
        deco.block(TV, "TV")
        deco.unblock(TV)
        self.assertEqual({p for p, _ in sent}, {"admin/client?form=black_list"})
        self.assertEqual([b for _, b in sent], [
            {"operation": "list"},
            {"operation": "block", "params": {"client_list": [{"mac": "00-11-22-33-44-55", "name": "VFY=", "client_type": "other"}]}},
            {"operation": "unblock", "params": {"client_list": ["00-11-22-33-44-55"]}},
        ])
        Client.request = lambda self, path, data: {"client_list": {}}  # what an empty list looks like
        self.assertEqual(BlockList(Client()).blocked(), set())


if __name__ == "__main__":
    unittest.main()
