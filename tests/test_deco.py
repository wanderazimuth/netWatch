import json
import os
import sqlite3
import tempfile
import unittest

from netwatch import db
from netwatch.deco import Deco, DecoClient, connection_label, normalize_mac
from netwatch.info import DeviceInfo, merge_info, usable_name


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeDeco(Deco):
    """Deco with the network call replaced by a scripted result."""

    def __init__(self, password_file, clock):
        super().__init__("http://deco", password_file, poll_interval=300, clock=clock)
        self.result = []
        self.calls = 0

    def _fetch(self):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class DecoTest(unittest.TestCase):
    def setUp(self):
        fd, self.pw = tempfile.mkstemp()
        os.write(fd, b"secret")
        os.close(fd)
        self.clock = FakeClock()
        self.deco = FakeDeco(self.pw, self.clock)

    def tearDown(self):
        os.remove(self.pw)

    def test_connection_labels(self):
        self.assertEqual(connection_label("WIRED"), "wired")
        self.assertEqual(connection_label("HOST_2G"), "2.4 GHz")
        self.assertEqual(connection_label("HOST_5G"), "5 GHz")
        self.assertEqual(connection_label("GUEST_5G"), "5 GHz guest")
        self.assertEqual(connection_label("IOT_2G"), "2.4 GHz IoT")
        self.assertEqual(connection_label("HOST_MLO"), "Wi-Fi")
        self.assertIsNone(connection_label("UNKNOWN"))

    def test_normalize_mac(self):
        self.assertEqual(normalize_mac("60-A4-B7-AE-7C-A4"), "60:a4:b7:ae:7c:a4")

    def test_clients_by_node(self):
        class Node:
            def __init__(self, name, mac):
                self.name, self.macaddr = name, mac

        class Client:
            def __init__(self):
                self.asked = []

            def request(self, path, body):
                mac = json.loads(body)["params"]["device_mac"]
                self.asked.append(mac)
                if mac == "60-A4-B7-AE-7C-9F":
                    raise RuntimeError("timeout")
                return {"client_list": [{"mac": "AA-BB-CC-00-00-01", "online": True},
                                        {"mac": "AA-BB-CC-00-00-02", "online": False}]}

        client = Client()
        via = Deco._clients_by_node(client, [Node("Upstairs", "60:a4:b7:ae:7c:a4"), Node("Basement", "60-A4-B7-AE-7C-9F")])
        self.assertEqual(client.asked, ["60-A4-B7-AE-7C-A4", "60-A4-B7-AE-7C-9F"])
        self.assertEqual(via, {"aa:bb:cc:00:00:01": "Upstairs"})

    def test_deco_name_recorded(self):
        conn = db.connect(":memory:")
        from netwatch.scanner import Sighting
        from netwatch.tracker import apply_scan
        apply_scan(conn, [Sighting("aa:aa:aa:aa:aa:aa", "192.168.0.50")], 0, 600,
                   {"aa:aa:aa:aa:aa:aa": DeviceInfo(connection="5 GHz", deco="Basement")})
        apply_scan(conn, [Sighting("aa:aa:aa:aa:aa:aa", "192.168.0.50")], 60, 600)
        self.assertEqual(conn.execute("SELECT deco FROM devices").fetchone()[0], "Basement")

    def test_polls_only_when_due(self):
        self.deco.result = [DecoClient("aa:aa:aa:aa:aa:aa", "192.168.0.50", "iPhone", "5 GHz")]
        self.assertTrue(self.deco.refresh())
        self.clock.t += 60
        self.assertFalse(self.deco.refresh())
        self.clock.t += 240
        self.assertTrue(self.deco.refresh())
        self.assertEqual(self.deco.calls, 2)

    def test_backs_off_after_failure(self):
        self.deco.result = RuntimeError("Cannot authorize")
        self.assertFalse(self.deco.refresh())
        self.clock.t += 300  # normal interval is not enough after a failure
        self.assertFalse(self.deco.refresh())
        self.assertEqual(self.deco.calls, 1)
        self.clock.t += 300  # 2 * 300 s since the failure
        self.deco.refresh()
        self.assertEqual(self.deco.calls, 2)
        self.clock.t += 600  # second failure: now 4 * 300 s
        self.assertFalse(self.deco.refresh())
        self.assertEqual(self.deco.calls, 2)

    def test_backoff_capped(self):
        self.deco.result = RuntimeError("down")
        self.deco._failures = 50
        self.deco.refresh()
        self.assertLessEqual(self.deco._next_poll - self.clock.t, 6 * 3600)

    def test_password_change_retries_immediately(self):
        self.deco.result = RuntimeError("Cannot authorize")
        self.deco.refresh()
        os.utime(self.pw, (0, os.stat(self.pw).st_mtime + 10))
        self.deco.result = []
        self.assertTrue(self.deco.refresh())
        self.assertEqual(self.deco.calls, 2)

    def test_old_data_kept_on_failure(self):
        self.deco.result = [DecoClient("aa:aa:aa:aa:aa:aa", "192.168.0.50", "iPhone", "5 GHz")]
        self.deco.refresh()
        self.deco.result = RuntimeError("down")
        self.clock.t += 300
        self.deco.refresh()
        self.assertEqual(self.deco.device_info()["aa:aa:aa:aa:aa:aa"].hostname, "iPhone")

    def test_sightings_limited_to_network(self):
        self.deco.result = [
            DecoClient("aa:aa:aa:aa:aa:aa", "192.168.0.50", "iPhone", "5 GHz"),
            DecoClient("bb:bb:bb:bb:bb:bb", "192.168.68.5", "guest", "5 GHz guest"),
            DecoClient("cc:cc:cc:cc:cc:cc", None, "no-ip", "wired"),
        ]
        self.deco.refresh()
        self.assertEqual([s.mac for s in self.deco.sightings("192.168.0.0/24")], ["aa:aa:aa:aa:aa:aa"])


class InfoTest(unittest.TestCase):
    def test_merge_priority(self):
        mac = "aa:aa:aa:aa:aa:aa"
        deco = {mac: DeviceInfo(hostname="GamingPC", connection="wired")}
        pihole = {mac: DeviceInfo(hostname="desktop-123", vendor="ASRock"), "bb:bb:bb:bb:bb:bb": DeviceInfo(vendor="Apple")}
        merged = merge_info(deco, pihole)
        self.assertEqual(merged[mac], DeviceInfo("GamingPC", "ASRock", "wired"))
        self.assertEqual(merged["bb:bb:bb:bb:bb:bb"], DeviceInfo(vendor="Apple"))

    def test_placeholder_names(self):
        self.assertFalse(usable_name("lwip"))
        self.assertTrue(usable_name("Pixel-8a"))


class MigrationTest(unittest.TestCase):
    def test_adds_connection_column(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            old = sqlite3.connect(path)
            old.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT, label TEXT,"
                        " first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, online INTEGER NOT NULL DEFAULT 1)")
            old.execute("INSERT INTO devices (mac, first_seen, last_seen) VALUES ('aa:aa:aa:aa:aa:aa', 1, 1)")
            old.commit()
            old.close()
            conn = db.connect(path)
            self.assertIsNone(conn.execute("SELECT connection FROM devices").fetchone()[0])
            conn.close()
        finally:
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(path + suffix):
                    os.remove(path + suffix)


if __name__ == "__main__":
    unittest.main()
